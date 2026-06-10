/**
 * VibeGuard — LLM Context Payload Builder & API Client
 *
 * Reads the filtered diff footprint from parser.ts and compiles a high-density,
 * security-focused prompt for adversarial QA analysis via the user's configured
 * LLM provider.
 *
 * The model is instructed to act as a **Sovereign System Architect** and return a
 * structured JSON map of intent + attack surfaces for each modified endpoint.
 *
 * Supported providers:
 *   · custom    — OpenAI-compatible endpoint (LM Studio, Ollama, vLLM, etc.)
 *   · openai    — OpenAI API (chat/completions)
 *   · anthropic — Anthropic API (messages)
 *
 * Response parsing handles both strict JSON-mode responses and fallback
 * extraction from models that wrap JSON in markdown fences.
 */

import type {
  VibeGuardConfig,
  FilteredDiff,
  FilteredFile,
  FilteredHunk,
  LLMAnalysisResult,
  ModifiedEndpoint,
  AnalysisVerdict,
  VulnerabilityVector,
} from "./types";
import { resolveApiKey } from "./config";
import * as ui from "./ui";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** Valid vulnerability vectors for response validation. */
const VALID_VECTORS = new Set<VulnerabilityVector>([
  "sql_injection",
  "privilege_escalation",
  "auth_bypass",
  "rce",
  "input_fuzzing",
  "xss",
  "path_traversal",
  "ssrf",
  "idor",
  "race_condition",
  "deserialization",
  "information_disclosure",
  "misconfiguration",
  "other",
]);

/** Valid HTTP methods for response validation. */
const VALID_METHODS = new Set(["POST", "GET", "PUT", "DELETE", "PATCH", "UNKNOWN"]);

/** Max length for a diff payload before truncation (chars, ~8K tokens). */
const MAX_PAYLOAD_CHARS = 28_000;

/** HTTP request timeout in milliseconds (6 seconds per spec). */
const REQUEST_TIMEOUT_MS = 6_000;

// ─── System Prompt ──────────────────────────────────────────────────────────────

/**
 * The Sovereign System Architect persona.
 *
 * Designed to elicit structured, security-conscious analysis of code changes.
 * The prompt explicitly:
 *   · Defines the model's role and expertise.
 *   · Requires strict JSON output matching the ModifiedEndpoint schema.
 *   · Guides the model to think adversarially about every input.
 *   · Asks the model to infer routes, methods, and parameters from code context.
 */
const SYSTEM_PROMPT = `You are a **Sovereign System Architect** — a principal-level security engineer and code reviewer. Your purpose is to analyze git diffs and identify intent, attack surfaces, and vulnerability vectors in every code change.

## Your Task

Analyze the provided git diff. For each modified file that touches an API endpoint, route handler, controller, or any code path that processes user input, return a structured JSON assessment.

## Rules

1. **Think adversarially.** Assume every user-controlled input is hostile until proven safe.
2. **Infer from context.** If the route path isn't explicit in the diff, estimate it from file names, function names, class names, or directory structure.
3. **Detect intent.** Describe what the code change is trying to accomplish — not just what it does, but *why* it was written.
4. **Surface all inputs.** List every variable, parameter, POST field, query string, header, cookie, or session value that feeds into the changed code.
5. **Be specific.** Vague findings like "check for bugs" are not acceptable. Name concrete vulnerability classes with evidence from the diff.
6. **Skip noise.** If a file change is purely cosmetic, configuration tuning, or has no security relevance, do not include it in the output.

## Vulnerability Vectors

You may flag any of these standard classes:
- **sql_injection** — Unparameterized queries, string concatenation into SQL.
- **privilege_escalation** — Missing authorization checks, role bypass.
- **auth_bypass** — Weak or missing authentication on sensitive paths.
- **rce** — eval(), exec(), system(), deserialization, command injection.
- **input_fuzzing** — Unvalidated user input reaching dangerous sinks.
- **xss** — Unescaped output, innerHTML, dangerous DOM apis.
- **path_traversal** — File reads/writes with user-controlled paths.
- **ssrf** — Server-side requests with user-controlled URLs.
- **idor** — Direct object references without ownership checks.
- **race_condition** — TOCTOU on shared state, non-atomic transactions.
- **deserialization** — Unsafe unserialize(), pickle, JSON.parse on untrusted data.
- **information_disclosure** — Stack traces, debug endpoints, verbose errors.
- **misconfiguration** — Disabled security features, permissive CORS, exposed secrets.
- **other** — Anything else worth flagging (explain in detected_intent).

## Output Format

Return ONLY a valid JSON object. No preamble, no markdown, no code fences.

The JSON object must have exactly one key: "modified_endpoints", which is an array of objects with these fields:

- **file_path** (string): Relative path to the modified file.
- **estimated_route** (string): Your best guess at the route/endpoint path (e.g. "/api/v1/users.php", "/graphql", "/auth/login"). Use "N/A" if no route is identifiable.
- **http_method** (string): One of "POST", "GET", "PUT", "DELETE", "PATCH", or "UNKNOWN".
- **detected_intent** (string): A concise description of what the change intends to do.
- **vulnerability_vectors** (string[]): Zero or more of the vulnerability classes listed above.
- **input_parameters** (string[]): Variable names, field names, or parameter sources detected in the change.

If no functional endpoints are modified, return: { "modified_endpoints": [] }

## Example

\`\`\`json
{
  "modified_endpoints": [
    {
      "file_path": "api/login.php",
      "estimated_route": "/api/login.php",
      "http_method": "POST",
      "detected_intent": "Authenticates a user by username/password against the database, then issues a JWT session token.",
      "vulnerability_vectors": ["sql_injection"],
      "input_parameters": ["username", "password", "POST_body"]
    }
  ]
}
\`\`\`

You are the final gatekeeper before code reaches production. Every vulnerability you miss is a potential breach.`;

// ─── Diff Serializer ────────────────────────────────────────────────────────────

/**
 * Serialize a FilteredDiff into a compact, token-efficient text representation
 * suitable for inclusion in an LLM prompt.
 *
 * Format:
 *   ## Changed Files (N)
 *   ### path/to/file.ext  (+A -D)  [context: function_name]
 *   @@ hunk header @@
 *   + added line
 *   - deleted line
 *     context line
 */
function serializeDiffForPrompt(diff: FilteredDiff): string {
  if (diff.files.length === 0) {
    return "(No functional code changes detected after noise filtering.)";
  }

  const parts: string[] = [];
  parts.push(`## Changed Files (${diff.files.length})`);
  parts.push("");

  for (const file of diff.files) {
    const statusLabel = file.status === "added" ? "[NEW]"
      : file.status === "deleted" ? "[DEL]"
      : file.status === "renamed" ? "[REN]"
      : "[MOD]";

    parts.push(`### ${file.path}  ${statusLabel}  +${file.additions} -${file.deletions}`);

    for (const hunk of file.hunks) {
      parts.push(hunk.header);
      if (hunk.surrounding_context) {
        parts.push(`  ↳ context: ${hunk.surrounding_context}`);
      }
      for (const line of hunk.lines) {
        const prefix = line.type === "add" ? "+" : line.type === "delete" ? "-" : " ";
        parts.push(`${prefix}${line.content}`);
      }
      parts.push(""); // blank between hunks
    }

    parts.push(""); // blank between files
  }

  return parts.join("\n");
}

/**
 * Serialize and truncate if needed. Adds a truncation notice so the model
 * knows the diff was cut for length.
 */
function buildDiffPayload(diff: FilteredDiff): string {
  let serialized = serializeDiffForPrompt(diff);

  if (serialized.length > MAX_PAYLOAD_CHARS) {
    const truncated = serialized.slice(0, MAX_PAYLOAD_CHARS);
    const lastNewline = truncated.lastIndexOf("\n");
    const cutPoint = lastNewline > 0 ? lastNewline : MAX_PAYLOAD_CHARS;

    serialized = truncated.slice(0, cutPoint) +
      `\n\n⚠️  [Diff truncated at ~${MAX_PAYLOAD_CHARS} chars — ${diff.files.length} files, ~${diff.estimatedTokens} tokens estimated. Full analysis may be incomplete.]`;
  }

  return serialized;
}

// ─── LLM API Clients ────────────────────────────────────────────────────────────

/**
 * Call the user's configured LLM API with the system prompt and user message.
 *
 * Dispatches to the correct provider based on `config.llm_provider`.
 * All providers return the raw response text for downstream JSON parsing.
 *
 * @param config      - Validated VibeGuard configuration.
 * @param userMessage - The user message to send.
 * @param systemPrompt - Optional custom system prompt. Uses Sovereign System Architect default if omitted.
 */
export async function callLLM(
  config: VibeGuardConfig,
  userMessage: string,
  systemPrompt?: string
): Promise<string> {
  const apiKey = resolveApiKey(config.llm_api_key);
  const prompt = systemPrompt ?? SYSTEM_PROMPT;

  switch (config.llm_provider) {
    case "custom":
    case "openai":
      return callOpenAICompatible(config.llm_api_endpoint, apiKey, config.llm_model, userMessage, prompt);

    case "anthropic":
      return callAnthropic(config.llm_api_endpoint, apiKey, config.llm_model, userMessage, prompt);

    default:
      throw new Error("Unknown LLM provider: " + config.llm_provider);
  }
}

/**
 * OpenAI-compatible chat completions API.
 * Used for both `openai` and `custom` providers.
 *
 * Attempts to use the `json_object` response_format for models that support it.
 * Falls back gracefully if the endpoint doesn't support that parameter.
 */
async function callOpenAICompatible(
  endpoint: string,
  apiKey: string,
  model: string,
  userMessage: string,
  systemPrompt?: string
): Promise<string> {
  const url = endpoint.replace(/\/+$/, "") + "/chat/completions";

  const body: Record<string, unknown> = {
    model,
    messages: [
      { role: "system", content: systemPrompt ?? SYSTEM_PROMPT },
      { role: "user", content: userMessage },
    ],
    temperature: 0.1,       // Low temp for deterministic analysis.
    max_tokens: 4096,
    response_format: { type: "json_object" },
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      throw new Error(
        `LLM API returned ${response.status} ${response.statusText}${errText ? `: ${errText.slice(0, 200)}` : ""}`
      );
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      error?: { message?: string };
    };

    if (data.error) {
      throw new Error(`LLM API error: ${data.error.message ?? JSON.stringify(data.error)}`);
    }

    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      throw new Error("LLM returned an empty response — no content in choices[0].message.content");
    }

    return content;
  } catch (err: unknown) {
    if ((err as Error).name === "AbortError") {
      throw new Error(
        "LLM request timed out after " + String(REQUEST_TIMEOUT_MS / 1000) + "s.\n" +
        "The configured LLM (" + model + ") did not respond within the deadline.\n" +
        "Check that your LLM endpoint is running and reachable, or increase the timeout."
      );
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Anthropic Messages API.
 *
 * Uses the Messages endpoint with a system prompt and user message.
 * For JSON-mode behavior on Claude, we include a prefill assistant message
 * with `{` to force the response to start as JSON.
 */
async function callAnthropic(
  endpoint: string,
  apiKey: string,
  model: string,
  userMessage: string,
  systemPrompt?: string
): Promise<string> {
  const url = endpoint.replace(/\/+$/, "") + "/messages";

  const body: Record<string, unknown> = {
    model,
    system: systemPrompt ?? SYSTEM_PROMPT,
    messages: [
      { role: "user", content: userMessage },
      { role: "assistant", content: "{" },  // Prefill to force JSON output.
    ],
    temperature: 0.1,
    max_tokens: 4096,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      throw new Error(
        `Anthropic API returned ${response.status} ${response.statusText}${errText ? `: ${errText.slice(0, 200)}` : ""}`
      );
    }

    const data = (await response.json()) as {
      content?: Array<{ type: string; text?: string }>;
      error?: { message?: string };
    };

    if (data.error) {
      throw new Error(`Anthropic API error: ${data.error.message ?? JSON.stringify(data.error)}`);
    }

    const textBlocks = data.content?.filter((b) => b.type === "text" && b.text);
    if (!textBlocks || textBlocks.length === 0) {
      throw new Error("Anthropic returned an empty response — no text content blocks");
    }

    // Prepend the `{` that we used as a prefill.
    return "{" + textBlocks.map((b) => b.text ?? "").join("");
  } catch (err: unknown) {
    if ((err as Error).name === "AbortError") {
      throw new Error(
        "LLM request timed out after " + String(REQUEST_TIMEOUT_MS / 1000) + "s.\n" +
        "The configured LLM (" + model + ") did not respond within the deadline.\n" +
        "Check that your LLM endpoint is running and reachable, or increase the timeout."
      );
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ─── Response Parsing ───────────────────────────────────────────────────────────

/**
 * Parse the LLM's raw text response into an LLMAnalysisResult.
 *
 * Handles:
 *   1. Clean JSON — direct parse.
 *   2. Markdown-fenced JSON — extracts from ```json ... ``` blocks.
 *   3. JSON with surrounding text — finds the outermost { } pair.
 *
 * Validates the structure matches the expected schema and sanitizes
 * malformed entries.
 */
function parseLLMResponse(raw: string): LLMAnalysisResult {
  let jsonStr = raw.trim();

  // Strip markdown code fences.
  const fenceMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) {
    jsonStr = fenceMatch[1].trim();
  }

  // If the response has text before or after the JSON object, extract just the
  // outermost brace pair.
  if (!jsonStr.startsWith("{")) {
    const firstBrace = jsonStr.indexOf("{");
    if (firstBrace !== -1) {
      const lastBrace = jsonStr.lastIndexOf("}");
      if (lastBrace > firstBrace) {
        jsonStr = jsonStr.slice(firstBrace, lastBrace + 1);
      }
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error(
      `Failed to parse LLM response as JSON. Raw response:\n${raw.slice(0, 500)}`
    );
  }

  // Validate top-level structure.
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("LLM response is not a JSON object.");
  }

  const obj = parsed as Record<string, unknown>;

  if (!Array.isArray(obj.modified_endpoints)) {
    throw new Error(
      'LLM response is missing "modified_endpoints" array. Got keys: ' +
      Object.keys(obj).join(", ")
    );
  }

  // Sanitize each endpoint entry.
  const endpoints: ModifiedEndpoint[] = [];
  for (let i = 0; i < obj.modified_endpoints.length; i++) {
    const entry = (obj.modified_endpoints as unknown[])[i];
    if (typeof entry !== "object" || entry === null) {
      continue; // Skip non-object entries.
    }

    const ep = entry as Record<string, unknown>;
    endpoints.push({
      file_path: String(ep.file_path ?? "unknown"),
      estimated_route: String(ep.estimated_route ?? "N/A"),
      http_method: sanitizeMethod(ep.http_method),
      detected_intent: String(ep.detected_intent ?? "No intent provided."),
      vulnerability_vectors: sanitizeVectors(ep.vulnerability_vectors),
      input_parameters: sanitizeStringArray(ep.input_parameters),
    });
  }

  return { modified_endpoints: endpoints };
}

/** Sanitize and validate the HTTP method field. */
function sanitizeMethod(raw: unknown): ModifiedEndpoint["http_method"] {
  if (typeof raw !== "string") return "UNKNOWN";
  const upper = raw.toUpperCase();
  return VALID_METHODS.has(upper) ? (upper as ModifiedEndpoint["http_method"]) : "UNKNOWN";
}

/** Sanitize and validate vulnerability vectors. */
function sanitizeVectors(raw: unknown): VulnerabilityVector[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((v): v is string => typeof v === "string")
    .map((v) => v.toLowerCase().trim())
    .filter((v): v is VulnerabilityVector => VALID_VECTORS.has(v as VulnerabilityVector));
}

/** Sanitize an array of strings. */
function sanitizeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((v): v is string => typeof v === "string")
    .map((v) => v.trim())
    .filter(Boolean);
}

// ─── Verdict Builder ────────────────────────────────────────────────────────────

/**
 * Build an AnalysisVerdict from the LLM's structured result.
 *
 * The verdict determines whether the push should be blocked.
 *
 * Severity heuristic:
 *   · critical: rce, auth_bypass                              → block
 *   · high:     sql_injection, privilege_escalation, deserialization  → block
 *   · medium:   ssrf, path_traversal, idor, information_disclosure    → warn
 *   · low:      xss, input_fuzzing, misconfiguration, race_condition  → pass with note
 *   · other:    depends on description                                → warn
 */
function buildVerdict(result: LLMAnalysisResult, diff: FilteredDiff): AnalysisVerdict {
  const riskSummary: AnalysisVerdict["risk_summary"] = {};

  let maxSeverity: "low" | "medium" | "high" | "critical" = "low";
  let hasAnyFinding = false;

  for (const ep of result.modified_endpoints) {
    if (ep.vulnerability_vectors.length === 0) continue;
    hasAnyFinding = true;

    const severity = maxVectorSeverity(ep.vulnerability_vectors);
    const existing = riskSummary[ep.file_path];

    if (!existing || severityRank(severity) > severityRank(existing.severity)) {
      riskSummary[ep.file_path] = {
        severity,
        vectors: ep.vulnerability_vectors,
      };
    } else if (existing && severityRank(severity) === severityRank(existing.severity)) {
      // Merge vectors.
      for (const v of ep.vulnerability_vectors) {
        if (!existing.vectors.includes(v)) {
          existing.vectors.push(v);
        }
      }
    }

    if (severityRank(severity) > severityRank(maxSeverity)) {
      maxSeverity = severity;
    }
  }

  // Build the explanation.
  const explanation = buildExplanation(result, riskSummary, diff);

  // Decision: block on high+ severity.
  const pass = maxSeverity !== "critical" && maxSeverity !== "high";

  return { pass, risk_summary: riskSummary, result, explanation };
}

function maxVectorSeverity(vectors: VulnerabilityVector[]): "low" | "medium" | "high" | "critical" {
  let max: "low" | "medium" | "high" | "critical" = "low";
  for (const v of vectors) {
    const s = vectorSeverity(v);
    if (severityRank(s) > severityRank(max)) max = s;
  }
  return max;
}

function vectorSeverity(v: VulnerabilityVector): "low" | "medium" | "high" | "critical" {
  switch (v) {
    case "rce":
    case "auth_bypass":
      return "critical";
    case "sql_injection":
    case "privilege_escalation":
    case "deserialization":
      return "high";
    case "ssrf":
    case "path_traversal":
    case "idor":
    case "information_disclosure":
      return "medium";
    case "xss":
    case "input_fuzzing":
    case "misconfiguration":
    case "race_condition":
      return "low";
    case "other":
      return "medium";
  }
}

function severityRank(s: "low" | "medium" | "high" | "critical"): number {
  switch (s) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
  }
}

function buildExplanation(
  result: LLMAnalysisResult,
  riskSummary: AnalysisVerdict["risk_summary"],
  diff: FilteredDiff,
): string {
  const lines: string[] = [];

  const endpointCount = result.modified_endpoints.length;
  const findingsCount = Object.keys(riskSummary).length;

  if (findingsCount === 0) {
    if (endpointCount === 0) {
      lines.push("No functional endpoint modifications detected in this push.");
    } else {
      lines.push(
        `${endpointCount} endpoint(s) modified — no vulnerability vectors flagged by the LLM.`
      );
    }
    lines.push(`Analyzed ${diff.files.length} file(s), ~${diff.estimatedTokens} tokens.`);
    return lines.join("\n");
  }

  lines.push(`${findingsCount} file(s) with flagged vulnerability vectors:\n`);

  for (const [file, risk] of Object.entries(riskSummary)) {
    const sevColor = risk.severity === "critical" || risk.severity === "high"
      ? "CRITICAL"
      : risk.severity === "medium"
        ? "WARN"
        : "INFO";

    lines.push(`  [${sevColor}] ${file}`);
    lines.push(`    Severity: ${risk.severity}`);
    lines.push(`    Vectors:  ${risk.vectors.join(", ")}`);
    lines.push("");
  }

  lines.push(`Analyzed ${diff.files.length} file(s), ~${diff.estimatedTokens} tokens.`);
  lines.push(`${diff.discarded.length} file(s) discarded by noise filter.`);

  return lines.join("\n");
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Run the full Phase 2 analysis pipeline:
 *   1. Build the LLM payload from the filtered diff.
 *   2. Call the configured LLM API.
 *   3. Parse and validate the JSON response.
 *   4. Build a pass/fail verdict with an explanation.
 *
 * @param config  — Validated VibeGuard configuration.
 * @param diff    — Filtered diff from parser.ts.
 * @returns An AnalysisVerdict that tells the hook whether to allow or block the push.
 */
export async function analyzeDiff(
  config: VibeGuardConfig,
  diff: FilteredDiff
): Promise<AnalysisVerdict> {
  // Build the user message with the serialized diff.
  const diffPayload = buildDiffPayload(diff);

  const userMessage = [
    "## Git Diff for Analysis",
    "",
    `Total files changed after noise filtering: ${diff.files.length}`,
    `Estimated tokens: ~${diff.estimatedTokens}`,
    `Files discarded by filter: ${diff.discarded.length}`,
    "",
    diffPayload,
    "",
    "Return the JSON analysis now. Remember: no preamble, no markdown fences — pure JSON only.",
  ].join("\n");

  // Call the LLM.
  ui.action(`Sending ${diff.files.length} file(s) (~${diff.estimatedTokens} tokens) to ${config.llm_model} via ${config.llm_provider}...`);

  let rawResponse: string;
  try {
    rawResponse = await callLLM(config, userMessage);
  } catch (err: unknown) {
    // Fail closed: any LLM error blocks the push.
    const isTimeout = (err as Error).message.includes("timed out");
    const prefix = isTimeout
      ? "LLM TIMEOUT"
      : "LLM analysis failed";

    throw new Error(
      prefix + ": " + (err as Error).message + "\n" +
      "Push blocked — cannot verify changes without LLM analysis."
    );
  }

  // Parse the structured response.
  const result = parseLLMResponse(rawResponse);

  // Build the pass/fail verdict.
  const verdict = buildVerdict(result, diff);

  return verdict;
}

/**
 * Dry-run: build the prompt that *would* be sent to the LLM without making
 * an API call. Useful for debugging prompt construction and token estimates.
 */
export function buildDryRunPayload(
  config: VibeGuardConfig,
  diff: FilteredDiff
): { systemPrompt: string; userMessage: string; estimatedTokens: number } {
  const diffPayload = buildDiffPayload(diff);

  const userMessage = [
    "## Git Diff for Analysis",
    "",
    `Total files changed after noise filtering: ${diff.files.length}`,
    `Estimated tokens: ~${diff.estimatedTokens}`,
    `Files discarded by filter: ${diff.discarded.length}`,
    "",
    diffPayload,
    "",
    "Return the JSON analysis now. Remember: no preamble, no markdown fences — pure JSON only.",
  ].join("\n");

  return {
    systemPrompt: SYSTEM_PROMPT,
    userMessage,
    estimatedTokens: diff.estimatedTokens,
  };
}
