/**
 * VibeGuard — Automated Parallel Test Runner
 *
 * Reads the attack_suite generated in Phase 5, executes each payload as an
 * HTTP request against the local dev target, and returns structured execution
 * results for assertion evaluation.
 *
 * Design:
 *   - Configurable concurrency cap (Fix #3) — default 3 concurrent requests
 *     to prevent self-DoS against lightweight local dev servers.
 *   - Dynamic auth token seeding (Fix #2) — negotiates a short-lived sandbox
 *     token before firing payloads so secured endpoints don't false-negative.
 *   - Strict 3-second timeout per payload to prevent the git push from hanging
 *     indefinitely on slow or looping server handlers.
 *   - GET requests serialize payload_data into URL query strings.
 *   - POST requests send payload_data as application/x-www-form-urlencoded
 *     (traditional PHP/cPanel) with a fallback Content-Type detection heuristic.
 *   - Response bodies are captured (first 2000 chars) for signature scanning
 *     by the assertion engine.
 *
 * Zero runtime dependencies — uses only Node.js built-in fetch.
 */

import { execSync } from "node:child_process";
import type {
  VibeGuardConfig,
  AttackSuite,
  AttackPayload,
  ExecutionResult,
  AssertionVerdict,
  TestReport,
} from "../core/types";
import { evaluateResponse, isVulnerable } from "./assertion";
import { buildRequest, AuthContext } from "../utils/http";
import * as ui from "../cli/ui";

// ─── Constants ───────────────────────────────────────────────────────────────────

/** Per-request timeout in milliseconds (3 seconds per spec). */
const REQUEST_TIMEOUT_MS = 3_000;

/** Maximum characters of response body to capture for signature scanning. */
const MAX_RESPONSE_BODY_CHARS = 2_000;

/** Maximum time to wait for the token generation command (ms). */
const TOKEN_GEN_TIMEOUT_MS = 15_000;

// ─── Public API ──────────────────────────────────────────────────────────────────

/**
 * Execute the full attack suite against the local dev server.
 *
 * Runs payloads in parallel with a concurrency cap from config. Each payload
 * is executed as an HTTP request, the response is captured, and assertions
 * are evaluated.
 *
 * @param attackSuite — The attack payloads from Phase 5.
 * @param config      — Validated VibeGuard config (for auth & concurrency settings).
 * @returns A TestReport aggregating all execution results and verdicts.
 */
export async function runTests(
  attackSuite: AttackSuite,
  config?: VibeGuardConfig
): Promise<TestReport> {
  if (attackSuite.attack_suite.length === 0) {
    return {
      results: [],
      vulnerabilitiesFound: 0,
      testsPassed: 0,
      testsErrored: 0,
      overallPass: true,
      summary: "No payloads to execute — skipping test run.",
    };
  }

  const concurrency = config?.max_concurrent_requests ?? 3;
  const totalPayloads = attackSuite.attack_suite.length;

  // Fix #2: Negotiate an auth token if auth_seeding is configured.
  const authContext = resolveAuthContext(config);

  ui.action(
    "Executing " + String(totalPayloads) + " payload(s) against local server " +
    "(concurrency: " + String(concurrency) + ", timeout: " +
    String(REQUEST_TIMEOUT_MS / 1000) + "s)" +
    (authContext ? ", auth: " + authContext.auth_type : "") +
    "..."
  );

  // Execute in parallel batches.
  const results = await executeParallel(attackSuite.attack_suite, concurrency, authContext);

  // Aggregate statistics.
  let vulnerabilitiesFound = 0;
  let testsPassed = 0;
  let testsErrored = 0;

  for (const r of results) {
    if (!r.completed) {
      testsErrored++;
    } else if (r.vulnerable) {
      vulnerabilitiesFound++;
    } else {
      testsPassed++;
    }
  }

  const overallPass = vulnerabilitiesFound === 0;

  // Build summary.
  const summary = buildSummary(results, totalPayloads, vulnerabilitiesFound, testsPassed, testsErrored, overallPass);

  return {
    results,
    vulnerabilitiesFound,
    testsPassed,
    testsErrored,
    overallPass,
    summary,
  };
}

// ─── Auth Token Resolution (Fix #2) ──────────────────────────────────────────────

/**
 * Resolve an AuthContext from the config's auth_seeding block.
 *
 * Runs the token_generation_command via shell and captures its stdout as the
 * token value. Returns null if auth_seeding is not configured or fails.
 */
function resolveAuthContext(config?: VibeGuardConfig): AuthContext | undefined {
  if (!config?.auth_seeding) return undefined;

  const { auth_type, token_generation_command, header_name, cookie_name, query_param_name } = config.auth_seeding;

  ui.muted("Generating sandbox auth token via: " + token_generation_command);

  let token: string;
  try {
    token = execSync(token_generation_command, {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: TOKEN_GEN_TIMEOUT_MS,
    }).trim();

    if (!token) {
      ui.warn("Auth token generation command returned empty output. Proceeding without auth.");
      return undefined;
    }
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    ui.warn("Auth token generation failed: " + msg + ". Proceeding without auth.");
    return undefined;
  }

  ui.ok("Sandbox token acquired (" + String(token.length) + " chars).");

  return {
    token,
    auth_type,
    header_name,
    cookie_name,
    query_param_name,
  };
}

// ─── Parallel Execution Engine ───────────────────────────────────────────────────

/**
 * Execute an array of payloads with a concurrency cap.
 *
 * Uses a simple worker-pool pattern: launch up to `concurrency` requests
 * simultaneously, and as each completes, launch the next. This keeps the
 * server under controlled load without a dependency on a concurrency library.
 *
 * Fix #3: The concurrency cap is now configurable (default 3) instead of
 * hardcoded at 8, preventing self-DoS against lightweight local dev servers.
 */
async function executeParallel(
  payloads: AttackPayload[],
  concurrency: number,
  authContext?: AuthContext
): Promise<ExecutionResult[]> {
  const results: ExecutionResult[] = new Array(payloads.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < payloads.length) {
      const index = nextIndex++;
      results[index] = await executeOne(payloads[index], authContext);
    }
  }

  // Launch the worker pool.
  const workers: Promise<void>[] = [];
  const poolSize = Math.min(concurrency, payloads.length);
  for (let i = 0; i < poolSize; i++) {
    workers.push(worker());
  }

  await Promise.all(workers);
  return results;
}

// ─── Single Payload Execution ────────────────────────────────────────────────────

/**
 * Execute a single adversarial payload against its target URL.
 *
 * Formats the request based on HTTP method:
 *   GET  → query string parameters
 *   POST → application/x-www-form-urlencoded body
 *
 * Includes a strict timeout and captures response metadata for assertion.
 */
async function executeOne(
  payload: AttackPayload,
  authContext?: AuthContext
): Promise<ExecutionResult> {
  const startTime = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let statusCode: number | null = null;
  let responseBody = "";
  let responseHeaders: Record<string, string> = {};
  let completed = false;
  let error: string | null = null;

  try {
    const { url, init } = buildRequest(payload, authContext);
    init.signal = controller.signal;

    const response = await fetch(url, init);
    clearTimeout(timer);
    completed = true;
    statusCode = response.status;

    // Capture headers.
    responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    // Capture body (first MAX_RESPONSE_BODY_CHARS characters).
    try {
      const text = await response.text();
      responseBody = text.slice(0, MAX_RESPONSE_BODY_CHARS);
    } catch {
      responseBody = "(could not read response body)";
    }
  } catch (err: unknown) {
    clearTimeout(timer);
    const name = (err as Error).name ?? "";

    if (name === "AbortError") {
      error = "Request timed out after " + String(REQUEST_TIMEOUT_MS / 1000) + "s.";
    } else {
      error = (err as Error).message ?? String(err);
    }
  }

  const latencyMs = Date.now() - startTime;

  // Evaluate security assertions on the response.
  const assertions: AssertionVerdict[] = completed
    ? evaluateResponse(statusCode, responseBody, payload, responseHeaders)
    : [];

  return {
    payload,
    statusCode,
    completed,
    latencyMs,
    responseBody,
    responseHeaders,
    error,
    assertions,
    vulnerable: isVulnerable(assertions),
  };
}

// ─── Summary Builder ─────────────────────────────────────────────────────────────

function buildSummary(
  results: ExecutionResult[],
  total: number,
  vulnerabilitiesFound: number,
  testsPassed: number,
  testsErrored: number,
  overallPass: boolean
): string {
  const lines: string[] = [];

  lines.push(
    "Test run complete: " +
    String(total) + " payload(s) executed."
  );

  if (overallPass) {
    lines.push(
      "Result: ALL TESTS PASSED — no vulnerabilities confirmed."
    );
    lines.push(
      "  Passed: " + String(testsPassed) +
      " | Errored: " + String(testsErrored) +
      " | Vulnerable: 0"
    );
  } else {
    lines.push(
      "Result: VULNERABILITIES FOUND — " +
      String(vulnerabilitiesFound) + " test(s) confirmed security issues."
    );
    lines.push(
      "  Vulnerable: " + String(vulnerabilitiesFound) +
      " | Passed: " + String(testsPassed) +
      " | Errored: " + String(testsErrored)
    );
  }

  // Per-result details for vulnerable tests.
  if (vulnerabilitiesFound > 0) {
    lines.push("");
    lines.push("Vulnerable test details:");
    for (const r of results) {
      if (!r.vulnerable) continue;

      const url = r.payload.target_url;
      const method = r.payload.method;
      const attackType = r.payload.attack_type;
      const status = r.statusCode !== null ? String(r.statusCode) : "N/A";

      lines.push("  > " + attackType + " " + method + " " + url + " (HTTP " + status + ")");

      for (const a of r.assertions) {
        if (!a.triggered) continue;
        lines.push("    [" + a.category + "] " + a.detail);
        if (a.matched_signature) {
          lines.push("    Matched: \"" + a.matched_signature.slice(0, 100) + "\"");
        }
      }
    }
  }

  // Errored tests.
  if (testsErrored > 0) {
    lines.push("");
    lines.push("Failed executions:");
    for (const r of results) {
      if (r.completed) continue;
      lines.push(
        "  > " + r.payload.method + " " + r.payload.target_url +
        " — " + (r.error ?? "Unknown error")
      );
    }
  }

  return lines.join("\n");
}
