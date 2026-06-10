/**
 * VibeGuard - Automated Parallel Test Runner
 *
 * Reads the attack_suite generated in Phase 5, executes each payload as an
 * HTTP request against the local dev target, and returns structured execution
 * results for assertion evaluation.
 *
 * Design:
 *   - Parallel execution with a concurrency cap (8 concurrent requests).
 *   - Strict 3-second timeout per payload to prevent the git push from hanging
 *     indefinitely on slow or looping server handlers.
 *   - GET requests serialize payload_data into URL query strings.
 *   - POST requests send payload_data as application/x-www-form-urlencoded
 *     (traditional PHP/cPanel) with a fallback Content-Type detection heuristic.
 *   - Response bodies are captured (first 2000 chars) for signature scanning
 *     by the assertion engine.
 *
 * Zero runtime dependencies â€” uses only Node.js built-in fetch.
 */

import type {
  AttackSuite,
  AttackPayload,
  ExecutionResult,
  AssertionVerdict,
  TestReport,
} from "../core/types";
import { evaluateResponse, isVulnerable } from "./assertion";
import { buildRequest } from "../utils/http";
import * as ui from "../cli/ui";

// â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Maximum concurrent HTTP requests. */
const MAX_CONCURRENCY = 8;

/** Per-request timeout in milliseconds (3 seconds per spec). */
const REQUEST_TIMEOUT_MS = 3_000;

/** Maximum characters of response body to capture for signature scanning. */
const MAX_RESPONSE_BODY_CHARS = 2_000;

/** User-agent sent with test requests. */
const USER_AGENT = "VibeGuard/0.9.0 (adversarial-payload-test)";

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Execute the full attack suite against the local dev server.
 *
 * Runs payloads in parallel with a concurrency cap. Each payload is executed
 * as an HTTP request, the response is captured, and assertions are evaluated.
 *
 * @param attackSuite - The attack payloads from Phase 5.
 * @returns A TestReport aggregating all execution results and verdicts.
 */
export async function runTests(attackSuite: AttackSuite): Promise<TestReport> {
  if (attackSuite.attack_suite.length === 0) {
    return {
      results: [],
      vulnerabilitiesFound: 0,
      testsPassed: 0,
      testsErrored: 0,
      overallPass: true,
      summary: "No payloads to execute â€” skipping test run.",
    };
  }

  const totalPayloads = attackSuite.attack_suite.length;
  ui.action(
    "Executing " + String(totalPayloads) + " payload(s) against local server " +
    "(concurrency: " + String(MAX_CONCURRENCY) + ", timeout: " +
    String(REQUEST_TIMEOUT_MS / 1000) + "s)..."
  );

  // Execute in parallel batches.
  const results = await executeParallel(attackSuite.attack_suite, MAX_CONCURRENCY);

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

// â”€â”€â”€ Parallel Execution Engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Execute an array of payloads with a concurrency cap.
 *
 * Uses a simple worker-pool pattern: launch up to `concurrency` requests
 * simultaneously, and as each completes, launch the next. This keeps the
 * server under controlled load without a dependency on a concurrency library.
 */
async function executeParallel(
  payloads: AttackPayload[],
  concurrency: number
): Promise<ExecutionResult[]> {
  const results: ExecutionResult[] = new Array(payloads.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < payloads.length) {
      const index = nextIndex++;
      results[index] = await executeOne(payloads[index]);
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

// â”€â”€â”€ Single Payload Execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Execute a single adversarial payload against its target URL.
 *
 * Formats the request based on HTTP method:
 *   GET  â†’ query string parameters
 *   POST â†’ application/x-www-form-urlencoded body
 *
 * Includes a strict timeout and captures response metadata for assertion.
 */
async function executeOne(payload: AttackPayload): Promise<ExecutionResult> {
  const startTime = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let statusCode: number | null = null;
  let responseBody = "";
  let responseHeaders: Record<string, string> = {};
  let completed = false;
  let error: string | null = null;

  try {
    const { url, init } = buildRequest(payload);
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

// â”€â”€â”€ Summary Builder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
      "Result: ALL TESTS PASSED â€” no vulnerabilities confirmed."
    );
    lines.push(
      "  Passed: " + String(testsPassed) +
      " | Errored: " + String(testsErrored) +
      " | Vulnerable: 0"
    );
  } else {
    lines.push(
      "Result: VULNERABILITIES FOUND â€” " +
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
        " â€” " + (r.error ?? "Unknown error")
      );
    }
  }

  return lines.join("\n");
}
