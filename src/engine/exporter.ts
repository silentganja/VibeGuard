/**
 * VibeGuard — Automated Regression Test Exporter
 *
 * Phase 14: Converts confirmed adversarial vulnerabilities into permanent,
 * runnable integration test files to prevent future regressions.
 *
 * Design:
 *   · Framework-agnostic: supports Jest (Node/TS) and Bash (universal cURL).
 *   · Each generated test encodes the exact payload that broke the endpoint
 *     and asserts the application now correctly rejects or sanitizes it.
 *   · Files written to the configured export_tests_dir with timestamped names.
 *   · Auto-staged via `git add` so the fix commit includes the regression test.
 *
 * Zero runtime dependencies — uses Node.js built-ins and child_process.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import type { ExecutionResult, VibeGuardConfig } from "../core/types";
import * as ui from "../cli/ui";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** Prefix for generated regression test filenames. */
const FILE_PREFIX = "vg_regression_";

/** Maximum payload value length in generated tests (chars). */
const MAX_PAYLOAD_VALUE_LEN = 200;

// ─── Public Types ───────────────────────────────────────────────────────────────

/** Context needed to generate a single regression test. */
export interface ExportContext {
  /** The vulnerable execution result. */
  result: ExecutionResult;
  /** The project root directory. */
  projectRoot: string;
  /** Configured test framework. */
  framework: "jest" | "bash";
  /** Target directory for test output. */
  testsDir: string;
}

/** Result of a test export operation. */
export interface ExportResult {
  /** Whether the test file was successfully written. */
  success: boolean;
  /** Absolute path to the generated test file. */
  filePath: string | null;
  /** Human-readable description of what was generated. */
  summary: string;
  /** Error message if generation failed. */
  error: string | null;
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Export regression tests for all confirmed vulnerabilities in a test report.
 *
 * For each vulnerable result, generates a framework-specific test file
 * and writes it to the configured export directory. Files are NOT
 * generated in CI/CD mode — test export is a local development feature.
 *
 * @param config     - Validated VibeGuard configuration.
 * @param results    - Array of vulnerable execution results.
 * @param projectRoot - Absolute path to the project root.
 * @returns Array of ExportResults, one per generated test.
 */
export function exportRegressionTests(
  config: VibeGuardConfig,
  results: ExecutionResult[],
  projectRoot: string
): ExportResult[] {
  const enabled = config.export_tests_enabled ?? true;
  if (!enabled) {
    return [];
  }

  const framework = config.export_tests_framework ?? "bash";
  const testsDir = path.join(projectRoot, config.export_tests_dir ?? ".vibeguard/tests");

  // Ensure the test directory exists.
  ensureDir(testsDir);

  const exportResults: ExportResult[] = [];

  for (const r of results) {
    const result = exportOne(r, framework, testsDir, projectRoot);
    exportResults.push(result);
  }

  return exportResults;
}

/**
 * Generate and write a single regression test file.
 */
function exportOne(
  result: ExecutionResult,
  framework: "jest" | "bash",
  testsDir: string,
  projectRoot: string
): ExportResult {
  const timestamp = Date.now();
  const ext = framework === "jest" ? ".test.js" : ".sh";
  const fileName = FILE_PREFIX + String(timestamp) + ext;
  const filePath = path.join(testsDir, fileName);

  let content: string;
  try {
    content = framework === "jest"
      ? generateJestTest(result)
      : generateBashTest(result);
  } catch (err: unknown) {
    return {
      success: false,
      filePath: null,
      summary: "Failed to generate test content.",
      error: (err as Error).message ?? String(err),
    };
  }

  try {
    fs.writeFileSync(filePath, content, "utf-8");
    // Make shell scripts executable on Unix.
    if (framework === "bash" && process.platform !== "win32") {
      try { fs.chmodSync(filePath, 0o755); } catch { /* best-effort */ }
    }
  } catch (err: unknown) {
    return {
      success: false,
      filePath: null,
      summary: "Failed to write test file.",
      error: (err as Error).message ?? String(err),
    };
  }

  // Auto-stage the file so it's included in the next commit.
  const staged = stageFile(filePath, projectRoot);

  return {
    success: true,
    filePath,
    summary: staged
      ? "Regression test generated and staged: " + path.relative(projectRoot, filePath)
      : "Regression test generated (staging skipped): " + path.relative(projectRoot, filePath),
    error: null,
  };
}

// ─── Jest Test Generator ───────────────────────────────────────────────────────

/**
 * Generate a Jest test block that asserts the endpoint correctly rejects
 * the adversarial payload that previously broke through.
 *
 * The test validates that the application now returns a safe status code
 * (401, 403, or 400) instead of the vulnerable response (200 or 500).
 *
 * Uses native `fetch` for zero-dependency compatibility.
 */
function generateJestTest(result: ExecutionResult): string {
  const payload = result.payload;
  const triggered = result.assertions.find((a) => a.triggered);
  const endpoint = payload.target_url;
  const method = payload.method;
  const attackType = payload.attack_type;
  const safeStatuses = getSafeStatusCodes(attackType);

  const lines: string[] = [];

  lines.push("/**");
  lines.push(" * VibeGuard Regression Test — Auto-generated");
  lines.push(" *");
  lines.push(" * Vulnerability: " + attackType);
  lines.push(" * Endpoint:      " + method + " " + endpoint);
  lines.push(" * Generated:     " + new Date().toISOString());
  lines.push(" *");
  lines.push(" * This test encodes the exact payload that previously exploited");
  lines.push(" * this endpoint. It asserts the application now correctly rejects");
  lines.push(" * or sanitizes the malicious input.");
  lines.push(" */");
  lines.push("");
  lines.push("const TARGET_URL = " + JSON.stringify(endpoint) + ";");
  lines.push("");

  // Build the payload data as a JS object.
  if (Object.keys(payload.payload_data).length > 0) {
    lines.push("const MALICIOUS_PAYLOAD = {");
    for (const [key, value] of Object.entries(payload.payload_data)) {
      const truncated = value.length > MAX_PAYLOAD_VALUE_LEN
        ? value.slice(0, MAX_PAYLOAD_VALUE_LEN - 3) + "..."
        : value;
      lines.push("  " + JSON.stringify(key) + ": " + JSON.stringify(truncated) + ",");
    }
    lines.push("};");
  } else {
    lines.push("const MALICIOUS_PAYLOAD = {};");
  }
  lines.push("");

  // Describe block.
  const describeName = method + " " + new URL(endpoint).pathname;
  lines.push("describe('VibeGuard Regression: " + escapeJsString(attackType) + "', () => {");
  lines.push("  it('should reject " + escapeJsString(attackType) + " payload on " + escapeJsString(describeName) + "', async () => {");

  // Build the fetch call.
  if (method === "GET") {
    const params = new URLSearchParams(payload.payload_data).toString();
    const getUrl = params ? endpoint + "?" + params : endpoint;
    lines.push("    const response = await fetch(" + JSON.stringify(getUrl) + ", {");
    lines.push("      method: 'GET',");
    lines.push("      headers: { 'Accept': '*/*' },");
    lines.push("      redirect: 'manual',");
    lines.push("    });");
  } else {
    lines.push("    const response = await fetch(TARGET_URL, {");
    lines.push("      method: 'POST',");
    lines.push("      headers: {");
    lines.push("        'Content-Type': 'application/x-www-form-urlencoded',");
    lines.push("        'Accept': '*/*',");
    lines.push("      },");
    lines.push("      body: new URLSearchParams(MALICIOUS_PAYLOAD).toString(),");
    lines.push("      redirect: 'manual',");
    lines.push("    });");
  }
  lines.push("");

  // Assertions.
  lines.push("    // The application must reject this payload with a safe status code.");
  lines.push("    // Vulnerable: 200 (bypass) or 500 (server crash).");
  lines.push("    // Safe:        400 (bad request), 401 (unauthorized), 403 (forbidden), 422 (validation).");
  lines.push("    const safeStatuses = " + JSON.stringify(safeStatuses) + ";");
  lines.push("    expect(safeStatuses).toContain(response.status);");
  lines.push("");

  // Additional assertion: no database errors in response.
  lines.push("    // Verify the response body does not leak database errors.");
  lines.push("    const body = await response.text();");
  lines.push("    expect(body).not.toMatch(/SQL syntax|SQLSTATE|PDOException|stack trace/i);");
  lines.push("  });");
  lines.push("});");
  lines.push("");

  return lines.join("\n");
}

/**
 * Determine which HTTP status codes are considered "safe" for a given
 * vulnerability type. These are the codes the application should return
 * after the vulnerability is patched.
 */
function getSafeStatusCodes(attackType: string): number[] {
  switch (attackType) {
    case "auth_bypass":
    case "privilege_escalation":
      return [401, 403];        // Must be rejected as unauthorized.
    case "idor":
      return [401, 403, 404];   // Should not expose other users' data.
    case "sql_injection":
    case "xss":
    case "rce":
    case "input_fuzzing":
    case "path_traversal":
    case "ssrf":
    case "deserialization":
      return [400, 422];        // Should be caught by input validation.
    default:
      return [400, 401, 403, 422];
  }
}

// ─── Bash Test Generator ────────────────────────────────────────────────────────

/**
 * Generate a bash script that uses cURL to replay the adversarial payload
 * and exits with code 1 if the vulnerability is still present.
 *
 * The script checks both the HTTP status code AND the response body for
 * signs of a successful exploit (stack traces, DB errors, auth bypass).
 */
function generateBashTest(result: ExecutionResult): string {
  const payload = result.payload;
  const triggered = result.assertions.find((a) => a.triggered);
  const endpoint = payload.target_url;
  const method = payload.method;
  const attackType = payload.attack_type;
  const safeStatuses = getSafeStatusCodes(attackType);
  const safeStatusPattern = safeStatuses.join("|");

  const lines: string[] = [];

  lines.push("#!/usr/bin/env bash");
  lines.push("# ──────────────────────────────────────────────────");
  lines.push("#  VibeGuard Regression Test — Auto-generated");
  lines.push("#");
  lines.push("#  Vulnerability: " + attackType);
  lines.push("#  Endpoint:      " + method + " " + endpoint);
  lines.push("#  Generated:     " + new Date().toISOString());
  lines.push("#");
  lines.push("#  This script replays the exact payload that previously");
  lines.push("#  exploited this endpoint. It exits 0 if the application");
  lines.push("#  now correctly rejects the payload, or 1 if the");
  lines.push("#  vulnerability is still present.");
  lines.push("# ──────────────────────────────────────────────────");
  lines.push("");
  lines.push("set -euo pipefail");
  lines.push("");
  lines.push("TARGET_URL=\"" + escapeBashString(endpoint) + "\"");
  lines.push("");

  // Build the cURL command.
  if (method === "GET") {
    const params = Object.entries(payload.payload_data)
      .map(([k, v]) => escapeBashString(k) + "=" + escapeBashString(v))
      .join("&");
    const getUrl = params ? endpoint + "?" + params : endpoint;
    lines.push("# Execute the adversarial GET request.");
    lines.push("response=$(curl -s -w '\\n%{http_code}' \\");
    lines.push("  -X GET \\");
    lines.push("  --max-time 5 \\");
    lines.push("  -H 'Accept: */*' \\");
    lines.push("  \"" + escapeBashString(getUrl) + "\")");
  } else {
    lines.push("# Execute the adversarial POST request.");
    lines.push("response=$(curl -s -w '\\n%{http_code}' \\");
    lines.push("  -X POST \\");
    lines.push("  --max-time 5 \\");
    lines.push("  -H 'Content-Type: application/x-www-form-urlencoded' \\");
    lines.push("  -H 'Accept: */*' \\");

    // Add each payload parameter as a -d flag.
    for (const [key, value] of Object.entries(payload.payload_data)) {
      const truncated = value.length > MAX_PAYLOAD_VALUE_LEN
        ? value.slice(0, MAX_PAYLOAD_VALUE_LEN - 3) + "..."
        : value;
      lines.push("  -d '" + escapeBashString(key) + "=" + escapeBashString(truncated) + "' \\");
    }

    // Remove trailing backslash from last line.
    const lastLine = lines[lines.length - 1];
    lines[lines.length - 1] = lastLine.replace(/ \\$/, "");
    lines.push("  \"" + escapeBashString(endpoint) + "\")");
  }

  lines.push("");
  lines.push("# Extract HTTP status code (last line of response).");
  lines.push("http_code=$(echo \"$response\" | tail -n1)");
  lines.push("body=$(echo \"$response\" | sed '$d')");
  lines.push("");
  lines.push("echo \"→  " + method + " " + endpoint + "\"");
  lines.push("echo \"   HTTP Status: $http_code\"");
  lines.push("");

  // Check status code.
  lines.push("# Check: the application must return a safe status code.");
  lines.push("safe_pattern='^(" + safeStatusPattern + ")$'");
  lines.push("if ! [[ \"$http_code\" =~ $safe_pattern ]]; then");
  lines.push("  echo \"✕  FAIL: Expected " + safeStatuses.join("/") + ", got $http_code\"");
  lines.push("  echo \"   The " + attackType + " payload still triggers a vulnerable response.\"");
  lines.push("  exit 1");
  lines.push("fi");
  lines.push("");

  // Check response body for leak signatures.
  lines.push("# Check: response body must not leak database errors or stack traces.");
  lines.push("if echo \"$body\" | grep -qiE '(SQL syntax|SQLSTATE|PDOException|stack trace|Fatal error|Uncaught)'; then");
  lines.push("  echo \"✕  FAIL: Response body contains database error or stack trace.\"");
  lines.push("  echo \"   Information disclosure vulnerability still present.\"");
  lines.push("  exit 1");
  lines.push("fi");
  lines.push("");

  // Check for auth bypass specifically.
  if (attackType === "auth_bypass" || attackType === "privilege_escalation") {
    lines.push("# Check: response must not indicate successful admin access.");
    lines.push("if echo \"$body\" | grep -qiE '(welcome.*admin|admin.*panel|dashboard|superuser|access_token)'; then");
    lines.push("  echo \"✕  FAIL: Response suggests privileged access was granted.\"");
    lines.push("  echo \"   Auth bypass vulnerability still present.\"");
    lines.push("  exit 1");
    lines.push("fi");
    lines.push("");
  }

  lines.push("echo \"✓  PASS: Application correctly rejects " + attackType + " payload.\"");
  lines.push("exit 0");
  lines.push("");

  return lines.join("\n");
}

// ─── Git Auto-Staging ──────────────────────────────────────────────────────────

/**
 * Stage a generated test file so it's included in the next commit.
 *
 * Uses `git add` from the project root. Failures are non-blocking —
 * the developer can always stage manually.
 *
 * @param filePath    - Absolute path to the generated test file.
 * @param projectRoot - Absolute path to the project root.
 * @returns true if the file was successfully staged.
 */
function stageFile(filePath: string, projectRoot: string): boolean {
  try {
    execSync("git add " + escapeShellArg(filePath), {
      cwd: projectRoot,
      encoding: "utf-8",
      stdio: "pipe",
      timeout: 5_000,
    });
    return true;
  } catch {
    // Best-effort — the file was still written.
    return false;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

function ensureDir(dir: string): void {
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch {
    // Directory already exists — ignore.
  }
}

/** Escape a string for safe inclusion in a JavaScript string literal. */
function escapeJsString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/\n/g, "\\n");
}

/** Escape a string for safe inclusion in a bash double-quoted string. */
function escapeBashString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "\\$").replace(/`/g, "\\`");
}

/** Escape a file path for shell argument passing. */
function escapeShellArg(arg: string): string {
  if (process.platform === "win32") {
    return '"' + arg.replace(/"/g, '\\"') + '"';
  }
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}
