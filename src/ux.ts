/**
 * VibeGuard — Terminal UX & Presentation Engine
 *
 * Phase 8: Builds high-contrast, minimalist terminal reports on top of the
 * low-level ui.ts primitives. Implements structured layouts for:
 *
 *   · Section dividers with optional labels
 *   · Aligned key-value tables
 *   · Threat cards (vulnerability details)
 *   · Patch cards (Phase 7 remediation)
 *   · Failure report (blocked push — full forensic display)
 *   · Success shield (passed push — minimalist confirmation)
 *
 * Design language:
 *   · White/bold     — headers, severity labels, primary actions
 *   · Muted gray     — file paths, metadata, secondary info
 *   · Red            — vulnerability warnings, blocked status, attack vectors
 *   · Green          — success confirmation, patches
 *   · Yellow         — warnings, errors
 *   · Cyan           — HTTP methods, URLs
 *
 * All output uses standard ANSI escape codes. No box-drawing Unicode that
 * might break in restricted SSH or VS Code terminal sessions.
 */

import type {
  AnalysisVerdict,
  TestReport,
  ExecutionResult,
  PatchResult,
  VulnerabilityVector,
} from "./types";

// ─── ANSI Style Constants ──────────────────────────────────────────────────────

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const WHITE = "\x1b[97m";
const GRAY = "\x1b[90m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const R = "\x1b[0m";

/** Terminal width — clamped to a safe maximum for readability. */
const TERM_WIDTH = Math.min(process.stdout.columns ?? 80, 100);

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Render the full failure report when a push is blocked.
 *
 * Displays a structured forensic summary:
 *   1. Blocked banner
 *   2. Per-vulnerability threat cards (file, endpoint, payload, signature, verdict)
 *   3. Per-vulnerability patch cards (Phase 7 remediation)
 *   4. Actionable footer with bypass instructions
 *
 * @param verdict       - Phase 2 LLM analysis verdict.
 * @param testReport    - Phase 6 test execution report.
 * @param patchResults  - Phase 7 patch generation results.
 * @param analysisPassed - Whether LLM analysis passed.
 */
export function renderFailureReport(
  verdict: AnalysisVerdict,
  testReport: TestReport,
  patchResults: PatchResult[],
  analysisPassed: boolean
): void {
  const vulnerableResults = testReport.results.filter((r) => r.vulnerable);
  const successPatches = patchResults.filter((p) => p.success);

  // ── Blocked Banner ──────────────────────────────────────────────────
  write("");
  write(divider());
  write(
    BOLD + WHITE + "  PUSH BLOCKED" + R +
    GRAY + " — Security Vulnerability Detected" + R
  );
  write(divider());
  write("");

  // ── Pre-failure context ─────────────────────────────────────────────
  if (!analysisPassed) {
    write(
      GRAY + "  " + BOLD + "LLM Analysis:" + R +
      GRAY + " High-severity vulnerability vectors detected in code diff." + R
    );
  }

  if (testReport.vulnerabilitiesFound > 0) {
    write(
      GRAY + "  " + BOLD + "Live Tests:" + R +
      GRAY + " " + String(testReport.vulnerabilitiesFound) +
      " payload(s) confirmed " + RED + "exploitable" + R +
      GRAY + " vulnerability/ies." + R
    );
  }

  write("");

  // ── Threat Cards ────────────────────────────────────────────────────
  for (let i = 0; i < vulnerableResults.length; i++) {
    const vr = vulnerableResults[i];
    const threatNum = i + 1;
    const totalThreats = vulnerableResults.length;

    renderThreatCard(vr, threatNum, totalThreats);

    // Find associated patch if any.
    const associatedPatch = successPatches.find(
      (p) => p.vulnerabilityType === vr.payload.attack_type
    );
    if (associatedPatch) {
      renderPatchCard(associatedPatch);
    }

    write("");
  }

  // ── Patch Summary ───────────────────────────────────────────────────
  if (successPatches.length > 0) {
    write(divider("Remediation Available"));
    write("");
    write(
      GRAY + "  " + String(successPatches.length) +
      " self-healing patch(es) written to " +
      WHITE + ".vibeguard/patches/" + R
    );
    write("");
    write(GRAY + "  Review:" + R + "  cat .vibeguard/patches/<file>.patch");
    write(GRAY + "  Apply:" + R + "   git apply .vibeguard/patches/<file>.patch");
    write(GRAY + "  Dry run:" + R + " git apply --stat .vibeguard/patches/<file>.patch");
    write("");
    write(divider());
  } else {
    write(divider());
  }

  // ── Footer ──────────────────────────────────────────────────────────
  write("");
  write(
    GRAY + "  Result:" + R +
    " " + String(testReport.vulnerabilitiesFound) + " vulnerability/ies" +
    " confirmed across " + String(vulnerableResults.length) + " endpoint(s)"
  );
  write(GRAY + "  Action:" + R + " Fix the issues above before pushing.");
  write("");

  if (successPatches.length > 0) {
    write(
      GRAY + "  Tip:" + R +
      " Apply the patches above, review the changes, commit, and push again."
    );
    write("");
  }

  write(GRAY + "  Bypass (NOT RECOMMENDED):" + R + " git push --no-verify");
  write("");
  write(divider());
}

/**
 * Render the minimalist success confirmation when all checks pass.
 *
 * Keeps the footprint tiny — the user's focus returns instantly to the
 * native git push stream.
 */
export function renderSuccessReport(): void {
  write("");
  write(
    BOLD + WHITE + divider() + R
  );
  write(
    "  " + GREEN + BOLD + "✓" + R +
    "  " + WHITE + "VibeGuard" + R +
    GRAY + " · All security checks passed · push allowed" + R
  );
  write(
    BOLD + WHITE + divider() + R
  );
  write("");
}

// ─── Threat Card ───────────────────────────────────────────────────────────────

/**
 * Render a single threat card showing the forensic details of a confirmed
 * vulnerability.
 *
 * Layout:
 *   Threat #N/TOTAL  ·  VECTOR  ·  SEVERITY
 *   ─────────────────────────────────────────
 *     File:       path/to/file.ext
 *     Endpoint:   METHOD http://...
 *     Payload:    key=malicious_value
 *     Signature:  matched error pattern
 *     Verdict:    VULNERABLE · HTTP 500 · 42ms
 */
function renderThreatCard(
  vr: ExecutionResult,
  num: number,
  total: number
): void {
  const severity = vectorSeverityLabel(vr.payload.attack_type);
  const sevColor = severity === "CRITICAL" || severity === "HIGH" ? RED : YELLOW;

  // Find the primary triggered assertion.
  const triggered = vr.assertions.find((a) => a.triggered);

  // ── Card Header ────────────────────────────────────────────────────
  write(
    "  " + BOLD + WHITE + "Threat #" + String(num) + "/" + String(total) + R +
    GRAY + "  ·  " + R +
    RED + vr.payload.attack_type + R +
    GRAY + "  ·  " + R +
    sevColor + BOLD + severity + R
  );
  write(GRAY + "  " + "─".repeat(Math.min(TERM_WIDTH - 4, 74)) + R);

  // ── Card Body ──────────────────────────────────────────────────────
  // File path
  write(
    GRAY + "    File:" + R +
    "       " + WHITE + vr.payload.target_url.replace(/\/+$/, "") + R
  );

  // Endpoint
  write(
    GRAY + "    Endpoint:" + R +
    "   " + CYAN + vr.payload.method + R + " " + vr.payload.target_url
  );

  // Payload data (first 2 params).
  const paramEntries = Object.entries(vr.payload.payload_data);
  if (paramEntries.length > 0) {
    write(GRAY + "    Payload:" + R);
    const show = paramEntries.slice(0, 3);
    for (const [key, value] of show) {
      const truncated = value.length > 60 ? value.slice(0, 57) + "..." : value;
      write(GRAY + "              " + R + key + GRAY + " = " + R + RED + truncated + R);
    }
    if (paramEntries.length > 3) {
      write(
        GRAY + "              " + R +
        GRAY + "(+" + String(paramEntries.length - 3) + " more parameters)" + R
      );
    }
  }

  // Matched signature.
  if (triggered && triggered.matched_signature) {
    const sig = triggered.matched_signature.length > 100
      ? triggered.matched_signature.slice(0, 97) + "..."
      : triggered.matched_signature;
    write(
      GRAY + "    Signature:" + R +
      "  " + YELLOW + sig + R
    );
  } else if (triggered) {
    const detail = triggered.detail.length > 100
      ? triggered.detail.slice(0, 97) + "..."
      : triggered.detail;
    write(
      GRAY + "    Signature:" + R +
      "  " + YELLOW + detail + R
    );
  }

  // Verdict line.
  const statusCode = vr.statusCode !== null ? String(vr.statusCode) : "N/A";
  write(
    GRAY + "    Verdict:" + R +
    "    " + RED + BOLD + "VULNERABLE" + R +
    GRAY + " · HTTP " + statusCode + " · " + String(vr.latencyMs) + "ms" + R
  );

  // Additional assertion details.
  if (triggered && triggered.category !== "none") {
    const categoryLabel =
      triggered.category === "status_code" ? "Status Code"
      : triggered.category === "database_leak" ? "Database Leak"
      : triggered.category === "auth_bypass" ? "Auth Bypass"
      : triggered.category;
    write(
      GRAY + "    Category:" + R +
      "  " + YELLOW + categoryLabel + R
    );
  }
}

// ─── Patch Card ────────────────────────────────────────────────────────────────

/**
 * Render a patch card showing the Phase 7 remediation details beneath its
 * associated threat card.
 *
 * Layout:
 *   ── Patch ────────────────────────────────────
 *     ✓  .vibeguard/patches/file.patch
 *        Explanation of the fix.
 *        Review:  cat ...
 *        Apply:   git apply ...
 */
function renderPatchCard(patch: PatchResult): void {
  write("");
  write(GRAY + "  " + "─".repeat(Math.min(TERM_WIDTH - 4, 36)) + " Patch " + "─".repeat(Math.min(TERM_WIDTH - 4, 34)) + R);
  write("");
  write(
    "    " + GREEN + BOLD + "✓" + R +
    "  " + WHITE + (patch.patchPath ?? "unknown") + R
  );
  write("");

  if (patch.explanation) {
    // Word-wrap the explanation at ~70 chars.
    const words = patch.explanation.split(/\s+/);
    let line = GRAY + "       " + R;
    for (const word of words) {
      const stripped = line.replace(/\x1b\[[0-9;]*m/g, "");
      if (stripped.length + word.length + 1 > 74) {
        write(line);
        line = GRAY + "       " + R + word;
      } else {
        line += (line.replace(/\x1b\[[0-9;]*m/g, "").length > 7 ? " " : "") + word;
      }
    }
    if (line.replace(/\x1b\[[0-9;]*m/g, "").length > 7) {
      write(line);
    }
    write("");
  }

  write(GRAY + "       Review:" + R + "  cat " + (patch.patchPath ?? ".vibeguard/patches/<file>.patch"));
  write(GRAY + "       Apply:" + R + "   git apply " + (patch.patchPath ?? ".vibeguard/patches/<file>.patch"));
}

// ─── Section Divider ───────────────────────────────────────────────────────────

/**
 * Render a horizontal section divider, optionally with a centered label.
 *
 * When no label is given, produces a full-width thin rule.
 * When a label is given, the label is centered within the rule.
 *
 * Examples:
 *   ────────────────────────────────────────────
 *   ─────────────── Section Name ───────────────
 *
 * @param label - Optional text to center within the divider.
 */
function divider(label?: string): string {
  const width = Math.min(TERM_WIDTH, 80);

  if (!label) {
    return GRAY + DIM + "─".repeat(width) + R;
  }

  const labelText = " " + label + " ";
  const remaining = width - labelText.length;
  const leftPad = Math.floor(remaining / 2);
  const rightPad = remaining - leftPad;

  return (
    GRAY + DIM + "─".repeat(Math.max(leftPad, 0)) + R +
    WHITE + labelText + R +
    GRAY + DIM + "─".repeat(Math.max(rightPad, 0)) + R
  );
}

// ─── Key-Value Table ───────────────────────────────────────────────────────────

/**
 * Render an aligned key-value table.
 *
 * Keys are right-aligned in muted gray; values are left-aligned in white.
 * The key column is padded to the width of the longest key.
 *
 * Example:
 *     Provider:  custom
 *     Endpoint:  http://localhost:11434/v1
 *       Model:  llama3.1:8b
 *
 * @param rows  - Array of [key, value] pairs.
 * @param indent - Number of leading spaces (default 2).
 */
export function renderKeyValueTable(
  rows: Array<[string, string]>,
  indent: number = 2
): void {
  if (rows.length === 0) return;

  const maxKeyLen = Math.max(...rows.map(([k]) => k.length));
  const prefix = " ".repeat(indent);

  for (const [key, value] of rows) {
    const paddedKey = key.padStart(maxKeyLen);
    write(
      prefix + GRAY + paddedKey + ":" + R + "  " + WHITE + value + R
    );
  }
}

// ─── Phase Header ──────────────────────────────────────────────────────────────

/**
 * Render a phase section header with consistent styling.
 *
 * Example:
 *   ── Phase 2: LLM Analysis ─────────────────────
 *
 * @param phase - Phase number.
 * @param title - Human-readable phase title.
 */
export function renderPhaseHeader(phase: number, title: string): void {
  write("");
  write(divider("Phase " + String(phase) + ": " + title));
}

// ─── Status Line Helpers ───────────────────────────────────────────────────────

/**
 * Render an in-progress action line.
 *   →  Doing something...
 */
export function renderAction(msg: string): void {
  write(WHITE + "→  " + msg + R);
}

/**
 * Render a success status line.
 *   ✓  Done
 */
export function renderSuccess(msg: string): void {
  write(GREEN + "✓  " + msg + R);
}

/**
 * Render a failure status line.
 *   ✕  Reason
 */
export function renderFailure(msg: string): void {
  write(RED + "✕  " + msg + R);
}

/**
 * Render a warning line.
 *   !  Warning message
 */
export function renderWarning(msg: string): void {
  write(YELLOW + "!  " + msg + R);
}

/**
 * Render a muted informational line.
 *   (gray) Some context info
 */
export function renderInfo(msg: string): void {
  write(GRAY + msg + R);
}

// ─── Internal Helpers ──────────────────────────────────────────────────────────

/**
 * Map a vulnerability vector to a severity label.
 */
function vectorSeverityLabel(v: VulnerabilityVector): string {
  switch (v) {
    case "rce":
    case "auth_bypass":
      return "CRITICAL";
    case "sql_injection":
    case "privilege_escalation":
    case "deserialization":
      return "HIGH";
    case "ssrf":
    case "path_traversal":
    case "idor":
    case "information_disclosure":
      return "MEDIUM";
    case "xss":
    case "input_fuzzing":
    case "misconfiguration":
    case "race_condition":
      return "LOW";
    case "other":
      return "MEDIUM";
  }
}

/**
 * Write a line to stdout. Thin wrapper so the module doesn't need ui.ts.
 */
function write(line: string): void {
  process.stdout.write(line + "\n");
}
