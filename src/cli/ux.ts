/**
 * VibeGuard â€” Terminal UX & Presentation Engine
 *
 * Phase 8: Builds high-contrast, minimalist terminal reports on top of the
 * low-level ui.ts primitives. Implements structured layouts for:
 *
 *   Â- Section dividers with optional labels
 *   Â- Aligned key-value tables
 *   Â- Threat cards (vulnerability details)
 *   Â- Patch cards (Phase 7 remediation)
 *   Â- Failure report (blocked push â€” full forensic display)
 *   Â- Success shield (passed push â€” minimalist confirmation)
 *
 * Design language:
 *   Â- White/bold     â€” headers, severity labels, primary actions
 *   Â- Muted gray     â€” file paths, metadata, secondary info
 *   Â- Red            â€” vulnerability warnings, blocked status, attack vectors
 *   Â- Green          â€” success confirmation, patches
 *   Â- Yellow         â€” warnings, errors
 *   Â- Cyan           â€” HTTP methods, URLs
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
} from "../core/types";
import { getOutputMode, detectCIPlatform } from "../compliance/ci";

// â”€â”€â”€ ANSI Style Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const WHITE = "\x1b[97m";
const GRAY = "\x1b[90m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const R = "\x1b[0m";

/** Terminal width â€” clamped to a safe maximum for readability. */
const TERM_WIDTH = Math.min(process.stdout.columns ?? 80, 100);

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
  // Dispatch to CI or terminal variant based on output mode.
  if (getOutputMode() === "ci") {
    renderFailureReportCI(verdict, testReport, patchResults, analysisPassed);
    return;
  }

  const vulnerableResults = testReport.results.filter((r) => r.vulnerable);
  const successPatches = patchResults.filter((p) => p.success);

  // â”€â”€ Blocked Banner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  write("");
  write(divider());
  write(
    BOLD + WHITE + "  PUSH BLOCKED" + R +
    GRAY + " â€” Security Vulnerability Detected" + R
  );
  write(divider());
  write("");

  // â”€â”€ Pre-failure context â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ Threat Cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ Patch Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ Footer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
 * Keeps the footprint tiny â€” the user's focus returns instantly to the
 * native git push stream.
 */
export function renderSuccessReport(): void {
  // Dispatch to CI or terminal variant based on output mode.
  if (getOutputMode() === "ci") {
    renderSuccessReportCI();
    return;
  }

  write("");
  write(
    BOLD + WHITE + divider() + R
  );
  write(
    "  " + GREEN + BOLD + "âœ“" + R +
    "  " + WHITE + "VibeGuard" + R +
    GRAY + " Â- All security checks passed Â- push allowed" + R
  );
  write(
    BOLD + WHITE + divider() + R
  );
  write("");
}

// â”€â”€â”€ CI/CD Machine-Readable Reports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Render a machine-readable failure report for CI/CD pipeline logs.
 *
 * Outputs a clean, parseable text breakdown of every vulnerability.
 * No ANSI colors, no box drawing â€” plain text suitable for log archival,
 * grep filtering, and CI pipeline log viewers.
 *
 * Format:
 *   [VibeGuard] PUSH BLOCKED â€” 2 vulnerability/ies confirmed
 *   [VibeGuard] Platform: GitHub Actions
 *   [VibeGuard]
 *   [VibeGuard] THREAT 1/2 | sql_injection | HIGH
 *   [VibeGuard]   URL:    POST http://localhost:8000/api/login.php
 *   [VibeGuard]   Payload: username=admin' OR '1'='1
 *   [VibeGuard]   Payload: password=anything' OR 1=1--
 *   [VibeGuard]   Signature: You have an error in your SQL syntax...
 *   [VibeGuard]   Status:  500 | 42ms
 *   [VibeGuard]
 *   [VibeGuard] RESULT: 2 vulnerability/ies found â€” build failed
 */
function renderFailureReportCI(
  verdict: AnalysisVerdict,
  testReport: TestReport,
  patchResults: PatchResult[],
  analysisPassed: boolean
): void {
  const vulnerableResults = testReport.results.filter((r) => r.vulnerable);
  const platform = detectCIPlatform() ?? "CI/CD";
  const successPatches = patchResults.filter((p) => p.success);

  // â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  writePlain("[VibeGuard] PUSH BLOCKED â€” " + String(testReport.vulnerabilitiesFound) + " vulnerability/ies confirmed");
  writePlain("[VibeGuard] Platform: " + platform);
  writePlain("[VibeGuard]");

  if (!analysisPassed) {
    writePlain("[VibeGuard] LLM Analysis: High-severity vulnerability vectors detected.");
  }

  writePlain("[VibeGuard] Live Tests: " + String(testReport.vulnerabilitiesFound) + " payload(s) confirmed exploitable.");
  writePlain("[VibeGuard]");

  // â”€â”€ Threat Cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  for (let i = 0; i < vulnerableResults.length; i++) {
    const vr = vulnerableResults[i];
    const severity = vectorSeverityLabel(vr.payload.attack_type);
    const triggered = vr.assertions.find((a) => a.triggered);

    writePlain(
      "[VibeGuard] THREAT " + String(i + 1) + "/" +
      String(vulnerableResults.length) + " | " +
      vr.payload.attack_type + " | " + severity
    );
    writePlain("[VibeGuard]   URL:       " + vr.payload.method + " " + vr.payload.target_url);

    // Payload data.
    for (const [key, value] of Object.entries(vr.payload.payload_data)) {
      const truncated = value.length > 100 ? value.slice(0, 97) + "..." : value;
      writePlain("[VibeGuard]   Payload:   " + key + "=" + truncated);
    }

    // Signature.
    if (triggered && triggered.matched_signature) {
      const sig = triggered.matched_signature.length > 120
        ? triggered.matched_signature.slice(0, 117) + "..."
        : triggered.matched_signature;
      writePlain("[VibeGuard]   Signature: " + sig);
    } else if (triggered) {
      const detail = triggered.detail.length > 120
        ? triggered.detail.slice(0, 117) + "..."
        : triggered.detail;
      writePlain("[VibeGuard]   Signature: " + detail);
    }

    // Status.
    const statusCode = vr.statusCode !== null ? String(vr.statusCode) : "N/A";
    writePlain("[VibeGuard]   Status:    " + statusCode + " | " + String(vr.latencyMs) + "ms");

    // Category.
    if (triggered && triggered.category !== "none") {
      writePlain("[VibeGuard]   Category:  " + triggered.category);
    }

    // Associated patch.
    const associatedPatch = successPatches.find(
      (p) => p.vulnerabilityType === vr.payload.attack_type
    );
    if (associatedPatch) {
      writePlain("[VibeGuard]   Patch:     " + (associatedPatch.patchPath ?? "N/A"));
      if (associatedPatch.explanation) {
        const expl = associatedPatch.explanation.length > 150
          ? associatedPatch.explanation.slice(0, 147) + "..."
          : associatedPatch.explanation;
        writePlain("[VibeGuard]   Fix:       " + expl);
      }
    }

    writePlain("[VibeGuard]");
  }

  // â”€â”€ Patch Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (successPatches.length > 0) {
    writePlain("[VibeGuard] PATCHES: " + String(successPatches.length) + " generated in .vibeguard/patches/");
    for (const p of successPatches) {
      writePlain("[VibeGuard]   " + (p.patchPath ?? "unknown"));
    }
    writePlain("[VibeGuard]");
  }

  // â”€â”€ Result â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  writePlain("[VibeGuard] RESULT: " + String(testReport.vulnerabilitiesFound) + " vulnerability/ies found â€” build failed");
  writePlain("[VibeGuard] " + String(testReport.testsPassed) + " passed | " + String(testReport.testsErrored) + " errored | " + String(testReport.vulnerabilitiesFound) + " vulnerable");
}

/**
 * Render a machine-readable success message for CI/CD pipeline logs.
 *
 * Minimal â€” one line confirming the security scan passed.
 */
function renderSuccessReportCI(): void {
  writePlain("[VibeGuard] PASS â€” All security checks passed.");
}

// â”€â”€â”€ Threat Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Render a single threat card showing the forensic details of a confirmed
 * vulnerability.
 *
 * Layout:
 *   Threat #N/TOTAL  Â-  VECTOR  Â-  SEVERITY
 *   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *     File:       path/to/file.ext
 *     Endpoint:   METHOD http://...
 *     Payload:    key=malicious_value
 *     Signature:  matched error pattern
 *     Verdict:    VULNERABLE Â- HTTP 500 Â- 42ms
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

  // â”€â”€ Card Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  write(
    "  " + BOLD + WHITE + "Threat #" + String(num) + "/" + String(total) + R +
    GRAY + "  Â-  " + R +
    RED + vr.payload.attack_type + R +
    GRAY + "  Â-  " + R +
    sevColor + BOLD + severity + R
  );
  write(GRAY + "  " + "â”€".repeat(Math.min(TERM_WIDTH - 4, 74)) + R);

  // â”€â”€ Card Body â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    GRAY + " Â- HTTP " + statusCode + " Â- " + String(vr.latencyMs) + "ms" + R
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

// â”€â”€â”€ Patch Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Render a patch card showing the Phase 7 remediation details beneath its
 * associated threat card.
 *
 * Layout:
 *   â”€â”€ Patch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *     âœ“  .vibeguard/patches/file.patch
 *        Explanation of the fix.
 *        Review:  cat ...
 *        Apply:   git apply ...
 */
function renderPatchCard(patch: PatchResult): void {
  write("");
  write(GRAY + "  " + "â”€".repeat(Math.min(TERM_WIDTH - 4, 36)) + " Patch " + "â”€".repeat(Math.min(TERM_WIDTH - 4, 34)) + R);
  write("");
  write(
    "    " + GREEN + BOLD + "âœ“" + R +
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

// â”€â”€â”€ Section Divider â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Render a horizontal section divider, optionally with a centered label.
 *
 * When no label is given, produces a full-width thin rule.
 * When a label is given, the label is centered within the rule.
 *
 * Examples:
 *   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Section Name â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * @param label - Optional text to center within the divider.
 */
function divider(label?: string): string {
  const width = Math.min(TERM_WIDTH, 80);

  if (!label) {
    return GRAY + DIM + "â”€".repeat(width) + R;
  }

  const labelText = " " + label + " ";
  const remaining = width - labelText.length;
  const leftPad = Math.floor(remaining / 2);
  const rightPad = remaining - leftPad;

  return (
    GRAY + DIM + "â”€".repeat(Math.max(leftPad, 0)) + R +
    WHITE + labelText + R +
    GRAY + DIM + "â”€".repeat(Math.max(rightPad, 0)) + R
  );
}

// â”€â”€â”€ Key-Value Table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€â”€ Phase Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Render a phase section header with consistent styling.
 *
 * Example:
 *   â”€â”€ Phase 2: LLM Analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * @param phase - Phase number.
 * @param title - Human-readable phase title.
 */
export function renderPhaseHeader(phase: number, title: string): void {
  write("");
  write(divider("Phase " + String(phase) + ": " + title));
}

// â”€â”€â”€ Status Line Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Render an in-progress action line.
 *   â†’  Doing something...
 */
export function renderAction(msg: string): void {
  write(WHITE + "â†’  " + msg + R);
}

/**
 * Render a success status line.
 *   âœ“  Done
 */
export function renderSuccess(msg: string): void {
  write(GREEN + "âœ“  " + msg + R);
}

/**
 * Render a failure status line.
 *   âœ•  Reason
 */
export function renderFailure(msg: string): void {
  write(RED + "âœ•  " + msg + R);
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


// Phase 14: Regression Test Export Notice

/**
 * Render a notice that regression tests were generated and auto-staged.
 *
 * Displayed as a high-contrast success line beneath the failure report
 * so the developer knows the test is ready to commit alongside the fix.
 *
 * @param testPaths - Absolute paths to the generated test files.
 */
export function renderExportNotice(testPaths: string[]): void {
  if (testPaths.length === 0) return;

  write("");
  write(
    GREEN + BOLD + "  [VibeGuard]" + R +
    GRAY + " Regression test" + (testPaths.length === 1 ? "" : "s") +
    " generated and staged:" + R
  );

  for (const p of testPaths) {
    // Show path relative to cwd for readability.
    const display = p.startsWith(process.cwd())
      ? p.slice(process.cwd().length + 1)
      : p;
    write(GRAY + "    " + display + R);
  }

  write("");
  write(
    GRAY + "  Tip:" + R +
    " Run the test to verify the fix, then commit together."
  );
}

// â”€â”€â”€ Internal Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

/**
 * Write a plain text line to stdout with no ANSI codes.
 * Used for CI/CD machine-readable output.
 */
function writePlain(line: string): void {
  // Strip any ANSI escape sequences that might have leaked through.
  const clean = line.replace(/\x1b\[[0-9;]*m/g, "");
  process.stdout.write(clean + "\n");
}
