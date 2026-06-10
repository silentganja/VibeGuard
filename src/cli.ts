#!/usr/bin/env node
/**
 * VibeGuard · CLI Entry Point
 *
 * Commands:
 *   vibeguard init       Interactive config wizard — creates .vibeguard.json
 *   vibeguard install    Install the git pre-push hook into .git/hooks/
 *   vibeguard uninstall  Remove the VibeGuard pre-push hook
 *   vibeguard config     Print the current configuration
 *   vibeguard run        [internal] Called by the pre-push hook — extracts
 *                        and prints the structured diff. Phase 2 will add
 *                        LLM analysis here.
 *
 * All output follows the minimalist monochrome aesthetic defined in ui.ts.
 */

import * as ui from "./ui";
import { initConfig, readConfig, printConfig, findProjectRoot } from "./config";
import { installHook, uninstallHook } from "./hooks";
import { extractDiff } from "./git";
import { filterDiff } from "./parser";
import { analyzeDiff } from "./llm";
import { checkServer, formatCheckResult } from "./checker";
import { mapTargetsFromAnalysis, formatMappingSummary } from "./mapper";
import { capture, restore } from "./dbGuard";
import { enforce as enforceCompliance } from "./compliance";
import { generatePayloads } from "./payloadGen";
import { runTests } from "./runner";
import { generateAllPatches, formatPatchSummary } from "./healer";
import { renderFailureReport, renderSuccessReport, renderPhaseHeader } from "./ux";
import { isHeadless, getOutputMode } from "./ci";
import type { RunArgs, TargetTargets, TestReport, PatchResult } from "./types";

// ─── Help Text ───────────────────────────────────────────────────────────────

const USAGE = `
${"\x1b[97m\x1b[1mVibeGuard\x1b[0m"} · CLI-native adversarial QA daemon

${"\x1b[90m"}Usage:${"\x1b[0m"}
  vibeguard ${"\x1b[97m"}<command>${"\x1b[0m"} [options]

${"\x1b[90m"}Commands:${"\x1b[0m"}
  ${"\x1b[97m"}init${"\x1b[0m"}        Create .vibeguard.json interactively
  ${"\x1b[97m"}install${"\x1b[0m"}     Install the git pre-push hook
  ${"\x1b[97m"}uninstall${"\x1b[0m"}   Remove the VibeGuard pre-push hook
  ${"\x1b[97m"}config${"\x1b[0m"}      Print current configuration
  ${"\x1b[97m"}run${"\x1b[0m"}         [internal] Execute pre-push analysis

${"\x1b[90m"}Examples:${"\x1b[0m"}
  vibeguard init
  vibeguard install
  vibeguard config

${"\x1b[90m"}Phase 9 · v0.9.0${"\x1b[0m"}
`;

// ─── Argument Parser (zero-dependency) ───────────────────────────────────────

interface ParsedArgs {
  command: string;
  flags: Record<string, string>;
}

function parseArgs(raw: string[]): ParsedArgs {
  const args = raw.slice(2); // drop node + script path
  const command = args[0] ?? "";
  const flags: Record<string, string> = {};

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++; // consume value
      } else {
        flags[key] = "true";
      }
    } else if (arg.startsWith("-")) {
      const key = arg.slice(1);
      const next = args[i + 1];
      if (next && !next.startsWith("-")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = "true";
      }
    }
  }

  return { command, flags };
}

// ─── Command Handlers ────────────────────────────────────────────────────────

async function handleInit(): Promise<void> {
  try {
    await initConfig();
  } catch (err: unknown) {
    ui.fail((err as Error).message);
    process.exit(1);
  }
}

function handleInstall(): void {
  try {
    installHook();
  } catch (err: unknown) {
    ui.fail((err as Error).message);
    process.exit(1);
  }
}

function handleUninstall(): void {
  try {
    uninstallHook();
  } catch (err: unknown) {
    ui.fail((err as Error).message);
    process.exit(1);
  }
}

function handleConfig(): void {
  try {
    printConfig();
  } catch (err: unknown) {
    ui.fail((err as Error).message);
    process.exit(1);
  }
}

/**
 * Internal command invoked by the pre-push hook.
 *
 * Full pipeline:
 *   0. Compliance checks — README + semantic commit message (Phase 5).
 *   1. Parse --local, --remote flags from the hook.
 *   2. Read the project config.
 *   3. Extract the raw git diff (Phase 1).
 *   4. Apply noise filter & token optimization (Phase 2 — parser).
 *   5. Verify local dev server is reachable (Phase 3 — checker).
 *   6. Send filtered payload to the configured LLM (Phase 2 — llm).
 *   7. Resolve endpoints to executable test URLs (Phase 3 — mapper).
 *   8. Capture database state snapshot (Phase 4 — dbGuard.capture).
 *   9. Generate adversarial payloads via LLM (Phase 5 — payloadGen).
 *  10. Fire payloads & analyze responses live (Phase 6 — runner + assertion).
 *  11. Restore database state (Phase 4 — dbGuard.restore).
 *  12. Build pass/fail verdict and report findings.
 *  13. Exit 0 (pass) or 1 (block).
 */
async function handleRun(flags: Record<string, string>): Promise<void> {
  const local = flags.local ?? flags.l ?? "";
  const remote = flags.remote ?? flags.r ?? "";

  if (!local) {
    ui.fail("--local <branch> is required");
    process.exit(1);
  }

  try {
    // ═══ Phase 5a: Compliance Checks (README + Commit) ════════════════════
    // Runs BEFORE any network calls, LLM analysis, or DB snapshots.
    // If README is missing/stale or commit message violates Conventional
    // Commits, the push is aborted instantly with exit code 1.
    const projectRoot = findProjectRoot() ?? process.cwd();

    ui.space();
    ui.header("Compliance Checks");
    enforceCompliance(projectRoot);

    // ═══ Phase 1: Extract Raw Diff ═══════════════════════════════════════
    ui.action("Extracting diff: " + local + " -> " + (remote || "upstream"));

    const rawDiff = extractDiff(local);

    if (rawDiff.files.length === 0) {
      ui.space();
      ui.rule();
      ui.header("Diff Summary");
      ui.muted("  (no changes detected — nothing to push)");
      ui.rule();
      ui.ok("VibeGuard analysis complete - no changes");
      process.exit(0);
    }

    // ═══ Phase 2a: Noise Filter & Token Optimization ═════════════════════
    ui.action("Filtering diff noise...");

    const filtered = filterDiff(rawDiff);

    // Show what's being analyzed vs. discarded.
    ui.space();
    ui.rule();
    ui.header("Diff Summary");
    ui.kv("Files changed", String(rawDiff.files.length));
    ui.kv("Lines added", "+" + String(rawDiff.totalAdditions));
    ui.kv("Lines deleted", "-" + String(rawDiff.totalDeletions));
    ui.muted("");
    ui.kv("Files for LLM analysis", String(filtered.files.length));
    ui.kv("Files filtered out", String(filtered.discarded.length));
    ui.kv("Estimated tokens", "~" + String(filtered.estimatedTokens));

    // Show discarded files if any.
    if (filtered.discarded.length > 0) {
      ui.muted("");
      ui.muted("Filtered out (non-functional noise):");
      for (const d of filtered.discarded) {
        ui.muted("  - " + d.path + " — " + d.reason);
      }
    }

    // Show files being analyzed.
    if (filtered.files.length > 0) {
      ui.muted("");
      ui.muted("Files under LLM analysis:");
      for (const file of filtered.files) {
        const statusIcon = file.status === "added" ? "A"
          : file.status === "deleted" ? "D"
          : file.status === "renamed" ? "R"
          : "M";
        const hunkCount = file.hunks.length;
        const hunkLabel = hunkCount === 1 ? "1 hunk" : String(hunkCount) + " hunks";
        ui.muted("  " + statusIcon + "  " + file.path + "  +" + String(file.additions) + " -" + String(file.deletions) + "  (" + hunkLabel + ")");
      }
    }

    ui.rule();

    // ═══ Read Config ═════════════════════════════════════════════════════
    const config = readConfig();

    if (filtered.files.length === 0) {
      // All changes were noise — no need to call the LLM or check server.
      ui.muted("All changes are non-functional (docs, styles, comments, whitespace).");
      ui.muted("No LLM analysis needed.");
      ui.ok("VibeGuard analysis complete - push allowed (no functional changes)");
      process.exit(0);
    }

    // ═══ Phase 3a: Connectivity Pre-flight Check ═════════════════════════
    ui.space();
    ui.header("Connectivity Check");
    ui.action("Probing " + config.target_local_url + "...");

    const serverCheck = await checkServer(config);

    if (!serverCheck.reachable) {
      // Fail fast — no point calling the LLM if the server is down.
      // Spec requires: [VibeGuard Error] Local development server at <url> is unreachable.
      ui.space();
      ui.rule();
      ui.fail("Local development server at " + config.target_local_url + " is unreachable. Please start your local environment before pushing.");
      ui.muted("");
      ui.muted("  " + formatCheckResult(serverCheck, config.target_local_url));
      ui.muted("");
      ui.muted("Troubleshooting:");
      ui.muted("  - Is your dev server running?");
      ui.muted("  - Is target_local_url correct in .vibeguard.json?");
      ui.muted("  - Check: " + config.target_local_url);
      ui.rule();
      ui.fail("Push blocked — cannot verify changes without a running server");
      ui.muted("");
      ui.muted("To bypass (NOT RECOMMENDED):");
      ui.muted("  git push --no-verify");
      process.exit(1);
    }

    ui.ok(formatCheckResult(serverCheck, config.target_local_url));

    // ═══ Phase 2b: LLM Analysis ═════════════════════════════════════════
    ui.space();
    ui.header("LLM Analysis");

    const verdict = await analyzeDiff(config, filtered);

    // ═══ Phase 2c: Verdict & Reporting ═══════════════════════════════════
    ui.space();
    ui.rule();
    ui.header("Analysis Results");

    // Print the explanation.
    for (const line of verdict.explanation.split("\n")) {
      if (line.trim()) {
        ui.muted(line);
      } else {
        ui.space();
      }
    }

    // Print per-endpoint details.
    if (verdict.result.modified_endpoints.length > 0) {
      ui.space();
      for (const ep of verdict.result.modified_endpoints) {
        const methodColor = ep.http_method === "POST" || ep.http_method === "PUT" || ep.http_method === "DELETE"
          ? "\x1b[33m"  // yellow for mutating methods
          : "\x1b[36m"; // cyan for safe methods
        const R = "\x1b[0m";

        ui.muted("  > " + ep.file_path);
        ui.muted("    " + methodColor + ep.http_method + R + " " + ep.estimated_route);
        ui.muted("    Intent: " + ep.detected_intent);

        if (ep.input_parameters.length > 0) {
          ui.muted("    Inputs: " + ep.input_parameters.join(", "));
        }

        if (ep.vulnerability_vectors.length > 0) {
          ui.muted("    Vectors: \x1b[31m" + ep.vulnerability_vectors.join(", ") + "\x1b[0m");
        }
      }
    }

    ui.rule();

    // ═══ Phase 3b: Target Mapping ═══════════════════════════════════════
    let targets: TargetTargets = { executable_tests: [] };

    if (verdict.result.modified_endpoints.length > 0) {
      ui.space();
      ui.header("Target Mapping");
      ui.action("Resolving endpoints to executable URLs...");

      targets = mapTargetsFromAnalysis(config, verdict.result);

      ui.space();
      const mappingSummary = formatMappingSummary(targets);
      for (const line of mappingSummary.split("\n")) {
        if (line.trim()) {
          ui.muted(line);
        } else {
          ui.space();
        }
      }

      // Show resolved test URLs prominently.
      ui.space();
      ui.header("Executable Test Targets");
      for (const test of targets.executable_tests) {
        const stratColor = test.mapping_strategy === "framework" ? "\x1b[36m"
          : test.mapping_strategy === "traditional" ? "\x1b[33m"
          : "\x1b[31m";
        const R = "\x1b[0m";

        ui.muted("  " + stratColor + test.http_method + R + " " + test.resolved_url);
        ui.muted("    File: " + test.associated_file + "  [" + test.mapping_strategy + "]");

        if (test.vulnerability_vectors.length > 0 && test.input_parameters.length > 0) {
          ui.muted("    Vectors: " + test.vulnerability_vectors.join(", ") + "  |  Inputs: " + test.input_parameters.join(", "));
        } else if (test.vulnerability_vectors.length > 0) {
          ui.muted("    Vectors: " + test.vulnerability_vectors.join(", "));
        } else if (test.input_parameters.length > 0) {
          ui.muted("    Inputs: " + test.input_parameters.join(", "));
        }
      }
      ui.rule();
    }

    // ═══ Phase 4a: DB State Capture ═════════════════════════════════════
    ui.space();
    ui.header("Database State Guard");
    ui.action("Capturing database state...");

    const snapshot = capture(config, filtered);

    if (snapshot.strategy !== "none") {
      ui.muted("  " + snapshot.summary);
      if (snapshot.tables.length > 0) {
        ui.muted("  Tables discovered:");
        for (const t of snapshot.tables) {
          ui.muted("    - " + t.tableName + " (" + t.operation + ")  ← " + t.sourceFile);
        }
      }
      if (!snapshot.success) {
        ui.warn("  Warning: Snapshot had errors — " + (snapshot.error ?? "unknown"));
      }
      ui.ok("Database state captured (" + snapshot.strategy + ")");
    } else {
      ui.muted("  " + snapshot.summary);
    }

    // ═══ Phase 5b: Adversarial Payload Generation ══════════════════════
    ui.space();
    ui.header("Adversarial Payload Generation");

    const payloadResult = await generatePayloads(config, targets, filtered);

    ui.space();
    if (payloadResult.attackSuite.attack_suite.length > 0) {
      ui.kv("Total payloads", String(payloadResult.attackSuite.attack_suite.length));
      ui.kv("LLM-generated", String(payloadResult.generatedCount));
      ui.kv("Fallback-generated", String(payloadResult.fallbackCount));

      if (payloadResult.errors.length > 0) {
        ui.warn("  Payload generation errors:");
        for (const err of payloadResult.errors) {
          ui.muted("    - " + err.target_url + ": " + err.error.slice(0, 120));
        }
      }

      // Show generated payloads.
      ui.space();
      ui.muted("Generated attack suite:");
      for (const p of payloadResult.attackSuite.attack_suite) {
        const R = "\x1b[0m";
        ui.muted("  > \x1b[31m" + p.attack_type + R + " " + p.method + " " + p.target_url);
        const paramKeys = Object.keys(p.payload_data);
        if (paramKeys.length > 0) {
          const preview: string[] = [];
          for (const k of paramKeys.slice(0, 3)) {
            const val = p.payload_data[k];
            const truncated = val.length > 60 ? val.slice(0, 57) + "..." : val;
            preview.push(k + "=" + truncated);
          }
          const suffix = paramKeys.length > 3 ? " (+" + String(paramKeys.length - 3) + " more)" : "";
          ui.muted("    Params: " + preview.join(", ") + suffix);
        }
        ui.muted("    Criteria: " + p.expected_fail_criteria.slice(0, 120));
      }
      ui.ok("Payload generation complete");
    } else {
      ui.muted("  No payloads generated — no vulnerability vectors detected on any endpoint.");
    }

    // ═══ Phase 6: Live Payload Execution & Response Analysis ═══════════
    let testReport: TestReport = {
      results: [],
      vulnerabilitiesFound: 0,
      testsPassed: 0,
      testsErrored: 0,
      overallPass: true,
      summary: "No payloads executed.",
    };

    if (payloadResult.attackSuite.attack_suite.length > 0) {
      ui.space();
      ui.header("Live Test Execution");
      testReport = await runTests(payloadResult.attackSuite);

      // Print per-result details.
      ui.space();
      for (const r of testReport.results) {
        const R = "\x1b[0m";
        if (r.vulnerable) {
          ui.muted("  \x1b[31m✕ VULNERABLE\x1b[0m " + r.payload.method + " " + r.payload.target_url);
          ui.muted("    Attack: " + r.payload.attack_type + " | HTTP " + String(r.statusCode ?? "N/A") + " | " + String(r.latencyMs) + "ms");
          for (const a of r.assertions) {
            if (a.triggered) {
              ui.muted("    [" + a.category + "] " + a.detail.slice(0, 130));
            }
          }
        } else if (!r.completed) {
          ui.muted("  \x1b[33m! ERROR\x1b[0m    " + r.payload.method + " " + r.payload.target_url);
          ui.muted("    " + (r.error ?? "Unknown error") + " (" + String(r.latencyMs) + "ms)");
        } else {
          ui.muted("  \x1b[32m✓ PASS\x1b[0m     " + r.payload.method + " " + r.payload.target_url);
          ui.muted("    HTTP " + String(r.statusCode) + " | " + String(r.latencyMs) + "ms");
        }
      }

      ui.space();
      ui.rule();

      // Print aggregate summary.
      for (const line of testReport.summary.split("\n")) {
        if (line.trim()) {
          if (testReport.overallPass) {
            ui.muted(line);
          } else {
            ui.muted(line);
          }
        } else {
          ui.space();
        }
      }
      ui.rule();
    } else {
      ui.space();
      ui.muted("─ Phase 6 (Live Test Execution) skipped — no payloads to execute ─");
    }

    // ═══ Phase 7: Self-Healing Patch Generation ════════════════════════
    // When tests confirm vulnerabilities, call the LLM to generate
    // localized code fixes. Patches are written to .vibeguard/patches/
    // for the developer to review — they are NEVER applied automatically.
    //
    // In CI/CD mode, patch generation is skipped: ephemeral build containers
    // have no use for local .patch files. The vulnerability breakdown is
    // still output as machine-readable text for log archival.
    let patchResults: PatchResult[] = [];

    if (!isHeadless() && !testReport.overallPass && testReport.vulnerabilitiesFound > 0) {
      ui.space();
      ui.header("Self-Healing Patch Engine");
      ui.action(
        "Generating patches for " +
        String(testReport.vulnerabilitiesFound) + " confirmed vulnerability/ies..."
      );

      const projectRoot = findProjectRoot() ?? process.cwd();
      patchResults = await generateAllPatches(config, testReport, targets, projectRoot);

      // Display patch generation summary (details deferred to final report).
      ui.space();
      if (patchResults.length > 0) {
        const successCount = patchResults.filter((p) => p.success).length;
        const failCount = patchResults.length - successCount;
        if (successCount > 0) {
          ui.ok(
            String(successCount) + " patch(es) generated → .vibeguard/patches/"
          );
        }
        if (failCount > 0) {
          ui.warn(
            String(failCount) + " endpoint(s) could not be patched (see report below)"
          );
        }
      } else {
        ui.muted("  No patches generated — no associated source files found for vulnerable endpoints.");
      }
      ui.rule();
    }

    // ═══ Phase 4b: DB State Restore ═════════════════════════════════════
    ui.space();
    ui.action("Restoring database state...");

    const restoreResult = restore(config);

    if (restoreResult.strategy !== "none") {
      if (restoreResult.success) {
        ui.ok(restoreResult.summary);
      } else {
        ui.warn("  " + restoreResult.summary);
        if (restoreResult.error) {
          ui.muted("  Error: " + restoreResult.error);
        }
        ui.warn("  Manual DB cleanup may be required.");
      }
    } else {
      ui.muted("  " + restoreResult.summary);
    }

    ui.rule();

    // ═══ Combined Final Verdict ═════════════════════════════════════════
    // The push passes only if BOTH the LLM analysis AND the live test run
    // report no vulnerabilities. If either finds issues, the push is blocked.
    const analysisPassed = verdict.pass;
    const testsPassed = testReport.overallPass;
    const finalPass = analysisPassed && testsPassed;

    if (finalPass) {
      renderSuccessReport();
      process.exit(0);
    } else {
      renderFailureReport(verdict, testReport, patchResults, analysisPassed);
      process.exit(1);
    }
  } catch (err: unknown) {
    // ═══ Emergency Restore on Pipeline Failure ══════════════════════════
    // If anything in the pipeline throws, attempt DB restore before exiting.
    // This ensures we never leave the database in a dirty state.
    try {
      const config = readConfig();
      const emergencyRestore = restore(config);
      if (emergencyRestore.strategy !== "none" && emergencyRestore.success) {
        ui.muted("  (Emergency DB restore completed)");
      }
    } catch {
      // Restore itself failed — nothing more we can do.
    }

    // Fail closed: any error in the analysis pipeline blocks the push.
    const message = (err as Error).message ?? String(err);
    const isTimeout = message.includes("TIMEOUT") || message.includes("timed out");

    ui.space();
    ui.rule();

    if (isTimeout) {
      // Dark-mode timeout warning per spec.
      ui.fail("LLM Request Timed Out");
      ui.muted("");
      ui.muted("  " + message.replace(/\n/g, "\n  "));
      ui.muted("");
      ui.muted("The configured LLM did not respond within the 6-second deadline.");
      ui.muted("This prevents VibeGuard from blocking your push indefinitely.");
      ui.muted("");
      ui.muted("Troubleshooting:");
      ui.muted("  - Verify your LLM is running at the endpoint in .vibeguard.json");
      ui.muted("  - Check llm_model in .vibeguard.json matches an available model.");
      ui.muted("  - For local models (Ollama/LM Studio), ensure the server is started.");
    } else {
      ui.fail("VibeGuard analysis encountered an error");
      ui.muted("  " + message);
    }

    ui.rule();
    ui.fail("Push blocked — analysis could not complete");
    ui.muted("");
    ui.muted("To bypass (NOT RECOMMENDED):");
    ui.muted("  git push --no-verify");
    process.exit(1);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv);

  switch (command) {
    case "init":
      await handleInit();
      break;

    case "install":
      handleInstall();
      break;

    case "uninstall":
      handleUninstall();
      break;

    case "config":
      handleConfig();
      break;

    case "run":
      await handleRun(flags);
      break;

    case "":
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(USAGE);
      break;

    default:
      ui.fail(`Unknown command: "${command}"`);
      ui.muted("Run `vibeguard` without arguments to see usage.");
      process.exit(1);
  }
}

main().catch((err) => {
  ui.fail(`Unexpected error: ${err.message}`);
  process.exit(1);
});
