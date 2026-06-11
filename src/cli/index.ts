#!/usr/bin/env node
/**
 * VibeGuard Â· CLI Entry Point
 *
 * Commands:
 *   vibeguard init       Interactive config wizard â€” creates .vibeguard.json
 *   vibeguard install    Install the git pre-push hook into .git/hooks/
 *   vibeguard uninstall  Remove the VibeGuard pre-push hook
 *   vibeguard config     Print the current configuration
 *   vibeguard run        [internal] Called by the pre-push hook â€” extracts
 *                        and prints the structured diff. Phase 2 will add
 *                        LLM analysis here.
 *
 * All output follows the minimalist monochrome aesthetic defined in ui.ts.
 */

import * as ui from "./ui";
import { initConfig, readConfig, printConfig, findProjectRoot } from "../core/config";
import { installHook, uninstallHook } from "../core/hooks";
import { extractDiff } from "../analyzer/git";
import { filterDiff } from "../analyzer/parser";
import { analyzeDiff } from "../infrastructure/llm";
import { checkServer, formatCheckResult } from "../infrastructure/checker";
import { mapTargetsFromAnalysis, formatMappingSummary } from "../analyzer/mapper";
import { capture, restore } from "../infrastructure/dbGuard";
import { enforce as enforceCompliance } from "../compliance/compliance";
import { generatePayloads } from "../engine/payloadGen";
import { runTests } from "../engine/runner";
import { generateAllPatches, formatPatchSummary } from "../engine/healer";
import { exportRegressionTests } from "../engine/exporter";
import { renderFailureReport, renderSuccessReport, renderPhaseHeader, renderExportNotice } from "./ux";
import { isHeadless, getOutputMode } from "../compliance/ci";
import { dispatchAlert, buildReport } from "../infrastructure/webhooks";
import type { RunArgs, TargetTargets, TestReport, PatchResult } from "../core/types";
import { VERSION as CORE_VERSION } from "../core/version";
import { ensureTrusted, hasExecutableCommands, isTrusted, promptTrust } from "../core/trust";
import { write as logWrite, writeSync as logWriteSync, initLogger } from "../utils/logger";

// â”€â”€â”€ Version & Build Info â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const VERSION = `VibeGuard v${CORE_VERSION}`;

// â”€â”€â”€ Help Text â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const USAGE = `
${"\x1b[97m\x1b[1mVibeGuard\x1b[0m"} Â· CLI-native adversarial QA daemon

${"\x1b[90m"}Usage:${"\x1b[0m"}
  vibeguard ${"\x1b[97m"}<command>${"\x1b[0m"} [options]

${"\x1b[90m"}Commands:${"\x1b[0m"}
  ${"\x1b[97m"}init${"\x1b[0m"}        Create .vibeguard.json interactively
  ${"\x1b[97m"}install${"\x1b[0m"}     Install the git pre-push hook
  ${"\x1b[97m"}uninstall${"\x1b[0m"}   Remove the VibeGuard pre-push hook
  ${"\x1b[97m"}config${"\x1b[0m"}      Print current configuration
  ${"\x1b[97m"}trust${"\x1b[0m"}       Review & approve shell commands defined in .vibeguard.json
  ${"\x1b[97m"}run${"\x1b[0m"}         [internal] Execute pre-push analysis

${"\x1b[90m"}Options:${"\x1b[0m"}
  ${"\x1b[97m"}--version, -v${"\x1b[0m"}   Print version and exit
  ${"\x1b[97m"}--help, -h${"\x1b[0m"}      Show this help text

${"\x1b[90m"}Examples:${"\x1b[0m"}
  vibeguard init
  vibeguard install
  vibeguard config
  vibeguard --version

${"\x1b[90m" + VERSION + "\x1b[0m"}
`;

// â”€â”€â”€ Argument Parser (zero-dependency) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€â”€ Command Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
 * Review and approve the shell commands defined in .vibeguard.json
 * (server lifecycle / token generation). Approval is cached per project
 * and invalidated whenever the commands change.
 */
async function handleTrust(): Promise<void> {
  try {
    const config = readConfig();
    const projectRoot = findProjectRoot() ?? process.cwd();

    if (!hasExecutableCommands(config)) {
      ui.muted("No executable commands defined in .vibeguard.json — nothing to trust.");
      return;
    }

    if (isTrusted(projectRoot, config)) {
      ui.ok("The current command set is already trusted for this project.");
      return;
    }

    const approved = await promptTrust(projectRoot, config);
    if (!approved) {
      ui.muted("Commands were NOT trusted. VibeGuard will refuse to execute them.");
      process.exit(1);
    }
  } catch (err: unknown) {
    ui.fail((err as Error).message);
    process.exit(1);
  }
}

/**
 * Internal command invoked by the pre-push hook.
 *
 * Full pipeline:
 *   0. Compliance checks â€” README + semantic commit message (Phase 5).
 *   1. Parse --local, --remote flags from the hook.
 *   2. Read the project config.
 *   3. Extract the raw git diff (Phase 1).
 *   4. Apply noise filter & token optimization (Phase 2 â€” parser).
 *   5. Verify local dev server is reachable (Phase 3 â€” checker).
 *   6. Send filtered payload to the configured LLM (Phase 2 â€” llm).
 *   7. Resolve endpoints to executable test URLs (Phase 3 â€” mapper).
 *   8. Capture database state snapshot (Phase 4 â€” dbGuard.capture).
 *   9. Generate adversarial payloads via LLM (Phase 5 â€” payloadGen).
 *  10. Fire payloads & analyze responses live (Phase 6 â€” runner + assertion).
 *  11. Restore database state (Phase 4 â€” dbGuard.restore).
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
    // â•â•â• Phase 5a: Compliance Checks (README + Commit) â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // Runs BEFORE any network calls, LLM analysis, or DB snapshots.
    // If README is missing/stale or commit message violates Conventional
    // Commits, the push is aborted instantly with exit code 1.
    const projectRoot = findProjectRoot() ?? process.cwd();

    ui.space();
    ui.header("Compliance Checks");
    enforceCompliance(projectRoot);

    // â•â•â• Phase 1: Extract Raw Diff â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ui.action("Extracting diff: " + local + " -> " + (remote || "upstream"));

    const rawDiff = extractDiff(local);

    if (rawDiff.files.length === 0) {
      ui.space();
      ui.rule();
      ui.header("Diff Summary");
      ui.muted("  (no changes detected â€” nothing to push)");
      ui.rule();
      ui.ok("VibeGuard analysis complete - no changes");
      process.exit(0);
    }

    // â•â•â• Phase 2a: Noise Filter & Token Optimization â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
        ui.muted("  - " + d.path + " â€” " + d.reason);
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

    // â•â•â• Read Config â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    const config = readConfig();

    if (filtered.files.length === 0) {
      // All changes were noise â€” no need to call the LLM or check server.
      ui.muted("All changes are non-functional (docs, styles, comments, whitespace).");
      ui.muted("No LLM analysis needed.");
      ui.ok("VibeGuard analysis complete - push allowed (no functional changes)");
      process.exit(0);
    }

    // â•â•â• Phase 3a: Connectivity Pre-flight Check â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // Security trust gate: .vibeguard.json is committed to the repo and may
    // define shell commands (server lifecycle, token generation). Never
    // execute them without explicit, cached user approval.
    await ensureTrusted(projectRoot, config);

    ui.space();
    ui.header("Connectivity Check");
    ui.action("Probing " + config.target_local_url + "...");

    const serverCheck = await checkServer(config);

    if (!serverCheck.reachable) {
      // Fail fast â€” no point calling the LLM if the server is down.
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
      ui.fail("Push blocked â€” cannot verify changes without a running server");
      ui.muted("");
      ui.muted("To bypass (NOT RECOMMENDED):");
      ui.muted("  git push --no-verify");
      process.exit(1);
    }

    ui.ok(formatCheckResult(serverCheck, config.target_local_url));

    // â•â•â• Phase 2b: LLM Analysis â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ui.space();
    ui.header("LLM Analysis");

    const verdict = await analyzeDiff(config, filtered);

    // â•â•â• Phase 2c: Verdict & Reporting â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

    // â•â•â• Phase 3b: Target Mapping â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

    // â•â•â• Phase 4a: DB State Capture â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ui.space();
    ui.header("Database State Guard");
    ui.action("Capturing database state...");

    const snapshot = capture(config, filtered);

    if (snapshot.strategy !== "none") {
      ui.muted("  " + snapshot.summary);
      if (snapshot.tables.length > 0) {
        ui.muted("  Tables discovered:");
        for (const t of snapshot.tables) {
          ui.muted("    - " + t.tableName + " (" + t.operation + ")  â† " + t.sourceFile);
        }
      }
      if (!snapshot.success) {
        ui.warn("  Warning: Snapshot had errors â€” " + (snapshot.error ?? "unknown"));
      }
      ui.ok("Database state captured (" + snapshot.strategy + ")");
    } else {
      ui.muted("  " + snapshot.summary);
    }

    // â•â•â• Phase 5b: Adversarial Payload Generation â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
      ui.muted("  No payloads generated â€” no vulnerability vectors detected on any endpoint.");
    }

    // â•â•â• Phase 6: Live Payload Execution & Response Analysis â•â•â•â•â•â•â•â•â•â•â•
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
      testReport = await runTests(payloadResult.attackSuite, config);

      // Print per-result details.
      ui.space();
      for (const r of testReport.results) {
        const R = "\x1b[0m";
        if (r.vulnerable) {
          ui.muted("  \x1b[31mâœ• VULNERABLE\x1b[0m " + r.payload.method + " " + r.payload.target_url);
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
          ui.muted("  \x1b[32mâœ“ PASS\x1b[0m     " + r.payload.method + " " + r.payload.target_url);
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
      ui.muted("â”€ Phase 6 (Live Test Execution) skipped â€” no payloads to execute â”€");
    }

    // â•â•â• Phase 7: Self-Healing Patch Generation â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // When tests confirm vulnerabilities, call the LLM to generate
    // localized code fixes. Patches are written to .vibeguard/patches/
    // for the developer to review â€” they are NEVER applied automatically.
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
            String(successCount) + " patch(es) generated â†’ .vibeguard/patches/"
          );
        }
        if (failCount > 0) {
          ui.warn(
            String(failCount) + " endpoint(s) could not be patched (see report below)"
          );
        }
      } else {
        ui.muted("  No patches generated â€” no associated source files found for vulnerable endpoints.");
      }
      ui.rule();
    }



    // Phase 15: Automated Regression Test Export
    // When vulnerabilities are confirmed locally, generate a permanent
    // regression test and auto-stage it so the fix commit includes the test.
    let exportedTests: string[] = [];

    if (!isHeadless() && !testReport.overallPass && testReport.vulnerabilitiesFound > 0) {
      const vulnerableResults = testReport.results.filter((r) => r.vulnerable);
      const projectRootExport = findProjectRoot() ?? process.cwd();

      const exportResults = exportRegressionTests(config, vulnerableResults, projectRootExport);

      for (const er of exportResults) {
        if (er.success && er.filePath) {
          exportedTests.push(er.filePath);
          ui.ok(er.summary);
        } else if (!er.success) {
          ui.muted("  Test export skipped: " + (er.error ?? "unknown reason"));
        }
      }
    }

    // Phase 15: CI/CD Webhook Notification
    // Fire vulnerability alerts to Slack/Discord/Teams before DB restore.
    // Only in headless CI mode; best-effort — failures never block the push.
    if (isHeadless() && !testReport.overallPass && testReport.vulnerabilitiesFound > 0) {
      const projectName = projectRoot.split(/[\\/\\\\]/).pop() ?? "unknown";
      const report = buildReport(testReport, local, projectName ?? "unknown");
      const webhookConfig = config;

      // Race webhook dispatch against a 2s deadline — never block exit.
      try {
        await Promise.race([
          dispatchAlert(
            report,
            webhookConfig.webhook_slack,
            webhookConfig.webhook_discord,
            webhookConfig.webhook_teams
          ),
          new Promise<void>((_, reject) =>
            setTimeout(() => reject(new Error("Webhook dispatch deadline exceeded")), 2500)
          ),
        ]);
      } catch {
        // Webhook timed out — non-blocking, push already blocked.
        ui.muted("  Webhook dispatch skipped (timeout or delivery failure).");
      }
    }

    // â•â•â• Phase 4b: DB State Restore â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

    // â•â•â• Combined Final Verdict â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
      renderExportNotice(exportedTests);
      process.exit(1);
    }
  } catch (err: unknown) {
    // â•â•â• Emergency Restore on Pipeline Failure â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // If anything in the pipeline throws, attempt DB restore before exiting.
    // This ensures we never leave the database in a dirty state.
    try {
      const config = readConfig();
      const emergencyRestore = restore(config);
      if (emergencyRestore.strategy !== "none" && emergencyRestore.success) {
        ui.muted("  (Emergency DB restore completed)");
      }
    } catch {
      // Restore itself failed â€” nothing more we can do.
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
    ui.fail("Push blocked â€” analysis could not complete");
    ui.muted("");
    ui.muted("To bypass (NOT RECOMMENDED):");
    ui.muted("  git push --no-verify");
    process.exit(1);
  }
}

// â”€â”€â”€ Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function main(): Promise<void> {
  // Phase 15: Top-level crash boundary — captures unhandled exceptions
  // to the structured debug log before displaying a minimal terminal banner.
  try {
  const { command, flags } = parseArgs(process.argv);

  // â”€â”€ Global flags (before command dispatch) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // --version / -v always takes precedence.
  if (command === "--version" || command === "-v" || flags.version || flags.v) {
    process.stdout.write(VERSION + "\n");
    process.exit(0);
  }

  // --help / -h shows usage regardless of command position.
  if (command === "--help" || command === "-h" || flags.help || flags.h) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

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

    case "trust":
      await handleTrust();
      break;

    case "run":
      await handleRun(flags);
      break;

    case "":
    case "help":
      process.stdout.write(USAGE);
      break;

    default:
      ui.fail(`Unknown command: "${command}"`);
      ui.muted("Run `vibeguard --help` to see usage.");
      process.exit(1);
  }
  } catch (err: unknown) {
    // Phase 15: Unhandled exception — log the full stack trace,
    // show a minimal dark-mode banner, and exit with code 1.
    const stack = (err as Error).stack ?? (err as Error).message ?? String(err);
    const projectRoot = findProjectRoot() ?? process.cwd();

    // Phase 15: Initialize the structured debug logger.
    initLogger(projectRoot).catch(() => { /* non-blocking */ });

    // Write the crash diagnostics to the structured log file.
    logWriteSync("error", "runtime_crash", stack, projectRoot);

    // Minimal dark-mode banner — professional, non-intrusive.
    ui.space();
    ui.rule();
    ui.fail("VibeGuard Critical Exception");
    ui.muted("  An unhandled engine crash occurred.");
    ui.muted("  Detailed diagnostics have been securely written to:");
    ui.muted("  .vibeguard/logs/engine_debug.log");
    ui.rule();

    process.exit(1);
  }
}

main();
