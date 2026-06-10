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
import { initConfig, readConfig, printConfig } from "./config";
import { installHook, uninstallHook } from "./hooks";
import { extractDiff, getChangedFiles } from "./git";
import type { RunArgs } from "./types";

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

${"\x1b[90m"}Phase 1 · v0.1.0${"\x1b[0m"}
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
 * Steps:
 *   1. Parse --local, --remote, --sha flags from the hook.
 *   2. Read the project config.
 *   3. Run the git diff extraction.
 *   4. Print a structured summary of the changes.
 *   5. Exit 0 (pass) or 1 (fail).
 *
 * Phase 2 will insert the LLM analysis call between steps 3 and 4.
 */
function handleRun(flags: Record<string, string>): void {
  const local = flags.local ?? flags.l ?? "";
  const remote = flags.remote ?? flags.r ?? "";
  const sha = flags.sha ?? flags.s ?? "";

  if (!local) {
    ui.fail("--local <branch> is required");
    process.exit(1);
  }

  try {
    // 1. Read config (validates it exists and is well-formed).
    const config = readConfig();

    // 2. Extract the structured diff.
    ui.action(`Extracting diff: ${local} → ${remote || "upstream"}`);

    const diff = extractDiff(local);

    // 3. Print structured summary.
    ui.space();
    ui.rule();
    ui.header("Diff Summary");

    if (diff.files.length === 0) {
      ui.muted("  (no changes detected — nothing to push)");
      ui.rule();
      ui.ok("VibeGuard analysis complete · no changes");
      process.exit(0);
    }

    ui.kv("Files changed", String(diff.files.length));
    ui.kv("Lines added", `+${diff.totalAdditions}`);
    ui.kv("Lines deleted", `-${diff.totalDeletions}`);
    ui.rule();

    // Per-file breakdown.
    for (const file of diff.files) {
      const statusIcon = file.status === "added" ? "A"
        : file.status === "deleted" ? "D"
        : file.status === "renamed" ? "R"
        : "M";

      const displayPath = file.status === "renamed"
        ? `${file.oldPath} → ${file.path}`
        : file.path;

      const stats = `+${file.additions}  -${file.deletions}`;
      ui.muted(`  ${statusIcon}  ${displayPath}  ${stats}`);
    }

    ui.rule();

    // 4. Memory footprint summary (what would be sent to the LLM).
    const totalLines = diff.files.reduce(
      (sum, f) => sum + f.hunks.reduce((s, h) => s + h.lines.length, 0),
      0
    );
    ui.muted(
      `Memory footprint: ${diff.files.length} files, ` +
      `${totalLines} diff lines, ` +
      `${diff.totalAdditions} additions, ` +
      `${diff.totalDeletions} deletions`
    );

    // 5. Phase 2 placeholder.
    ui.space();
    ui.muted("─ Phase 2 (LLM analysis) not yet integrated ─");

    // 6. In Phase 1, we always pass — the diff extraction is the deliverable.
    //    Phase 2 will conditionally fail based on LLM verdict.
    ui.ok("VibeGuard analysis complete · push allowed");
    process.exit(0);
  } catch (err: unknown) {
    ui.fail((err as Error).message);
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
      handleRun(flags);
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
