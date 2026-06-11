/**
 * VibeGuard — Command Trust Store
 *
 * `.vibeguard.json` is committed to the repository, and several of its fields
 * are shell commands executed on the developer's machine:
 *   · server_start_command
 *   · server_stop_command
 *   · auth_seeding.token_generation_command
 *
 * Without a trust gate, anyone who can commit to a repo gets arbitrary code
 * execution on every teammate's machine on push. This module implements a
 * direnv-style "allow" flow:
 *
 *   · A SHA-256 fingerprint of the executable command set is computed.
 *   · The first time commands are seen — or whenever they change — the user
 *     must explicitly approve them before anything is executed.
 *   · Approvals are cached per project root in the user's home directory
 *     (~/.vibeguard/trusted.json), never inside the repository.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as readline from "node:readline";
import { createHash } from "node:crypto";
import type { VibeGuardConfig } from "./types";
import * as ui from "../cli/ui";

// ─── Constants ──────────────────────────────────────────────────────────────

const TRUST_DIR = path.join(os.homedir(), ".vibeguard");
const TRUST_FILE = path.join(TRUST_DIR, "trusted.json");

// ─── Command Extraction ────────────────────────────────────────────────────

/** The config fields that contain executable shell commands. */
export interface ExecutableCommands {
  server_start_command: string;
  server_stop_command: string;
  token_generation_command: string;
}

export function getExecutableCommands(config: VibeGuardConfig): ExecutableCommands {
  return {
    server_start_command: config.server_start_command?.trim() ?? "",
    server_stop_command: config.server_stop_command?.trim() ?? "",
    token_generation_command: config.auth_seeding?.token_generation_command?.trim() ?? "",
  };
}

/** True when the config defines at least one executable command. */
export function hasExecutableCommands(config: VibeGuardConfig): boolean {
  const cmds = getExecutableCommands(config);
  return Boolean(
    cmds.server_start_command || cmds.server_stop_command || cmds.token_generation_command
  );
}

/** Stable SHA-256 fingerprint of the command set. */
export function commandsFingerprint(config: VibeGuardConfig): string {
  const cmds = getExecutableCommands(config);
  const canonical = JSON.stringify([
    cmds.server_start_command,
    cmds.server_stop_command,
    cmds.token_generation_command,
  ]);
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}

// ─── Trust Store I/O ────────────────────────────────────────────────────────

type TrustStore = Record<string, string>; // absolute project root → fingerprint

function readStore(): TrustStore {
  try {
    const raw = fs.readFileSync(TRUST_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as TrustStore;
    }
  } catch {
    // Missing or corrupt store — treat as empty (nothing trusted).
  }
  return {};
}

function writeStore(store: TrustStore): void {
  fs.mkdirSync(TRUST_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(TRUST_FILE, JSON.stringify(store, null, 2) + "\n", {
    encoding: "utf-8",
    mode: 0o600,
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

/** Whether the current command set for this project has been approved. */
export function isTrusted(projectRoot: string, config: VibeGuardConfig): boolean {
  if (!hasExecutableCommands(config)) return true; // nothing to execute
  const store = readStore();
  return store[path.resolve(projectRoot)] === commandsFingerprint(config);
}

/** Persist approval for the current command set. */
export function recordTrust(projectRoot: string, config: VibeGuardConfig): void {
  const store = readStore();
  store[path.resolve(projectRoot)] = commandsFingerprint(config);
  writeStore(store);
}

/** Remove any stored approval for this project. */
export function revokeTrust(projectRoot: string): void {
  const store = readStore();
  delete store[path.resolve(projectRoot)];
  writeStore(store);
}

function describeCommands(config: VibeGuardConfig): string[] {
  const cmds = getExecutableCommands(config);
  const lines: string[] = [];
  if (cmds.server_start_command) {
    lines.push("  server_start_command:      " + cmds.server_start_command);
  }
  if (cmds.server_stop_command) {
    lines.push("  server_stop_command:       " + cmds.server_stop_command);
  }
  if (cmds.token_generation_command) {
    lines.push("  token_generation_command:  " + cmds.token_generation_command);
  }
  return lines;
}

/**
 * Interactively prompt the user to approve the command set.
 * Returns true if approved (and persists the approval).
 */
export async function promptTrust(
  projectRoot: string,
  config: VibeGuardConfig
): Promise<boolean> {
  ui.space();
  ui.warn("This repository's .vibeguard.json defines shell commands that VibeGuard will execute:");
  for (const line of describeCommands(config)) {
    ui.muted(line);
  }
  ui.muted("  Only approve commands you have reviewed and recognize.");
  ui.space();

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise<string>((resolve) => {
    rl.question("Trust and execute these commands? [y/N]: ", (a) => resolve(a.trim().toLowerCase()));
  });
  rl.close();

  if (answer === "y" || answer === "yes") {
    recordTrust(projectRoot, config);
    ui.ok("Commands trusted. Approval is cached and re-required if they change.");
    return true;
  }
  return false;
}

/**
 * Gate used by the run pipeline before any config-defined command executes.
 *
 *   · No commands configured       → proceed.
 *   · Already approved (unchanged) → proceed.
 *   · Interactive TTY              → prompt the user.
 *   · Non-interactive (hooks/CI)   → fail closed with instructions to run
 *                                    `vibeguard trust` once, manually.
 */
export async function ensureTrusted(
  projectRoot: string,
  config: VibeGuardConfig
): Promise<void> {
  if (isTrusted(projectRoot, config)) return;

  if (process.stdin.isTTY && process.stdout.isTTY) {
    const approved = await promptTrust(projectRoot, config);
    if (approved) return;
    throw new Error(
      "Execution of repository-defined commands was not approved. " +
      "Remove the command fields from .vibeguard.json or run `vibeguard trust` to review them."
    );
  }

  throw new Error(
    "This repository's .vibeguard.json defines shell commands (server lifecycle / token generation) " +
    "that have not been trusted on this machine, and no interactive terminal is available to approve them.\n" +
    "Review and approve them once with: vibeguard trust"
  );
}
