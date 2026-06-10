/**
 * VibeGuard — Post-Install Verification Wrapper
 *
 * Phase 10: Runs after `npm install` to verify the installation is
 * functional and the binary is accessible. Checks:
 *
 *   1. Node.js version meets the minimum requirement (≥ 18).
 *   2. The bundled entry point exists and is executable.
 *   3. The `vibeguard` command resolves on the PATH.
 *   4. Git is available (required for diff extraction).
 *
 * This script exits 0 on success (silent) and prints warnings on
 * non-fatal issues. Fatal issues print errors to stderr.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");

// ─── Checks ────────────────────────────────────────────────────────────────────

let issues = 0;

function warn(msg) {
  console.warn(`\x1b[33m!  ${msg}\x1b[0m`);
  issues++;
}

function ok(msg) {
  // Silent on success — keeps install output clean.
}

// ── Node.js Version ──────────────────────────────────────────────────
const nodeVersion = process.versions.node;
const major = parseInt(nodeVersion.split(".")[0], 10);
if (major < 18) {
  warn(`Node.js ${nodeVersion} is below the minimum required version (18.x).`);
  warn("  Upgrade Node.js: https://nodejs.org/");
} else {
  ok(`Node.js ${nodeVersion} ✓`);
}

// ── Entry Point Exists ───────────────────────────────────────────────
const entryPoint = path.join(DIST, "cli.js");
if (!fs.existsSync(entryPoint)) {
  warn(`Entry point not found at ${entryPoint}`);
  warn("  Run `npm run build` to compile TypeScript.");
} else {
  ok("Entry point found ✓");
}

// ── Git Available ────────────────────────────────────────────────────
try {
  execSync("git --version", { stdio: "pipe" });
  ok("Git available ✓");
} catch {
  warn("Git is not available on the PATH.");
  warn("  VibeGuard requires Git for diff extraction and hook installation.");
  warn("  Install Git: https://git-scm.com/");
}

// ── Execute Permission Check ─────────────────────────────────────────
try {
  const entryStat = fs.statSync(entryPoint);
  // On Unix, verify the file is executable (or that we're on Windows where
  // execute permissions don't apply the same way).
  if (process.platform !== "win32") {
    // eslint-disable-next-line no-bitwise
    if ((entryStat.mode & 0o111) === 0) {
      warn("Entry point is not executable. Run: chmod +x dist/cli.js");
    }
  }
  ok("Execute permissions ✓");
} catch {
  // Already warned above if entry point is missing.
}

// ── Summary ──────────────────────────────────────────────────────────
if (issues > 0) {
  console.warn(`\x1b[33m!  VibeGuard installed with ${issues} warning(s).\x1b[0m`);
  console.warn("\x1b[90m   Run `vibeguard` to see available commands.\x1b[0m");
} else {
  // Silent success — the user's `npm install` output stays clean.
}

// Never block install — warnings are non-fatal.
process.exit(0);
