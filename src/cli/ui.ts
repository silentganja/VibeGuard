/**
 * VibeGuard — Terminal UI Utilities
 *
 * Minimalist, high-contrast monochrome output. No spinners, no progress bars.
 * Every function is a single-call, single-line status emitter.
 *
 * Design language:
 *   -  gray   — informational / context
 *   →  white  — action in progress
 *   ✓  green  — success
 *   ✕  red    — failure / abort
 *   !  yellow — warning
 *
 * All escape sequences reset after each call so no state leaks.
 */

// ─── ANSI Codes ──────────────────────────────────────────────────────────────

const DIM = "\x1b[2m";
const GRAY = "\x1b[90m";
const WHITE = "\x1b[97m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const BOLD = "\x1b[1m";
const R = "\x1b[0m";

// ─── Public API ──────────────────────────────────────────────────────────────

/** Dim context line — file paths, metadata, secondary info. */
export function muted(msg: string): void {
  process.stdout.write(`${GRAY}${msg}${R}\n`);
}

/** Action-in-progress line — "→  Doing X". */
export function action(msg: string): void {
  process.stdout.write(`${WHITE}→  ${msg}${R}\n`);
}

/** Success line — "✓  Done". */
export function ok(msg: string): void {
  process.stdout.write(`${GREEN}✓  ${msg}${R}\n`);
}

/** Failure / abort line — "✕  Reason". */
export function fail(msg: string): void {
  process.stdout.write(`${RED}✕  ${msg}${R}\n`);
}

/** Warning line — "!  Heads up". */
export function warn(msg: string): void {
  process.stdout.write(`${YELLOW}!  ${msg}${R}\n`);
}

/** Bold section header — used to open a new visual block. */
export function header(title: string): void {
  process.stdout.write(`\n${BOLD}${WHITE}${title}${R}\n`);
}

/** Simple key:value pair rendered as dim-key colon bright-value. */
export function kv(key: string, value: string): void {
  process.stdout.write(`${GRAY}${key}:${R} ${WHITE}${value}${R}\n`);
}

/** Render a horizontal rule — thin, dim, full terminal width. */
export function rule(): void {
  const width = process.stdout.columns ?? 80;
  process.stdout.write(`${DIM}${GRAY}${"─".repeat(width)}${R}\n`);
}

/** Print raw text with no prefix — for diffs, config dumps, etc. */
export function raw(msg: string): void {
  process.stdout.write(`${msg}\n`);
}

/** Print a blank line. */
export function space(): void {
  process.stdout.write("\n");
}
