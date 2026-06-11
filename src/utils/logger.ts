/**
 * VibeGuard — Structured Debug Logging Engine
 *
 * Phase 15: Records execution metrics to a hidden local log file without
 * polluting the clean terminal UI. All writes are non-blocking — the log
 * engine never delays the active Git hook or HTTP test runner.
 *
 * Design:
 *   - JSON Lines (.jsonl) format — each line is a self-contained JSON object.
 *   - Append-only file stream: .vibeguard/logs/engine_debug.log.
 *   - Log directory is auto-created on first write.
 *   - All writes use asynchronous fs.appendFile — zero blocking I/O.
 *   - Verbose payloads and network headers are piped here instead of stdout.
 *
 * Zero runtime dependencies — uses only Node.js built-ins.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** Directory under the project root where log files are stored. */
const LOG_DIR = ".vibeguard/logs";

/** Log filename. */
const LOG_FILE = "engine_debug.log";

/** Maximum log file size before rotation (~10 MB). */
const MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024;

/** Number of rotated backup files to keep. */
const MAX_BACKUPS = 3;

// ─── Public Types ───────────────────────────────────────────────────────────────

/** Log severity levels. */
export type LogLevel = "info" | "warn" | "error";

/** Log context identifiers for traceability through the 10-phase pipeline. */
export type LogContext =
  | "cli_entry"
  | "git_parser"
  | "diff_filter"
  | "llm_client"
  | "connectivity"
  | "route_mapper"
  | "db_guard"
  | "compliance"
  | "payload_gen"
  | "runner"
  | "assertion"
  | "healer"
  | "webhooks"
  | "exporter"
  | "runtime_crash"
  | "config"
  | "cache";

/** Shape of a single log entry written to disk. */
export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  context: LogContext;
  message: string;
}

// ─── State ──────────────────────────────────────────────────────────────────────

/** Cached path to the log file, resolved lazily on first write. */
let logFilePath: string | null = null;

/** Pending write promise — used to serialize writes without blocking the caller. */
let writeQueue: Promise<void> = Promise.resolve();

/** Tracks approximate current log file size to trigger rotation. */
let currentLogSize = 0;

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Initialize the logger — resolves the project root and ensures the
 * log directory exists. Called automatically on first write if not
 * explicitly invoked.
 *
 * @param projectRoot - Absolute path to the project root.
 */
export async function initLogger(projectRoot: string): Promise<void> {
  const logDir = path.join(projectRoot, LOG_DIR);

  // Ensure the log directory exists.
  try {
    await fs.mkdir(logDir, { recursive: true });
  } catch {
    // Directory already exists or cannot be created.
  }

  logFilePath = path.join(logDir, LOG_FILE);

  // Check current log file size for rotation decision.
  try {
    const stat = await fs.stat(logFilePath);
    currentLogSize = stat.size;
  } catch {
    currentLogSize = 0;
  }

  // Rotate if file exceeds max size.
  if (currentLogSize > MAX_LOG_SIZE_BYTES) {
    await rotateLogs(logDir);
    currentLogSize = 0;
  }
}

/**
 * Write a structured log entry to disk.
 *
 * This is the primary public interface. Writes are queued asynchronously
 * so that rapid-fire calls never interleave or block the event loop.
 *
 * @param level   - Severity level.
 * @param context - Pipeline context identifier.
 * @param message - Free-form debug message or error dump.
 */
export function write(
  level: LogLevel,
  context: LogContext,
  message: string
): void {
  // Chain writes through the queue to prevent interleaving without blocking.
  writeQueue = writeQueue.then(() => writeImmediate(level, context, message));
}

/**
 * Synchronous variant for use in crash handlers where async I/O may
 * not complete before process.exit. Uses fs.writeFileSync to guarantee
 * the entry hits disk before the process terminates.
 *
 * @param level   - Severity level.
 * @param context - Pipeline context identifier.
 * @param message - Free-form debug message or error dump.
 * @param projectRoot - Absolute path to the project root.
 */
export function writeSync(
  level: LogLevel,
  context: LogContext,
  message: string,
  projectRoot: string
): void {
  try {
    const fsSync = require("fs") as typeof import("fs");
    const logDir = path.join(projectRoot, LOG_DIR);

    // Synchronous directory creation.
    try { fsSync.mkdirSync(logDir, { recursive: true }); } catch { /* ok */ }

    const filePath = path.join(logDir, LOG_FILE);
    const entry = formatEntry(level, context, message);
    fsSync.appendFileSync(filePath, entry, "utf-8");
  } catch {
    // Absolute last resort — cannot log the logging failure.
  }
}

// ─── Internal Helpers ───────────────────────────────────────────────────────────

/**
 * Write a single log entry to disk immediately (called from the queue).
 */
async function writeImmediate(
  level: LogLevel,
  context: LogContext,
  message: string
): Promise<void> {
  // Lazy initialization on first write.
  if (!logFilePath) {
    // Try to discover the project root.
    const cwd = process.cwd();
    await initLogger(cwd);
  }

  if (!logFilePath) return; // Cannot resolve path — silently skip.

  const entry = formatEntry(level, context, message);
  const entryBytes = Buffer.byteLength(entry, "utf-8");

  try {
    await fs.appendFile(logFilePath, entry, "utf-8");
    currentLogSize += entryBytes;

    // Check rotation threshold after write.
    if (currentLogSize > MAX_LOG_SIZE_BYTES) {
      const logDir = path.dirname(logFilePath);
      await rotateLogs(logDir);
      currentLogSize = 0;
    }
  } catch {
    // Log write failed — silently ignore. We never crash on logging failure.
  }
}

/**
 * Format a structured log entry as a single JSON line.
 */
function formatEntry(level: LogLevel, context: LogContext, message: string): string {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    context,
    message: message.length > 4000
      ? message.slice(0, 3997) + "..."
      : message,
  };

  return JSON.stringify(entry) + "\n";
}

/**
 * Rotate log files: engine_debug.log → engine_debug.1.log, etc.
 * Keeps up to MAX_BACKUPS old files, discarding the oldest.
 */
async function rotateLogs(logDir: string): Promise<void> {
  // Shift existing backups: 2 → 3, 1 → 2, current → 1.
  for (let i = MAX_BACKUPS; i >= 1; i--) {
    const oldFile = path.join(logDir, `engine_debug.${i}.log`);
    const newFile = path.join(logDir, `engine_debug.${i + 1}.log`);

    if (i === MAX_BACKUPS) {
      // Remove the oldest backup.
      try { await fs.unlink(oldFile); } catch { /* ok */ }
    } else {
      try { await fs.rename(oldFile, newFile); } catch { /* ok */ }
    }
  }

  // Rename current log to .1.
  const currentFile = path.join(logDir, LOG_FILE);
  const firstBackup = path.join(logDir, "engine_debug.1.log");
  try { await fs.rename(currentFile, firstBackup); } catch { /* ok */ }
}

/**
 * Ensure the log directory is listed in .gitignore.
 * Called by the hook installer (Phase 15 extension).
 *
 * @param projectRoot - Absolute path to the project root.
 */
export function ensureLogsGitignored(projectRoot: string): void {
  const fsSync = require("fs") as typeof import("fs");
  const gitignorePath = path.join(projectRoot, ".gitignore");

  let lines: string[] = [];
  let exists = false;

  try {
    lines = fsSync.readFileSync(gitignorePath, "utf-8").split(/\r?\n/);
    exists = true;
  } catch {
    // .gitignore doesn't exist.
  }

  const logPattern = ".vibeguard/logs/";

  for (const line of lines) {
    if (line.trim() === logPattern) return; // Already present.
  }

  if (exists) {
    const lastLine = lines.length > 0 ? lines[lines.length - 1].trim() : "";
    if (lastLine !== "") lines.push("");
  }

  lines.push("# Phase 15: Structured debug logs (never commit)");
  lines.push(logPattern);

  try {
    fsSync.writeFileSync(gitignorePath, lines.join("\n") + "\n", "utf-8");
  } catch {
    // Best-effort.
  }
}
