/**
 * VibeGuard — Diff Hash Cache Manager
 *
 * Phase 12: Eliminates redundant LLM API calls by hashing the sanitized
 * (post-Phase-2a) diff and caching LLM responses to the local filesystem.
 *
 * Design:
 *   · SHA-256 hash of the sanitized diff string — deterministic, fast, collision-resistant.
 *   · Cache entries stored as .vibeguard/cache/llm_<hash>.json in the project root.
 *   · Cache directory is .gitignore'd — never leaks into the repository.
 *   · Cache is optional; disabled when llm_cache_enabled is false or in CI mode.
 *
 * Zero runtime dependencies — uses Node.js built-in crypto, fs, and path.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** Directory under the project root where cache entries are stored. */
const CACHE_DIR = ".vibeguard/cache";

/** Prefix for cache filenames. */
const CACHE_FILE_PREFIX = "llm_";

/** File extension for cache entries. */
const CACHE_FILE_EXT = ".json";

/** Maximum age of a cache entry before it's considered stale (24 hours in ms). */
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Generate a deterministic SHA-256 hash of the sanitized diff payload.
 *
 * The hash is computed from the serialized diff string that would be sent
 * to the LLM — not the raw git diff. This means changing a code comment
 * (which the noise filter strips) does NOT bust the cache.
 *
 * @param diffPayload - The serialized, filtered diff string from buildDiffPayload().
 * @returns A 64-character lowercase hex SHA-256 digest.
 */
export function hashDiff(diffPayload: string): string {
  return crypto.createHash("sha256").update(diffPayload, "utf-8").digest("hex");
}

/**
 * Read a cached LLM response from the filesystem.
 *
 * Cache entries are keyed by the SHA-256 hash of the sanitized diff.
 * Stale entries (older than CACHE_MAX_AGE_MS) are treated as misses
 * and cleaned up automatically.
 *
 * @param hash       - The SHA-256 hash from hashDiff().
 * @param projectRoot - Absolute path to the project root.
 * @returns The cached response string, or null if no valid cache entry exists.
 */
export function readCache(hash: string, projectRoot: string): string | null {
  const cacheDir = path.join(projectRoot, CACHE_DIR);
  const cacheFile = path.join(cacheDir, CACHE_FILE_PREFIX + hash + CACHE_FILE_EXT);

  try {
    const stat = fs.statSync(cacheFile);

    // Check staleness.
    if (Date.now() - stat.mtimeMs > CACHE_MAX_AGE_MS) {
      // Stale — remove it.
      try { fs.unlinkSync(cacheFile); } catch { /* best-effort */ }
      return null;
    }

    const raw = fs.readFileSync(cacheFile, "utf-8");
    const entry = JSON.parse(raw) as CacheEntry;

    // Validate the entry structure.
    if (!entry || typeof entry.response !== "string") {
      // Corrupt entry — remove it.
      try { fs.unlinkSync(cacheFile); } catch { /* best-effort */ }
      return null;
    }

    return entry.response;
  } catch (err: unknown) {
    // File doesn't exist or can't be read — cache miss.
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      // Unexpected error — log but don't block.
      // (In CI, stderr is captured; locally it's visible.)
    }
    return null;
  }
}

/**
 * Write an LLM response to the filesystem cache.
 *
 * Creates the cache directory if it doesn't exist. Each entry is a small
 * JSON file containing the response text and metadata.
 *
 * @param hash        - The SHA-256 hash from hashDiff().
 * @param response    - The raw LLM response text to cache.
 * @param projectRoot - Absolute path to the project root.
 */
export function writeCache(hash: string, response: string, projectRoot: string): void {
  const cacheDir = path.join(projectRoot, CACHE_DIR);

  // Ensure the cache directory exists.
  ensureDir(cacheDir);

  const cacheFile = path.join(cacheDir, CACHE_FILE_PREFIX + hash + CACHE_FILE_EXT);

  const entry: CacheEntry = {
    hash,
    response,
    cachedAt: new Date().toISOString(),
    version: "1.0.0",
  };

  try {
    fs.writeFileSync(cacheFile, JSON.stringify(entry, null, 2), "utf-8");
  } catch {
    // Cache write failed — non-blocking. The pipeline continues without caching.
  }
}

/**
 * Get the path to the cache directory (for .gitignore management).
 *
 * @param projectRoot - Absolute path to the project root.
 * @returns Absolute path to the .vibeguard/cache/ directory.
 */
export function getCacheDir(projectRoot: string): string {
  return path.join(projectRoot, CACHE_DIR);
}

/**
 * Ensure the cache directory is listed in the project's .gitignore.
 *
 * Called by the hook installer to guarantee cache files never leak into
 * the repository. Appends the entry if not already present.
 *
 * @param projectRoot - Absolute path to the project root.
 */
export function ensureCacheGitignored(projectRoot: string): void {
  const gitignorePath = path.join(projectRoot, ".gitignore");

  let lines: string[] = [];
  let exists = false;

  try {
    lines = fs.readFileSync(gitignorePath, "utf-8").split(/\r?\n/);
    exists = true;
  } catch {
    // .gitignore doesn't exist — will be created.
  }

  const cachePattern = ".vibeguard/cache/";

  // Check if already gitignored.
  for (const line of lines) {
    if (line.trim() === cachePattern) {
      return; // Already present.
    }
  }

  // Append the cache pattern.
  if (exists) {
    // Add a blank line before our entry if the file doesn't end with one.
    const lastLine = lines.length > 0 ? lines[lines.length - 1].trim() : "";
    if (lastLine !== "") {
      lines.push("");
    }
  }

  lines.push("# Phase 12: LLM response cache (never commit)");
  lines.push(cachePattern);

  try {
    fs.writeFileSync(gitignorePath, lines.join("\n") + "\n", "utf-8");
  } catch {
    // Best-effort — the cache is local-only regardless.
  }
}

// ─── Internal Types ─────────────────────────────────────────────────────────────

interface CacheEntry {
  hash: string;
  response: string;
  cachedAt: string;
  version: string;
}

// ─── Internal Helpers ───────────────────────────────────────────────────────────

function ensureDir(dir: string): void {
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch {
    // Directory already exists or cannot be created — ignore.
  }
}
