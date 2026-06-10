/**
 * VibeGuard — Shared Type Definitions
 *
 * Core interfaces for configuration, git diff analysis, and hook payloads.
 * Every module imports from here to maintain a single source of truth.
 */

// ─── Configuration ───────────────────────────────────────────────────────────

export type LLMProvider = "custom" | "openai" | "anthropic";

export interface VibeGuardConfig {
  /** LLM provider identifier — "custom" for self-hosted / local gateways */
  llm_provider: LLMProvider;

  /** Full URL to the LLM API endpoint (e.g. http://localhost:11434/v1 or https://api.openai.com/v1) */
  llm_api_endpoint: string;

  /** Raw string OR an environment variable reference (e.g. "$OPENAI_API_KEY") */
  llm_api_key: string;

  /** Model identifier (e.g. "gpt-4o", "claude-fable-5", "llama3:8b") */
  llm_model: string;

  /** Base URL of the locally running dev server under test (e.g. http://localhost:8000) */
  target_local_url: string;

  /** Glob-style paths to exclude from analysis (e.g. ["vendor/**", "node_modules/**"]) */
  exclude_paths: string[];
}

/** Shape of the raw JSON on disk before validation. */
export type RawConfig = Partial<VibeGuardConfig> & { [key: string]: unknown };

// ─── Git Diff Structures ─────────────────────────────────────────────────────

export type FileStatus = "added" | "modified" | "deleted" | "renamed";

/** A single line within a diff hunk. */
export interface DiffLine {
  type: "add" | "delete" | "context";
  content: string;
  oldLineNumber?: number;
  newLineNumber?: number;
}

/** One contiguous change block within a file. */
export interface DiffHunk {
  header: string; // e.g. "@@ -12,7 +12,9 @@ import { foo } from './bar';"
  lines: DiffLine[];
}

/** Structured representation of a single file's changes. */
export interface DiffFile {
  path: string;
  status: FileStatus;
  oldPath?: string; // populated for renames
  additions: number;
  deletions: number;
  hunks: DiffHunk[];
}

/** The complete parsed diff ready for LLM consumption. */
export interface DiffResult {
  files: DiffFile[];
  totalAdditions: number;
  totalDeletions: number;
  rawDiff: string;
}

// ─── Hook Runtime Payload ────────────────────────────────────────────────────

/** Parsed from stdin when the pre-push hook fires. */
export interface PushRef {
  localRef: string; // e.g. "refs/heads/feature/foo"
  localSha: string;
  remoteRef: string; // e.g. "refs/heads/main"
  remoteSha: string;
  localBranch: string; // "feature/foo"
  remoteBranch: string; // "main"
}

/** Arguments passed to the internal `vibeguard run` command. */
export interface RunArgs {
  localBranch: string;
  remoteBranch: string;
  sha: string;
}
