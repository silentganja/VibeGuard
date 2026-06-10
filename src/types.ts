/**
 * VibeGuard — Shared Type Definitions
 *
 * Core interfaces for configuration, git diff analysis, and hook payloads.
 * Every module imports from here to maintain a single source of truth.
 */

// ─── Configuration ───────────────────────────────────────────────────────────

export type LLMProvider = "custom" | "openai" | "anthropic";

/** Supported database dialect for state guarding. */
export type DbType = "mysql" | "postgresql" | "sqlite" | "none";

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

  // ── Phase 4: Database State Guard ────────────────────────────────────

  /** Database dialect to guard. "none" disables state capture. */
  db_type?: DbType;

  /** Database hostname or IP (MySQL / PostgreSQL). */
  db_host?: string;

  /** Database port (MySQL default 3306, PostgreSQL default 5432). */
  db_port?: number;

  /** Database user for snapshot and restore operations. */
  db_user?: string;

  /** Database password. Supports $ENV_VAR references. */
  db_pass?: string;

  /** Database or schema name. */
  db_name?: string;

  /** Absolute or relative path to the SQLite database file. */
  db_sqlite_path?: string;
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

// ─── Phase 2: Parser & Noise Filter ────────────────────────────────────────────

/** Known vulnerability vector identifiers surfaced by the LLM. */
export type VulnerabilityVector =
  | "sql_injection"
  | "privilege_escalation"
  | "auth_bypass"
  | "rce"
  | "input_fuzzing"
  | "xss"
  | "path_traversal"
  | "ssrf"
  | "idor"
  | "race_condition"
  | "deserialization"
  | "information_disclosure"
  | "misconfiguration"
  | "other";

/** HTTP method detected from route-level code analysis. */
export type HttpMethod = "POST" | "GET" | "PUT" | "DELETE" | "PATCH" | "UNKNOWN";

/** A single endpoint modification detected by the LLM. */
export interface ModifiedEndpoint {
  /** Relative file path from project root. */
  file_path: string;

  /** Best-guess route string (e.g. "/api/v1/auth.php"). */
  estimated_route: string;

  /** HTTP method inferred from the code change. */
  http_method: HttpMethod;

  /** Natural-language description of what the code change intends to do. */
  detected_intent: string;

  /** Potential vulnerability classes flagged. */
  vulnerability_vectors: VulnerabilityVector[];

  /** Variable names, POST params, or user-controlled inputs observed. */
  input_parameters: string[];
}

/** The complete structured response expected from the LLM. */
export interface LLMAnalysisResult {
  modified_endpoints: ModifiedEndpoint[];
}

/** Internal representation of the scanner verdict for hook pass/fail logic. */
export interface AnalysisVerdict {
  /** Whether the push should be allowed. */
  pass: boolean;

  /** Map of file → severity-weighted risk summary. */
  risk_summary: Record<string, { severity: "low" | "medium" | "high" | "critical"; vectors: VulnerabilityVector[] }>;

  /** The raw structured result from the LLM. */
  result: LLMAnalysisResult;

  /** Human-readable explanation for the terminal. */
  explanation: string;
}

// ─── Phase 2: Filtered Diff Structures ─────────────────────────────────────────

/** A single sanitized change line within a filtered hunk. */
export interface FilteredLine {
  type: "add" | "delete" | "context";
  content: string;
}

/** A filtered hunk — only functional changes, no comments/whitespace noise. */
export interface FilteredHunk {
  header: string;
  /** Inferred function or endpoint name from the hunk context (if detectable). */
  surrounding_context: string | null;
  lines: FilteredLine[];
}

/** A filtered file diff ready for LLM consumption. */
export interface FilteredFile {
  path: string;
  status: FileStatus;
  additions: number;
  deletions: number;
  hunks: FilteredHunk[];
}

/** The output of the noise filter — a token-optimized diff footprint. */
export interface FilteredDiff {
  files: FilteredFile[];
  totalAdditions: number;
  totalDeletions: number;
  /** Files that were discarded by the filter, with reason. */
  discarded: Array<{ path: string; reason: string }>;
  /** Estimated token count of the filtered payload. */
  estimatedTokens: number;
}

// ─── Phase 3: Target Mapper ────────────────────────────────────────────────────

/** The URL-mapping strategy used to resolve a route. */
export type MappingStrategy = "traditional" | "framework" | "unresolved";

/** A single executable test target resolved from an LLM-detected endpoint. */
export interface ExecutableTest {
  /** The fully resolved local URL to test (e.g. http://localhost:8000/api/v1/auth.php). */
  resolved_url: string;

  /** HTTP method to use when probing this endpoint. */
  http_method: HttpMethod;

  /** Parameters / input fields detected by the LLM. */
  input_parameters: string[];

  /** Vulnerability classes flagged for this endpoint. */
  vulnerability_vectors: VulnerabilityVector[];

  /** The relative file path this test is derived from. */
  associated_file: string;

  /** Which mapping strategy was used to resolve the URL. */
  mapping_strategy: MappingStrategy;

  /** Human-readable note about how the URL was resolved (for debugging). */
  mapping_note: string;
}

/** The Phase 3 output — a structured set of executable test definitions. */
export interface TargetTargets {
  executable_tests: ExecutableTest[];
}

/** Result of the connectivity pre-flight check. */
export interface ServerCheckResult {
  /** Whether the local dev server responded within the timeout. */
  reachable: boolean;

  /** HTTP status code returned (if any). */
  statusCode: number | null;

  /** Latency in milliseconds (if reachable). */
  latencyMs: number | null;

  /** Error message if unreachable. */
  error: string | null;
}

/** Framework type detected in the project root. */
export type FrameworkType =
  | "nodejs"       // package.json
  | "go"           // go.mod
  | "php-laravel"  // composer.json + artisan
  | "php-symfony"  // composer.json + bin/console
  | "php-raw"      // composer.json without framework markers
  | "python"       // requirements.txt, pyproject.toml
  | "ruby"         // Gemfile
  | "rust"         // Cargo.toml
  | "elixir"       // mix.exs
  | "unknown";     // No recognizable framework

/** Public subfolder candidates — stripped from file paths in traditional mapping. */
export const PUBLIC_SUBFOLDER_CANDIDATES = [
  "public",
  "www",
  "htdocs",
  "web",
  "public_html",
  "html",
  "dist",
  "build",
  "static",
] as const;

// ─── Phase 4: Database State Guard ─────────────────────────────────────────────

/** A database table discovered from scanning the diff for SQL keywords. */
export interface DiscoveredTable {
  /** Table name extracted from the query. */
  tableName: string;
  /** The SQL operation that referenced this table (SELECT, UPDATE, INSERT, DELETE, etc.). */
  operation: string;
  /** The file where this reference was found. */
  sourceFile: string;
}

/** Result returned by dbGuard.capture(). */
export interface SnapshotResult {
  /** Whether the snapshot was successfully taken. */
  success: boolean;
  /** Path to the snapshot artifact (SQLite backup file or SQL dump file). */
  artifactPath: string | null;
  /** List of tables covered by the snapshot. */
  tables: DiscoveredTable[];
  /** Strategy used: "binary_copy" | "sql_dump" | "none". */
  strategy: "binary_copy" | "sql_dump" | "none";
  /** Human-readable summary of what was captured. */
  summary: string;
  /** Error message if success is false. */
  error: string | null;
}

/** Result returned by dbGuard.restore(). */
export interface RestoreResult {
  /** Whether the restore was successfully applied. */
  success: boolean;
  /** Strategy used for restore: "binary_copy" | "sql_restore" | "rollback" | "none". */
  strategy: "binary_copy" | "sql_restore" | "rollback" | "none";
  /** Human-readable summary of the restore operation. */
  summary: string;
  /** Error message if success is false. */
  error: string | null;
}

/** Configuration needed to establish a database connection. */
export interface DbConnectionConfig {
  type: DbType;
  host: string;
  port: number;
  user: string;
  pass: string;
  name: string;
  sqlitePath: string;
}
