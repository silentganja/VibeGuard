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

  // ── Phase 12: LLM Caching & Rate Limit Handling ────────────────────────

  /** Maximum number of retry attempts for rate-limited (429) or server-error (5xx) responses. Default: 3. */
  llm_max_retries?: number;

  /** Enable diff-hash-based response caching to skip redundant LLM calls. Default: true. */
  llm_cache_enabled?: boolean;

  // ── Phase 13: Webhook Notification Engine ────────────────────────────

  /** Slack incoming webhook URL for CI/CD vulnerability alerts. */
  webhook_slack?: string;

  /** Discord incoming webhook URL for CI/CD vulnerability alerts. */
  webhook_discord?: string;

  /** Microsoft Teams incoming webhook URL for CI/CD vulnerability alerts. */
  webhook_teams?: string;

  // ── Phase 14: Automated Test Export ──────────────────────────────────

  /** Enable automatic regression test generation from confirmed vulnerabilities. Default: true. */
  export_tests_enabled?: boolean;

  /** Test framework format for generated regression tests. Default: "bash". */
  export_tests_framework?: "jest" | "bash";

  /** Directory for generated regression test files. Default: ".vibeguard/tests". */
  export_tests_dir?: string;

  // ── Fix #1: Server Lifetime Management ──────────────────────────────

  /** Shell command to start the local dev server (e.g. "docker-compose up -d local-api"). */
  server_start_command?: string;

  /** Shell command to stop the local dev server (e.g. "docker-compose down"). */
  server_stop_command?: string;

  // ── Fix #2: Dynamic Authentication & Token Seeding ──────────────────

  /** Configuration for automatic token negotiation before adversarial tests run. */
  auth_seeding?: AuthSeedingConfig;

  // ── Fix #3: Concurrency Throttling ──────────────────────────────────

  /** Maximum concurrent HTTP requests during adversarial testing. Default: 3. */
  max_concurrent_requests?: number;
}

/** Configuration for dynamic auth token negotiation. */
export interface AuthSeedingConfig {
  /** Auth type to use when injecting the token into requests. */
  auth_type: "bearer" | "header" | "cookie" | "query";

  /** Shell command that produces a short-lived sandbox token on stdout. */
  token_generation_command: string;

  /** Custom header name (required when auth_type is "header"). */
  header_name?: string;

  /** Custom cookie name (required when auth_type is "cookie"). */
  cookie_name?: string;

  /** Custom query parameter name (required when auth_type is "query"). */
  query_param_name?: string;
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
  /** Vulnerability vectors explicitly ignored via @vibeguard-ignore directives in this file. */
  ignored_vectors: VulnerabilityVector[];
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
  /** Aggregated count of all ignored-vector directives found across files. */
  totalIgnoredVectors: number;
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

// ─── Phase 5: Compliance & Payload Generation ──────────────────────────────────

/** Result of the compliance verification step. */
export interface ComplianceResult {
  /** Whether all checks passed. */
  passed: boolean;
  /** README.md existence and content check. */
  readme_check: { ok: boolean; reason: string };
  /** Semantic commit message check. */
  commit_check: { ok: boolean; reason: string };
}

/** Valid Conventional Commits prefixes. */
export const CONVENTIONAL_COMMIT_PREFIXES = [
  "feat:",
  "fix:",
  "docs:",
  "style:",
  "refactor:",
  "perf:",
  "test:",
  "build:",
  "ci:",
  "chore:",
  "revert:",
  "security:",
] as const;

/** A single adversarial test payload. */
export interface AttackPayload {
  /** The target URL to fire this payload against. */
  target_url: string;
  /** HTTP method for the request. */
  method: "POST" | "GET";
  /** The vulnerability class this payload tests. */
  attack_type: VulnerabilityVector;
  /** Key-value pairs of parameter names to malicious values. */
  payload_data: Record<string, string>;
  /** What response indicates the attack succeeded. */
  expected_fail_criteria: string;
}

/** Container for the full attack suite returned by the LLM. */
export interface AttackSuite {
  attack_suite: AttackPayload[];
}

/** Result of the payload generation phase. */
export interface PayloadGenResult {
  /** Whether generation succeeded (LLM responded with parseable JSON). */
  success: boolean;
  /** The full attack suite. */
  attackSuite: AttackSuite;
  /** Count of payloads that were LLM-generated vs fallback-generated. */
  generatedCount: number;
  /** Count of payloads created via fallback when LLM parsing failed. */
  fallbackCount: number;
  /** Per-target errors, if any. */
  errors: Array<{ target_url: string; error: string }>;
}

// ─── Phase 6: Execution & Assertion ────────────────────────────────────────────

/** The outcome of a single assertion check against a response. */
export interface AssertionVerdict {
  /** Whether the assertion triggered (true = vulnerability confirmed). */
  triggered: boolean;
  /** Which assertion category fired. */
  category: "status_code" | "database_leak" | "auth_bypass" | "none";
  /** Human-readable explanation of what was detected. */
  detail: string;
  /** The matched signature or pattern that triggered (if any). */
  matched_signature: string | null;
}

/** Result of executing a single adversarial payload. */
export interface ExecutionResult {
  /** The payload that was executed. */
  payload: AttackPayload;
  /** HTTP status code returned by the server. */
  statusCode: number | null;
  /** Whether the request completed or timed out / errored. */
  completed: boolean;
  /** Response latency in milliseconds. */
  latencyMs: number;
  /** First 2000 characters of the response body (for signature scanning). */
  responseBody: string;
  /** Response headers (as key-value pairs). */
  responseHeaders: Record<string, string>;
  /** Error message if the request failed entirely. */
  error: string | null;
  /** Assertion verdicts for this response. */
  assertions: AssertionVerdict[];
  /** Overall verdict: true if ANY assertion triggered (vulnerability confirmed). */
  vulnerable: boolean;
}

// ─── Phase 7: Self-Healing Patch Engine ──────────────────────────────────────

/** Aggregated exploit context for a single vulnerable test. */
export interface ExploitContext {
  /** The relative file path of the source file that failed. */
  source_file: string;
  /** The raw code contents of that file. */
  source_code: string;
  /** The specific payload data used in the successful attack. */
  payload_data: Record<string, string>;
  /** The attack type (vulnerability vector). */
  attack_type: VulnerabilityVector;
  /** The response signature or exception stack trace that triggered the failure. */
  response_signature: string;
  /** The target URL that was attacked. */
  target_url: string;
  /** HTTP method used. */
  http_method: string;
  /** The assertion category that triggered. */
  assertion_category: string;
  /** The assertion detail message. */
  assertion_detail: string;
}

/** Structured remediation response expected from the LLM. */
export interface RemediationResult {
  /** Whether the LLM provided a remediation. */
  remediation_applied: boolean;
  /** The vulnerability type that was patched. */
  vulnerability_type: string;
  /** Short explanation of why the code broke and how the fix resolves it. */
  explanation: string;
  /** The complete, corrected contents of the source file with security patches applied. */
  patched_code: string;
}

/** Result of the patch generation process for a single vulnerable file. */
export interface PatchResult {
  /** Whether a patch was successfully generated. */
  success: boolean;
  /** Path to the generated .patch file (relative to .vibeguard/patches/). */
  patchPath: string | null;
  /** The unified diff content. */
  patchContent: string | null;
  /** The vulnerability type that was addressed. */
  vulnerabilityType: string | null;
  /** Human-readable explanation of the fix. */
  explanation: string | null;
  /** Error message if generation failed. */
  error: string | null;
}

/** Aggregate report for the full test run. */
export interface TestReport {
  /** Every individual execution result. */
  results: ExecutionResult[];
  /** Number of tests that confirmed a vulnerability. */
  vulnerabilitiesFound: number;
  /** Number of tests that passed cleanly. */
  testsPassed: number;
  /** Number of tests that failed to execute (network error, timeout). */
  testsErrored: number;
  /** Overall pass/fail — true if NO vulnerabilities were confirmed. */
  overallPass: boolean;
  /** Human-readable summary for the terminal. */
  summary: string;
}
