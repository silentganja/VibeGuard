/**
 * VibeGuard — Core Module Barrel Export
 *
 * Foundation types, configuration management, and git hook installer.
 */

// Types (single source of truth for all interfaces)
export type {
  LLMProvider,
  DbType,
  VibeGuardConfig,
  RawConfig,
  FileStatus,
  DiffLine,
  DiffHunk,
  DiffFile,
  DiffResult,
  PushRef,
  RunArgs,
  VulnerabilityVector,
  HttpMethod,
  ModifiedEndpoint,
  LLMAnalysisResult,
  AnalysisVerdict,
  FilteredLine,
  FilteredHunk,
  FilteredFile,
  FilteredDiff,
  MappingStrategy,
  ExecutableTest,
  TargetTargets,
  ServerCheckResult,
  FrameworkType,
  DiscoveredTable,
  SnapshotResult,
  RestoreResult,
  DbConnectionConfig,
  ComplianceResult,
  AttackPayload,
  AttackSuite,
  PayloadGenResult,
  AssertionVerdict,
  ExecutionResult,
  ExploitContext,
  RemediationResult,
  PatchResult,
  TestReport,
} from "./types";

export {
  PUBLIC_SUBFOLDER_CANDIDATES,
  CONVENTIONAL_COMMIT_PREFIXES,
} from "./types";

// Configuration
export {
  findProjectRoot,
  validateConfig,
  readConfig,
  resolveApiKey,
  initConfig,
  printConfig,
  getDbConnectionConfig,
} from "./config";

// Git hooks
export {
  installHook,
  uninstallHook,
} from "./hooks";
