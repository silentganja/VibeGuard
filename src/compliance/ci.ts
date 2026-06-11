/**
 * VibeGuard --” CI/CD Environment Detection & Enterprise Configuration
 *
 * Phase 9: Detects headless automation environments (GitHub Actions, GitLab CI,
 * Jenkins, CircleCI, etc.) and switches the engine into machine-readable,
 * non-interactive mode. Provides environment-variable-based configuration
 * fallback for environments where .vibeguard.json is not present.
 *
 * Design:
 *   - isHeadless() --” inspects process environment for known CI flags.
 *   - readConfigFromEnv() --” maps VIBE_* env vars to VibeGuardConfig.
 *   - getOutputMode() --” returns "ci" or "terminal" for output formatting.
 *   - Zero runtime dependencies --” uses only process.env inspection.
 */

import type { VibeGuardConfig, DbType, LLMProvider } from "../core/types";

// â”€â”€â”€ CI Detection Flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Known environment variables that indicate a CI/CD automation environment.
 *
 * These are set by major CI providers and are widely recognized conventions.
 * The `CI` variable is the de-facto standard (set by GitHub Actions, GitLab CI,
 * Travis CI, CircleCI, and many others).
 */
const CI_FLAGS: string[] = [
  "CI",                    // Universal CI flag (GitHub Actions, GitLab, Travis, Circle, etc.)
  "GITHUB_ACTIONS",        // GitHub Actions
  "GITLAB_CI",             // GitLab CI/CD
  "JENKINS_HOME",          // Jenkins
  "TRAVIS",                // Travis CI
  "CIRCLECI",              // CircleCI
  "TF_BUILD",              // Azure DevOps Pipelines
  "BITBUCKET_BUILD_NUMBER",// Bitbucket Pipelines
  "BUILDKITE",             // Buildkite
  "DRONE",                  // Drone CI
  "CODEBUILD_BUILD_ID",    // AWS CodeBuild
  "BUDDY",                 // Buddy CI/CD
  "SEMAPHORE",             // Semaphore CI
  "APPVEYOR",              // AppVeyor
  "TEAMCITY_VERSION",      // TeamCity
  "GOCD_SERVER_URL",       // GoCD
  "BAMBOO_AGENT_HOME",     // Bamboo
];

/**
 * Custom VibeGuard flag for forcing enterprise/headless mode.
 *
 * Set VIBE_ENV=enterprise to force headless mode even on a local machine.
 * This is useful for testing CI behavior locally or running VibeGuard in
 * automated scripts that are not traditional CI pipelines.
 */
const ENTERPRISE_FLAG = "VIBE_ENV";
const ENTERPRISE_VALUE = "enterprise";

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Determine whether VibeGuard is running in a headless CI/CD environment.
 *
 * Returns true if ANY of the following conditions are met:
 *   1. A recognized CI environment variable is set to a truthy value.
 *   2. VIBE_ENV is set to "enterprise" (explicit opt-in).
 *   3. The process has no TTY attached (stdin is not a terminal).
 *
 * When headless, VibeGuard will:
 *   - Skip interactive prompts (init wizard, config creation).
 *   - Disable ANSI color codes in output.
 *   - Output machine-readable text streams.
 *   - Not write to .git/hooks.
 *   - Bypass the Phase 7 patch viewer UI.
 */
export function isHeadless(): boolean {
  // Check explicit enterprise flag first (user override).
  if (process.env[ENTERPRISE_FLAG] === ENTERPRISE_VALUE) {
    return true;
  }

  // Check for known CI environment variables.
  for (const flag of CI_FLAGS) {
    if (process.env[flag]) {
      // Some CI systems set CI=false --” respect that.
      if (flag === "CI" && process.env.CI === "false") {
        continue;
      }
      return true;
    }
  }

  // Check if stdin is not a TTY (piped input = headless).
  if (!process.stdin.isTTY) {
    return true;
  }

  return false;
}

/**
 * Get the current output mode based on the execution environment.
 *
 *   "ci"       --” Headless CI/CD pipeline; machine-readable, no ANSI colors.
 *   "terminal" --” Local developer terminal; full ANSI UX, interactive.
 */
export function getOutputMode(): "ci" | "terminal" {
  return isHeadless() ? "ci" : "terminal";
}

/**
 * Detect which CI platform is running (for diagnostic/logging purposes).
 *
 * Returns the name of the first detected CI platform, or null if none.
 */
export function detectCIPlatform(): string | null {
  if (process.env.GITHUB_ACTIONS === "true") return "GitHub Actions";
  if (process.env.GITLAB_CI === "true") return "GitLab CI/CD";
  if (process.env.JENKINS_HOME) return "Jenkins";
  if (process.env.TRAVIS === "true") return "Travis CI";
  if (process.env.CIRCLECI === "true") return "CircleCI";
  if (process.env.TF_BUILD === "true") return "Azure DevOps";
  if (process.env.BITBUCKET_BUILD_NUMBER) return "Bitbucket Pipelines";
  if (process.env.BUILDKITE === "true") return "Buildkite";
  if (process.env.DRONE === "true") return "Drone CI";
  if (process.env.CODEBUILD_BUILD_ID) return "AWS CodeBuild";
  if (process.env.SEMAPHORE === "true") return "Semaphore CI";
  if (process.env.APPVEYOR === "true") return "AppVeyor";
  if (process.env.TEAMCITY_VERSION) return "TeamCity";
  if (process.env.BAMBOO_AGENT_HOME) return "Bamboo";
  if (process.env[ENTERPRISE_FLAG] === ENTERPRISE_VALUE) return "Enterprise Mode";

  // Generic CI flag is set but no specific platform identified.
  if (process.env.CI === "true") return "Generic CI";

  return null;
}

// â”€â”€â”€ Environment Variable â†’ Config Mapping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Environment variable keys used for CI/CD configuration.
 *
 * When .vibeguard.json is missing (common in CI where config files are
 * .gitignore'd) or when running headless, VibeGuard reads configuration
 * from these environment variables.
 */
const ENV_LLM_PROVIDER = "VIBE_LLM_PROVIDER";
const ENV_LLM_ENDPOINT = "VIBE_LLM_ENDPOINT";
const ENV_LLM_KEY = "VIBE_LLM_KEY";
const ENV_LLM_MODEL = "VIBE_LLM_MODEL";
const ENV_TARGET_URL = "VIBE_TARGET_URL";
const ENV_EXCLUDE_PATHS = "VIBE_EXCLUDE_PATHS";
const ENV_DB_TYPE = "VIBE_DB_TYPE";
const ENV_DB_HOST = "VIBE_DB_HOST";
const ENV_DB_PORT = "VIBE_DB_PORT";
const ENV_DB_USER = "VIBE_DB_USER";
const ENV_DB_PASS = "VIBE_DB_PASS";
const ENV_DB_NAME = "VIBE_DB_NAME";
const ENV_DB_SQLITE_PATH = "VIBE_DB_SQLITE_PATH";
const ENV_WEBHOOK_SLACK = "VIBE_WEBHOOK_SLACK";
const ENV_WEBHOOK_DISCORD = "VIBE_WEBHOOK_DISCORD";
const ENV_WEBHOOK_TEAMS = "VIBE_WEBHOOK_TEAMS";

/** Valid LLM provider values. */
const VALID_PROVIDERS = new Set<string>(["custom", "openai", "anthropic"]);

/** Valid DB type values. */
const VALID_DB_TYPES = new Set<string>(["mysql", "postgresql", "sqlite", "none"]);

/**
 * Read VibeGuard configuration from environment variables.
 *
 * This is the CI/CD fallback when .vibeguard.json is not present.
 * All fields are optional --” missing required fields will be caught by
 * the config validation step (validateConfig).
 *
 * Resolution matrix:
 *   VIBE_LLM_PROVIDER  â†’ llm_provider
 *   VIBE_LLM_ENDPOINT  â†’ llm_api_endpoint
 *   VIBE_LLM_KEY       â†’ llm_api_key
 *   VIBE_LLM_MODEL     â†’ llm_model
 *   VIBE_TARGET_URL    â†’ target_local_url
 *   VIBE_EXCLUDE_PATHS â†’ exclude_paths (comma-separated)
 *   VIBE_DB_TYPE       â†’ db_type
 *   VIBE_DB_HOST       â†’ db_host
 *   VIBE_DB_PORT       â†’ db_port (parsed as integer)
 *   VIBE_DB_USER       â†’ db_user
 *   VIBE_DB_PASS       â†’ db_pass
 *   VIBE_DB_NAME       â†’ db_name
 *   VIBE_DB_SQLITE_PATH â†’ db_sqlite_path
 *
 * @returns A partial VibeGuardConfig populated from environment variables.
 */
export function readConfigFromEnv(): Partial<VibeGuardConfig> {
  const config: Partial<VibeGuardConfig> = {};

  // â”€â”€ LLM Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const provider = process.env[ENV_LLM_PROVIDER];
  if (provider && VALID_PROVIDERS.has(provider)) {
    config.llm_provider = provider as LLMProvider;
  }

  const endpoint = process.env[ENV_LLM_ENDPOINT];
  if (endpoint) {
    config.llm_api_endpoint = endpoint;
  }

  const apiKey = process.env[ENV_LLM_KEY];
  if (apiKey) {
    config.llm_api_key = apiKey;
  }

  const model = process.env[ENV_LLM_MODEL];
  if (model) {
    config.llm_model = model;
  }

  // â”€â”€ Target Server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const targetUrl = process.env[ENV_TARGET_URL];
  if (targetUrl) {
    config.target_local_url = targetUrl;
  }

  const excludeRaw = process.env[ENV_EXCLUDE_PATHS];
  if (excludeRaw) {
    config.exclude_paths = excludeRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // â”€â”€ Database State Guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const dbType = process.env[ENV_DB_TYPE];
  if (dbType && VALID_DB_TYPES.has(dbType)) {
    config.db_type = dbType as DbType;
  }

  const dbHost = process.env[ENV_DB_HOST];
  if (dbHost) {
    config.db_host = dbHost;
  }

  const dbPort = process.env[ENV_DB_PORT];
  if (dbPort) {
    const parsed = parseInt(dbPort, 10);
    if (!isNaN(parsed)) {
      config.db_port = parsed;
    }
  }

  const dbUser = process.env[ENV_DB_USER];
  if (dbUser) {
    config.db_user = dbUser;
  }

  const dbPass = process.env[ENV_DB_PASS];
  if (dbPass !== undefined) {
    config.db_pass = dbPass;
  }

  const dbName = process.env[ENV_DB_NAME];
  if (dbName) {
    config.db_name = dbName;
  }

  const dbSqlitePath = process.env[ENV_DB_SQLITE_PATH];
  if (dbSqlitePath) {
    config.db_sqlite_path = dbSqlitePath;

  // Phase 13: Webhook URLs
  const webhookSlack = process.env[ENV_WEBHOOK_SLACK];
  if (webhookSlack) {
    config.webhook_slack = webhookSlack;
  }
  const webhookDiscord = process.env[ENV_WEBHOOK_DISCORD];
  if (webhookDiscord) {
    config.webhook_discord = webhookDiscord;
  }
  const webhookTeams = process.env[ENV_WEBHOOK_TEAMS];
  if (webhookTeams) {
    config.webhook_teams = webhookTeams;
  }
  }

  return config;
}

/**
 * Check whether all required config fields are present in an env-based config.
 *
 * In CI/CD, llm_provider, llm_api_endpoint, llm_api_key, llm_model, and
 * target_local_url are all required.
 *
 * @returns Array of missing field names. Empty array = all required fields present.
 */
export function getMissingEnvConfigFields(): string[] {
  const missing: string[] = [];

  if (!process.env[ENV_LLM_PROVIDER]) missing.push(ENV_LLM_PROVIDER);
  if (!process.env[ENV_LLM_ENDPOINT]) missing.push(ENV_LLM_ENDPOINT);
  if (!process.env[ENV_LLM_KEY]) missing.push(ENV_LLM_KEY);
  if (!process.env[ENV_LLM_MODEL]) missing.push(ENV_LLM_MODEL);
  if (!process.env[ENV_TARGET_URL]) missing.push(ENV_TARGET_URL);

  return missing;
}

// â”€â”€â”€ Environment Variable Key Constants (for external reference) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Export the env var key names so other modules can reference them
 * in error messages and documentation without hardcoding strings.
 */
export const ENV_KEYS = {
  LLM_PROVIDER: ENV_LLM_PROVIDER,
  LLM_ENDPOINT: ENV_LLM_ENDPOINT,
  LLM_KEY: ENV_LLM_KEY,
  LLM_MODEL: ENV_LLM_MODEL,
  TARGET_URL: ENV_TARGET_URL,
  EXCLUDE_PATHS: ENV_EXCLUDE_PATHS,
  DB_TYPE: ENV_DB_TYPE,
  DB_HOST: ENV_DB_HOST,
  DB_PORT: ENV_DB_PORT,
  DB_USER: ENV_DB_USER,
  DB_PASS: ENV_DB_PASS,
  DB_NAME: ENV_DB_NAME,
  DB_SQLITE_PATH: ENV_DB_SQLITE_PATH,
  WEBHOOK_SLACK: ENV_WEBHOOK_SLACK,
  WEBHOOK_DISCORD: ENV_WEBHOOK_DISCORD,
  WEBHOOK_TEAMS: ENV_WEBHOOK_TEAMS,
} as const;
