/**
 * VibeGuard â€” Configuration Manager
 *
 * Reads, writes, and validates `.vibeguard.json` at the project root.
 * The project root is discovered by walking upward from cwd until a `.git`
 * directory or folder is found.
 *
 * LLM API keys may be stored as raw strings OR as environment variable
 * references prefixed with `$` (e.g. "$OPENAI_API_KEY"). The resolver
 * expands these at read time.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import type { VibeGuardConfig, RawConfig, DbConnectionConfig } from "./types";
import { isHeadless, detectCIPlatform, readConfigFromEnv, getMissingEnvConfigFields, ENV_KEYS } from "../compliance/ci";
import * as ui from "../cli/ui";

// â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const CONFIG_FILENAME = ".vibeguard.json";

const VALID_PROVIDERS = new Set(["custom", "openai", "anthropic"]);

const DEFAULT_CONFIG: VibeGuardConfig = {
  llm_provider: "custom",
  llm_api_endpoint: "http://localhost:11434/v1",
  llm_api_key: "$LLM_API_KEY",
  llm_model: "llama3:8b",
  target_local_url: "http://localhost:8000",
  exclude_paths: ["node_modules/**", "vendor/**", ".git/**", "dist/**", "build/**"],
  // Phase 4 defaults
  db_type: "none",
  db_host: "127.0.0.1",
  db_port: 3306,
  db_user: "root",
  db_pass: "",
  db_name: "",
  db_sqlite_path: "",
};

// â”€â”€â”€ Project Root Discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Walk upward from `startDir` until a `.git` entry is found. */
export function findProjectRoot(startDir: string = process.cwd()): string | null {
  let current = path.resolve(startDir);

  for (let i = 0; i < 64; i++) {
    const gitPath = path.join(current, ".git");
    try {
      const stat = fs.statSync(gitPath);
      if (stat.isDirectory() || stat.isFile()) {
        return current;
      }
    } catch {
      // .git doesn't exist here, walk up
    }

    const parent = path.dirname(current);
    if (parent === current) break; // reached filesystem root
    current = parent;
  }
  return null;
}

// â”€â”€â”€ Path Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function configPath(root: string): string {
  return path.join(root, CONFIG_FILENAME);
}

// â”€â”€â”€ Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Validate a raw config object. Returns a list of human-readable errors. */
export function validateConfig(raw: Partial<VibeGuardConfig>): string[] {
  const errors: string[] = [];

  // llm_provider
  if (!raw.llm_provider) {
    errors.push("llm_provider is required (\"custom\" | \"openai\" | \"anthropic\")");
  } else if (!VALID_PROVIDERS.has(raw.llm_provider)) {
    errors.push(`llm_provider must be one of: ${[...VALID_PROVIDERS].join(", ")}`);
  }

  // llm_api_endpoint
  if (!raw.llm_api_endpoint || typeof raw.llm_api_endpoint !== "string") {
    errors.push("llm_api_endpoint is required (e.g. \"http://localhost:11434/v1\")");
  } else {
    try {
      new URL(raw.llm_api_endpoint);
    } catch {
      errors.push("llm_api_endpoint is not a valid URL");
    }
  }

  // llm_api_key
  if (!raw.llm_api_key || typeof raw.llm_api_key !== "string") {
    errors.push("llm_api_key is required (string or $ENV_VAR reference)");
  }

  // llm_model
  if (!raw.llm_model || typeof raw.llm_model !== "string") {
    errors.push("llm_model is required (e.g. \"gpt-4o\", \"claude-fable-5\")");
  }

  // target_local_url
  if (!raw.target_local_url || typeof raw.target_local_url !== "string") {
    errors.push("target_local_url is required (e.g. \"http://localhost:8000\")");
  } else {
    try {
      new URL(raw.target_local_url);
    } catch {
      errors.push("target_local_url is not a valid URL");
    }
  }

  // exclude_paths
  if (raw.exclude_paths !== undefined) {
    if (!Array.isArray(raw.exclude_paths)) {
      errors.push("exclude_paths must be an array of strings");
    } else {
      for (let i = 0; i < raw.exclude_paths.length; i++) {
        if (typeof raw.exclude_paths[i] !== "string") {
          errors.push(`exclude_paths[${i}] must be a string`);
        }
      }
    }
  }

  // â”€â”€ Phase 4: DB config validation (all fields are optional) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const VALID_DB_TYPES = new Set(["mysql", "postgresql", "sqlite", "none"]);

  if (raw.db_type !== undefined) {
    if (typeof raw.db_type !== "string" || !VALID_DB_TYPES.has(raw.db_type)) {
      errors.push('db_type must be one of: "mysql" | "postgresql" | "sqlite" | "none"');
    } else if (raw.db_type !== "none") {
      // When a DB type is active, validate related fields.
      if (raw.db_type === "sqlite") {
        if (raw.db_sqlite_path !== undefined && typeof raw.db_sqlite_path !== "string") {
          errors.push("db_sqlite_path must be a string (path to .db file)");
        }
      } else {
        // MySQL or PostgreSQL: host, port, user, name are needed.
        if (raw.db_host !== undefined && typeof raw.db_host !== "string") {
          errors.push("db_host must be a string");
        }
        if (raw.db_port !== undefined && typeof raw.db_port !== "number") {
          errors.push("db_port must be a number");
        }
        if (raw.db_user !== undefined && typeof raw.db_user !== "string") {
          errors.push("db_user must be a string");
        }
        if (raw.db_pass !== undefined && typeof raw.db_pass !== "string") {
          errors.push("db_pass must be a string (or $ENV_VAR)");
        }
        if (raw.db_name !== undefined && typeof raw.db_name !== "string") {
          errors.push("db_name must be a string");
        }
      }
    }
  }

  return errors;
}

// â”€â”€â”€ Reading â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Read and validate the config from the project root.
 *
 * Strategy:
 *   1. If running headless (CI/CD) â†’ skip filesystem config, read from env vars.
 *   2. If .vibeguard.json exists â†’ read and validate it (local dev mode).
 *   3. If .vibeguard.json is missing BUT env vars are set â†’ use env vars.
 *   4. If neither exists â†’ throw with actionable error message.
 *
 * Throws with a user-facing message if anything is wrong.
 */
export function readConfig(root?: string): VibeGuardConfig {
  const headless = isHeadless();

  // â”€â”€ Path 1: Headless CI/CD â€” use environment variables â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (headless) {
    const envConfig = readConfigFromEnv();

    // Merge with defaults for any missing fields.
    const merged = { ...DEFAULT_CONFIG, ...envConfig };

    const errors = validateConfig(merged);
    if (errors.length > 0) {
      const missingFields = getMissingEnvConfigFields();
      const platform = detectCIPlatform() ?? "CI/CD";

      let msg = `Invalid or missing ${platform} environment configuration:\n`;
      msg += `  ${errors.join("\n  ")}`;

      if (missingFields.length > 0) {
        msg += `\n\nMissing required environment variables:\n`;
        for (const field of missingFields) {
          msg += `  Â· ${field}\n`;
        }
        msg += `\nSet these variables in your CI pipeline configuration.`;
      }

      throw new Error(msg);
    }

    return merged as VibeGuardConfig;
  }

  // â”€â”€ Path 2 & 3: Local â€” try filesystem config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const projectRoot = root ?? findProjectRoot();

  const filePath = projectRoot
    ? path.join(projectRoot, CONFIG_FILENAME)
    : CONFIG_FILENAME;

  let raw: unknown;
  let fileExists = false;

  if (projectRoot) {
    try {
      const contents = fs.readFileSync(filePath, "utf-8");
      raw = JSON.parse(contents);
      fileExists = true;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new Error(
          `Failed to read ${CONFIG_FILENAME}: ${(err as Error).message}`
        );
      }
      // ENOENT â€” file doesn't exist. Fall through to env var check.
    }
  }

  // â”€â”€ Path 3: No config file â€” try env vars as fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!fileExists) {
    const envConfig = readConfigFromEnv();

    // If env vars provide the critical fields, use them.
    if (envConfig.llm_provider && envConfig.llm_api_endpoint &&
        envConfig.llm_api_key && envConfig.llm_model &&
        envConfig.target_local_url) {

      const merged = { ...DEFAULT_CONFIG, ...envConfig };
      const errors = validateConfig(merged);
      if (errors.length > 0) {
        throw new Error(
          `Invalid environment configuration:\n  ${errors.join("\n  ")}`
        );
      }

      return merged as VibeGuardConfig;
    }

    // No config file and insufficient env vars â€” cannot proceed.
    throw new Error(
      `No ${CONFIG_FILENAME} found and no ${ENV_KEYS.LLM_PROVIDER}/${ENV_KEYS.LLM_ENDPOINT}/${ENV_KEYS.LLM_KEY}/${ENV_KEYS.LLM_MODEL}/${ENV_KEYS.TARGET_URL} environment variables set.\n` +
      `Run \`vibeguard init\` to create a config file, or set the VIBE_* environment variables for CI/CD usage.`
    );
  }

  // â”€â”€ Path 2: Config file exists â€” validate and return â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${CONFIG_FILENAME} must contain a JSON object.`);
  }

  const errors = validateConfig(raw as RawConfig);
  if (errors.length > 0) {
    throw new Error(
      `Invalid ${CONFIG_FILENAME}:\n  ${errors.join("\n  ")}`
    );
  }

  return raw as VibeGuardConfig;
}

// â”€â”€â”€ API Key Resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Resolve an API key that may be an env-var reference.
 *   "$OPENAI_API_KEY" â†’ process.env.OPENAI_API_KEY
 *   "sk-abc123"       â†’ "sk-abc123" (passthrough)
 */
export function resolveApiKey(raw: string): string {
  if (raw.startsWith("$")) {
    const varName = raw.slice(1);
    const value = process.env[varName];
    if (!value) {
      throw new Error(
        `Environment variable "${varName}" is not set. ` +
        `(Referenced by llm_api_key in ${CONFIG_FILENAME})`
      );
    }
    return value;
  }
  return raw;
}

// â”€â”€â”€ Interactive Initialization â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Run the interactive `vibeguard init` wizard.
 * Prompts the user for each config field, shows defaults, writes the file.
 */
export async function initConfig(targetDir?: string): Promise<VibeGuardConfig> {
  const projectRoot = targetDir ?? findProjectRoot() ?? process.cwd();

  // Check if .git exists here; if not, warn but still allow config creation.
  const gitPath = path.join(projectRoot, ".git");
  let hasGit = false;
  try {
    const stat = fs.statSync(gitPath);
    hasGit = stat.isDirectory() || stat.isFile();
  } catch {
    // no .git
  }

  if (!hasGit) {
    ui.warn("No .git directory detected. Run `git init` before installing hooks.");
  }

  const filePath = configPath(projectRoot);

  if (fs.existsSync(filePath)) {
    ui.warn(`${CONFIG_FILENAME} already exists. It will be overwritten.`);
  }

  ui.header("VibeGuard Â· Configuration");
  ui.space();
  ui.muted("Press Enter to accept the default value shown in brackets.");
  ui.space();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const ask = (prompt: string, def: string): Promise<string> =>
    new Promise((resolve) => {
      rl.question(`${GRAY}${prompt}${R} [${WHITE}${def}${R}]: `, (answer) => {
        resolve(answer.trim() || def);
      });
    });

  // We inline the ANSI codes here because ui.ts exports functions, not strings.
  const GRAY = "\x1b[90m";
  const WHITE = "\x1b[97m";
  const R = "\x1b[0m";

  const provider = await ask("LLM Provider (custom | openai | anthropic)", DEFAULT_CONFIG.llm_provider);
  const endpoint = await ask("LLM API Endpoint", DEFAULT_CONFIG.llm_api_endpoint);
  const apiKey = await ask("LLM API Key (raw string or $ENV_VAR)", DEFAULT_CONFIG.llm_api_key);
  const model = await ask("LLM Model", DEFAULT_CONFIG.llm_model);
  const targetUrl = await ask("Target Local Dev Server URL", DEFAULT_CONFIG.target_local_url);
  const excludeRaw = await ask("Exclude paths (comma-separated)", DEFAULT_CONFIG.exclude_paths.join(", "));

  // â”€â”€ Phase 4: Database Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  ui.space();
  ui.muted("â”€ Database State Guard (Phase 4) â”€");
  ui.muted("  These fields are optional. Set db_type to \"none\" to skip DB guarding.");
  ui.space();

  const dbType = await ask("DB Type (mysql | postgresql | sqlite | none)", DEFAULT_CONFIG.db_type ?? "none");
  let dbHost = "";
  let dbPort = "";
  let dbUser = "";
  let dbPass = "";
  let dbName = "";
  let dbSqlitePath = "";

  if (dbType !== "none") {
    if (dbType === "sqlite") {
      dbSqlitePath = await ask("SQLite DB file path", DEFAULT_CONFIG.db_sqlite_path ?? "");
    } else {
      dbHost = await ask("DB Host", DEFAULT_CONFIG.db_host ?? "127.0.0.1");
      dbPort = await ask("DB Port", String(DEFAULT_CONFIG.db_port ?? (dbType === "postgresql" ? 5432 : 3306)));
      dbUser = await ask("DB User", DEFAULT_CONFIG.db_user ?? "root");
      dbPass = await ask("DB Password (or $ENV_VAR)", DEFAULT_CONFIG.db_pass ?? "");
      dbName = await ask("DB Name", DEFAULT_CONFIG.db_name ?? "");
    }
  }

  rl.close();

  const config: VibeGuardConfig = {
    llm_provider: provider as VibeGuardConfig["llm_provider"],
    llm_api_endpoint: endpoint,
    llm_api_key: apiKey,
    llm_model: model,
    target_local_url: targetUrl,
    exclude_paths: excludeRaw.split(",").map((s) => s.trim()).filter(Boolean),
    db_type: dbType as VibeGuardConfig["db_type"],
    db_host: dbHost || undefined,
    db_port: dbPort ? parseInt(dbPort, 10) : undefined,
    db_user: dbUser || undefined,
    db_pass: dbPass || undefined,
    db_name: dbName || undefined,
    db_sqlite_path: dbSqlitePath || undefined,
  };

  // Validate before writing
  const errors = validateConfig(config);
  if (errors.length > 0) {
    ui.fail("Configuration is invalid:");
    for (const err of errors) {
      ui.muted(`  Â· ${err}`);
    }
    throw new Error("Aborted due to validation errors.");
  }

  // Write it
  fs.writeFileSync(filePath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  ui.space();
  ui.ok(`${CONFIG_FILENAME} written â†’ ${filePath}`);

  return config;
}

// â”€â”€â”€ Helpers exposed for CLI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Print the current config to stdout (for `vibeguard config`). */
export function printConfig(): void {
  const config = readConfig();
  ui.header("VibeGuard Â· Current Configuration");
  ui.space();
  ui.kv("Provider", config.llm_provider);
  ui.kv("Endpoint", config.llm_api_endpoint);
  ui.kv("API Key", config.llm_api_key.startsWith("$")
    ? `${config.llm_api_key} (env var)`
    : "(literal â€” consider using $ENV_VAR)");
  ui.kv("Model", config.llm_model);
  ui.kv("Target URL", config.target_local_url);
  ui.kv("Excluded", config.exclude_paths.join(", ") || "(none)");

  // â”€â”€ Phase 4: Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const dbType = config.db_type ?? "none";
  ui.space();
  ui.muted("â”€ Database State Guard â”€");
  ui.kv("DB Type", dbType);
  if (dbType !== "none") {
    if (dbType === "sqlite") {
      ui.kv("DB SQLite Path", config.db_sqlite_path || "(not set)");
    } else {
      ui.kv("DB Host", config.db_host || "(not set)");
      ui.kv("DB Port", String(config.db_port ?? ""));
      ui.kv("DB User", config.db_user || "(not set)");
      ui.kv("DB Pass", config.db_pass?.startsWith("$")
        ? `${config.db_pass} (env var)`
        : config.db_pass ? "(literal)" : "(not set)");
      ui.kv("DB Name", config.db_name || "(not set)");
    }
  }
}

// â”€â”€â”€ Phase 4 Helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Extract a normalized DbConnectionConfig from the full config.
 * Resolves $ENV_VAR references in db_pass and fills defaults.
 */
export function getDbConnectionConfig(config: VibeGuardConfig): DbConnectionConfig {
  const dbType = config.db_type ?? "none";

  const resolvedPass = config.db_pass
    ? (config.db_pass.startsWith("$")
      ? (process.env[config.db_pass.slice(1)] ?? "")
      : config.db_pass)
    : "";

  return {
    type: dbType as DbConnectionConfig["type"],
    host: config.db_host ?? "127.0.0.1",
    port: config.db_port ?? (dbType === "postgresql" ? 5432 : 3306),
    user: config.db_user ?? "root",
    pass: resolvedPass,
    name: config.db_name ?? "",
    sqlitePath: config.db_sqlite_path ?? "",
  };
}
