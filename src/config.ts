/**
 * VibeGuard — Configuration Manager
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
import type { VibeGuardConfig, RawConfig } from "./types";
import * as ui from "./ui";

// ─── Constants ───────────────────────────────────────────────────────────────

const CONFIG_FILENAME = ".vibeguard.json";

const VALID_PROVIDERS = new Set(["custom", "openai", "anthropic"]);

const DEFAULT_CONFIG: VibeGuardConfig = {
  llm_provider: "custom",
  llm_api_endpoint: "http://localhost:11434/v1",
  llm_api_key: "$LLM_API_KEY",
  llm_model: "llama3:8b",
  target_local_url: "http://localhost:8000",
  exclude_paths: ["node_modules/**", "vendor/**", ".git/**", "dist/**", "build/**"],
};

// ─── Project Root Discovery ──────────────────────────────────────────────────

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

// ─── Path Helpers ────────────────────────────────────────────────────────────

function configPath(root: string): string {
  return path.join(root, CONFIG_FILENAME);
}

// ─── Validation ──────────────────────────────────────────────────────────────

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

  return errors;
}

// ─── Reading ─────────────────────────────────────────────────────────────────

/**
 * Read and validate the config from the project root.
 * Throws with a user-facing message if anything is wrong.
 */
export function readConfig(root?: string): VibeGuardConfig {
  const projectRoot = root ?? findProjectRoot();
  if (!projectRoot) {
    throw new Error(
      "No .git directory found. Run `vibeguard init` inside a git repository."
    );
  }

  const filePath = configPath(projectRoot);
  let raw: unknown;

  try {
    const contents = fs.readFileSync(filePath, "utf-8");
    raw = JSON.parse(contents);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `No ${CONFIG_FILENAME} found. Run \`vibeguard init\` first.`
      );
    }
    throw new Error(
      `Failed to read ${CONFIG_FILENAME}: ${(err as Error).message}`
    );
  }

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

// ─── API Key Resolution ──────────────────────────────────────────────────────

/**
 * Resolve an API key that may be an env-var reference.
 *   "$OPENAI_API_KEY" → process.env.OPENAI_API_KEY
 *   "sk-abc123"       → "sk-abc123" (passthrough)
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

// ─── Interactive Initialization ──────────────────────────────────────────────

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

  ui.header("VibeGuard · Configuration");
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

  rl.close();

  const config: VibeGuardConfig = {
    llm_provider: provider as VibeGuardConfig["llm_provider"],
    llm_api_endpoint: endpoint,
    llm_api_key: apiKey,
    llm_model: model,
    target_local_url: targetUrl,
    exclude_paths: excludeRaw.split(",").map((s) => s.trim()).filter(Boolean),
  };

  // Validate before writing
  const errors = validateConfig(config);
  if (errors.length > 0) {
    ui.fail("Configuration is invalid:");
    for (const err of errors) {
      ui.muted(`  · ${err}`);
    }
    throw new Error("Aborted due to validation errors.");
  }

  // Write it
  fs.writeFileSync(filePath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  ui.space();
  ui.ok(`${CONFIG_FILENAME} written → ${filePath}`);

  return config;
}

// ─── Helpers exposed for CLI ─────────────────────────────────────────────────

/** Print the current config to stdout (for `vibeguard config`). */
export function printConfig(): void {
  const config = readConfig();
  ui.header("VibeGuard · Current Configuration");
  ui.space();
  ui.kv("Provider", config.llm_provider);
  ui.kv("Endpoint", config.llm_api_endpoint);
  ui.kv("API Key", config.llm_api_key.startsWith("$")
    ? `${config.llm_api_key} (env var)`
    : "(literal — consider using $ENV_VAR)");
  ui.kv("Model", config.llm_model);
  ui.kv("Target URL", config.target_local_url);
  ui.kv("Excluded", config.exclude_paths.join(", ") || "(none)");
}
