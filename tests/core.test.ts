/**
 * VibeGuard — Unit Tests (core modules)
 *
 * Covers the security and correctness fixes from the v1.1.0 hardening pass.
 * Uses Node.js built-in test runner — zero additional dependencies.
 *
 * Run: npx tsx --test tests/core.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

// ─── sanitizeToken (src/utils/http.ts) ────────────────────────────────────

import { sanitizeToken } from "../src/utils/http";

describe("sanitizeToken", () => {
  it("trims whitespace", () => {
    assert.equal(sanitizeToken("  abc123  "), "abc123");
  });

  it("rejects CR (\\r) with a clear error", () => {
    assert.throws(
      () => sanitizeToken("token\r\ninjected-header: evil"),
      /CR\/LF/,
    );
  });

  it("rejects LF (\\n) with a clear error", () => {
    assert.throws(
      () => sanitizeToken("token\nX-Injected: evil"),
      /CR\/LF/,
    );
  });

  it("rejects CR alone", () => {
    assert.throws(
      () => sanitizeToken("token\rEvil: true"),
      /CR\/LF/,
    );
  });

  it("passes through a valid token unchanged (aside from trim)", () => {
    const token = "eyJhbGciOiJIUzI1NiJ9.abc.signature";
    assert.equal(sanitizeToken(token), token);
  });
});

// ─── Trust Store (src/core/trust.ts) ──────────────────────────────────────

import {
  getExecutableCommands,
  hasExecutableCommands,
  commandsFingerprint,
} from "../src/core/trust";

// Minimal config shape enough to exercise the trust functions.
function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    llm_provider: "custom" as const,
    llm_api_endpoint: "http://localhost:11434/v1",
    llm_api_key: "key",
    llm_model: "llama3",
    target_local_url: "http://localhost:8000",
    exclude_paths: [],
    db_type: "none" as const,
    ...overrides,
  };
}

describe("getExecutableCommands", () => {
  it("returns empty strings when no commands are configured", () => {
    const config = makeConfig();
    const cmds = getExecutableCommands(config);
    assert.equal(cmds.server_start_command, "");
    assert.equal(cmds.server_stop_command, "");
    assert.equal(cmds.token_generation_command, "");
  });

  it("extracts all three command fields when present", () => {
    const config = makeConfig({
      server_start_command: "docker-compose up",
      server_stop_command: "docker-compose down",
      auth_seeding: {
        auth_type: "bearer",
        token_generation_command: "echo token",
      },
    });
    const cmds = getExecutableCommands(config);
    assert.equal(cmds.server_start_command, "docker-compose up");
    assert.equal(cmds.server_stop_command, "docker-compose down");
    assert.equal(cmds.token_generation_command, "echo token");
  });

  it("trims whitespace from commands", () => {
    const config = makeConfig({
      server_start_command: "  npm start  ",
    });
    const cmds = getExecutableCommands(config);
    assert.equal(cmds.server_start_command, "npm start");
  });
});

describe("hasExecutableCommands", () => {
  it("returns false when no commands are configured", () => {
    assert.equal(hasExecutableCommands(makeConfig()), false);
  });

  it("returns true when server_start_command is set", () => {
    assert.equal(
      hasExecutableCommands(makeConfig({ server_start_command: "npm start" })),
      true,
    );
  });

  it("returns true when server_stop_command is set", () => {
    assert.equal(
      hasExecutableCommands(makeConfig({ server_stop_command: "npm stop" })),
      true,
    );
  });

  it("returns true when token_generation_command is set", () => {
    assert.equal(
      hasExecutableCommands(
        makeConfig({
          auth_seeding: {
            auth_type: "bearer",
            token_generation_command: "echo token",
          },
        }),
      ),
      true,
    );
  });
});

describe("commandsFingerprint", () => {
  it("is stable — same commands produce the same fingerprint", () => {
    const config = makeConfig({
      server_start_command: "npm run dev",
      auth_seeding: {
        auth_type: "bearer",
        token_generation_command: "node gen-token.js",
      },
    });
    const fp1 = commandsFingerprint(config);
    const fp2 = commandsFingerprint(config);
    assert.equal(fp1, fp2);
    assert.equal(fp1.length, 64); // SHA-256 hex
  });

  it("changes when server_start_command changes", () => {
    const a = makeConfig({ server_start_command: "npm start" });
    const b = makeConfig({ server_start_command: "npm run dev" });
    assert.notEqual(commandsFingerprint(a), commandsFingerprint(b));
  });

  it("changes when token_generation_command changes", () => {
    const a = makeConfig({
      auth_seeding: { auth_type: "bearer", token_generation_command: "cmd-a" },
    });
    const b = makeConfig({
      auth_seeding: { auth_type: "bearer", token_generation_command: "cmd-b" },
    });
    assert.notEqual(commandsFingerprint(a), commandsFingerprint(b));
  });

  it("changes when a command is removed (goes to empty string)", () => {
    const a = makeConfig({ server_start_command: "npm start" });
    const b = makeConfig(); // no commands
    assert.notEqual(commandsFingerprint(a), commandsFingerprint(b));
  });

  it("is stable across structurally-identical configs", () => {
    // Two config objects with the same values but different object identity
    const a = makeConfig({
      server_start_command: "npm start",
      server_stop_command: "npm stop",
      auth_seeding: { auth_type: "bearer", token_generation_command: "cmd" },
    });
    const b = makeConfig({
      server_start_command: "npm start",
      server_stop_command: "npm stop",
      auth_seeding: { auth_type: "bearer", token_generation_command: "cmd" },
    });
    assert.equal(commandsFingerprint(a), commandsFingerprint(b));
  });
});

// ─── Config Defaults Merging (src/core/config.ts) ────────────────────────

import { validateConfig } from "../src/core/config";

// DEFAULT_CONFIG values — mirrored here for testing since the constant
// isn't exported. These must stay in sync with config.ts.
const EXPECTED_DEFAULTS = {
  llm_max_retries: 3,
  llm_cache_enabled: true,
  export_tests_enabled: true,
  export_tests_framework: "bash",
  export_tests_dir: ".vibeguard/tests",
  server_start_command: "",
  server_stop_command: "",
  webhook_slack: "",
  webhook_discord: "",
  webhook_teams: "",
  max_concurrent_requests: 3,
  db_type: "none",
  db_host: "127.0.0.1",
  db_port: 3306,
  db_user: "root",
  db_pass: "",
  db_name: "",
  db_sqlite_path: "",
};

// Minimal valid config that passes validation.
const MINIMAL_CONFIG = {
  llm_provider: "custom" as const,
  llm_api_endpoint: "http://localhost:11434/v1",
  llm_api_key: "key",
  llm_model: "llama3",
  target_local_url: "http://localhost:8000",
};

describe("config validation and merging", () => {
  it("a minimal valid config passes validation", () => {
    const errors = validateConfig(MINIMAL_CONFIG);
    assert.equal(errors.length, 0);
  });

  it("validateConfig rejects a missing llm_provider", () => {
    const errors = validateConfig({ ...MINIMAL_CONFIG, llm_provider: undefined as unknown as string });
    assert.ok(errors.some((e) => e.includes("llm_provider")));
  });

  it("validateConfig accepts all optional newer fields", () => {
    // This is the key test: a config that sets every field VibeGuardConfig
    // defines should pass validation with zero errors — proving the schema
    // supports all fields that the DEFAULT_CONFIG spread writes.
    const full = {
      ...MINIMAL_CONFIG,
      exclude_paths: ["node_modules/**"],
      db_type: "mysql" as const,
      db_host: "10.0.0.1",
      db_port: 3307,
      db_user: "admin",
      db_pass: "secret",
      db_name: "testdb",
      llm_max_retries: 5,
      llm_cache_enabled: false,
      webhook_slack: "https://hooks.slack.com/x",
      webhook_discord: "https://discord.com/api/webhooks/y",
      webhook_teams: "https://webhook.office.com/z",
      export_tests_enabled: false,
      export_tests_framework: "jest" as const,
      export_tests_dir: "custom/tests",
      server_start_command: "npm run dev",
      server_stop_command: "kill-server",
      max_concurrent_requests: 8,
      auth_seeding: {
        auth_type: "bearer" as const,
        token_generation_command: "echo token",
      },
    };

    const errors = validateConfig(full);
    assert.equal(errors.length, 0);
  });

  it("merging DEFAULT_CONFIG under a partial config produces a valid config", () => {
    // Simulates: { ...DEFAULT_CONFIG, ...partialFileConfig }
    // This is what readConfig does in all three paths.
    // A pre-v1.1 config missing newer keys should still validate.
    const merged = {
      ...EXPECTED_DEFAULTS,
      ...MINIMAL_CONFIG,
    };

    const errors = validateConfig(merged);
    assert.equal(errors.length, 0);
  });

  it("user overrides in the merged config take precedence over defaults", () => {
    const userOverrides = {
      max_concurrent_requests: 10,
      server_start_command: "my-custom-start",
      webhook_slack: "https://hooks.slack.com/xyz",
    };

    const merged = {
      ...EXPECTED_DEFAULTS,
      ...MINIMAL_CONFIG,
      ...userOverrides,
    };

    // User values should be present.
    assert.equal(merged.max_concurrent_requests, 10);
    assert.equal(merged.server_start_command, "my-custom-start");
    assert.equal(merged.webhook_slack, "https://hooks.slack.com/xyz");

    // Non-overridden defaults should still be intact.
    assert.equal(merged.llm_cache_enabled, true);
    assert.equal(merged.export_tests_enabled, true);
    assert.equal(merged.llm_max_retries, 3);

    // Should still validate.
    const errors = validateConfig(merged);
    assert.equal(errors.length, 0);
  });
});
