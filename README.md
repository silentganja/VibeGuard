# VibeGuard

**CLI-native adversarial local QA daemon** — intercepts `git push`, extracts diffs, analyzes changes via your own LLM, maps endpoints to executable test URLs, and guards your local database against side effects from adversarial payloads.

> **Philosophy:** Your code should not leave your machine until an AI adversary has tried to break it — without touching production, without calling home, without runtime dependencies.

---

## Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration (.vibeguard.json)](#configuration)
- [Phase-by-Phase Breakdown](#phase-by-phase-breakdown)
  - [Phase 1 — Git Diff Extraction](#phase-1--git-diff-extraction)
  - [Phase 2 — Noise Filter & LLM Analysis](#phase-2--noise-filter--llm-analysis)
  - [Phase 3 — Target Mapper & Connectivity Check](#phase-3--target-mapper--connectivity-check)
  - [Phase 4 — Database State Guard](#phase-4--database-state-guard)
- [Pre-Push Hook Behavior](#pre-push-hook-behavior)
- [Pipeline Flow](#pipeline-flow)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Architecture

```
                         ┌─────────────────────┐
                         │    git push          │
                         │  (developer action)  │
                         └─────────┬───────────┘
                                   │
                         ┌─────────▼───────────┐
                         │  .git/hooks/pre-push │  ← installed by `vibeguard install`
                         │  (bash / PowerShell) │
                         └─────────┬───────────┘
                                   │ invokes `vibeguard run`
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐    ┌───────────────────────┐    ┌─────────────────────┐
│  Phase 1      │    │  Phase 2              │    │  Phase 3            │
│  git.ts       │    │  parser.ts → llm.ts   │    │  checker.ts         │
│               │    │                       │    │  mapper.ts          │
│ Extract raw   │    │ Strip noise           │    │                     │
│ git diff from │───▶│ Filter comments/docs  │───▶│ Check server alive  │
│ remote...HEAD │    │ Send to your LLM      │    │ Resolve file paths  │
│               │    │ Get intent + vectors  │    │ to executable URLs  │
└───────────────┘    └───────────────────────┘    └──────────┬──────────┘
                                                             │
                                      ┌──────────────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │  Phase 4                │
                         │  dbGuard.ts             │
                         │                         │
                         │  Discover SQL tables    │
                         │  Snapshot DB state      │
                         │  ── [Phase 5/6 TBD] ──  │
                         │  Restore DB state       │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │  Verdict                │
                         │  Pass (exit 0)          │
                         │  Block (exit 1)         │
                         └─────────────────────────┘
```

**Zero runtime dependencies.** Everything runs on Node.js built-ins and native CLI tools (`git`, `mysqldump`, `pg_dump`). The LLM is your own — local or remote.

---

## Installation

### Prerequisites

- **Node.js** ≥ 18 (uses `fetch`, `AbortController`, and ES2020)
- **Git** ≥ 2.0
- A running **LLM** (see [LLM Provider Setup](#llm-provider-setup))
- (Optional) **MySQL** / **PostgreSQL** / **SQLite** — for Phase 4 database state guarding

### Steps

```bash
# Clone the repository
git clone https://github.com/silentganja/VibeGuard.git
cd VibeGuard

# Install TypeScript compiler (only dev dependency)
npm install

# Compile TypeScript → JavaScript
npm run build

# Make `vibeguard` available globally on your PATH
npm link
```

### Verify Installation

```bash
vibeguard
```

You should see the usage screen with the current phase and version.

---

## Quick Start

```bash
# 1. Navigate to any git repository
cd ~/projects/my-php-app

# 2. Create your configuration interactively
vibeguard init

# 3. Install the git pre-push hook
vibeguard install

# 4. Make some changes and push — VibeGuard activates automatically
git add .
git commit -m "Add login endpoint"
git push
```

On every `git push`, VibeGuard will:
1. Extract the exact diff of what you're about to push.
2. Strip out non-functional noise (CSS, docs, comments).
3. Check that your local dev server is running.
4. Send the critical code changes to your LLM for adversarial analysis.
5. Resolve modified files to reachable HTTP URLs.
6. Snapshot your database (if configured).
7. Report vulnerabilities and either allow or block the push.

---

## Commands

| Command | Description |
|---|---|
| `vibeguard init` | Interactive wizard — creates `.vibeguard.json` at the repo root. |
| `vibeguard install` | Writes the `pre-push` hook into `.git/hooks/`. Backs up existing hooks. |
| `vibeguard uninstall` | Removes the VibeGuard hook. Restores previous hook from backup if one exists. |
| `vibeguard config` | Prints the current configuration with all fields. |
| `vibeguard run` | **[Internal]** Invoked by the pre-push hook. Runs the full analysis pipeline. |

### `vibeguard run` (Internal)

Called automatically by the pre-push hook with these flags:

```
vibeguard run --local <branch> --remote <branch> --sha <commit-ish>
```

You can also run it manually to test the pipeline without pushing:

```bash
vibeguard run --local main --remote origin/main
```

---

## Configuration

VibeGuard reads `.vibeguard.json` from the root of your git repository. Run `vibeguard init` to create it interactively, or write it by hand.

### Full Schema

```json
{
  "llm_provider": "custom",
  "llm_api_endpoint": "http://localhost:11434/v1",
  "llm_api_key": "$LLM_API_KEY",
  "llm_model": "llama3:8b",
  "target_local_url": "http://localhost:8000",
  "exclude_paths": ["node_modules/**", "vendor/**", ".git/**", "dist/**"],
  "db_type": "none",
  "db_host": "127.0.0.1",
  "db_port": 3306,
  "db_user": "root",
  "db_pass": "",
  "db_name": "",
  "db_sqlite_path": ""
}
```

### Field Reference

#### LLM Configuration (Required)

| Field | Type | Description |
|---|---|---|
| `llm_provider` | `"custom"` \| `"openai"` \| `"anthropic"` | Which API format to use. `custom` is OpenAI-compatible (works with Ollama, LM Studio, vLLM, LocalAI, etc.). |
| `llm_api_endpoint` | `string` (URL) | Full URL to your LLM's API. For Ollama: `http://localhost:11434/v1`. For LM Studio: `http://localhost:1234/v1`. For OpenAI: `https://api.openai.com/v1`. |
| `llm_api_key` | `string` | API key for authentication. Use `$ENV_VAR` syntax to reference environment variables (e.g., `$OPENAI_API_KEY`). This keeps secrets out of the config file. |
| `llm_model` | `string` | Model identifier. Examples: `llama3:8b`, `gpt-4o`, `claude-sonnet-4-6`, `codellama:7b`. Must match a model available at your endpoint. |

#### Target Server Configuration (Required)

| Field | Type | Description |
|---|---|---|
| `target_local_url` | `string` (URL) | Base URL of your locally running dev server. VibeGuard probes this before analysis. Examples: `http://localhost:8000`, `http://localhost:3000`, `http://localhost/my-app`. |
| `exclude_paths` | `string[]` | Glob-style patterns to exclude from git diff. Typical values: `node_modules/**`, `vendor/**`, `.git/**`, `dist/**`, `build/**`. |

#### Database State Guard (Optional — Phase 4)

| Field | Type | Default | Description |
|---|---|---|---|
| `db_type` | `"mysql"` \| `"postgresql"` \| `"sqlite"` \| `"none"` | `"none"` | Database dialect to guard. Set to `"none"` to skip DB snapshots entirely. |
| `db_host` | `string` | `"127.0.0.1"` | Database hostname or IP. Used by MySQL and PostgreSQL. |
| `db_port` | `number` | `3306` (MySQL) / `5432` (PostgreSQL) | Database port. |
| `db_user` | `string` | `"root"` | Database user with read/write access for dump and restore. |
| `db_pass` | `string` | `""` | Database password. Supports `$ENV_VAR` references (e.g., `$DB_PASSWORD`). |
| `db_name` | `string` | `""` | Database or schema name to connect to. |
| `db_sqlite_path` | `string` | `""` | Absolute or relative path to the SQLite `.db` file. Only used when `db_type` is `"sqlite"`. |

### LLM Provider Setup

<details>
<summary><strong>Ollama (local — recommended for privacy)</strong></summary>

```json
{
  "llm_provider": "custom",
  "llm_api_endpoint": "http://localhost:11434/v1",
  "llm_api_key": "ollama",
  "llm_model": "llama3:8b"
}
```

```bash
# Install and start Ollama
ollama pull llama3:8b
ollama serve
```
</details>

<details>
<summary><strong>LM Studio (local — GUI)</strong></summary>

```json
{
  "llm_provider": "custom",
  "llm_api_endpoint": "http://localhost:1234/v1",
  "llm_api_key": "lm-studio",
  "llm_model": "local-model"
}
```

Start the local server in LM Studio's UI before using VibeGuard.
</details>

<details>
<summary><strong>OpenAI</strong></summary>

```json
{
  "llm_provider": "openai",
  "llm_api_endpoint": "https://api.openai.com/v1",
  "llm_api_key": "$OPENAI_API_KEY",
  "llm_model": "gpt-4o"
}
```

```bash
export OPENAI_API_KEY="sk-..."
```
</details>

<details>
<summary><strong>Anthropic (Claude)</strong></summary>

```json
{
  "llm_provider": "anthropic",
  "llm_api_endpoint": "https://api.anthropic.com",
  "llm_api_key": "$ANTHROPIC_API_KEY",
  "llm_model": "claude-sonnet-4-6"
}
```

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```
</details>

---

## Phase-by-Phase Breakdown

### Phase 1 — Git Diff Extraction

**Module:** [`src/git.ts`](src/git.ts)

- Resolves the remote tracking branch (`origin/main`) for your current local branch.
- Runs `git diff <upstream>...HEAD` — the three-dot syntax captures exactly the changes about to be pushed, excluding anything already on the remote.
- Parses the unified diff into structured objects: `DiffFile` → `DiffHunk` → `DiffLine`.
- Respects `exclude_paths` from `.vibeguard.json` via git's `:(exclude)` pathspec.
- Outputs a `DiffResult` with per-file additions, deletions, hunks, and the raw diff text.

### Phase 2 — Noise Filter & LLM Analysis

**Modules:** [`src/parser.ts`](src/parser.ts) · [`src/llm.ts`](src/llm.ts)

#### 2a — Noise Filter (`src/parser.ts`)

Runs **locally and deterministically** — the LLM never sees non-functional changes.

- **File Extension Whitelisting**: Keeps functional code (`.php`, `.js`, `.ts`, `.go`, `.py`, `.rb`, `.java`, `.rs`, etc.). Discards `.css`, `.scss`, `.md`, `.svg`, fonts, images, audio, video, archives, source maps, and lockfiles.
- **JSON Handling**: Discards all `.json` except known config/manifest files (`package.json`, `composer.json`, `tsconfig.json`, `.vibeguard.json`) and files under `config/` or `.github/` directories.
- **Comment Stripping**: Removes single-line comments (`//`, `#`, `--`), multi-line block comments (`/* ... */`), JSDoc/PHPDoc continuations (` * @param`), and Python/Elixir docstrings (`"""..."""`). Inline comment stripping is string-literal-aware to avoid false positives on URLs containing `//`.
- **Whitespace Filtering**: Drops lines that are only whitespace changes.
- **Hunk Context Extraction**: Infers the surrounding function, class, method, or route name from git's `@@` hunk headers using 12+ language-specific regex patterns.
- **Token Estimation**: Character-based heuristic (~3.5 chars/token) for payload sizing.

#### 2b — LLM Analysis (`src/llm.ts`)

Sends the filtered diff to your configured LLM with a **Sovereign System Architect** system prompt.

The prompt instructs the model to:
1. Think adversarially — assume every user input is hostile.
2. Infer routes, HTTP methods, and parameters from code context.
3. Detect the *intent* behind each change, not just the mechanics.
4. Flag concrete vulnerability vectors with evidence from the diff.

**Response Schema** (strict JSON mode):

```json
{
  "modified_endpoints": [
    {
      "file_path": "api/login.php",
      "estimated_route": "/api/login.php",
      "http_method": "POST",
      "detected_intent": "Authenticates user by username/password, issues JWT token.",
      "vulnerability_vectors": ["sql_injection"],
      "input_parameters": ["username", "password", "POST_body"]
    }
  ]
}
```

**Supported vulnerability vectors:** `sql_injection`, `privilege_escalation`, `auth_bypass`, `rce`, `input_fuzzing`, `xss`, `path_traversal`, `ssrf`, `idor`, `race_condition`, `deserialization`, `information_disclosure`, `misconfiguration`, `other`.

**Timeout:** 6 seconds. If your LLM doesn't respond within the deadline, VibeGuard aborts with a dark-mode warning and blocks the push (exit code 1). This prevents the hook from blocking your workflow indefinitely.

**API Support:**
- `custom` / `openai` — OpenAI-compatible chat completions with `response_format: { type: "json_object" }` and Bearer token auth.
- `anthropic` — Anthropic Messages API with `{` prefill to force JSON output. Uses `x-api-key` header.

**Severity-based Verdict:**
| Severity | Vectors | Result |
|---|---|---|
| **Critical** | `rce`, `auth_bypass` | Push blocked |
| **High** | `sql_injection`, `privilege_escalation`, `deserialization` | Push blocked |
| **Medium** | `ssrf`, `path_traversal`, `idor`, `information_disclosure` | Warn (push allowed, findings shown) |
| **Low** | `xss`, `input_fuzzing`, `misconfiguration`, `race_condition` | Pass with note |

### Phase 3 — Target Mapper & Connectivity Check

**Modules:** [`src/checker.ts`](src/checker.ts) · [`src/mapper.ts`](src/mapper.ts)

#### 3a — Connectivity Check (`src/checker.ts`)

Before any mapping occurs, VibeGuard verifies your local dev server is alive:

- Sends an HTTP `HEAD` request to `target_local_url` with a **1.5-second timeout**.
- Falls back to `GET` if the server returns 405 (Method Not Allowed).
- Handles DNS failures, connection refused, timeouts, and connection resets with specific diagnostic messages.
- If the server is unreachable, the push is **aborted immediately** (before incurring LLM API costs) with:
  ```
  ✕  Local development server at http://localhost:8000 is unreachable.
     Please start your local environment before pushing.
  ```

#### 3b — Route Resolution Engine (`src/mapper.ts`)

Cross-references the LLM's `modified_endpoints` against your local project layout using a **dual-strategy** resolver:

**Strategy 1 — Traditional File-to-URL (PHP/cPanel / Apache / Nginx):**
- Detects public subfolders: `public/`, `www/`, `htdocs/`, `web/`, `public_html/`, `html/`, `dist/`, `build/`, `static/`.
- Verifies the directory is actually a web root (contains `index.php`, `index.html`, `.htaccess`, etc.).
- Maps file paths to URL paths: `public/api/v1/login.php` → `/api/v1/login.php`.
- Combines with `target_local_url`: `http://localhost:8000/api/v1/login.php`.

**Strategy 2 — Modern Framework Route (Next.js / Laravel / Go / Rails):**
- Detects frameworks via sentinel files: `package.json`, `go.mod`, `composer.json` + `artisan` (Laravel) / `bin/console` (Symfony), `Gemfile`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `mix.exs`.
- Uses the LLM's `estimated_route` directly: `http://localhost:8000/api/users`.
- Automatically falls back to traditional mapping when `estimated_route` is `"N/A"` or the file lives deep in source directories.

**Output — `TargetTargets`:**
```json
{
  "executable_tests": [
    {
      "resolved_url": "http://localhost:8000/api/v1/auth.php",
      "http_method": "POST",
      "input_parameters": ["username", "password"],
      "vulnerability_vectors": ["sql_injection"],
      "associated_file": "api/v1/auth.php"
    }
  ]
}
```

### Phase 4 — Database State Guard

**Module:** [`src/dbGuard.ts`](src/dbGuard.ts)

Ensures adversarial test payloads (future Phase 5/6) never leave your database in a dirty state. Uses **zero runtime dependencies** — all operations use Node.js built-ins and native CLI tools.

#### Capture (`dbGuard.capture()`)

Called **before** test payloads fire. Runs the appropriate strategy based on `db_type`:

| Database | Strategy | Mechanism | Artifact |
|---|---|---|---|
| **SQLite** | Binary copy | `fs.copyFileSync()` | `.vibeguard/tmp/backup.db` |
| **MySQL** | Per-table dump | `mysqldump --single-transaction --no-tablespaces` | `.vibeguard/tmp/table_state.sql` |
| **PostgreSQL** | Per-table dump | `pg_dump --clean --if-exists --no-owner` | `.vibeguard/tmp/table_state.sql` |
| **none** | No-op | — | — |

**Table Discovery:** Before taking a snapshot, VibeGuard scans the filtered diff for SQL keywords to identify which tables are referenced by the changed code:

- `FROM <table>`, `JOIN <table>`, `UPDATE <table>`, `INSERT INTO <table>`, `DELETE FROM <table>`, `ALTER TABLE <table>`, `CREATE TABLE <table>`, `DROP TABLE <table>`, `TRUNCATE <table>`, `REPLACE INTO <table>`
- Filters out SQL keywords (IF, EXISTS, SET, WHERE, etc.) and short aliases.
- Only the discovered tables are dumped — not the entire database.

#### Restore (`dbGuard.restore()`)

Called **after** test payloads conclude. Reverses all side effects:

| Database | Strategy | Mechanism |
|---|---|---|
| **SQLite** | Binary restore | Copy backup `.db` over the active file, delete backup |
| **MySQL** | SQL restore | `mysql < table_state.sql`, delete dump |
| **PostgreSQL** | SQL restore | `psql -v ON_ERROR_STOP=1 < table_state.sql`, delete dump |

#### Emergency Restore

If any step in the pipeline throws an unhandled error, the `catch` block in `handleRun` calls `dbGuard.restore()` before exiting. This guarantees the database is never left in a dirty state — even if the LLM times out, the network fails, or a payload crashes the server.

---

## Pre-Push Hook Behavior

When `vibeguard install` is run, it writes a script to `.git/hooks/pre-push`. On every `git push`:

1. **Git passes pushed refs** to the hook via stdin (one line per ref: `local_ref local_sha remote_ref remote_sha`).
2. **The hook parses** each ref to extract branch names.
3. **The hook invokes** `vibeguard run --local <branch> --remote <branch> --sha <sha>` for each ref.
4. **VibeGuard runs the full pipeline** (Phases 1–4).
5. **If VibeGuard exits 0:** The push proceeds.
6. **If VibeGuard exits 1:** The push is blocked. The developer sees the vulnerability report and must fix the issues.

### Hook Platforms

- **Linux / macOS / Git Bash (Windows):** The bash script runs natively.
- **Windows PowerShell fallback:** A `pre-push.ps1` is also written for Windows-native Git installations.

### Bypassing the Hook

In an emergency, you can skip the hook:

```bash
git push --no-verify
```

> **⚠️ This bypasses all security analysis.** Only use this when you are certain the changes are safe and you cannot fix the blocking issue immediately.

### Uninstalling

```bash
vibeguard uninstall
```

This removes the VibeGuard hook and restores any previous hook that was backed up during installation.

---

## Pipeline Flow

```
Developer runs: git push
        │
        ▼
┌─────────────────────────────────────────────┐
│  .git/hooks/pre-push                        │
│  Reads refs from stdin, invokes:            │
│  vibeguard run --local main --remote origin │
└──────────────────┬──────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌────────┐  ┌────────────┐  ┌───────────────┐
│ PHASE 1│  │ PHASE 2    │  │ PHASE 3       │
│ git.ts │  │ parser.ts  │  │ checker.ts    │
│        │  │ llm.ts     │  │ mapper.ts     │
│        │  │            │  │               │
│ Extract│  │ Filter CSS │  │ HEAD → server │
│ diff   │  │ Strip docs │  │ Resolve URLs  │
│ from   │──▶│ Send to    │──▶│ Traditional   │
│ remote │  │ your LLM   │  │ & Framework   │
│        │  │ Parse JSON │  │ mapping       │
│        │  │ Build      │  │               │
│        │  │ verdict    │  │               │
└────────┘  └────────────┘  └───────┬───────┘
                                     │
                          ┌──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │ PHASE 4             │
               │ dbGuard.ts          │
               │                     │
               │ Discover SQL tables │
               │ Snapshot DB state   │
               │ ── [Phase 5/6] ──   │
               │ Restore DB state    │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │ VERDICT             │
               │                     │
               │ Pass (exit 0)       │
               │   OR                │
               │ Block (exit 1)      │
               │ with full report    │
               └─────────────────────┘
```

**Fail-closed design:** Any error in the pipeline (LLM timeout, server unreachable, DB snapshot failure) blocks the push and exits with code 1. VibeGuard defaults to safety.

---

## Project Structure

```
vibe-guard/
├── src/
│   ├── cli.ts          # CLI entry point — argument parsing, command dispatch, pipeline orchestration
│   ├── config.ts       # Configuration manager — read/write/validate .vibeguard.json, init wizard, env-var resolution
│   ├── types.ts        # Shared type definitions — all interfaces, types, and constants
│   ├── ui.ts           # Terminal UI — minimalist monochrome output helpers (muted, action, ok, fail, etc.)
│   │
│   ├── git.ts          # Phase 1 — Git diff extraction, remote resolution, unified diff parser
│   │
│   ├── parser.ts       # Phase 2a — Noise filter, comment stripper, file extension whitelist, token estimator
│   ├── llm.ts          # Phase 2b — LLM API client (OpenAI/Anthropic/custom), Sovereign System Architect prompt, JSON parser, verdict builder
│   │
│   ├── checker.ts      # Phase 3a — Connectivity pre-flight check (1.5s timeout, HEAD→GET fallback)
│   ├── mapper.ts       # Phase 3b — Dual-strategy route resolution (traditional & framework), TargetTargets builder
│   │
│   └── dbGuard.ts      # Phase 4 — Database state guard (SQLite/MySQL/PostgreSQL), table discovery, snapshot capture/restore
│
├── dist/               # Compiled JavaScript output (after `npm run build`)
├── .vibeguard.json     # Project configuration (created by `vibeguard init`)
├── package.json        # npm package manifest (zero runtime dependencies)
├── tsconfig.json       # TypeScript compiler configuration
└── README.md           # This file
```

---

## Troubleshooting

### "LLM Request Timed Out"

```
✕  LLM Request Timed Out
   The configured LLM (llama3:8b) did not respond within the 6-second deadline.
   This prevents VibeGuard from blocking your push indefinitely.

   Troubleshooting:
   - Verify your LLM is running at the endpoint in .vibeguard.json
   - Check llm_model in .vibeguard.json matches an available model
   - For local models (Ollama/LM Studio), ensure the server is started
```

**Fix:** Verify your LLM server is running. For Ollama: `ollama list`. For LM Studio: check the local server is started in the UI.

### "Local development server is unreachable"

**Fix:**
1. Start your local dev server (e.g., `php -S localhost:8000`, `npm run dev`, `go run .`).
2. Verify `target_local_url` in `.vibeguard.json` matches the actual server URL.
3. Check your firewall isn't blocking localhost connections.

### "No .vibeguard.json found"

Run `vibeguard init` inside your git repository to create the configuration file.

### "LLM response is missing modified_endpoints array"

Your LLM returned a response that doesn't match the required JSON schema. This can happen with very small models or models that don't support JSON mode. Try:
- Using a model with better instruction-following (≥ 7B parameters recommended).
- Verifying your LLM endpoint supports `response_format: { type: "json_object" }`.
- Checking that the model has enough context window for the diff payload.

### "git diff failed"

VibeGuard couldn't resolve the remote tracking branch. Ensure:
- You have a remote configured: `git remote -v`
- Your branch tracks a remote: `git branch -vv`
- Set upstream if needed: `git push --set-upstream origin <branch>`

### Database tools not found

For MySQL state guarding: `mysqldump` and `mysql` must be on your PATH.
For PostgreSQL state guarding: `pg_dump` and `psql` must be on your PATH.

```bash
# Verify MySQL tools
which mysqldump mysql

# Verify PostgreSQL tools
which pg_dump psql
```

If they're not found, install them or add their directory to your PATH. Set `db_type` to `"none"` if you don't need database guarding.

---

## License

MIT

---

**Built with zero runtime dependencies.** Only requires TypeScript to compile. Uses your own LLM — no data ever leaves your machine unless you configure a cloud provider.
