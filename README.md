# VibeGuard

**CLI-native adversarial local QA daemon** — intercepts `git push`, enforces code quality standards, extracts diffs, analyzes changes via your own LLM, maps endpoints to executable URLs, guards your database, generates red-team payloads, fires live HTTP attacks to verify your code can withstand real exploits, and auto-generates security patches for every confirmed vulnerability — all before it leaves your machine.

> **Philosophy:** Your code should not leave your machine until an AI adversary has tried to break it — and an AI security engineer has fixed what broke — without touching production, without calling home, without runtime dependencies.

> **⚠️ Model Requirement:** VibeGuard performs at **100% capability on unfiltered/uncensored AI models**. The LLM is instructed to think like an adversary — generating real SQL injection payloads, command injection strings, XSS vectors, and auth bypass attacks. **Filtered or safety-aligned models (e.g., some cloud-hosted, RLHF-heavy models) may refuse to generate exploit payloads**, causing Phase 5 (payload generation) and Phase 7 (patch generation) to fall back to deterministic defaults. For full adversarial coverage, use a local unfiltered model (Ollama with Llama 3, Mistral, CodeLlama, etc.) or a model with minimal refusal tuning.

---

## Table of Contents

- [Architecture](#architecture)
- [Model Requirements](#model-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration (.vibeguard.json)](#configuration)
- [Phase-by-Phase Breakdown](#phase-by-phase-breakdown)
  - [Phase 1 — Git Diff Extraction](#phase-1--git-diff-extraction)
  - [Phase 2 — Noise Filter & LLM Analysis](#phase-2--noise-filter--llm-analysis)
  - [Phase 3 — Target Mapper & Connectivity Check](#phase-3--target-mapper--connectivity-check)
  - [Phase 4 — Database State Guard](#phase-4--database-state-guard)
  - [Phase 5 — Compliance & Payload Generation](#phase-5--compliance--payload-generation)
  - [Phase 6 — Live Execution & Response Assertion](#phase-6--live-execution--response-assertion)
  - [Phase 7 — Self-Healing Patch Engine](#phase-7--self-healing-patch-engine)
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
│  Phase 5a     │    │  Phase 1+2            │    │  Phase 3            │
│  compliance.ts│    │  git.ts → parser.ts   │    │  checker.ts         │
│               │    │  → llm.ts             │    │  mapper.ts          │
│ README check  │    │                       │    │                     │
│ Commit lint   │───▶│ Extract diff          │───▶│ Probe dev server    │
│               │    │ Strip noise           │    │ Resolve file→URL    │
│ (runs FIRST)  │    │ LLM analysis          │    │ (dual strategy)     │
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
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │  Phase 5b + 6           │
                         │  payloadGen.ts          │
                         │  runner.ts              │
                         │  assertion.ts           │
                         │                         │
                         │  Generate red-team      │
                         │  payloads via LLM       │
                         │  Fire HTTP requests     │
                         │  (3s timeout, parallel) │
                         │  Judge responses        │
                         │  (status, DB leak,      │
                         │   auth bypass)          │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │  Phase 7                │
                         │  healer.ts              │
                         │                         │
                         │  For each vuln found:   │
                         │  Read source file       │
                         │  Send exploit context   │
                         │  + code to LLM          │
                         │  Receive patched code   │
                         │  Generate unified diff  │
                         │  Write .patch files     │
                         │  (NEVER auto-apply)     │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │  Phase 4b + Verdict     │
                         │                         │
                         │  Restore DB state       │
                         │  Combined verdict:      │
                         │  LLM + live test pass   │
                         │  → exit 0 (push)        │
                         │  Any failure → exit 1   │
                         │  Show patch paths       │
                         └─────────────────────────┘
```

**Zero runtime dependencies.** Everything runs on Node.js built-ins and native CLI tools (`git`, `mysqldump`, `pg_dump`). The LLM is your own — local or remote.

---

## Model Requirements

VibeGuard's adversarial capabilities depend on the LLM's willingness to think like an attacker. The system prompts instruct the model to generate real exploit payloads and security patches — tasks that some safety-aligned models may refuse.

### Unfiltered Models (100% Capability)

Unfiltered or minimally-filtered models execute all VibeGuard phases at full capacity:

| Model | Type | Phase 5 (Payloads) | Phase 7 (Patches) |
|---|---|---|---|
| **Llama 3 / 3.1** (8B, 70B, 405B) | Local — Ollama / vLLM | ✅ Full adversarial payloads | ✅ Full remediation patches |
| **Mistral / Mixtral** (7B, 8×7B) | Local — Ollama / vLLM | ✅ Full adversarial payloads | ✅ Full remediation patches |
| **CodeLlama** (7B, 13B, 34B) | Local — Ollama / vLLM | ✅ Full adversarial payloads | ✅ Full remediation patches |
| **DeepSeek Coder / V3** | Local + Cloud | ✅ Full adversarial payloads | ✅ Full remediation patches |
| **Qwen 2.5 Coder** (7B, 32B) | Local — Ollama / vLLM | ✅ Full adversarial payloads | ✅ Full remediation patches |
| **Claude (Anthropic API)** | Cloud | ⚠️ May refuse some payloads | ✅ Full remediation patches |

### Filtered / Safety-Aligned Models (Reduced Capability)

Models with heavy RLHF safety tuning may refuse to generate exploit payloads. When this happens, VibeGuard **automatically falls back** to deterministic payloads (70+ built-in attack values across 14 vectors). Phase 7 patches may also be affected — the model may refuse to analyze or modify code it deems "harmful."

| Model | Issue | Fallback Behavior |
|---|---|---|
| **GPT-4o / GPT-4** (OpenAI) | May refuse SQL injection / RCE payload generation | Falls back to deterministic payload library |
| **Gemini** (Google) | Heavy safety filtering on adversarial prompts | Falls back to deterministic payload library |
| **Claude** (Anthropic) | May refuse overtly malicious payloads (RCE, SQLi) | Falls back to deterministic payload library |
| **Phi-3/4** (Microsoft) | Alignment tuning may block red-team prompts | Falls back to deterministic payload library |

### Recommendation

> **For full adversarial coverage, use a local unfiltered model.** Install [Ollama](https://ollama.com), pull `llama3.1:8b` or `mistral:7b`, and configure VibeGuard:
> ```json
> {
>   "llm_provider": "custom",
>   "llm_api_endpoint": "http://localhost:11434/v1",
>   "llm_api_key": "ollama",
>   "llm_model": "llama3.1:8b"
> }
> ```

**Why this matters:**
- **Phase 5 (Payload Generation):** Filtered models may refuse to craft `' OR 1=1--` strings or `<script>alert(1)</script>` vectors. The deterministic fallback covers all 14 vulnerability classes, but lacks context-awareness (e.g., it won't know your endpoint expects `user_uuid` specifically).
- **Phase 7 (Patch Generation):** Filtered models may refuse to analyze vulnerable code or output "I cannot assist with that." The push still blocks, but you won't get a remediation patch — you'll need to fix the code manually.
- **Phase 2 (LLM Analysis):** Generally works on all models — vulnerability analysis is a defensive task that rarely triggers safety filters.

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
1. Validate your README is current and your commit follows Conventional Commits.
2. Extract the exact diff of what you're about to push.
3. Strip out non-functional noise (CSS, docs, comments).
4. Verify your local dev server is reachable.
5. Send code changes to your LLM for adversarial analysis (Sovereign System Architect).
6. Resolve modified files to reachable HTTP URLs (traditional + framework mapping).
7. Snapshot your database tables (SQLite/MySQL/PostgreSQL).
8. Generate red-team attack payloads via LLM (with deterministic fallback).
9. Fire payloads live against your server (parallel, 3s timeout each).
10. Run security assertions on every response (status code, DB leaks, auth bypass).
11. **Generate self-healing patches** for every confirmed vulnerability (Phase 7).
12. Restore your database to its pre-test state.
13. Report the combined verdict — pass or block the push. Show available patches.

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

### Phase 5 — Compliance & Payload Generation

**Modules:** [`src/compliance.ts`](src/compliance.ts) · [`src/payloadGen.ts`](src/payloadGen.ts)

#### 5a — Compliance Validator (`src/compliance.ts`)

Runs **at the very start** of the pipeline — before any network calls, LLM API costs, or database changes. Two mandatory checks:

**README Update Check:**
- Verifies `README.md` exists at the project root.
- Enforces minimum content length (200 chars).
- Detects stub/template indicators (`# Project Title`, `TODO`, `[INSERT]`, `tbd`, etc.).
- Scores for architectural documentation keywords (`architecture`, `pipeline`, `configuration`, `2026`, etc.) — requires ≥ 3 matches.
- Checks file modification age — flags if > 90 days stale.

**Semantic Commit Check:**
- Reads the latest commit via `git log -1 --pretty=%B`.
- Validates against 12 Conventional Commits prefixes: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `chore:`, `revert:`, `security:`.
- Auto-skips merge commits.
- Rejects vague descriptions (`"update"`, `"fix"`, `"wip"`, `"tmp"`).
- Requires ≥ 3 characters of meaningful description after the prefix.

If either check fails, the push is **aborted immediately** with exit code 1 and a high-contrast terminal warning:

```
✕  Compliance Check Failed

   README Check:   FAILED
     README.md appears to be a stub or template (contains "# Project Title").
     Replace with real project documentation.

   Commit Check:   PASSED

   Push blocked — compliance checks must pass before analysis proceeds.
```

#### 5b — Red-Team Payload Generator (`src/payloadGen.ts`)

Sends the Phase 3 `TargetTargets` + Phase 2 diff context to your LLM with a **Red-Team Security Engineer** system prompt.

**LLM-driven generation:**
- Requires context-aware payloads — if an endpoint expects `user_uuid`, the payload injects into that specific field: `user_uuid=1' OR '1'='1`.
- One payload per vulnerability vector per endpoint.
- Each payload includes `expected_fail_criteria` describing what response indicates a successful breach.

**Response Schema:**
```json
{
  "attack_suite": [
    {
      "target_url": "http://localhost:8000/api/login.php",
      "method": "POST",
      "attack_type": "sql_injection",
      "payload_data": {
        "username": "admin' OR '1'='1",
        "password": "anything' OR 1=1--"
      },
      "expected_fail_criteria": "HTTP 200 with session token — SQL injection bypassed authentication"
    }
  ]
}
```

**Deterministic Fallback Generator:**
If the LLM is unreachable or returns unparseable JSON, VibeGuard falls back to a built-in payload library covering all 14 vulnerability vectors with 70+ known attack values:

| Vector | Fallback Payloads |
|---|---|
| `sql_injection` | `1' OR '1'='1`, `' UNION SELECT NULL--`, `admin'--` |
| `auth_bypass` | `admin'--`, `' OR 1=1--`, `admin'#` |
| `rce` | `; ls -la`, `| whoami`, `$(cat /etc/passwd)` |
| `xss` | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` |
| `path_traversal` | `../../../etc/passwd`, URL-encoded variants |
| `ssrf` | `http://169.254.169.254/latest/meta-data/` |
| … and 8 more | Each with expected failure criteria |

### Phase 6 — Live Execution & Response Assertion

**Modules:** [`src/runner.ts`](src/runner.ts) · [`src/assertion.ts`](src/assertion.ts)

#### 6a — Parallel HTTP Runner (`src/runner.ts`)

Executes the full `attack_suite` against your local dev server.

- **Concurrency:** Up to 8 parallel requests via a worker-pool pattern.
- **Timeout:** Strict **3-second limit** per payload — aborts if the server hangs.
- **GET requests:** Payload data serialized into URL query strings via `URLSearchParams`.
- **POST requests:** Dual content-type handling:
  - `application/x-www-form-urlencoded` — default for traditional PHP/cPanel stacks.
  - `application/json` — auto-detected when payload values contain JSON-like structures (`{...}` or `[...]`).
- Captures first 2000 characters of each response body for signature scanning.
- Records latency, status code, and response headers per request.

#### 6b — Security Assertion Engine / The Judge (`src/assertion.ts`)

Evaluates every HTTP response against three assertion categories. An endpoint is marked **VULNERABLE** if any assertion triggers:

**1. Status Code Assertion:**
- HTTP 500 Internal Server Error — unhandled exception triggered by payload.
- HTTP 502 Bad Gateway — upstream service may have crashed.
- HTTP 503 Service Unavailable — server may be overloaded.

**2. Database Leak Assertion:**
Scans response bodies with 25+ regex patterns for raw infrastructure errors:
- MySQL/MariaDB: `You have an error in your SQL syntax`
- PDO/PHP: `Fatal error: Uncaught PDOException`, `SQLSTATE[42000]`
- PostgreSQL: `ERROR: syntax error at`, `pg_query()`
- SQLite: `SQLITE_ERROR`, `SQLite3::`
- Laravel: `Illuminate\Database\QueryException`
- Django: `django.db.utils`, `DatabaseError`
- Rails: `ActiveRecord::`, `PG::Error`
- SQLAlchemy: `sqlalchemy.exc.`
- Stack traces with file paths (`/var/www/`, `C:\xampp\`, `in /.../file.php on line 42`)

**3. Auth Bypass Assertion:**
An exploit targeting an auth or privilege endpoint returns HTTP 200 with privileged content instead of HTTP 401/403:
- Admin panel keywords: `admin dashboard`, `welcome back, admin`
- User data exposure: `username.*password`, `<table>` with user records
- Session tokens: `access_token`, `session_id` in response
- Database row dumps: `Array ([id] =>`, `{"id":..., "role":"admin"}`
- Redirect to admin area: HTTP 302 with `Location: /admin/...`

#### Test Result Display

Each test result is shown with color-coded status:

```
✕ VULNERABLE  POST http://localhost:8000/api/login.php
  Attack: sql_injection | HTTP 500 | 42ms
  [database_leak] Response body contains raw database error — SQL syntax leak.

✓ PASS        GET http://localhost:8000/api/users
  HTTP 200 | 18ms

! ERROR       POST http://localhost:8000/api/upload
  Request timed out after 3s. (3012ms)
```

#### Combined Verdict

The push passes only if **both** the LLM analysis (Phase 2) AND the live test run (Phase 6) report zero vulnerabilities. If either finds issues, the push is blocked:

```
✕  VibeGuard analysis FAILED — push blocked

   LLM analysis detected high-severity vulnerability vectors.
   Live tests confirmed 2 vulnerability/ies.

   Review the findings above and fix the issues before pushing.
```

### Phase 7 — Self-Healing Patch Engine

**Module:** [`src/healer.ts`](src/healer.ts)

When live tests confirm a vulnerability, Phase 7 automatically generates a localized code fix — a security patch — for each vulnerable file. Patches are written to `.vibeguard/patches/` for the developer to review. **Patches are NEVER applied automatically** — you review and apply them manually.

#### Pipeline Position

```
Phase 6 (Live Tests) → Phase 7 (Patch Generation) → Phase 4b (DB Restore) → Verdict
```

Phase 7 runs **before** database restore, so the exploit context (response signatures, stack traces) is still fresh for the LLM to analyze.

#### Step 1 — Exploit Context Aggregation

For each vulnerable test result, `buildExploitContext()` compiles a forensic profile:

- **Source file path** — cross-referenced from the Phase 3 target map (`target_url` → `associated_file`)
- **Raw source code** — read from disk (files up to 100KB; larger files are skipped with a warning)
- **Attack payload data** — the exact parameters that breached the endpoint
- **Response signature** — the triggered assertion category, matched DB error pattern, HTTP status, and response body excerpt (first 500 chars)
- **Vulnerability type** — the attack vector that confirmed the breach

#### Step 2 — Remediation Prompt

The exploit context + complete source code is sent to the LLM with a **Hardened Systems Security Engineer** system prompt. The model is instructed to:

1. Analyze WHY the exploit succeeded
2. Produce a corrected version of the **entire source file**
3. Follow vulnerability-specific remediation guidelines:

| Vulnerability | Remediation Strategy |
|---|---|
| `sql_injection` | Replace string concatenation with parameterized queries / prepared statements |
| `auth_bypass` / `privilege_escalation` | Add authorization checks, session validation, role verification |
| `xss` | Escape output with context-appropriate encoding; avoid innerHTML |
| `rce` / `command_injection` | Use argument arrays instead of shell strings; validate with allowlists |
| `path_traversal` | Canonicalize paths; verify result stays within allowed root |
| `ssrf` | Validate URLs against allowlists; block internal IP ranges |
| `deserialization` | Use safe formats (JSON) with schema validation |
| `input_fuzzing` / `misconfiguration` | Add input validation; enable security features |

#### Step 3 — Response Parsing

The LLM returns a JSON object:

```json
{
  "remediation_applied": true,
  "vulnerability_type": "sql_injection",
  "explanation": "The login handler concatenated user input directly into a SQL query. Replaced with a parameterized statement using positional placeholders, which prevents the injected ' OR '1'='1 payload from altering query logic.",
  "patched_code": "<?php\n// Full corrected file contents...\n?>"
}
```

If the model cannot determine a fix, `remediation_applied` is `false` — this is better than guessing.

#### Step 4 — Unified Diff Generation

`generateUnifiedDiff()` implements an **LCS (Longest Common Subsequence)** based diff algorithm:

1. Compute the LCS table between original and patched line arrays
2. Backtrack through the table to produce an edit script (keep / insert / delete)
3. Group edits into hunks with **3 lines of context** (standard unified diff format)
4. Merge adjacent hunks that overlap in their context windows
5. Format as standard `--- a/` / `+++ b/` / `@@` unified diff

The diff is written to `.vibeguard/patches/<filename>.patch`.

#### Step 5 — Patch File Output

Each vulnerable file gets its own `.patch` file:

```
.vibeguard/patches/
├── api_login.php.patch
├── src_auth_middleware.ts.patch
└── controllers_user_controller.py.patch
```

#### Terminal Display

```
── Self-Healing Patch Engine ──
→  Generating patches for 2 confirmed vulnerability/ies...
→  Requesting patch from llama3.1:8b for api/login.php (sql_injection)...

✓  Patch: .vibeguard/patches/api_login.php.patch [sql_injection]
   Replaced string concatenation with parameterized query using PDO prepared statements.

✓  Patch: .vibeguard/patches/src_auth.ts.patch [auth_bypass]
   Added session token validation before returning user data. Returns 401 for unauthenticated requests.

   2 patch(es) written to .vibeguard/patches/
   Review with: cat .vibeguard/patches/<file>.patch
   Apply with: git apply .vibeguard/patches/<file>.patch
```

#### Reviewing and Applying Patches

```bash
# Review a patch before applying
cat .vibeguard/patches/api_login.php.patch

# Apply a single patch
git apply .vibeguard/patches/api_login.php.patch

# Apply all patches
git apply .vibeguard/patches/*.patch

# Check what a patch would change (dry run)
git apply --stat .vibeguard/patches/api_login.php.patch
```

#### Failure Modes

| Scenario | Behavior |
|---|---|
| No associated source file found for target URL | Patch skipped — error in results |
| Source file too large (> 100KB) | Patch skipped — file too large |
| LLM call fails / times out | Patch skipped — LLM error in results |
| LLM returns `remediation_applied: false` | Patch skipped — model could not determine fix |
| Patched code identical to original | Patch skipped — no changes needed |
| Cannot write patch file to disk | Error reported, diff content still available in memory |

All failures are non-blocking — the push is still blocked (vulnerabilities were found), but you'll need to fix the code manually if patches couldn't be generated.

---

## Pre-Push Hook Behavior

When `vibeguard install` is run, it writes a script to `.git/hooks/pre-push`. On every `git push`:

1. **Git passes pushed refs** to the hook via stdin (one line per ref: `local_ref local_sha remote_ref remote_sha`).
2. **The hook parses** each ref to extract branch names.
3. **The hook invokes** `vibeguard run --local <branch> --remote <branch> --sha <sha>` for each ref.
4. **VibeGuard runs the full pipeline** (Phases 1–7 — compliance, diff, filter, LLM analysis, URL mapping, DB guard, payload generation, live test execution, response assertion, self-healing patch generation, DB restore).
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
                   ▼
┌─────────────────────────────────────────────┐
│  PHASE 5a — COMPLIANCE                      │
│  compliance.ts                              │
│  README check + commit message lint         │
│  FAIL → exit 1 (abort immediately)          │
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
│ diff   │──▶│ Strip docs │──▶│ Resolve URLs  │
│ from   │  │ Send to    │  │ Traditional   │
│ remote │  │ your LLM   │  │ & Framework   │
│        │  │ Parse JSON │  │ mapping       │
│        │  │ Build      │  │               │
│        │  │ verdict    │  │               │
└────────┘  └────────────┘  └───────┬───────┘
                                     │
                          ┌──────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ PHASE 4a     │  │ PHASE 5b     │  │ PHASE 6      │
│ dbGuard.ts   │  │ payloadGen.ts│  │ runner.ts    │
│              │  │              │  │ assertion.ts │
│ Snapshot DB  │──▶│ Generate     │──▶│ Fire HTTP    │
│ (SQLite/     │  │ red-team     │  │ requests     │
│  MySQL/PG)   │  │ payloads     │  │ (parallel,   │
│              │  │ via LLM      │  │  3s timeout) │
│              │  │ (+ fallback) │  │ Judge:       │
│              │  │              │  │ status code, │
│              │  │              │  │ DB leak,     │
│              │  │              │  │ auth bypass  │
└──────┬───────┘  └──────────────┘  └──────┬───────┘
       │                                    │
       │         ┌──────────────────────────┘
       │         │
       │         ▼
       │  ┌─────────────────────┐
       │  │ PHASE 7             │
       │  │ healer.ts           │
       │  │                     │
       │  │ For each vuln:      │
       │  │ Read source file    │
       │  │ Compile exploit ctx │
       │  │ Call LLM as         │
       │  │ Hardened Security   │
       │  │ Engineer            │
       │  │ Generate .patch     │
       │  │ (NEVER auto-apply)  │
       │  └──────────┬──────────┘
       │             │
       │             └──────────┐
       │                        │
       ▼                        ▼
┌─────────────────────┐
│ PHASE 4b + VERDICT  │
│ dbGuard.ts          │
│                     │
│ Restore DB state    │
│ Combined verdict:   │
│ LLM pass + test     │
│ pass → exit 0       │
│ Any fail → exit 1   │
│ Show patch paths    │
└─────────────────────┘
```

**Fail-closed design:** Any error in the pipeline (LLM timeout, server unreachable, DB snapshot failure, patch generation failure) blocks the push and exits with code 1. VibeGuard defaults to safety. Patch generation failures are non-blocking but reported — vulnerabilities were still found.

---

## Project Structure

```
vibe-guard/
├── src/
│   ├── cli.ts          # CLI entry point — argument parsing, command dispatch, full 6-phase pipeline orchestration
│   ├── config.ts       # Configuration manager — read/write/validate .vibeguard.json, init wizard, env-var resolution
│   ├── types.ts        # Shared type definitions — all interfaces, types, and constants for all 6 phases
│   ├── ui.ts           # Terminal UI — minimalist monochrome output helpers (muted, action, ok, fail, etc.)
│   │
│   ├── git.ts          # Phase 1 — Git diff extraction, remote resolution, unified diff parser
│   │
│   ├── parser.ts       # Phase 2a — Noise filter, comment stripper, file extension whitelist, token estimator
│   ├── llm.ts          # Phase 2b — LLM API client (OpenAI/Anthropic/custom), prompts, JSON parser, verdict builder
│   │
│   ├── checker.ts      # Phase 3a — Connectivity pre-flight check (1.5s timeout, HEAD→GET fallback)
│   ├── mapper.ts       # Phase 3b — Dual-strategy route resolution (traditional & framework), TargetTargets builder
│   │
│   ├── dbGuard.ts      # Phase 4 — Database state guard (SQLite/MySQL/PostgreSQL), table discovery, capture/restore
│   │
│   ├── compliance.ts   # Phase 5a — Pre-push compliance checks (README validation + Conventional Commits enforcement)
│   ├── payloadGen.ts   # Phase 5b — Red-team adversarial payload generation via LLM + deterministic fallback
│   │
│   ├── runner.ts       # Phase 6a — Parallel HTTP execution engine (8 concurrent, 3s timeout, GET/POST formatting)
│   ├── assertion.ts    # Phase 6b — Security assertion engine (status code, DB leak, auth bypass signature matching)
│   │
│   └── healer.ts       # Phase 7 — Self-Healing Patch Engine (exploit context, remediation LLM prompt, unified LCS diff, .patch output)
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

### "Compliance Check Failed"

VibeGuard blocks pushes that don't meet code quality standards.

**README check failed:** Ensure `README.md` exists at the project root with substantive architectural documentation (≥ 200 chars, real content, not a stub/template). Update it to reflect the current codebase state.

**Commit check failed:** Rewrite your commit message to follow Conventional Commits:
```bash
# Bad
git commit -m "update"

# Good
git commit -m "feat: add user authentication endpoint with JWT session tokens"
```

Valid prefixes: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `chore:`, `revert:`, `security:`

### "Payload generation failed" or "LLM generated 0 payloads"

The LLM could not generate payloads — this is most often caused by a **filtered/safety-aligned model** refusing to create exploit strings. VibeGuard automatically falls back to deterministic payload generation using a built-in library of 70+ attack values. The fallback payloads cover all 14 vulnerability vectors. You'll see `fallbackCount` in the payload generation summary — these are perfectly valid for testing.

For context-aware payloads (where the LLM knows your endpoint expects `user_uuid` and crafts an injection specific to that field), use an unfiltered model. See [Model Requirements](#model-requirements).

### "LLM generated 0 payloads — all fallback"

Your LLM may be a filtered/safety-aligned model that refuses to generate exploit payloads. VibeGuard automatically falls back to a built-in library of 70+ attack values — these work, but lack context-awareness.

**Fix:** Use an unfiltered local model for full adversarial coverage. See [Model Requirements](#model-requirements) for recommendations.

```bash
# Install Ollama and an unfiltered model
ollama pull llama3.1:8b
```

Then update `.vibeguard.json`:
```json
{
  "llm_provider": "custom",
  "llm_api_endpoint": "http://localhost:11434/v1",
  "llm_api_key": "ollama",
  "llm_model": "llama3.1:8b"
}
```

### "No patches generated" or "LLM could not determine a fix"

The self-healing patch engine (Phase 7) couldn't generate a fix. This can happen when:

- **Filtered model refused:** Safety-aligned models may refuse to analyze vulnerable code or output modified versions. Use an unfiltered model for patch generation.
- **Source file not found:** The vulnerable endpoint's source file couldn't be located from the target URL mapping. Check that the endpoint file from Phase 3 actually exists on disk.
- **File too large:** Source files over 100KB are skipped to avoid overwhelming the LLM's context window.
- **LLM returned `remediation_applied: false`:** The model couldn't determine a safe fix — this is better than guessing incorrectly.

**Fix:** Review the patch results in the terminal output. Each failure includes a specific error message. For manual remediation, review the vulnerability details shown in the Phase 6 results and apply the appropriate fix based on the vulnerability type.

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
