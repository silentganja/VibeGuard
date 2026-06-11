# VibeGuard

**Your code doesn't reach GitHub until an AI adversary has tried to break it and an AI security engineer has fixed what broke.**

VibeGuard installs a pre-push Git hook that triggers automatically before every `git push`. It extracts your diff, sends it to your own LLM for adversarial analysis, fires live exploit payloads against your local dev server, judges the responses, generates security patches, exports regression tests, and alerts your team — all before the push leaves your machine.

> **v1.1.0** · 30+ source modules · 7 domain directories · Zero runtime dependencies · ~122 KB production bundle · **5 System Hardening Fixes**
>
> **⚠️ Model Requirement:** VibeGuard performs at **100% capability on unfiltered/uncensored AI models**. Filtered or safety-aligned models (RLHF-heavy, cloud-hosted) may refuse to generate exploit payloads, causing the red-team engine to fall back to deterministic defaults. For full adversarial coverage, use a local unfiltered model (Ollama + Llama 3 / Mistral).

---

## Table of Contents

- [How It Works](#how-it-works)
- [Model Requirements](#model-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [CI/CD Usage](#cicd-usage)
- [Capabilities](#capabilities)
- [Project Structure](#project-structure)
- [Packaging & Distribution](#packaging--distribution)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## How It Works

```
                         ┌─────────────────────┐
                         │    git push          │
                         └─────────┬───────────┘
                                   │
                         ┌─────────▼───────────┐
                         │  .git/hooks/pre-push │  ← installed by `vibeguard install`
                         └─────────┬───────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌───────────────┐    ┌───────────────────────┐    ┌──────────────────────┐
│  Compliance   │    │  Diff Analysis        │    │  Connectivity        │
│  README check │───▶│  merge-base → parser  │───▶│  Probe dev server    │
│  Commit lint  │    │  Filter noise         │    │  Auto-start if down  │
└───────────────┘    │  Ignore directives    │    │  Map file → URL      │
                     └───────────────────────┘    └──────────┬───────────┘
                                                             │
                         ┌───────────────────────────────────┘
                         ▼
┌────────────────────┐    ┌───────────────────────┐    ┌────────────────────┐
│  DB State Guard    │    │  Red-Team Execution    │    │  Self-Healing      │
│  Snapshot tables   │───▶│  Auth token seeding    │───▶│  LLM remediation   │
│  (MySQL/PG/SQLite) │    │  Generate payloads     │    │  Unified diff patch│
└────────────────────┘    │  Fire HTTP (capped 3)  │    └──────────┬─────────┘
                          │  Assertion judgment    │               │
                          └───────────────────────┘               │
                                                                  │
┌─────────────────────────────────────────────────────────────────┘
▼
┌────────────────────────┐
│  Verdict + Recovery     │
│  Export regression test │
│  Notify team (Slack/DC) │
│  Restore DB state       │
│  Stop server (if auto)  │
│  Pass → exit 0 (push)   │
│  Any failure → exit 1   │
└────────────────────────┘
```

**Every `git push` triggers this pipeline automatically.** The pre-push hook intercepts the push, VibeGuard runs its full analysis against your local dev server, and the push only proceeds if every check passes. If a vulnerability is confirmed, the push is blocked with a detailed forensic report, a remediation patch, and a regression test ready to commit alongside your fix.

**Zero runtime dependencies.** Everything runs on Node.js built-ins and native CLI tools (`git`, `mysqldump`, `pg_dump`). The LLM is your own — local or remote. Works identically in local terminals and CI/CD pipelines via automatic environment detection.

---

## Model Requirements

VibeGuard's adversarial capabilities depend on the LLM's willingness to think like an attacker.

### Unfiltered Models (100% Capability)

| Model | Host | Red-Team Payloads | Security Patches |
|---|---|---|---|
| **Llama 3 / 3.1** (8B–405B) | Ollama / vLLM | ✅ Full adversarial | ✅ Full remediation |
| **Mistral / Mixtral** (7B, 8×7B) | Ollama / vLLM | ✅ Full adversarial | ✅ Full remediation |
| **CodeLlama** (7B–34B) | Ollama / vLLM | ✅ Full adversarial | ✅ Full remediation |
| **DeepSeek Coder / V3** | Local + Cloud | ✅ Full adversarial | ✅ Full remediation |
| **Qwen 2.5 Coder** (7B–32B) | Ollama / vLLM | ✅ Full adversarial | ✅ Full remediation |

### Filtered / Safety-Aligned Models (Reduced Capability)

| Model | Issue | Fallback |
|---|---|---|
| **GPT-4o / GPT-4** | May refuse SQLi/RCE payloads | Deterministic library (70+ values) |
| **Gemini** | Heavy safety filtering | Deterministic library |
| **Claude** (Anthropic) | May refuse overtly malicious payloads | Deterministic library |
| **Phi-3/4** | Alignment tuning blocks red-team | Deterministic library |

> **Recommendation:** Use a local unfiltered model. Install [Ollama](https://ollama.com), pull `llama3.1:8b`, and configure:
> ```json
> { "llm_provider": "custom", "llm_api_endpoint": "http://localhost:11434/v1", "llm_api_key": "ollama", "llm_model": "llama3.1:8b" }
> ```

---

## Installation

**Prerequisites:** Node.js ≥ 18, Git ≥ 2.0, a running LLM.

```bash
git clone https://github.com/silentganja/VibeGuard.git
cd VibeGuard
npm install        # TypeScript + esbuild (only dev deps)
npm run build:all  # Compile + bundle
npm link           # Make `vibeguard` globally available
```

Verify: `vibeguard --version` → `VibeGuard Engine v1.0.0 (2026)`

---

## Quick Start

```bash
cd ~/projects/my-app
vibeguard init       # Interactive config wizard
vibeguard install    # Install git pre-push hook
git commit -m "feat: add login endpoint"
git push             # VibeGuard triggers automatically before the push
```

On every `git push`, VibeGuard validates your README and commit message, extracts the diff, analyzes it via your LLM, maps endpoints to executable URLs, snapshots your database, generates red-team payloads, fires live HTTP exploits, judges responses, generates remediation patches, exports regression tests, and reports the verdict — all before your code leaves your machine.

---

## Commands

| Command | Description |
|---|---|
| `vibeguard init` | Interactive wizard — creates `.vibeguard.json` |
| `vibeguard install` | Writes `pre-push` hook into `.git/hooks/`. Skips gracefully in CI. |
| `vibeguard uninstall` | Removes the VibeGuard hook, restores backup if present. |
| `vibeguard config` | Prints current configuration. |
| `vibeguard run` | **[Internal]** Full pipeline — invoked automatically by the pre-push hook. |
| `vibeguard --version` / `-v` | Prints version and exits. |
| `vibeguard --help` / `-h` | Shows usage and command reference. |

`vibeguard run` flags: `--local <branch> --remote <branch> --sha <commit-ish>`

---

## Configuration

### Full Schema

```json
{
  "llm_provider": "custom",           // "custom" | "openai" | "anthropic"
  "llm_api_endpoint": "http://localhost:11434/v1",
  "llm_api_key": "$LLM_API_KEY",      // raw string or $ENV_VAR reference
  "llm_model": "llama3:8b",
  "target_local_url": "http://localhost:8000",
  "exclude_paths": ["node_modules/**", "vendor/**", ".git/**", "dist/**"],
  "db_type": "none",                  // "mysql" | "postgresql" | "sqlite" | "none"
  "db_host": "127.0.0.1",
  "db_port": 3306,
  "db_user": "root",
  "db_pass": "",
  "db_name": "",
  "db_sqlite_path": "",
  "llm_max_retries": 3,
  "llm_cache_enabled": true,
  "webhook_slack": "",
  "webhook_discord": "",
  "webhook_teams": "",
  "export_tests_enabled": true,
  "export_tests_framework": "bash",
  "export_tests_dir": ".vibeguard/tests",
  "server_start_command": "docker-compose up -d local-api",
  "server_stop_command": "docker-compose down",
  "max_concurrent_requests": 3,
  "auth_seeding": {
    "auth_type": "bearer",
    "token_generation_command": "node scripts/generate-sandbox-token.js",
    "header_name": "X-API-Key",
    "cookie_name": "sandbox_token",
    "query_param_name": "token"
  }
}
```

### Core Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `llm_provider` | `"custom"` \| `"openai"` \| `"anthropic"` | Yes | API format. `custom` = OpenAI-compatible (Ollama, vLLM, LM Studio). |
| `llm_api_endpoint` | URL | Yes | LLM API endpoint. |
| `llm_api_key` | string | Yes | API key. Prefix with `$` for env-var lookup (`$OPENAI_API_KEY`). |
| `llm_model` | string | Yes | Model ID (`llama3:8b`, `gpt-4o`, `claude-sonnet-4-6`). |
| `target_local_url` | URL | Yes | Base URL of your local dev server. |
| `exclude_paths` | string[] | No | Glob patterns excluded from diff analysis. |
| `db_*` | varies | No | Database guard. Set `db_type: "none"` to skip. |
| `llm_max_retries` | number | No | Retry attempts for rate-limited requests. Default: 3. |
| `llm_cache_enabled` | boolean | No | Cache LLM responses by diff hash. Default: true. |
| `webhook_slack` | URL | No | Slack incoming webhook for CI alerts. |
| `webhook_discord` | URL | No | Discord incoming webhook for CI alerts. |
| `webhook_teams` | URL | No | Teams incoming webhook for CI alerts. |
| `export_tests_enabled` | boolean | No | Auto-generate regression tests. Default: true. |
| `export_tests_framework` | `"jest"` \| `"bash"` | No | Test format. Default: `"bash"`. |
| `export_tests_dir` | string | No | Test output directory. Default: `".vibeguard/tests"`. |
| `server_start_command` | string | No | Shell command to auto-start the dev server if unreachable (Fix #1). |
| `server_stop_command` | string | No | Shell command to gracefully stop the dev server after tests (Fix #1). |
| `max_concurrent_requests` | number | No | Max parallel HTTP requests during testing. Default: `3` (Fix #3). |
| `auth_seeding` | object | No | Dynamic token negotiation for secured endpoints (Fix #2). See below. |

### Auth Seeding (Fix #2)

When endpoints require authentication, VibeGuard can negotiate a short-lived sandbox token before firing adversarial payloads. This prevents false-negative 401/403 results against secured routes.

| Field | Type | Required | Description |
|---|---|---|---|
| `auth_seeding.auth_type` | `"bearer"` \| `"header"` \| `"cookie"` \| `"query"` | Yes | How to inject the token into requests. |
| `auth_seeding.token_generation_command` | string | Yes | Shell command that prints a valid token to stdout. |
| `auth_seeding.header_name` | string | When `auth_type: "header"` | Custom header name (e.g. `X-API-Key`). |
| `auth_seeding.cookie_name` | string | When `auth_type: "cookie"` | Cookie name for the token. |
| `auth_seeding.query_param_name` | string | When `auth_type: "query"` | Query parameter name for the token. |

### Inline Ignore Directives (Fix #4)

Suppress false positives on intentional low-level code by annotating source lines directly:

```php
// @vibeguard-ignore sql_injection
$raw_query = "SELECT * FROM logs WHERE id = " . $untrusted_id;
```

```python
# @vibeguard-ignore rce,xss
os.system(user_provided_cmd)  # intentionally sandboxed upstream
```

Supported vectors: `sql_injection`, `xss`, `rce`, `auth_bypass`, `privilege_escalation`, `input_fuzzing`, `path_traversal`, `ssrf`, `idor`, `race_condition`, `deserialization`, `information_disclosure`, `misconfiguration`, `other`. Comma-separate multiple vectors. Works across all comment styles (`//`, `#`, `/* */`).

<details>
<summary><strong>LLM Provider Setup Examples</strong></summary>

**Ollama (recommended):**
```json
{ "llm_provider": "custom", "llm_api_endpoint": "http://localhost:11434/v1", "llm_api_key": "ollama", "llm_model": "llama3:8b" }
```

**LM Studio:**
```json
{ "llm_provider": "custom", "llm_api_endpoint": "http://localhost:1234/v1", "llm_api_key": "lm-studio", "llm_model": "local-model" }
```

**OpenAI:**
```json
{ "llm_provider": "openai", "llm_api_endpoint": "https://api.openai.com/v1", "llm_api_key": "$OPENAI_API_KEY", "llm_model": "gpt-4o" }
```

**Anthropic:**
```json
{ "llm_provider": "anthropic", "llm_api_endpoint": "https://api.anthropic.com", "llm_api_key": "$ANTHROPIC_API_KEY", "llm_model": "claude-sonnet-4-6" }
```
</details>

---

## CI/CD Usage

VibeGuard runs in CI/CD with **zero config files** — everything via environment variables.

<details>
<summary><strong>GitHub Actions</strong></summary>

```yaml
name: VibeGuard Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm install -g vibeguard
      - run: npm start & sleep 5
      - name: Run VibeGuard
        env:
          VIBE_LLM_PROVIDER: custom
          VIBE_LLM_ENDPOINT: ${{ secrets.VIBE_LLM_ENDPOINT }}
          VIBE_LLM_KEY: ${{ secrets.VIBE_LLM_KEY }}
          VIBE_LLM_MODEL: llama3.1:8b
          VIBE_TARGET_URL: http://localhost:3000
          VIBE_WEBHOOK_SLACK: ${{ secrets.VIBE_WEBHOOK_SLACK }}
        run: vibeguard run --local ${{ github.ref_name }} --remote origin/main
```
</details>

<details>
<summary><strong>GitLab CI</strong></summary>

```yaml
vibeguard:
  stage: test
  image: node:20
  before_script:
    - npm install -g vibeguard
    - npm start & sleep 5
  script:
    - vibeguard run --local $CI_COMMIT_BRANCH --remote origin/main
  variables:
    VIBE_LLM_PROVIDER: custom
    VIBE_LLM_ENDPOINT: $VIBE_LLM_ENDPOINT
    VIBE_LLM_KEY: $VIBE_LLM_KEY
    VIBE_LLM_MODEL: llama3.1:8b
    VIBE_TARGET_URL: http://localhost:3000
```
</details>

<details>
<summary><strong>Jenkins / Generic CI</strong></summary>

```bash
export VIBE_LLM_PROVIDER=custom
export VIBE_LLM_ENDPOINT="$LLM_ENDPOINT"
export VIBE_LLM_KEY="$LLM_KEY"
export VIBE_LLM_MODEL=llama3.1:8b
export VIBE_TARGET_URL=http://localhost:3000
export VIBE_WEBHOOK_SLACK="$SLACK_WEBHOOK"
vibeguard run --local "$BRANCH" --remote origin/main
```
</details>

**CI Environment Variables:** `VIBE_LLM_PROVIDER` · `VIBE_LLM_ENDPOINT` · `VIBE_LLM_KEY` · `VIBE_LLM_MODEL` · `VIBE_TARGET_URL` · `VIBE_EXCLUDE_PATHS` · `VIBE_WEBHOOK_SLACK` · `VIBE_WEBHOOK_DISCORD` · `VIBE_WEBHOOK_TEAMS` · `VIBE_DB_TYPE` · `VIBE_DB_HOST` · `VIBE_DB_PORT` · `VIBE_DB_USER` · `VIBE_DB_PASS` · `VIBE_DB_NAME` · `VIBE_DB_SQLITE_PATH`

---

## Capabilities

<details>
<summary><strong>Diff Extraction & Noise Filtering</strong></summary>

<strong>Intelligent Merge-Base Diff Tracking (Fix #5):</strong> Computes the cryptographic common ancestor via `git merge-base HEAD @{u}` before computing the diff. This prevents nested feature branches (feature/nested → feature/parent → main) from capturing hundreds of lines of unrelated team changes in the diff — only the developer's own code is analyzed.

Captures the exact changes about to be pushed via `git diff <merge-base>...HEAD`. Strips non-functional noise — comments, doc blocks, CSS, lockfiles, whitespace — before sending to the LLM. File extension whitelist covers 50+ languages. Supports inline `@vibeguard-ignore <vector>` directives for suppressing false positives on intentionally dangerous but safe code. Outputs a token-optimized payload with a discarded-file audit trail and ignored-vector summary.

📁 [`src/analyzer/git.ts`](src/analyzer/git.ts) · [`src/analyzer/parser.ts`](src/analyzer/parser.ts)
</details>

<details>
<summary><strong>Adversarial LLM Analysis</strong></summary>

The diff is analyzed by a "Sovereign System Architect" persona — a principal-level security engineer instructed to think adversarially about every input. Supports OpenAI-compatible and Anthropic APIs with 6-second timeout, JSON-mode response format, and fallback extraction from markdown-fenced responses. Produces a structured verdict with per-file risk summaries and severity grading (critical/high/medium/low).

📁 [`src/infrastructure/llm.ts`](src/infrastructure/llm.ts)
</details>

<details>
<summary><strong>Diff-Hash Caching & Rate-Limit Handling</strong></summary>

SHA-256 hashes the sanitized diff to cache LLM responses locally (`.vibeguard/cache/`). Identical code changes skip the network entirely with a `[VibeGuard: Using Cached Intent]` indicator. Exponential backoff retry on 429/502/503/504 (1s → 2.5s → 5s). Circuit breaker trips after consecutive failures, aborting with a clean `[LLM Error]` message.

📁 [`src/utils/cache.ts`](src/utils/cache.ts)
</details>

<details>
<summary><strong>Route Resolution & Connectivity</strong></summary>

Dual-strategy URL mapping: traditional (file path → URL with public subfolder detection) and framework-aware (Laravel, Symfony, Next.js, Go, Rails via sentinel files). Probes `target_local_url` before analysis begins.

**Server Lifetime Management (Fix #1):** If the health check fails, VibeGuard automatically runs `server_start_command` to spin up your Docker container or local backend, waits for warmup, retries the probe, then runs all tests. After the pipeline completes, `server_stop_command` gracefully tears down the environment. No more "forgot to start Docker" push blocks.

📁 [`src/analyzer/mapper.ts`](src/analyzer/mapper.ts) · [`src/infrastructure/checker.ts`](src/infrastructure/checker.ts)
</details>

<details>
<summary><strong>Database State Guard</strong></summary>

Discovers SQL-referenced tables from the diff (12 regex patterns for FROM/UPDATE/INSERT/DELETE). Captures state before adversarial payloads fire and restores after — always, even on pipeline crash (emergency restore in catch block). Three backends: SQLite (binary copy), MySQL (`mysqldump`), PostgreSQL (`pg_dump`).

📁 [`src/infrastructure/dbGuard.ts`](src/infrastructure/dbGuard.ts)
</details>

<details>
<summary><strong>Red-Team Payload Generation</strong></summary>

A "Red-Team Security Engineer" persona generates context-aware attack payloads targeting your endpoint's specific parameter names. Deterministic fallback library covers all 14 vulnerability vectors with 70+ known attack values — SQL injection, XSS, RCE, path traversal, SSRF, IDOR, deserialization, and more.

📁 [`src/engine/payloadGen.ts`](src/engine/payloadGen.ts)
</details>

<details>
<summary><strong>Live HTTP Execution & Assertions</strong></summary>

Fires payloads in parallel against your local dev server with a configurable concurrency cap (default 3, Fix #3) to prevent self-DoS against lightweight single-threaded servers. Strict 3-second timeout per request. GET requests become query strings; POST requests are form-urlencoded (auto-detects JSON). Captures response body, headers, status code, and latency. Three assertion categories: status code (500/502/503), database leak (25+ regex signatures), and auth bypass (admin panel detection, user data exposure).

**Dynamic Auth Token Seeding (Fix #2):** Before firing payloads, VibeGuard can negotiate a short-lived sandbox token via `token_generation_command` and inject it into every request as a Bearer token, custom header, cookie, or query parameter. This ensures secured endpoints return meaningful vulnerability signals rather than false-negative 401s.

📁 [`src/engine/runner.ts`](src/engine/runner.ts) · [`src/engine/assertion.ts`](src/engine/assertion.ts) · [`src/utils/http.ts`](src/utils/http.ts)
</details>

<details>
<summary><strong>Self-Healing Patch Engine</strong></summary>

A "Hardened Systems Security Engineer" persona receives the exploit context (source file + payload + response signature) and produces a surgically precise code fix. Per-vector remediation guidelines: parameterized queries for SQLi, authorization checks for auth bypass, output escaping for XSS, argument arrays for RCE. LCS-based unified diff patches written to `.vibeguard/patches/` — **never auto-applied**, always reviewed.

📁 [`src/engine/healer.ts`](src/engine/healer.ts) · [`src/utils/diff.ts`](src/utils/diff.ts)
</details>

<details>
<summary><strong>Regression Test Export</strong></summary>

Converts confirmed vulnerabilities into permanent, runnable test files. Two formats: **Jest** (`describe`/`it` blocks asserting the endpoint now rejects the payload) and **Bash** (cURL script that exits 1 if the vulnerability is still present). Generated files are auto-staged via `git add` so the fix commit always includes the regression guard.

📁 [`src/engine/exporter.ts`](src/engine/exporter.ts)
</details>

<details>
<summary><strong>CI/CD Webhook Notifications</strong></summary>

Broadcasts vulnerability alerts to Slack, Discord, and Microsoft Teams when running in headless CI mode. Platform-specific formatting: Discord embeds (#ff0000), Slack Block Kit (mrkdwn), Teams Adaptive Cards. Parallel dispatch with 2s timeout — one slow webhook never blocks the others.

📁 [`src/infrastructure/webhooks.ts`](src/infrastructure/webhooks.ts)
</details>

<details>
<summary><strong>Structured Debug Logging</strong></summary>

Non-blocking JSON Lines logger writes execution metrics to `.vibeguard/logs/engine_debug.log`. Each entry captures timestamp, severity level, pipeline context, and message. Automatic rotation at 10 MB (3 backups). Crash-safe synchronous variant for unhandled exceptions. 17 log contexts span the full pipeline.

📁 [`src/utils/logger.ts`](src/utils/logger.ts)
</details>

<details>
<summary><strong>CI/CD Detection & Enterprise Config</strong></summary>

Detects 15 CI platforms automatically (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps, etc.). Switches to machine-readable output in headless mode. 17 `VIBE_*` environment variables provide full configuration without a config file. Hook installation and patch generation gracefully skip in CI.

📁 [`src/compliance/ci.ts`](src/compliance/ci.ts) · [`src/compliance/compliance.ts`](src/compliance/compliance.ts)
</details>

<details>
<summary><strong>Production Build & Distribution</strong></summary>

5-stage build pipeline: dev artifact cleanup → type-check → esbuild bundle (single minified CJS, ~122 KB, Node 18+) → platform wrappers (Unix shell + Windows `.cmd`) → optional Node.js SEA native binaries (6 targets: linux/macos/win × x64/arm64). Post-install verification script validates Node version, Git availability, and permissions.

📁 [`scripts/build.mjs`](scripts/build.mjs) · [`scripts/verify.mjs`](scripts/verify.mjs)
</details>

---

## Project Structure

```
vibe-guard/
├── src/
│   ├── cli/                   # Entry points & UI
│   │   ├── index.ts           #   CLI entry — args, dispatch, full pipeline
│   │   ├── ui.ts              #   Low-level terminal UI primitives
│   │   └── ux.ts              #   Terminal UX — threat cards, patch cards, CI dispatch
│   │
│   ├── core/                  # Foundation & Configuration
│   │   ├── index.ts           #   Barrel export
│   │   ├── types.ts           #   All shared interfaces, types, and constants
│   │   ├── config.ts          #   Config manager — .vibeguard.json, CI env-var fallback
│   │   └── hooks.ts           #   Git hook installer — bash + PowerShell, CI-aware
│   │
│   ├── analyzer/              # Git & File Analysis
│   │   ├── index.ts           #   Barrel export
│   │   ├── git.ts             #   Diff extraction, merge-base tracking (Fix #5), unified diff parser
│   │   ├── parser.ts          #   Noise filter, comment stripper, token estimator, @vibeguard-ignore (Fix #4)
│   │   └── mapper.ts          #   Route resolution (traditional + framework)
│   │
│   ├── engine/                # Execution & Security
│   │   ├── index.ts           #   Barrel export
│   │   ├── runner.ts          #   Parallel HTTP execution (configurable concurrency, auth seeding)
│   │   ├── assertion.ts       #   Security assertions (25+ regex patterns)
│   │   ├── payloadGen.ts      #   Red-team payload gen + deterministic fallback (70+ values)
│   │   ├── healer.ts          #   Self-healing patch engine (LCS diff, LLM remediation)
│   │   └── exporter.ts        #   Regression test export (Jest + Bash, auto git-staged)
│   │
│   ├── infrastructure/        # External Connections & State
│   │   ├── index.ts           #   Barrel export
│   │   ├── llm.ts             #   LLM client (OpenAI/Anthropic/custom) + cache + retry
│   │   ├── dbGuard.ts         #   DB guard (SQLite/MySQL/PostgreSQL) + table discovery
│   │   ├── checker.ts         #   Connectivity pre-flight + server lifecycle (Fix #1)
│   │   └── webhooks.ts        #   CI notifications (Slack/Discord/Teams)
│   │
│   ├── compliance/            # Validation & CI
│   │   ├── index.ts           #   Barrel export
│   │   ├── ci.ts              #   CI detection (15 platforms), env-var config (17 vars)
│   │   └── compliance.ts      #   README + commit message enforcement
│   │
│   └── utils/                 # Shared Utilities
│       ├── index.ts           #   Barrel export
│       ├── diff.ts            #   LCS-based unified diff generator
│       ├── http.ts            #   HTTP request builders (GET/POST, auth-aware)
│       ├── comment-stripper.ts #  Language-agnostic comment detection & removal
│       ├── cache.ts           #   SHA-256 diff hash cache + file-system store
│       └── logger.ts          #   Structured JSON Lines logger + log rotation
│
├── scripts/
│   ├── build.mjs              # 5-stage production build (cleanup → type-check → bundle → wrappers → SEA)
│   └── verify.mjs             # Post-install verification
│
├── dist/
│   ├── vibeguard.cjs          #   Production bundle (~122 KB, zero deps)
│   ├── vibeguard              #   Unix wrapper
│   └── vibeguard.cmd          #   Windows wrapper
│
├── .vibeguard.json            # Project config (created by `vibeguard init`)
├── package.json               # Zero runtime deps, esbuild + typescript as devDeps
├── tsconfig.json
└── README.md
```

**Dependency flow (no cycles):** `cli` → `engine` / `analyzer` / `infrastructure` / `compliance` → `core` → `utils`

---

## Packaging & Distribution

```bash
npm install -g .               # Global install from source
npm pack                       # Create .tgz for distribution
node scripts/build.mjs         # Bundle only (dist/vibeguard.cjs)
node scripts/build.mjs --native  # Bundle + native binaries
```

---

## Troubleshooting

<details>
<summary><strong>Common issues</strong></summary>

**"Local development server at \<url\> is unreachable"**
Your dev server isn't running. Start it before pushing. Verify `target_local_url` in `.vibeguard.json`.

**"LLM request timed out after 6s"**
Your LLM didn't respond in time. Check: is the LLM running? Is `llm_api_endpoint` correct? For local models (Ollama/LM Studio), ensure the server is started.

**"[LLM Error] API unreachable after 3 attempt(s)"**
The circuit breaker tripped after 3 consecutive API failures. Check your LLM endpoint and network connectivity. A single successful call resets the breaker.

**"LLM API returned 4xx"**
Authentication or endpoint issue. Verify `llm_api_key` and `llm_api_endpoint`. For `$ENV_VAR` references, ensure the variable is set.

**"No .vibeguard.json found" (local)**
Run `vibeguard init` to create your config interactively.

**"Missing required environment variables" (CI)**
Set `VIBE_LLM_PROVIDER`, `VIBE_LLM_ENDPOINT`, `VIBE_LLM_KEY`, `VIBE_LLM_MODEL`, and `VIBE_TARGET_URL` in your CI pipeline.

**"Failed to parse LLM response as JSON"**
The model returned non-JSON output. Try a different model. The built-in fallback handles this for payload generation.

**"No upstream tracking branch found"**
Set the upstream: `git push --set-upstream origin <branch>`.

**"Server start command failed"**
VibeGuard tried to auto-start your dev server but the command failed. Check `server_start_command` in `.vibeguard.json`. Example: `"docker-compose up -d local-api"` or `"npm run dev"`.

**"Auth token generation failed"**
The `token_generation_command` in your `auth_seeding` config failed or returned empty. Verify the command prints a valid token to stdout.

**"Connection refused" persists despite auto-start**
VibeGuard launches `server_start_command` as a detached process and polls the server for up to 60s. If it never becomes reachable, the server is likely failing to boot — run the command manually and check its output.

**"commands ... have not been trusted on this machine"**
The repo's `.vibeguard.json` defines shell commands that VibeGuard refuses to execute without your approval. Review and approve them once with `vibeguard trust`.

**"max_concurrent_requests" validation error**
Must be 1–50. Lightweight single-threaded servers: keep at 2–3. Multi-threaded (Go, Node cluster): 5–8 is safe.

**"[VibeGuard Critical Exception]"**
An unhandled engine crash occurred. Full diagnostics are in `.vibeguard/logs/engine_debug.log`. This should never happen — please file a bug report.

**"npm link" says "permission denied" (Linux/macOS)**
Use `sudo npm link` or configure a user-level global prefix.

**Push blocked but I want to bypass**
`git push --no-verify` (not recommended — the vulnerabilities are real).
</details>

---

## Security Notes

`.vibeguard.json` is committed to the repository, and three of its fields are shell commands executed on your machine: `server_start_command`, `server_stop_command`, and `auth_seeding.token_generation_command`.

- VibeGuard never executes these commands until you explicitly trust them. The first time they are seen — and any time they change — you must approve them (run `vibeguard trust`; approvals are cached in `~/.vibeguard/trusted.json`, outside the repo).
- In non-interactive contexts (git hooks, CI) untrusted commands fail closed with guidance instead of executing.
- Auth tokens produced by `token_generation_command` are trimmed and rejected if they contain CR/LF characters, preventing HTTP header injection.

---

## License

MIT — see [package.json](package.json).
