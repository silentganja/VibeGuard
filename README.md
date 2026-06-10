# VibeGuard

**CLI-native adversarial local QA daemon** — your code doesn't leave your machine until an AI adversary has tried to break it and an AI security engineer has fixed what broke.

> **v1.0.0** · 11-phase engine · 27 source modules · Zero runtime dependencies
>
> **⚠️ Model Requirement:** VibeGuard performs at **100% capability on unfiltered/uncensored AI models**. Filtered or safety-aligned models (RLHF-heavy, cloud-hosted) may refuse to generate exploit payloads, causing Phase 5/7 to fall back to deterministic defaults. Use a local unfiltered model (Ollama + Llama 3 / Mistral) for full adversarial coverage.

---

## Table of Contents

- [Architecture](#architecture)
- [Model Requirements](#model-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [CI/CD Usage](#cicd-usage)
- [Phase-by-Phase Breakdown](#phase-by-phase-breakdown)
- [Project Structure](#project-structure)
- [Packaging & Distribution](#packaging--distribution)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Architecture

```
                         ┌─────────────────────┐
                         │    git push          │
                         └─────────┬───────────┘
                                   │
                         ┌─────────▼───────────┐
                         │  .git/hooks/pre-push │  ← `vibeguard install`
                         └─────────┬───────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌───────────────┐    ┌───────────────────────┐    ┌─────────────────────┐
│  Phase 5a     │    │  Phase 1+2            │    │  Phase 3            │
│  Compliance   │    │  git → parser → llm   │    │  checker + mapper   │
│  README check │───▶│  Extract diff          │───▶│  Probe dev server   │
│  Commit lint  │    │  Strip noise           │    │  Resolve file→URL   │
└───────────────┘    └───────────────────────┘    └──────────┬──────────┘
                                                             │
                         ┌───────────────────────────────────┘
                         ▼
┌────────────────────┐    ┌───────────────────────┐    ┌────────────────────┐
│  Phase 4           │    │  Phase 5b + 6          │    │  Phase 7           │
│  DB Guard          │    │  payload → run → assert│    │  Healer            │
│  Snapshot tables   │───▶│  Generate red-team     │───▶│  LLM remediation   │
│                    │    │  Fire HTTP (parallel)  │    │  Unified diff patch│
└────────────────────┘    └───────────────────────┘    └──────────┬─────────┘
                                                                  │
┌─────────────────────────────────────────────────────────────────┘
▼
┌────────────────────────┐
│  Phase 4b + Verdict    │
│  Restore DB state      │
│  Pass → exit 0 (push)  │
│  Any failure → exit 1  │
└────────────────────────┘
```

**Zero runtime dependencies.** Everything runs on Node.js built-ins and native CLI tools (`git`, `mysqldump`, `pg_dump`). The LLM is your own — local or remote. Works identically in local terminals and CI/CD pipelines via automatic environment detection.

---

## Model Requirements

VibeGuard's adversarial capabilities depend on the LLM's willingness to think like an attacker.

### Unfiltered Models (100% Capability)

| Model | Host | Phase 5 (Payloads) | Phase 7 (Patches) |
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
git push             # VibeGuard activates automatically
```

On every `git push`, VibeGuard validates your README + commit message, extracts the diff, analyzes via your LLM, maps endpoints, snapshots your DB, fires live exploits, judges responses, generates patches, restores your DB, and reports the verdict.

---

## Commands

| Command | Description |
|---|---|
| `vibeguard init` | Interactive wizard — creates `.vibeguard.json` |
| `vibeguard install` | Writes `pre-push` hook into `.git/hooks/`. Skips gracefully in CI. |
| `vibeguard uninstall` | Removes the VibeGuard hook, restores backup if present. |
| `vibeguard config` | Prints current configuration. |
| `vibeguard run` | **[Internal]** Full pipeline — invoked by the pre-push hook. |
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
  "db_sqlite_path": ""
}
```

### Field Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `llm_provider` | `"custom"` \| `"openai"` \| `"anthropic"` | Yes | API format. `custom` = OpenAI-compatible (Ollama, vLLM, LM Studio). |
| `llm_api_endpoint` | URL | Yes | LLM API endpoint. |
| `llm_api_key` | string | Yes | API key. Prefix with `$` for env-var lookup (`$OPENAI_API_KEY`). |
| `llm_model` | string | Yes | Model ID (`llama3:8b`, `gpt-4o`, `claude-sonnet-4-6`). |
| `target_local_url` | URL | Yes | Base URL of your dev server. |
| `exclude_paths` | string[] | No | Glob patterns excluded from diff analysis. |
| `db_*` | varies | No | Phase 4 DB guard. Set `db_type: "none"` to skip. |

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
vibeguard run --local "$BRANCH" --remote origin/main
```
</details>

**Environment Variables:** `VIBE_LLM_PROVIDER` · `VIBE_LLM_ENDPOINT` · `VIBE_LLM_KEY` · `VIBE_LLM_MODEL` · `VIBE_TARGET_URL` · `VIBE_EXCLUDE_PATHS` · `VIBE_DB_TYPE` · `VIBE_DB_HOST` · `VIBE_DB_PORT` · `VIBE_DB_USER` · `VIBE_DB_PASS` · `VIBE_DB_NAME` · `VIBE_DB_SQLITE_PATH`

---

## Phase-by-Phase Breakdown

<details>
<summary><strong>Phase 1 — Git Diff Extraction</strong></summary>

[`src/analyzer/git.ts`](src/analyzer/git.ts)

- Resolves the remote tracking branch (`origin/main`) and runs `git diff <upstream>...HEAD`.
- Three-dot syntax captures exactly what's about to be pushed.
- Parses unified diff → `DiffFile` → `DiffHunk` → `DiffLine` structured objects.
- Respects `exclude_paths` via git's `:(exclude)` pathspec.
</details>

<details>
<summary><strong>Phase 2 — Noise Filter & LLM Analysis</strong></summary>

[`src/analyzer/parser.ts`](src/analyzer/parser.ts) · [`src/infrastructure/llm.ts`](src/infrastructure/llm.ts)

**2a — Noise Filter:** Runs locally. File extension whitelist (50+ languages), comment stripping (single-line, block, JSDoc, docstrings), lockfile exclusion, whitespace removal. Outputs token-optimized `FilteredDiff` with discarded-file audit trail.

**2b — LLM Analysis:** "Sovereign System Architect" persona. Supports OpenAI-compatible (`/chat/completions`) and Anthropic (`/messages`) APIs. 6-second timeout, JSON-mode response format, fallback extraction from markdown-fenced responses. Produces `AnalysisVerdict` with pass/fail + per-file risk summary.
</details>

<details>
<summary><strong>Phase 3 — Connectivity Check & Route Mapping</strong></summary>

[`src/infrastructure/checker.ts`](src/infrastructure/checker.ts) · [`src/analyzer/mapper.ts`](src/analyzer/mapper.ts)

**3a — Connectivity:** Probes `target_local_url` with 1.5s timeout (HEAD → GET fallback). Blocks push immediately if unreachable.

**3b — Route Mapping:** Dual-strategy resolution — traditional (file path → URL, public subfolder detection) and framework (Laravel, Symfony, Next.js, Go, Rails sentinel files). Cross-references LLM's `estimated_route` with filesystem layout.
</details>

<details>
<summary><strong>Phase 4 — Database State Guard</strong></summary>

[`src/infrastructure/dbGuard.ts`](src/infrastructure/dbGuard.ts)

SQL table discovery (12 regex patterns scanning diff hunks for FROM/UPDATE/INSERT/DELETE). Three backends: SQLite (binary file copy), MySQL (`mysqldump`), PostgreSQL (`pg_dump`). Capture before Phase 5/6 payloads fire; restore after — always, even on pipeline crash (emergency restore in `catch` block).
</details>

<details>
<summary><strong>Phase 5 — Compliance & Payload Generation</strong></summary>

[`src/compliance/compliance.ts`](src/compliance/compliance.ts) · [`src/engine/payloadGen.ts`](src/engine/payloadGen.ts)

**5a — Compliance:** Runs BEFORE any network calls. Validates README.md exists, is substantive (≥200 chars), contains architectural docs, and was modified within 90 days. Enforces Conventional Commits (`feat:`, `fix:`, `docs:`, etc.) on the latest commit.

**5b — Payload Generation:** "Red-Team Security Engineer" persona. Context-aware — targets specific parameter names from the diff. Deterministic fallback library covers all 14 vulnerability vectors with 70+ known attack values.
</details>

<details>
<summary><strong>Phase 6 — Live Execution & Response Assertion</strong></summary>

[`src/engine/runner.ts`](src/engine/runner.ts) · [`src/engine/assertion.ts`](src/engine/assertion.ts)

**6a — Runner:** Parallel HTTP execution (8 concurrent), 3s timeout per request. GET → query string, POST → form-urlencoded (auto-detects JSON payloads). Captures response body (first 2000 chars), headers, status code, latency.

**6b — Assertion Engine:** Three categories — status code (500/502/503), database leak (25+ regex signatures: MySQL, PDO, PostgreSQL, SQLite, Laravel, Django, Rails, SQLAlchemy), auth bypass (admin panel detection, user data exposure, redirect to admin areas).
</details>

<details>
<summary><strong>Phase 7 — Self-Healing Patch Engine</strong></summary>

[`src/engine/healer.ts`](src/engine/healer.ts)

"Hardened Systems Security Engineer" persona. Exploit context aggregation (source file + payload + response signature + assertion detail). Per-vector remediation guidelines (parameterized queries for SQLi, authorization checks for auth bypass, output escaping for XSS, argument arrays for RCE, canonicalization for path traversal, allowlists for SSRF, safe formats for deserialization). LCS-based unified diff generation via [`src/utils/diff.ts`](src/utils/diff.ts). Patches written to `.vibeguard/patches/` — **never auto-applied**. Skipped in CI mode.
</details>

<details>
<summary><strong>Phase 8 — Terminal UX</strong></summary>

[`src/cli/ux.ts`](src/cli/ux.ts)

ANSII-styled terminal output (bold, dim, gray, white, green, red, yellow, cyan). Threat cards (file, endpoint, payload, signature, verdict), patch cards (path, word-wrapped explanation, review/apply commands). Automatic CI/terminal dispatch via `getOutputMode()`. Machine-readable `[VibeGuard]` prefixed output for CI logs.
</details>

<details>
<summary><strong>Phase 9 — CI/CD Detection & Enterprise Config</strong></summary>

[`src/compliance/ci.ts`](src/compliance/ci.ts)

Detects 15 CI platforms via environment flags. Headless detection via CI env vars + `VIBE_ENV=enterprise` + `!process.stdin.isTTY`. 14 `VIBE_*` env vars mapped to `VibeGuardConfig`. Config resolution: CI env vars → local `.vibeguard.json` → env var fallback. Hook installation/uninstallation skipped in CI. Phase 7 patch generation skipped in CI.
</details>

<details>
<summary><strong>Phase 10 — Packaging & Distribution</strong></summary>

[`scripts/build.mjs`](scripts/build.mjs) · [`scripts/verify.mjs`](scripts/verify.mjs)

4-stage build: type-check → esbuild bundle (single minified CJS, ~103 KB, Node 18+) → platform wrappers (Unix shell + Windows `.cmd`) → optional Node.js SEA native binaries (6 targets: linux/macos/win × x64/arm64). `postinstall` verification script (Node version, Git availability, entry point, execute permissions). `--version` / `-v` flag.
</details>

---

## Pre-Push Hook Behavior

<details>
<summary><strong>Hook flow</strong></summary>

1. Git passes pushed refs to the hook via stdin (`local_ref local_sha remote_ref remote_sha`).
2. Hook parses branch names and invokes `vibeguard run --local <branch> --remote <branch>`.
3. VibeGuard runs the full pipeline (Phases 1–7).
4. **Exit 0** → push proceeds. **Exit 1** → push blocked with forensic report.
5. Bash hook for Linux/macOS/Git Bash; PowerShell fallback (`pre-push.ps1`) for Windows.
6. Existing hooks are backed up as `.vibeguard.bak` before overwriting.
</details>

---

## Project Structure

```
vibe-guard/
├── src/
│   ├── cli/                   # Entry points & UI
│   │   ├── index.ts           #   CLI entry — args, dispatch, 10-phase pipeline
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
│   │   ├── git.ts             #   Phase 1 — Diff extraction, unified diff parser
│   │   ├── parser.ts          #   Phase 2a — Noise filter, comment stripper, token estimator
│   │   └── mapper.ts          #   Phase 3b — Route resolution (traditional + framework)
│   │
│   ├── engine/                # Execution & Security
│   │   ├── index.ts           #   Barrel export
│   │   ├── runner.ts          #   Phase 6a — Parallel HTTP execution (8 concurrent, 3s timeout)
│   │   ├── assertion.ts       #   Phase 6b — Security assertions (25+ regex patterns)
│   │   ├── payloadGen.ts      #   Phase 5b — Red-team payload gen + deterministic fallback
│   │   └── healer.ts          #   Phase 7 — Self-healing patch engine
│   │
│   ├── infrastructure/        # External Connections & State
│   │   ├── index.ts           #   Barrel export
│   │   ├── llm.ts             #   Phase 2b — LLM client (OpenAI/Anthropic/custom)
│   │   ├── dbGuard.ts         #   Phase 4 — DB guard (SQLite/MySQL/PostgreSQL)
│   │   └── checker.ts         #   Phase 3a — Connectivity pre-flight check
│   │
│   ├── compliance/            # Validation & CI
│   │   ├── index.ts           #   Barrel export
│   │   ├── ci.ts              #   Phase 9 — CI detection (15 platforms), env-var config
│   │   └── compliance.ts      #   Phase 5a — README + commit message enforcement
│   │
│   └── utils/                 # Shared Utilities (extracted per Phase 11)
│       ├── index.ts           #   Barrel export
│       ├── diff.ts            #   LCS-based unified diff generator
│       ├── http.ts            #   HTTP request builders (GET/POST)
│       └── comment-stripper.ts #  Language-agnostic comment detection & removal
│
├── scripts/
│   ├── build.mjs              # Production build (esbuild + optional SEA binaries)
│   └── verify.mjs             # Post-install verification
│
├── dist/
│   ├── vibeguard.cjs          #   Production bundle (~103 KB, zero deps)
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
npm install -g .              # Global install from source
npm pack                      # Create .tgz for distribution
node scripts/build.mjs        # Bundle only (dist/vibeguard.cjs)
node scripts/build.mjs --native  # Bundle + native binaries
```

---

## Troubleshooting

<details>
<summary><strong>Common issues</strong></summary>

**"Local development server at <url> is unreachable"**
Your dev server isn't running. Start it before pushing. Verify `target_local_url` in `.vibeguard.json`.

**"LLM request timed out after 6s"**
Your LLM didn't respond in time. Check: is the LLM running? Is `llm_api_endpoint` correct? For local models (Ollama/LM Studio), ensure the server is started.

**"LLM API returned 4xx"**
Authentication or endpoint issue. Verify `llm_api_key` and `llm_api_endpoint`. For `$ENV_VAR` references, ensure the variable is set.

**"No .vibeguard.json found" (local)**
Run `vibeguard init` to create your config interactively.

**"Missing required environment variables" (CI)**
Set `VIBE_LLM_PROVIDER`, `VIBE_LLM_ENDPOINT`, `VIBE_LLM_KEY`, `VIBE_LLM_MODEL`, and `VIBE_TARGET_URL` in your CI pipeline.

**"No upstream tracking branch found"**
Set the upstream: `git push --set-upstream origin <branch>`.

**"Failed to parse LLM response as JSON"**
The model returned non-JSON output. Try a different model. The built-in fallback handles this for payload generation.

**"npm link" says "permission denied" (Linux/macOS)**
Use `sudo npm link` or configure a user-level global prefix.

**"VIBEGUARD_ENTRY is not defined" (Windows PowerShell hook)**
Re-run `vibeguard install` to regenerate hooks with the current path.

**Push blocked but I want to bypass**
`git push --no-verify` (not recommended — the vulnerabilities are real).
</details>

---

## License

MIT — see [package.json](package.json).
