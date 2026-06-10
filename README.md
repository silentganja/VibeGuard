# VibeGuard

**CLI-native adversarial local QA daemon** — intercepts `git push`, extracts diffs, and validates changes via custom LLMs before they leave your machine.

## Phase 1 · v0.1.0

Core infrastructure: configuration management, git pre-push hook installation, and structured diff extraction.

### Install

```bash
git clone https://github.com/silentganja/VibeGuard.git
cd VibeGuard
npm install
npm run build
npm link    # makes `vibeguard` available globally
```

### Usage

```bash
vibeguard init       # Create .vibeguard.json interactively
vibeguard install    # Install the git pre-push hook
vibeguard config     # Print current configuration
vibeguard uninstall  # Remove the hook
```

### Configuration (`.vibeguard.json`)

```json
{
  "llm_provider": "custom",
  "llm_api_endpoint": "http://localhost:11434/v1",
  "llm_api_key": "$LLM_API_KEY",
  "llm_model": "llama3:8b",
  "target_local_url": "http://localhost:8000",
  "exclude_paths": ["node_modules/**", "vendor/**", ".git/**", "dist/**"]
}
```

Supports `custom`, `openai`, and `anthropic` providers. API keys can be raw strings or `$ENV_VAR` references.

### Architecture

```
vibeguard init      →  .vibeguard.json (interactive wizard)
vibeguard install   →  .git/hooks/pre-push (bash + PowerShell)
vibeguard run       →  git diff @{u}...HEAD → structured diff → [Phase 2: LLM]
```

### What happens on `git push`

1. Hook captures local & remote branch names
2. Extracts the exact diff of changes about to be pushed (`git diff <upstream>...HEAD`)
3. Parses diff into structured memory footprint (files, hunks, additions, deletions)
4. Respects `exclude_paths` from config
5. **[Phase 2]** Sends diff to configured LLM for adversarial QA analysis
6. Pass (exit 0) or block (exit 1) the push

### Tech Stack

- **TypeScript** → compiled to Node.js
- **Zero runtime dependencies** — only devDependencies for the TypeScript compiler
- Cross-platform hooks (bash for Linux/macOS/Git Bash, PowerShell fallback for Windows)

### License

MIT
