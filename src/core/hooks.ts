/**
 * VibeGuard â€” Git Hook Installer
 *
 * Writes a native `.git/hooks/pre-push` script into the target repository.
 * The script is a bash script that:
 *   1. Reads pushed refs from stdin (git pre-push protocol).
 *   2. Invokes `vibeguard run` for each ref.
 *   3. Aborts the push if vibeguard exits non-zero.
 *
 * Cross-platform: the bash script runs natively on Linux/macOS and inside
 * Git Bash on Windows. On Windows without Git Bash, we also write a
 * PowerShell wrapper.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { findProjectRoot } from "./config";
import { isHeadless, detectCIPlatform } from "../compliance/ci";
import * as ui from "../cli/ui";
import { ensureCacheGitignored } from "../utils/cache";

// â”€â”€â”€ Hook Script (Bash) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Generates the bash pre-push hook content.
 * Uses `node` with an absolute path to vibeguard for zero-config reliability.
 */
function generateBashHook(vibeguardEntry: string): string {
  return `#!/usr/bin/env bash
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  VibeGuard Â· Pre-Push Hook
#  Installed by: vibeguard install
#  DO NOT EDIT MANUALLY â€” run \`vibeguard install\` to regenerate.
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
set -euo pipefail

VIBEGUARD="${vibeguardEntry}"

# â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo ""
echo -e "\\x1b[2mâ•­â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•®\\x1b[0m"
echo -e "\\x1b[2mâ”‚\\x1b[0m  \\x1b[97mVibeGuard\\x1b[0m Â· Pre-Push Analysis           \\x1b[2mâ”‚\\x1b[0m"
echo -e "\\x1b[2mâ•°â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•¯\\x1b[0m"
echo ""

FAILED=0

# â”€â”€ Process each pushed ref â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
while read -r local_ref local_sha remote_ref remote_sha; do
  local_branch=\$(echo "\$local_ref" | sed 's|refs/heads/||')
  remote_branch=\$(echo "\$remote_ref" | sed 's|refs/heads/||')

  echo -e "\\x1b[90mâ†’\\x1b[0m  \\x1b[97m\$local_branch\\x1b[0m \\x1b[90mâ†’\\x1b[0m \\x1b[97m\$remote_branch\\x1b[0m"

  node "\$VIBEGUARD" run \\
    --local "\$local_branch" \\
    --remote "\$remote_branch" \\
    --sha "\$local_sha"

  if [ \$? -ne 0 ]; then
    FAILED=1
  fi
done

# â”€â”€ Result â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo ""
if [ \$FAILED -eq 0 ]; then
  echo -e "\\x1b[32mâœ“  VibeGuard analysis passed\\x1b[0m"
  exit 0
else
  echo -e "\\x1b[31mâœ•  Push aborted â€” VibeGuard analysis failed\\x1b[0m"
  exit 1
fi
`;
}

// â”€â”€â”€ Hook Script (PowerShell) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Generates a PowerShell pre-push hook for Windows-native git installations.
 *
 * Git for Windows looks for `pre-push` (no extension) first and executes it
 * via bash if present. If bash is unavailable, we also write `pre-push.ps1`
 * as a fallback that users can configure manually via `git config core.hooksPath`.
 */
function generatePowerShellHook(vibeguardEntry: string): string {
  // Build via array join to avoid backtick collision between PowerShell's
  // escape character (`e) and JavaScript's template literal delimiter.
  const e = "`e"; // PowerShell ANSI escape prefix

  return [
    "# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
    "#  VibeGuard Â· Pre-Push Hook (PowerShell)",
    "#  Installed by: vibeguard install",
    "#  DO NOT EDIT MANUALLY â€” run `vibeguard install` to regenerate.",
    "# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
    "",
    '$ErrorActionPreference = "Stop"',
    "",
    'Write-Host ""',
    `Write-Host ("${e}[2mâ•­â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•®${e}[0m")`,
    `Write-Host ("${e}[2mâ”‚${e}[0m  ${e}[97mVibeGuard${e}[0m Â· Pre-Push Analysis           ${e}[2mâ”‚${e}[0m")`,
    `Write-Host ("${e}[2mâ•°â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•¯${e}[0m")`,
    'Write-Host ""',
    "",
    '$failed = $false',
    "",
    "# Read push refs from stdin (git passes them as lines)",
    "$input | ForEach-Object {",
    "  $parts = $_ -split ' '",
    "  if ($parts.Length -ge 4) {",
    "    $localRef = $parts[0]",
    "    $localSha = $parts[1]",
    "    $remoteRef = $parts[2]",
    "    $remoteSha = $parts[3]",
    "",
    "    $localBranch = $localRef -replace 'refs/heads/', ''",
    "    $remoteBranch = $remoteRef -replace 'refs/heads/', ''",
    "",
    `    Write-Host ("${e}[90mâ†’${e}[0m  ${e}[97m$localBranch${e}[0m ${e}[90mâ†’${e}[0m ${e}[97m$remoteBranch${e}[0m")`,
    "",
    '    $result = & node "$env:VIBEGUARD_ENTRY" run --local $localBranch --remote $remoteBranch --sha $localSha 2>&1',
    "    if ($LASTEXITCODE -ne 0) {",
    "      Write-Host $result",
    "      $failed = $true",
    "    }",
    "  }",
    "}",
    "",
    'Write-Host ""',
    "if (-not $failed) {",
    `  Write-Host ("${e}[32mâœ“  VibeGuard analysis passed${e}[0m")`,
    "  exit 0",
    "} else {",
    `  Write-Host ("${e}[31mâœ•  Push aborted â€” VibeGuard analysis failed${e}[0m")`,
    "  exit 1",
    "}",
    "",
  ].join("\n");
}

// â”€â”€â”€ Installer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Install the pre-push hook into the target project's `.git/hooks/` directory.
 *
 * Strategy:
 *   1. Locate the project root via .git discovery.
 *   2. Write the bash hook as `.git/hooks/pre-push`.
 *   3. On non-Windows: `chmod +x` the hook.
 *   4. On Windows: also write `pre-push.ps1` as a PowerShell fallback.
 */
export function installHook(): void {
  // In headless CI/CD environments, skip hook installation gracefully.
  // Git hooks are a local development feature â€” they have no meaning in
  // ephemeral CI build containers where .git may not even exist.
  if (isHeadless()) {
    const platform = detectCIPlatform() ?? "headless environment";
    ui.muted("Skipping hook installation â€” running in " + platform + ".");
    ui.muted("VibeGuard is invoked directly via `vibeguard run` in CI pipelines.");
    return;
  }

  const projectRoot = findProjectRoot();
  if (!projectRoot) {
    ui.fail("No .git directory found. Are you inside a git repository?");
    process.exit(1);
  }

  const hooksDir = path.join(projectRoot, ".git", "hooks");

  // Ensure hooks directory exists (it should, but be defensive).
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
    ui.muted(`Created ${hooksDir}`);
  }

  // Resolve the path to the compiled CLI entry point.
  // When running via `node dist/cli.js`, this is the absolute path to cli.js.
  const vibeguardEntry = process.argv[1];
  // On Windows, normalize backslashes to forward slashes for bash compatibility.
  const normalizedEntry = vibeguardEntry.replace(/\\/g, "/");

  // â”€â”€ Bash hook â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const bashHookPath = path.join(hooksDir, "pre-push");
  const bashContent = generateBashHook(normalizedEntry);

  // Back up existing hook if present and it's not ours.
  if (fs.existsSync(bashHookPath)) {
    const existing = fs.readFileSync(bashHookPath, "utf-8");
    if (!existing.includes("VibeGuard")) {
      const backupPath = bashHookPath + ".vibeguard.bak";
      fs.writeFileSync(backupPath, existing, { mode: 0o755 });
      ui.warn(`Existing hook backed up â†’ ${backupPath}`);
    }
  }

  fs.writeFileSync(bashHookPath, bashContent, { mode: 0o755 });
  ui.ok(`Hook installed â†’ ${bashHookPath}`);

  // On Unix, ensure executable bit is set.
  if (os.platform() !== "win32") {
    try {
      fs.chmodSync(bashHookPath, 0o755);
    } catch {
      // Some filesystems don't support chmod; the mode in writeFileSync should
      // have handled it, but we try chmod as a fallback.
    }
  }

  // â”€â”€ PowerShell fallback (Windows) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (os.platform() === "win32") {
    const psHookPath = path.join(hooksDir, "pre-push.ps1");
    const psContent = generatePowerShellHook(normalizedEntry);
    fs.writeFileSync(psHookPath, psContent, { mode: 0o644 });
    ui.muted(`PowerShell fallback â†’ ${psHookPath}`);
    ui.muted("(The bash hook runs automatically via Git Bash.)");
  }


  // Phase 12: Ensure LLM response cache directory is never committed.
  ensureCacheGitignored(projectRoot);

  // â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  ui.space();
  ui.header("Hook Behavior");
  ui.muted("On every `git push`, the pre-push hook will:");
  ui.muted("  1. Capture the local & remote branch names.");
  ui.muted("  2. Extract the diff of changes about to be pushed.");
  ui.muted("  3. [Phase 2] Send the diff to your configured LLM for analysis.");
  ui.muted("  4. Pass (exit 0) or block (exit 1) the push based on the result.");
  ui.space();
  ui.muted("To remove the hook, delete .git/hooks/pre-push manually.");
}

// â”€â”€â”€ Uninstaller â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Remove the VibeGuard pre-push hook. Restore backup if one exists. */
export function uninstallHook(): void {
  // In headless CI/CD environments, there are no hooks to uninstall.
  if (isHeadless()) {
    ui.muted("Hook uninstall skipped â€” running in headless/CI environment.");
    return;
  }

  const projectRoot = findProjectRoot();
  if (!projectRoot) {
    ui.fail("No .git directory found.");
    process.exit(1);
  }

  const hooksDir = path.join(projectRoot, ".git", "hooks");
  const bashHookPath = path.join(hooksDir, "pre-push");
  const backupPath = bashHookPath + ".vibeguard.bak";
  const psHookPath = path.join(hooksDir, "pre-push.ps1");

  if (!fs.existsSync(bashHookPath)) {
    ui.muted("No VibeGuard hook found. Nothing to uninstall.");
    return;
  }

  // Verify it's our hook before removing.
  const existing = fs.readFileSync(bashHookPath, "utf-8");
  if (!existing.includes("VibeGuard")) {
    ui.warn("The pre-push hook was not installed by VibeGuard. Remove it manually.");
    return;
  }

  // Remove our hook.
  fs.unlinkSync(bashHookPath);

  // Restore backup if it exists.
  if (fs.existsSync(backupPath)) {
    fs.renameSync(backupPath, bashHookPath);
    ui.ok("Restored previous hook from backup.");
  } else {
    ui.ok("Hook removed.");
  }

  // Remove PowerShell fallback.
  if (fs.existsSync(psHookPath)) {
    const psContent = fs.readFileSync(psHookPath, "utf-8");
    if (psContent.includes("VibeGuard")) {
      fs.unlinkSync(psHookPath);
    }
  }
}
