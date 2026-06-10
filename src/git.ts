/**
 * VibeGuard — Git Diff Extractor
 *
 * Core engine that runs when the pre-push hook fires. Extracts the exact
 * code changes about to be pushed and parses them into a structured memory
 * footprint ready for LLM consumption (Phase 2).
 *
 * Operations:
 *   · Resolves the remote tracking branch for the current local branch.
 *   · Runs `git diff <remote>...HEAD` to get the changes being pushed.
 *   · Parses the unified diff into structured DiffFile / DiffHunk / DiffLine objects.
 *   · Respects `.vibeguard.json` exclude_paths.
 */

import { execSync } from "node:child_process";
import type { DiffResult, DiffFile, DiffHunk, DiffLine, FileStatus } from "./types";
import { readConfig } from "./config";

// ─── Low-level Git Commands ──────────────────────────────────────────────────

/**
 * Run a git command and return trimmed stdout.
 * Throws if the command fails.
 */
function git(args: string[], cwd?: string): string {
  try {
    const result = execSync(`git ${args.join(" ")}`, {
      cwd: cwd ?? process.cwd(),
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 50 * 1024 * 1024, // 50 MB — generous for large diffs
    });
    return result.trim();
  } catch (err: unknown) {
    const stderr = (err as { stderr?: string }).stderr ?? "";
    throw new Error(`git ${args[0]} failed: ${stderr}`);
  }
}

/**
 * Get the remote tracking branch for the given local branch.
 * Example: "main" → "origin/main"
 * Returns null if no upstream is configured.
 */
function getUpstream(localBranch: string): string | null {
  try {
    const upstream = git(["rev-parse", "--abbrev-ref", `${localBranch}@{u}`]);
    return upstream || null;
  } catch {
    // No upstream configured — fall back to origin/<branch>
    return `origin/${localBranch}`;
  }
}

/**
 * Run the diff between the remote tracking branch and HEAD.
 *
 * Uses the three-dot syntax `<remote>...HEAD` which shows changes on the
 * local branch since it diverged from the remote — this is exactly the set
 * of changes about to be pushed, excluding anything already on the remote.
 */
function runDiff(upstream: string, excludePaths: string[]): string {
  const args = ["diff", "--unified=3", `${upstream}...HEAD`];

  // Add exclusions
  for (const p of excludePaths) {
    args.push(`--`, `:!${p}`);
  }

  // Use `-- .` to scope to the working tree, then exclusions filter it.
  args.push("--", ".");

  return git(args);
}

// ─── Diff Parser ─────────────────────────────────────────────────────────────

/**
 * Parse a unified diff string into a structured DiffResult.
 *
 * Handles:
 *   · File headers: diff --git a/X b/Y
 *   · Extended headers: new file mode, deleted file mode, rename from/to
 *   · Hunks: @@ -oldStart,oldCount +newStart,newCount @@ context
 *   · Lines: +additions, -deletions, context
 */
function parseDiff(raw: string): DiffResult {
  const files: DiffFile[] = [];
  let totalAdditions = 0;
  let totalDeletions = 0;

  const lines = raw.split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Match file header: "diff --git a/<path> b/<path>"
    const fileMatch = line.match(/^diff --git a\/(.*?) b\/(.*?)$/);
    if (fileMatch) {
      const aPath = fileMatch[1];
      const bPath = fileMatch[2];

      // Determine file status and path from extended headers
      let status: FileStatus = "modified";
      let displayPath = bPath;
      let oldPath: string | undefined;

      // Peek ahead for extended headers
      i++;
      while (i < lines.length) {
        const next = lines[i];

        if (next.startsWith("new file mode")) {
          status = "added";
          i++;
          continue;
        }
        if (next.startsWith("deleted file mode")) {
          status = "deleted";
          displayPath = aPath;
          i++;
          continue;
        }
        if (next.startsWith("rename from ")) {
          status = "renamed";
          oldPath = next.replace("rename from ", "").trim();
          i++;
          continue;
        }
        if (next.startsWith("rename to ")) {
          displayPath = next.replace("rename to ", "").trim();
          i++;
          continue;
        }
        // Stop at the first hunk header or next file header
        if (next.startsWith("@@") || next.startsWith("diff --git")) {
          break;
        }
        i++; // skip other extended headers (index, similarity, etc.)
      }

      // Parse hunks
      const hunks: DiffHunk[] = [];
      let additions = 0;
      let deletions = 0;

      while (i < lines.length && !lines[i].startsWith("diff --git")) {
        const hunkLine = lines[i];

        // Hunk header: "@@ -oldStart,oldCount +newStart,newCount @@ context"
        const hunkMatch = hunkLine.match(
          /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$/
        );
        if (hunkMatch) {
          const oldStart = parseInt(hunkMatch[1], 10);
          const newStart = parseInt(hunkMatch[3], 10);
          const context = hunkMatch[5].trim();

          const hunk: DiffHunk = {
            header: hunkLine,
            lines: [],
          };

          let oldLineNum = oldStart;
          let newLineNum = newStart;

          i++;
          while (i < lines.length) {
            const dl = lines[i];

            // Stop when we hit the next hunk or file
            if (dl.startsWith("@@") || dl.startsWith("diff --git")) {
              break;
            }

            if (dl.startsWith("+")) {
              hunk.lines.push({
                type: "add",
                content: dl.slice(1),
                newLineNumber: newLineNum,
              });
              additions++;
              newLineNum++;
            } else if (dl.startsWith("-")) {
              hunk.lines.push({
                type: "delete",
                content: dl.slice(1),
                oldLineNumber: oldLineNum,
              });
              deletions++;
              oldLineNum++;
            } else {
              // Context line (starts with space or is empty)
              const content = dl.startsWith(" ") ? dl.slice(1) : dl;
              hunk.lines.push({
                type: "context",
                content,
                oldLineNumber: oldLineNum,
                newLineNumber: newLineNum,
              });
              oldLineNum++;
              newLineNum++;
            }
            i++;
          }

          hunks.push(hunk);
        } else {
          i++;
        }
      }

      totalAdditions += additions;
      totalDeletions += deletions;

      files.push({
        path: displayPath,
        status,
        oldPath,
        additions,
        deletions,
        hunks,
      });

      // `i` now points to the next "diff --git" line or EOF
      continue;
    }

    i++;
  }

  return {
    files,
    totalAdditions,
    totalDeletions,
    rawDiff: raw,
  };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Extract the full structured diff for a branch about to be pushed.
 *
 * @param localBranch  — the local branch name (e.g. "feature/login")
 * @param excludePaths — optional override for exclude_paths from config
 */
export function extractDiff(
  localBranch: string,
  excludePaths?: string[]
): DiffResult {
  const config = readConfig();
  const excludes = excludePaths ?? config.exclude_paths;

  const upstream = getUpstream(localBranch);
  if (!upstream) {
    throw new Error(
      `No upstream tracking branch found for "${localBranch}". ` +
      `Set one with: git push --set-upstream origin ${localBranch}`
    );
  }

  const raw = runDiff(upstream, excludes);

  if (!raw) {
    // No diff — nothing to push (or identical to remote)
    return {
      files: [],
      totalAdditions: 0,
      totalDeletions: 0,
      rawDiff: "",
    };
  }

  return parseDiff(raw);
}

/**
 * Get the list of changed file paths only (lightweight check).
 * Faster than full diff parsing when you just need the file list.
 */
export function getChangedFiles(localBranch: string): string[] {
  const upstream = getUpstream(localBranch);
  if (!upstream) return [];

  try {
    const raw = git(["diff", "--name-only", `${upstream}...HEAD`]);
    return raw ? raw.split("\n").filter(Boolean) : [];
  } catch {
    return [];
  }
}
