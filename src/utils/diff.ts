/**
 * VibeGuard — Unified Diff Generator
 *
 * LCS (Longest Common Subsequence) based diffing algorithm extracted from the
 * Phase 7 Self-Healing Patch Engine. Produces standard unified diff format
 * patches for developer review.
 *
 * Zero runtime dependencies — pure algorithmic implementation.
 */

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Generate a standard unified diff between original and patched code.
 *
 * Implements LCS-based diffing with context grouping. Output format:
 *
 *   --- a/path/to/file
 *   +++ b/path/to/file
 *   @@ -oldStart,oldCount +newStart,newCount @@
 *    context line
 *   -removed line
 *   +added line
 *    context line
 *
 * Returns null if the original and patched code are identical.
 */
export function generateUnifiedDiff(
  original: string,
  patched: string,
  filePath: string,
  contextLines: number = 3
): string | null {
  // Normalize line endings.
  const origLines = original.replace(/\r\n/g, "\n").split("\n");
  const patchLines = patched.replace(/\r\n/g, "\n").split("\n");

  // Quick check: are they identical?
  if (origLines.length === patchLines.length &&
      origLines.every((l, i) => l === patchLines[i])) {
    return null;
  }

  // Compute the edit script using LCS.
  const dp = computeLCS(origLines, patchLines);
  const edits = backtrackEdits(origLines, patchLines, dp);

  // Group edits into hunks with context.
  const hunks = groupIntoHunks(edits, contextLines);

  // Format the unified diff.
  const output: string[] = [];
  output.push("--- a/" + filePath.replace(/\\/g, "/"));
  output.push("+++ b/" + filePath.replace(/\\/g, "/"));

  for (const hunk of hunks) {
    output.push(
      "@@ -" + String(hunk.oldStart) + "," + String(hunk.oldCount) +
      " +" + String(hunk.newStart) + "," + String(hunk.newCount) + " @@"
    );

    for (const line of hunk.lines) {
      output.push(line);
    }
  }

  return output.join("\n") + "\n";
}

// ─── LCS Diff Algorithm ─────────────────────────────────────────────────────────

/**
 * Compute the Longest Common Subsequence table for two line arrays.
 *
 * dp[i][j] = length of LCS of a[0..i-1] and b[0..j-1].
 */
function computeLCS(a: string[], b: string[]): number[][] {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from(
    { length: m + 1 },
    () => new Array(n + 1).fill(0)
  );

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  return dp;
}

/** A single edit operation in the diff. */
interface EditOp {
  type: "keep" | "insert" | "delete";
  line: string;
  oldLine?: number;  // 1-based line number in original
  newLine?: number;  // 1-based line number in patched
}

/**
 * Backtrack through the LCS table to produce an edit script.
 *
 * The edit script describes how to transform the original file into the
 * patched file through a sequence of keep/insert/delete operations.
 */
function backtrackEdits(a: string[], b: string[], dp: number[][]): EditOp[] {
  const edits: EditOp[] = [];
  let i = a.length;
  let j = b.length;

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      edits.unshift({ type: "keep", line: a[i - 1], oldLine: i, newLine: j });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      edits.unshift({ type: "insert", line: b[j - 1], newLine: j });
      j--;
    } else if (i > 0) {
      edits.unshift({ type: "delete", line: a[i - 1], oldLine: i });
      i--;
    }
  }

  return edits;
}

// ─── Hunk Grouper ───────────────────────────────────────────────────────────────

/** A single unified diff hunk. */
interface DiffHunk {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: string[];
}

/**
 * Group a flat edit script into unified diff hunks with context.
 *
 * Each hunk includes `contextLines` unchanged lines before and after the
 * changed region. Adjacent hunks that overlap in their context are merged.
 */
function groupIntoHunks(edits: EditOp[], contextLines: number): DiffHunk[] {
  // Find changed regions (runs of insert/delete operations).
  const changedIndices: number[] = [];
  for (let i = 0; i < edits.length; i++) {
    if (edits[i].type !== "keep") {
      changedIndices.push(i);
    }
  }

  if (changedIndices.length === 0) {
    return [];
  }

  // Expand each changed index to include context.
  const included = new Set<number>();
  for (const idx of changedIndices) {
    // Include context before.
    for (let c = idx - contextLines; c <= idx + contextLines; c++) {
      if (c >= 0 && c < edits.length) {
        included.add(c);
      }
    }
  }

  // Sort the included indices and split into contiguous runs.
  const sorted = [...included].sort((a, b) => a - b);

  const runs: number[][] = [];
  let currentRun: number[] = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] === sorted[i - 1] + 1) {
      currentRun.push(sorted[i]);
    } else {
      runs.push(currentRun);
      currentRun = [sorted[i]];
    }
  }
  runs.push(currentRun);

  // Convert each run into a DiffHunk.
  const hunks: DiffHunk[] = [];
  for (const run of runs) {
    const hunkEdits = run.map((idx) => edits[idx]);

    // Compute the range line numbers for the hunk header.
    let oldStart = Infinity;
    let oldCount = 0;
    let newStart = Infinity;
    let newCount = 0;

    const hunkLines: string[] = [];

    for (const edit of hunkEdits) {
      switch (edit.type) {
        case "keep": {
          hunkLines.push(" " + edit.line);
          if (edit.oldLine && edit.oldLine < oldStart) oldStart = edit.oldLine;
          if (edit.newLine && edit.newLine < newStart) newStart = edit.newLine;
          oldCount++;
          newCount++;
          break;
        }
        case "delete": {
          hunkLines.push("-" + edit.line);
          if (edit.oldLine && edit.oldLine < oldStart) oldStart = edit.oldLine;
          oldCount++;
          break;
        }
        case "insert": {
          hunkLines.push("+" + edit.line);
          if (edit.newLine && edit.newLine < newStart) newStart = edit.newLine;
          newCount++;
          break;
        }
      }
    }

    // If no keep lines in the hunk, oldStart/newStart may be Infinity.
    // Use the first delete's oldLine or first insert's newLine.
    if (oldStart === Infinity) {
      for (const edit of hunkEdits) {
        if (edit.type === "delete" && edit.oldLine) {
          oldStart = edit.oldLine;
          break;
        }
      }
      // If only inserts, use the line before the hunk in the original.
      if (oldStart === Infinity) {
        const firstEdit = hunkEdits[0];
        if (firstEdit.newLine) {
          oldStart = firstEdit.newLine; // approximate
        } else {
          oldStart = 1;
        }
      }
    }

    if (newStart === Infinity) {
      for (const edit of hunkEdits) {
        if (edit.type === "insert" && edit.newLine) {
          newStart = edit.newLine;
          break;
        }
      }
      if (newStart === Infinity) {
        const firstEdit = hunkEdits[0];
        if (firstEdit.oldLine) {
          newStart = firstEdit.oldLine;
        } else {
          newStart = 1;
        }
      }
    }

    // oldCount should be at least 1 for the header to make sense.
    if (oldCount === 0) oldCount = 1;
    if (newCount === 0) newCount = 1;

    hunks.push({
      oldStart,
      oldCount,
      newStart,
      newCount,
      lines: hunkLines,
    });
  }

  return hunks;
}
