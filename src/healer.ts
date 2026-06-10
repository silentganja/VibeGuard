/**
 * VibeGuard - Self-Healing Patch Engine
 *
 * When a local endpoint fails the security assertions in Phase 6, this module
 * isolates the vulnerable source file, transmits the exploit context to the
 * custom LLM API, receives a localized code fix, and generates a unified diff
 * patch for the developer to review.
 *
 * Design:
 *   - NEVER overwrites the developer's original source file automatically.
 *   - Outputs patch files to .vibeguard/patches/<filename>.patch.
 *   - Uses the SAME LLM API client pattern as Phase 2 (llm.ts) — callLLM()
 *     with a custom Hardened Systems Security Engineer system prompt.
 *   - Produces standard unified diff format for easy review and application.
 *   - Fail-safe: if the LLM is unreachable or returns invalid data, the
 *     patch generation fails gracefully and the pipeline continues.
 *
 * Zero runtime dependencies — uses only Node.js built-ins.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
  VibeGuardConfig,
  ExecutionResult,
  TargetTargets,
  TestReport,
  ExploitContext,
  RemediationResult,
  PatchResult,
} from "./types";
import { callLLM } from "./llm";
import * as ui from "./ui";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** Directory under .vibeguard/ where patch files are written. */
const PATCHES_DIR = ".vibeguard/patches";

/** Maximum source file size to read (chars, ~100KB). Larger files are skipped. */
const MAX_SOURCE_FILE_CHARS = 100_000;

/** Number of context lines in unified diff hunks. */
const DIFF_CONTEXT_LINES = 3;

// ─── Hardened Systems Security Engineer System Prompt ───────────────────────────

const REMEDIATION_SYSTEM_PROMPT = `You are a **Hardened Systems Security Engineer** — a principal-level application security expert specializing in code remediation. Your purpose is to analyze vulnerable code that failed a live adversarial security test, understand the exploit that broke through, and produce a surgically precise fix.

## Your Task

You will receive:
1. The **complete source code** of the file that failed a security test.
2. The **exploit context** — what payload was sent, what vulnerability was flagged, what response signature confirmed the breach.

You must:
1. Understand WHY the exploit succeeded by analyzing the vulnerable code path.
2. Produce a corrected version of the **ENTIRE source file** with the vulnerability patched.
3. Ensure the fix is minimal, correct, and follows security best practices.

## Remediation Guidelines by Vulnerability Type

### sql_injection
- Replace string concatenation / interpolation in SQL queries with **parameterized queries** (prepared statements).
- Never concatenate user input into SQL strings.
- If the language/framework has a query builder or ORM, use its parameter binding.
- For raw SQL, use positional (\`?\`) or named (\`:param\`) placeholders.

### auth_bypass / privilege_escalation
- Add proper **authorization checks** before sensitive operations.
- Verify session tokens, user roles, or ownership before returning data.
- Return HTTP 401/403 for unauthorized access — never silently return partial data.
- Validate that the authenticated user has permission for the specific resource being accessed.

### xss
- **Escape output** using context-appropriate encoding (HTML entities, JS encoding, URL encoding).
- Use framework-provided escaping functions (htmlspecialchars, html.EscapeString, escapeHtml, etc.).
- Apply Content-Security-Policy headers where appropriate.
- Never use innerHTML or dangerouslySetInnerHTML with user-controlled data.

### rce / command injection
- Avoid executing shell commands with user input. Use language-native APIs instead.
- If shell execution is unavoidable, use \`execFile\`/\`execve\` (argument arrays) instead of \`exec\`/\`system\` (string shells).
- Validate and sanitize all inputs with an allowlist approach.
- Escape shell metacharacters if you must use a shell.

### path_traversal
- Resolve and canonicalize all file paths before use.
- Restrict file access to an explicit base directory.
- Reject paths containing \`..\` or absolute paths.
- Use path.normalize() / realpath() and verify the result stays within the allowed root.

### ssrf
- Validate and restrict destination URLs against an allowlist.
- Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
- Disable redirect following or validate each redirect target.

### deserialization
- Never deserialize untrusted data with dangerous formats (pickle, unserialize, eval).
- Use safe serialization formats (JSON) with schema validation.
- If complex deserialization is required, use a sandboxed or capability-limited parser.

### general (input_fuzzing, misconfiguration, information_disclosure, other)
- Add input validation: type checks, length limits, format validation, range checks.
- Remove debug endpoints, stack traces, and verbose error messages from production responses.
- Enable security features that are currently disabled (CSRF protection, secure cookies, CORS restrictions).

## Rules

1. **Fix the root cause, not the symptom.** Do not just add a try/catch wrapper — fix the vulnerable pattern itself.
2. **Preserve functionality.** The code must still work correctly after the fix. Do not change behavior unless it is inherently insecure.
3. **Return the COMPLETE file.** Every line of the source file must be present in patched_code — unchanged lines included.
4. **Be surgical.** Change only the lines necessary to fix the vulnerability. Do not rewrite working code, do not reformat, do not reorganize imports unless the fix requires it.
5. **Comment your changes.** Add brief inline comments above changed lines explaining the security fix (e.g. "// FIX: Use parameterized query to prevent SQL injection").
6. **If you cannot determine a fix**, set remediation_applied to false and explain why. This is better than guessing.

## Output Format

Return ONLY a valid JSON object. No preamble, no markdown, no code fences.

{
  "remediation_applied": true,
  "vulnerability_type": "sql_injection",
  "explanation": "Short, precise description of why the code broke and how the fix resolves it.",
  "patched_code": "The complete, corrected contents of the source file with security patches applied."
}

If no fix can be determined:
{
  "remediation_applied": false,
  "vulnerability_type": "sql_injection",
  "explanation": "Could not determine a safe fix because the vulnerable code pattern was ambiguous or the source file was incomplete.",
  "patched_code": ""
}

Remember: you are the last line of defense before vulnerable code reaches production. Every fix you produce prevents a potential breach.`;

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Generate security patches for all vulnerable results in a test report.
 *
 * For each vulnerable ExecutionResult, this function:
 *   1. Cross-references the target URL against the target map to find the
 *      associated source file.
 *   2. Reads the source file from disk.
 *   3. Compiles the exploit context (payload + response + assertions).
 *   4. Calls the configured LLM with a Hardened Systems Security Engineer
 *      prompt requesting a patched version of the file.
 *   5. Generates a unified diff between the original and patched code.
 *   6. Writes the patch to .vibeguard/patches/<filename>.patch.
 *
 * Patches are NEVER applied automatically — they are written to disk for the
 * developer to review and apply manually.
 *
 * @param config      - Validated VibeGuard configuration (for LLM access).
 * @param testReport  - The Phase 6 test report containing vulnerable results.
 * @param targets     - The Phase 3 target map (for file → URL resolution).
 * @param projectRoot - Absolute path to the project root.
 * @returns An array of PatchResults, one per vulnerable test.
 */
export async function generateAllPatches(
  config: VibeGuardConfig,
  testReport: TestReport,
  targets: TargetTargets,
  projectRoot: string
): Promise<PatchResult[]> {
  // Find vulnerable results.
  const vulnerableResults = testReport.results.filter((r) => r.vulnerable);

  if (vulnerableResults.length === 0) {
    return [];
  }

  ui.action(
    "Generating security patches for " +
    String(vulnerableResults.length) + " vulnerable endpoint(s)..."
  );

  // Ensure the patches directory exists.
  const patchesDir = path.join(projectRoot, PATCHES_DIR);
  ensureDir(patchesDir);

  // Build a lookup from target URL → associated file path.
  const urlToFile = buildUrlToFileMap(targets);

  // Generate a patch for each vulnerable result.
  const results: PatchResult[] = [];
  for (const vr of vulnerableResults) {
    const patchResult = await generateOnePatch(config, vr, urlToFile, patchesDir);
    results.push(patchResult);
  }

  return results;
}

/**
 * Generate a patch for a single vulnerable execution result.
 */
async function generateOnePatch(
  config: VibeGuardConfig,
  vr: ExecutionResult,
  urlToFile: Map<string, string>,
  patchesDir: string
): Promise<PatchResult> {
  const targetUrl = vr.payload.target_url;

  // Find the associated source file.
  const sourceFile = urlToFile.get(targetUrl);
  if (!sourceFile) {
    return {
      success: false,
      patchPath: null,
      patchContent: null,
      vulnerabilityType: vr.payload.attack_type,
      explanation: null,
      error: "Could not find associated source file for target URL: " + targetUrl,
    };
  }

  // Read the source file.
  let sourceCode: string;
  try {
    sourceCode = fs.readFileSync(sourceFile, "utf-8");
  } catch {
    return {
      success: false,
      patchPath: null,
      patchContent: null,
      vulnerabilityType: vr.payload.attack_type,
      explanation: null,
      error: "Could not read source file: " + sourceFile,
    };
  }

  // Skip files that are too large.
  if (sourceCode.length > MAX_SOURCE_FILE_CHARS) {
    return {
      success: false,
      patchPath: null,
      patchContent: null,
      vulnerabilityType: vr.payload.attack_type,
      explanation: null,
      error: "Source file too large (" + String(sourceCode.length) + " chars, max " + String(MAX_SOURCE_FILE_CHARS) + "): " + sourceFile,
    };
  }

  // Build the exploit context.
  const context = buildExploitContext(vr, sourceFile, sourceCode);

  // Call the LLM for remediation.
  let remediation: RemediationResult;
  try {
    remediation = await callLLMForRemediation(config, context);
  } catch (err: unknown) {
    return {
      success: false,
      patchPath: null,
      patchContent: null,
      vulnerabilityType: vr.payload.attack_type,
      explanation: null,
      error: "LLM remediation call failed: " + ((err as Error).message ?? String(err)),
    };
  }

  if (!remediation.remediation_applied || !remediation.patched_code) {
    return {
      success: false,
      patchPath: null,
      patchContent: null,
      vulnerabilityType: remediation.vulnerability_type || vr.payload.attack_type,
      explanation: remediation.explanation || null,
      error: "LLM could not determine a fix: " + (remediation.explanation || "No explanation provided."),
    };
  }

  // Generate the unified diff.
  const patchContent = generateUnifiedDiff(
    sourceCode,
    remediation.patched_code,
    sourceFile
  );

  if (!patchContent) {
    return {
      success: false,
      patchPath: null,
      patchContent: null,
      vulnerabilityType: remediation.vulnerability_type,
      explanation: remediation.explanation,
      error: "Generated patched code is identical to original — no changes to apply.",
    };
  }

  // Write the patch file.
  const patchFileName = sourceFile.replace(/[/\\:]/g, "_") + ".patch";
  const patchPath = path.join(patchesDir, patchFileName);

  try {
    fs.writeFileSync(patchPath, patchContent, "utf-8");
  } catch (err: unknown) {
    return {
      success: false,
      patchPath: null,
      patchContent,
      vulnerabilityType: remediation.vulnerability_type,
      explanation: remediation.explanation,
      error: "Failed to write patch file: " + ((err as Error).message ?? String(err)),
    };
  }

  return {
    success: true,
    patchPath: path.relative(process.cwd(), patchPath),
    patchContent,
    vulnerabilityType: remediation.vulnerability_type,
    explanation: remediation.explanation,
    error: null,
  };
}

// ─── Exploit Context Builder ────────────────────────────────────────────────────

/**
 * Compile the exploit context for a single vulnerable test.
 *
 * Extracts the parameters of a failed test:
 *   - The relative file path of the source file.
 *   - The raw code contents of that file.
 *   - The specific payload data used in the successful attack.
 *   - The response signature or exception that triggered the failure.
 */
function buildExploitContext(
  vr: ExecutionResult,
  sourceFile: string,
  sourceCode: string
): ExploitContext {
  // Extract the first triggered assertion for context.
  const triggeredAssertion = vr.assertions.find((a) => a.triggered);

  // Build a response signature from the triggered assertion + response body excerpt.
  let responseSignature = "";
  if (triggeredAssertion) {
    responseSignature = "[" + triggeredAssertion.category + "] " + triggeredAssertion.detail;
    if (triggeredAssertion.matched_signature) {
      responseSignature += "\nMatched signature: " + triggeredAssertion.matched_signature;
    }
  }

  // Append a snippet of the response body if available.
  if (vr.responseBody && vr.responseBody.length > 0) {
    const bodyExcerpt = vr.responseBody.slice(0, 500);
    responseSignature += "\n\nResponse body excerpt:\n" + bodyExcerpt;
  }

  if (vr.statusCode !== null) {
    responseSignature += "\n\nHTTP Status: " + String(vr.statusCode);
  }

  return {
    source_file: sourceFile,
    source_code: sourceCode,
    payload_data: vr.payload.payload_data,
    attack_type: vr.payload.attack_type,
    response_signature: responseSignature,
    target_url: vr.payload.target_url,
    http_method: vr.payload.method,
    assertion_category: triggeredAssertion?.category ?? "none",
    assertion_detail: triggeredAssertion?.detail ?? "No assertion detail available.",
  };
}

// ─── LLM Remediation Call ───────────────────────────────────────────────────────

/**
 * Call the configured LLM with a remediation prompt.
 *
 * Uses the same callLLM() function as Phase 2 but with the Hardened Systems
 * Security Engineer system prompt and a context-rich user message.
 */
async function callLLMForRemediation(
  config: VibeGuardConfig,
  context: ExploitContext
): Promise<RemediationResult> {
  const userMessage = buildRemediationUserMessage(context);

  ui.action(
    "Requesting patch from " + config.llm_model + " for " +
    context.source_file + " (" + context.attack_type + ")..."
  );

  const rawResponse = await callLLM(config, userMessage, REMEDIATION_SYSTEM_PROMPT);

  return parseRemediationResponse(rawResponse);
}

/**
 * Build the user message containing the source code and exploit context.
 */
function buildRemediationUserMessage(context: ExploitContext): string {
  const lines: string[] = [];

  lines.push("## Vulnerability Report");
  lines.push("");
  lines.push("### Source File");
  lines.push("`" + context.source_file + "`");
  lines.push("");
  lines.push("### Attack Type");
  lines.push(context.attack_type);
  lines.push("");
  lines.push("### HTTP Method & Target");
  lines.push(context.http_method + " " + context.target_url);
  lines.push("");
  lines.push("### Payload Data");
  for (const [key, value] of Object.entries(context.payload_data)) {
    const truncated = value.length > 200 ? value.slice(0, 197) + "..." : value;
    lines.push("- " + key + ": " + truncated);
  }
  lines.push("");
  lines.push("### Response Signature (why the test failed)");
  lines.push(context.assertion_detail);
  lines.push("");
  lines.push("### Full Response Context");
  lines.push(context.response_signature);
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Source Code to Patch");
  lines.push("");
  lines.push("Below is the COMPLETE source code of `" + context.source_file + "`. Analyze it, find the vulnerability, and return the fully patched version.");
  lines.push("");
  lines.push("```");
  lines.push(context.source_code);
  lines.push("```");
  lines.push("");
  lines.push("Return the JSON remediation now. Remember: no preamble, no markdown fences — pure JSON only.");

  return lines.join("\n");
}

// ─── Remediation Response Parser ────────────────────────────────────────────────

/**
 * Parse the LLM's JSON remediation response.
 *
 * Uses the same robust parsing logic as llm.ts — handles markdown-fenced JSON,
 * bare JSON, and JSON with surrounding text.
 */
function parseRemediationResponse(raw: string): RemediationResult {
  let jsonStr = raw.trim();

  // Strip markdown code fences.
  const fenceMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) {
    jsonStr = fenceMatch[1].trim();
  }

  // If the response has text before or after the JSON object, extract just the
  // outermost brace pair.
  if (!jsonStr.startsWith("{")) {
    const firstBrace = jsonStr.indexOf("{");
    if (firstBrace !== -1) {
      const lastBrace = jsonStr.lastIndexOf("}");
      if (lastBrace > firstBrace) {
        jsonStr = jsonStr.slice(firstBrace, lastBrace + 1);
      }
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error(
      "Failed to parse remediation response as JSON. Raw response:\n" +
      raw.slice(0, 500)
    );
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Remediation response is not a JSON object.");
  }

  const obj = parsed as Record<string, unknown>;

  return {
    remediation_applied: Boolean(obj.remediation_applied),
    vulnerability_type: String(obj.vulnerability_type ?? "unknown"),
    explanation: String(obj.explanation ?? "No explanation provided."),
    patched_code: String(obj.patched_code ?? ""),
  };
}

// ─── Unified Diff Generator ─────────────────────────────────────────────────────

/**
 * Generate a standard unified diff between the original and patched code.
 *
 * Implements LCS (Longest Common Subsequence) based diffing with context
 * grouping. Output format:
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
function generateUnifiedDiff(
  original: string,
  patched: string,
  filePath: string
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
  const hunks = groupIntoHunks(edits, DIFF_CONTEXT_LINES);

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

// ─── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Build a lookup map from resolved URL to associated file path.
 *
 * This allows us to find which source file a vulnerable payload target
 * corresponds to.
 */
function buildUrlToFileMap(targets: TargetTargets): Map<string, string> {
  const map = new Map<string, string>();

  for (const test of targets.executable_tests) {
    // Normalize the URL for matching: strip trailing slashes, lowercase.
    const normalizedUrl = test.resolved_url.replace(/\/+$/, "").toLowerCase();

    if (!map.has(normalizedUrl)) {
      map.set(normalizedUrl, test.associated_file);
    }

    // Also store the non-normalized version for exact matching.
    if (!map.has(test.resolved_url)) {
      map.set(test.resolved_url, test.associated_file);
    }
  }

  return map;
}

/**
 * Ensure a directory exists, creating it if necessary.
 */
function ensureDir(dir: string): void {
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch {
    // Directory already exists or cannot be created — ignore.
  }
}

/**
 * Format a PatchResult for terminal display.
 */
export function formatPatchResult(result: PatchResult): string {
  if (result.success) {
    return (
      "✓ Patch generated: " + (result.patchPath ?? "unknown") +
      " (" + (result.vulnerabilityType ?? "unknown") + ")" +
      "\n  " + (result.explanation ?? "No explanation provided.")
    );
  }

  return (
    "✕ Patch failed: " + (result.vulnerabilityType ?? "unknown") +
    "\n  Error: " + (result.error ?? "Unknown error")
  );
}

/**
 * Format a summary of all patch results for the final verdict display.
 */
export function formatPatchSummary(results: PatchResult[]): string {
  if (results.length === 0) {
    return "";
  }

  const succeeded = results.filter((r) => r.success);
  const failed = results.filter((r) => !r.success);

  const lines: string[] = [];
  lines.push("");

  if (succeeded.length > 0) {
    lines.push(
      "Patches generated: " + String(succeeded.length) + " file(s)"
    );
    for (const r of succeeded) {
      lines.push("  ✓ " + (r.patchPath ?? "unknown"));
      lines.push("    Type: " + (r.vulnerabilityType ?? "unknown"));
      if (r.explanation) {
        lines.push("    " + r.explanation.slice(0, 150));
      }
    }
  }

  if (failed.length > 0) {
    lines.push(
      "Patches NOT generated: " + String(failed.length) + " file(s)"
    );
    for (const r of failed) {
      lines.push("  ✕ " + (r.vulnerabilityType ?? "unknown") + " — " + (r.error ?? "Unknown error"));
    }
  }

  if (succeeded.length > 0) {
    lines.push("");
    lines.push("To apply a patch:  git apply .vibeguard/patches/<file>.patch");
    lines.push("To review a patch: cat .vibeguard/patches/<file>.patch");
  }

  return lines.join("\n");
}
