/**
 * VibeGuard - Diff Noise Filter & Token Optimizer
 *
 * Takes the raw structured diff from Phase 1 (git.ts) and applies deterministic
 * noise filtering to produce a token-optimized payload suitable for LLM
 * consumption. All filtering is local - the LLM never sees CSS, docs, or
 * whitespace-only changes.
 *
 * Pipeline:
 *   1. File extension whitelisting - discard styling, docs, assets, lockfiles.
 *   2. Line-level cleaning - strip comments, doc blocks, whitespace noise.
 *   3. Hunk context extraction - infer surrounding function/endpoint from @@ headers.
 *   4. Token estimation - rough character-based heuristic for payload sizing.
 */

import type {
  DiffResult,
  DiffFile,
  DiffHunk,
  FileStatus,
  FilteredDiff,
  FilteredFile,
  FilteredHunk,
  FilteredLine,
} from "./types";

// ─── File Extension Whitelist ──────────────────────────────────────────────────

/**
 * Extensions for files that contain functional back-end or front-end logic.
 * These are the only files that pass through the filter.
 */
const FUNCTIONAL_EXTENSIONS = new Set([
  // Back-end
  ".php", ".phtml",
  ".py", ".pyi", ".pyx",
  ".rb", ".rake",
  ".go",
  ".rs",
  ".java", ".kt", ".kts", ".scala",
  ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx",
  ".cs",
  ".swift",
  ".pl", ".pm",
  ".lua",
  ".r",
  ".ex", ".exs",
  ".clj", ".cljs", ".edn",
  ".dart",
  ".elm",
  ".hs",
  ".nim",
  ".zig",
  ".v", ".sv",

  // Front-end logic
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".vue", ".svelte",

  // Shell / scripting
  ".sh", ".bash", ".zsh", ".ps1", ".psm1",

  // Database / query
  ".sql", ".psql",

  // Config-as-code (security-relevant)
  ".yaml", ".yml", ".toml",
]);

/**
 * Extensions that are never functional code - always discarded.
 */
const NOISE_EXTENSIONS = new Set([
  ".css", ".scss", ".sass", ".less", ".styl",
  ".md", ".mdx", ".rst", ".txt", ".adoc",
  ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".avif",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".map",
  ".pdf", ".csv", ".tsv",
  ".mp3", ".mp4", ".wav", ".ogg", ".webm",
  ".zip", ".tar", ".gz", ".bz2", ".xz",
]);

/**
 * Lockfile filenames - always discarded (huge diffs, zero security signal).
 */
const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  "Cargo.lock",
  "poetry.lock",
  "go.sum",
  "pubspec.lock",
  "mix.lock",
  "Pipfile.lock",
  "packages.lock.json",
]);

/**
 * JSON files that are NOT lockfiles and may carry security-relevant config.
 */
const KEEP_JSON_FILES = new Set([
  "package.json",
  "composer.json",
  "tsconfig.json",
  ".vibeguard.json",
]);

/** Patterns for files to always discard regardless of extension. */
const ALWAYS_DISCARD_PATTERNS = [
  /\.min\.(js|css)$/i,
  /\.generated\./i,
  /\.d\.ts$/,
  /__snapshots__\//,
  /\.snap$/,
];

// ─── Comment / Noise Patterns ──────────────────────────────────────────────────

/** Regex for single-line comments across languages. */
const SINGLE_LINE_COMMENT_RE = /^\s*(\/\/|#|--|;|%|!).*$/;

/** Regex for lines that are only whitespace. */
const WHITESPACE_ONLY_RE = /^\s*$/;

/** Detect the start of a C-style block comment or JSDoc/PHPDoc block. */
const BLOCK_COMMENT_START_RE = /^\s*\/\*[*!]?/;

/** Detect the end of a C-style block comment. */
const BLOCK_COMMENT_END_RE = /\*\/\s*$/;

/** Detect a Python/Elixir docstring delimiter (triple-quote). */
const DOCSTRING_DELIM_RE = /^\s*("{3}|'{3})/;

/** Inline comment suffix - matches // or # after code. */
const INLINE_COMMENT_RE = /(\/\/|#)\s*[^/].*$/;

/** Strip inline C-style comments mid-line (before any code continuation). */
const INLINE_BLOCK_COMMENT_RE = /\/\*.*?\*\//g;

/**
 * Lines that serve only as block-comment continuation markers.
 * e.g. " * @param foo" or " * Description..."
 */
const JSDOC_CONTINUATION_RE = /^\s*\*\s?/;

// ─── Context Extraction ────────────────────────────────────────────────────────

/**
 * Patterns to extract function/method/class names from hunk @@ headers.
 * Git unified diff includes the line right after the @@ that provides context.
 */
const FUNCTION_CONTEXT_RES: RegExp[] = [
  // PHP
  /function\s+(\w+)\s*\(/,
  // Python
  /def\s+(\w+)\s*\(/,
  /class\s+(\w+)\s*[:(]/,
  // Go
  /func\s+(?:[(]\w+\s+\*?\w+[)])?\s*(\w+)\s*[(]/,
  // JavaScript / TypeScript
  /(?:async\s+)?function\s+(\w+)\s*[(]/,
  /(?:static\s+)?(?:async\s+)?(\w+)\s*[(][^)]*[)]\s*[{]/,  // method shorthand
  /class\s+(\w+)/,
  // Ruby
  /def\s+(?:self[.])?(\w+)/,
  // Rust
  /fn\s+(\w+)\s*[<(]/,
  // Java / C# / Kotlin / Scala / Swift
  /(?:public|private|protected|internal|static|final|abstract)\s+(?:\w+\s+)*(\w+)\s*[(]/,
  // Elixir
  /def\s+(\w+)[(\s]/,
  // Dart
  /(?:void|Future|Widget|String|int|bool|num|dynamic)\s+(\w+)\s*[(]/,
  // Shell
  /^(\w+)\s*[(]\s*[)]\s*[{]/,
  // Route / endpoint markers (framework-agnostic)
  /(?:route|endpoint|path)\s*[:=]\s*['\"]([^'\"]+)['\"]/i,
  /@(?:Get|Post|Put|Delete|Patch|RequestMapping)\s*[(]\s*['\"]([^'\"]+)['\"]/i,
];

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Apply the full noise filter pipeline to a raw DiffResult.
 *
 * @param diff - The structured diff from Phase 1 extractDiff().
 * @returns A token-optimized FilteredDiff ready for LLM consumption.
 */
export function filterDiff(diff: DiffResult): FilteredDiff {
  const filteredFiles: FilteredFile[] = [];
  const discarded: Array<{ path: string; reason: string }> = [];
  let totalAdditions = 0;
  let totalDeletions = 0;

  for (const file of diff.files) {
    const reason = shouldDiscard(file);
    if (reason) {
      discarded.push({ path: file.path, reason });
      continue;
    }

    const filtered = filterFile(file);
    if (filtered.hunks.length === 0) {
      discarded.push({
        path: file.path,
        reason: "All changes were comments, whitespace, or documentation",
      });
      continue;
    }

    filteredFiles.push(filtered);
    totalAdditions += filtered.additions;
    totalDeletions += filtered.deletions;
  }

  return {
    files: filteredFiles,
    totalAdditions,
    totalDeletions,
    discarded,
    estimatedTokens: estimateTokens(filteredFiles),
  };
}

// ─── File-Level Filtering ──────────────────────────────────────────────────────

/**
 * Determine if a file should be discarded, with a human-readable reason.
 * Returns null if the file should be kept.
 */
function shouldDiscard(file: DiffFile): string | null {
  const path = file.path;
  const basename = getBasename(path);
  const ext = getExtension(basename);

  // Check always-discard patterns first.
  for (const pattern of ALWAYS_DISCARD_PATTERNS) {
    if (pattern.test(path) || pattern.test(basename)) {
      return "Matches discard pattern: " + String(pattern);
    }
  }

  // Lockfiles by name.
  if (LOCKFILE_NAMES.has(basename)) {
    return "Lockfile - excluded from analysis";
  }

  // Noise extensions - always discard.
  if (NOISE_EXTENSIONS.has(ext)) {
    return "Non-functional file type: " + ext;
  }

  // JSON files - only keep known config/manifest files.
  if (ext === ".json") {
    if (KEEP_JSON_FILES.has(basename)) {
      return null;
    }
    if (path.includes("/config/") || path.includes("/.github/") || path.startsWith(".github/")) {
      return null;
    }
    return "JSON file - excluded by default (add to KEEP_JSON_FILES to track)";
  }

  // XML files - keep if they look like config, discard if layout.
  if (ext === ".xml") {
    if (path.includes("/config/") || path.includes("/resources/") || path.includes("/AndroidManifest")) {
      return null;
    }
    return "XML file - likely layout/markup, excluded";
  }

  // Files with no extension - keep if they look like config/infra files.
  if (!ext) {
    const keepNoExt = new Set([
      "Dockerfile", "Makefile", "Rakefile", "Gemfile",
      "Procfile", "Vagrantfile", ".env.example",
    ]);
    if (keepNoExt.has(basename) || basename.startsWith("Dockerfile")) {
      return null;
    }
    if (basename.startsWith(".")) {
      return "Dotfile without tracked extension - excluded";
    }
    return "File without recognized extension - excluded";
  }

  // Functional extensions - keep.
  if (FUNCTIONAL_EXTENSIONS.has(ext)) {
    return null;
  }

  return "Unrecognized file type: " + ext;
}

/** Extract the basename from a file path. */
function getBasename(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] ?? path;
}

/** Extract the file extension (including compound extensions like .d.ts). */
function getExtension(basename: string): string {
  if (!basename.includes(".")) return "";
  const parts = basename.split(".");
  // Join all parts after the first for compound extensions.
  if (parts.length <= 2) return "." + parts[parts.length - 1];
  return "." + parts.slice(1).join(".");
}

// ─── File-Level Processing ─────────────────────────────────────────────────────

/**
 * Filter a single DiffFile: strip noise lines and extract context.
 */
function filterFile(file: DiffFile): FilteredFile {
  const filteredHunks: FilteredHunk[] = [];
  let additions = 0;
  let deletions = 0;

  for (const hunk of file.hunks) {
    const filtered = filterHunk(hunk);
    if (filtered.lines.length === 0) continue;

    filteredHunks.push(filtered);
    additions += countByType(filtered.lines, "add");
    deletions += countByType(filtered.lines, "delete");
  }

  return {
    path: file.path,
    status: file.status,
    additions,
    deletions,
    hunks: filteredHunks,
  };
}

function countByType(lines: FilteredLine[], type: string): number {
  let count = 0;
  for (const line of lines) {
    if (line.type === type) count++;
  }
  return count;
}

// ─── Hunk-Level Processing ─────────────────────────────────────────────────────

/**
 * Filter a single DiffHunk: strip comment lines, doc blocks, whitespace noise,
 * and extract surrounding function/endpoint context from the header.
 */
function filterHunk(hunk: DiffHunk): FilteredHunk {
  const context = extractContext(hunk.header);
  const filteredLines: FilteredLine[] = [];

  let inBlockComment = false;
  let inDocstring = false;
  let docstringDelimiter = "";

  for (const line of hunk.lines) {
    const trimmed = line.content.trim();

    // Track multi-line comment state
    if (inBlockComment) {
      if (BLOCK_COMMENT_END_RE.test(trimmed)) {
        inBlockComment = false;
      }
      continue;
    }

    if (inDocstring) {
      if (trimmed === docstringDelimiter || trimmed.endsWith(docstringDelimiter)) {
        inDocstring = false;
        docstringDelimiter = "";
      }
      continue;
    }

    // Detect comment/docstring starts
    if (BLOCK_COMMENT_START_RE.test(trimmed)) {
      if (!BLOCK_COMMENT_END_RE.test(trimmed)) {
        inBlockComment = true;
      }
      continue;
    }

    // Detect Python/Elixir docstrings (triple-quote).
    const dsMatch = trimmed.match(DOCSTRING_DELIM_RE);
    if (dsMatch) {
      docstringDelimiter = dsMatch[0];
      // Check if single-line docstring: e.g. """foo"""
      const rest = trimmed.slice(docstringDelimiter.length);
      if (rest.endsWith(docstringDelimiter)) {
        continue; // Single-line docstring, skip.
      }
      inDocstring = true;
      continue;
    }

    // JSDoc/PHPDoc continuations: " * text" lines.
    if (JSDOC_CONTINUATION_RE.test(line.content) && !trimmed.startsWith("*/")) {
      continue;
    }

    // Skip pure comment lines
    if (SINGLE_LINE_COMMENT_RE.test(trimmed)) {
      continue;
    }

    // Skip whitespace-only lines
    if (WHITESPACE_ONLY_RE.test(trimmed)) {
      continue;
    }

    // Skip context lines that are pure noise (empty after trimming).
    if (line.type === "context" && WHITESPACE_ONLY_RE.test(trimmed)) {
      continue;
    }

    // Strip inline comments from added/deleted lines
    let content = line.content;
    if (line.type === "add" || line.type === "delete") {
      // Strip inline block comments first.
      content = content.replace(INLINE_BLOCK_COMMENT_RE, "");

      // Strip inline single-line comments (respecting string literals).
      content = stripInlineComment(content);

      // If after stripping the line is empty, skip it.
      if (WHITESPACE_ONLY_RE.test(content.trim())) {
        continue;
      }
    }

    filteredLines.push({
      type: line.type,
      content,
    });
  }

  return {
    header: hunk.header,
    surrounding_context: context,
    lines: filteredLines,
  };
}

// ─── Comment Stripping Helpers ──────────────────────────────────────────────────

/**
 * Strip an inline single-line comment from a line of code.
 * Handles the case where // or # appears inside a string literal.
 *
 * Strategy: find the comment delimiter that appears outside of quotes.
 * This is a simplified heuristic - it does not handle every edge case
 * but avoids the most common false positive (URLs).
 */
function stripInlineComment(line: string): string {
  // Check for // comments (JS/TS/Go/PHP/Java/C/etc.)
  const doubleSlashIdx = findCommentDelimiter(line, "//");
  if (doubleSlashIdx !== -1) {
    const candidate = line.slice(0, doubleSlashIdx).trimEnd();
    if (candidate.length > 0) return candidate;
    return "";
  }

  // Check for # comments (Python/Ruby/PHP/Shell)
  const hashIdx = findCommentDelimiter(line, "#");
  if (hashIdx !== -1) {
    const candidate = line.slice(0, hashIdx).trimEnd();
    if (candidate.length > 0) return candidate;
    return "";
  }

  return line;
}

/**
 * Find the position of a comment delimiter that is NOT inside a string literal.
 * Returns -1 if no viable comment delimiter is found.
 */
function findCommentDelimiter(line: string, delimiter: string): number {
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBacktick = false;

  for (let i = 0; i < line.length - 1; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : "";

    // Toggle quote state (skip escaped quotes).
    if (ch === "'" && prev !== "\\" && !inDoubleQuote && !inBacktick) {
      inSingleQuote = !inSingleQuote;
      continue;
    }
    if (ch === '"' && prev !== "\\" && !inSingleQuote && !inBacktick) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }
    if (ch === "`" && prev !== "\\" && !inSingleQuote && !inDoubleQuote) {
      inBacktick = !inBacktick;
      continue;
    }

    // Check for delimiter outside of any string.
    if (!inSingleQuote && !inDoubleQuote && !inBacktick) {
      if (line.slice(i, i + delimiter.length) === delimiter) {
        return i;
      }
    }
  }

  return -1;
}

// ─── Context Extraction ─────────────────────────────────────────────────────────

/**
 * Try to extract a function/method/class/endpoint name from a hunk header.
 *
 * Git unified diff headers include the line of code that immediately
 * precedes the changed block. This often contains function signatures,
 * class definitions, or route annotations.
 *
 * Example header:
 *   @@ -12,7 +12,9 @@ import { foo } from './bar';
 *
 * Returns the matched symbol name, or null if nothing is recognizable.
 */
function extractContext(header: string): string | null {
  // Strip the line-number part: "@@ -12,7 +12,9 @@ "
  const contextPart = header.replace(
    /^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*/,
    ""
  );

  if (!contextPart) return null;

  // Try each context pattern.
  for (const re of FUNCTION_CONTEXT_RES) {
    const match = contextPart.match(re);
    if (match && match[1]) {
      return match[1];
    }
  }

  // If the context part is short and meaningful, use it directly.
  const cleaned = contextPart.trim();
  if (cleaned.length > 2 && cleaned.length < 120) {
    return cleaned;
  }

  return null;
}

// ─── Token Estimation ───────────────────────────────────────────────────────────

/**
 * Rough token count estimator.
 *
 * Uses a simple character-based heuristic:
 *   - Code: ~3.5 chars/token on average (conservative for code-heavy text).
 *   - 1 token minimum.
 */
function estimateTokens(files: FilteredFile[]): number {
  let totalChars = 0;

  for (const file of files) {
    totalChars += file.path.length;

    for (const hunk of file.hunks) {
      totalChars += hunk.header.length;
      if (hunk.surrounding_context) {
        totalChars += hunk.surrounding_context.length;
      }

      for (const line of hunk.lines) {
        totalChars += line.content.length + 1; // +1 for the type marker (+/-/)
      }
    }
  }

  return Math.max(1, Math.ceil(totalChars / 3.5));
}

// ─── Standalone Utilities ──────────────────────────────────────────────────────

/**
 * Quick pre-filter: return only the files from a DiffResult that would survive
 * the extension whitelist. Useful for displaying a preview before full parsing.
 */
export function previewFilteredFiles(diff: DiffResult): { kept: string[]; discarded: string[] } {
  const kept: string[] = [];
  const discarded: string[] = [];

  for (const file of diff.files) {
    const reason = shouldDiscard(file);
    if (reason) {
      discarded.push(file.path);
    } else {
      kept.push(file.path);
    }
  }

  return { kept, discarded };
}
