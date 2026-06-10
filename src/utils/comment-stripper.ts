/**
 * VibeGuard — Comment & Noise Stripping Utilities
 *
 * Deterministic, language-agnostic comment detection and removal for the
 * Phase 2a noise filter. Strips single-line comments, block comments,
 * JSDoc/PHPDoc continuations, and docstrings from source code lines.
 *
 * Extracted from the parser module to keep the noise filter focused on
 * file-level filtering and hunk-level processing.
 *
 * Zero runtime dependencies — pure regex-based detection.
 */

// ─── Comment / Noise Patterns ──────────────────────────────────────────────────

/** Regex for single-line comments across languages. */
export const SINGLE_LINE_COMMENT_RE = /^\s*(\/\/|#|--|;|%|!).*$/;

/** Regex for lines that are only whitespace. */
export const WHITESPACE_ONLY_RE = /^\s*$/;

/** Detect the start of a C-style block comment or JSDoc/PHPDoc block. */
export const BLOCK_COMMENT_START_RE = /^\s*\/\*[*!]?/;

/** Detect the end of a C-style block comment. */
export const BLOCK_COMMENT_END_RE = /\*\/\s*$/;

/** Detect a Python/Elixir docstring delimiter (triple-quote). */
export const DOCSTRING_DELIM_RE = /^\s*("{3}|'{3})/;

/** Inline comment suffix - matches // or # after code. */
const INLINE_COMMENT_RE = /(\/\/|#)\s*[^/].*$/;

/** Strip inline C-style comments mid-line (before any code continuation). */
export const INLINE_BLOCK_COMMENT_RE = /\/\*.*?\*\//g;

/**
 * Lines that serve only as block-comment continuation markers.
 * e.g. " * @param foo" or " * Description..."
 */
export const JSDOC_CONTINUATION_RE = /^\s*\*\s?/;

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Determine whether a trimmed line is a standalone comment (not inline).
 *
 * Returns true for single-line comments, JSDoc continuations, and docstring
 * delimiters — lines that carry zero functional signal and should be entirely
 * excluded from LLM analysis.
 */
export function isCommentLine(trimmed: string): boolean {
  return (
    SINGLE_LINE_COMMENT_RE.test(trimmed) ||
    JSDOC_CONTINUATION_RE.test(trimmed) ||
    DOCSTRING_DELIM_RE.test(trimmed) ||
    BLOCK_COMMENT_START_RE.test(trimmed)
  );
}

/**
 * Determine whether a trimmed line is empty (whitespace only).
 */
export function isEmptyLine(trimmed: string): boolean {
  return WHITESPACE_ONLY_RE.test(trimmed);
}

/**
 * Strip inline comments from a line of code while preserving string literals.
 *
 * Handles the case where // or # appears inside a string literal by tracking
 * quote state. Also strips inline block comments (/* ... *​/).
 *
 * @returns The line with inline comments removed, or empty string if only
 *          a comment remained.
 */
export function stripInlineComment(line: string): string {
  // Strip inline block comments first.
  let content = line.replace(INLINE_BLOCK_COMMENT_RE, "");

  // Check for // comments (JS/TS/Go/PHP/Java/C/etc.)
  const doubleSlashIdx = findCommentDelimiter(content, "//");
  if (doubleSlashIdx !== -1) {
    const candidate = content.slice(0, doubleSlashIdx).trimEnd();
    if (candidate.length > 0) return candidate;
    return "";
  }

  // Check for # comments (Python/Ruby/PHP/Shell)
  const hashIdx = findCommentDelimiter(content, "#");
  if (hashIdx !== -1) {
    const candidate = content.slice(0, hashIdx).trimEnd();
    if (candidate.length > 0) return candidate;
    return "";
  }

  return content;
}

// ─── Internal Helpers ──────────────────────────────────────────────────────────

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
