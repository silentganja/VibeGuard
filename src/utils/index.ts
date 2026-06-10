/**
 * VibeGuard — Utilities Barrel Export
 */

export { generateUnifiedDiff } from "./diff";
export { buildRequest } from "./http";
export {
  isCommentLine,
  isEmptyLine,
  stripInlineComment,
  SINGLE_LINE_COMMENT_RE,
  WHITESPACE_ONLY_RE,
  BLOCK_COMMENT_START_RE,
  BLOCK_COMMENT_END_RE,
  DOCSTRING_DELIM_RE,
  JSDOC_CONTINUATION_RE,
} from "./comment-stripper";
