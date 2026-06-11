/**
 * VibeGuard - Compliance Validator
 *
 * Runs at the very start of the pre-push pipeline --” before any code analysis,
 * network calls, or database snapshots. Enforces two quality gates:
 *
 *   1. README Update Check:
 *      Verifies that README.md exists in the project root, contains substantive
 *      content (not a stub), and references current architectural documentation.
 *      Projects without documentation or with stale READMEs are blocked.
 *
 *   2. Semantic Commit Message Check:
 *      Parses the latest local commit via `git log -1 --pretty=%B` and enforces
 *      the Conventional Commits standard. The commit subject must start with a
 *      recognized prefix (feat:, fix:, docs:, refactor:, chore:, etc.) followed
 *      by a descriptive message.
 *
 * If either check fails, the push is aborted immediately with exit code 1.
 * These checks run locally and cost nothing --” they prevent sloppy pushes from
 * ever reaching the LLM analysis stage.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import type { ComplianceResult } from "../core/types";
import { CONVENTIONAL_COMMIT_PREFIXES } from "../core/types";
import * as ui from "../cli/ui";

// â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Minimum character count for README.md to be considered substantive. */
const MIN_README_LENGTH = 200;

/** Phrases that suggest the README is a stub or unedited template. */
const STUB_INDICATORS = [
  "# Project Title",
  "# My Project",
  "# Your Project Name",
  "## Getting Started",
  "TODO",
  "FIXME",
  "[INSERT",
  "[TODO]",
  "coming soon",
  "work in progress",
  "tbd",
];

/** Keywords that suggest architectural or up-to-date documentation. */
const CURRENT_DOC_INDICATORS = [
  "architecture",
  "phase",
  "pipeline",
  "endpoint",
  "configuration",
  "install",
  "module",
  "2026",
  "component",
  "api",
  "setup",
  "schema",
  "quick start",
];

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Run both compliance checks against the current project.
 *
 * @param projectRoot - Absolute path to the project root (discovered via .git).
 * @returns A ComplianceResult with detailed pass/fail for each check.
 */
export function verify(projectRoot: string): ComplianceResult {
  const readmeCheck = checkReadme(projectRoot);
  const commitCheck = checkCommitMessage();

  return {
    passed: readmeCheck.ok && commitCheck.ok,
    readme_check: readmeCheck,
    commit_check: commitCheck,
  };
}

/**
 * Enforce compliance and abort if checks fail.
 *
 * Calls verify() and, if the result is not passing, prints a high-contrast
 * terminal warning and exits with code 1. This is the entry point called by
 * the CLI at the very start of the pre-push pipeline.
 *
 * @param projectRoot - Absolute path to the project root.
 */
export function enforce(projectRoot: string): void {
  const result = verify(projectRoot);

  if (result.passed) {
    ui.muted("  Compliance checks passed (README + commit message).");
    return;
  }

  // Build a stark failure message.
  ui.space();
  ui.rule();
  ui.fail("Compliance Check Failed");
  ui.muted("");

  if (!result.readme_check.ok) {
    ui.fail("  README Check:   FAILED");
    ui.muted("    " + result.readme_check.reason);
    ui.muted("");
    ui.muted("    Action required:");
    ui.muted("      - Ensure README.md exists at the project root.");
    ui.muted("      - Update it with current architectural documentation.");
    ui.muted("      - Reference the 2026 roadmap or current phase details.");
  } else {
    ui.ok("  README Check:   PASSED");
  }

  ui.muted("");

  if (!result.commit_check.ok) {
    ui.fail("  Commit Check:   FAILED");
    ui.muted("    " + result.commit_check.reason);
    ui.muted("");
    ui.muted("    Action required:");
    ui.muted("      - Rewrite your commit message to follow Conventional Commits.");
    ui.muted("      - Must start with: feat:, fix:, docs:, refactor:, chore:, etc.");
    ui.muted("      - Example: git commit -m \"feat: add user authentication endpoint\"");
  } else {
    ui.ok("  Commit Check:   PASSED");
  }

  ui.rule();
  ui.fail("Push blocked --” compliance checks must pass before analysis proceeds.");
  ui.muted("");
  ui.muted("To bypass (NOT RECOMMENDED):");
  ui.muted("  git push --no-verify");
  process.exit(1);
}

// â”€â”€â”€ README Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Verify that README.md exists, is substantive, and contains current documentation.
 */
function checkReadme(projectRoot: string): { ok: boolean; reason: string } {
  const readmePath = path.join(projectRoot, "README.md");

  // Check existence.
  if (!fs.existsSync(readmePath)) {
    return {
      ok: false,
      reason: "README.md not found at project root. Every project must have current documentation.",
    };
  }

  let content: string;
  try {
    content = fs.readFileSync(readmePath, "utf-8");
  } catch {
    return {
      ok: false,
      reason: "README.md exists but could not be read. Check file permissions.",
    };
  }

  // Check minimum length.
  if (content.trim().length < MIN_README_LENGTH) {
    return {
      ok: false,
      reason:
        "README.md is too short (" +
        content.trim().length +
        " chars, minimum " +
        MIN_README_LENGTH +
        "). Expand it with architectural documentation.",
    };
  }

  // Check for stub indicators.
  const contentLower = content.toLowerCase();
  for (const stub of STUB_INDICATORS) {
    if (content.includes(stub)) {
      return {
        ok: false,
        reason:
          'README.md appears to be a stub or template (contains "' +
          stub +
          '"). Replace with real project documentation.',
      };
    }
  }

  // Check for current documentation indicators.
  let docScore = 0;
  for (const indicator of CURRENT_DOC_INDICATORS) {
    if (contentLower.includes(indicator)) {
      docScore++;
    }
  }

  if (docScore < 3) {
    return {
      ok: false,
      reason:
        "README.md does not contain enough current architectural documentation. " +
        "Include sections on architecture, setup, configuration, and the current development phase.",
    };
  }

  // Check modification time --” README should have been touched recently alongside code.
  try {
    const stat = fs.statSync(readmePath);
    const ageDays = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60 * 24);
    if (ageDays > 90) {
      return {
        ok: false,
        reason:
          "README.md was last modified " +
          Math.round(ageDays) +
          " days ago. Update it to reflect the current state of the codebase (2026 roadmap).",
      };
    }
  } catch {
    // Stat failed --” ignore this sub-check.
  }

  return {
    ok: true,
    reason: "README.md exists with substantive architectural documentation (" + content.trim().length + " chars).",
  };
}

// â”€â”€â”€ Commit Message Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Verify that the latest git commit follows the Conventional Commits standard.
 *
 * Checks:
 *   1. A commit exists (at least one commit in the repo).
 *   2. The subject line starts with a recognized prefix (feat:, fix:, etc.).
 *   3. There is a description after the prefix (not just "feat:" with nothing after).
 */
function checkCommitMessage(): { ok: boolean; reason: string } {
  let message: string;
  try {
    message = execSync("git log -1 --pretty=%B", {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return {
      ok: false,
      reason: "Could not read git commit history. Ensure at least one commit exists in the repository.",
    };
  }

  if (!message) {
    return {
      ok: false,
      reason: "No commits found in this repository. Create at least one commit before pushing.",
    };
  }

  // Extract the subject line (first line, strip any merge prefix).
  const subject = message.split("\n")[0].trim();

  // Skip merge commits --” they're auto-generated.
  if (subject.startsWith("Merge ") || subject.startsWith("Merge branch ")) {
    return {
      ok: true,
      reason: "Merge commit detected --” semantic check skipped for auto-generated merge messages.",
    };
  }

  // Check for conventional commit prefix.
  let matchedPrefix = "";
  for (const prefix of CONVENTIONAL_COMMIT_PREFIXES) {
    if (subject.startsWith(prefix)) {
      matchedPrefix = prefix;
      break;
    }
  }

  if (!matchedPrefix) {
    const validPrefixes = CONVENTIONAL_COMMIT_PREFIXES.map((p) => '"' + p + '"').join(", ");
    return {
      ok: false,
      reason:
        'Commit message does not follow Conventional Commits. Subject: "' +
        subject.slice(0, 80) +
        '".\n      Must start with one of: ' +
        validPrefixes +
        ".",
    };
  }

  // Check there's a description after the prefix.
  const description = subject.slice(matchedPrefix.length).trim();
  if (!description || description.length < 3) {
    return {
      ok: false,
      reason:
        'Commit message has a valid prefix ("' +
        matchedPrefix +
        '") but lacks a descriptive message. Example: "feat: add user login endpoint".',
    };
  }

  // Check the description isn't just a single vague word.
  const vagueWords = ["update", "fix", "change", " stuff", "wip", "test", "tmp"];
  if (vagueWords.includes(description.toLowerCase())) {
    return {
      ok: false,
      reason:
        'Commit description is too vague ("' +
        description +
        '"). Provide a meaningful summary of the change.',
    };
  }

  return {
    ok: true,
    reason: 'Commit follows Conventional Commits: "' + subject.slice(0, 80) + '".',
  };
}
