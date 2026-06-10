/**
 * VibeGuard - Heuristic Route Resolution Engine
 *
 * Cross-references the LLM's modified_endpoints against the local project
 * layout to resolve exact, executable HTTP URLs. Implements a dual-strategy
 * mapping resolver:
 *
 *   1. Traditional File-to-URL Mapping (PHP/cPanel / Apache / Nginx static):
 *      - Detects public subfolders (public/, www/, htdocs/, etc.)
 *      - Maps file paths relative to the web root
 *      - Strips non-public directory prefixes
 *
 *   2. Modern Framework Route Mapping (Next.js, Laravel, Go, Rails, etc.):
 *      - Detects framework presence via sentinel files in the project root
 *      - Uses the LLM's estimated_route as the authoritative URL path
 *      - Falls back to traditional mapping when estimated_route is "N/A"
 *
 * Output: A TargetTargets structure containing executable test definitions
 * ready for adversarial probing.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
  VibeGuardConfig,
  ModifiedEndpoint,
  LLMAnalysisResult,
  ExecutableTest,
  TargetTargets,
  MappingStrategy,
  FrameworkType,
  HttpMethod,
  VulnerabilityVector,
} from "../core/types";
import { PUBLIC_SUBFOLDER_CANDIDATES } from "../core/types";
import { findProjectRoot } from "../core/config";

// â”€â”€â”€ Framework Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Framework sentinel files. Order matters - first match wins.
 * Each entry maps a filename to the framework type it indicates.
 */
const FRAMEWORK_SENTINELS: Array<{ file: string; type: FrameworkType }> = [
  { file: "go.mod", type: "go" },
  { file: "Cargo.toml", type: "rust" },
  { file: "mix.exs", type: "elixir" },
  { file: "Gemfile", type: "ruby" },
];

/**
 * PHP-specific framework markers. If composer.json exists, we check for these
 * framework-specific sentinel files to distinguish Laravel from Symfony from
 * raw PHP.
 */
const PHP_FRAMEWORK_MARKERS: Array<{ file: string; type: FrameworkType }> = [
  { file: "artisan", type: "php-laravel" },
  { file: "bin/console", type: "php-symfony" },
];

/**
 * Python-specific framework markers.
 */
const PYTHON_SENTINELS = [
  "requirements.txt",
  "pyproject.toml",
  "setup.py",
  "setup.cfg",
  "Pipfile",
];

/**
 * Node.js sentinel.
 */
const NODE_SENTINELS = [
  "package.json",
];

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Resolve the LLM's analysis result into a set of executable test targets.
 *
 * For each modified endpoint, applies both mapping strategies and selects
 * the best one based on framework detection and the quality of the LLM's
 * estimated route.
 *
 * @param config       - Validated VibeGuard configuration.
 * @param llmResult    - The structured analysis from Phase 2.
 * @param projectRoot  - Absolute path to the project root (from findProjectRoot).
 * @returns A TargetTargets structure with resolved URLs.
 */
export function mapTargets(
  config: VibeGuardConfig,
  llmResult: LLMAnalysisResult,
  projectRoot: string
): TargetTargets {
  const framework = detectFramework(projectRoot);
  const publicSubfolder = detectPublicSubfolder(projectRoot);
  const baseUrl = sanitizeBaseUrl(config.target_local_url);

  const executableTests: ExecutableTest[] = [];

  for (const ep of llmResult.modified_endpoints) {
    const test = resolveEndpoint(ep, baseUrl, projectRoot, framework, publicSubfolder);
    executableTests.push(test);
  }

  return { executable_tests: executableTests };
}

/**
 * Map targets using only the LLM result and config.
 * The project root is auto-discovered from cwd.
 */
export function mapTargetsFromAnalysis(
  config: VibeGuardConfig,
  llmResult: LLMAnalysisResult
): TargetTargets {
  const projectRoot = findProjectRoot() ?? process.cwd();
  return mapTargets(config, llmResult, projectRoot);
}

// â”€â”€â”€ Single Endpoint Resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Resolve a single modified endpoint to an executable test definition.
 *
 * Decision logic:
 *   1. If this is a framework project AND the LLM provided a meaningful route,
 *      use framework mapping (estimated_route).
 *   2. Otherwise, use traditional file-to-URL mapping.
 *   3. If neither produces a valid URL, mark as unresolved.
 */
function resolveEndpoint(
  ep: ModifiedEndpoint,
  baseUrl: string,
  projectRoot: string,
  framework: FrameworkType,
  publicSubfolder: string | null
): ExecutableTest {
  // Determine whether to trust the LLM's estimated_route.
  const hasReliableRoute = ep.estimated_route !== "N/A"
    && ep.estimated_route !== "unknown"
    && ep.estimated_route.length > 1;

  const isFramework = framework !== "unknown" && framework !== "php-raw";

  let strategy: MappingStrategy;
  let resolvedUrl: string;
  let note: string;

  if (isFramework && hasReliableRoute) {
    // â”€â”€ Framework mapping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    strategy = "framework";
    resolvedUrl = combineUrl(baseUrl, ep.estimated_route);
    note = `Framework route via ${framework} (estimated by LLM)`;
  } else {
    // â”€â”€ Traditional file-to-URL mapping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    strategy = "traditional";
    const urlPath = filePathToUrlPath(ep.file_path, publicSubfolder, projectRoot);
    resolvedUrl = combineUrl(baseUrl, urlPath);
    note = publicSubfolder
      ? `Traditional mapping - file path mapped to URL (public subfolder: ${publicSubfolder}/)`
      : "Traditional mapping - file path mapped to URL (no public subfolder detected)";

    // If traditional mapping produced a weak URL (e.g., deep nested source files),
    // and the LLM gave us something useful, prefer the LLM's route as a fallback.
    if (hasReliableRoute && isDeepSourcePath(ep.file_path, publicSubfolder)) {
      const frameworkUrl = combineUrl(baseUrl, ep.estimated_route);
      resolvedUrl = frameworkUrl;
      strategy = "framework";
      note = `Framework route fallback - file at "${ep.file_path}" is outside the web root, using LLM estimated route instead`;
    }
  }

  // Final sanity check: if the URL is just the base with no path, note it.
  if (resolvedUrl === baseUrl || resolvedUrl === baseUrl + "/") {
    if (!hasReliableRoute) {
      strategy = "unresolved";
      note = `Unable to resolve a specific URL for "${ep.file_path}" - no route estimated and file outside web root`;
    }
  }

  return {
    resolved_url: resolvedUrl,
    http_method: sanitizeMethod(ep.http_method),
    input_parameters: ep.input_parameters,
    vulnerability_vectors: ep.vulnerability_vectors,
    associated_file: ep.file_path,
    mapping_strategy: strategy,
    mapping_note: note,
  };
}

// â”€â”€â”€ Framework Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Detect the project framework by scanning for sentinel files.
 *
 * Checks in order:
 *   1. Go, Rust, Elixir, Ruby (single-file sentinels)
 *   2. Node.js (package.json)
 *   3. Python (requirements.txt, pyproject.toml, etc.)
 *   4. PHP (composer.json + framework-specific markers)
 *
 * Returns "unknown" if no recognizable framework is found.
 */
function detectFramework(projectRoot: string): FrameworkType {
  // Check single-file sentinels.
  for (const { file, type } of FRAMEWORK_SENTINELS) {
    if (fileExists(projectRoot, file)) {
      return type;
    }
  }

  // Check Node.js.
  for (const file of NODE_SENTINELS) {
    if (fileExists(projectRoot, file)) {
      return "nodejs";
    }
  }

  // Check Python.
  for (const file of PYTHON_SENTINELS) {
    if (fileExists(projectRoot, file)) {
      return "python";
    }
  }

  // Check PHP (composer.json present).
  if (fileExists(projectRoot, "composer.json")) {
    for (const { file, type } of PHP_FRAMEWORK_MARKERS) {
      if (fileExists(projectRoot, file)) {
        return type;
      }
    }
    return "php-raw";
  }

  return "unknown";
}

// â”€â”€â”€ Public Subfolder Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Detect the public web root subfolder within the project.
 *
 * Common patterns:
 *   - Laravel:         public/
 *   - Symfony:         public/
 *   - cPanel / Apache: public_html/, www/, htdocs/
 *   - Static sites:    dist/, build/
 *   - General:         web/, html/, static/
 *
 * Returns the subfolder name (without trailing slash), or null if the
 * project root itself is the web root.
 */
function detectPublicSubfolder(projectRoot: string): string | null {
  for (const candidate of PUBLIC_SUBFOLDER_CANDIDATES) {
    const candidatePath = path.join(projectRoot, candidate);
    try {
      const stat = fs.statSync(candidatePath);
      if (stat.isDirectory()) {
        // Verify it looks like a web root: contains at least one .php, .html,
        // or index.* file.
        if (isWebRoot(candidatePath)) {
          return candidate;
        }
      }
    } catch {
      // Directory does not exist - skip.
    }
  }

  // Check if the project root itself looks like a web root.
  if (isWebRoot(projectRoot)) {
    return null; // root is the web root
  }

  // No public subfolder found, but the root might still serve files.
  // Return null to indicate root-based serving.
  return null;
}

/**
 * Heuristic: does the given directory look like it serves web content?
 *
 * Checks for the presence of index files or common web entry points.
 */
function isWebRoot(dir: string): boolean {
  const webFiles = [
    "index.php", "index.html", "index.htm",
    "app.php", "server.php", "main.go",
    "_redirects", ".htaccess", "web.config",
  ];

  for (const file of webFiles) {
    if (fileExists(dir, file)) {
      return true;
    }
  }

  // Also check for subdirectories that suggest web content.
  const webDirs = ["css", "js", "assets", "images", "img", "fonts", "static"];
  for (const subdir of webDirs) {
    try {
      const stat = fs.statSync(path.join(dir, subdir));
      if (stat.isDirectory()) {
        return true;
      }
    } catch {
      // Skip.
    }
  }

  return false;
}

// â”€â”€â”€ File Path â†’ URL Path Conversion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Convert a relative file path from the git diff into a URL path.
 *
 * Strategy:
 *   1. If the file lives inside the public subfolder, strip that prefix.
 *   2. If there's no public subfolder, assume the project root IS the web root
 *      and use the file path directly.
 *   3. Map the filesystem path to a forward-slash URL.
 *
 * Examples:
 *   public/api/login.php  â†’  /api/login.php   (public subfolder stripped)
 *   api/v1/users.php      â†’  /api/v1/users.php (no public subfolder, root is web root)
 *   src/Controller.php    â†’  /src/Controller.php (deep source, may trigger fallback)
 */
function filePathToUrlPath(
  filePath: string,
  publicSubfolder: string | null,
  projectRoot: string
): string {
  // Normalize to forward slashes.
  let normalized = filePath.replace(/\\/g, "/");

  // Strip the public subfolder prefix if present.
  if (publicSubfolder) {
    const prefix = publicSubfolder + "/";
    if (normalized.startsWith(prefix)) {
      normalized = normalized.slice(prefix.length);
    }
  }

  // Ensure leading slash.
  if (!normalized.startsWith("/")) {
    normalized = "/" + normalized;
  }

  return normalized;
}

/**
 * Determine if a file path is "deep" - i.e., lives in a source directory
 * that is unlikely to be directly served by a web server.
 *
 * This is used to decide whether to fall back to the LLM's estimated_route
 * even in traditional mapping mode.
 */
function isDeepSourcePath(filePath: string, publicSubfolder: string | null): boolean {
  const deepPrefixes = [
    "src/", "lib/", "app/", "vendor/", "node_modules/",
    "internal/", "pkg/", "controllers/", "models/", "services/",
    "repositories/", "middleware/", "config/", "database/",
  ];

  const normalized = filePath.replace(/\\/g, "/");

  // If inside a public subfolder, it is NOT deep.
  if (publicSubfolder && normalized.startsWith(publicSubfolder + "/")) {
    return false;
  }

  for (const prefix of deepPrefixes) {
    if (normalized.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

// â”€â”€â”€ URL Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Combine a base URL with a URL path, sanitizing slashes.
 *
 * Examples:
 *   ("http://localhost:8000", "/api/users")  â†’ "http://localhost:8000/api/users"
 *   ("http://localhost:8000/", "api/users")  â†’ "http://localhost:8000/api/users"
 *   ("http://localhost:8000", "/api/users")  â†’ "http://localhost:8000/api/users"
 *   ("http://localhost/my-app", "/api/v1/")  â†’ "http://localhost/my-app/api/v1"
 */
function combineUrl(baseUrl: string, urlPath: string): string {
  const base = baseUrl.replace(/\/+$/, "");
  const path_ = urlPath.replace(/\\/g, "/").replace(/\/+$/, "");

  if (!path_.startsWith("/")) {
    return base + "/" + path_;
  }

  return base + path_;
}

/**
 * Normalize a base URL from config: strip trailing slashes, ensure protocol.
 */
function sanitizeBaseUrl(raw: string): string {
  let url = raw.trim().replace(/\/+$/, "");
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }
  return url;
}

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Check if a file exists at projectRoot/filename. */
function fileExists(projectRoot: string, filename: string): boolean {
  try {
    const stat = fs.statSync(path.join(projectRoot, filename));
    return stat.isFile();
  } catch {
    return false;
  }
}

/**
 * Sanitize the HTTP method for the executable test output.
 * Maps UNKNOWN and PATCH to valid values (the spec schema uses POST|GET|PUT|DELETE).
 * We keep PATCH as-is since it's a valid HTTP method; UNKNOWN becomes GET.
 */
function sanitizeMethod(method: HttpMethod): HttpMethod {
  if (method === "UNKNOWN") {
    return "GET";
  }
  return method;
}

// â”€â”€â”€ Diagnostics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Generate a human-readable summary of the mapping phase.
 *
 * Returns a multi-line string showing which strategy was used for each endpoint
 * and the resolved URLs.
 */
export function formatMappingSummary(targets: TargetTargets): string {
  const lines: string[] = [];

  const strategyCounts: Record<MappingStrategy, number> = {
    traditional: 0,
    framework: 0,
    unresolved: 0,
  };

  for (const test of targets.executable_tests) {
    strategyCounts[test.mapping_strategy]++;
  }

  lines.push(
    `Resolved ${targets.executable_tests.length} endpoint(s) to executable test targets:`
  );
  lines.push(
    `  Traditional: ${strategyCounts.traditional} | Framework: ${strategyCounts.framework} | Unresolved: ${strategyCounts.unresolved}`
  );
  lines.push("");

  for (const test of targets.executable_tests) {
    const stratLabel = test.mapping_strategy === "framework" ? "[FRAMEWORK]"
      : test.mapping_strategy === "traditional" ? "[TRADITIONAL]"
      : "[UNRESOLVED]";

    lines.push(`  ${stratLabel} ${test.http_method} ${test.resolved_url}`);
    lines.push(`    File: ${test.associated_file}`);
    lines.push(`    Note: ${test.mapping_note}`);

    if (test.vulnerability_vectors.length > 0) {
      lines.push(`    Vectors: ${test.vulnerability_vectors.join(", ")}`);
    }
    if (test.input_parameters.length > 0) {
      lines.push(`    Inputs: ${test.input_parameters.join(", ")}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
