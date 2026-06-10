/**
 * VibeGuard — Production Build Pipeline
 *
 * Phase 10: Cross-platform bundling and native executable generation.
 *
 * This script:
 *   1. Bundles all TypeScript modules into a single minified CJS file via esbuild.
 *   2. Prepends a Node.js shebang for direct execution on Unix systems.
 *   3. Generates platform-specific wrapper scripts (Linux, macOS, Windows).
 *   4. Optionally compiles to native binaries via Node.js SEA (Single Executable
 *      Application) for fully standalone distribution.
 *
 * Usage:
 *   node scripts/build.mjs              # Bundle only
 *   node scripts/build.mjs --native      # Bundle + native SEA binaries
 *   node scripts/build.mjs --target linux,macos,win  # Specific platforms
 *
 * Requirements:
 *   · esbuild (devDependency) — for bundling
 *   · Node.js ≥ 20 (for SEA) — for native binary compilation
 *   · postject (optional) — for SEA blob injection (`npm install -g postject`)
 */

import * as esbuild from "esbuild";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// ─── Path Resolution ───────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const SRC_ENTRY = path.join(ROOT, "src", "cli.ts");

// ─── Build Configuration ───────────────────────────────────────────────────────

const BUILD_TAG = "VibeGuard Engine v1.0.0 (2026)";
const SEA_CONFIG_PATH = path.join(DIST, "sea-config.json");
const SEA_BLOB_PATH = path.join(DIST, "sea-prep.blob");

/** Target platform configurations for native binary generation. */
const PLATFORM_TARGETS = [
  { name: "linux-x64",    os: "linux",   arch: "x64",   ext: "" },
  { name: "linux-arm64",  os: "linux",   arch: "arm64", ext: "" },
  { name: "macos-x64",    os: "darwin",  arch: "x64",   ext: "" },
  { name: "macos-arm64",  os: "darwin",  arch: "arm64", ext: "" },
  { name: "win-x64",      os: "win32",   arch: "x64",   ext: ".exe" },
];

// ─── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const doNative = args.includes("--native");
  const targetFilter = args.find((a) => a.startsWith("--target="));
  const targets = targetFilter
    ? targetFilter.slice("--target=".length).split(",").map((s) => s.trim())
    : null;

  console.log("");
  console.log(`  ${BUILD_TAG}`);
  console.log("  Production Build Pipeline");
  console.log("");

  // ── Step 1: TypeScript type-check ──────────────────────────────────
  console.log("  [1/4] Type-checking...");
  try {
    execSync("npx tsc --noEmit", { cwd: ROOT, stdio: "pipe" });
    console.log("  ✓  Type-check passed");
  } catch (err) {
    console.log("  ✕  Type-check failed — run `tsc` to see errors.");
    process.exit(1);
  }

  // ── Step 2: Bundle with esbuild ────────────────────────────────────
  console.log("  [2/4] Bundling with esbuild...");
  await bundle();
  console.log("  ✓  Bundle complete");

  // ── Step 3: Generate wrapper scripts ───────────────────────────────
  console.log("  [3/4] Generating platform wrappers...");
  generateWrappers();
  console.log("  ✓  Wrappers generated");

  // ── Step 4: Native SEA binaries (optional) ────────────────────────
  if (doNative) {
    console.log("  [4/4] Compiling native binaries via Node.js SEA...");
    await compileNativeBinaries(targets);
    console.log("  ✓  Native binaries compiled");
  } else {
    console.log("  [4/4] Skipping native binaries (use --native to enable)");
  }

  // ── Summary ───────────────────────────────────────────────────────
  console.log("");
  console.log("  ─── Build Output ──────────────────────────────");
  console.log("");
  listOutputFiles();
  console.log("");
  console.log("  ✓  Production build complete.");
  console.log("");
  console.log("  Distribution:");
  console.log("    npm install -g .            # Install globally from source");
  console.log("    npm pack                    # Create .tgz for distribution");
  console.log("    node scripts/build.mjs --native  # Generate standalone binaries");
  console.log("");
}

// ─── esbuild Bundler ───────────────────────────────────────────────────────────

async function bundle() {
  // Ensure dist exists.
  fs.mkdirSync(DIST, { recursive: true });

  const result = await esbuild.build({
    entryPoints: [SRC_ENTRY],
    bundle: true,
    platform: "node",
    target: "node18",
    format: "cjs",
    outfile: path.join(DIST, "vibeguard.cjs"),
    minify: true,
    minifySyntax: true,
    minifyWhitespace: true,
    treeShaking: true,
    // The entry file (cli.ts) already starts with #!/usr/bin/env node.
    // esbuild preserves the first-line shebang from the entry point.
    // Drop console.log in production? No — we need the output.
    // Drop debugger statements.
    drop: ["debugger"],
    // External dependencies we want to keep as require() calls (none for us).
    // All deps are bundled.
    external: [],
    // Generate sourcemap for debugging.
    sourcemap: false,
    // Legal comments in output.
    legalComments: "none",
    // Log level.
    logLevel: "warning",
  });

  // Make the bundle executable on Unix.
  const bundlePath = path.join(DIST, "vibeguard.cjs");
  try {
    fs.chmodSync(bundlePath, 0o755);
  } catch {
    // chmod not supported (Windows) — ignore.
  }

  // Write a size report.
  const stats = fs.statSync(bundlePath);
  const sizeKB = (stats.size / 1024).toFixed(1);
  console.log(`    Bundle size: ${sizeKB} KB`);

  if (result.warnings.length > 0) {
    console.log(`    Warnings: ${result.warnings.length}`);
  }
}

// ─── Platform Wrappers ─────────────────────────────────────────────────────────

/**
 * Generate platform-specific wrapper scripts that invoke the bundled JS.
 *
 * While the bundled .cjs file already has a shebang for Unix, Windows
 * requires a .cmd wrapper. We also provide a shell wrapper for systems
 * that need explicit Node invocation.
 */
function generateWrappers() {
  const bundlePath = path.join(DIST, "vibeguard.cjs");
  const bundleRelPath = "vibeguard.cjs";

  // ── Unix shell wrapper (fallback) ──────────────────────────────────
  const unixWrapper = path.join(DIST, "vibeguard");
  const unixContent = [
    "#!/usr/bin/env sh",
    'exec node "$(dirname "$0")/' + bundleRelPath + '" "$@"',
    "",
  ].join("\n");
  fs.writeFileSync(unixWrapper, unixContent, { mode: 0o755 });

  // ── Windows .cmd wrapper ───────────────────────────────────────────
  const winWrapper = path.join(DIST, "vibeguard.cmd");
  const winContent = [
    "@echo off",
    'node "%~dp0\\' + bundleRelPath.replace(/\//g, "\\") + '" %*',
    "",
  ].join("\r\n");
  fs.writeFileSync(winWrapper, winContent, { mode: 0o644 });
}

// ─── Node.js SEA Native Binary Compilation ─────────────────────────────────────

/**
 * Compile the bundled JS into standalone native binaries using
 * Node.js Single Executable Application (SEA) support.
 *
 * Requires Node.js ≥ 20 and the `postject` tool installed globally:
 *   npm install -g postject
 *
 * This generates a fully standalone binary that embeds the Node.js
 * runtime — users do NOT need Node.js installed to run the binary.
 */
async function compileNativeBinaries(targetFilter) {
  // Check Node.js version (SEA requires ≥ 20).
  const nodeVersion = process.versions.node;
  const major = parseInt(nodeVersion.split(".")[0], 10);
  if (major < 20) {
    console.log("  !  Node.js SEA requires Node ≥ 20. Current: " + nodeVersion);
    console.log("  !  Skipping native binary compilation.");
    return;
  }

  // Check for postject.
  let hasPostject = false;
  try {
    execSync("npx postject --version 2>/dev/null || which postject 2>/dev/null", {
      cwd: ROOT,
      stdio: "pipe",
    });
    hasPostject = true;
  } catch {
    try {
      execSync("which postject", { cwd: ROOT, stdio: "pipe" });
      hasPostject = true;
    } catch {
      // postject not found.
    }
  }

  if (!hasPostject) {
    console.log("  !  postject not found — install it to generate native binaries:");
    console.log("  !    npm install -g postject");
    console.log("  !  Skipping native binary compilation.");
    return;
  }

  // ── Create SEA config ──────────────────────────────────────────────
  const seaConfig = {
    main: path.join(DIST, "vibeguard.cjs"),
    output: SEA_BLOB_PATH,
    disableExperimentalSEAWarning: true,
  };
  fs.writeFileSync(SEA_CONFIG_PATH, JSON.stringify(seaConfig, null, 2));

  // ── Generate SEA blob ──────────────────────────────────────────────
  try {
    execSync(
      `node --experimental-sea-config "${SEA_CONFIG_PATH}"`,
      { cwd: ROOT, stdio: "pipe" }
    );
  } catch (err) {
    console.log("  ✕  SEA blob generation failed: " + (err && err.message ? err.message : String(err)));
    return;
  }

  // ── Compile per-platform binaries ──────────────────────────────────
  const targets = targetFilter
    ? PLATFORM_TARGETS.filter((t) => targetFilter.includes(t.name))
    : PLATFORM_TARGETS;

  if (targets.length === 0) {
    console.log("  !  No matching platform targets found.");
    return;
  }

  for (const target of targets) {
    await compileBinaryForPlatform(target);
  }
}

async function compileBinaryForPlatform(target) {
  const binaryName = "vibeguard-" + target.name + target.ext;
  const binaryPath = path.join(DIST, binaryName);

  // Copy the current Node.js binary as the base.
  const nodeBin = process.execPath;
  try {
    fs.copyFileSync(nodeBin, binaryPath);
  } catch (err) {
    console.log(`  ✕  Failed to copy node binary for ${target.name}: ${(err && err.message ? err.message : String(err))}`);
    return;
  }

  // Inject the SEA blob using postject.
  try {
    execSync(
      `npx postject "${binaryPath}" NODE_SEA_BLOB "${SEA_BLOB_PATH}" --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`,
      { cwd: ROOT, stdio: "pipe" }
    );
    // Make executable on Unix.
    if (target.os !== "win32") {
      fs.chmodSync(binaryPath, 0o755);
    }
    const stats = fs.statSync(binaryPath);
    const sizeMB = (stats.size / (1024 * 1024)).toFixed(1);
    console.log(`    ✓  ${binaryName} (${sizeMB} MB)`);
  } catch (err) {
    console.log(`  ✕  Failed to inject blob for ${target.name}: ${(err && err.message ? err.message : String(err))}`);
    // Clean up failed binary.
    try { fs.unlinkSync(binaryPath); } catch { /* ignore */ }
  }
}

// ─── Output Listing ────────────────────────────────────────────────────────────

function listOutputFiles() {
  const files = fs.readdirSync(DIST)
    .filter((f) => !f.endsWith(".d.ts") && !f.endsWith(".d.ts.map"))
    .sort();

  for (const file of files) {
    const filePath = path.join(DIST, file);
    try {
      const stats = fs.statSync(filePath);
      if (stats.isFile()) {
        const sizeKB = (stats.size / 1024).toFixed(1);
        const mode = (stats.mode & 0o111) !== 0 ? " (executable)" : "";
        console.log(`    dist/${file}  —  ${sizeKB} KB${mode}`);
      }
    } catch {
      console.log(`    dist/${file}`);
    }
  }
}

// ─── Run ───────────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error("Build failed:", err.message);
  process.exit(1);
});
