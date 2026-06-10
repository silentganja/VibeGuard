/**
 * VibeGuard — Connectivity Pre-flight Checker & Server Lifecycle Manager
 *
 * Before any mapping or adversarial testing begins, this module verifies that
 * the local development server (configured in .vibeguard.json) is alive and
 * responding to HTTP requests.
 *
 * If the server is unreachable:
 *   1. If server_start_command is configured, attempt to auto-start the server.
 *   2. If no start command is set, abort the push with a clear diagnostic.
 *
 * Fix #1: Server Lifetime Management — automatically spins up and tears down
 * the local dev environment so the developer never has to remember to start
 * Docker or their local backend before pushing.
 */

import { execSync } from "node:child_process";
import type { VibeGuardConfig, ServerCheckResult } from "../core/types";
import * as ui from "../cli/ui";

// ─── Constants ───────────────────────────────────────────────────────────────────

/** Maximum time to wait for the server to respond (milliseconds). */
const CHECK_TIMEOUT_MS = 1500;

/** Maximum time to wait for a server start command to complete (ms). */
const SERVER_START_TIMEOUT_MS = 60_000;

/** Delay between server-start and first health probe (ms). */
const SERVER_START_WARMUP_MS = 2_000;

/** HTTP user-agent string sent with the probe request. */
const USER_AGENT = "VibeGuard/0.9.0 (pre-push connectivity check)";

// ─── Public API ──────────────────────────────────────────────────────────────────

/**
 * Probe the target local dev server and return a detailed status.
 *
 * If the server is unreachable and server_start_command is configured, this
 * function will attempt to start it automatically and retry the health check.
 *
 * Strategy:
 *   1. Send an HTTP HEAD request to the base URL.
 *   2. If HEAD returns 405 (Method Not Allowed) or similar, retry with GET.
 *   3. Time out after CHECK_TIMEOUT_MS.
 *   4. Return a structured ServerCheckResult regardless of outcome.
 *
 * This function NEVER throws — it always returns a result object. The caller
 * decides whether to abort based on the `reachable` field.
 *
 * @param config — Validated VibeGuard configuration.
 * @returns A ServerCheckResult with reachability status and diagnostics.
 */
export async function checkServer(config: VibeGuardConfig): Promise<ServerCheckResult> {
  const baseUrl = normalizeBaseUrl(config.target_local_url);

  // First attempt: probe directly.
  const firstCheck = await runCheck(baseUrl);

  if (firstCheck.reachable) {
    return firstCheck;
  }

  // Server is unreachable — try auto-start if configured.
  if (config.server_start_command && config.server_start_command.trim().length > 0) {
    ui.muted("Local server is not running. Attempting auto-start...");
    const started = startServer(config.server_start_command);

    if (!started) {
      return {
        reachable: false,
        statusCode: null,
        latencyMs: null,
        error: `Server start command failed. Tried: ${config.server_start_command}`,
      };
    }

    // Give the server a moment to spin up, then retry.
    ui.muted(`Waiting ${SERVER_START_WARMUP_MS / 1000}s for server to warm up...`);
    await sleep(SERVER_START_WARMUP_MS);

    const secondCheck = await runCheck(baseUrl);
    if (secondCheck.reachable) {
      ui.ok("Server is now reachable after auto-start.");
      return secondCheck;
    }

    return {
      reachable: false,
      statusCode: secondCheck.statusCode,
      latencyMs: null,
      error: `Server started but still not reachable at ${baseUrl}: ${secondCheck.error ?? "unknown"}`,
    };
  }

  // No auto-start configured — return the original failure.
  return firstCheck;
}

/**
 * Gracefully stop the local dev server if a stop command is configured.
 *
 * Called after all adversarial tests complete. Failures are logged but never
 * thrown — the test results are already determined at this point.
 *
 * @param config — Validated VibeGuard configuration.
 */
export function stopServer(config: VibeGuardConfig): void {
  if (!config.server_stop_command || config.server_stop_command.trim().length === 0) {
    return;
  }

  ui.muted("Stopping local dev server...");
  try {
    execSync(config.server_stop_command, {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    });
    ui.ok("Server stopped.");
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    ui.warn("Failed to stop server: " + msg);
  }
}

// ─── Internal Helpers ────────────────────────────────────────────────────────────

interface ProbeResult {
  reachable: boolean;
  statusCode: number | null;
  error: string | null;
}

/**
 * Perform a full check: HEAD first, fallback to GET if appropriate.
 */
async function runCheck(baseUrl: string): Promise<ServerCheckResult> {
  const start = Date.now();

  // Try HEAD first — it is the lightest probe and most servers support it.
  const headResult = await probe(baseUrl, "HEAD");

  if (headResult.reachable) {
    return {
      reachable: true,
      statusCode: headResult.statusCode,
      latencyMs: Date.now() - start,
      error: null,
    };
  }

  // If HEAD failed with a method-not-allowed type error, retry with GET.
  if (headResult.statusCode === 405 || headResult.statusCode === 501) {
    const getResult = await probe(baseUrl, "GET");
    if (getResult.reachable) {
      return {
        reachable: true,
        statusCode: getResult.statusCode,
        latencyMs: Date.now() - start,
        error: null,
      };
    }
    // GET also failed — fall through to return the GET error.
    return {
      reachable: false,
      statusCode: getResult.statusCode,
      latencyMs: null,
      error: getResult.error,
    };
  }

  // HEAD failed for non-method reasons (connection refused, timeout, DNS, etc.).
  return {
    reachable: false,
    statusCode: headResult.statusCode,
    latencyMs: null,
    error: headResult.error,
  };
}

/**
 * Send an HTTP request to the given URL with a short timeout.
 */
async function probe(url: string, method: "HEAD" | "GET"): Promise<ProbeResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method,
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
      },
      signal: controller.signal,
      // Do not follow redirects — we only care about the direct response.
      redirect: "manual",
    });

    clearTimeout(timer);

    // Any response (including 4xx/5xx) means the server is reachable.
    return {
      reachable: true,
      statusCode: response.status,
      error: null,
    };
  } catch (err: unknown) {
    clearTimeout(timer);

    const error = categorizeError(err, url);
    return {
      reachable: false,
      statusCode: null,
      error,
    };
  }
}

/**
 * Execute the server start command via execSync.
 * Returns true if the command succeeded (exit code 0), false otherwise.
 */
function startServer(command: string): boolean {
  try {
    execSync(command, {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: SERVER_START_TIMEOUT_MS,
    });
    return true;
  } catch (err: unknown) {
    const stderr = (err as { stderr?: string }).stderr ?? "";
    const msg = (err as Error).message ?? String(err);
    ui.warn("Server start command failed: " + (stderr || msg));
    return false;
  }
}

/**
 * Promise-based sleep helper.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Produce a human-readable error message from a failed fetch.
 */
function categorizeError(err: unknown, url: string): string {
  const name = (err as Error).name ?? "";

  if (name === "AbortError") {
    return `Request timed out after ${CHECK_TIMEOUT_MS}ms — server at ${url} is not responding.`;
  }

  const message = (err as Error).message ?? String(err);

  if (message.includes("ECONNREFUSED") || message.includes("Connection refused")) {
    return `Connection refused — no server listening at ${url}. Is your dev server running?`;
  }

  if (message.includes("ENOTFOUND") || message.includes("getaddrinfo")) {
    return `DNS resolution failed for ${url} — check the hostname in target_local_url.`;
  }

  if (message.includes("ECONNRESET")) {
    return `Connection reset by peer at ${url} — the server may have crashed or rejected the request.`;
  }

  if (message.includes("ETIMEDOUT") || message.includes("network timeout")) {
    return `Network timeout connecting to ${url} — check your firewall or server bind address.`;
  }

  // Fallback: include the original message.
  return `Failed to reach ${url}: ${message}`;
}

/**
 * Normalize a base URL for probing.
 *
 * Ensures the URL has a protocol and no trailing path that might confuse
 * a simple connectivity check. We probe the root, not a specific path.
 */
function normalizeBaseUrl(raw: string): string {
  let url = raw.trim().replace(/\/+$/, "");

  // Ensure protocol is present.
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }

  return url;
}

/**
 * Format a ServerCheckResult for terminal display.
 *
 * Returns a multi-line string suitable for ui.muted() or ui.fail().
 */
export function formatCheckResult(result: ServerCheckResult, targetUrl: string): string {
  if (result.reachable) {
    const ms = result.latencyMs !== null ? `${result.latencyMs}ms` : "unknown";
    return (
      `Local server at ${targetUrl} is reachable. (Status ${result.statusCode}, ${ms})`
    );
  }

  return result.error ?? `Server at ${targetUrl} is unreachable for an unknown reason.`;
}
