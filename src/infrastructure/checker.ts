/**
 * VibeGuard - Connectivity Pre-flight Checker
 *
 * Before any mapping or adversarial testing begins, this module verifies that
 * the local development server (configured in .vibeguard.json) is alive and
 * responding to HTTP requests.
 *
 * If the server is unreachable, the push is aborted immediately with a clear
 * diagnostic message - there is no point running LLM analysis against an
 * environment that does not exist.
 *
 * Design:
 *   - Single HEAD request (falling back to GET if HEAD is not supported).
 *   - Aggressive 1.5-second timeout - fast failure is the goal.
 *   - Handles DNS failures, connection refused, timeouts, and non-2xx responses.
 */

import type { VibeGuardConfig, ServerCheckResult } from "../core/types";

// â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Maximum time to wait for the server to respond (milliseconds). */
const CHECK_TIMEOUT_MS = 1500;

/** HTTP user-agent string sent with the probe request. */
const USER_AGENT = "VibeGuard/0.9.0 (pre-push connectivity check)";

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Probe the target local dev server and return a detailed status.
 *
 * Strategy:
 *   1. Send an HTTP HEAD request to the base URL.
 *   2. If HEAD returns 405 (Method Not Allowed) or similar, retry with GET.
 *   3. Time out after CHECK_TIMEOUT_MS.
 *   4. Return a structured ServerCheckResult regardless of outcome.
 *
 * This function NEVER throws - it always returns a result object. The caller
 * decides whether to abort based on the `reachable` field.
 *
 * @param config - Validated VibeGuard configuration.
 * @returns A ServerCheckResult with reachability status and diagnostics.
 */
export async function checkServer(config: VibeGuardConfig): Promise<ServerCheckResult> {
  const baseUrl = normalizeBaseUrl(config.target_local_url);
  const start = Date.now();

  // Try HEAD first - it is the lightest probe and most servers support it.
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
    // GET also failed - fall through to return the GET error.
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

// â”€â”€â”€ Internal Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

interface ProbeResult {
  reachable: boolean;
  statusCode: number | null;
  error: string | null;
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
      // Do not follow redirects - we only care about the direct response.
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
 * Produce a human-readable error message from a failed fetch.
 */
function categorizeError(err: unknown, url: string): string {
  const name = (err as Error).name ?? "";

  if (name === "AbortError") {
    return `Request timed out after ${CHECK_TIMEOUT_MS}ms - server at ${url} is not responding.`;
  }

  const message = (err as Error).message ?? String(err);

  if (message.includes("ECONNREFUSED") || message.includes("Connection refused")) {
    return `Connection refused - no server listening at ${url}. Is your dev server running?`;
  }

  if (message.includes("ENOTFOUND") || message.includes("getaddrinfo")) {
    return `DNS resolution failed for ${url} - check the hostname in target_local_url.`;
  }

  if (message.includes("ECONNRESET")) {
    return `Connection reset by peer at ${url} - the server may have crashed or rejected the request.`;
  }

  if (message.includes("ETIMEDOUT") || message.includes("network timeout")) {
    return `Network timeout connecting to ${url} - check your firewall or server bind address.`;
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
