/**
 * VibeGuard — HTTP Request Builders
 *
 * Utilities for constructing HTTP requests from attack payload definitions.
 * Extracted from the Phase 6 test runner to keep the runner focused on
 * execution orchestration.
 *
 * Zero runtime dependencies — uses only Node.js built-ins.
 */

import type { AttackPayload } from "../core/types";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** User-agent sent with test requests. */
const USER_AGENT = "VibeGuard/0.9.0 (adversarial-payload-test)";

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Build the HTTP request URL and init object for a given payload.
 *
 * GET requests serialize payload_data into the query string.
 * POST requests send payload_data as application/x-www-form-urlencoded
 * (with automatic JSON detection for nested payloads).
 */
export function buildRequest(
  payload: AttackPayload
): { url: string; init: RequestInit } {
  const paramCount = Object.keys(payload.payload_data).length;

  if (paramCount === 0) {
    // No parameters — just hit the URL directly.
    return {
      url: payload.target_url,
      init: {
        method: payload.method,
        headers: {
          "User-Agent": USER_AGENT,
          "Accept": "*/*",
        },
        redirect: "manual",
      },
    };
  }

  if (payload.method === "GET") {
    return buildGetRequest(payload);
  }

  return buildPostRequest(payload);
}

// ─── GET Request Builder ────────────────────────────────────────────────────────

/**
 * Build a GET request with payload_data serialized as query parameters.
 *
 * Example:
 *   target_url = "http://localhost:8000/api/users"
 *   payload_data = { user_id: "1' OR '1'='1", role: "admin" }
 *   → "http://localhost:8000/api/users?user_id=1%27+OR+%271%27%3D%271&role=admin"
 */
function buildGetRequest(
  payload: AttackPayload
): { url: string; init: RequestInit } {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(payload.payload_data)) {
    params.append(key, value);
  }

  const separator = payload.target_url.includes("?") ? "&" : "?";
  const url = payload.target_url + separator + params.toString();

  return {
    url,
    init: {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
      },
      redirect: "manual",
    },
  };
}

// ─── POST Request Builder ───────────────────────────────────────────────────────

/**
 * Build a POST request with payload_data as form-urlencoded.
 *
 * Traditional PHP/cPanel stacks expect form-encoded POST bodies.
 * JSON Content-Type is also common for modern frameworks — we use
 * form-urlencoded as the default since it's the superset compatibility
 * choice, but detect JSON-like values and switch accordingly.
 */
function buildPostRequest(
  payload: AttackPayload
): { url: string; init: RequestInit } {
  // Detect if the payload data looks like JSON (contains nested structures
  // or JSON-specific values like {"key": "value"}).
  const looksLikeJson = Object.values(payload.payload_data).some(
    (v) => (v.trim().startsWith("{") && v.trim().endsWith("}")) ||
           (v.trim().startsWith("[") && v.trim().endsWith("]"))
  );

  let body: string;
  let contentType: string;

  if (looksLikeJson) {
    // Build a JSON body from the payload data.
    const obj: Record<string, string> = {};
    for (const [key, value] of Object.entries(payload.payload_data)) {
      obj[key] = value;
    }
    body = JSON.stringify(obj);
    contentType = "application/json";
  } else {
    // Standard form-urlencoded.
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(payload.payload_data)) {
      params.append(key, value);
    }
    body = params.toString();
    contentType = "application/x-www-form-urlencoded";
  }

  return {
    url: payload.target_url,
    init: {
      method: "POST",
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Content-Type": contentType,
      },
      body,
      redirect: "manual",
    },
  };
}
