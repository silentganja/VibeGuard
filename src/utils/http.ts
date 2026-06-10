/**
 * VibeGuard — HTTP Request Builders
 *
 * Utilities for constructing HTTP requests from attack payload definitions.
 * Extracted from the Phase 6 test runner to keep the runner focused on
 * execution orchestration.
 *
 * Fix #2: Dynamic Authentication & Token Seeding — accepts an optional auth
 * context so adversarial payloads carry valid sandbox tokens, preventing
 * false-negative 401/403 results against secured endpoints.
 *
 * Zero runtime dependencies — uses only Node.js built-ins.
 */

import type { AttackPayload, AuthSeedingConfig } from "../core/types";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** User-agent sent with test requests. */
const USER_AGENT = "VibeGuard/0.9.0 (adversarial-payload-test)";

// ─── Auth Resolution Context ─────────────────────────────────────────────────────

/** Resolved authentication data ready to inject into every request. */
export interface AuthContext {
  /** The raw token value. */
  token: string;
  /** How to inject it. */
  auth_type: AuthSeedingConfig["auth_type"];
  /** Custom header name (for "header" auth_type). */
  header_name?: string;
  /** Custom cookie name (for "cookie" auth_type). */
  cookie_name?: string;
  /** Custom query parameter name (for "query" auth_type). */
  query_param_name?: string;
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Build the HTTP request URL and init object for a given payload.
 *
 * GET requests serialize payload_data into the query string.
 * POST requests send payload_data as application/x-www-form-urlencoded
 * (with automatic JSON detection for nested payloads).
 *
 * @param payload     — The adversarial payload to build a request for.
 * @param authContext — Optional resolved auth token for secured endpoints.
 */
export function buildRequest(
  payload: AttackPayload,
  authContext?: AuthContext
): { url: string; init: RequestInit } {
  const paramCount = Object.keys(payload.payload_data).length;

  if (paramCount === 0) {
    // No parameters — just hit the URL directly.
    return {
      url: payload.target_url,
      init: buildInit(payload.method, null, null, authContext),
    };
  }

  if (payload.method === "GET") {
    return buildGetRequest(payload, authContext);
  }

  return buildPostRequest(payload, authContext);
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
  payload: AttackPayload,
  authContext?: AuthContext
): { url: string; init: RequestInit } {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(payload.payload_data)) {
    params.append(key, value);
  }

  // Inject auth query param if applicable.
  if (authContext && authContext.auth_type === "query" && authContext.query_param_name) {
    params.append(authContext.query_param_name, authContext.token);
  }

  const separator = payload.target_url.includes("?") ? "&" : "?";
  const url = payload.target_url + separator + params.toString();

  return {
    url,
    init: buildInit("GET", null, null, authContext),
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
  payload: AttackPayload,
  authContext?: AuthContext
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
    init: buildInit("POST", body, contentType, authContext),
  };
}

// ─── Init Builder (Auth-Aware) ───────────────────────────────────────────────────

/**
 * Build the RequestInit object with optional auth headers/cookies injected.
 */
function buildInit(
  method: string,
  body: string | null,
  contentType: string | null,
  authContext?: AuthContext
): RequestInit {
  const headers: Record<string, string> = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
  };

  if (contentType) {
    headers["Content-Type"] = contentType;
  }

  // Inject auth token based on auth_type.
  if (authContext && authContext.token) {
    switch (authContext.auth_type) {
      case "bearer":
        headers["Authorization"] = "Bearer " + authContext.token;
        break;
      case "header":
        if (authContext.header_name) {
          headers[authContext.header_name] = authContext.token;
        }
        break;
      case "cookie":
        if (authContext.cookie_name) {
          headers["Cookie"] = authContext.cookie_name + "=" + authContext.token;
        }
        break;
      // "query" is handled in buildGetRequest / URL construction.
    }
  }

  const init: RequestInit = {
    method,
    headers,
    body: body ?? undefined,
  };
  init.redirect = "manual";
  return init;
}
