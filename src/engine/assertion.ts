/**
 * VibeGuard - Security Assertion Engine (The Judge)
 *
 * Evaluates each HTTP response from the test runner to determine whether
 * an adversarial payload successfully triggered a vulnerability.
 *
 * Three assertion categories:
 *
 *   1. Status Code Assertion:
 *      The server returned an unhandled HTTP 500 Internal Server Error,
 *      indicating the payload caused a server-side crash or unhandled exception.
 *
 *   2. Database Leak Assertion:
 *      The response body contains raw database error signatures --” SQL syntax
 *      errors, PDO exceptions, PostgreSQL query failures, SQLite warnings,
 *      or unhandled runtime stack traces. These indicate information disclosure
 *      and confirm injection vulnerabilities.
 *
 *   3. Auth Bypass Assertion:
 *      An exploit targeting an admin or privileged endpoint returns HTTP 200
 *      with content suggesting access to protected resources (database rows,
 *      admin panels, user lists) instead of HTTP 401/403.
 *
 * Each assertion returns a structured AssertionVerdict with the triggered
 * category, a human-readable detail, and the matched signature.
 */

import type { AssertionVerdict, AttackPayload, VulnerabilityVector } from "../core/types";

// â”€â”€â”€ Database Error Signatures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Regex patterns for raw database and infrastructure errors in response bodies.
 *
 * These signatures indicate that a payload triggered an unhandled database
 * exception, exposing internal infrastructure details to the attacker.
 * Match is case-insensitive.
 */
const DB_ERROR_SIGNATURES: RegExp[] = [
  // MySQL / MariaDB
  /(?:You have an error in your SQL syntax|MySQL (?:server )?error|mysql_fetch|mysqli_fetch|mysql_num_rows|mysqli_num_rows)/i,
  /(?:SQLSTATE\[\w+\])/i,   // PDO error code
  /(?:check the manual that (?:corresponds to your|corresponds to) (?:MySQL|MariaDB) server version)/i,

  // PDO / PHP
  /(?:Fatal error:\s*Uncaught PDOException)/i,
  /(?:PDOException|PDO::\w+)/i,
  /(?:Uncaught (?:Error|Exception|TypeError))/i,
  /(?:SQLSTATE\[\d+\])/i,

  // PostgreSQL
  /(?:PostgreSQL query failed|pg_query\(\)|pg_exec\(\))/i,
  /(?:ERROR:\s+syntax error (?:at|near))/i,
  /(?:psql:|PL\/pgSQL)/i,

  // SQLite
  /(?:SQLite3::\w+|sqlite_\w+\(\))/i,
  /(?:SQLite error:|SQLITE_ERROR)/i,
  /(?:unable to open database file)/i,

  // Generic SQL / ORM
  /(?:SQL\s*error:|SQLSTATE|syntax error.*SQL)/i,
  /(?:Illuminate\\Database\\QueryException)/i,   // Laravel
  /(?:django\.db\.utils|DatabaseError|IntegrityError)/i,  // Django
  /(?:ActiveRecord::\w+|PG::Error|Mysql2::Error)/i,       // Rails
  /(?:sqlalchemy\.exc\.\w+)/i,                            // SQLAlchemy

  // Stack traces / debug
  /(?:Stack trace:|#\d+\s+\S+\.\w+\(\d+\))/i,
  /(?:in\s+\/[\w\/]+\.\w+\s+on\s+line\s+\d+)/i,
  /(?:Traceback\s+\(most\s+recent\s+call\s+last\))/i,
  /(?:\.php\s+on\s+line\s+\d+|\.py",\s+line\s+\d+)/i,
  /(?:Warning:\s+\w+\(\)\s+expects|Notice:\s+\w+)/i,

  // Sensitive file / path disclosure
  /(?:\/var\/www\/|\/home\/\w+\/|C:\\xampp\\|C:\\wamp\\)/i,
  /(?:WEB-INF\/web\.xml|\.git\/config|\.env)/i,
];

// â”€â”€â”€ Auth Bypass Indicators â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Keywords and patterns that suggest a response contains privileged or
 * administrative data that should not be accessible without authentication.
 */
const AUTH_BYPASS_INDICATORS: RegExp[] = [
  // Admin panel access
  /(?:admin\s*(?:panel|dashboard|console|portal|cp|area))/i,
  /(?:welcome\s*(?:back,\s*)?admin)/i,
  /(?:administrator|super\s*user|superuser)/i,

  // User data exposure
  /(?:user\s*(?:list|table|directory|records|data|management))/i,
  /(?:username.*password|email.*role|user_id.*is_admin)/i,
  /(?:<table[^>]*>.*(?:id|username|email|password|role).*<\/table>)/is,

  // Session / token data
  /(?:access_token|session_id|auth_token|bearer\s+[\w-]+\.[\w-]+\.[\w-]+)/i,
  /(?:set-cookie:\s*(?:session|auth|token)=)/i,

  // Database row dumps
  /(?:Array\s*\(.*\[(?:id|username|password|email)\].*\))/is,
  /(?:\{[^}]*"(?:id|username|email|role)"[^}]*\})/i,

  // Sensitive operations
  /(?:successfully\s*(?:deleted|updated|created|modified))/i,
  /(?:query\s*(?:executed|completed|successful))/i,
];

/**
 * Endpoint path segments that suggest admin or privileged access.
 * Auth bypass on these is more severe.
 */
const ADMIN_PATH_SEGMENTS = [
  "admin", "dashboard", "manage", "settings",
  "config", "users", "accounts", "staff",
  "mod", "moderator", "cp", "panel",
  "supervisor", "root", "system",
];

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Evaluate a single HTTP response against all security assertions.
 *
 * @param statusCode    - HTTP status code from the response.
 * @param responseBody  - The response body text (first 2000 chars typically).
 * @param payload       - The attack payload that was executed.
 * @param responseHeaders - Response headers as key-value pairs.
 * @returns An array of AssertionVerdicts (empty if all assertions pass).
 */
export function evaluateResponse(
  statusCode: number | null,
  responseBody: string,
  payload: AttackPayload,
  responseHeaders: Record<string, string>
): AssertionVerdict[] {
  const verdicts: AssertionVerdict[] = [];

  if (statusCode === null) {
    // Request completely failed --” not a vulnerability, just a network error.
    return verdicts;
  }

  // â”€â”€ Assertion 1: Status Code â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const statusVerdict = checkStatusCode(statusCode, payload);
  if (statusVerdict) verdicts.push(statusVerdict);

  // â”€â”€ Assertion 2: Database Leak â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const dbLeakVerdict = checkDatabaseLeak(responseBody, payload);
  if (dbLeakVerdict) verdicts.push(dbLeakVerdict);

  // â”€â”€ Assertion 3: Auth Bypass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const authBypassVerdict = checkAuthBypass(statusCode, responseBody, payload, responseHeaders);
  if (authBypassVerdict) verdicts.push(authBypassVerdict);

  return verdicts;
}

/**
 * Aggregate assertion verdicts into a single boolean: was a vulnerability confirmed?
 */
export function isVulnerable(verdicts: AssertionVerdict[]): boolean {
  return verdicts.some((v) => v.triggered);
}

// â”€â”€â”€ Status Code Assertion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function checkStatusCode(
  statusCode: number,
  _payload: AttackPayload
): AssertionVerdict | null {
  if (statusCode === 500) {
    return {
      triggered: true,
      category: "status_code",
      detail: "Server returned HTTP 500 Internal Server Error --” unhandled exception triggered by payload.",
      matched_signature: "HTTP 500",
    };
  }

  // Also flag 502/503 as potential vulnerabilities (server crash / overload).
  if (statusCode === 502) {
    return {
      triggered: true,
      category: "status_code",
      detail: "Server returned HTTP 502 Bad Gateway --” upstream service may have crashed due to payload.",
      matched_signature: "HTTP 502",
    };
  }

  if (statusCode === 503) {
    return {
      triggered: true,
      category: "status_code",
      detail: "Server returned HTTP 503 Service Unavailable --” server may be overloaded or crashed.",
      matched_signature: "HTTP 503",
    };
  }

  return null;
}

// â”€â”€â”€ Database Leak Assertion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function checkDatabaseLeak(
  responseBody: string,
  _payload: AttackPayload
): AssertionVerdict | null {
  if (!responseBody || responseBody.length === 0) return null;

  for (const pattern of DB_ERROR_SIGNATURES) {
    pattern.lastIndex = 0;
    const match = pattern.exec(responseBody);
    if (match) {
      const excerpt = match[0].length > 120
        ? match[0].slice(0, 117) + "..."
        : match[0];

      return {
        triggered: true,
        category: "database_leak",
        detail: "Response body contains raw database error or stack trace --” information disclosure confirming injection vulnerability.",
        matched_signature: excerpt,
      };
    }
  }

  return null;
}

// â”€â”€â”€ Auth Bypass Assertion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function checkAuthBypass(
  statusCode: number,
  responseBody: string,
  payload: AttackPayload,
  responseHeaders: Record<string, string>
): AssertionVerdict | null {
  // Auth bypass only applies to auth-related attack types.
  if (payload.attack_type !== "auth_bypass" && payload.attack_type !== "privilege_escalation") {
    return null;
  }

  // If the server correctly rejected the request, no bypass occurred.
  if (statusCode === 401 || statusCode === 403) {
    return null;
  }

  // An HTTP 200 on an auth bypass attempt is suspicious.
  if (statusCode === 200) {
    // Check if the response contains indicators of privileged access.
    const indicators = findAuthBypassIndicators(responseBody, responseHeaders, payload.target_url);

    if (indicators.length > 0) {
      return {
        triggered: true,
        category: "auth_bypass",
        detail: "Auth bypass confirmed: HTTP 200 with privileged content --” " + indicators.join("; "),
        matched_signature: indicators[0],
      };
    }

    // Even without explicit indicators, 200 on auth bypass is worth flagging
    // if the target URL looks like an admin endpoint.
    if (isAdminEndpoint(payload.target_url)) {
      return {
        triggered: true,
        category: "auth_bypass",
        detail: "Potential auth bypass: admin endpoint returned HTTP 200 on bypass payload instead of 401/403.",
        matched_signature: "HTTP 200 on admin endpoint",
      };
    }
  }

  // HTTP 302 redirect to a dashboard or admin page is also suspicious.
  if (statusCode === 302 || statusCode === 301) {
    const location = responseHeaders["location"] ?? responseHeaders["Location"] ?? "";
    if (isAdminEndpoint(location)) {
      return {
        triggered: true,
        category: "auth_bypass",
        detail: "Auth bypass: server redirected to admin area (" + location + ") after bypass payload.",
        matched_signature: "Redirect to " + location,
      };
    }
  }

  return null;
}

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function findAuthBypassIndicators(
  body: string,
  _headers: Record<string, string>,
  _url: string
): string[] {
  const found: string[] = [];

  if (!body || body.length === 0) return found;

  for (const pattern of AUTH_BYPASS_INDICATORS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(body);
    if (match) {
      const excerpt = match[0].length > 100
        ? match[0].slice(0, 97) + "..."
        : match[0];
      found.push(excerpt);
    }

    // Limit to 3 indicators to keep the output readable.
    if (found.length >= 3) break;
  }

  return found;
}

function isAdminEndpoint(url: string): boolean {
  const lower = url.toLowerCase();
  for (const segment of ADMIN_PATH_SEGMENTS) {
    if (lower.includes("/" + segment) || lower.includes("=" + segment)) {
      return true;
    }
  }
  return false;
}
