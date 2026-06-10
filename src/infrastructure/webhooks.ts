/**
 * VibeGuard — Universal Webhook Notification Engine
 *
 * Phase 13: Broadcasts high-priority security alerts to Slack, Discord, and
 * Microsoft Teams when vulnerabilities are detected during headless CI/CD runs.
 *
 * Design:
 *   · Zero external SDKs — native `fetch` to standard incoming webhook URLs.
 *   · Three platform-specific JSON formatters (Discord embeds, Slack blocks,
 *     Teams Adaptive Cards).
 *   · Parallel dispatch via Promise.allSettled — one slow webhook never blocks
 *     the pipeline exit.
 *   · Graceful failures — a webhook error logs a warning but never alters the
 *     exit code. The primary goal is blocking the push; the alert is secondary.
 *
 * Zero runtime dependencies — uses only Node.js built-in fetch.
 */

import type { TestReport, ExecutionResult } from "../core/types";
import * as ui from "../cli/ui";

// ─── Constants ──────────────────────────────────────────────────────────────────

/** Hard timeout per webhook request (milliseconds). */
const WEBHOOK_TIMEOUT_MS = 2_000;

/** User-agent sent with webhook requests. */
const USER_AGENT = "VibeGuard/1.0.0 (Webhook Notification Engine)";

// ─── Public Types ───────────────────────────────────────────────────────────────

/** Aggregated vulnerability report for webhook payloads. */
export interface WebhookReport {
  /** Project name (from directory or CI env). */
  project: string;
  /** Git branch being pushed. */
  branch: string;
  /** Total vulnerabilities confirmed. */
  vulnerabilityCount: number;
  /** Total payloads executed. */
  totalTests: number;
  /** Number of tests that passed cleanly. */
  testsPassed: number;
  /** Per-vulnerability detail entries. */
  findings: WebhookFinding[];
}

/** A single confirmed vulnerability for the webhook detail. */
export interface WebhookFinding {
  /** Source file path. */
  file: string;
  /** Target URL that was attacked. */
  targetUrl: string;
  /** HTTP method used. */
  method: string;
  /** Vulnerability vector (sql_injection, xss, etc.). */
  vulnerabilityType: string;
  /** The winning payload data (key=value pairs). */
  payload: string;
  /** HTTP status code returned. */
  statusCode: string;
  /** Response latency in ms. */
  latencyMs: string;
  /** The assertion detail that confirmed the vulnerability. */
  assertionDetail: string;
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Dispatch vulnerability alerts to all configured webhook destinations.
 *
 * Checks which webhook URLs are configured, formats the report for each
 * platform, and fires HTTP POST requests in parallel. A 2-second timeout
 * per webhook prevents slow endpoints from delaying the pipeline exit.
 *
 * Webhook failures are logged as terminal warnings but never throw —
 * the push was already blocked, and the alert is best-effort.
 *
 * @param report       - Aggregated vulnerability report.
 * @param webhookSlack - Slack incoming webhook URL (or empty).
 * @param webhookDiscord - Discord incoming webhook URL (or empty).
 * @param webhookTeams - Teams incoming webhook URL (or empty).
 */
export async function dispatchAlert(
  report: WebhookReport,
  webhookSlack?: string,
  webhookDiscord?: string,
  webhookTeams?: string
): Promise<void> {
  const tasks: Array<Promise<void>> = [];

  if (webhookSlack && webhookSlack.length > 0) {
    tasks.push(sendSlack(report, webhookSlack));
  }

  if (webhookDiscord && webhookDiscord.length > 0) {
    tasks.push(sendDiscord(report, webhookDiscord));
  }

  if (webhookTeams && webhookTeams.length > 0) {
    tasks.push(sendTeams(report, webhookTeams));
  }

  if (tasks.length === 0) {
    return; // No webhooks configured — nothing to do.
  }

  ui.muted("  Dispatching vulnerability alert to " + String(tasks.length) + " webhook(s)...");

  // Fire all webhooks in parallel, never blocking each other.
  const results = await Promise.allSettled(tasks);

  // Log any failures as warnings.
  let successCount = 0;
  let failCount = 0;

  for (const result of results) {
    if (result.status === "fulfilled") {
      successCount++;
    } else {
      failCount++;
      ui.warn("  Webhook delivery failed: " + String(result.reason).slice(0, 120));
    }
  }

  if (successCount > 0) {
    ui.muted("  Alert delivered to " + String(successCount) + " destination(s).");
  }
  if (failCount > 0) {
    ui.warn("  " + String(failCount) + " webhook(s) failed to deliver (non-blocking).");
  }
}

// ─── Report Builder ─────────────────────────────────────────────────────────────

/**
 * Build a WebhookReport from the Phase 6 TestReport and execution context.
 *
 * Extracts only confirmed vulnerabilities — passing or errored tests are
 * omitted from the alert payload.
 *
 * @param testReport - The Phase 6 test execution report.
 * @param branch     - The git branch name being pushed.
 * @param project    - Project identifier (directory name or CI project).
 * @returns A WebhookReport ready for formatting.
 */
export function buildReport(
  testReport: TestReport,
  branch: string,
  project: string
): WebhookReport {
  const findings: WebhookFinding[] = [];

  for (const r of testReport.results) {
    if (!r.vulnerable) continue;

    // Extract the winning payload data as a compact string.
    const payloadEntries = Object.entries(r.payload.payload_data);
    const payloadStr = payloadEntries
      .slice(0, 5)
      .map(([k, v]) => k + "=" + (v.length > 80 ? v.slice(0, 77) + "..." : v))
      .join(", ");

    // Find the primary triggered assertion.
    const triggered = r.assertions.find((a) => a.triggered);

    findings.push({
      file: r.payload.target_url.replace(/\/+$/, ""),
      targetUrl: r.payload.target_url,
      method: r.payload.method,
      vulnerabilityType: r.payload.attack_type,
      payload: payloadStr || "(no payload data)",
      statusCode: r.statusCode !== null ? String(r.statusCode) : "N/A",
      latencyMs: String(r.latencyMs) + "ms",
      assertionDetail: triggered?.detail.slice(0, 200) ?? "Vulnerability confirmed by test execution.",
    });
  }

  return {
    project,
    branch,
    vulnerabilityCount: testReport.vulnerabilitiesFound,
    totalTests: testReport.results.length,
    testsPassed: testReport.testsPassed,
    findings,
  };
}

// ─── Discord Formatter ──────────────────────────────────────────────────────────

/**
 * Build a Discord webhook payload using the `embeds` format.
 *
 * Discord embed structure:
 *   · Red color (#ff0000) for high-severity security alert.
 *   · Title with vulnerability count and project/branch info.
 *   · Fields for each confirmed vulnerability (file, URL, vector, payload).
 *   · Footer with timestamp.
 */
function formatDiscordPayload(report: WebhookReport): Record<string, unknown> {
  const fields: Array<Record<string, unknown>> = [];

  for (const f of report.findings.slice(0, 10)) {
    // Discord limits embeds to 25 fields; we cap at 10 for readability.
    fields.push({
      name: f.vulnerabilityType.toUpperCase() + " · " + f.method + " " + f.targetUrl,
      value: [
        "**File:** " + f.file,
        "**Payload:** `" + f.payload + "`",
        "**Status:** " + f.statusCode + " · " + f.latencyMs,
        "**Detail:** " + f.assertionDetail.slice(0, 150),
      ].join("\n"),
      inline: false,
    });
  }

  // Truncation notice if we have more findings than we can show.
  if (report.findings.length > 10) {
    fields.push({
      name: "⚠️  " + String(report.findings.length - 10) + " more vulnerabilit(ies) truncated",
      value: "See CI logs for full breakdown.",
      inline: false,
    });
  }

  return {
    embeds: [
      {
        title: "🔴 VibeGuard: " + String(report.vulnerabilityCount) + " Vulnerabilit(ies) Detected",
        description: [
          "**Project:** " + report.project,
          "**Branch:** " + report.branch,
          "**Tests:** " + String(report.totalTests) + " executed · " + String(report.testsPassed) + " passed · " + String(report.vulnerabilityCount) + " vulnerable",
        ].join("\n"),
        color: 0xff0000, // Red
        fields,
        footer: {
          text: "VibeGuard · " + new Date().toISOString(),
        },
      },
    ],
  };
}

// ─── Slack Formatter ────────────────────────────────────────────────────────────

/**
 * Build a Slack webhook payload using the `blocks` layout.
 *
 * Slack Block Kit structure:
 *   · Header block with alert title.
 *   · Context block with project/branch/stats.
 *   · Divider.
 *   · Section blocks for each vulnerability (markdown with code blocks).
 *   · Context footer with timestamp.
 */
function formatSlackPayload(report: WebhookReport): Record<string, unknown> {
  const blocks: Array<Record<string, unknown>> = [];

  // Header.
  blocks.push({
    type: "header",
    text: {
      type: "plain_text",
      text: ":red_circle: VibeGuard: " + String(report.vulnerabilityCount) + " Vulnerabilit(ies) Detected",
      emoji: true,
    },
  });

  // Context.
  blocks.push({
    type: "section",
    text: {
      type: "mrkdwn",
      text: [
        "*Project:* " + report.project + "  |  *Branch:* " + report.branch,
        "*Tests:* " + String(report.totalTests) + " executed · " + String(report.testsPassed) + " passed · " + String(report.vulnerabilityCount) + " vulnerable",
      ].join("\n"),
    },
  });

  blocks.push({ type: "divider" });

  // Vulnerability details (cap at 10 for readability).
  for (const f of report.findings.slice(0, 10)) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: [
          "*" + f.vulnerabilityType.toUpperCase() + "*  ·  " + f.method + " " + f.targetUrl,
          "",
          "```" + f.payload + "```",
          "_File:_ " + f.file + "  |  _Status:_ " + f.statusCode + "  |  " + f.latencyMs,
        ].join("\n"),
      },
    });
  }

  // Truncation notice.
  if (report.findings.length > 10) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: ":warning: *" + String(report.findings.length - 10) + " more vulnerabilit(ies)* — see CI logs for full breakdown.",
      },
    });
  }

  blocks.push({ type: "divider" });

  // Footer.
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: "VibeGuard · " + new Date().toISOString(),
      },
    ],
  });

  return { blocks };
}

// ─── Microsoft Teams Formatter ──────────────────────────────────────────────────

/**
 * Build a Microsoft Teams webhook payload using the Adaptive Card format.
 *
 * Teams Adaptive Card structure:
 *   · Red accent color for critical alert.
 *   · Title + fact set for project/branch/stats.
 *   · Container items for each vulnerability (fact set per finding).
 */
function formatTeamsPayload(report: WebhookReport): Record<string, unknown> {
  const facts: Array<Record<string, string>> = [
    { title: "Project", value: report.project },
    { title: "Branch", value: report.branch },
    { title: "Tests Executed", value: String(report.totalTests) },
    { title: "Passed", value: String(report.testsPassed) },
    { title: "Vulnerable", value: String(report.vulnerabilityCount) },
  ];

  const bodyItems: Array<Record<string, unknown>> = [
    {
      type: "FactSet",
      facts,
    },
    {
      type: "TextBlock",
      text: "━━━━━━━━━━━━━━━━━━━━",
      color: "attention",
      weight: "lighter",
      size: "small",
    },
  ];

  // Vulnerability details.
  for (const f of report.findings.slice(0, 10)) {
    bodyItems.push({
      type: "FactSet",
      facts: [
        { title: "Vector", value: f.vulnerabilityType.toUpperCase() },
        { title: "Endpoint", value: f.method + " " + f.targetUrl },
        { title: "File", value: f.file },
        { title: "Payload", value: f.payload.length > 120 ? f.payload.slice(0, 117) + "..." : f.payload },
        { title: "Status", value: f.statusCode + " · " + f.latencyMs },
      ],
    });
    bodyItems.push({
      type: "TextBlock",
      text: " ",
      size: "small",
    });
  }

  if (report.findings.length > 10) {
    bodyItems.push({
      type: "TextBlock",
      text: "⚠ " + String(report.findings.length - 10) + " more vulnerabilit(ies) — see CI logs.",
      color: "warning",
      weight: "bolder",
    });
  }

  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          type: "AdaptiveCard",
          version: "1.4",
          body: [
            {
              type: "TextBlock",
              text: "🔴 VibeGuard: " + String(report.vulnerabilityCount) + " Vulnerabilit(ies) Detected",
              weight: "bolder",
              size: "large",
              color: "attention",
            },
            ...bodyItems,
          ],
          msteams: {
            width: "Full",
          },
        },
      },
    ],
  };
}

// ─── HTTP Dispatchers ───────────────────────────────────────────────────────────

async function sendSlack(report: WebhookReport, url: string): Promise<void> {
  const payload = formatSlackPayload(report);
  await postWebhook(url, payload, "Slack");
}

async function sendDiscord(report: WebhookReport, url: string): Promise<void> {
  const payload = formatDiscordPayload(report);
  await postWebhook(url, payload, "Discord");
}

async function sendTeams(report: WebhookReport, url: string): Promise<void> {
  const payload = formatTeamsPayload(report);
  await postWebhook(url, payload, "Teams");
}

/**
 * Fire a single HTTP POST to an incoming webhook URL with a strict timeout.
 *
 * @param url      - The webhook URL.
 * @param payload  - The JSON-serializable payload object.
 * @param label    - Human-readable platform label for error messages.
 */
async function postWebhook(
  url: string,
  payload: Record<string, unknown>,
  label: string
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      throw new Error(
        label + " webhook returned " + String(response.status) + " " +
        response.statusText + (errText ? ": " + errText.slice(0, 150) : "")
      );
    }
  } catch (err: unknown) {
    clearTimeout(timer);

    const name = (err as Error).name ?? "";
    if (name === "AbortError") {
      throw new Error(label + " webhook timed out after " + String(WEBHOOK_TIMEOUT_MS / 1000) + "s.");
    }
    throw err;
  }
}
