/**
 * VibeGuard — Engine Module Barrel Export
 *
 * Adversarial test execution, security assertion evaluation,
 * payload generation, and self-healing patch generation.
 */

// Test execution
export { runTests } from "./runner";

// Security assertions
export { evaluateResponse, isVulnerable } from "./assertion";

// Adversarial payload generation
export { generatePayloads } from "./payloadGen";

// Self-healing patch engine
export {
  generateAllPatches,
  formatPatchResult,
  formatPatchSummary,
} from "./healer";
