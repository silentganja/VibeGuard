/**
 * VibeGuard — Compliance Module Barrel Export
 *
 * CI/CD detection, enterprise configuration, and codebase compliance checks.
 */

// CI/CD environment detection & env-var config
export {
  isHeadless,
  getOutputMode,
  detectCIPlatform,
  readConfigFromEnv,
  getMissingEnvConfigFields,
  ENV_KEYS,
} from "./ci";

// README + commit message compliance
export { verify, enforce } from "./compliance";
