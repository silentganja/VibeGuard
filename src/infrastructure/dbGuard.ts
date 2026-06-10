/**
 * VibeGuard - Local Database State Guard
 *
 * Handles state isolation and recovery during adversarial payload testing.
 * Before test payloads are fired (Phase 5/6), this module captures the current
 * state of affected database tables. After testing concludes, it restores them
 * to their pre-test condition â€” regardless of whether tests passed or failed.
 *
 * Strategies:
 *   SQLite:        Binary file copy â†’ restore from copy.
 *   MySQL:         mysqldump per-table â†’ mysql restore.
 *   PostgreSQL:    pg_dump per-table â†’ psql restore.
 *   none:          No-op (db_type not configured).
 *
 * Table Discovery:
 *   Scans the filtered diff for SQL keywords (FROM, UPDATE, INSERT INTO, etc.)
 *   to identify which tables are referenced by the changed code. Only those
 *   tables are snapped â€” minimizing dump size and restore time.
 *
 * Zero runtime dependencies â€” uses native CLI tools (mysqldump, pg_dump, etc.)
 * and Node.js built-in modules only.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import type {
  VibeGuardConfig,
  FilteredDiff,
  FilteredFile,
  DiscoveredTable,
  SnapshotResult,
  RestoreResult,
  DbConnectionConfig,
} from "../core/types";
import { getDbConnectionConfig } from "../core/config";
import { findProjectRoot } from "../core/config";

// â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Directory under the project root for temp artifacts. */
const TMP_DIR = ".vibeguard/tmp";

/** SQLite backup filename. */
const SQLITE_BACKUP_FILE = "backup.db";

/** SQL dump filename (MySQL / PostgreSQL). */
const SQL_DUMP_FILE = "table_state.sql";

// â”€â”€â”€ SQL Table Discovery Patterns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Regex patterns to extract table names from SQL statements in code.
 * Each pattern captures the table name in group 1.
 */
const TABLE_DISCOVERY_PATTERNS: Array<{ pattern: RegExp; operation: string }> = [
  { pattern: /FROM\s+[`"]?(\w+)[`"]?/gi, operation: "SELECT" },
  { pattern: /JOIN\s+[`"]?(\w+)[`"]?/gi, operation: "JOIN" },
  { pattern: /UPDATE\s+[`"]?(\w+)[`"]?/gi, operation: "UPDATE" },
  { pattern: /INSERT\s+INTO\s+[`"]?(\w+)[`"]?/gi, operation: "INSERT" },
  { pattern: /DELETE\s+FROM\s+[`"]?(\w+)[`"]?/gi, operation: "DELETE" },
  { pattern: /INTO\s+[`"]?(\w+)[`"]?/gi, operation: "INSERT" },
  { pattern: /ALTER\s+TABLE\s+[`"]?(\w+)[`"]?/gi, operation: "ALTER" },
  { pattern: /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?/gi, operation: "CREATE" },
  { pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"]?(\w+)[`"]?/gi, operation: "DROP" },
  { pattern: /TRUNCATE\s+(?:TABLE\s+)?[`"]?(\w+)[`"]?/gi, operation: "TRUNCATE" },
  { pattern: /REPLACE\s+INTO\s+[`"]?(\w+)[`"]?/gi, operation: "REPLACE" },
];

/** Table names to ignore â€” common SQL keywords that aren't actual tables. */
const IGNORED_TABLES = new Set([
  "IF", "EXISTS", "NOT", "NULL", "DEFAULT", "SET",
  "WHERE", "AND", "OR", "VALUES", "ORDER", "GROUP",
  "HAVING", "LIMIT", "OFFSET", "AS", "ON", "USING",
  "DUAL", "TABLE", "TABLES", "COLUMN", "COLUMNS",
]);

// â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Capture the current state of database tables referenced by the changed code.
 *
 * Called BEFORE Phase 5/6 payloads are triggered. Selects the strategy based
 * on the configured db_type and creates a snapshot artifact in .vibeguard/tmp/.
 *
 * @param config       - Validated VibeGuard configuration.
 * @param filteredDiff - The filtered diff from Phase 2a (used for table discovery).
 * @returns A SnapshotResult describing what was captured.
 */
export function capture(config: VibeGuardConfig, filteredDiff: FilteredDiff): SnapshotResult {
  const db = getDbConnectionConfig(config);

  if (db.type === "none") {
    return {
      success: true,
      artifactPath: null,
      tables: [],
      strategy: "none",
      summary: "DB guarding disabled (db_type is \"none\"). No snapshot taken.",
      error: null,
    };
  }

  // Discover which tables are referenced by the changed code.
  const tables = discoverTables(filteredDiff);

  if (tables.length === 0) {
    return {
      success: true,
      artifactPath: null,
      tables: [],
      strategy: "none",
      summary: "No SQL table references detected in the diff. Skipping snapshot.",
      error: null,
    };
  }

  // Ensure temp directory exists.
  const projectRoot = findProjectRoot() ?? process.cwd();
  const tmpDir = path.join(projectRoot, TMP_DIR);
  ensureDir(tmpDir);

  try {
    switch (db.type) {
      case "sqlite":
        return sqliteCapture(db.sqlitePath, tmpDir, tables);
      case "mysql":
        return mysqlCapture(db, tmpDir, tables);
      case "postgresql":
        return postgresCapture(db, tmpDir, tables);
      default:
        return {
          success: true,
          artifactPath: null,
          tables: [],
          strategy: "none",
          summary: "Unknown db_type â€” no snapshot taken.",
          error: null,
        };
    }
  } catch (err: unknown) {
    return {
      success: false,
      artifactPath: null,
      tables,
      strategy: db.type === "sqlite" ? "binary_copy" : "sql_dump",
      summary: "Snapshot failed â€” see error field.",
      error: (err as Error).message,
    };
  }
}

/**
 * Restore database state from the snapshot artifact.
 *
 * Called AFTER Phase 5/6 payloads conclude â€” regardless of whether tests
 * passed or failed. This ensures side effects from adversarial payloads
 * are fully reversed.
 *
 * @param config - Validated VibeGuard configuration.
 * @returns A RestoreResult describing the restore operation.
 */
export function restore(config: VibeGuardConfig): RestoreResult {
  const db = getDbConnectionConfig(config);

  if (db.type === "none") {
    return {
      success: true,
      strategy: "none",
      summary: "DB guarding disabled â€” nothing to restore.",
      error: null,
    };
  }

  const projectRoot = findProjectRoot() ?? process.cwd();
  const tmpDir = path.join(projectRoot, TMP_DIR);

  try {
    switch (db.type) {
      case "sqlite":
        return sqliteRestore(db.sqlitePath, tmpDir);
      case "mysql":
        return mysqlRestore(db, tmpDir);
      case "postgresql":
        return postgresRestore(db, tmpDir);
      default:
        return {
          success: true,
          strategy: "none",
          summary: "Unknown db_type â€” nothing to restore.",
          error: null,
        };
    }
  } catch (err: unknown) {
    return {
      success: false,
      strategy: db.type === "sqlite" ? "binary_copy" : "sql_restore",
      summary: "Restore failed â€” manual intervention may be required. See error field.",
      error: (err as Error).message,
    };
  }
}

// â”€â”€â”€ Table Discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Scan all filtered diff hunks for SQL table name references.
 *
 * Runs each TABLE_DISCOVERY_PATTERN against every changed line (additions
 * and context; deletions are ignored since they represent removed code).
 * Deduplicates by table name + operation combination.
 */
function discoverTables(diff: FilteredDiff): DiscoveredTable[] {
  const found = new Map<string, DiscoveredTable>(); // key = tableName:operation

  for (const file of diff.files) {
    for (const hunk of file.hunks) {
      for (const line of hunk.lines) {
        // Only scan added and context lines â€” deleted code is no longer active.
        if (line.type === "delete") continue;

        for (const { pattern, operation } of TABLE_DISCOVERY_PATTERNS) {
          // Reset regex state (global flag carries lastIndex across calls).
          pattern.lastIndex = 0;

          let match: RegExpExecArray | null;
          while ((match = pattern.exec(line.content)) !== null) {
            const rawName = match[1];
            const tableName = rawName.toLowerCase();

            // Skip SQL keywords that aren't real tables.
            if (IGNORED_TABLES.has(tableName.toUpperCase())) continue;

            // Skip very short names (likely aliases, not tables).
            if (tableName.length < 2) continue;

            const key = tableName + ":" + operation;
            if (!found.has(key)) {
              found.set(key, {
                tableName,
                operation,
                sourceFile: file.path,
              });
            }
          }
        }
      }
    }
  }

  return Array.from(found.values());
}

// â”€â”€â”€ SQLite Capture / Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Capture: create a binary copy of the SQLite database file.
 */
function sqliteCapture(
  sqlitePath: string,
  tmpDir: string,
  tables: DiscoveredTable[]
): SnapshotResult {
  const resolvedPath = resolveSqlitePath(sqlitePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error("SQLite database file not found: " + resolvedPath);
  }

  const backupPath = path.join(tmpDir, SQLITE_BACKUP_FILE);
  fs.copyFileSync(resolvedPath, backupPath);

  const tableNames = tables.map((t) => t.tableName).join(", ");

  return {
    success: true,
    artifactPath: backupPath,
    tables,
    strategy: "binary_copy",
    summary: "SQLite binary snapshot saved to " + backupPath +
      " (" + formatBytes(fs.statSync(backupPath).size) + ", tables: " + tableNames + ")",
    error: null,
  };
}

/**
 * Restore: copy the backup file back over the active SQLite database.
 */
function sqliteRestore(sqlitePath: string, tmpDir: string): RestoreResult {
  const resolvedPath = resolveSqlitePath(sqlitePath);
  const backupPath = path.join(tmpDir, SQLITE_BACKUP_FILE);

  if (!fs.existsSync(backupPath)) {
    return {
      success: true,
      strategy: "binary_copy",
      summary: "No SQLite backup found at " + backupPath + " â€” nothing to restore.",
      error: null,
    };
  }

  fs.copyFileSync(backupPath, resolvedPath);
  fs.unlinkSync(backupPath); // Clean up the backup.

  return {
    success: true,
    strategy: "binary_copy",
    summary: "SQLite database restored from " + backupPath + " â€” backup deleted.",
    error: null,
  };
}

/** Resolve a SQLite path â€” relative paths are resolved from the project root. */
function resolveSqlitePath(raw: string): string {
  if (path.isAbsolute(raw)) return raw;
  const root = findProjectRoot() ?? process.cwd();
  return path.resolve(root, raw);
}

// â”€â”€â”€ MySQL Capture / Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Capture: run mysqldump for the discovered tables.
 */
function mysqlCapture(
  db: DbConnectionConfig,
  tmpDir: string,
  tables: DiscoveredTable[]
): SnapshotResult {
  const uniqueTables = dedupeTableNames(tables);
  const dumpPath = path.join(tmpDir, SQL_DUMP_FILE);
  const tableArgs = uniqueTables.map((t) => escapeIdentifier(t, "mysql")).join(" ");

  const cmd = buildMysqlDumpCommand(db, tableArgs, dumpPath);
  execSync(cmd, { encoding: "utf-8", stdio: "pipe", timeout: 30_000 });

  return {
    success: true,
    artifactPath: dumpPath,
    tables,
    strategy: "sql_dump",
    summary: "MySQL dump saved to " + dumpPath +
      " (" + uniqueTables.length + " table(s): " + uniqueTables.join(", ") + ")",
    error: null,
  };
}

/**
 * Restore: source the SQL dump back into MySQL.
 */
function mysqlRestore(db: DbConnectionConfig, tmpDir: string): RestoreResult {
  const dumpPath = path.join(tmpDir, SQL_DUMP_FILE);

  if (!fs.existsSync(dumpPath)) {
    return {
      success: true,
      strategy: "sql_restore",
      summary: "No MySQL dump found at " + dumpPath + " â€” nothing to restore.",
      error: null,
    };
  }

  const cmd = buildMysqlRestoreCommand(db, dumpPath);
  execSync(cmd, { encoding: "utf-8", stdio: "pipe", timeout: 30_000 });

  // Clean up the dump file after successful restore.
  fs.unlinkSync(dumpPath);

  return {
    success: true,
    strategy: "sql_restore",
    summary: "MySQL tables restored from " + dumpPath + " â€” dump file deleted.",
    error: null,
  };
}

function buildMysqlDumpCommand(db: DbConnectionConfig, tables: string, outFile: string): string {
  const parts = ["mysqldump"];

  if (db.host) parts.push("-h", db.host);
  if (db.port) parts.push("-P", String(db.port));
  if (db.user) parts.push("-u", db.user);
  if (db.pass) parts.push("--password=" + db.pass);

  parts.push("--no-tablespaces");     // Avoid SUPER privilege requirement.
  parts.push("--skip-add-drop-table"); // Don't drop tables on restore (safety).
  parts.push("--skip-comments");       // Reduce dump size.
  parts.push("--skip-lock-tables");    // Avoid locking during dump.
  parts.push("--single-transaction");  // Consistent snapshot without locking.
  parts.push(db.name);
  parts.push(tables);

  // Redirect to file via shell.
  return parts.join(" ") + " > " + escapeShellArg(outFile);
}

function buildMysqlRestoreCommand(db: DbConnectionConfig, dumpFile: string): string {
  const parts = ["mysql"];

  if (db.host) parts.push("-h", db.host);
  if (db.port) parts.push("-P", String(db.port));
  if (db.user) parts.push("-u", db.user);
  if (db.pass) parts.push("--password=" + db.pass);
  parts.push(db.name);

  return parts.join(" ") + " < " + escapeShellArg(dumpFile);
}

// â”€â”€â”€ PostgreSQL Capture / Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Capture: run pg_dump for the discovered tables.
 */
function postgresCapture(
  db: DbConnectionConfig,
  tmpDir: string,
  tables: DiscoveredTable[]
): SnapshotResult {
  const uniqueTables = dedupeTableNames(tables);
  const dumpPath = path.join(tmpDir, SQL_DUMP_FILE);
  const tableArgs = uniqueTables.map((t) => "-t " + escapeIdentifier(t, "postgres")).join(" ");

  const cmd = buildPgDumpCommand(db, tableArgs, dumpPath);
  const env = db.pass ? { ...process.env, PGPASSWORD: db.pass } : process.env;
  execSync(cmd, { encoding: "utf-8", stdio: "pipe", timeout: 30_000, env });

  return {
    success: true,
    artifactPath: dumpPath,
    tables,
    strategy: "sql_dump",
    summary: "PostgreSQL dump saved to " + dumpPath +
      " (" + uniqueTables.length + " table(s): " + uniqueTables.join(", ") + ")",
    error: null,
  };
}

/**
 * Restore: source the SQL dump back into PostgreSQL via psql.
 */
function postgresRestore(db: DbConnectionConfig, tmpDir: string): RestoreResult {
  const dumpPath = path.join(tmpDir, SQL_DUMP_FILE);

  if (!fs.existsSync(dumpPath)) {
    return {
      success: true,
      strategy: "sql_restore",
      summary: "No PostgreSQL dump found at " + dumpPath + " â€” nothing to restore.",
      error: null,
    };
  }

  const cmd = buildPsqlRestoreCommand(db, dumpPath);
  const env = db.pass ? { ...process.env, PGPASSWORD: db.pass } : process.env;
  execSync(cmd, { encoding: "utf-8", stdio: "pipe", timeout: 30_000, env });

  // Clean up the dump file after successful restore.
  fs.unlinkSync(dumpPath);

  return {
    success: true,
    strategy: "sql_restore",
    summary: "PostgreSQL tables restored from " + dumpPath + " â€” dump file deleted.",
    error: null,
  };
}

function buildPgDumpCommand(db: DbConnectionConfig, tableArgs: string, outFile: string): string {
  const parts = ["pg_dump"];

  if (db.host) parts.push("-h", db.host);
  if (db.port) parts.push("-p", String(db.port));
  if (db.user) parts.push("-U", db.user);
  parts.push("--no-owner");
  parts.push("--no-privileges");
  parts.push("--no-tablespaces");
  parts.push("--clean");               // Include DROP statements for clean restore.
  parts.push("--if-exists");           // Don't error if table doesn't exist yet.
  parts.push("--format=plain");
  parts.push(tableArgs);
  parts.push(db.name);

  // Redirect to file via shell.
  return parts.join(" ") + " > " + escapeShellArg(outFile);
}

function buildPsqlRestoreCommand(db: DbConnectionConfig, dumpFile: string): string {
  const parts = ["psql"];

  if (db.host) parts.push("-h", db.host);
  if (db.port) parts.push("-p", String(db.port));
  if (db.user) parts.push("-U", db.user);
  parts.push("-d", db.name);
  parts.push("-q");                    // Quiet mode.
  parts.push("-v", "ON_ERROR_STOP=1"); // Stop on first error.

  return parts.join(" ") + " < " + escapeShellArg(dumpFile);
}

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/** Ensure a directory exists, creating parents if needed. */
function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/** Format a byte count into a human-readable string. */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

/** Extract unique table names from discovered tables. */
function dedupeTableNames(tables: DiscoveredTable[]): string[] {
  return [...new Set(tables.map((t) => t.tableName))];
}

/**
 * Escape a table identifier for shell CLI tools.
 * MySQL uses backtick quoting; PostgreSQL uses double-quote.
 */
function escapeIdentifier(name: string, dialect: "mysql" | "postgres"): string {
  if (dialect === "mysql") return "`" + name + "`";
  return '"' + name + '"';
}

/** Escape a path argument for shell redirection. */
function escapeShellArg(arg: string): string {
  // On Windows, wrap in double quotes; on Unix, single quotes are safer.
  if (process.platform === "win32") {
    return '"' + arg.replace(/"/g, '\\"') + '"';
  }
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

// â”€â”€â”€ Cleanup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Remove all temp artifacts from the .vibeguard/tmp/ directory.
 * Called as a safety measure â€” restore() already cleans individual artifacts,
 * but this ensures no stale files remain.
 */
export function cleanup(): void {
  const projectRoot = findProjectRoot() ?? process.cwd();
  const tmpDir = path.join(projectRoot, TMP_DIR);

  if (fs.existsSync(tmpDir)) {
    const files = fs.readdirSync(tmpDir);
    for (const file of files) {
      try {
        fs.unlinkSync(path.join(tmpDir, file));
      } catch {
        // Best-effort cleanup â€” individual files may already be gone.
      }
    }
  }
}
