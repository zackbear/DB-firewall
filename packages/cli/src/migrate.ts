// migrate: run the bundled migrations/001_postgresql.sql with the settings it reads.
import { readFileSync } from "node:fs";
import type pg from "pg";
import { tenantKey } from "./key.js";

export const MIGRATION = new URL("../sql/001_postgresql.sql", import.meta.url);

export async function migrate(client: pg.ClientBase, opts: {
  schema?: string; column?: string; mode?: string; context?: string; hardenSignals?: boolean;
} = {}): Promise<void> {
  const mode = (opts.mode ?? "permissive").toLowerCase();
  if (mode !== "permissive" && mode !== "restrictive") {
    throw new Error(`--mode must be permissive or restrictive, got ${opts.mode}`);
  }
  const context = (opts.context ?? "signed").toLowerCase();
  if (context !== "signed" && context !== "plain") {
    throw new Error(`--context must be signed or plain, got ${opts.context}`);
  }
  // DB_FIREWALL_TENANT_KEY installs (or rotates to) that key; unset keeps the
  // database's key, or generates one on the first run. The script clears it.
  const key = tenantKey();
  // Session settings, as run_migration() does: the script runs its own
  // BEGIN ... COMMIT, and this connection ends after the command.
  // Keep the key out of the server log where this role may (a superuser):
  // statement and parameter logging off for this session.
  if (key) {
    await client.query("SELECT set_config('log_statement', 'none', false), " +
      "set_config('log_min_duration_statement', '-1', false), set_config('log_parameter_max_length', '0', false), " +
      "set_config('log_parameter_max_length_on_error', '0', false) FROM pg_roles WHERE rolname = current_user AND rolsuper");
  }
  await client.query(
    "SELECT set_config('dbfw.tenant_column', $1, false), set_config('dbfw.schema', $2, false), " +
    "set_config('dbfw.policy_mode', $3, false), set_config('dbfw.context', $4, false), " +
    "set_config('dbfw.tenant_key', $5, false), set_config('dbfw.harden_signals', $6, false)",
    [opts.column ?? "tenant_id", opts.schema ?? "public", mode, context, key?.toString("hex") ?? "",
     opts.hardenSignals ? "on" : "off"]);
  try {
    await client.query(readFileSync(MIGRATION, "utf8"));
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});   // the script's transaction, if left open
    throw err;
  } finally {
    // The script clears the key when it succeeds; a failed run must not leave it.
    await client.query("SELECT set_config('dbfw.tenant_key', '', false)").catch(() => {});
  }
}
