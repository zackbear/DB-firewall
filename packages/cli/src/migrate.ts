// migrate: run the bundled migrations/001_postgresql.sql with the settings it reads.
import { readFileSync } from "node:fs";
import type pg from "pg";

export const MIGRATION = new URL("../sql/001_postgresql.sql", import.meta.url);

export async function migrate(client: pg.ClientBase, opts: {
  schema?: string; column?: string; mode?: string;
} = {}): Promise<void> {
  const mode = (opts.mode ?? "permissive").toLowerCase();
  if (mode !== "permissive" && mode !== "restrictive") {
    throw new Error(`--mode must be permissive or restrictive, got ${opts.mode}`);
  }
  // Session settings, as run_migration() does: the script runs its own
  // BEGIN ... COMMIT, and this connection ends after the command.
  await client.query(
    "SELECT set_config('dbfw.tenant_column', $1, false), set_config('dbfw.schema', $2, false), " +
    "set_config('dbfw.policy_mode', $3, false)",
    [opts.column ?? "tenant_id", opts.schema ?? "public", mode]);
  try {
    await client.query(readFileSync(MIGRATION, "utf8"));
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});   // the script's transaction, if left open
    throw err;
  }
}
