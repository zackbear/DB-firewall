// Shared live setup: DBFW_PG_URL is an admin URL (CI: the postgres service).
// Creates schema ts_app with docs (tenant A: id 1, tenant B: id 2), applies
// the real migration (migrations/001_postgresql.sql) to it, and a normal
// login role dbfw_ts for the app. Tests run one file at a time.
import { readFileSync } from "node:fs";
import pg from "pg";

export const ADMIN_URL = process.env.DBFW_PG_URL;
if (!ADMIN_URL && process.env.DBFW_REQUIRE_LIVE) {
  throw new Error("DBFW_REQUIRE_LIVE is set but DBFW_PG_URL is not: the live tests would be skipped");
}
/** node:test options for a suite that needs the database. */
export const live = { skip: ADMIN_URL ? false : "DBFW_PG_URL not set" };
export const SCHEMA = "ts_app";
const APP_USER = "dbfw_ts", APP_PW = "DbfwTs_2026x";

export function appUrl() {
  const u = new URL(ADMIN_URL);
  u.username = APP_USER;
  u.password = APP_PW;
  return u.toString();
}

export async function setup() {
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await admin.query(`CREATE SCHEMA ${SCHEMA}`);
    await admin.query(`DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_USER}') THEN
        CREATE ROLE ${APP_USER} LOGIN PASSWORD '${APP_PW}';
      END IF; END $$`);
    await admin.query(`CREATE TABLE ${SCHEMA}.docs (id int PRIMARY KEY, tenant_id text NOT NULL, body text)`);
    await admin.query(`INSERT INTO ${SCHEMA}.docs VALUES (1, 'A', 'a-doc'), (2, 'B', 'b-doc')`);
    await admin.query(`GRANT USAGE ON SCHEMA ${SCHEMA} TO ${APP_USER}`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ${SCHEMA}.docs TO ${APP_USER}`);
    await admin.query(`DELETE FROM public._firewall_bypass_roles WHERE role_name = '${APP_USER}'`)
      .catch(() => {});                       // table exists only after a first migration
    await admin.query("SELECT set_config('dbfw.tenant_column', 'tenant_id', false), " +
                      `set_config('dbfw.schema', '${SCHEMA}', false), ` +
                      "set_config('dbfw.policy_mode', 'permissive', false)");
    const migration = new URL("../../../migrations/001_postgresql.sql", import.meta.url);
    await admin.query(readFileSync(migration, "utf8"));
  } finally {
    await admin.end();
  }
}

export async function adminQuery(text, values) {
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try { return (await admin.query(text, values)).rows; } finally { await admin.end(); }
}
