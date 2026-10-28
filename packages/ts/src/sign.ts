import { createHmac } from "node:crypto";
import { TENANT_SETTING } from "./tenant.js";

/**
 * Signed tenant context (the migration's default): app.tenant_sig =
 * hex(HMAC-SHA256(key, _firewall_nonce() + ":" + tenant)). The nonce changes
 * with every transaction and the key never reaches the database session, so
 * SQL run inside fn can set app.current_tenant but cannot sign another tenant.
 */
export const TENANT_KEY_ENV = "DB_FIREWALL_TENANT_KEY";
export const SIG_SETTING = "app.tenant_sig";

let warned = false;

/** The key from DB_FIREWALL_TENANT_KEY (hex, 32 to 64 bytes), or undefined when unset. */
export function tenantKey(): Buffer | undefined {
  const raw = (process.env[TENANT_KEY_ENV] ?? "").trim();
  if (!raw) return undefined;
  if (!/^(?:[0-9a-fA-F]{2}){32,64}$/.test(raw)) {
    throw new TypeError(`DB Firewall: ${TENANT_KEY_ENV} must be 32 to 64 bytes, hex-encoded`);
  }
  return Buffer.from(raw, "hex");
}

/** hex(HMAC-SHA256(key, nonce:tenant)), as public._firewall_sign() computes it. */
export function signTenant(key: Buffer, nonce: string, tenant: string): string {
  return createHmac("sha256", key).update(`${nonce}:${tenant}`, "utf8").digest("hex");
}

/** Runs one statement in the transaction and returns its rows. */
export type Run = (text: string, values?: unknown[]) => Promise<any[]>;

/** What enter() saw before fn ran: the settings to restore and the driver's own prepared statements. */
export interface Entered { keep: string; drivers: string[] }

// Snapshot taken in the transaction, before fn: the session-level settings
// and role (_firewall_session_settings()) and the protocol-level prepared
// statements the driver made.
const SNAPSHOT = "public._firewall_session_settings() AS keep, " +
  "(SELECT coalesce(pg_catalog.array_agg(name), '{}') FROM pg_catalog.pg_prepared_statements WHERE NOT from_sql) AS drivers";

/**
 * In the open transaction, before fn: set the tenant, signed when the key is
 * set. Without it the tenant is set unsigned (warned once): a database
 * migrated with the default signed context then shows no rows (fail closed).
 */
export async function enter(run: Run, tenant: string): Promise<Entered> {
  const key = tenantKey();
  let row: any;
  if (!key) {
    if (!warned) {
      warned = true;
      console.warn(`DB Firewall: ${TENANT_KEY_ENV} is not set: the tenant context is unsigned. ` +
                   "A database migrated with the default signed context then shows no rows.");
    }
    [row] = await run(`SELECT set_config('${TENANT_SETTING}', $1, true), ${SNAPSHOT}`, [tenant]);
  } else {
    [row] = await run(`SELECT public._firewall_nonce() AS nonce, ${SNAPSHOT}`);
    await run(`SELECT set_config('${TENANT_SETTING}', $1, true), set_config('${SIG_SETTING}', $2, true)`,
              [tenant, signTenant(key, String(row.nonce), tenant)]);
  }
  // Drivers differ: pg parses jsonb, postgres.js returns it as text.
  return { keep: typeof row.keep === "string" ? row.keep : JSON.stringify(row.keep),
           drivers: Array.isArray(row.drivers) ? row.drivers : [] };
}

// Casts qualified: a temp type named jsonb would shadow the plain name.
// $1::text: postgres.js would JSON-encode a jsonb-typed parameter a second time.
// suspect: SQL-level prepared statements fn made, plus driver statements fn
// removed, counted before the reset. The driver's statement cache is then
// stale, so the connection is better discarded.
const RESET = "WITH c AS MATERIALIZED (SELECT " +
  "(SELECT count(*) FROM pg_catalog.pg_prepared_statements WHERE from_sql) " +
  "OPERATOR(pg_catalog.+) (SELECT count(*) FROM pg_catalog.unnest($2::pg_catalog.text[]) d WHERE NOT EXISTS " +
  "(SELECT 1 FROM pg_catalog.pg_prepared_statements p WHERE NOT p.from_sql AND p.name OPERATOR(pg_catalog.=) d)) AS n) " +
  "SELECT c.n::int AS suspect, public._firewall_reset_session($1::pg_catalog.text::pg_catalog.jsonb) FROM c";

/** fn left the transaction or the session unusable; it was rolled back and the
 *  session reset. The connection should still be discarded where the driver allows it. */
export class SessionResetError extends Error {}

/**
 * After COMMIT or ROLLBACK, outside any transaction: undo the session state fn
 * left (public._firewall_reset_session: temp objects, SQL-level prepared
 * statements, custom settings, cursors, LISTEN, advisory locks), so the
 * connection's next user (another tenant) cannot run into it. After the
 * transaction ended, so a deferred trigger firing at COMMIT cannot undo it.
 * RESET ALL runs alone first, so a short statement_timeout fn set cannot stop
 * the rest. Returns true when the connection should be discarded. Throws when
 * the reset fails: the connection must then be discarded.
 */
export async function resetOutside(run: Run, e: Entered): Promise<boolean> {
  await run("RESET ALL");
  await run("SELECT pg_catalog.pg_advisory_unlock_all()");
  const [r] = await run(RESET, [e.keep, e.drivers]);
  return r?.suspect > 0;
}
