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

/**
 * Set the tenant for the current transaction, signed when the key is set.
 * Without it the tenant is set unsigned (warned once): a database migrated
 * with the default signed context then shows no rows (fail closed). Returns
 * the session settings to restore afterwards (_firewall_session_settings()).
 */
async function setTenant(run: Run, tenant: string): Promise<unknown> {
  const key = tenantKey();
  if (!key) {
    if (!warned) {
      warned = true;
      console.warn(`DB Firewall: ${TENANT_KEY_ENV} is not set: the tenant context is unsigned. ` +
                   "A database migrated with the default signed context then shows no rows.");
    }
    const [row] = await run(`SELECT set_config('${TENANT_SETTING}', $1, true), ` +
                            "public._firewall_session_settings() AS keep", [tenant]);
    return row.keep;
  }
  const [row] = await run("SELECT public._firewall_nonce() AS nonce, public._firewall_session_settings() AS keep");
  await run(`SELECT set_config('${TENANT_SETTING}', $1, true), set_config('${SIG_SETTING}', $2, true)`,
            [tenant, signTenant(key, String(row.nonce), tenant)]);
  return row.keep;
}

const SAVEPOINT = "_dbfw_fn";
// Casts qualified: a temp type named jsonb would shadow the plain name.
// $1::text: postgres.js would JSON-encode a jsonb-typed parameter a second time.
// planted: SQL-level prepared statements fn made, counted before the reset
// drops them. A driver whose statement fn replaced now has a stale cache.
const RESET = "WITH c AS MATERIALIZED (SELECT count(*) AS n FROM pg_catalog.pg_prepared_statements WHERE from_sql) " +
  "SELECT c.n::int AS planted, public._firewall_reset_session($1::pg_catalog.text::pg_catalog.jsonb) FROM c";

/** fn left the transaction unusable; it was rolled back and the session reset.
 *  The connection should still be discarded where the driver allows it. */
export class SessionResetError extends Error {}

/**
 * In the open transaction: set the tenant, run body, then undo the session
 * state body left (public._firewall_reset_session: temp objects, SQL-level
 * prepared statements, custom settings, cursors, LISTEN, advisory locks), on
 * success and on error, so the connection's next user (another tenant) cannot
 * run into it. body runs in a savepoint, so the reset also runs after a failed
 * statement. When body broke the transaction (left it aborted, released the
 * savepoint), the transaction is rolled back, the reset runs outside it, and
 * SessionResetError is thrown. terminate: end the backend if even that fails
 * (postgres.js recovers; node-postgres would crash on the error event, so its
 * adapter destroys the client instead).
 */
export async function scoped<T>(run: Run, tenant: string, body: () => Promise<T>,
                                terminate = false, onPlanted?: () => void): Promise<T> {
  const snapshot = await setTenant(run, tenant);
  // Drivers differ: pg parses jsonb, postgres.js returns it as text.
  const keep = typeof snapshot === "string" ? snapshot : JSON.stringify(snapshot);
  await run(`SAVEPOINT ${SAVEPOINT}`);
  let result: T;
  try {
    result = await body();
  } catch (err) {
    await reset(run, keep, true, terminate, onPlanted);
    throw err;
  }
  await reset(run, keep, false, terminate, onPlanted);
  return result;
}

async function reset(run: Run, keep: string, failed: boolean, terminate: boolean,
                     onPlanted?: () => void): Promise<void> {
  const once = async () => { const [r] = await run(RESET, [keep]); if (r?.planted > 0) onPlanted?.(); };
  try {
    if (failed) await run(`ROLLBACK TO SAVEPOINT ${SAVEPOINT}`);
    await once();
    return;
  } catch (err) {
    onPlanted?.();                    // the connection is suspect either way
    try {
      await run("ROLLBACK");
      await once();
    } catch {
      if (terminate) await run("SELECT pg_catalog.pg_terminate_backend(pg_catalog.pg_backend_pid())").catch(() => {});
    }
    throw new SessionResetError("DB Firewall: the function left the transaction unusable " +
      `(${(err as Error).message}); it was rolled back and the session reset`);
  }
}

/** Clears session-level values fn may have set, before a connection goes back to a pool. */
export const CLEAR_TENANT =
  `SELECT set_config('${TENANT_SETTING}', '', false), set_config('${SIG_SETTING}', '', false)`;
