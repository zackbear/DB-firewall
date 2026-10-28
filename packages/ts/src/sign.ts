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
 * with the default signed context then shows no rows (fail closed).
 */
export async function setTenant(run: Run, tenant: string): Promise<void> {
  const key = tenantKey();
  if (!key) {
    if (!warned) {
      warned = true;
      console.warn(`DB Firewall: ${TENANT_KEY_ENV} is not set: the tenant context is unsigned. ` +
                   "A database migrated with the default signed context then shows no rows.");
    }
    await run(`SELECT set_config('${TENANT_SETTING}', $1, true)`, [tenant]);
    return;
  }
  const [row] = await run("SELECT public._firewall_nonce() AS nonce");
  await run(`SELECT set_config('${TENANT_SETTING}', $1, true), set_config('${SIG_SETTING}', $2, true)`,
            [tenant, signTenant(key, String(row.nonce), tenant)]);
}

/** Clears session-level values fn may have set, before a connection goes back to a pool. */
export const CLEAR_TENANT =
  `SELECT set_config('${TENANT_SETTING}', '', false), set_config('${SIG_SETTING}', '', false)`;
