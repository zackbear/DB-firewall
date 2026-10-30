// The signing key the app uses (DB_FIREWALL_TENANT_KEY), shared by migrate and verify.
import { createHmac } from "node:crypto";

export const TENANT_KEY_ENV = "DB_FIREWALL_TENANT_KEY";

/** The key (hex, 32 to 64 bytes), or undefined when unset. */
export function tenantKey(): Buffer | undefined {
  const raw = (process.env[TENANT_KEY_ENV] ?? "").trim();
  if (!raw) return undefined;
  if (!/^(?:[0-9a-fA-F]{2}){32,64}$/.test(raw)) {
    throw new Error(`${TENANT_KEY_ENV} must be 32 to 64 bytes, hex-encoded`);
  }
  return Buffer.from(raw, "hex");
}

/** hex(HMAC-SHA256(key, nonce:tenant)), as db_firewall._firewall_sign() computes it. */
export const sign = (key: Buffer, nonce: string, tenant: string) =>
  createHmac("sha256", key).update(`${nonce}:${tenant}`, "utf8").digest("hex");
