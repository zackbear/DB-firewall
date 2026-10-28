import { AsyncLocalStorage } from "node:async_hooks";

/**
 * The PostgreSQL setting the DB Firewall migration's RLS policies read
 * (migrations/001_postgresql.sql). Set per transaction only, so it can never
 * outlive the transaction or leak to the next user of a pooled connection.
 */
export const TENANT_SETTING = "app.current_tenant";

/** Characters the Python middleware also refuses (NUL, newlines, backslash). */
const BAD_CHARS = /[\u0000\n\r\\]/;

/**
 * Return tenantId when it is a safe tenant id; throw otherwise. Same rules as
 * the Python middleware (validate_tenant_id), so one id works on both sides.
 */
export function validateTenantId(tenantId: unknown): string {
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    throw new TypeError("DB Firewall: tenant id must be a non-empty string");
  }
  if (BAD_CHARS.test(tenantId)) {
    throw new TypeError("DB Firewall: tenant id contains NUL, newline or backslash characters");
  }
  if (tenantId.toLowerCase() === "__bypass__") {
    throw new TypeError("DB Firewall: __BYPASS__ is reserved (MySQL bypass marker)");
  }
  return tenantId;
}

const scope = new AsyncLocalStorage<string>();

/**
 * Run fn with tenantId as the current tenant for everything it awaits.
 * withTenant(db, fn) without an explicit tenant uses it. Set it on the
 * server from the authenticated session, never from model output.
 */
export function runWithTenant<T>(tenantId: string, fn: () => T): T {
  return scope.run(validateTenantId(tenantId), fn);
}

/** The tenant set by runWithTenant / bindTenant, or undefined. */
export function currentTenant(): string | undefined {
  return scope.getStore();
}

/** The explicit tenant, else the scoped one; throws when there is none (fail closed). */
export function resolveTenant(explicit?: string): string {
  const tenant = explicit ?? currentTenant();
  if (tenant === undefined) {
    throw new Error(
      "DB Firewall: no tenant. Pass one to withTenant() or run inside runWithTenant() / bindTenant().",
    );
  }
  return validateTenantId(tenant);
}
