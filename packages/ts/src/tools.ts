import { runWithTenant, validateTenantId } from "./tenant.js";

/**
 * Bind every tool in a tool set to one tenant. Each tool's execute() runs
 * inside runWithTenant(tenantId), so withTenant(db, fn) in the tool body uses
 * that tenant. The tenant comes from your server's session, never from the
 * model: do not add a tenant field to a tool's input schema.
 *
 * Works with AI SDK tools ({ description, inputSchema, execute }) and any
 * other object whose values have an execute function; the rest is copied.
 */
export function bindTenant<T extends Record<string, unknown>>(tools: T, tenantId: string): T {
  const tenant = validateTenantId(tenantId);
  const bound: Record<string, unknown> = {};
  for (const [name, tool] of Object.entries(tools)) {
    const execute = (tool as { execute?: unknown } | null)?.execute;
    bound[name] = typeof execute === "function"
      ? { ...(tool as object), execute: (...args: unknown[]) =>
            runWithTenant(tenant, () => execute.apply(tool, args)) }
      : tool;
  }
  return bound as T;
}
