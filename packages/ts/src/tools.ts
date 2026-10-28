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
            inScope(tenant, runWithTenant(tenant, () => execute.apply(tool, args))) }
      : tool;
  }
  return bound as T;
}

/**
 * A streaming tool (async *execute) returns an async iterator whose body runs
 * on each next(), outside the call above: run every step in the scope too.
 */
function inScope(tenant: string, result: unknown): unknown {
  const it = result as AsyncIterator<unknown> & AsyncIterable<unknown>;
  if (!it || typeof it.next !== "function" || typeof (it as any)[Symbol.asyncIterator] !== "function") {
    return result;
  }
  const step = (name: "next" | "return" | "throw") => (...a: unknown[]) =>
    runWithTenant(tenant, () => (it as any)[name]?.(...a) ?? Promise.resolve({ done: true, value: a[0] }));
  return { next: step("next"), return: step("return"), throw: step("throw"),
           [Symbol.asyncIterator]() { return this; } };
}
