/**
 * DB Firewall — Convex adapter
 * ============================
 * Tenant-scoped function builders. Enforcement lives INSIDE your Convex
 * functions (this file), not in Python: Convex has no SQL layer to rewrite.
 *
 *   import { tenantQuery, tenantMutation } from "./tenant";
 *   export const list = tenantQuery({
 *     args: {},
 *     handler: async (ctx) => ctx.tdb.query("orders").collect(),   // only this tenant's rows
 *   });
 *
 * Requirements (see schema.example.ts):
 *   - every tenant table has a `tenantId: v.string()` field
 *   - every tenant table has `.index("by_tenant", ["tenantId"])`
 *   - the auth provider sets a tenant claim on the identity (default `tenant_id`)
 */
import {
  customAction,
  customCtx,
  customMutation,
  customQuery,
} from "convex-helpers/server/customFunctions";
import type { TableNamesInDataModel } from "convex/server";
import type { GenericId } from "convex/values";
import type { DatabaseReader, DatabaseWriter, QueryCtx, MutationCtx, ActionCtx } from "./_generated/server";
import type { DataModel, Doc, Id } from "./_generated/dataModel";
import { action, mutation, query } from "./_generated/server";

/** Name of the identity claim that carries the tenant. Change once, here. */
export const TENANT_CLAIM = "tenant_id";
export const TENANT_FIELD = "tenantId";
export const TENANT_INDEX = "by_tenant";

type TableName = TableNamesInDataModel<DataModel>;

/** Resolve the tenant from the auth identity; throw (fail closed) when absent. */
export async function requireTenantId(ctx: { auth: QueryCtx["auth"] }): Promise<string> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new Error("DB Firewall: unauthenticated");
  const raw = (identity as Record<string, unknown>)[TENANT_CLAIM];
  if (typeof raw !== "string" || raw.length === 0) {
    throw new Error(`DB Firewall: identity has no '${TENANT_CLAIM}' claim`);
  }
  return raw;
}

/** Read helpers: every query is forced through the by_tenant index. */
export function tenantReader(db: DatabaseReader, tenantId: string) {
  return {
    tenantId,
    /** `db.query(table)` pre-filtered to this tenant via the by_tenant index. */
    query<T extends TableName>(table: T) {
      // Cast: the index is guaranteed by the schema convention, not by the type system.
      return (db.query(table) as any).withIndex(TENANT_INDEX, (q: any) => q.eq(TENANT_FIELD, tenantId));
    },
    /** `db.get(id)` that returns null for foreign-tenant docs (fail closed). */
    async get<T extends TableName>(id: Id<T>): Promise<Doc<T> | null> {
      const doc = (await db.get(id)) as (Doc<T> & { tenantId?: string }) | null;
      return doc && doc.tenantId === tenantId ? doc : null;
    },
  };
}

/** Write helpers: stamp on insert, verify ownership before patch/replace/delete. */
export function tenantWriter(db: DatabaseWriter, tenantId: string) {
  const reader = tenantReader(db, tenantId);
  const own = async <T extends TableName>(id: Id<T>) => {
    if (!(await reader.get(id))) throw new Error("DB Firewall: document not found in tenant");
  };
  return {
    ...reader,
    async insert<T extends TableName>(table: T, doc: Record<string, unknown>): Promise<GenericId<T>> {
      if (TENANT_FIELD in doc && doc[TENANT_FIELD] !== tenantId) {
        throw new Error("DB Firewall: document sets a foreign tenantId");
      }
      return db.insert(table, { ...doc, [TENANT_FIELD]: tenantId } as any);
    },
    async patch<T extends TableName>(id: Id<T>, patch: Record<string, unknown>) {
      if (TENANT_FIELD in patch && patch[TENANT_FIELD] !== tenantId) {
        throw new Error("DB Firewall: patch may not change tenantId");
      }
      await own(id);
      return db.patch(id, patch as any);
    },
    async replace<T extends TableName>(id: Id<T>, doc: Record<string, unknown>) {
      if (TENANT_FIELD in doc && doc[TENANT_FIELD] !== tenantId) {
        throw new Error("DB Firewall: replace may not change tenantId");
      }
      await own(id);
      return db.replace(id, { ...doc, [TENANT_FIELD]: tenantId } as any);
    },
    async delete<T extends TableName>(id: Id<T>) {
      await own(id);
      return db.delete(id);
    },
  };
}

export type TenantReader = ReturnType<typeof tenantReader>;
export type TenantWriter = ReturnType<typeof tenantWriter>;

/** Query builder: `ctx.tenantId` + `ctx.tdb` (read-only, tenant-scoped). */
export const tenantQuery = customQuery(
  query,
  customCtx(async (ctx: QueryCtx) => {
    const tenantId = await requireTenantId(ctx);
    return { tenantId, tdb: tenantReader(ctx.db, tenantId) };
  }),
);

/** Mutation builder: `ctx.tenantId` + `ctx.tdb` (read/write, tenant-scoped). */
export const tenantMutation = customMutation(
  mutation,
  customCtx(async (ctx: MutationCtx) => {
    const tenantId = await requireTenantId(ctx);
    return { tenantId, tdb: tenantWriter(ctx.db, tenantId) };
  }),
);

/** Action builder: actions have no `db`; they only get `ctx.tenantId` and must
 *  call tenantQuery/tenantMutation functions via ctx.runQuery/ctx.runMutation. */
export const tenantAction = customAction(
  action,
  customCtx(async (ctx: ActionCtx) => ({ tenantId: await requireTenantId(ctx) })),
);
