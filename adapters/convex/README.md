# DB Firewall — Convex adapter

Convex has no SQL and no connection to wrap, so **enforcement lives inside your
Convex functions**, not in the Python middleware. `tenant.ts` gives you
drop-in replacements for `query` / `mutation` / `action` that:

1. read the tenant from the auth identity claim (`tenant_id` by default) and
   **throw if it is missing** (fail closed);
2. expose `ctx.tenantId`;
3. expose `ctx.tdb`, a scoped database helper:

| `ctx.tdb.*`          | What it enforces                                                |
| -------------------- | --------------------------------------------------------------- |
| `query(table)`       | always `.withIndex("by_tenant", q => q.eq("tenantId", tenant))` |
| `get(id)`            | returns `null` unless `doc.tenantId === tenant`                 |
| `insert(table, doc)` | stamps `tenantId`; rejects a foreign value                      |
| `patch/replace(id)`  | verifies ownership first; rejects `tenantId` changes            |
| `delete(id)`         | verifies ownership first                                        |

## Install

```bash
npm i convex-helpers
cp adapters/convex/tenant.ts convex/tenant.ts
# add tenantId + .index("by_tenant", ["tenantId"]) to each table (see schema.example.ts)
```

```ts
// convex/orders.ts
import { v } from "convex/values";
import { tenantQuery, tenantMutation } from "./tenant";

export const list = tenantQuery({
  args: {},
  handler: async (ctx) => ctx.tdb.query("orders").collect(),
});

export const create = tenantMutation({
  args: { customer: v.string(), total: v.number() },
  handler: async (ctx, args) => ctx.tdb.insert("orders", args),
});
```

## Rules

- **Never use `ctx.db` directly** in tenant-facing functions; it is still on
  `ctx` because Convex needs it, so add a lint rule or code review check.
  `ctx.tdb` is the only scoped surface.
- The tenant claim must be issued by your auth provider (Clerk/Auth0/custom
  JWT) from trusted server code. A claim the client can set is no boundary.
- Actions have no database: `tenantAction` only supplies `ctx.tenantId`; do
  reads/writes through `ctx.runQuery` / `ctx.runMutation` of tenant functions.
- `ctx.tdb.query(table)` returns the untyped index query (`any`) because the
  `by_tenant` index is a convention the type system cannot see. Keep the
  schema example's naming exactly.

## Verification

`npx tsc --noEmit` passes with convex 1.47.0, convex-helpers 0.1.128 and
TypeScript 7.0.2 (strict), using Convex's standard `_generated/` templates.
No runtime test exists here; test with `convex-test` in your own project.
