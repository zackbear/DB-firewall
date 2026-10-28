# @db-firewall/pg

Tenant isolation for TypeScript AI agents on PostgreSQL.

Every query runs in a transaction that is bound to one tenant. PostgreSQL row-level security (RLS) enforces it, so a bug in your code or a prompt-injected agent cannot read or write another tenant's rows. The tenant comes from your server's session, never from the model.

- Works with node-postgres (`pg`), postgres.js and Drizzle.
- No runtime dependencies. Drizzle is an optional peer dependency.
- Node 20 or later.
- The RLS policies come from the DB Firewall migration (`migrations/001_postgresql.sql` in this repo).

## 1. Install the policies (once)

Run the migration as a database admin. Set the tenant column, and the policy mode if your app already has RLS policies of its own:

```bash
psql "$ADMIN_URL" \
  -c "SET dbfw.tenant_column = 'tenant_id'" \
  -c "SET dbfw.schema = 'public'" \
  -c "SET dbfw.policy_mode = 'restrictive'" \
  -f migrations/001_postgresql.sql
```

- `permissive` (the default): the tenant policies are the only policies on the table. Another permissive policy on the same table would be OR-ed with them and could widen access, so the scanner reports one.
- `restrictive`: the tenant policies are AND-ed with your own policies, such as Supabase or Drizzle `pgPolicy`. Your policies decide which of the tenant's rows a user sees, and they can never reach past the tenant. A table with no permissive policy of its own gets `fw_<hash>_base` (`USING (true)`). Re-run the migration after you add the first policy of your own to a table.

Re-run the migration after you add tables. It protects every table that has the tenant column.

## 2. Connect as a normal role

RLS does not apply to a superuser or a `BYPASSRLS` role. Check the role once at start-up:

```ts
import pg from "pg";
import { assertSafeRole } from "@db-firewall/pg";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
await assertSafeRole(pool);   // throws for a superuser, BYPASSRLS, or a _firewall_bypass_roles role
```

## 3. Run queries as a tenant

```ts
import { withTenant } from "@db-firewall/pg";

const docs = await withTenant(pool, tenantId, async (client) =>
  (await client.query("SELECT * FROM docs")).rows);   // only tenantId's rows
```

`withTenant` opens a transaction, sets `app.current_tenant` for that transaction only (`set_config(..., true)`), runs your function, and commits. If the function throws, it rolls back. The setting ends with the transaction, so a pooled connection never carries a tenant to its next user (tested with a one-connection pool). Transaction-mode poolers such as PgBouncer keep a transaction on one server connection, so this should hold behind them too; that is not tested here.

The same call works with each driver:

```ts
// postgres.js
const rows = await withTenant(sql, tenantId, (tx) => tx`SELECT * FROM docs`);

// Drizzle (any PostgreSQL driver)
const rows = await withTenant(db, tenantId, (tx) => tx.select().from(docs));
```

With no tenant, `withTenant` throws before it touches the database. RLS also returns no rows to a connection that has no tenant set.

When you pass a single `pg` client instead of a pool, it must not be inside a transaction: the `COMMIT` would also commit the caller's work.

## 4. Bind AI SDK tools to the tenant

```ts
import { tool } from "ai";
import { z } from "zod";
import { bindTenant, withTenant } from "@db-firewall/pg";

const tools = {
  listDocs: tool({
    description: "List the user's documents",
    inputSchema: z.object({ search: z.string() }),   // no tenant field: the model never picks it
    execute: async ({ search }) =>
      withTenant(db, async (tx) => tx.select().from(docs).where(ilike(docs.title, `%${search}%`))),
  }),
};

// Per request, with the tenant from your auth session:
const result = await generateText({ model, tools: bindTenant(tools, session.tenantId), prompt });
```

`bindTenant` wraps each tool's `execute` so that `withTenant(db, fn)` inside it uses the bound tenant. A tool called outside `bindTenant` throws (`no tenant`). Concurrent requests keep separate tenants (AsyncLocalStorage).

`runWithTenant(tenantId, fn)` does the same for any code path, for example a job or an MCP tool handler.

## Tenant ids

These are refused, with the same rules as the Python middleware:
- an empty string or a value that is not a string;
- NUL, newline or backslash characters;
- `__BYPASS__` in any letter case.

## Tests

The tests run against a live PostgreSQL, with the real migration installed:

```bash
cd packages/ts
npm ci
DBFW_PG_URL="postgres://postgres@localhost:5432/dbfw_test" npm test
```

They cover each driver, the pooled-connection leak, rollback, cross-tenant writes, the role check, and tool binding with concurrent tenants, including through the AI SDK's `generateText` with a mock model that tries to name another tenant. Without `DBFW_PG_URL`, only the tests that need no database run.
