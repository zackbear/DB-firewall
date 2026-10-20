---
name: db-firewall
description: This skill should be used whenever a project has database access that needs tenant isolation and AI agent protection. Trigger when the codebase contains PostgreSQL, MySQL, SQL Server, Oracle, or SQLite databases; ORMs (SQLAlchemy, Django ORM, Prisma, Sequelize, TypeORM, Drizzle); MCP servers with database access; multi-tenant architecture with tenant_id columns; row-level security (RLS) requirements; or any AI agent, LLM tool, or LangChain component that queries a database. Covers middleware integration, database-level RLS/VPD migrations, CI/CD security scanning, and MCP server wrapping.
---

# DB Firewall — Universal AI Agent Tenant Isolation

Enforces tenant isolation at the database level so AI agents, MCP servers, and LLM tools cannot access data outside their assigned tenant — regardless of what query they generate.

## Before You Start

Assess these before implementing — they determine which layers you need:

| Question | If Yes | If No |
|----------|--------|-------|
| Does the ORM support connection-level context variables? | Middleware works fully | Raw SQL queries bypass middleware; use DB-level RLS as primary layer |
| Is the agent running as the same DB user as the app? | **Must separate them first** — shared user breaks per-tenant revocation | Proceed to migration |
| Are there existing raw SQL queries in the codebase? | RLS must be primary layer; middleware alone won't filter these | Middleware-only may suffice |
| Is this PostgreSQL? | Run `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` for each table AND create policies — both required | See engine-specific notes in migration files |

## NEVER Do These

- **NEVER fail open** — if tenant context is missing, return zero rows; never fall back to returning all rows "just in case"; an empty result is always safer than a cross-tenant data leak
- **NEVER protect only SELECT** — INSERT without tenant_id creates orphaned rows; DELETE without tenant_id can silently wipe other tenants' data; all DML (SELECT, INSERT, UPDATE, DELETE) must be filtered
- **NEVER give the AI agent admin database credentials** — RLS and VPD policies do NOT fire for superusers/DBA roles in PostgreSQL and Oracle; the agent's DB user must be unprivileged
- **NEVER rely on application-layer filtering alone** — when the agent is compromised, hallucinates, or bugs out, application code fails; the database must enforce isolation independently as a second layer
- **NEVER share a DB user across tenants** — the `_firewall_tenant_map` must map one DB user per tenant; shared credentials make audit logs meaningless and break per-tenant revocation
- **NEVER skip the CI scanner** — new tables added without RLS policies are silent cross-tenant leaks; the scanner is the only automated check that catches them before production
- **NEVER use `SET` instead of `SET LOCAL` for tenant context in transactions** — `SET` persists across transaction boundaries in connection pools; a pooled connection reused by another tenant inherits the previous tenant's context. The middleware uses `set_config(..., true)` (transaction-local), so it refuses autocommit connections; release wrapped connections via `release()`/`close()` and hook `pool_checkin` into the pool
- **NEVER hardcode bypass roles** — `excluded_users` and the `_firewall_bypass_roles` table are empty by default; on Supabase/Neon/RDS the app connects as `postgres`, so a built-in `postgres` bypass disables every policy. Opt roles in explicitly, and never run the agent as the table owner, a superuser or a `BYPASSRLS` role
- **NEVER assume policy creation equals enforcement in PostgreSQL** — `CREATE POLICY` alone is insufficient; you must also run `ALTER TABLE your_table ENABLE ROW LEVEL SECURITY` separately, or the policy exists but silently does nothing

## Step 1: Add Config and Point to It

Copy `config/firewall.yaml` to `.db-firewall.yaml` in the project, then set `DB_FIREWALL_CONFIG` to its full path (or pass `load_config(project_root=...)`). The firewall never searches the current or home folder. With no path set, it runs on built-in defaults. Required customizations:

| Field | Action |
|-------|--------|
| `tenant_column` | Match the project's actual column name (e.g. `org_id`, `company_id`) |
| `excluded_tables` | Add migration/audit/config tables that are legitimately cross-tenant |
| `excluded_users` | Leave empty unless a specific role (e.g. `_migrator`) must bypass; mirror it in `_firewall_bypass_roles` |
| `fail_mode` | **ALWAYS set to `closed` for production** — `open` is for local dev only |

## Step 2: Run the Database Migration

**MANDATORY — read the full migration file before executing it.**

Select based on detected database engine:

| Engine | Migration File | Notes |
|--------|---------------|-------|
| PostgreSQL | `migrations/001_postgresql.sql` | Native RLS — read entire file, contains policy + role setup |
| MySQL / MariaDB | `migrations/002_mysql.sql` | Views + triggers — read entire file, order matters |
| SQL Server | `migrations/003_sqlserver.sql` | Native RLS — read entire file, contains security predicate functions |
| Oracle | `migrations/004_oracle.sql` | VPD — read entire file, parameter order is exact and non-negotiable |
| SQLite | No migration needed | Middleware-only enforcement — skip to Step 3 |

**Do NOT load** migration files for database engines not present in the project.

## Step 3: Integrate the Middleware

Read `middleware/db_firewall.py` before integrating — it contains the full API surface.

Select the integration pattern for the detected framework:

**Python (any framework):**
```python
from db_firewall import protect
conn = protect(raw_connection, tenant_id="TENANT_A")
```

**Django:**
```python
# myapp/middleware.py — build the class once, then reference it by dotted path
from db_firewall import django_middleware_class
TenantMiddleware = django_middleware_class()   # default: request.tenant_id or session["tenant_id"]

# settings.py — after your auth middleware, so request.tenant_id is set
MIDDLEWARE = [..., 'myapp.middleware.TenantMiddleware']
```

**FastAPI:**
```python
from db_firewall import fastapi_middleware
# tenant_id_source: callable(request) -> tenant from a VERIFIED source (JWT claim, session)
fastapi_middleware(app, tenant_id_source=lambda req: req.state.user.tenant_id)
```

**Flask:**
```python
from db_firewall import flask_hooks
# tenant_id_source: callable that extracts tenant from Flask request context
flask_hooks(app, tenant_id_source=lambda: g.tenant_id)
```

All three web integrations ignore `X-Tenant-ID` unless you pass
`trust_tenant_header=True` (or set it in config), and never read `?tenant_id=`.
Any client can send that header, so trust it only behind a gateway that
authenticates the caller and overwrites any client-sent value. Register
`flask_hooks(app)` after your auth hook. Jobs sent to your own thread pool need
`contextvars.copy_context().run(...)` to see the request's tenant.

**SQLAlchemy:**
```python
from db_firewall import sqlalchemy_event_hooks
sqlalchemy_event_hooks(engine)
```

**MCP Server wrapping** (read `hooks/mcp_wrapper.py` first — **Do NOT load if the project has no MCP server**):
```json
{
  "command": "python",
  "args": ["-m", "db_firewall.mcp_wrapper", "--tenant", "TENANT_A",
           "--", "npx", "-y", "@mcp/server-postgres", "postgresql://..."]
}
```

## Step 4: Add CI/CD Scanner

**MANDATORY for production deployments.** Add to the deployment pipeline:

```yaml
- name: DB Firewall Security Check
  run: python -m db_firewall.scanner --dsn $DATABASE_URL --strict
```

The scanner detects tables without RLS policies applied. `--strict` fails the build on any unprotected table. Run `hooks/scanner.py` locally first to review output before adding to CI.

## Step 5: Seed Tenant Mappings

The migration files create `_firewall_tenant_map` automatically. For greenfield projects without a migration run yet:

```sql
CREATE TABLE IF NOT EXISTS _firewall_tenant_map (
  db_user  TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL
);

INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES ('mcp_service', 'TENANT_A');
INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES ('ai_agent_svc', 'TENANT_B');
```

One row per DB user. Never share a DB user between tenants.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| RLS not firing; all rows returned | DB user is a superuser or has `BYPASSRLS` attribute | Create an unprivileged role; never use superuser for agent connections |
| RLS not firing; policy exists | `ENABLE ROW LEVEL SECURITY` was not run on the table | `ALTER TABLE your_table ENABLE ROW LEVEL SECURITY` |
| Tenant context bleeds between requests | Using `SET` instead of `SET LOCAL` for context variable, or connection returned to pool without `release()` | Use `set_config(..., true)`/`SET LOCAL`; call `release()` on the wrapper; add `pool_checkin` as the pool reset hook |
| `RuntimeError: ... autocommit` from `protect()` on Postgres | Transaction-local context needs an open transaction | `connection.autocommit = False`, or use `tenant_scope()` with middleware-only enforcement |
| All rows visible although policies exist | Role listed in `_firewall_bypass_roles`, or app connects as owner/superuser/`BYPASSRLS` | Remove the row; connect the app as an unprivileged role |
| Middleware filtering but raw SQL queries bypass it | Raw SQL not routed through middleware connection wrapper | Add `protect()` to all connection acquisition paths; use DB-level RLS as primary layer |
| INSERT rows have NULL tenant_id despite firewall | Policy only filters SELECT; INSERT policy is missing | Add a separate `WITH CHECK` policy or use a trigger to stamp tenant_id on INSERT |
| CI scanner passes but new table leaks data | Scanner only checks tables with existing rows (empty tables skipped) | Run `--strict --include-empty` to check schema-only tables |

## NoSQL Stores (MongoDB, Redis, Firestore, Convex)

The SQL middleware does not apply. Use `adapters/` (read the module docstring first; drivers import lazily):

| Store | Call | Second layer |
|-------|------|--------------|
| MongoDB | `adapters.mongodb.protect_collection(col, tenant_id)` / `protect_database(db, tenant_id)` | None — use per-tenant DB users |
| Redis | `adapters.redis.protect_redis(client, tenant_id)` | `client.acl_setuser(**acl_setuser_args(tenant_id, password))` |
| Firestore | `adapters.firestore.protect_firestore(client, tenant_id, mode="subcollection")` | Write `generate_rules()` to `firestore.rules`; gate with `hooks.scanner --firestore-rules` |
| Convex | Copy `adapters/convex/tenant.ts`; use `tenantQuery`/`tenantMutation` and `ctx.tdb` | N/A — enforcement is the Convex function itself |

- **NEVER** hand the agent `.raw` — it is the unscoped client.
- **NEVER** use a tenant id containing `* ? [ ] : \` with Redis, or `/` with Firestore; the adapters reject them.
- Firestore `collection_group()` and Mongo `allow_cross_collection=True` are the two places scoping depends on the data, not the path — stamp `tenant_id` on every document.
- Only MongoDB (mongomock) and Redis (real server) adapters are exercised by tests; Firestore runs against a fake client and Convex is type-checked only.
