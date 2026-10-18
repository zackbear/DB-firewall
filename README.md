# 🛡️ DB Firewall — Universal AI Agent Tenant Isolation

**One config file. Any database. Any agent. Automatic enforcement.**

When you give an AI agent access to your database, it will happily run `SELECT * FROM orders` and return *everyone's* data. DB Firewall adds an **invisible WHERE clause** at the database layer so agents can only see their tenant's rows — no matter what SQL they generate.

> Based on ["The Invisible Firewall" by Arunkumar Moola Balaji](https://medium.com/@arunkumar.mb/the-invisible-firewall-securing-ai-agents-with-oracle-vpd-180b361e2478), extended to work universally across all databases and AI agent frameworks.

---

## Quick Start

### 1. Drop the config into your project root

```bash
cp config/firewall.yaml .db-firewall.yaml
```

### 2. Run the migration for your database

```bash
# PostgreSQL
psql -f migrations/001_postgresql.sql

# MySQL
mysql < migrations/002_mysql.sql

# SQL Server
sqlcmd -i migrations/003_sqlserver.sql

# Oracle
sqlplus sys/pass@db @migrations/004_oracle.sql
```

### 3. Wrap your connections

```python
from db_firewall import protect

conn = psycopg2.connect("postgresql://...")
safe_conn = protect(conn, tenant_id="TENANT_A")

# Every query is now silently filtered
cursor = safe_conn.cursor()
cursor.execute("SELECT * FROM orders")  # Returns ONLY Tenant A's orders
```

---

## How It Works

```bash
┌─────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  AI Agent    │────▶│  DB Firewall │────▶│     Database          │
│  (MCP/Lang-  │     │  Middleware   │     │                      │
│   Chain/etc) │     │              │     │  ┌──────────────────┐ │
│              │     │  Rewrites:   │     │  │ Native RLS/VPD   │ │
│  SELECT *    │     │  adds WHERE  │     │  │ (second layer)   │ │
│  FROM orders │     │  tenant_id=  │     │  └──────────────────┘ │
│              │     │  'TENANT_A'  │     │                      │
└─────────────┘     └──────────────┘     └──────────────────────┘
                    ▲ Layer 1            ▲ Layer 2
                    Middleware            Database-native
                    (all engines)         (Postgres/SQL Server/Oracle)
```

**Two layers of defense:**

1. **Middleware** — Rewrites SQL before it reaches the database (works with ALL engines)
2. **Database-native** — RLS (Postgres, SQL Server) or VPD (Oracle) as a second enforcement layer

Even if the middleware is bypassed, the database-native layer still blocks cross-tenant access.

---

## Supported Databases

| Database | Native Security | Middleware | Migration Script |
| --- | --- | --- | --- |
| **PostgreSQL** 9.5+ | ✅ Row-Level Security | ✅ | `001_postgresql.sql` |
| **MySQL** 5.7+ / MariaDB | ❌ (Views + Triggers) | ✅ | `002_mysql.sql` |
| **SQL Server** 2016+ | ✅ Security Policies | ✅ | `003_sqlserver.sql` |
| **Oracle** 10g+ | ✅ Virtual Private Database | ✅ | `004_oracle.sql` |
| **SQLite** | ❌ | ✅ (middleware only) | None needed |

## Supported Frameworks

| Framework | Integration |
| --- | --- |
| **Raw DB-API** | `protect(connection)` |
| **SQLAlchemy** | `sqlalchemy_event_hooks(engine)` |
| **Django** | Middleware class |
| **FastAPI** | `fastapi_middleware(app)` |
| **Flask** | `flask_hooks(app)` |
| **MCP Servers** | `mcp_wrapper.py` stdio proxy |
| **LangChain** | Wrap the connection before passing to agent |

---

## MCP Server Protection

Wrap any MCP database server to auto-inject tenant isolation:

**Before (UNSAFE):**

```json
{
  "sql_mcp": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
  }
}
```

**After (PROTECTED):**

```json
{
  "sql_mcp": {
    "command": "python",
    "args": [
      "-m", "hooks.mcp_wrapper",
      "--tenant", "TENANT_A",
      "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://..."
    ]
  }
}
```

---

## CI/CD Security Gate

Add the scanner to your pipeline to **fail the build** if unprotected tables exist:

```yaml
# GitHub Actions
- name: DB Firewall Security Scan
  run: python -m hooks.scanner --dsn $DATABASE_URL --strict

# GitLab CI
db-security-check:
  script: python -m hooks.scanner --dsn $DATABASE_URL --strict

# Docker
RUN python -m hooks.scanner --dsn $DATABASE_URL --strict
```

The scanner returns exit code 1 if ANY table with a `tenant_id` column is missing RLS/VPD protection.

---

## Configuration

Create `.db-firewall.yaml` in your project root:

```yaml
version: "1.0"
tenant_column: "tenant_id"
fail_mode: "closed"           # "closed" = no tenant → 0 rows (SAFE)

protect:
  select: true
  insert: true
  update: true
  delete: true

audit:
  enabled: true
  retention_days: 90

excluded_users: []            # EMPTY by default — see "Bypass roles" below

excluded_tables:
  - "_firewall_*"
  - "schema_migrations"
  - "app_config"
```

### Bypass roles (excluded users)

Nothing bypasses the firewall by default. Earlier versions hardcoded `postgres`, `root`, `sa`, `admin`, `_migrator`; on Supabase, Neon, RDS and most managed databases the **application itself** connects as `postgres`, which silently disabled every policy.

Opt a role in deliberately, at both layers:

```yaml
# middleware layer (.db-firewall.yaml)
excluded_users: ["_migrator"]
```

```sql
-- database layer (created by the migrations, empty by default)
INSERT INTO _firewall_bypass_roles (role_name) VALUES ('_migrator');
```

Postgres, MySQL and SQL Server migrations all consult `_firewall_bypass_roles`. Oracle's VPD function has no bypass list (use `EXEMPT ACCESS POLICY` deliberately if needed).

Independently of this table, PostgreSQL **superusers, roles with `BYPASSRLS`, and the table owner** are never subject to RLS (the migration uses `FORCE ROW LEVEL SECURITY`, which covers owners, but not superusers/`BYPASSRLS`). If you want DB-native enforcement, do not connect the app as the database owner or a superuser; the middleware layer still applies either way.

### Connection pooling

Tenant context is cleared when a connection goes back to the pool. Three rules:

1. **PostgreSQL context is transaction-local** (`set_config(..., true)`), so it dies on `commit`/`rollback` and cannot leak to the next borrower. It therefore needs an open transaction: the DB-API default (`autocommit=False`) opens one implicitly. `protect()` raises `RuntimeError` on an autocommit connection instead of silently falling back. Set the context again (`protect()`) after each commit if you issue more tenant queries on the same connection.
2. **Release through the wrapper.** `ProtectedConnection.release()` (also run by `close()` and `__exit__`) clears the DB-side context on every engine (`set_config('',false)`, `SET @_fw_tenant_id = NULL`, `sp_set_session_context ... NULL`, `PKG_SAAS_SECURITY.clear_tenant`) and the thread-local. `release()` does not close or commit the underlying connection.
3. **Hook `pool_checkin` into your pool** as a belt for anything that bypassed the wrapper:

```python
from db_firewall import pool_checkin, sqlalchemy_event_hooks

# psycopg_pool
pool = ConnectionPool(dsn, reset=pool_checkin)

# SQLAlchemy — sqlalchemy_event_hooks(engine) already does this:
# sets context per checkout and runs pool_checkin on checkin
sqlalchemy_event_hooks(engine)
```

A failure to set the DB-side context raises when `fail_mode: closed` (the default); it only degrades to middleware-only enforcement with a warning when `fail_mode: open`.

---

## Security Principles

| Principle | Implementation |
| --- | --- |
| **Fail closed** | No tenant context = 0 rows returned. Never defaults to "show all". |
| **Defense in depth** | Middleware + database-native RLS/VPD. Two independent layers. |
| **Full DML protection** | SELECT, INSERT, UPDATE, AND DELETE are all filtered. |
| **Audit trail** | Every tenant assignment logged with session, IP, timestamp. |
| **Zero trust the agent** | The AI doesn't know about tenancy. The database enforces it. |
| **Connection pool safe** | Postgres context is transaction-local; every engine is cleared on `release()`/`pool_checkin`. See "Connection pooling". |

---

## Project Structure

```bash
db-firewall/
├── config/
│   └── firewall.yaml            # Default configuration + documentation
├── migrations/
│   ├── 001_postgresql.sql        # PostgreSQL native RLS (auto-applies to all tables)
│   ├── 002_mysql.sql             # MySQL secure views + triggers
│   ├── 003_sqlserver.sql         # SQL Server security policies
│   └── 004_oracle.sql            # Oracle VPD (production-hardened)
├── middleware/
│   └── db_firewall.py            # Universal Python middleware (DB-agnostic)
├── hooks/
│   ├── mcp_wrapper.py            # MCP server stdio proxy with SQL rewriting
│   └── scanner.py                # CI/CD security scanner
├── tests/
│   ├── test_firewall.py          # SQL rewriting / context unit tests
│   ├── test_rewrite_safety.py    # tenant-id injection safety
│   └── test_pool_leak.py         # Postgres pool-leak proof (opt-in: DBFW_PG_DSN)
├── SKILL.md                      # Auto-integration trigger for AI workflows
└── README.md                     # This file
```

---

## License

MIT — Use this in every production system you build. No excuses.

---

## NoSQL stores

The SQL middleware rewrites `WHERE`; document/key stores have nothing to rewrite, so `adapters/` wraps the client object instead and, where the store supports it, emits a server-side policy as the second layer. Same contract as `protect()`: no tenant → `TenantRequired`; unknown methods never fall through to the raw client; `.raw` is the explicit admin escape hatch. Drivers are imported lazily — `pip install -r requirements-adapters.txt` only for what you use.

| Store | Enforcement layer | What's blocked | Tested with |
| --- | --- | --- | --- |
| **MongoDB** | Middleware only (`{'$and': [{tenant_id: T}, user_filter]}`, docs stamped on write) | `$set/$unset/$rename/$inc` on `tenant_id`, foreign `tenant_id` in filters/docs, pipeline-form updates, `$lookup/$unionWith/$graphLookup/$facet/$merge/$out` (unless `allow_cross_collection=True`), `drop/rename/watch/map_reduce`, any unwrapped method | `mongomock` 4.3 (no real `mongod`) |
| **Redis** | Middleware (key prefix `tenant:<T>:`) **+ server ACL** (`~tenant:<T>:*`) | `keys`-less `scan`, `flushdb/flushall`, `eval/evalsha/script/function`, `config`, `dbsize`, `randomkey`, `migrate/move/swapdb/select`, `info`, unknown `execute_command`s; tenant ids containing `* ? [ ] : \` | Real Redis 7.0 incl. ACL user isolation |
| **Firestore** | Middleware (path `tenants/<T>/...` or `where(tenant_id==T)` + post-read verify) **+ `firestore.rules`** | `client.document(path)`, `transaction()`, `collections()`, foreign-tenant `where`, `set/update` that change `tenant_id`, batch refs outside the tenant | In-memory fake client only (**not** run against the emulator) |
| **Convex** | Inside Convex functions (TypeScript `tenantQuery/tenantMutation/tenantAction`) | Missing tenant claim, foreign `tenantId` on insert/patch/replace, `get/patch/replace/delete` of foreign docs | `tsc --noEmit` only (convex 1.47, convex-helpers 0.1.128); **no runtime test** |

**MongoDB**
```python
from adapters.mongodb import protect_collection, protect_database
orders = protect_collection(db.orders, tenant_id="TENANT_A")   # or protect_database(db, "TENANT_A").orders
orders.find({"status": "open"})                 # {'$and': [{'tenant_id': 'TENANT_A'}, {...}]}
orders.insert_one({"total": 5})                 # tenant_id stamped; a foreign tenant_id raises
orders.aggregate([{"$group": ...}])             # $match on tenant prepended; $lookup/$out refused
```
Known gaps: no server-side layer (use per-tenant databases/users for defense in depth); `$where`/`$expr` are passed through (they cannot widen the `$and`, but can be slow); aggregation stages allowed with `allow_cross_collection=True` are not scoped on the foreign collection.

**Redis**
```python
from adapters.redis import protect_redis, acl_setuser_args
r = protect_redis(redis.Redis(), tenant_id="TENANT_A")   # keys become tenant:TENANT_A:<key>
r.set("cart", "..."); r.keys("*"); r.pipeline().incr("hits").execute()
r.flushdb()                                               # TenantRequired
admin.acl_setuser(**acl_setuser_args("TENANT_A", password="..."))   # stronger: server refuses foreign keys
```
Known gaps: Pub/Sub channels, Streams (`XADD`…) and HyperLogLog are not in the command table (they raise); Lua is blocked outright; the ACL layer cannot scope `SCAN`, so it denies it (drop `-scan` if tenants need iteration via the middleware).

**Firestore**
```python
from adapters.firestore import protect_firestore, generate_rules
fs = protect_firestore(client, "TENANT_A")                    # mode="subcollection" (default) or "field"
fs.collection("orders").document("o1").set({...})             # -> tenants/TENANT_A/orders/o1
fs.collection_group("orders")                                 # auto where(tenant_id == T): docs MUST carry the field
open("firestore.rules", "w").write(generate_rules(tenant_claim="tenant_id"))
python -m hooks.scanner --firestore-rules firestore.rules     # CI: fails on any `if true` rule
```
Known gaps: in subcollection mode the returned references are raw, so `.parent.parent` can walk out of the tenant path (the rules file is the real boundary there); field mode does a read-before-write on `set/update/delete` (one extra read, not transactional); `where(filter=FieldFilter(...))` keyword form is not inspected (the tenant `where` is still ANDed in).

**Convex** — see `adapters/convex/README.md`. Copy `tenant.ts` into `convex/`, add `tenantId` + `.index("by_tenant", ["tenantId"])` to each table, and use `ctx.tdb` instead of `ctx.db`.
