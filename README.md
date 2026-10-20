# 🛡️ DB Firewall — Universal AI Agent Tenant Isolation

**One config file. Any database. Any agent. Automatic enforcement.**

When you give an AI agent access to your database, it will happily run `SELECT * FROM orders` and return *everyone's* data. DB Firewall adds an **invisible WHERE clause** at the database layer so agents can only see their tenant's rows — no matter what SQL they generate.

> Based on ["The Invisible Firewall" by Arunkumar Moola Balaji](https://medium.com/@arunkumar.mb/the-invisible-firewall-securing-ai-agents-with-oracle-vpd-180b361e2478), extended to work universally across all databases and AI agent frameworks.

---

## Quick Start

### 1. Install and drop the config into your project root

```bash
pip install -r requirements.txt        # sqlglot (AST rewriter) + pyyaml
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

### What the middleware rewriter scopes

The default rewriter (`rewriter: "ast"`, built on [sqlglot](https://github.com/tobymao/sqlglot)) parses **every** statement that goes through a protected connection; there is no regex pre-filter deciding which statements "look like" they touch a tenant table. Only these statement heads get through:

* `SELECT` / `UNION` / `INTERSECT` / `EXCEPT`, `INSERT`, `UPDATE`, `DELETE` — optionally `WITH`-wrapped or parenthesised. Every reference to a protected table (a table that has the tenant column and is not in `excluded_tables`; unquoted names are case-folded per engine, quoted names keep their case) gets `<alias>.tenant_id = '<tenant>'`, not just the first `FROM`.
* transaction control: `BEGIN` / `START TRANSACTION`, `COMMIT` / `END`, `ROLLBACK` / `ABORT`, `SAVEPOINT`, `RELEASE`, `ROLLBACK TO`.
* `SET` / `RESET` of any setting **except** `app.current_tenant`, `role`, `session_authorization`, `search_path`, `row_security`, `RESET ALL` and MySQL's `@_fw_tenant_id` (so `SET statement_timeout`, `SET TIME ZONE`, `SET LOCAL lock_timeout` work; nothing that moves the tenant or the role does). `set_config()` inside a `SELECT` follows the same list and must name its setting with a literal.
* `SELECT` without tables (`SELECT 1`, `SELECT now()`).

Everything else — `DO`, `CALL`, `EXECUTE`, `PREPARE`, `DECLARE`, `EXPLAIN`, `SHOW`, `COPY`, `TRUNCATE`, `MERGE`, `VACUUM`, every `CREATE`/`ALTER`/`DROP`/`GRANT`, `TABLE t`, `VALUES`, several statements in one string, `U&"…"` unicode-escaped identifiers/literals, nested `/* /* */ */` comments, anything sqlglot cannot parse — raises `PermissionError` while a tenant is set, whatever tables it names. With no tenant and `fail_mode: closed` the same allow-list applies and any statement touching a protected table is refused.

Shapes the rewriter scopes:

| Shape | Result |
| --- | --- |
| `SELECT … FROM t [WHERE …]`, `UPDATE t …`, `DELETE FROM t …` | predicate ANDed into `WHERE` (existing `OR`s are parenthesised) |
| `JOIN` (inner, comma, cross), self-joins with aliases | one predicate per reference, qualified by its alias |
| `LEFT JOIN t` / left side of `RIGHT JOIN` | predicate goes into that join's `ON`, so outer-join semantics are kept |
| `FULL JOIN`, `JOIN … USING`, `NATURAL JOIN` | predicate goes into `WHERE` (always safe; may drop NULL-extended rows) |
| `UNION` / `INTERSECT` / `EXCEPT` | every branch scoped |
| `WITH … AS (…)` (incl. `RECURSIVE`, data-modifying CTEs) | CTE bodies and the main query scoped; CTE names are never treated as tables |
| subqueries in `WHERE` / `SELECT` list, derived tables, `LATERAL (…)`, `EXISTS` | scoped in their own scope |
| `UPDATE t … FROM other`, `DELETE FROM t USING other`, MySQL multi-table forms | target and sources all scoped |
| `INSERT INTO t (cols) VALUES (…)` / `SELECT …` / `… RETURNING` | `tenant_id` appended to the column list and stamped into every row / branch; the `SELECT` source is scoped |
| `INSERT … (…, tenant_id, …)` with the right literal | left alone; a different literal is refused |
| `INSERT … (…, tenant_id, …) VALUES (…, %s)` (placeholder in the tenant column) | **refused** unless `allow_tenant_placeholder: true` — the bound value is the caller's, and only Postgres RLS `WITH CHECK` would verify it |
| `INSERT … ON CONFLICT DO UPDATE SET …` | `AND <target>.tenant_id = '<tenant>'` is added to the `DO UPDATE … WHERE`, so a conflict with another tenant's row updates nothing; assigning the tenant column there is refused. MySQL `ON DUPLICATE KEY UPDATE` has no `WHERE` and is refused on protected tables |
| driver placeholders `%s`, `%(name)s`, `$1`, `?`, `?1`, `:name`, `:1` | preserved byte-for-byte (`?` is a jsonb operator on PostgreSQL, so it is not a placeholder there) |
| SQL comments | stripped from the rewritten statement |
| statements touching only excluded / non-tenant tables | returned unchanged |

Still **refused** (`PermissionError`, fail closed) because they cannot be proven scoped:

* more than one statement; anything sqlglot cannot parse (incl. unterminated literals and backslash-escaped quotes, which mean different things per engine)
* `SELECT … INTO` and every statement head outside the allow-list above (DDL included — run migrations on an unprotected connection)
* `INSERT` without a column list / `DEFAULT VALUES`; `INSERT … SELECT *` when the column list already names `tenant_id`; an `INSERT` literal, `UPDATE … SET`, `ON CONFLICT DO UPDATE SET` or `ON DUPLICATE KEY UPDATE` that assigns a different tenant (or a placeholder) to the tenant column; tuple assignments that include it (`SET (a, tenant_id) = (…)` / `= ROW(…)` / `= (SELECT …)`)
* table-valued functions in `FROM` (`generate_series(…)`), a bare table in parentheses `(t) AS x`, a column-list alias on a protected table (`t AS x(a, b)` renames the tenant column), the same unaliased table twice in one scope

**Metadata lookups fail closed.** Whether a table carries the tenant column is read from the catalog once per table and cached per connection (cleared by `protect()`) and per DSN for 60 s. A lookup that errors — permission denied, an aborted transaction from an earlier failed statement, a dead connection — raises `PermissionError` and is never cached, so a transient error can never demote a table to "unprotected". Inside an open transaction the lookup runs in its own `SAVEPOINT`, as does the `_firewall_tenant_map` probe in `protect()`, so neither can abort the caller's transaction. On an engine the middleware cannot introspect (`DBEngine.UNKNOWN`) every non-excluded table counts as protected and the lookup refuses the query.

**Driver entry points.** `ProtectedConnection` mediates `cursor()`, `execute()`, `executemany()`, `stream()`, `copy()` and `pipeline()`; `ProtectedCursor` mediates `execute()`, `executemany()`, `stream()` and `copy()`, all through one guard that applies the rewrite (tenant set) or the fail-closed check (no tenant). Any other attribute named like a SQL entry point (`execute*`, `copy*`, `executescript`, `callproc`, `exec_driver_sql`, …) raises `PermissionError` instead of being delegated, so a driver method the wrapper does not know cannot bypass it. The SQLAlchemy hook registers `before_cursor_execute` with `retval=True`, so the scoped statement is the one that executes.

`rewriter: "regex"` (or `DB_FIREWALL_REWRITER=regex`) keeps the old dependency-free injector: it handles single-table statements and refuses every multi-scope shape above. With `rewriter: "ast"` and sqlglot missing, `protect()`'d queries raise `ImportError` rather than silently downgrading.

In both modes the database-native RLS/VPD policy remains the second layer: the rewriter can only narrow a query, never widen it, and a statement that slips past it unscoped still hits the row policy.

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
| **Django** | `django_middleware_class(tenant_id_source=...)` |
| **FastAPI** | `fastapi_middleware(app, tenant_id_source=...)` |
| **Flask** | `flask_hooks(app, tenant_id_source=...)` |
| **MCP Servers** | `mcp_wrapper.py` stdio proxy |
| **LangChain** | Wrap the connection before passing to agent |

Web integrations take the tenant from a verified source: `tenant_id_source`, or
by default `request.tenant_id` / the session (Django), `request.state.tenant_id`
(FastAPI), `g.tenant_id` / the session (Flask). Each request starts with exactly
that tenant, or none, and restores the previous context when it ends.

- **Header:** `X-Tenant-ID` is ignored unless `trust_tenant_header: true`, because
  any client can send it. Enable it only behind a gateway that authenticates the
  caller and **overwrites** any client-sent `X-Tenant-ID`. `?tenant_id=` is never read.
- **Concurrency:** the tenant lives in a `ContextVar`. Concurrent asyncio requests
  and FastAPI/Starlette sync endpoints each see their own tenant. Jobs you submit to
  your own `ThreadPoolExecutor` do not inherit it: wrap them with
  `contextvars.copy_context().run(...)`.
- **Flask:** call `flask_hooks(app)` after registering your auth `before_request`
  hook, on the app rather than a blueprint.
- **Streaming responses:** Django streaming bodies run as the request's tenant.
  Flask runs teardown before a streaming body is read, so a Flask generator must
  open its own `tenant_scope(tenant)` or use `protect(conn, tenant_id=...)`.
  Django async streaming bodies under ASGI are not covered yet.
- **Outside requests:** prefer `tenant_scope(...)` or `protect(conn, tenant_id=...)`
  over a bare `set_tenant()`, which stays set for the rest of that thread or task.
- **`fail_mode: open`:** a request with no verified tenant runs unscoped. Use
  `closed` in production; the web integrations log a warning when they see `open`.

> **Upgrading:** earlier versions read `X-Tenant-ID` (and `?tenant_id=` on FastAPI
> and Flask) from every request. If you relied on that, pass `tenant_id_source=...`,
> or set `trust_tenant_header: true` behind an authenticating gateway. Until then,
> such requests have no tenant: blocked with `fail_mode: closed`, unscoped with
> `open`. The first ignored header is logged as a warning.
>
> `protect(conn, tenant_id="A")` no longer sets the shared tenant, so a later
> `protect(other_conn)` without a tenant does not inherit "A". It falls back to
> the `TENANT_ID` environment variable or `_firewall_tenant_map`, then fails
> closed. Pass `tenant_id=` to every `protect()` call, or wrap the work in
> `tenant_scope("A")`.

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

What the wrapper does with each line from the agent:

- `tools/call`: every string that looks like SQL is scoped to the tenant, under any argument name and at any depth (nested objects, lists). A string counts as SQL when its first word is a SQL statement keyword, or when it holds a comment marker (`/*`, `--`, `#`) and any keyword.
- SQL the rewriter cannot scope (DDL, multiple statements, `COPY`, `CALL`, ...) gets a JSON-RPC error and never reaches the server.
- A line that is not a JSON object or array is dropped, not passed through.
- Limit: prose that starts with a keyword ("Update the report") is treated as SQL, so it is rewritten or refused.
- Defence in depth: run the migrations and give the wrapped server a role without `BYPASSRLS`, so row-level security still blocks anything a string check misses.

> **Upgrading:** earlier versions rewrote only the top-level `query`, `sql`,
> `statement`, `command` and `code` arguments, passed non-JSON lines through
> unchanged, and stopped proxying after the first refused query. The
> `migrate` and `check` commands of `middleware/db_firewall.py` did nothing
> and are removed: apply migrations with `psql`/`mysql`/`sqlcmd` or
> `run_migration(conn)`, and audit with `hooks/scanner.py`. `run_migration()`
> now finds `migrations/` and raises `FileNotFoundError` instead of logging.
> The PostgreSQL scanner failed on every run (a literal `%` in a parameterised
> query) and, had it run, accepted unforced RLS and a single policy. It now
> uses psycopg 3 when installed, else psycopg2.

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

The scanner returns exit code 1 if ANY table with a `tenant_id` column is missing RLS/VPD protection. On PostgreSQL a table counts as protected only when row-level security is enabled AND forced (table owners bypass unforced RLS) and all four firewall policies (select, insert, update, delete) exist on that exact `public.<table>`. The JSON report lists `missing_policies` and `rls_forced`.

---

## Configuration

Create `.db-firewall.yaml` in your project root:

```yaml
version: "1.0"
tenant_column: "tenant_id"
fail_mode: "closed"           # "closed" = no tenant → 0 rows (SAFE)
rewriter: "ast"               # "ast" (sqlglot, default) or "regex" (legacy, no dependency)
allow_tenant_placeholder: false   # INSERT ... (tenant_id) VALUES (%s) is refused unless true

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
2. **Release through the wrapper.** `ProtectedConnection.release()` (also run by `close()` and `__exit__`) clears the DB-side context on every engine (`set_config('',false)`, `SET @_fw_tenant_id = NULL`, `sp_set_session_context ... NULL`, `PKG_SAAS_SECURITY.clear_tenant`) and leaves the request's tenant context alone (a wrapped connection never changes it; its cursors carry their own tenant). `release()` does not close or commit the underlying connection.
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
| **Full DML protection** | SELECT, INSERT, UPDATE, AND DELETE are all filtered — every table reference, in every CTE, branch and subquery. |
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
│   ├── db_firewall.py            # Universal Python middleware (DB-agnostic)
│   └── sql_rewriter.py           # sqlglot AST rewriter (scopes every table reference)
├── hooks/
│   ├── mcp_wrapper.py            # MCP server stdio proxy with SQL rewriting
│   └── scanner.py                # CI/CD security scanner
├── tests/
│   ├── test_firewall.py          # SQL rewriting / context unit tests
│   ├── test_sql_rewriter.py      # AST rewriter: structural proof per shape (no DB)
│   ├── test_rewrite_safety.py    # tenant-id injection safety
│   ├── test_sqlalchemy_hook.py   # SQLAlchemy hook actually swaps the statement (sqlite, no DB)
│   ├── test_pool_leak.py         # Postgres pool-leak + rewriter-vs-RLS e2e (opt-in: DBFW_PG_DSN)
│   └── test_gate_live.py         # middleware alone vs RLS-less tables as dbfw_app (opt-in: DBFW_PG_DSN)
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
