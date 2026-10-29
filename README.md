# 🛡️ DB Firewall — Universal AI Agent Tenant Isolation

**One config file. Any database. Any agent. Automatic enforcement.**

When you give an AI agent access to your database, it will happily run `SELECT * FROM orders` and return *everyone's* data. DB Firewall adds an **invisible WHERE clause** at the database layer so agents can only see their tenant's rows — no matter what SQL they generate.

> Based on ["The Invisible Firewall" by Arunkumar Moola Balaji](https://medium.com/@arunkumar.mb/the-invisible-firewall-securing-ai-agents-with-oracle-vpd-180b361e2478), extended to work universally across all databases and AI agent frameworks.

---

## Quick Start

### 1. Install and point the firewall at your config

```bash
pip install -r requirements.txt        # sqlglot (AST rewriter) + pyyaml
cp config/firewall.yaml .db-firewall.yaml
export DB_FIREWALL_CONFIG="$PWD/.db-firewall.yaml"
export PYTHONPATH="$PWD/middleware:$PYTHONPATH"   # no pip package yet: import from the checkout
```

> **Upgrading from an earlier version?** Read [CHANGELOG.md](CHANGELOG.md) first.
> Four changes can break an existing setup: the config path, the `X-Tenant-ID`
> header and `protect()` can refuse queries or leave tables unscoped; the CLI
> change breaks scripts that call the removed commands.

### 2. Run the migration for your database

```bash
# PostgreSQL (or run_migration(conn), which passes tenant_column, schema,
# policy_mode, tenant_context and DB_FIREWALL_TENANT_KEY from your config and
# environment). policy_mode: restrictive when the app has RLS policies of its
# own (Supabase, Drizzle pgPolicy); see below. The app needs the same key.
export DB_FIREWALL_TENANT_KEY=$(openssl rand -hex 32)   # store it as a secret
psql -c "SET dbfw.tenant_column = 'tenant_id'" -c "SET dbfw.schema = 'public'" \
     -c "SET dbfw.policy_mode = 'permissive'" -c "SET dbfw.tenant_key = '$DB_FIREWALL_TENANT_KEY'" \
     -f migrations/001_postgresql.sql

# MySQL (or run_migration(conn)). Step 2 creates the views and prints the
# trigger DDL, which step 3 runs: MySQL cannot create a trigger from a routine.
mysql db < migrations/002_mysql.sql
mysql -N -B -r db -e "SET @dbfw_tenant_column = 'tenant_id'; CALL _firewall_apply_all()" | mysql db

# SQL Server (or run_migration(conn)); set the column in the same session first.
# set_col.sql holds one line: EXEC sp_set_session_context N'dbfw.tenant_column', N'tenant_id';
sqlcmd -i set_col.sql,migrations/003_sqlserver.sql

# Oracle: edit SCHEMA_OWNER and TENANT_COLUMN at the top, then run as SYS
sqlplus / as sysdba @migrations/004_oracle.sql
```

Each script protects every table that has the tenant column (PostgreSQL: in the
chosen schema; MySQL: the current database; SQL Server: all schemas; Oracle:
`SCHEMA_OWNER`). Re-run it after adding tables (MySQL: steps 2 and 3).
`run_migration()` handles PostgreSQL, MySQL and SQL Server; Oracle needs sqlplus.
Tested live: PostgreSQL 14, 15, 16 and 17, MySQL 8.4, SQL Server 2022 and Oracle Database Free
23ai (see "Tests" for the live suites).

MySQL has no RLS. Its layer is views plus triggers, keyed on the user variable
`@_fw_tenant_id`:

* A client that can send raw SQL can set that variable (MySQL also accepts
  escaped and accent-folded spellings of its name). So on MySQL the middleware
  refuses every statement with a user variable (an `@` outside single-quoted
  literals and comments, also inside double quotes or backticks) and dynamic
  SQL (`PREPARE`, `EXECUTE`, `DEALLOCATE`, `CALL`, `DO`, `HANDLER`). Pass
  values as parameters or single-quoted literals. The same check runs when
  the engine is not recognised. Agents with a raw connection are not covered.
* On every engine the middleware refuses MySQL/MariaDB executable comments
  (`/*! ... */`, `/*M! ... */`): MySQL runs their text as SQL. On MySQL it
  also refuses `#` comments.
* `rewriter: regex` is refused on MySQL: it has had cross-tenant read
  bypasses, and no database layer stands behind base-table reads. Use the
  default `ast` rewriter.
* Grants for the app user: `SELECT` on the `v_` views; `SELECT`, `INSERT`,
  `UPDATE`, `DELETE` on the base tables (the middleware's `UPDATE`/`DELETE`
  adds a `WHERE` on the tenant column, which needs `SELECT`; the triggers
  check every write); `INSERT` on `_firewall_audit_log` when `audit.enabled`;
  `EXECUTE` only on `_firewall_init_connection` (for pools). So reads of the
  base tables are scoped by the middleware alone; the views are the read path
  the database layer covers. Views and triggers run as their definer, so the
  app needs no other routine. Never grant it `EXECUTE ON db.*`,
  `CREATE TEMPORARY TABLES`, DDL rights, or other rights on the `_firewall_`
  tables.
* A user with a `_firewall_tenant_map` row gets that tenant whenever none is
  set. The map uses the user part of the login (`USER()`, before the first
  `@`): keep no anonymous accounts and no user names that contain `@`.
* The views and triggers compare tenants exactly (`BINARY`). The middleware's
  rewrite uses `=`, which ignores case under MySQL's default collation: keep
  tenant ids unique ignoring case, and use a string tenant column. `BINARY`
  stops the views from seeking on an index of the tenant column, so large
  tables read slower through them.
* Re-running drops and re-creates each trigger, so writes in between are not
  checked, and `CREATE OR REPLACE VIEW` waits for open transactions that read
  the view. Re-run when the app is quiet. It also drops and re-creates the
  routines, and MySQL deletes a routine's grants with it: run the
  `GRANT EXECUTE ON PROCEDURE db._firewall_init_connection` again after each
  run (until then the app's pool hook fails with "execute command denied").
* `run_migration()` is tested with PyMySQL. Old mysql-connector versions
  refuse the multi-statement routines.
* Tables with names over 57 characters get a hashed name stem
  (`v_<first 40>_<16 hex>`), so the names fit MySQL's 64 characters. A user
  with DDL rights could create a table named like another table's stem and
  take over its view and triggers; keep DDL away from app users.

PostgreSQL tenant context (`engines.postgresql.tenant_context`, `dbfw.context`):

* `signed` (default): the app sets `app.current_tenant` and
  `app.tenant_sig = hex(HMAC-SHA256(key, _firewall_nonce() || ':' || tenant))`.
  The key is `DB_FIREWALL_TENANT_KEY` (hex, 32 to 64 bytes) in the app, and
  `public._firewall_keys` in the database, which no app role can read. The
  nonce is the backend and the transaction's start time, so a signature holds
  for one transaction only. SQL the app or an AI agent runs inside the
  transaction can still set `app.current_tenant`, but cannot sign it, so the
  policies treat it as no tenant: no rows. The Python middleware and
  `@db-firewall/pg` sign for you. Without the key they set the tenant unsigned
  (warned once), which a signed database answers with no rows. The migration
  installs `dbfw.tenant_key` when set (this also rotates it). Otherwise it keeps
  the key, or generates one on the first run: read it with
  `SELECT encode(key, 'hex') FROM public._firewall_keys` or `npx db-firewall key`.
  The policies check the signature once per query, not once per row (an
  InitPlan). Tested on PostgreSQL 14 to 17.
* **Session reset.** SQL run in one tenant's transaction could leave session
  state for the connection's next user: a temp view that shadows a table, a
  SQL-level prepared statement under a driver's statement name, or a custom
  setting used as a drop box. `withTenant` (TypeScript) holds one connection
  for the call (a pg client, or a reserved postgres.js connection) and runs
  `public._firewall_reset_session` on it after COMMIT or ROLLBACK, also when
  the function throws. After the transaction, so a deferred trigger that fires
  at COMMIT cannot undo it. Python's `release()` and `pool_checkin` run it on
  return. It drops
  temp objects and SQL-level prepared statements, drops `currval`/`lastval`,
  closes cursors, stops `LISTEN`, releases advisory locks, and resets every
  setting. It then
  restores the session settings and role the connection had before: in
  TypeScript from before the call, in Python from when the middleware first
  set a tenant on the connection. The driver's own prepared statements stay.
  When the reset fails, a node-postgres connection is destroyed, and a
  postgres.js connection is retired (kept reserved, never reused: postgres.js
  does not survive a reserved connection being ended). A node-postgres
  connection is also destroyed when the function replaced or removed one of
  the driver's prepared statements. In Python a reset that fails closes the
  connection, and `pool_checkin` raises so the pool drops it. A `release()`
  inside an open transaction is followed by the app's COMMIT, where a deferred
  trigger could still run, so the next tenant set on that connection resets
  it again first.
* **Triggers and TRUNCATE.** RLS does not cover what a trigger does or
  `TRUNCATE`. With `TRIGGER` on a table, a role can attach its own function
  (even one in `pg_temp`) that then runs in other tenants' sessions as those
  tenants. The migration revokes `TRIGGER` and `TRUNCATE` on every protected
  table from everyone but the owner, and `verify` fails on `TRIGGER` on any
  table. Re-run the migration after granting privileges (`GRANT ALL` includes
  both).
  The reset costs about 1 ms per call. [Inference] It was measured on localhost.
* **The migration protects itself.** It binds every name and operator in
  `pg_catalog`, so a planted operator such as `public.=` for `varchar, text`
  cannot bind into a policy. It refuses to run when a `public._firewall_*`
  object belongs to a role that is neither the one running it nor a superuser,
  because another role may have planted it to read the key. It checks this
  first and again as its last statement, in case an object was planted while
  it waited on a lock. The scanners read the policies the same way. They fail
  when any function the migration creates differs from it, when an extra
  `public._firewall_*` function exists, or when the firewall objects have more
  than one owner that is not a superuser. Do not let app roles `CREATE` in any
  schema (`REVOKE CREATE ON SCHEMA public FROM PUBLIC` is the default since
  PostgreSQL 15). An app role can set its own defaults (`ALTER ROLE ... SET
  search_path`), which no reset undoes. Without `CREATE` it cannot plant
  anything for that path to reach, but it can still make its own connections
  fail. `npx db-firewall verify` checks `CREATE` on the database (a new schema
  named like the role comes first in the default `search_path`, `"$user",
  public`) and in every schema, and `TRIGGER` on every table. Schema-qualify
  table names in the app, or give the app role a `search_path` without
  `"$user"` (`ALTER ROLE app SET search_path = public`), so an object planted
  later cannot shadow a table.
* **Strict mode and hardening.** `npx db-firewall verify --strict` makes the
  check an allowlist: everything the app role can read must be protected
  tenant data (protected tables, `security_invoker` views over them, their
  sequences), no large object may be readable, the role may not read other
  sessions' SQL (`--allow-query-text` accepts that on managed PostgreSQL),
  and no `SECURITY DEFINER` function outside the firewall's may exist, unless
  you mark it shared with `--allow-global schema.name` (functions:
  `schema.name(argtypes)`).
  `npx db-firewall migrate --harden --app-role <role>` (or
  `engines.postgresql.harden: true` with `app_role`) revokes what `verify`
  fails on that the migration can remove, by any grantor: `CREATE` on the
  database and every schema, `TRIGGER` and `TRUNCATE` on every table (default
  privileges too), `pg_stat_activity` and `pg_stat_statements`, and the
  backend signals. It refuses when the app role owns the database or any
  object in it, or keeps one of these through a role it is a member of. Both cover the whole database;
  `--harden` needs a superuser.
* **DDL guard.** `npx db-firewall migrate --ddl-guard` (or
  `engines.postgresql.ddl_guard: true`) installs two event triggers: a new
  table with the tenant column in a protected schema is protected at the end
  of the `CREATE TABLE` (or `ALTER TABLE ... ADD COLUMN`, or a rename), not at
  the next migration run, and a change that weakens a protected table fails
  (RLS off or not forced, a firewall policy dropped or altered, another
  permissive policy in permissive mode, a rule, the table moved, renamed out
  of scope, or given a parent, child or partition that is not protected).
  After each command it checks every table in the protected schemas, so a
  partition, a child, or a typed table that gets the column through
  `ALTER TYPE ... CASCADE` is protected too. It binds every role but a
  superuser and the migration's own role. Needs a superuser to install. It
  does not stop a table owner's own trigger, which sees every tenant's
  writes to that table.
* **Tenant column type.** The migration refuses a tenant column whose type
  belongs to a role that is not a superuser, or whose collation is not
  deterministic. The policies call that type's cast and equality, so the
  type's owner would decide which tenant's rows a session sees. Use text or
  varchar.
* **Keys that tell on other tenants.** A unique key, or a foreign key to a
  protected table, that leaves out the tenant column still sees every
  tenant's rows: a duplicate error, or a missing parent, shows the app that
  another tenant has the value. `verify` lists them, exclusion constraints
  included (the tenant column counts there only with `=`), and `--strict`
  fails on them. A one-column key on a sequence, identity or uuid default is
  not listed, but an app that sends its own ids can still learn which ids
  exist. Put the tenant column in the key, and
  reference `(tenant_id, id)`, not `id`.
* **One role for all tenants.** Sessions of the same role can read each
  other's current query text in `pg_stat_activity`, and can end or cancel each
  other's backends (`pg_terminate_backend`). An app role can also change its
  own defaults (`ALTER ROLE CURRENT_USER SET ...`) so that its later
  connections fail. None of this reads another tenant's rows, but SQL one
  tenant's agent runs can see what another tenant's request is running, and
  stop it. Keep literal values out of SQL text (use parameters), and see
  "What a pass means" in `packages/cli/README.md`. To stop the signals, set
  `engines.postgresql.harden_signals: true` (or `dbfw.harden_signals = on`, or
  `npx db-firewall migrate --harden-signals`). The migration then revokes
  `pg_terminate_backend` and `pg_cancel_backend` from `PUBLIC` in that
  database. That covers every app and role in the database, so it is off by
  default and needs a superuser; grant the functions back to admin roles that
  need them. `verify` reports both, and the role's current defaults, as
  information lines.
* **The key in logs.** A key you pass in (`dbfw.tenant_key`,
  `DB_FIREWALL_TENANT_KEY` at migration time) is SQL text. If statement or
  parameter logging is on, it reaches the server log. `run_migration` and
  `db-firewall migrate` switch that logging off for their session when they
  run as a superuser. With `psql`, or as another role, prefer letting the
  migration generate the key and reading it with `npx db-firewall key`.
* `plain`: `app.current_tenant` alone. Any SQL in the transaction can set it,
  so it relies on the middleware's SQL rewriter. The scanner reports a plain
  table as unprotected unless `tenant_context: plain` is configured.

Upgrading from an earlier version: re-running the migration switches to
signed. Set `DB_FIREWALL_TENANT_KEY` in the app before (or with) the
migration, or set `tenant_context: plain` to keep the old behaviour. The
migration also revokes every grant but the owner's, column grants included,
on the key, `_firewall_sign` and `_firewall_set_tenant`, and every write grant
on the bypass list and the tenant map. Reading the map stays allowed, because
the `db_user_map` resolution reads it. This covers platforms such as Supabase
that grant new objects to their roles directly. `_firewall_set_tenant` is now
for admins only.

PostgreSQL policy mode (`engines.postgresql.policy_mode`, `dbfw.policy_mode`):

* `permissive` (default): the four tenant policies are the table's only
  policies. PostgreSQL ORs permissive policies, so any other permissive policy
  on the table widens access; the scanner reports it as unprotected.
* `restrictive`: the tenant policies are `AS RESTRICTIVE`, so they AND with the
  app's own policies. App policies can narrow rows inside the tenant, never
  widen past it, and the scanner accepts them. PostgreSQL needs one permissive
  policy before it allows any row: a table with none of its own gets
  `fw_<hash>_base` (`USING (true)`). Re-run the migration after adding the
  first policy of your own to a table, so the base policy is removed; until
  then it ORs with your policy inside the tenant, and the scanner reports
  `stale_base_policy`. An app policy that covers only `SELECT` leaves no
  permissive policy for writes, so they are refused.

The scanner also checks each firewall policy's shape: it must apply to
`PUBLIC`, cover its own command, and use exactly the predicate the migration
creates. The scanner asks PostgreSQL to deparse that predicate on a temporary
copy of the table (rolled back; needs the default `TEMP` privilege) and
compares the text exactly, so a changed cast, constant or function overload
shows up. When it cannot build that reference (a read-only transaction, no
`TEMP` privilege, no `SELECT` on the table), the table is reported with
`predicate_check: "unavailable: <reason>"` and counts as unprotected. A policy altered after the migration (`ALTER POLICY ... TO
some_role`, `USING (true)`, `... IS NOT NULL`) is listed in
`altered_policies` and the table counts as unprotected.

Oracle: run as SYS. The logon/logoff triggers call the package, and any other
DBA user needs a direct grant from the schema owner first (see section 6b of
the script). A trigger that does not compile is disabled, so it cannot block logins.

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
* `SET` / `RESET` of any setting **except** `app.current_tenant`, `app.tenant_sig`, `role`, `session_authorization` / `SET SESSION AUTHORIZATION`, `search_path`, `row_security`, `RESET ALL` and MySQL's `@_fw_tenant_id` (so `SET statement_timeout`, `SET TIME ZONE`, `SET LOCAL lock_timeout` work; nothing that moves the tenant or the role does). `set_config()` inside a `SELECT` follows the same list and must name its setting with a literal.
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

`rewriter: "regex"` (or `DB_FIREWALL_REWRITER=regex`) keeps the old dependency-free injector: it handles single-table statements and refuses every multi-scope shape above. It is deprecated and will be removed in the next major version: it had cross-tenant read bypasses that the `ast` rewriter did not (see CHANGELOG). It runs only on PostgreSQL, SQL Server and Oracle, where RLS or VPD stands behind it, and logs a warning once per process there. Everywhere else (MySQL, SQLite, an unrecognised engine, the MCP wrapper) it raises `PermissionError`. With `rewriter: "ast"` and sqlglot missing, `protect()`'d queries raise `ImportError` rather than silently downgrading.

In both modes the database-native RLS/VPD policy remains the second layer: the rewriter can only narrow a query, never widen it, and a statement that slips past it unscoped still hits the row policy.

---

## Supported Databases

| Database | Native Security | Middleware | Migration Script |
| --- | --- | --- | --- |
| **PostgreSQL** 13+ (9.5+ with `tenant_context: plain`) | ✅ Row-Level Security, signed tenant context | ✅ | `001_postgresql.sql` |
| **MySQL** 5.7+ / MariaDB | ❌ (Views + Triggers) | ✅ | `002_mysql.sql` |
| **SQL Server** 2016+ | ✅ Security Policies | ✅ | `003_sqlserver.sql` |
| **Oracle** 10g+ | ✅ Virtual Private Database | ✅ | `004_oracle.sql` |
| **SQLite** | ❌ | ✅ (middleware only) | None needed |

## Supported Frameworks

| Framework | Integration |
| --- | --- |
| **Raw DB-API** | `protect(connection)` |
| **SQLAlchemy** | `sqlalchemy_event_hooks(engine)` |
| **Django** (WSGI and ASGI) | `django_middleware_class(tenant_id_source=...)` |
| **FastAPI** | `fastapi_middleware(app, tenant_id_source=...)` |
| **Flask** | `flask_hooks(app, tenant_id_source=...)` |
| **MCP Servers** | `mcp_wrapper.py` stdio proxy |
| **LangChain** | Wrap the connection before passing to agent |
| **TypeScript** (node-postgres, postgres.js, Drizzle, AI SDK) | [`@db-firewall/pg`](packages/ts/README.md): `withTenant`, `bindTenant`, `assertSafeRole` (PostgreSQL RLS) |
| **Node CLI** (PostgreSQL) | [`npx db-firewall`](packages/cli/README.md) `migrate` / `scan` / `verify` (no Python needed) |
| **Python verify** (PostgreSQL) | `python -m hooks.verify --dsn $APP_URL --tenant <id>`: the same checks as `db-firewall verify` (see "CI/CD Security Gate") |

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
- **Django under ASGI:** the middleware is sync- and async-capable, so Django runs it
  natively under WSGI and ASGI. Under ASGI a sync `tenant_id_source` runs through
  `sync_to_async` (safe for database-backed sessions); an `async def` source is awaited.
  An `async def` source needs async mode: ASGI, with only async-capable middleware after
  this one. Otherwise Django refuses to start (`ImproperlyConfigured`).
- **Streaming responses:** Django streaming bodies, sync or async (ASGI), run as the
  request's tenant, even though they are read after the middleware returns. An async
  body runs in one task whose context holds the tenant, so timeouts held across
  chunks work, and its cleanup (`finally`) runs as that tenant even when the client
  disconnects mid-stream or the response is only garbage-collected.
  Put middleware that wraps streaming bodies, such as `GZipMiddleware`, above DB
  Firewall in `MIDDLEWARE` (Django's docs already place GZip near the top). If one sits
  below it and the server's send fails mid-stream, that stream's task stays pending and
  its cleanup does not run. No other tenant's code is affected.
  Under WSGI, a sync body that is closed early (the client goes away) also runs
  its `finally` as the request's tenant: the wrapper takes over the body's close.
  Flask runs teardown before a streaming body is read, so a Flask generator must
  open its own `tenant_scope(tenant)` or use `protect(conn, tenant_id=...)`.
- **Outside requests:** prefer `tenant_scope(...)` or `protect(conn, tenant_id=...)`
  over a bare `set_tenant()`, which stays set for the rest of that thread or task.
- **`fail_mode: open`:** a request with no verified tenant runs unscoped. Use
  `closed` in production; the web integrations log a warning when they see `open`.

Upgrade notes for these integrations are in [CHANGELOG.md](CHANGELOG.md).

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
- SQL in an object key is refused. A leading T-SQL label (`lbl: SELECT ...`) or a `sp_`/`xp_` procedure name counts as SQL.
- Limit: prose that starts with a keyword ("Update the report") is treated as SQL, so it is rewritten or refused. A bare SQL Server procedure name without `EXEC` or a `sp_`/`xp_` prefix is not caught: rely on row-level security for those.
- Defence in depth: run the migrations and give the wrapped server a role without `BYPASSRLS`, so row-level security still blocks anything a string check misses.

---

## CI/CD Security Gate

Add the scanner to your pipeline to **fail the build** if unprotected tables exist. Run it from the repo root (it is the `hooks` module of this checkout). On PostgreSQL it uses psycopg 3 when installed, else psycopg2:

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

With `--strict` the scanner returns exit code 1 if ANY non-excluded table with the tenant column is missing protection: PostgreSQL RLS, MySQL views + triggers, a SQL Server security policy named `firewall_rls_<table>`, or an Oracle VPD policy (`FN_TENANT_ISOLATION`, enabled, covering SELECT/INSERT/UPDATE/DELETE with update check; DSN `oracle://user:pass@host:1521/service`, needs `oracledb`). On SQLite every such table is reported unprotected, and an engine the scanner does not know fails the run. `engines.<engine>.schema` sets the schema it checks on PostgreSQL, MySQL and Oracle; on SQL Server it checks all schemas. It reads the schema, not the rows, so empty tables are checked too. On MySQL it checks that the view and the three triggers exist, not what they contain. On PostgreSQL a table counts as protected only when row-level security is enabled AND forced (table owners bypass unforced RLS) and all four firewall policies (select, insert, update, delete) exist on that exact `<schema>.<table>`, with no other permissive policy (PostgreSQL ORs permissive policies, so one extra `USING (true)` opens every row). The JSON report lists `missing_policies`, `extra_permissive_policies` and `rls_forced`.

### Verify (PostgreSQL)

The scanner reads the policies. `verify` tests the isolation itself, as the
app's own role: it connects with the app's URL, sets no tenant, an unsigned
tenant and the signed `--tenant`, and counts what each sees; it checks the
role, ownership, grants, and every read path RLS does not guard.

```yaml
- name: DB Firewall verify
  env:
    DB_FIREWALL_TENANT_KEY: ${{ secrets.DB_FIREWALL_TENANT_KEY }}
  run: python -m hooks.verify --dsn $APP_URL --tenant <a tenant with rows> --strict
```

`python -m hooks.verify` and `npx db-firewall verify` are the same check:
both run the shared check queries in `checks/postgresql.sql`, give the same
checks, results and details, and take the same options (`--schema`,
`--column`, `--exclude`, `--write-probe`, `--strict`, `--allow-global`,
`--allow-query-text`, `--json`; `--dsn` here for `--url`). CI runs the attack
corpus against both, and compares their output. Exit codes: 0 pass, 1 a check
failed, 2 usage or connection error, 3 inconclusive. The checks, and what a
pass does and does not mean, are in [packages/cli/README.md](packages/cli/README.md#verify).

---

## Configuration

The firewall reads config only from a path you name. It never searches the
current folder or your home folder, so a stray file cannot change the policy.

- `DB_FIREWALL_CONFIG=/path/to/.db-firewall.yaml` (a file, or a folder that holds one), or
- `load_config(project_root="/path/to/app")`, then pass the dict to `protect(conn, config=...)` or `sqlalchemy_event_hooks(engine, config=...)`.
- Use an absolute path. A relative one is resolved against the current folder each time config is read.
- Neither set: built-in defaults (`fail_mode: closed`, `tenant_column: tenant_id`). A named file or folder with no config file raises `FileNotFoundError`. A file that does not hold a mapping (empty, `null`, a list) raises `ValueError`. A YAML file without PyYAML raises `ImportError`.
- `DB_FIREWALL_TENANT_COLUMN`, `DB_FIREWALL_FAIL_MODE` and `DB_FIREWALL_REWRITER` override the file.
- `config/firewall.yaml` documents every key, including `resolution` (the order `protect()` looks for a tenant), `excluded_users`, `audit` and `engines`. `load_config` rejects an unknown resolution source, a malformed `excluded_users` and unsafe table names.

Example `.db-firewall.yaml`:

```yaml
version: "1.0"
tenant_column: "tenant_id"
fail_mode: "closed"           # "closed" = no tenant → queries on protected tables refused (SAFE)
rewriter: "ast"               # "ast" (sqlglot, default) or "regex" (deprecated, no dependency)
allow_tenant_placeholder: false   # INSERT ... (tenant_id) VALUES (%s) is refused unless true

protect:
  select: true
  insert: true
  update: true
  delete: true

excluded_users: []            # EMPTY by default — see "Bypass roles" 

excluded_tables:
  - "_firewall_*"
  - "schema_migrations"
  - "app_config"
```

### Bypass roles (excluded users)

Nothing bypasses the firewall by default. Earlier versions hardcoded `postgres`, `root`, `sa`, `admin`, `_migrator`; on Supabase, Neon, RDS and most managed databases the **application itself** connects as `postgres`, which silently disabled every policy.

Opt a role in deliberately, at both layers:

```yaml
# middleware layer (.db-firewall.yaml): exact name as the database reports it
excluded_users: ["_migrator"]
```

```sql
-- database layer (created by the migrations, empty by default)
INSERT INTO _firewall_bypass_roles (role_name) VALUES ('_migrator');
```

The middleware asks the database for the connection's user (`current_user`,
`CURRENT_USER()`, `SYSTEM_USER`, `USER`) only when `excluded_users` is not
empty. A listed user's connections are not rewritten, not checked and get no
DB-side context; a warning is logged once per user. A failed lookup counts as
not excluded.

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
| **Fail closed** | No tenant context: the middleware refuses queries on protected tables (`PermissionError`) and RLS returns 0 rows. Never defaults to "show all". |
| **Defense in depth** | Middleware + database-native RLS/VPD. Two independent layers. |
| **Full DML protection** | SELECT, INSERT, UPDATE, AND DELETE are all filtered — every table reference, in every CTE, branch and subquery. |
| **Audit trail** | With `audit.enabled`, the middleware writes a `_firewall_audit_log` row per DB-side tenant assignment (PostgreSQL, MySQL, SQL Server; same transaction). On Oracle, `set_tenant` logs to `VPD_AUDIT_LOG` in an autonomous transaction. `purge_audit(conn)` applies `retention_days`; `log_queries` logs each executed statement. |
| **Zero trust the agent** | The AI doesn't know about tenancy. The database enforces it. On PostgreSQL the tenant is signed per transaction, so SQL the agent runs cannot switch it. |
| **Connection pool safe** | Postgres context is transaction-local; every engine is cleared on `release()`/`pool_checkin`. See "Connection pooling". |

---

## Project Structure

```bash
db-firewall/
├── .github/workflows/tests.yml   # CI: pytest and TypeScript on PostgreSQL 14-17; live MySQL + SQL Server
├── .github/workflows/oracle-nightly.yml  # CI: Oracle Free, nightly and on Oracle/middleware PRs
├── adapters/                     # NoSQL: mongodb.py, redis.py, firestore.py, convex/ (see "NoSQL stores")
├── config/
│   └── firewall.yaml             # Default configuration + documentation
├── migrations/
│   ├── 001_postgresql.sql        # PostgreSQL native RLS (auto-applies to public tables with a tenant_id column)
│   ├── 002_mysql.sql             # MySQL secure views + triggers
│   ├── 003_sqlserver.sql         # SQL Server security policies
│   └── 004_oracle.sql            # Oracle VPD (every SCHEMA_OWNER table with TENANT_COLUMN; run as SYS)
├── middleware/
│   ├── db_firewall/              # Universal Python middleware (DB-agnostic), one module per concern:
│   │                             #   config, engines, context, introspection, rewrite, db_context,
│   │                             #   resolution, audit, wrappers, streams, web, sqlalchemy_hooks,
│   │                             #   migrate (+ __main__ CLI)
│   └── sql_rewriter/             # sqlglot AST rewriter (scopes every table reference):
│                                 #   __init__ (rewrite), lexing, astutil, writes
├── hooks/
│   ├── mcp_wrapper.py            # MCP server stdio proxy with SQL rewriting
│   ├── scanner.py                # CI/CD security scanner (CLI)
│   └── scan_engines.py           # per-engine checks (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
├── packages/ts/                  # @db-firewall/pg: TypeScript tenant transactions + AI SDK tool binding
├── packages/cli/                 # db-firewall: Node CLI (migrate, scan, verify) for PostgreSQL
├── tests/                        # see "Running the tests"
├── requirements.txt              # core + test dependencies
├── requirements-adapters.txt     # optional NoSQL drivers
├── CHANGELOG.md                  # changes and upgrade notes
├── SKILL.md                      # Auto-integration trigger for AI workflows
└── README.md                     # This file
```

## Running the tests

```bash
pip install -r requirements.txt pytest-cov flask starlette httpx sqlalchemy pymongo mongomock django
python -m pytest -q                                   # no database needed; live tests skip
DBFW_PG_DSN="host=localhost port=5432 dbname=dbfw_test user=postgres" \
  python -m pytest -q --cov=middleware                # adds the live PostgreSQL tests
```

The live tests create the `dbfw_app` role and their own tables, and apply
`migrations/001_postgresql.sql`, so point `DBFW_PG_DSN` at a throwaway database
as a superuser. CI does the same on PostgreSQL 14, 15, 16 and 17 and fails
below 85% coverage.

`tests/attacks/postgresql.sql` is the attack corpus: the ways to reach
another tenant's rows on PostgreSQL that the reviews found (definer views and
functions, rules, ownership, functions PostgreSQL runs without an `EXECUTE`
check, shared stores), and safe patterns that must pass. CI runs it on every
version: `db-firewall verify` and `python -m hooks.verify` must fail each attack with the named check, and
an attack's leak query, when it has one, must really show data tenant A must
not see on that version. Add every new bypass there before fixing it.

| Test file | Covers |
| --- | --- |
| `test_sql_rewriter.py`, `test_firewall.py`, `test_rewrite_safety.py` | AST and regex rewriters, tenant-id injection safety |
| `test_engines_fakes.py` | engine detection, DB-side context, cursor mediation, pool check-in, tenant map (fake drivers) |
| `test_config_loading.py`, `test_package_layout.py` | explicit config path; package re-exports and setting forwarding |
| `test_request_context.py`, `test_django_asgi.py` | request tenant for Django (WSGI + ASGI, real Django), FastAPI, Flask; streaming bodies |
| `test_sqlalchemy_hook.py` | SQLAlchemy hook swaps the statement (sqlite) |
| `test_mcp_wrapper.py`, `test_migration_cli.py` | MCP stdio proxy; `run_migration()` and the CLI |
| `test_config_features.py` | `excluded_users`, `audit`, `resolution`, `engines` (fakes + live PostgreSQL) |
| `test_scanner_fakes.py` | scanner logic for MySQL, SQL Server, Oracle (scripted cursors) |
| `test_oracle_live.py` | live Oracle: VPD migration with a custom column, middleware, scanner (opt-in: `DBFW_ORA_DSN`; setup steps in the file) |
| `test_mysql_live.py` | live MySQL: `run_migration()` with a custom column, views and triggers, middleware, audit, resolution, scanner (opt-in: `DBFW_MYSQL_DSN`, admin user; run `tests/live_setup/mysql_before.sql` first) |
| `test_sqlserver_live.py` | live SQL Server: `run_migration()` with a custom column, security policy, middleware, audit, resolution, scanner (opt-in: `DBFW_MSSQL_DSN`, needs `pymssql`; run `tests/live_setup/sqlserver_before.sql` first) |
| `test_gate_live.py`, `test_pool_leak.py`, `test_scanner_live.py` | live PostgreSQL: middleware vs RLS, pool leaks, scanner (opt-in: `DBFW_PG_DSN`) |
| `test_adapters_*.py` | MongoDB (mongomock), Redis (skipped unless `redis` is installed and a server runs at `REDIS_URL`, default `localhost:6390`; not run in CI), Firestore (fake client) |

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
