# Changelog

## 2026-10-26: config sections, migrations, Oracle (PR #10)

### Upgrading

- **`resolution`, `excluded_users`, `audit` and `engines` now take effect.**
  The defaults keep the old behaviour. If your `.db-firewall.yaml` was copied
  from the old sample, check these sections before upgrading. The old sample
  listed `db_user_map` first, then `session_var` and `connection_param` enabled,
  with `env_var` off: that order is now used.
- **`audit.enabled` now defaults to false.** It used to be true but was never
  read. With true, the PostgreSQL, MySQL or SQL Server audit table from the
  migration must exist, or tenant assignment fails under `fail_mode: closed`.
- **MySQL migration: new steps.** The old script could not run on a live
  server (see Fixed). `source migrations/002_mysql.sql` no longer applies the
  views and triggers by itself: run `CALL _firewall_apply_all()` and pipe its
  output to `mysql` (README "Run the migration"), or use `run_migration(conn)`.
  It drops and re-creates the firewall routines and triggers, and MySQL drops
  routine grants with the routine: re-grant `EXECUTE` on
  `_firewall_init_connection` after each run.
- **`run_migration()`** runs MySQL (it parses `DELIMITER`) and refuses Oracle
  with `NotImplementedError` (SQL*Plus `DEFINE`). Before, it sent both scripts
  to the driver, which cannot run them.
- **Oracle now resolves the tenant from `TENANT_USER_MAP` by default** (the
  `db_user_map` source). Before, `protect()` on Oracle found no tenant there.
- **A set but invalid tenant value raises**, as before (`TENANT_ID=""` or
  `"bad\id"`). It never falls through to the next source.
- **Table names in config** (`resolution[].table`, audit tables) may no longer
  contain `#`, and are checked when a config is passed as a dict too.
- **MySQL:** a tenant id of `__BYPASS__` (any case) is refused, and the views
  and triggers match tenants exactly (`BINARY`). A tenant `b` no longer sees
  rows of `B` at the database layer.
- **MySQL: the middleware refuses user variables and dynamic SQL.** Any
  statement with an `@` outside single-quoted literals and comments, and any
  `PREPARE`, `EXECUTE`, `DEALLOCATE`, `CALL`, `DO` or `HANDLER`, is refused.
  An `@` inside a double-quoted string or a backticked name is refused too:
  pass such values as parameters.
- **The scanner** fails on an engine it does not know, instead of passing with
  an empty report.
- **Oracle:** run the migration as SYS. Re-running it now replaces the policies
  on every table in `SCHEMA_OWNER` that has `TENANT_COLUMN`.

### Added

- `excluded_users`: connections whose DB user is listed are not scoped. Exact
  match on the name the database reports; a failed lookup counts as not excluded.
- `audit`: one audit row per DB-side tenant assignment, `purge_audit(conn)`
  for `retention_days`, and `log_queries` to the `db_firewall.audit` logger.
- `resolution`: the order `protect()` uses to look for a tenant: `env_var`,
  `db_user_map`, `session_var`, `connection_param`. The request tenant always
  comes first.
- `engines`: `use_rls` / `use_views` / `use_vpd` false skips the DB-side
  context; `schema` sets what the scanner checks (and where the PostgreSQL
  migration applies RLS); `audit_table` per engine.
- Migrations take the tenant column: PostgreSQL (`dbfw.tenant_column`,
  `dbfw.schema`), MySQL (`@dbfw_tenant_column`), SQL Server (session context),
  Oracle (`DEFINE TENANT_COLUMN`).
- Scanner: Oracle VPD check (`oracle://` DSN). MySQL checks all three triggers.
- Live test suites for MySQL, SQL Server and Oracle.

### Fixed

- Django WSGI: a sync streaming body closed early runs its cleanup as the
  request's tenant.
- Oracle `set_tenant` committed the caller's open transaction and hid a failed
  context set. The audit row now uses an autonomous transaction, and a context
  error reaches the caller.
- Oracle migration: the logon/logoff triggers compiled invalid when the script
  ran as a DBA user other than SYS, and an invalid logon trigger blocks logins.
  Invalid triggers are now disabled, with an error that says to run as SYS.
- Oracle migration protected a fixed list of 4 tables; it now finds every table
  with the tenant column.
- SQL Server tenant context, introspection and scanner used `?`, which pymssql
  does not bind; they now use the driver's parameter marker.
- MySQL migration, found on a live MySQL 8.4 (all predate this PR):
  - the views read `@_fw_tenant_id` directly, which MySQL refuses (ERROR 1351);
  - the triggers were created through `PREPARE`, which MySQL refuses (ERROR 1295);
  - the routines looked up the caller with `CURRENT_USER()`, which inside a
    DEFINER routine is the definer: the map and bypass checks used the wrong
    user. They now use `USER()`;
  - a row with a NULL tenant column passed the insert trigger (`!=` with NULL);
  - `NOT LIKE 'v_%'` skipped every table whose name starts with `v`, such as
    `vendors`, so it got no view or triggers. The PostgreSQL, MySQL and SQL
    Server scripts now escape `_` in `LIKE` (`ESCAPE '#'`, `[_]`).
- MySQL layer, found by the second review of this PR:
  - the middleware let `SET @a=1, @_fw_tenant_id=...`, quoted, escaped and
    accented variable names, and `:=` through. On MySQL it now refuses every
    statement with a user variable (`@` outside single-quoted literals) and
    dynamic SQL (`PREPARE`, `EXECUTE`, `CALL`, `DO`, `HANDLER`), with either
    rewriter;
  - a tenant named `__bypass__` (any case, or with accents) passed the bypass
    check. `__BYPASS__` is no longer a valid tenant id, and the SQL compares
    the marker and the tenant as `BINARY`;
  - under `NO_BACKSLASH_ESCAPES` the migration reported success but created
    no triggers. The script uses no backslash escapes now, and
    `run_migration()` raises if the trigger DDL does not split;
  - `_firewall_apply_all` ran as its definer with a column name the caller
    sets; it is now `SQL SECURITY INVOKER`;
  - a table name over 57 characters stopped the trigger step; such names now
    get a hashed stem.
- SQL Server migration failed on a second run (the audit index already existed).
- Docs: unread config keys, scanner coverage, audit and fail-closed wording
  (first commits of this PR).

### Tested live

- PostgreSQL 16 (CI), MySQL 8.4, SQL Server 2022 Developer and Oracle Database
  Free 23ai: `tests/test_mysql_live.py`, `tests/test_sqlserver_live.py`,
  `tests/test_oracle_live.py` (opt-in; setup SQL in `tests/live_setup/`).
- Not tested: MariaDB, older MySQL and SQL Server versions, Azure SQL.

## 2026-10-20: security and structure batch (PRs #4 to #9)

Read **Upgrading** first: four of these changes can break an existing setup.
The config path, the `X-Tenant-ID` header and `protect()` can refuse queries or
leave tables unscoped until you change your setup; the CLI change breaks
scripts that call the removed commands.

### Upgrading

1. **Config path (#5).** Config is no longer found automatically in the current
   folder or the home folder. Set `DB_FIREWALL_CONFIG=/abs/path/.db-firewall.yaml`
   (a file, or a folder that holds one), or call `load_config(project_root=...)`.
   Until you do, the built-in defaults apply. If your file set a custom
   `tenant_column` (for example `org_id`), tables that use it are **not scoped**
   until you set the path. A `.db-firewall.*` file left in the current folder is
   logged once as a warning.
2. **Tenant header (#4).** The web integrations no longer read `X-Tenant-ID`
   (or `?tenant_id=` on FastAPI and Flask) from every request. Pass
   `tenant_id_source=...`, or set `trust_tenant_header: true` behind a gateway
   that authenticates the caller and overwrites the header. Until then, such
   requests have no tenant: their queries on protected tables are refused under
   `fail_mode: closed` and run unscoped under `open`. The first ignored header is logged as a warning.
3. **`protect()` and the shared tenant (#4).** `protect(conn, tenant_id="A")`
   no longer sets the shared request tenant, so a later `protect(other_conn)`
   without a tenant does not inherit "A". It falls back to the `TENANT_ID`
   environment variable, then `_firewall_tenant_map`, then no tenant: queries
   on protected tables are refused under `fail_mode: closed`, unscoped under
   `open`. Pass `tenant_id=` to every `protect()` call, or wrap the work in
   `tenant_scope("A")`.
4. **CLI (#6, #8).** The `migrate` and `check` commands did nothing and are
   removed. `python -m middleware.db_firewall info` prints the active config.
   Apply migrations with `psql` / `mysql` / `sqlcmd` or `run_migration(conn)`,
   and audit with `hooks/scanner.py`. The old `python middleware/db_firewall.py`
   path no longer exists.

Also changed:

- `sqlalchemy_event_hooks(engine, config=None)` reads config once when you
  attach it, not on every query (#5).
- `run_migration()` raises `FileNotFoundError` instead of logging and applying
  nothing (#6).
- The MCP wrapper refuses SQL it cannot scope with a JSON-RPC error and drops
  lines that are not JSON. Before, it passed them through or stopped (#6).
- An `async def` `tenant_id_source` in sync mode (WSGI, or ASGI with sync-only
  middleware after this one) raises `ImproperlyConfigured` at startup (#9).

### Fixed

- **Request tenant (#4).** The tenant is request-scoped (`ContextVar` with
  enter/exit tokens), so it cannot leak between requests, threads or asyncio
  tasks. Django streaming bodies are read as the request's tenant.
- **Config (#5).** A named config path with no config file, or a file that is
  not a mapping, raises instead of quietly using defaults. Before, a missing
  file with a custom `tenant_column` returned rows for every tenant.
  `DEFAULT_CONFIG` is deep-copied.
- **MCP wrapper (#6).** Every SQL-looking string in a `tools/call` is scoped,
  under any argument name and at any depth. Before, only 5 top-level argument
  names were checked, so SQL elsewhere reached the database unscoped.
- **Scanner (#6).** The PostgreSQL check crashed on every run. It now passes a
  table only when RLS is enabled and forced, all four firewall policies exist
  on that exact `public.<table>`, and no other permissive policy exists.
- **Migrations (#6).** `run_migration()` looked in a folder that does not
  exist. It now uses the repo's `migrations/`.
- **Django ASGI (#9).** An async streaming body's cleanup (`finally`) runs as
  the request's tenant, also when the client disconnects mid-stream.

### Added

- Django middleware is sync- and async-capable and runs natively under ASGI
  (#9). Async streaming bodies keep the request's tenant.
- GitHub Actions: tests on Python 3.11 and 3.13 against PostgreSQL 16, with
  85% minimum coverage and a 15-minute job timeout (#7, #9).
- Tests for engine paths with fake drivers, the MCP wrapper, the scanner, config
  loading, the package layout and Django under WSGI and ASGI. Middleware
  coverage is 95% (#5 to #9).

### Changed

- `middleware/db_firewall.py` and `middleware/sql_rewriter.py` are now packages
  of small modules (#8). `import db_firewall`, `from middleware.db_firewall
  import ...` and `import sql_rewriter` still work. Setting `db_firewall.X`
  (for example `TABLE_CACHE_TTL`) still takes effect. No behavior change:
  21,980 rewrite and check cases give the same result as the old code.

### Known limits

- Under Django ASGI, middleware that wraps streaming bodies (such as
  `GZipMiddleware`) must sit above DB Firewall in `MIDDLEWARE`. If it sits below
  and the server's send fails mid-stream, that stream's cleanup does not run.
- Under Django WSGI, a sync streaming body that is closed early may run its
  `finally` as another tenant. (Fixed 2026-10-26.)
- The MCP wrapper finds SQL by its first keyword. Prose that starts with a
  keyword is treated as SQL. A bare SQL Server procedure name without `EXEC`
  or a `sp_` / `xp_` prefix is not caught. Row-level security is the backstop.
