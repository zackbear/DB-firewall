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
- **`run_migration()`** now refuses MySQL and Oracle with `NotImplementedError`.
  Those scripts need their own client (`DELIMITER`, SQL*Plus `DEFINE`). Before,
  it sent them to the driver, which cannot run them.
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
- Live Oracle Database Free 23ai test suite (`tests/test_oracle_live.py`).

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
- SQL Server tenant context used `?`, which pymssql does not bind; it now uses
  the driver's parameter marker.
- Docs: unread config keys, scanner coverage, audit and fail-closed wording
  (first commits of this PR).

### Not tested live

- The MySQL and SQL Server migration changes and scanner checks are tested with
  scripted cursors only. [Unverified] MySQL may refuse `CREATE TRIGGER` inside a
  prepared statement, which `002_mysql.sql` uses; this predates this PR.

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
