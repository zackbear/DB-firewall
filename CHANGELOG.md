# Changelog

## 2026-10-28: PostgreSQL 14 to 17 and the attack corpus in CI (PR #16)

- **CI runs on PostgreSQL 14, 15, 16 and 17:** the Python suite (with the
  coverage gate), `@db-firewall/pg` and the CLI.
- **Attack corpus for PostgreSQL** (`tests/attacks/postgresql.sql`): 73
  attacks from the PR 13 to 16 reviews and 5 safe patterns. On every version,
  `verify` must fail each attack with the named check. Most attacks also have
  a leak query: run as the app for tenant A, it must show data tenant A must
  not see (so the case is real on that version). Safe patterns must pass,
  and the fixture must pass verify before and after the corpus. The CLI's own
  list of failing cases moved there. The parser rejects an unknown or
  repeated directive, and the test pins the number of cases.
- A review broke one defence in `verify` at a time: 16 of 27 breaks passed
  the old tests. With the new cases, every break of a check the corpus can
  set up is caught; the corpus cannot yet set up `SECURITY DEFINER` type
  I/O functions or selectivity estimators (they need C code).
- The CLI tests revoke `CREATE` on schema `public` from `PUBLIC` (PostgreSQL
  14 grants it, and `verify` fails on it), and skip what needs a newer
  server.

## 2026-10-28: Strict mode and hardening (PR #15)

- **`db-firewall verify --strict`:** an allowlist instead of a list of known
  leak paths. Everything a role the app can use can read must be protected
  tenant data: a protected table, a `security_invoker` view whose chain
  reaches only protected tables (it must read at least one table and call no
  function outside `pg_catalog`), or a sequence a protected table owns. No
  large object may be readable, and the role may not read other sessions' SQL
  in `pg_stat_activity` or `pg_stat_statements` (`--allow-query-text` accepts
  it, for managed PostgreSQL). No `SECURITY DEFINER` function outside the
  firewall's may exist, executable or not.
  `--allow-global` (repeatable, globs, needs `--strict`) marks shared data:
  `schema.name` for a relation, `schema.name(argtypes)` for a function. In
  the bypass-objects check it clears only functions and foreign tables
  without the tenant column, never a view over a tenant table.
- **verify, all modes:** fails on any rule other than a view's own (its
  actions run as the owner), on a `SECURITY DEFINER` function PostgreSQL runs
  without checking `EXECUTE` (triggers, aggregate, range and index support,
  operator family operators, estimators, planner support, type I/O,
  conversions, transforms, text search parsers and templates, FDW and
  language handlers and validators), and when a role the app can use owns
  the database or any object in it (an owner can change a domain constraint
  or a function body, or grant itself `CREATE` and `TRIGGER` back). A new information line reports whether the role can read other
  sessions' SQL. `--exclude` globs read `[^a]` as fnmatch does (a literal
  `^`).
- **`migrate --harden --app-role <role>`** (`dbfw.harden`, `dbfw.app_role`,
  `engines.postgresql.harden` / `app_role`): revokes, from `PUBLIC` and the
  app role, by any grantor: `CREATE` on the database and every schema,
  `TRIGGER` and `TRUNCATE` on every table and in default privileges,
  `pg_stat_activity` with `pg_stat_get_activity` and
  `pg_stat_get_backend_activity`, `pg_stat_statements` when installed, and
  the backend signals. It refuses, and changes nothing, when the app role can
  act as the owner of the database or any object in it, or still has one of
  these through a role it is a member of. It needs a superuser and is off by default.

## 2026-10-28: Signed tenant context (PR #14), breaking

- **PostgreSQL tenant context is signed by default** (`dbfw.context` /
  `engines.postgresql.tenant_context`: `signed`). The app sets
  `app.tenant_sig = hex(HMAC-SHA256(key, nonce:tenant))` next to
  `app.current_tenant`. The nonce is the backend and the transaction's start,
  and the key is `DB_FIREWALL_TENANT_KEY` in the app and `_firewall_keys` in the
  database. SQL the app or an AI agent runs can set `app.current_tenant`, but
  cannot sign it, so it can no longer switch tenants. This closes the gap in
  `@db-firewall/pg`, where SQL run inside `withTenant` could switch, and makes
  the Python SQL rewriter a second layer, not the only one.
- The policies check the signature once per query (`(SELECT f())`, an
  InitPlan), so they run faster than the plain policies (200k-row count:
  15 ms, against 341 ms).
- Python middleware and `@db-firewall/pg` sign with `DB_FIREWALL_TENANT_KEY`
  and clear `app.tenant_sig` too. The `session_var` resolution source takes
  only a signed tenant. The SQL rewriter refuses `app.tenant_sig`.
- The migration revokes every non-owner grant on the key, the bypass list,
  the tenant map, `_firewall_sign` and `_firewall_set_tenant`, which covers
  platforms that grant new objects directly. `_firewall_set_tenant` is now for
  admins only. `_firewall_auto_resolve` maps `session_user`, not the
  function owner.
- Scanners report `tenant_context` and expect `signed`. The CLI adds
  `migrate --context`, `scan --context` and `db-firewall key`. `verify` needs
  the key and also checks that an unsigned tenant sees nothing, that the app
  cannot read the key or sign, and that the signing functions match the
  migration.
- From the independent review:
  - **Session reset:** SQL run in one tenant's transaction could leave a temp
    view, a SQL-level prepared statement or a custom setting for the
    connection's next user (another tenant). `public._firewall_reset_session`
    now clears these after every `withTenant` call, and on Python `release()`
    and `pool_checkin`.
  - **Planted objects:** the migration refuses `public._firewall_*` objects
    planted by another role, which could have read the key. All its DDL is
    schema-qualified.
  - **Operators:** the migration binds the predicates in `pg_catalog`, so a
    planted operator such as `public.=` for `varchar, text` cannot bind. The
    scanners and `verify` read policies the same way.
  - **Scanners** fail when a firewall function differs from the migration or
    the firewall objects have more than one owner.
  - **`verify`** fails when the app can `CREATE` in `public`.
  - **Tenant map:** reading it stays allowed (`db_user_map`). Column grants
    on the key are revoked.
  - **Key handling:** `migrate` turns statement and parameter logging off for
    its session when it runs as a superuser, and clears `dbfw.tenant_key`
    after a failed run.
- From the second review round:
  - **TS:** when `fn` breaks its transaction, the reset now runs after a
    `ROLLBACK`. node-postgres connections are destroyed. Advisory locks are
    released. The reset's casts are qualified.
  - **Python:** the reset restores the settings from when the middleware
    first set a tenant, not the ones agent SQL changed. A failed reset closes
    the connection, and `pool_checkin` raises. `transaction_*` settings are
    not restored.
  - **Migration:** the owner guard also runs as the last statement.
  - **Scanners:** they check every function the migration creates and flag
    extra `_firewall_*` functions. Several superuser owners are accepted.
    `verify` fails on `CREATE` in any schema.
- From the third review round:
  - **TS:** every adapter now holds one connection for the call (Drizzle via
    `db.$client`; postgres.js via `sql.reserve()` with `begin`/`savepoint`
    added) and resets the session after COMMIT, so a deferred trigger cannot
    undo the reset. `RESET ALL` and the advisory-lock release run first, so a
    short `statement_timeout` cannot stop the reset.
  - **Failed resets:** node-postgres connections are destroyed. postgres.js
    connections are retired, because ending them crashed postgres.js. A
    node-postgres connection whose driver statements were removed is also
    destroyed.
  - **Migration:** the guard is two `DO` blocks, so no TEMP privilege is
    needed.
  - **`verify`** also fails on `TRIGGER` on any table.
- From the fourth review round:
  - **Migration:** it revokes `TRIGGER` and `TRUNCATE` on protected tables
    from everyone but the owner. A trigger function, even in `pg_temp`, runs
    in other tenants' sessions.
  - **Python:** after a `release()` inside an open transaction, the next
    tenant set on that connection resets it again first.
  - **TS:**
    - Drizzle relational queries work again (the full relational config is
      passed).
    - A pg client that fn ends no longer crashes the process.
    - A transaction left aborted makes the call throw on Drizzle and
      postgres.js too.
- From the independent final review:
  - **`verify`:**
    - It fails on `CREATE` on the database. A schema named like the role
      comes first in the default `search_path`, and a view in it shadows a
      table.
    - It fails on membership in `pg_read_all_data`, `pg_write_all_data`,
      `pg_execute_server_program`, `pg_read_server_files` and
      `pg_write_server_files`.
  - **The reset** also drops `currval`/`lastval` (`DISCARD SEQUENCES`).
  - **Docs:**
    - `search_path` guidance: schema-qualify table names, or leave out
      `"$user"`.
    - The limits of one shared role: query text in `pg_stat_activity`,
      `pg_terminate_backend`, and `ALTER ROLE` on itself.
- Opt-in `harden_signals` (`dbfw.harden_signals`, `migrate --harden-signals`):
  it revokes `pg_terminate_backend` / `pg_cancel_backend` from `PUBLIC` in the
  database, so tenants sharing one role cannot end each other's requests. It
  needs a superuser. `verify` adds two information lines: whether the role
  can signal other sessions, and its role-level defaults.
- **Upgrade:** set `DB_FIREWALL_TENANT_KEY` in the app before re-running the
  migration, or set `tenant_context: plain`. PostgreSQL 13+ for signed.

## 2026-10-28: Node CLI (PR #13)

- **`db-firewall` CLI** (`packages/cli`, `npx db-firewall`), for PostgreSQL:
  - `migrate` runs the repo's `001_postgresql.sql` (shipped unchanged) with
    `--column`, `--schema` and `--mode permissive|restrictive`, then prints the
    scan.
  - `scan` ports the Python PostgreSQL scanner, including the exact-predicate
    check. `--schema` is repeatable. The default exclusions are exactly the
    tables the migration skips, and excluded tables are listed. `--strict`
    exits 1 when a table is unprotected or none is found.
  - `verify` connects as the app's role and tests the behaviour. It fails on:
    a role it is a member of that skips RLS, write access to the bypass list
    (column grants included), ownership of `public` (the database owner on
    PG15+) or of a firewall object, table ownership,
    `TRUNCATE`, rows visible without a tenant or from another tenant, a
    tenant with no rows, definer views (followed through view chains),
    materialized views, foreign tables, `SECURITY DEFINER` and `LEAKPROOF`
    functions in any schema, and readable tenant tables in other schemas.
    Privileges count for every role the app can `SET ROLE` to. It also fails
    when `_firewall_is_bypass_role` differs from the migration. The README
    says what a pass does not prove (copies, side channels, untagged tables). Read-only by default. `--write-probe` adds a
    rolled-back cross-tenant insert. Exit 3 when a check is inconclusive.
  - Live tests in the `typescript` CI job. Not yet published to npm.

## 2026-10-28: TypeScript package and restrictive policies (PR #12)

- **`@db-firewall/pg`** (`packages/ts`): tenant isolation for TypeScript on
  PostgreSQL. `withTenant(db, tenantId, fn)` runs `fn` in one transaction with
  `app.current_tenant` set for that transaction only, on node-postgres,
  postgres.js or Drizzle, and fails closed without a tenant. `bindTenant(tools,
  tenantId)` binds AI SDK tools (or any `{ execute }` set) to the server's
  tenant, so the model cannot pick it. `assertSafeRole(db)` refuses a
  superuser, a `BYPASSRLS` role or a bypass role. No runtime dependencies.
  Tested live in CI with the real migration, including through the AI SDK's
  `generateText`. Not yet published to npm. From the PR 12 review: only real
  `pg.Pool` / `pg.Client`, postgres.js and Drizzle databases are accepted (a
  pool wrapper such as pg-promise mixed connections and returned another
  tenant's rows); the handle given to `fn`, and everything reached through it
  (sessions, query builders, pending queries), stops working when `fn`
  settles, including nested transactions, savepoints and event emitters;
  listeners added inside `fn` are removed when it settles (event data stays
  plain);
  `release()`, `connect()` and `end()` on it are refused; a nested
  call or a raw Drizzle transaction is refused; streaming tools stay in scope;
  a session-level tenant is cleared on node-postgres.
- **PostgreSQL `policy_mode: restrictive`** (`engines.postgresql.policy_mode`,
  `dbfw.policy_mode`): the tenant policies are created `AS RESTRICTIVE`, so
  they AND with the app's own RLS policies instead of being OR-ed with them.
  A table with no permissive policy of its own gets `fw_<hash>_base`. The
  scanner accepts other permissive policies when all four tenant policies are
  restrictive, and reports `policy_mode`. The default stays `permissive`.
- **Scanner (PostgreSQL): firewall policies are checked by shape**, not only by
  name: each must apply to `PUBLIC`, cover its own command and use exactly the
  predicate the migration creates, as PostgreSQL deparses it on a temporary
  copy of the table (rolled back). When that is not possible (read-only
  transaction, no `TEMP` privilege), `predicate_check` says why and the table
  counts as unprotected. An altered policy is reported in `altered_policies` and the table
  counts as unprotected. A policy left by an older migration counts as altered
  unless it matches the current predicate: re-run the migration. `stale_base_policy` flags a base
  policy left next to app policies in restrictive mode.

## 2026-10-28: live CI and attack corpus (PR #11)

- **CI runs the live suites** on MySQL 8.4 and SQL Server 2022 for every pull
  request, and on Oracle Database Free 23ai every night.
- **Attack corpus** (`tests/attack_corpus.py`): the reads and writes the PR 10
  and PR 11 reviews used to reach another tenant. `tests/test_mysql_live.py`
  runs each one through `protect()` as tenant A, with both rewriters, as an
  admin and as the app user with the README grants, and compares the result
  (or the state it leaves) with the same SQL run raw where only tenant A's rows
  exist. A difference, a changed tenant B row or a changed tenant variable fails
  the build. Add each new bypass there first.
- **sqlglot is pinned** (`sqlglot==30.24.0`). The rewriter's safety depends on
  how sqlglot parses, so upgrade only when the suite and the corpus pass.
- **`rewriter: regex` is deprecated** and will be removed in the next major
  version. **It now runs only on PostgreSQL, SQL Server and Oracle**, where RLS
  or VPD stands behind it, with a `FutureWarning` once per process. Everywhere
  else it raises `PermissionError`: MySQL, SQLite, an unrecognised engine, and
  a call that names no engine (the MCP wrapper). The PR 11 reviews found
  cross-tenant reads through it on MySQL (`... --id-2`, which MySQL does not
  read as a comment; a scalar subquery in the select list), on SQLite, and
  through the MCP wrapper.
- **pyodbc: the engine comes from the driver.** A pyodbc connection used to
  count as SQL Server before the driver was asked, so pyodbc to MySQL got SQL
  Server rules. It now uses `getinfo(SQL_DBMS_NAME)`; no answer means unknown.
- **pytest 9.2 compatibility.** pytest 9.2 undoes a monkeypatch of a name
  that is not in the module's `__dict__` with `delattr`. For the package's
  log-once flags (`_warned_*`) that deleted the flag from its module, and later
  code that reads it failed. A delete through the package now restores the
  earlier value. Found when CI picked up pytest 9.2.0.

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
- MySQL executable comments (`/*! ... */`, `/*M! ... */`) passed the middleware.
  With `rewriter: regex`, `/*!DELETE FROM orders*/` ran unscoped and
  `... /*! OR 1=1 */` widened a scoped query to every tenant. They are now
  refused on every engine (predates this PR). The MySQL checks also run when
  the engine is not recognised.
- `rewriter: regex` passed a statement through unscoped when its table finder
  missed a table: `FROM (SELECT 1) t, orders`, `FROM (orders)`,
  `STRAIGHT_JOIN`, and a trailing MySQL `# comment` that hid the appended
  predicate. On MySQL these read every tenant's rows (predates this PR). It
  now refuses comma joins, parenthesised and derived tables and
  `STRAIGHT_JOIN` on every engine, and `#` on MySQL. The default `ast`
  rewriter was not affected.
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
