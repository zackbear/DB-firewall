# db-firewall (CLI)

Install, scan and verify DB Firewall's tenant isolation on PostgreSQL, from Node. No Python needed.

```bash
export DB_FIREWALL_TENANT_KEY=$(openssl rand -hex 32)          # the app uses the same key
npx db-firewall migrate --url "$ADMIN_URL"                     # install the RLS policies and the key
npx db-firewall scan    --url "$DATABASE_URL" --strict         # CI gate: exit 1 if a table is unprotected
npx db-firewall verify  --url "$APP_URL" --tenant acme         # test isolation as your app's own role
npx db-firewall key     --url "$ADMIN_URL"                     # print the database's key
```

## migrate

Runs `migrations/001_postgresql.sql` (shipped unchanged in this package) as an admin role. It protects every table in the schema that has the tenant column, and is safe to re-run after you add tables.

- `--column tenant_id`: the tenant column.
- `--schema public`: the schema.
- `--mode permissive|restrictive`: use `restrictive` when your app has RLS policies of its own (Supabase, Drizzle `pgPolicy`). The tenant policies are then AND-ed with them. See the main README, "Run the migration".
- `--harden-signals`: revoke `pg_terminate_backend` and `pg_cancel_backend` from `PUBLIC` in this database, so tenants sharing the app role cannot end or cancel each other's requests. It covers every app and role in the database, so it is off by default and needs a superuser.
- `--harden --app-role <role>`: also revoke what `verify` fails on that the migration can remove, from `PUBLIC` and the app role, whoever granted it: `CREATE` on the database and on every schema, `TRIGGER` and `TRUNCATE` on every table and in default privileges (so tables created later do not get them), `pg_stat_activity` with `pg_stat_get_activity` and `pg_stat_get_backend_activity` (all tenants share one role, so its sessions see each other's SQL text), and the backend signals (as `--harden-signals`). `SELECT`, `INSERT`, `UPDATE` and `DELETE` stay. It covers the whole database, so it is off by default and needs a superuser. It refuses, and changes nothing, when the app role can act as the owner of the database or of any object in it (an owner can grant itself everything back: give them to another role first), or still has one of these privileges through a role it is a member of. `CASCADE` also removes what the app role passed on with a grant option. Roles that only have `pg_monitor` lose `pg_stat_activity` too: grant it to them again. Default privileges granted to a group role the app is in are not changed; `verify` fails on what they grant. Give the bare role name, without quotes. Run it again after granting new privileges (`GRANT ALL` includes `TRIGGER` and `TRUNCATE`).
- `--ddl-guard`: install the DDL guard, two event triggers in this database that run at the end of every DDL command. Aft A table with the tenant column that has no firewall policies (created, renamed, given the column later, a new partition or child, or a typed table changed by `ALTER TYPE ... CASCADE`) is protected at the end of the command, the way the migration would, so it is never open until the next run. A table with a permissive policy of its own, in permissive mode, is refused instead. A command that weakens a protected table (one with firewall policies) fails: RLS turned off or not forced, a firewall policy dropped, renamed or altered (also by dropping the tenant column with `CASCADE`), another permissive policy in permissive mode (it ORs with the tenant policies), the table taken out of what the migration protects (moved to another schema, renamed to a name the migration skips, its tenant column renamed, its schema renamed), or given a parent, child or partition that is not protected, either way round (`INHERIT`, `ATTACH PARTITION`, `PARTITION OF` in another schema or as a foreign table: reading the parent shows the child's rows, and a partition gets the rows written to the parent). A rule on a protected table fails. Policy names `fw_<hash>_*` are the firewall's: no command may create one, rename a policy to one, or alter one. `TRIGGER` and `TRUNCATE` granted to another role are revoked again. A renamed table gets the policies of its new name. Not stopped: code the table's owner attaches to it (a trigger, a CHECK constraint, a default, a generated column, an index expression, a domain constraint) runs on every tenant's writes, and can copy them out. Dropping the table is fine. It binds every role, table owners included, but a superuser and the role that owns the migration's objects: only they can skip it with `SET dbfw.ddl_guard_skip = 'on'` (the migration sets it for itself), and only a superuser can remove it (`DROP EVENT TRIGGER _firewall_ddl_guard, _firewall_ddl_drop_guard`). A later run without the flag leaves it in place. It needs a superuser. `verify` reports whether it is on.
- `--context signed|plain`: `signed` (default) makes the policies accept a tenant only with a signature made with the key for the current transaction, so SQL the app runs cannot switch tenants. `DB_FIREWALL_TENANT_KEY`, when set, is installed (or rotated to); otherwise the database keeps its key, or generates one on the first run (`db-firewall key` prints it). See the main README, "PostgreSQL tenant context".

After the migration it prints the scan.

## scan

Lists every table in the schema that has the tenant column, and reports whether it is protected. Protected means all of these:

- RLS is enabled and forced.
- All four firewall policies exist.
- Each policy applies to `PUBLIC`, covers its own command, and uses exactly the migration's predicate, read with `search_path = pg_catalog`, so an operator planted in another schema shows. The CLI asks PostgreSQL to deparse that predicate on a temporary copy of the table, which is rolled back.
- In permissive mode, no other permissive policy exists on the table.
- The firewall functions match the migration and every `public._firewall_*` object has one owner (see verify, 2).
- The policies use the expected tenant context, `--context signed` (the default) or `plain`. `tenant_context` in the report names the one they use.

`--strict` exits 1 when a table is unprotected or no table is found (a wrong `--column` or `--schema`). `--json` prints `{ tables, excluded }`. Each table report has the Python scanner's fields (`hooks/scanner.py`) plus `schema` and `owner`. When the predicate check cannot run (a read-only transaction, no `TEMP` privilege, or no `SELECT` on the table), the report says why in `predicate_check`, and the table counts as unprotected.

`--schema` is repeatable. `--exclude <glob>` (repeatable, `*`, `?`, `[abc]`) replaces the default exclusions, which are exactly the tables the migration skips: `_firewall_*` and the migration-history tables (`schema_migrations`, `alembic_version`, `knex_migrations`, `prisma_migrations`, `__diesel_schema_migrations`, `flyway_schema_history`). Excluded tables are always listed in the output.

## verify

The checks are the shared queries in `checks/postgresql.sql` (shipped as `sql/checks_postgresql.sql`); `python -m hooks.verify` in the repository runs the same file, with the same results.

Connect with your app's own URL and role, not an admin's, with `DB_FIREWALL_TENANT_KEY` set to the key the app uses (exit 2 without it). `verify` tests behaviour, not only the policies. It is read-only by default: each check runs in a transaction that is rolled back.

1. **The role:** RLS applies to it and to every role it is a member of. None is a superuser, has `BYPASSRLS`, is in `_firewall_bypass_roles`, or is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_execute_server_program`, `pg_read_server_files` or `pg_write_server_files`. The last three run programs or read and write files as the server.
2. **Firewall objects:** the functions the policies, the signing and the session reset use (`_firewall_is_bypass_role`, `_firewall_tenant`, `_firewall_sign`, `_firewall_nonce`, `_firewall_reset_session`, `_firewall_session_settings`) match the migration (body, `SECURITY DEFINER`, settings, volatility), and every `public._firewall_*` object has one owner. `scan` checks this too. Every function the migration creates is checked, and an extra `public._firewall_*` function fails. No role the app can use can `CREATE` in any schema or owns one, or the database (it could plant objects or operators, and reach them through a `search_path` it sets for itself with `ALTER ROLE ... SET`), or has `TRIGGER` on a table or owns one (a deferred trigger runs at COMMIT). No role the app can use can read `_firewall_keys` or execute `_firewall_sign` or `_firewall_set_tenant`. The role, and every role it can `SET ROLE` to, cannot write `_firewall_bypass_roles` or `_firewall_tenant_map`, column grants included (else it could add itself as a bypass role). It cannot act as the owner of schema `public` or of any `_firewall_*` object (else it could drop and replace the bypass list), nor of the database or any object in it, temporary objects and large objects aside (an owner can change a domain constraint or a function body that runs in other tenants' sessions, or grant itself its rights back). On PostgreSQL 15 and later the database owner owns `public`, so do not make the app role the database owner.
3. **Tables found:** at least one table has the tenant column.
4. **Per table:**
   - the scan above passes;
   - the role does not own the table (an owner can turn RLS off);
   - the role has no `TRUNCATE` (RLS does not apply to it);
   - with no tenant, the role sees no rows;
   - with the tenant set but not signed, as SQL the app runs could set it, the role sees no rows (this fails on a plain context);
   - as `--tenant`, signed with the key, every visible row belongs to that tenant.
5. **Tenant has rows:** `--tenant` sees at least one row somewhere. A tenant with no rows proves nothing, so this fails.
6. **Read paths RLS does not guard,** in any schema, for the role and every role it can `SET ROLE` to: no foreign table (RLS does not reach remote data). No materialized view with the tenant column or built over a function. No view or materialized view the role can read (a column grant is enough) whose chain down to a tenant table holds a materialized view or a view that runs as an owner who skips RLS (use `security_invoker = true`). No `SECURITY DEFINER` function owned by such a role that the app can execute, or that PostgreSQL runs without checking `EXECUTE`: a trigger or event trigger function, an aggregate's or range type's support function, index support (an operator family's operators too), a selectivity estimator, planner support, type I/O, an encoding conversion, a transform, a text search parser or template, or a foreign-data wrapper's or language's handler or validator. A function body is not inspected, so every such function counts, except the firewall's own. No `LEAKPROOF` function outside `pg_catalog` (it runs before the RLS filter and can leak the rows it sees). No rule other than a view's own, on any table or view (a rule's actions run as the table owner, and a write reaches a table through a view, a column grant or a cascade): use a trigger instead.
7. **Other schemas:** no table with the tenant column that the role can read (a column grant is enough) outside `--schema`.

A table no usable role can `SELECT` (such as a partition read through its parent) gets no row checks: there are no direct reads, and the other checks cover the rest. A table readable only after `SET ROLE` is inconclusive: run `verify` as that role. So is a row check whose query fails. A global check whose query fails counts as failed.

`--write-probe` also tries, per table, to insert a row for another tenant, which RLS must refuse. It is rolled back, but it fires `BEFORE INSERT` triggers and uses up a sequence value, so it is off by default. A refusal by anything other than RLS is inconclusive.

### Strict mode (`--strict`)

The checks above look for known leak paths. `--strict` turns that into an allowlist, so unknown paths fail too. Everything a role the app can use can read must be protected tenant data:

- a table the migration protects;
- a `security_invoker` view that reads at least one table, calls no function outside `pg_catalog`, and whose chain reaches only protected tables (no materialized view, foreign table or definer view on the way). Constants in a view body (`VALUES`, literals) cannot be seen;
- a sequence a protected table owns (`serial`, identity). Its value is shared: `nextval` shows how many rows all tenants have inserted.

Anything else the app can read fails: a table without the tenant column (an audit log, a history table, a reference table), an invoker view over one or over constants, a standalone sequence, a foreign table. Also:

- no large object may be readable (they are one store for the whole database, with no tenant);
- the role may not read other sessions' SQL in `pg_stat_activity` or `pg_stat_statements` (literal values in another tenant's queries). `migrate --harden` revokes it. On managed PostgreSQL only the provider's superuser can, so `--allow-query-text` turns this check into an information line: send values as parameters. Without `--strict` it is an information line. With `--allow-query-text`, `pg_stat_statements`' own views (`pg_stat_statements`, `pg_stat_statements_info`) are accepted as readable too;
- no `SECURITY DEFINER` function outside the firewall's own may exist, executable or not, because it runs as its owner, whatever it reads, and PostgreSQL runs some functions (triggers, aggregate, range and index support, type I/O) without checking `EXECUTE`.

`--allow-global` (repeatable, `*`, `?` and `[abc]` globs; it needs `--strict`) marks data every tenant may share, such as a list of countries: `schema.name` for a table, view or sequence, `schema.name(argtypes)` for a function, as verify prints it (`app.f(*)` for every overload, and for array types; `app.*` never clears a function). In the bypass-objects check it clears only functions, such as a platform's own definer functions, and foreign tables without the tenant column; never a view over a tenant table or a rule. Allowlist deliberately: an allowlisted table that holds tenant data is a leak.

Strict mode closes most of what "What a pass means" lists below: tenant data in tables without the tenant column, and copies into readable tables, now fail unless you allowlist them.

### What a pass means

A pass means `verify` found no known leak path. It does not prove isolation. It does not see:

- **Tenant data in tables without the tenant column,** such as child tables, audit logs or history tables. Give every table that holds tenant data the tenant column, so the migration protects it. `--strict` fails on such tables unless you allowlist them.
- **Copies made by triggers, rules or jobs** into a table the app can read, even a plain (not `SECURITY DEFINER`) trigger. `--strict` fails on the readable target unless it is protected or allowlisted.
- **Side channels** that RLS leaves open: a `UNIQUE` or foreign-key error, or timing, can show that another tenant has a value. `verify` lists the keys on protected tables that leave out the tenant column (an information line; `--strict` fails on them): a unique key or primary key, an expression index included, and a foreign key from any table to a protected one. A single-column key on a generated value (an identity column, or a default from a sequence, `gen_random_uuid()` or `uuid_generate_v1`/`v4`) is not listed: a duplicate only shows that an id is taken. An exclusion constraint counts as a unique key, and its tenant column counts only with `=`. A foreign key passes only when the referencing table is protected and its own tenant column fills the referenced tenant column, so a plain `doc_id REFERENCES docs (id)` fails `--strict` (the app can link to, and probe for, another tenant's row). Put the tenant column in the key, as `UNIQUE (tenant_id, email)` and `FOREIGN KEY (tenant_id, doc_id) REFERENCES docs (tenant_id, id)`. Timing is not checked.
- **Your app setting `app.current_tenant` itself.** `verify` assumes only the middleware (`withTenant`) sets it, from the authenticated session.
- **What one role shares.** All tenants use one database role, so its sessions can read each other's current query text (`pg_stat_activity`: `migrate --harden` stops that, `--strict` fails on it), which can hold another tenant's literal values, and end each other's backends (`migrate --harden-signals` stops that). The role can also change its own defaults (`ALTER ROLE CURRENT_USER SET ...`) so its later connections fail; that is availability only. Information lines in `verify` report whether the role can signal other sessions or read their SQL, and which role-level defaults are set; they never fail.
- **Privileges granted later.** `verify` checks the database as it is when it runs. Run it in CI and after every change to grants.

Run it in CI and after schema changes, and review triggers, rules and jobs that copy tenant rows.

Exit codes: 0 all checks passed; 1 a check failed; 2 usage or connection error; 3 no failure, but a check was inconclusive (not a pass).

## Tests

```bash
cd packages/cli && npm ci
DBFW_PG_URL="postgres://postgres@localhost:5432/dbfw_test" npm test
```

The tests run the CLI against a live PostgreSQL (CI: 14, 15, 16 and 17). `test/attacks.test.mjs` runs the attack corpus, `tests/attacks/postgresql.sql` in the repository: for each attack, `verify` must fail the named check, and its leak query, when it has one, must show data tenant A must not see; safe patterns must pass. The parser rejects an unknown or repeated directive, and the test pins the number of cases. Cases that need a newer server (`security_invoker` views need 15, `GRANT ... WITH INHERIT FALSE` needs 16) are skipped on older ones. They cover protected, unprotected, widened and altered tables, both policy modes, and each verify failure: a bypass role it is a member of, ownership of the table, of `public` or of a firewall function, column grants, `TRUNCATE`, a writable bypass list, definer views (also as a chain, or in another schema), materialized views, `SECURITY DEFINER` functions, other schemas, no tables, a tenant with no rows, partitions and an inconclusive probe.
