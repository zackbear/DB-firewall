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

Connect with your app's own URL and role, not an admin's, with `DB_FIREWALL_TENANT_KEY` set to the key the app uses (exit 2 without it). `verify` tests behaviour, not only the policies. It is read-only by default: each check runs in a transaction that is rolled back.

1. **The role:** RLS applies to it and to every role it is a member of. None is a superuser, has `BYPASSRLS`, is in `_firewall_bypass_roles`, or is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_execute_server_program`, `pg_read_server_files` or `pg_write_server_files`. The last three run programs or read and write files as the server.
2. **Firewall objects:** the functions the policies, the signing and the session reset use (`_firewall_is_bypass_role`, `_firewall_tenant`, `_firewall_sign`, `_firewall_nonce`, `_firewall_reset_session`, `_firewall_session_settings`) match the migration (body, `SECURITY DEFINER`, settings, volatility), and every `public._firewall_*` object has one owner. `scan` checks this too. Every function the migration creates is checked, and an extra `public._firewall_*` function fails. No role the app can use can `CREATE` in any schema (it could plant objects or operators, and reach them through a `search_path` it sets for itself with `ALTER ROLE ... SET`) or has `TRIGGER` on a table (a deferred trigger runs at COMMIT). No role the app can use can read `_firewall_keys` or execute `_firewall_sign` or `_firewall_set_tenant`. The role, and every role it can `SET ROLE` to, cannot write `_firewall_bypass_roles` or `_firewall_tenant_map`, column grants included (else it could add itself as a bypass role). It cannot act as the owner of schema `public` or of any `_firewall_*` object (else it could drop and replace the bypass list). On PostgreSQL 15 and later the database owner owns `public`, so do not make the app role the database owner.
3. **Tables found:** at least one table has the tenant column.
4. **Per table:**
   - the scan above passes;
   - the role does not own the table (an owner can turn RLS off);
   - the role has no `TRUNCATE` (RLS does not apply to it);
   - with no tenant, the role sees no rows;
   - with the tenant set but not signed, as SQL the app runs could set it, the role sees no rows (this fails on a plain context);
   - as `--tenant`, signed with the key, every visible row belongs to that tenant.
5. **Tenant has rows:** `--tenant` sees at least one row somewhere. A tenant with no rows proves nothing, so this fails.
6. **Read paths RLS does not guard,** in any schema, for the role and every role it can `SET ROLE` to: no foreign table (RLS does not reach remote data). No materialized view with the tenant column or built over a function. No view or materialized view the role can read (a column grant is enough) whose chain down to a tenant table holds a materialized view or a view that runs as an owner who skips RLS (use `security_invoker = true`). No `SECURITY DEFINER` function owned by such a role that the app can execute. A function body is not inspected, so every such function counts, except the firewall's own. No `LEAKPROOF` function outside `pg_catalog` (it runs before the RLS filter and can leak the rows it sees).
7. **Other schemas:** no table with the tenant column that the role can read (a column grant is enough) outside `--schema`.

A table no usable role can `SELECT` (such as a partition read through its parent) gets no row checks: there are no direct reads, and the other checks cover the rest. A table readable only after `SET ROLE` is inconclusive: run `verify` as that role. So is a row check whose query fails. A global check whose query fails counts as failed.

`--write-probe` also tries, per table, to insert a row for another tenant, which RLS must refuse. It is rolled back, but it fires `BEFORE INSERT` triggers and uses up a sequence value, so it is off by default. A refusal by anything other than RLS is inconclusive.

### What a pass means

A pass means `verify` found no known leak path. It does not prove isolation. It does not see:

- **Tenant data in tables without the tenant column,** such as child tables, audit logs or history tables. Give every table that holds tenant data the tenant column, so the migration protects it.
- **Copies made by triggers, rules or jobs** into a table the app can read, even a plain (not `SECURITY DEFINER`) trigger.
- **Side channels** that RLS leaves open: a `UNIQUE` or foreign-key error, or timing, can show that another tenant has a value.
- **Your app setting `app.current_tenant` itself.** `verify` assumes only the middleware (`withTenant`) sets it, from the authenticated session.
- **What one role shares.** All tenants use one database role, so its sessions can read each other's current query text (`pg_stat_activity`) and end each other's backends. The role can also change its own defaults (`ALTER ROLE CURRENT_USER SET ...`) so its later connections fail. That is availability and metadata, not another tenant's rows.
- **Privileges granted later.** `verify` checks the database as it is when it runs. Run it in CI and after every change to grants.

Run it in CI and after schema changes, and review triggers, rules and jobs that copy tenant rows.

Exit codes: 0 all checks passed; 1 a check failed; 2 usage or connection error; 3 no failure, but a check was inconclusive (not a pass).

## Tests

```bash
cd packages/cli && npm ci
DBFW_PG_URL="postgres://postgres@localhost:5432/dbfw_test" npm test
```

The tests run the CLI against a live PostgreSQL. They cover protected, unprotected, widened and altered tables, both policy modes, and each verify failure: a bypass role it is a member of, ownership of the table, of `public` or of a firewall function, column grants, `TRUNCATE`, a writable bypass list, definer views (also as a chain, or in another schema), materialized views, `SECURITY DEFINER` functions, other schemas, no tables, a tenant with no rows, partitions and an inconclusive probe.
