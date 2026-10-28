# db-firewall (CLI)

Install, scan and verify DB Firewall's tenant isolation on PostgreSQL, from Node. No Python needed.

```bash
npx db-firewall migrate --url "$ADMIN_URL"                     # install the RLS policies
npx db-firewall scan    --url "$DATABASE_URL" --strict         # CI gate: exit 1 if a table is unprotected
npx db-firewall verify  --url "$APP_URL" --tenant acme         # test isolation as your app's own role
```

## migrate

Runs `migrations/001_postgresql.sql` (shipped unchanged in this package) as an admin role. It protects every table in the schema that has the tenant column, and is safe to re-run after you add tables.

- `--column tenant_id`: the tenant column.
- `--schema public`: the schema.
- `--mode permissive|restrictive`: use `restrictive` when your app has RLS policies of its own (Supabase, Drizzle `pgPolicy`). The tenant policies are then AND-ed with them. See the main README, "Run the migration".

After the migration it prints the scan.

## scan

Lists every table in the schema that has the tenant column, and reports whether it is protected. Protected means all of these:

- RLS is enabled and forced.
- All four firewall policies exist.
- Each policy applies to `PUBLIC`, covers its own command, and uses exactly the migration's predicate. The CLI asks PostgreSQL to deparse that predicate on a temporary copy of the table, which is rolled back.
- In permissive mode, no other permissive policy exists on the table.

`--strict` exits 1 when a table is unprotected or no table is found (a wrong `--column` or `--schema`). `--json` prints `{ tables, excluded }`. Each table report has the Python scanner's fields (`hooks/scanner.py`) plus `schema` and `owner`. When the predicate check cannot run (a read-only transaction, no `TEMP` privilege, or no `SELECT` on the table), the report says why in `predicate_check`, and the table counts as unprotected.

`--schema` is repeatable. `--exclude <glob>` (repeatable, `*`, `?`, `[abc]`) replaces the default exclusions, which are exactly the tables the migration skips: `_firewall_*` and the migration-history tables (`schema_migrations`, `alembic_version`, `knex_migrations`, `prisma_migrations`, `__diesel_schema_migrations`, `flyway_schema_history`). Excluded tables are always listed in the output.

## verify

Connect with your app's own URL and role, not an admin's. `verify` tests behaviour, not only the policies. It is read-only by default: each check runs in a transaction that is rolled back.

1. **The role:** RLS applies to it and to every role it can `SET ROLE` to or inherits. None is a superuser, has `BYPASSRLS` or is in `_firewall_bypass_roles`.
2. **Firewall tables:** the role cannot write `_firewall_bypass_roles` or `_firewall_tenant_map` (else it could add itself as a bypass role).
3. **Tables found:** at least one table has the tenant column.
4. **Per table:**
   - the scan above passes;
   - the role does not own the table (an owner can turn RLS off);
   - the role has no `TRUNCATE` (RLS does not apply to it);
   - with no tenant, the role sees no rows;
   - as `--tenant`, every visible row belongs to that tenant.
5. **Tenant has rows:** `--tenant` sees at least one row somewhere. A tenant with no rows proves nothing, so this fails.
6. **Read paths RLS does not guard:** in the scanned schemas, no materialized view over a tenant table, no view that runs as an owner who skips RLS (use `security_invoker = true`), and no `SECURITY DEFINER` function owned by such a role that the app can execute.
7. **Other schemas:** no table with the tenant column that the role can read outside `--schema`.

A table the role cannot `SELECT` gets no row checks, and that is reported as inconclusive.

`--write-probe` also tries, per table, to insert a row for another tenant, which RLS must refuse. It is rolled back, but it fires `BEFORE INSERT` triggers and uses up a sequence value, so it is off by default. A refusal by anything other than RLS is inconclusive.

Exit codes: 0 all checks passed; 1 a check failed; 2 usage or connection error; 3 no failure, but a check was inconclusive (not a pass).

## Tests

```bash
cd packages/cli && npm ci
DBFW_PG_URL="postgres://postgres@localhost:5432/dbfw_test" npm test
```

The tests run the CLI against a live PostgreSQL. They cover protected, unprotected, widened and altered tables, both policy modes, and each verify failure: a bypass role reachable by `SET ROLE`, table ownership, `TRUNCATE`, a writable bypass list, definer views, materialized views, `SECURITY DEFINER` functions, other schemas, no tables, a tenant with no rows and an inconclusive probe.
