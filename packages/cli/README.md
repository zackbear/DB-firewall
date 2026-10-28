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

`--strict` exits 1 when a table is unprotected. `--json` prints the full report, which has the same fields as the Python scanner (`hooks/scanner.py`). When the predicate check cannot run (a read-only transaction, or no `TEMP` privilege), the report says why in `predicate_check`, and the table counts as unprotected.

`--exclude <glob>` (repeatable) replaces the default exclusions: `_firewall_*`, the common migration-history tables, `app_config` and `feature_flags`.

## verify

Connect with your app's own URL and role, not an admin's. `verify` tests behaviour, not only the policies. Each check runs in a transaction that is rolled back:

1. **The role:** RLS applies to it, so it is not a superuser, not `BYPASSRLS`, and not in `_firewall_bypass_roles`.
2. **The policies:** the scan above passes for each table.
3. **No tenant:** the role sees no rows.
4. **As `--tenant`:** every visible row belongs to that tenant.
5. **Cross-tenant insert:** an insert of a row for another tenant is refused by RLS. Any other error is reported as inconclusive (`--`), not as a pass.

It exits 1 when any check fails. A table the role cannot `SELECT` is skipped and reported.

Exit codes: 0 ok, 1 a check failed, 2 usage or connection error.

## Tests

```bash
cd packages/cli && npm ci
DBFW_PG_URL="postgres://postgres@localhost:5432/dbfw_test" npm test
```

The tests run the CLI against a live PostgreSQL. They cover protected, unprotected, widened and altered tables, the superuser role check, and both policy modes.
