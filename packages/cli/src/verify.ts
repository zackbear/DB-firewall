// verify: connect as the app's own role and test the isolation, not just the
// policies' presence. Every check runs in a transaction that is rolled back.
import type pg from "pg";
import { ident, scan, type TableReport } from "./scan.js";

export interface Check { table: string; check: string; ok: boolean | null; detail: string }

const RLS_VIOLATION = "42501";       // insufficient_privilege: what an RLS refusal raises
const MARK = "__dbfw_verify_other__";

/** Throws unless RLS applies to the connected role (same rule as assertSafeRole). */
export async function roleCheck(client: pg.ClientBase): Promise<Check> {
  try {
    const { rows } = await client.query(
      "SELECT r.rolname, r.rolsuper, r.rolbypassrls, public._firewall_is_bypass_role(current_user::text) AS fw " +
      "FROM pg_roles r WHERE r.rolname = current_user");
    const r = rows[0];
    const why = r.rolsuper ? "is a superuser" : r.rolbypassrls ? "has BYPASSRLS"
      : r.fw ? "is in _firewall_bypass_roles" : "";
    return { table: "-", check: "role", ok: !why,
             detail: why ? `role ${r.rolname} ${why}: RLS does not apply to it` : `role ${r.rolname}` };
  } catch (err) {
    return { table: "-", check: "role", ok: false,
             detail: `could not check (is the migration installed?): ${(err as Error).message}` };
  }
}

/** Run fn in a transaction (optionally as tenant) and always roll back. */
async function inTx<T>(client: pg.ClientBase, tenant: string | null, fn: () => Promise<T>): Promise<T> {
  await client.query("BEGIN");
  try {
    if (tenant !== null) await client.query("SELECT set_config('app.current_tenant', $1, true)", [tenant]);
    return await fn();
  } finally {
    await client.query("ROLLBACK");
  }
}

export async function verify(client: pg.ClientBase, opts: {
  tenant: string; schema?: string; column?: string; exclude?: string[];
}): Promise<{ checks: Check[]; tables: TableReport[] }> {
  const schema = opts.schema ?? "public", column = opts.column ?? "tenant_id";
  const checks: Check[] = [await roleCheck(client)];
  const tables = await scan(client, { schema, column, exclude: opts.exclude });
  for (const t of tables) {
    const name = `${ident(schema)}.${ident(t.table)}`;
    checks.push({ table: t.table, check: "policies", ok: t.protected,
                  detail: t.protected ? `${t.policy_mode} policies in place` : summary(t) });
    // 1. No tenant: no rows at all (fail closed).
    try {
      const n = await inTx(client, null, async () =>
        Number((await client.query(`SELECT count(*) AS n FROM ${name}`)).rows[0].n));
      checks.push({ table: t.table, check: "no tenant sees nothing", ok: n === 0, detail: `${n} rows visible` });
    } catch (err) {
      checks.push(skipped(t.table, "no tenant sees nothing", err));
      continue;                                   // no SELECT on this table: nothing else to test
    }
    // 2. As the tenant: every visible row is the tenant's.
    const foreign = await inTx(client, opts.tenant, async () => Number((await client.query(
      `SELECT count(*) AS n FROM ${name} WHERE ${ident(column)} IS DISTINCT FROM $1`, [opts.tenant])).rows[0].n));
    checks.push({ table: t.table, check: "tenant sees only its rows", ok: foreign === 0,
                  detail: `${foreign} rows of another tenant visible` });
    // 3. As the tenant: a row for another tenant is refused.
    try {
      await inTx(client, opts.tenant, () =>
        client.query(`INSERT INTO ${name} (${ident(column)}) VALUES ($1)`, [MARK]));
      checks.push({ table: t.table, check: "cross-tenant insert refused", ok: false,
                    detail: "a row for another tenant was accepted (rolled back)" });
    } catch (err) {
      const code = (err as { code?: string }).code;
      checks.push(code === RLS_VIOLATION && /row-level security/i.test(String((err as Error).message))
        ? { table: t.table, check: "cross-tenant insert refused", ok: true, detail: "refused by RLS" }
        : { table: t.table, check: "cross-tenant insert refused", ok: null,
            detail: `inconclusive: ${(err as Error).message.split("\n")[0]}` });
    }
  }
  return { checks, tables };
}

function summary(t: TableReport): string {
  const parts = [];
  if (!t.rls_enabled) parts.push("RLS off");
  if (!t.rls_forced) parts.push("RLS not forced");
  if (t.missing_policies.length) parts.push(`missing ${t.missing_policies.join(",")}`);
  if (t.altered_policies.length) parts.push(`altered ${t.altered_policies.join(",")}`);
  if (t.policy_mode === "permissive" && t.extra_permissive_policies.length) {
    parts.push(`extra permissive ${t.extra_permissive_policies.join(",")}`);
  }
  if (t.predicate_check !== "ok") parts.push(t.predicate_check);
  return parts.join("; ") || "not protected";
}

function skipped(table: string, check: string, err: unknown): Check {
  return { table, check, ok: null, detail: `skipped: ${(err as Error).message.split("\n")[0]}` };
}
