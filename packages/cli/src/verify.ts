// verify: connect as the app's own role and test the isolation, not just the
// policies' presence. Read-only by default: every check runs in a transaction
// that is rolled back, and nothing is written unless --write-probe is given.
import type pg from "pg";
import { ident, scan, type TableReport } from "./scan.js";

/** ok: true pass, false fail, null inconclusive (counted separately, never as a pass). */
export interface Check { table: string; check: string; ok: boolean | null; detail: string }

const RLS_VIOLATION = "42501";       // insufficient_privilege: what an RLS refusal raises
const MARK = "__dbfw_verify_other__";

// A role that skips RLS: superuser, BYPASSRLS, or listed in _firewall_bypass_roles.
const BYPASSES = "(r.rolsuper OR r.rolbypassrls OR public._firewall_is_bypass_role(r.rolname::text))";

/**
 * The role and every role it can SET ROLE to (or inherits): none may skip RLS.
 * Also: the app must not be able to write the firewall's own tables.
 */
export async function roleChecks(client: pg.ClientBase): Promise<Check[]> {
  const out: Check[] = [];
  try {
    const { rows } = await client.query(
      `SELECT r.rolname, r.rolname = current_user AS self, r.rolsuper, r.rolbypassrls,
              public._firewall_is_bypass_role(r.rolname::text) AS fw
       FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER') AND ${BYPASSES}`);
    const why = (r: any) => r.rolsuper ? "is a superuser" : r.rolbypassrls ? "has BYPASSRLS"
      : "is in _firewall_bypass_roles";
    out.push(rows.length
      ? { table: "-", check: "role", ok: false, detail: rows.map((r) => r.self
            ? `role ${r.rolname} ${why(r)}` : `can SET ROLE ${r.rolname}, which ${why(r)}`).join("; ") +
            ": RLS does not apply" }
      : { table: "-", check: "role", ok: true, detail: "no role it can use skips RLS" });
    const { rows: w } = await client.query(
      `SELECT t AS name FROM unnest(ARRAY['public._firewall_bypass_roles', 'public._firewall_tenant_map']) t
       WHERE to_regclass(t) IS NOT NULL
         AND has_table_privilege(current_user, t, 'INSERT, UPDATE, DELETE, TRUNCATE')`);
    out.push({ table: "-", check: "cannot write firewall tables", ok: w.length === 0,
               detail: w.length ? `can write ${w.map((x) => x.name).join(", ")} (could add itself as a bypass role)`
                                : "no write access" });
  } catch (err) {
    out.push({ table: "-", check: "role", ok: false,
               detail: `could not check (is the migration installed?): ${msg(err)}` });
  }
  return out;
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
  tenant: string; schemas?: string[]; column?: string; exclude?: string[]; writeProbe?: boolean;
}): Promise<{ checks: Check[]; tables: TableReport[]; excluded: string[] }> {
  const schemas = opts.schemas?.length ? opts.schemas : ["public"];
  const column = opts.column ?? "tenant_id";
  const checks: Check[] = await roleChecks(client);
  const { tables, excluded } = await scan(client, { schemas, column, exclude: opts.exclude });
  if (!tables.length) {
    checks.push({ table: "-", check: "tables found", ok: false,
                  detail: `no table with column ${column} in ${schemas.join(", ")} (wrong --column or --schema?)` });
  }
  let ownRows = 0;
  for (const t of tables) {
    const label = `${t.schema}.${t.table}`, name = `${ident(t.schema)}.${ident(t.table)}`;
    checks.push({ table: label, check: "policies", ok: t.protected,
                  detail: t.protected ? `${t.policy_mode} policies in place` : summary(t) });
    // Privileges RLS does not cover: the owner can turn RLS off; TRUNCATE ignores it.
    const { rows: [priv] } = await client.query(
      `SELECT pg_has_role(current_user, c.relowner, 'MEMBER') AS owns,
              has_table_privilege(current_user, c.oid, 'TRUNCATE') AS truncate,
              has_table_privilege(current_user, c.oid, 'SELECT') AS can_select
       FROM pg_class c WHERE c.oid = $1::regclass`, [name]);
    checks.push({ table: label, check: "role does not own the table", ok: !priv.owns,
                  detail: priv.owns ? `owned by ${t.owner}, which this role can act as: it can disable RLS`
                                    : `owned by ${t.owner}` });
    checks.push({ table: label, check: "no TRUNCATE", ok: !priv.truncate,
                  detail: priv.truncate ? "TRUNCATE is granted and RLS does not apply to it" : "not granted" });
    if (!priv.can_select) {
      checks.push({ table: label, check: "row checks", ok: null, detail: "skipped: no SELECT on the table" });
      continue;
    }
    // No tenant: no rows at all (fail closed).
    const none = await inTx(client, null, async () =>
      Number((await client.query(`SELECT count(*) AS n FROM ${name}`)).rows[0].n));
    checks.push({ table: label, check: "no tenant sees nothing", ok: none === 0, detail: `${none} rows visible` });
    // As the tenant: every visible row is the tenant's.
    const [foreign, own] = await inTx(client, opts.tenant, async () => {
      const { rows: [r] } = await client.query(
        `SELECT count(*) FILTER (WHERE ${ident(column)} IS DISTINCT FROM $1) AS foreign,
                count(*) FILTER (WHERE ${ident(column)} = $1) AS own FROM ${name}`, [opts.tenant]);
      return [Number(r.foreign), Number(r.own)];
    });
    ownRows += own;
    checks.push({ table: label, check: "tenant sees only its rows", ok: foreign === 0,
                  detail: `${own} own rows, ${foreign} rows of another tenant visible` });
    if (opts.writeProbe) checks.push(await writeProbe(client, label, name, column, opts.tenant));
  }
  if (tables.length && ownRows === 0) {
    checks.push({ table: "-", check: "tenant has rows", ok: false,
                  detail: `tenant ${opts.tenant} sees no rows in any table, so the row checks prove nothing: use a tenant that has data` });
  }
  checks.push(...await bypassObjects(client, schemas, column));
  checks.push(await otherSchemas(client, schemas, column));
  return { checks, tables, excluded };
}

/**
 * Opt-in (--write-probe): insert a row for another tenant as --tenant, which
 * RLS must refuse. Rolled back, but it fires BEFORE INSERT triggers and uses
 * up a sequence value even when refused.
 */
async function writeProbe(client: pg.ClientBase, label: string, name: string, column: string,
                          tenant: string): Promise<Check> {
  try {
    await inTx(client, tenant, () => client.query(`INSERT INTO ${name} (${ident(column)}) VALUES ($1)`, [MARK]));
    return { table: label, check: "cross-tenant insert refused", ok: false,
             detail: "a row for another tenant was accepted (rolled back)" };
  } catch (err) {
    const code = (err as { code?: string }).code;
    return code === RLS_VIOLATION && /row-level security/i.test(msg(err))
      ? { table: label, check: "cross-tenant insert refused", ok: true, detail: "refused by RLS" }
      : { table: label, check: "cross-tenant insert refused", ok: null, detail: `inconclusive: ${msg(err)}` };
  }
}

/**
 * Read paths RLS does not guard, in the scanned schemas, that the role can use:
 * a materialized view over a protected table (no RLS at all); a view that runs
 * as an owner who skips RLS (not security_invoker); a SECURITY DEFINER
 * function owned by such a role (the firewall's own functions aside).
 */
async function bypassObjects(client: pg.ClientBase, schemas: string[], column: string): Promise<Check[]> {
  const { rows: views } = await client.query(
    `SELECT DISTINCT n.nspname || '.' || v.relname AS name, v.relkind = 'm' AS matview,
            pg_get_userbyid(v.relowner) AS owner
     FROM pg_class v JOIN pg_namespace n ON n.oid = v.relnamespace
     JOIN pg_rewrite rw ON rw.ev_class = v.oid
     JOIN pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_rewrite'::regclass
     JOIN pg_class t ON t.oid = d.refobjid AND t.oid <> v.oid AND t.relkind IN ('r', 'p')
     JOIN pg_roles r ON r.oid = v.relowner
     WHERE v.relkind IN ('v', 'm') AND n.nspname = ANY($1)
       AND has_table_privilege(current_user, v.oid, 'SELECT')
       AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = t.oid AND a.attname = $2
                     AND a.attnum > 0 AND NOT a.attisdropped)
       AND (v.relkind = 'm' OR (NOT COALESCE('security_invoker=true' = ANY(v.reloptions)
                                            OR 'security_invoker=on' = ANY(v.reloptions), false)
                               AND ${BYPASSES}))
     ORDER BY 1`, [schemas, column]);
  const { rows: fns } = await client.query(
    `SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS name,
            pg_get_userbyid(p.proowner) AS owner
     FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
     WHERE p.prosecdef AND n.nspname = ANY($1) AND p.proname NOT LIKE '#_firewall#_%' ESCAPE '#'
       AND has_function_privilege(current_user, p.oid, 'EXECUTE') AND ${BYPASSES}
     ORDER BY 1`, [schemas]);
  const list = [
    ...views.map((v) => `${v.matview ? "materialized view" : "view"} ${v.name} (owner ${v.owner})`),
    ...fns.map((f) => `SECURITY DEFINER function ${f.name} (owner ${f.owner})`),
  ];
  return [{ table: "-", check: "no RLS-bypassing views or functions", ok: list.length === 0,
            detail: list.length ? `the role can read through: ${list.join("; ")}` : "none found" }];
}

/** Tables with the tenant column outside the scanned schemas that the role can read. */
async function otherSchemas(client: pg.ClientBase, schemas: string[], column: string): Promise<Check> {
  const { rows } = await client.query(
    `SELECT n.nspname || '.' || c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p') AND NOT (n.nspname = ANY($1))
       AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
       AND has_table_privilege(current_user, c.oid, 'SELECT')
       AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $2
                     AND a.attnum > 0 AND NOT a.attisdropped)
     ORDER BY 1`, [schemas, column]);
  return { table: "-", check: "no tenant tables in other schemas", ok: rows.length === 0,
           detail: rows.length ? `not checked, readable: ${rows.map((r) => r.name).join(", ")} (add --schema)`
                               : "none readable" };
}

function summary(t: TableReport): string {
  const parts = [];
  if (!t.rls_enabled) parts.push("RLS off");
  else if (!t.rls_forced) parts.push("RLS not forced");
  if (t.missing_policies.length) parts.push(`missing ${t.missing_policies.join(",")}`);
  if (t.altered_policies.length) parts.push(`altered ${t.altered_policies.join(",")}`);
  if (t.policy_mode === "permissive" && t.extra_permissive_policies.length) {
    parts.push(`extra permissive ${t.extra_permissive_policies.join(",")}`);
  }
  if (t.predicate_check !== "ok") parts.push(t.predicate_check);
  return parts.join("; ") || "not protected";
}

const msg = (err: unknown) => String((err as Error).message).split("\n")[0] ?? "error";
