// verify: connect as the app's own role and test the isolation, not just the
// policies' presence. Read-only by default: every check runs in a transaction
// that is rolled back, and nothing is written unless --write-probe is given.
import type pg from "pg";
import { readFileSync } from "node:fs";
import { MIGRATION } from "./migrate.js";
import { ident, scan, type TableReport } from "./scan.js";

/** ok: true pass, false fail, null inconclusive (counted separately, never as a pass). */
export interface Check { table: string; check: string; ok: boolean | null; detail: string }

const RLS_VIOLATION = "42501";       // insufficient_privilege: what an RLS refusal raises
const MARK = "__dbfw_verify_other__";

// A role that skips RLS: superuser, BYPASSRLS, or listed in _firewall_bypass_roles.
const BYPASSES = "(r.rolsuper OR r.rolbypassrls OR public._firewall_is_bypass_role(r.rolname::text))";

/**
 * True when any role the app can use holds the privilege: itself, a role it
 * inherits, or one it can SET ROLE to. expr names that role m.oid.
 * ponytail: MEMBER also counts a grant WITH INHERIT FALSE, SET FALSE (a false fail).
 */
const anyRole = (expr: string) =>
  `EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER') AND ${expr})`;

/**
 * The role and every role it can SET ROLE to (or inherits): none may skip RLS.
 * Also: the app must not be able to write the firewall's own tables.
 */
export async function roleChecks(client: pg.ClientBase): Promise<Check[]> {
  const why = (r: any) => r.rolsuper ? "is a superuser" : r.rolbypassrls ? "has BYPASSRLS"
    : "is in _firewall_bypass_roles";
  // One client runs one query at a time: run the checks in order.
  const checks: (() => Promise<Check>)[] = [
    () => guard("role", async () => {
      const { rows } = await client.query(
        `SELECT r.rolname, r.rolname = current_user AS self, r.rolsuper, r.rolbypassrls,
                public._firewall_is_bypass_role(r.rolname::text) AS fw
         FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER') AND ${BYPASSES}`);
      return rows.length
        ? { ok: false, detail: rows.map((r) => r.self ? `role ${r.rolname} ${why(r)}`
              : `is a member of ${r.rolname}, which ${why(r)}`).join("; ") + ": RLS does not apply" }
        : { ok: true, detail: "no role it can use skips RLS" };
    }),
    () => guard("cannot write firewall tables", async () => {
      const { rows } = await client.query(
        `SELECT t AS name FROM unnest(ARRAY['public._firewall_bypass_roles', 'public._firewall_tenant_map']) t
         WHERE to_regclass(t) IS NOT NULL
           AND ${anyRole(`(has_any_column_privilege(m.oid, t, 'INSERT') OR has_any_column_privilege(m.oid, t, 'UPDATE')
                           OR has_table_privilege(m.oid, t, 'DELETE, TRUNCATE'))`)}`);
      return { ok: rows.length === 0, detail: rows.length
        ? `can write ${rows.map((x) => x.name).join(", ")} (could add itself as a bypass role)` : "no write access" };
    }),
    // The owner of schema public (on PG15+ the database owner, via pg_database_owner)
    // can drop the bypass list and create its own; an owner of a firewall object can replace it.
    () => guard("does not own firewall objects", async () => {
      const { rows } = await client.query(
        `SELECT 'schema public' AS name FROM pg_namespace WHERE nspname = 'public' AND pg_has_role(current_user, nspowner, 'MEMBER')
         UNION ALL SELECT 'table ' || relname FROM pg_class WHERE relnamespace = 'public'::regnamespace
           AND relname LIKE '#_firewall#_%' ESCAPE '#' AND pg_has_role(current_user, relowner, 'MEMBER')
         UNION ALL SELECT 'function ' || proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace
           AND proname LIKE '#_firewall#_%' ESCAPE '#' AND pg_has_role(current_user, proowner, 'MEMBER')`);
      return { ok: rows.length === 0, detail: rows.length
        ? `can act as the owner of ${rows.map((x) => x.name).join(", ")} (could drop or replace the bypass list)` : "owns none" };
    }),
    // Every policy calls this function, so a changed body (say, a session-setting
    // "maintenance switch") opens every table while the policies still look exact.
    () => guard("bypass function unchanged", async () => {
      const want = /FUNCTION _firewall_is_bypass_role\(p_role TEXT\)\s*RETURNS BOOLEAN AS \$\$([\s\S]*?)\$\$/
        .exec(readFileSync(MIGRATION, "utf8"))?.[1];
      const { rows: [f] } = await client.query(
        `SELECT prosrc, prosecdef, proconfig, l.lanname, prorettype = 'boolean'::regtype AS bool
         FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
         WHERE p.oid = 'public._firewall_is_bypass_role(text)'::regprocedure`);
      const norm = (x: string) => x.replace(/\s+/g, " ").trim();
      const diff = [];
      if (!want || norm(f.prosrc) !== norm(want)) diff.push("body");
      if (!f.prosecdef) diff.push("not SECURITY DEFINER");
      if (JSON.stringify(f.proconfig) !== JSON.stringify(["search_path=pg_catalog, pg_temp"])) diff.push("settings");
      if (f.lanname !== "sql" || !f.bool) diff.push("language or return type");
      return { ok: diff.length === 0, detail: diff.length
        ? `public._firewall_is_bypass_role differs from the migration (${diff.join(", ")}): re-run migrate`
        : "matches the migration" };
    }),
  ];
  const out: Check[] = [];
  for (const check of checks) out.push(await check());
  return out;
}

/** A global check; a query error fails it (a precondition that cannot be checked is not met). */
async function guard(check: string, fn: () => Promise<{ ok: boolean; detail: string }>): Promise<Check> {
  try {
    return { table: "-", check, ...await fn() };
  } catch (err) {
    return { table: "-", check, ok: false, detail: `could not check (is the migration installed?): ${msg(err)}` };
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
    // Privileges RLS does not cover: the owner can turn RLS off; TRUNCATE ignores it.
    const { rows: [priv] } = await client.query(
      `SELECT pg_has_role(current_user, c.relowner, 'MEMBER') AS owns,
              ${anyRole("has_table_privilege(m.oid, c.oid, 'TRUNCATE')")} AS truncate,
              has_column_privilege(current_user, c.oid, $2, 'SELECT') AS can_select,
              ${anyRole("has_column_privilege(m.oid, c.oid, $2, 'SELECT')")} AS some_role_selects
       FROM pg_class c WHERE c.oid = $1::regclass`, [name, column]);
    checks.push({ table: label, check: "role does not own the table", ok: !priv.owns,
                  detail: priv.owns ? `owned by ${t.owner}, which this role can act as: it can disable RLS`
                                    : `owned by ${t.owner}` });
    checks.push({ table: label, check: "no TRUNCATE", ok: !priv.truncate,
                  detail: priv.truncate ? "TRUNCATE is granted and RLS does not apply to it" : "not granted" });
    checks.push({ table: label, check: "policies", ok: t.protected,
                  detail: t.protected ? `${t.policy_mode} policies in place` : summary(t) });
    if (!priv.can_select) {
      // No direct reads (e.g. a partition read through its parent): the policies
      // above and the view and function checks below cover the other paths.
      checks.push(priv.some_role_selects
        ? { table: label, check: "row checks", ok: null,
            detail: `readable only after SET ROLE to another role: run verify as that role` }
        : { table: label, check: "row checks", ok: true, detail: `no role it can use can SELECT ${column}: no direct reads` });
      continue;
    }
    try {
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
    } catch (err) {
      checks.push({ table: label, check: "row checks", ok: null, detail: `query failed: ${msg(err)}` });
      continue;
    }
    if (opts.writeProbe) checks.push(await writeProbe(client, label, name, column, opts.tenant));
  }
  if (tables.length && ownRows === 0) {
    checks.push({ table: "-", check: "tenant has rows", ok: false,
                  detail: `tenant ${opts.tenant} sees no rows in any table, so the row checks prove nothing: use a tenant that has data` });
  }
  checks.push(await bypassObjects(client, column));
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
 * Read paths RLS does not guard, in any schema, that the role can use:
 * a foreign table; a LEAKPROOF function outside pg_catalog;
 * a view or materialized view whose chain down to a tenant table holds a
 * materialized view (no RLS at all) or a view that runs as an owner who skips
 * RLS (not security_invoker); a SECURITY DEFINER function owned by such a role.
 * ponytail: any such view in the chain counts, even one shadowed by a lower
 * definer view of a non-bypassing owner (a false fail, never a false pass).
 */
function bypassObjects(client: pg.ClientBase, column: string): Promise<Check> {
  return guard("no RLS-bypassing views or functions", async () => {
  const { rows: views } = await client.query(
    `WITH RECURSIVE rel AS (
       SELECT v.oid, v.relkind = 'm' OR (NOT COALESCE((SELECT option_value::boolean FROM pg_options_to_table(v.reloptions)
                                                      WHERE option_name = 'security_invoker'), false)
                                         AND ${BYPASSES}) AS bad
       FROM pg_class v JOIN pg_roles r ON r.oid = v.relowner WHERE v.relkind IN ('v', 'm')),
     dep AS (
       SELECT DISTINCT rw.ev_class AS v, d.refobjid AS t FROM pg_rewrite rw
       JOIN pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_rewrite'::regclass
                       AND d.refclassid = 'pg_class'::regclass AND d.refobjid <> rw.ev_class),
     chain(top, cur, bad) AS (
       SELECT d.v, d.t, rel.bad FROM dep d JOIN rel ON rel.oid = d.v
       UNION
       SELECT c.top, d.t, c.bad OR rel.bad FROM chain c JOIN dep d ON d.v = c.cur JOIN rel ON rel.oid = d.v)
     SELECT DISTINCT n.nspname || '.' || v.relname AS name, v.relkind = 'm' AS matview,
            pg_get_userbyid(v.relowner) AS owner
     FROM chain c JOIN pg_class v ON v.oid = c.top JOIN pg_namespace n ON n.oid = v.relnamespace
     JOIN pg_class t ON t.oid = c.cur AND t.relkind IN ('r', 'p')
     WHERE c.bad AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND ${anyRole("has_any_column_privilege(m.oid, v.oid, 'SELECT')")}
       AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = t.oid AND a.attname = $1
                     AND a.attnum > 0 AND NOT a.attisdropped)
     UNION
     -- A materialized view with the tenant column, or built over a function (no table dependency).
     SELECT n.nspname || '.' || v.relname, true, pg_get_userbyid(v.relowner)
     FROM pg_class v JOIN pg_namespace n ON n.oid = v.relnamespace
     WHERE v.relkind = 'm' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND ${anyRole("has_any_column_privilege(m.oid, v.oid, 'SELECT')")}
       AND (EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = v.oid AND a.attname = $1
                      AND a.attnum > 0 AND NOT a.attisdropped)
            OR EXISTS (SELECT 1 FROM pg_rewrite rw JOIN pg_depend d ON d.objid = rw.oid
                         AND d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_proc'::regclass
                       JOIN pg_proc f ON f.oid = d.refobjid AND f.pronamespace <> 'pg_catalog'::regnamespace
                       WHERE rw.ev_class = v.oid))
     ORDER BY 1`, [column]);
  // Foreign tables: RLS does not reach the remote data, read as the mapped user.
  const { rows: foreign } = await client.query(
    `SELECT n.nspname || '.' || c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'f' AND ${anyRole("has_any_column_privilege(m.oid, c.oid, 'SELECT')")}
     ORDER BY 1`);
  // ponytail: a function body is opaque (plpgsql records no dependencies), so every
  // such function counts, the firewall's own aside. A LEAKPROOF function outside
  // pg_catalog runs before the RLS filter and can leak the rows it sees.
  const { rows: fns } = await client.query(
    `SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS name,
            pg_get_userbyid(p.proowner) AS owner, p.proleakproof AS leakproof
     FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND NOT (n.nspname = 'public' AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
       AND ${anyRole("has_function_privilege(m.oid, p.oid, 'EXECUTE')")}
       AND (p.proleakproof OR (p.prosecdef AND ${BYPASSES}))
     ORDER BY 1`);
  const list = [
    ...views.map((v) => `${v.matview ? "materialized view" : "view"} ${v.name} (owner ${v.owner})`),
    ...foreign.map((f) => `foreign table ${f.name}`),
    ...fns.map((f) => `${f.leakproof ? "LEAKPROOF" : "SECURITY DEFINER"} function ${f.name} (owner ${f.owner})`),
  ];
  return { ok: list.length === 0,
           detail: list.length ? `the role can read through: ${list.join("; ")}` : "none found" };
  });
}

/** Tables with the tenant column outside the scanned schemas that the role can read. */
function otherSchemas(client: pg.ClientBase, schemas: string[], column: string): Promise<Check> {
  return guard("no tenant tables in other schemas", async () => {
  const { rows } = await client.query(
    `SELECT n.nspname || '.' || c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p') AND NOT (n.nspname = ANY($1))
       AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
       AND ${anyRole("has_any_column_privilege(m.oid, c.oid, 'SELECT')")}
       AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $2
                     AND a.attnum > 0 AND NOT a.attisdropped)
     ORDER BY 1`, [schemas, column]);
  return { ok: rows.length === 0,
           detail: rows.length ? `not checked, readable: ${rows.map((r) => r.name).join(", ")} (add --schema)`
                               : "none readable" };
  });
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
