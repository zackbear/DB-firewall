// verify: connect as the app's own role and test the isolation, not just the
// policies' presence. Read-only by default: every check runs in a transaction
// that is rolled back, and nothing is written unless --write-probe is given.
import type pg from "pg";
import { sign } from "./key.js";
import { firewallObjects, globMatch, ident, scan, withCatalogPath, type TableReport } from "./scan.js";

/** ok: true pass, false fail, null inconclusive (counted separately, never as a pass). */
export interface Check { table: string; check: string; ok: boolean | null; detail: string }

const RLS_VIOLATION = "42501";       // insufficient_privilege: what an RLS refusal raises
const MARK = "__dbfw_verify_other__";

// A role that skips RLS: superuser, BYPASSRLS, or listed in _firewall_bypass_roles.
const BYPASSES = "(r.rolsuper OR r.rolbypassrls OR public._firewall_is_bypass_role(r.rolname::text))";

// Predefined roles that skip RLS in effect: they read every row (all_data),
// or run programs / read and write files as the server (and so connect as
// anyone it trusts).
const PREDEFINED = ["pg_read_all_data", "pg_write_all_data", "pg_execute_server_program",
                    "pg_read_server_files", "pg_write_server_files"];

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
      const { rows: pre } = await client.query(
        `SELECT rolname FROM pg_roles WHERE rolname = ANY($1) AND pg_has_role(current_user, oid, 'MEMBER') ORDER BY 1`,
        [PREDEFINED]);
      const bad = [
        ...rows.map((r) => r.self ? `role ${r.rolname} ${why(r)}` : `is a member of ${r.rolname}, which ${why(r)}`),
        ...pre.map((r) => `is a member of ${r.rolname}, which reads or runs things as the server`),
      ];
      return bad.length
        ? { ok: false, detail: bad.join("; ") + ": RLS does not apply" }
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
    // With the key, or a way to sign, the app could sign any tenant.
    () => guard("cannot read the key or sign", async () => {
      const { rows } = await client.query(
        `SELECT 'table _firewall_keys' AS name WHERE to_regclass('public._firewall_keys') IS NOT NULL
           AND ${anyRole("has_any_column_privilege(m.oid, 'public._firewall_keys'::regclass, 'SELECT')")}
         UNION ALL SELECT 'function ' || p.proname FROM pg_proc p
         WHERE p.pronamespace = 'public'::regnamespace AND p.proname IN ('_firewall_sign', '_firewall_set_tenant')
           AND ${anyRole("has_function_privilege(m.oid, p.oid, 'EXECUTE')")}`);
      return { ok: rows.length === 0, detail: rows.length
        ? `can use ${rows.map((x) => x.name).join(", ")} (could sign another tenant): re-run migrate` : "neither" };
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
    // The policies call these (and they sign): see firewallObjects().
    () => guard("firewall functions unchanged", () => firewallObjects(client)),
    // CREATE in a schema lets the app plant objects or operators that a later
    // migration or query binds to: a view named like a table, reached through
    // a search_path the app role sets for itself (ALTER ROLE ... SET persists
    // across sessions, and no reset can undo it). The migration refuses planted
    // _firewall_* objects and pins search_path; nothing else should rely on that.
    // Information, never a failure: what one shared role allows that no
    // tenant check can see.
    () => info("signals other sessions (info)", async () => {
      const { rows: [r] } = await client.query(
        `SELECT ${anyRole(`EXISTS (SELECT 1 FROM pg_proc p WHERE p.pronamespace = 'pg_catalog'::regnamespace
           AND p.proname IN ('pg_terminate_backend', 'pg_cancel_backend')
           AND has_function_privilege(m.oid, p.oid, 'EXECUTE'))`)} AS can`);
      return { ok: true, detail: r.can
        ? "yes: SQL one tenant runs can end or cancel another tenant's requests (availability only); " +
          "migrate --harden-signals revokes it" : "no (pg_terminate_backend / pg_cancel_backend revoked)" };
    }),
    () => info("role defaults (info)", async () => {
      const { rows: [r] } = await client.query(
        `SELECT string_agg(ro.rolname || COALESCE(' in ' || d.datname, '') || ': ' || array_to_string(s.setconfig, ', '),
                           '; ' ORDER BY ro.rolname) AS set
         FROM pg_db_role_setting s JOIN pg_roles ro ON ro.oid = s.setrole
         LEFT JOIN pg_database d ON d.oid = s.setdatabase
         WHERE pg_has_role(current_user, s.setrole, 'MEMBER') AND (s.setdatabase = 0 OR d.datname = current_database())`);
      return { ok: true, detail: (r.set ? `set: ${r.set}` : "none") +
        " (the role can change its own with ALTER ROLE CURRENT_USER SET; no grant prevents it, " +
        "and a bad value can break its later connections)" };
    }),
    // TRIGGER on a table lets the app attach a deferred trigger: it fires at
    // COMMIT, after an in-transaction session reset (postgres.js), and can
    // leave state for the connection's next user.
    () => guard("cannot create triggers", async () => {
      const { rows } = await client.query(
        `SELECT c.oid::regclass::text AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relkind IN ('r', 'p', 'v', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
           AND n.nspname NOT LIKE 'pg#_toast%' ESCAPE '#'
           AND (${anyRole("has_table_privilege(m.oid, c.oid, 'TRIGGER')")}
                OR pg_has_role(current_user, c.relowner, 'MEMBER'))
         ORDER BY 1 LIMIT 20`);
      return { ok: rows.length === 0, detail: rows.length
        ? `TRIGGER is granted on, or a role it can use owns, ${rows.map((r) => r.name).join(", ")}: ` +
          "REVOKE TRIGGER ... FROM the app role, and give owned tables to another role"
        : "no TRIGGER on any table" };
    }),
    () => guard("cannot create in any schema", async () => {
      // CREATE on the database makes new schemas, such as one named like the
      // role: the default search_path ("$user", public) looks there first, so a
      // view in it shadows a table for every session of the role.
      const { rows: [db] } = await client.query(
        `SELECT ${anyRole("has_database_privilege(m.oid, current_database(), 'CREATE')")} AS create_db,
                pg_has_role(current_user, datdba, 'MEMBER') AS owns
         FROM pg_database WHERE datname = current_database()`);
      if (db.create_db || db.owns) {
        return { ok: false, detail: db.owns ? "a role it can use owns this database (an owner can grant itself CREATE)"
          : "a role it can use can CREATE schemas in this database (REVOKE CREATE ON DATABASE ... FROM PUBLIC and the app role)" };
      }
      const { rows } = await client.query(
        `SELECT n.nspname FROM pg_namespace n
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_toast%' ESCAPE '#'
           AND n.nspname NOT LIKE 'pg#_temp#_%' ESCAPE '#'
           AND (${anyRole("has_schema_privilege(m.oid, n.oid, 'CREATE')")}
                OR pg_has_role(current_user, n.nspowner, 'MEMBER'))
         ORDER BY 1`);
      return { ok: rows.length === 0, detail: rows.length
        ? `a role it can use can CREATE in, or owns, ${rows.map((r) => r.nspname).join(", ")}: REVOKE CREATE ON SCHEMA ... ` +
          "FROM PUBLIC and the app role, and give owned schemas to another role (run migrations as another role)"
        : "no CREATE in any schema" };
    }),
  ];
  const out: Check[] = [];
  for (const check of checks) out.push(await check());
  return out;
}

/** An information line: always ok, also when its query fails (say, an
 *  unreadable catalog), so it can never change verify's result. */
async function info(check: string, fn: () => Promise<{ ok: boolean; detail: string }>): Promise<Check> {
  try {
    return { table: "-", check, ...await fn(), ok: true };
  } catch (err) {
    return { table: "-", check, ok: true, detail: `could not read: ${msg(err)}` };
  }
}

/** A global check; a query error fails it (a precondition that cannot be checked is not met). */
async function guard(check: string, fn: () => Promise<{ ok: boolean; detail: string }>): Promise<Check> {
  try {
    return { table: "-", check, ...await fn() };
  } catch (err) {
    return { table: "-", check, ok: false, detail: `could not check (is the migration installed?): ${msg(err)}` };
  }
}

/** How a transaction sets the tenant: not at all, unsigned (as SQL the app ran could), or signed. */
type Ctx = { tenant: string; key?: Buffer } | null;

/** Run fn in a transaction with that context, and always roll back. */
async function inTx<T>(client: pg.ClientBase, ctx: Ctx, fn: () => Promise<T>): Promise<T> {
  await client.query("BEGIN");
  try {
    if (ctx?.key) {
      const { rows: [r] } = await client.query("SELECT public._firewall_nonce() AS n");
      await client.query("SELECT set_config('app.current_tenant', $1, true), set_config('app.tenant_sig', $2, true)",
                         [ctx.tenant, sign(ctx.key, r.n, ctx.tenant)]);
    } else if (ctx) {
      await client.query("SELECT set_config('app.current_tenant', $1, true)", [ctx.tenant]);
    }
    return await fn();
  } finally {
    await client.query("ROLLBACK");
  }
}

type VerifyOpts = {
  tenant: string; key: Buffer; schemas?: string[]; column?: string; exclude?: string[]; writeProbe?: boolean;
  /** Allowlist mode: see strictChecks(). */
  strict?: boolean; allowGlobal?: string[];
};
type VerifyResult = { checks: Check[]; tables: TableReport[]; excluded: string[] };

/** Every check runs with search_path = pg_catalog, pg_temp: a planted "="
 *  must not make "tenant sees only its rows" count another tenant's rows as own. */
export function verify(client: pg.ClientBase, opts: VerifyOpts): Promise<VerifyResult> {
  return withCatalogPath(client, () => verifyTables(client, opts));
}

async function verifyTables(client: pg.ClientBase, opts: VerifyOpts): Promise<VerifyResult> {
  const signed = { tenant: opts.tenant, key: opts.key };
  const schemas = opts.schemas?.length ? opts.schemas : ["public"];
  const column = opts.column ?? "tenant_id";
  const checks: Check[] = await roleChecks(client);
  const { tables, excluded } = await scan(client, { schemas, column, exclude: opts.exclude, context: "signed" });
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
      const count = async () => Number((await client.query(`SELECT count(*) AS n FROM ${name}`)).rows[0].n);
      const none = await inTx(client, null, count);
      checks.push({ table: label, check: "no tenant sees nothing", ok: none === 0, detail: `${none} rows visible` });
      // The tenant set without a signature, as SQL the app (or an agent) runs could set it.
      const unsigned = await inTx(client, { tenant: opts.tenant }, count);
      checks.push({ table: label, check: "unsigned tenant sees nothing", ok: unsigned === 0,
                    detail: unsigned ? `${unsigned} rows visible: SQL the app runs can switch tenants` : "0 rows" });
      // As the tenant: every visible row is the tenant's.
      const [foreign, own] = await inTx(client, signed, async () => {
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
    if (opts.writeProbe) checks.push(await writeProbe(client, label, name, column, signed));
  }
  if (tables.length && ownRows === 0) {
    checks.push({ table: "-", check: "tenant has rows", ok: false,
                  detail: `tenant ${opts.tenant} sees no rows in any table, so the row checks prove nothing: use a tenant that has data, and check that ` +
                          `DB_FIREWALL_TENANT_KEY is the database's key (db-firewall key)` });
  }
  checks.push(await bypassObjects(client, column, opts.allowGlobal ?? []));
  checks.push(await otherSchemas(client, schemas, column));
  if (opts.strict) checks.push(...await strictChecks(client, tables.filter((t) => t.protected), opts.allowGlobal ?? []));
  else checks.push(await queryText(client, false));
  return { checks, tables, excluded };
}

/**
 * Opt-in (--write-probe): insert a row for another tenant as --tenant, which
 * RLS must refuse. Rolled back, but it fires BEFORE INSERT triggers and uses
 * up a sequence value even when refused.
 */
async function writeProbe(client: pg.ClientBase, label: string, name: string, column: string,
                          ctx: { tenant: string; key: Buffer }): Promise<Check> {
  try {
    await inTx(client, ctx, () => client.query(`INSERT INTO ${name} (${ident(column)}) VALUES ($1)`, [MARK]));
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
 * RLS (not security_invoker); a SECURITY DEFINER function owned by such a role
 * (executable, or fired as a trigger); a rule on a relation the app can write.
 * ponytail: any such view in the chain counts, even one shadowed by a lower
 * definer view of a non-bypassing owner (a false fail, never a false pass).
 */
function bypassObjects(client: pg.ClientBase, column: string, allow: string[]): Promise<Check> {
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
    `SELECT n.nspname || '.' || c.relname AS name,
            EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $1
                      AND a.attnum > 0 AND NOT a.attisdropped) AS tenant
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'f' AND ${anyRole("has_any_column_privilege(m.oid, c.oid, 'SELECT')")}
     ORDER BY 1`, [column]);
  // A rule's actions run with the table owner's privileges: a rule on a
  // relation the app can write can read (or copy) what the app cannot.
  const { rows: rules } = await client.query(
    `SELECT rw.rulename || ' on ' || c.oid::regclass::text AS name FROM pg_rewrite rw JOIN pg_class c ON c.oid = rw.ev_class
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE rw.rulename <> '_RETURN' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND ${anyRole("has_table_privilege(m.oid, c.oid, 'INSERT, UPDATE, DELETE')")}
     ORDER BY 1`);
  // ponytail: a function body is opaque (plpgsql records no dependencies), so every
  // such function counts, the firewall's own aside. A LEAKPROOF function outside
  // pg_catalog runs before the RLS filter and can leak the rows it sees. A
  // trigger or event trigger function needs no EXECUTE to run: it counts whatever
  // its grants (any table: a cascade fires the triggers of tables the app cannot write).
  const { rows: fns } = await client.query(
    `SELECT p.oid::regprocedure::text AS name, pg_get_userbyid(p.proowner) AS owner, p.proleakproof AS leakproof
     FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND NOT (n.nspname = 'public' AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
       AND (${anyRole("has_function_privilege(m.oid, p.oid, 'EXECUTE')")}
            OR p.oid IN (SELECT tgfoid FROM pg_trigger UNION SELECT evtfoid FROM pg_event_trigger))
       AND (p.proleakproof OR (p.prosecdef AND ${BYPASSES}))
     ORDER BY 1`);
  // --allow-global clears only what may hold shared data by design: a function
  // (named with its arguments) or a foreign table without the tenant column.
  // Never a view over a tenant table or a rule.
  const list = [
    ...views.map((v) => `${v.matview ? "materialized view" : "view"} ${v.name} (owner ${v.owner})`),
    ...foreign.filter((f) => f.tenant || !allowedRel(allow, f.name)).map((f) => `foreign table ${f.name}`),
    ...rules.map((r) => `rule ${r.name}`),
    ...fns.filter((f) => !allowedFn(allow, f.name))
      .map((f) => `${f.leakproof ? "LEAKPROOF" : "SECURITY DEFINER"} function ${f.name} (owner ${f.owner})`),
  ];
  return { ok: list.length === 0,
           detail: list.length ? `the role can read through: ${list.join("; ")}` : "none found" };
  });
}

// --allow-global: an entry with "(" names functions with their arguments
// (schema.name(argtypes), as verify prints them; "app.f(*)" for every
// overload); one without names relations. "app.*" never clears a function.
const allowedRel = (globs: string[], name: string) => globs.some((g) => !g.includes("(") && globMatch(g, name));
const allowedFn = (globs: string[], sig: string) => globs.some((g) => g.includes("(") && globMatch(g, sig));
const listed = (names: string[]) => names.slice(0, 25).join(", ") + (names.length > 25 ? `, and ${names.length - 25} more` : "");

/** All tenants share one role, so its sessions see each other's SQL text in
 *  pg_stat_activity, literal values included. --strict fails on it. */
function queryText(client: pg.ClientBase, strict: boolean): Promise<Check> {
  const check = async () => {
    const { rows: [r] } = await client.query(
      `SELECT ${anyRole(`(has_table_privilege(m.oid, 'pg_catalog.pg_stat_activity', 'SELECT')
          OR has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')
          OR has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_backend_activity(integer)', 'EXECUTE'))`)} AS can`);
    return { ok: !r.can, detail: r.can
      ? "yes: SQL one tenant runs can read the query text of another tenant's session, literal values included " +
        "(send values as parameters; migrate --harden revokes it)" : "no (pg_stat_activity revoked)" };
  };
  return strict ? guard("strict: cannot read other sessions' SQL", check)
                : info("reads other sessions' SQL (info)", check);
}

/**
 * --strict: an allowlist instead of a list of known leak paths. Everything a
 * role the app can use can read must be protected tenant data: a protected
 * table, a security_invoker view that reads at least one table and whose chain
 * reaches only protected tables and calls no function outside pg_catalog (no
 * materialized views, foreign tables or definer views on the way), or a
 * sequence a protected table owns. Anything else (a table without the tenant
 * column, a log or history table, a reference table) needs --allow-global
 * schema.name, which says "this may be shared by all tenants". No large
 * object may be readable. And no SECURITY DEFINER function outside the
 * firewall's own may be executable, or fire as a trigger, unless allowlisted:
 * it runs as its owner, whatever it reads.
 */
async function strictChecks(client: pg.ClientBase, protectedTables: TableReport[], allow: string[]): Promise<Check[]> {
  const readable = () => guard("strict: only tenant data readable", async () => {
    const { rows: rels } = await client.query(
      `SELECT c.oid::int AS oid, n.nspname AS nsp, c.relname AS rel, n.nspname || '.' || c.relname AS name,
              c.relkind AS kind,
              COALESCE((SELECT option_value::boolean FROM pg_options_to_table(c.reloptions)
                        WHERE option_name = 'security_invoker'), false) AS invoker,
              (SELECT d.refobjid::int FROM pg_depend d
               WHERE c.relkind = 'S' AND d.classid = 'pg_class'::regclass AND d.objid = c.oid
                 AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i') LIMIT 1) AS owned_by,
              EXISTS (SELECT 1 FROM pg_rewrite rw JOIN pg_depend d ON d.objid = rw.oid
                        AND d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_proc'::regclass
                      JOIN pg_proc f ON f.oid = d.refobjid AND f.pronamespace <> 'pg_catalog'::regnamespace
                      WHERE rw.ev_class = c.oid) AS calls_fn,
              ${anyRole(`CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(m.oid, c.oid, 'SELECT, USAGE')
                         ELSE has_any_column_privilege(m.oid, c.oid, 'SELECT') END`)} AS readable
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
         AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_%' ESCAPE '#'`);
    const { rows: edges } = await client.query(
      `SELECT DISTINCT rw.ev_class::int AS v, d.refobjid::int AS t FROM pg_rewrite rw
       JOIN pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_rewrite'::regclass
                       AND d.refclassid = 'pg_class'::regclass AND d.refobjid <> rw.ev_class`);
    // By oid, not "schema.name": app."x.y" and "app.x".y print the same.
    const key = (nsp: string, rel: string) => JSON.stringify([nsp, rel]);
    const want = new Set(protectedTables.map((t) => key(t.schema, t.table)));
    const safe = new Set(rels.filter((r) => want.has(key(r.nsp, r.rel))).map((r) => r.oid as number));
    const byOid = new Map<number, any>(rels.map((r) => [r.oid, r]));
    const deps = new Map<number, number[]>();
    for (const e of edges) deps.set(e.v, [...(deps.get(e.v) ?? []), e.t]);
    // A view is safe when every view on its chain is security_invoker, reads at
    // least one relation and calls no function outside pg_catalog, and every
    // relation it reaches is protected (or itself allowed). ponytail: constants
    // in a view body (VALUES, literals in a UNION) cannot be seen.
    const safeView = (oid: number, seen = new Set<number>()): boolean => {
      if (seen.has(oid)) return true;
      seen.add(oid);
      const r = byOid.get(oid);
      if (!r) return false;                                  // a system relation (pg_catalog): not tenant data
      if (r.kind !== "v" || !r.invoker) return safe.has(oid) || allowedRel(allow, r.name);
      const to = deps.get(oid) ?? [];
      return !r.calls_fn && to.length > 0 && to.every((t) => safeView(t, seen));
    };
    const bad = rels.filter((r) => r.readable && !allowedRel(allow, r.name) && !(
      safe.has(r.oid) || (r.kind === "S" && r.owned_by && safe.has(r.owned_by)) || (r.kind === "v" && safeView(r.oid))))
      .map((r) => r.name).sort();
    return { ok: bad.length === 0, detail: bad.length
      ? `readable but not protected tenant data: ${listed(bad)} (protect them, revoke, or --allow-global schema.name)`
      : "everything readable is protected tenant data or allowlisted" };
  });
  // Large objects are one store for the whole database: no RLS, no tenant.
  const largeObjects = () => guard("strict: no readable large objects", async () => {
    const { rows: [r] } = await client.query(
      `SELECT count(*)::int AS n, current_setting('lo_compat_privileges')::boolean AS compat FROM pg_largeobject_metadata l
       WHERE current_setting('lo_compat_privileges')::boolean OR pg_has_role(current_user, l.lomowner, 'MEMBER')
          OR EXISTS (SELECT 1 FROM aclexplode(l.lomacl) a WHERE a.privilege_type = 'SELECT'
                       AND (a.grantee = 0 OR pg_has_role(current_user, a.grantee, 'MEMBER')))`);
    return { ok: r.n === 0, detail: r.n
      ? `${r.n} large object(s) readable${r.compat ? " (lo_compat_privileges is on)" : ""}: shared by all tenants (lo_unlink them, or revoke)`
      : "none" };
  });
  const definer = () => guard("strict: no SECURITY DEFINER functions", async () => {
    const { rows } = await client.query(
      `SELECT p.oid::regprocedure::text AS sig
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')
         AND NOT (n.nspname = 'public' AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
         AND (${anyRole("has_function_privilege(m.oid, p.oid, 'EXECUTE')")}
              OR p.oid IN (SELECT tgfoid FROM pg_trigger UNION SELECT evtfoid FROM pg_event_trigger))
       ORDER BY 1`);
    const bad = rows.filter((r) => !allowedFn(allow, r.sig)).map((r) => r.sig);
    return { ok: bad.length === 0, detail: bad.length
      ? `executable or a trigger, runs as its owner: ${listed(bad)} (revoke EXECUTE and drop such triggers, or --allow-global 'schema.name(args)')`
      : "none outside the firewall's own (or allowlisted)" };
  });
  // one client: one query at a time
  return [await readable(), await largeObjects(), await definer(), await queryText(client, true)];
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
  if (t.tenant_context === "plain") return "plain tenant context: SQL the app runs can switch tenants (re-run migrate)";
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
