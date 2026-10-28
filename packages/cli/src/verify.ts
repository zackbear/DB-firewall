// verify: connect as the app's own role and test the isolation, not just the
// policies' presence. Read-only by default: every check runs in a transaction
// that is rolled back, and nothing is written unless --write-probe is given.
import type pg from "pg";
import { sign } from "./key.js";
import { CHECKS, q, type GlobalCheck } from "./checks.js";
import { firewallObjects, globMatch, ident, scan, withCatalogPath, type TableReport } from "./scan.js";

/** ok: true pass, false fail, null inconclusive (counted separately, never as a pass). */
export interface Check { table: string; check: string; ok: boolean | null; detail: string }

const RLS_VIOLATION = "42501";       // insufficient_privilege: what an RLS refusal raises
const MARK = "__dbfw_verify_other__";

/**
 * The global checks of the shared checks file (@check and @info blocks), in
 * file order, then the firewall functions. The "strict:" ones run only with
 * --strict, after the table checks. One client runs one query at a time.
 */
export async function roleChecks(client: pg.ClientBase): Promise<Check[]> {
  const out: Check[] = [];
  for (const c of CHECKS().checks.filter((x) => !x.name.startsWith("strict:"))) out.push(await fileCheck(client, c));
  // The policies call these (and they sign): see firewallObjects().
  out.push(await guard("firewall functions unchanged", () => firewallObjects(client)));
  return out;
}

/** One @check or @info block: ok only when the row says true (NULL fails). */
export async function fileCheck(client: pg.ClientBase, c: GlobalCheck): Promise<Check> {
  const run = async () => {
    const { rows: [r] } = await client.query(c.sql);
    return { ok: r.ok === true, detail: String(r.detail) };
  };
  return c.info ? info(c.name, run) : guard(c.name, run);
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
      const { rows: [r] } = await client.query(q("nonce"));
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
  /** --strict: accept that the role reads other sessions' SQL (an info line instead). */
  allowQueryText?: boolean;
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
    const { rows: [priv] } = await client.query(q("table_privileges"), [name, column]);
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
  if (opts.strict) {
    checks.push(...await strictChecks(client, tables.filter((t) => t.protected), opts.allowGlobal ?? [], !!opts.allowQueryText));
  }
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
 * Read paths RLS does not guard, in any schema, that the role can use: the
 * @query bypass_* blocks of the checks file (views and materialized views,
 * foreign tables, rules, functions that run as their owner or LEAKPROOF).
 */
function bypassObjects(client: pg.ClientBase, column: string, allow: string[]): Promise<Check> {
  return guard("no RLS-bypassing views or functions", async () => {
    const { rows: views } = await client.query(q("bypass_views"), [column]);
    const { rows: foreign } = await client.query(q("bypass_foreign"), [column]);
    const { rows: rules } = await client.query(q("bypass_rules"));
    const { rows: fns } = await client.query(q("bypass_functions"));
    // --allow-global clears only what may hold shared data by design: a function
    // (named with its arguments) or a foreign table without the tenant column.
    // Never a view over a tenant table or a rule.
    const list = [
      ...views.map((v) => `${v.matview ? "materialized view" : "view"} ${v.name} (owner ${v.owner})`),
      ...foreign.filter((f) => f.tenant || !allowedRel(allow, f.name)).map((f) => `foreign table ${f.name}`),
      ...rules.map((r) => `rule ${r.name} (use a trigger)`),
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

/** @query query_text. --strict fails on it (unless --allow-query-text); else an information line. */
function queryText(client: pg.ClientBase, strict: boolean): Promise<Check> {
  const check = async () => {
    const { rows: [r] } = await client.query(q("query_text"));
    return { ok: !r.can, detail: r.can
      ? "yes: SQL one tenant runs can read the query text of another tenant's session (pg_stat_activity, " +
        "pg_stat_statements), literal values included (send values as parameters; migrate --harden revokes it, " +
        "or --allow-query-text where only the provider can)" : "no (pg_stat_activity and pg_stat_statements revoked)" };
  };
  return strict ? guard("strict: cannot read other sessions' SQL", check)
                : info("reads other sessions' SQL (info)", check);
}

/**
 * --strict: an allowlist instead of a list of known leak paths. Everything a
 * role the app can use can read must be protected tenant data (see @query
 * strict_readable); anything else needs --allow-global schema.name. The
 * "strict:" @check blocks of the file, no SECURITY DEFINER function outside
 * the firewall's own unless allowlisted, and no other sessions' SQL.
 */
async function strictChecks(client: pg.ClientBase, protectedTables: TableReport[], allow: string[],
                            allowQueryText: boolean): Promise<Check[]> {
  const readable = () => guard("strict: only tenant data readable", async () => {
    const { rows } = await client.query(q("strict_readable"),
                                        [JSON.stringify(protectedTables.map((t) => [t.schema, t.table]))]);
    // --allow-query-text also accepts the views of the pg_stat_statements extension.
    const bad = rows.filter((r) => !allowedRel(allow, r.name) && !(allowQueryText && r.extension === "pg_stat_statements") && !(
      r.safe || (r.invoker && !r.broken && (r.blockers as string[]).every((b) => allowedRel(allow, b)))))
      .map((r) => r.name as string).sort();
    return { ok: bad.length === 0, detail: bad.length
      ? `readable but not protected tenant data: ${listed(bad)} (protect them, revoke, or --allow-global schema.name)`
      : "everything readable is protected tenant data or allowlisted" };
  });
  const definer = () => guard("strict: no SECURITY DEFINER functions", async () => {
    const { rows } = await client.query(q("strict_definer"));
    const bad = rows.filter((r) => !allowedFn(allow, r.sig)).map((r) => r.sig);
    return { ok: bad.length === 0, detail: bad.length
      ? `runs as its owner: ${listed(bad)} (drop it or make it SECURITY INVOKER, or --allow-global 'schema.name(args)')`
      : "none outside the firewall's own (or allowlisted)" };
  });
  const out = [await readable()];
  for (const c of CHECKS().checks.filter((x) => x.name.startsWith("strict:"))) out.push(await fileCheck(client, c));
  out.push(await definer(), await queryText(client, !allowQueryText));
  return out;
}

/** Tables with the tenant column outside the scanned schemas that the role can read. */
function otherSchemas(client: pg.ClientBase, schemas: string[], column: string): Promise<Check> {
  return guard("no tenant tables in other schemas", async () => {
    const { rows } = await client.query(q("other_schemas"), [schemas, column]);
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
