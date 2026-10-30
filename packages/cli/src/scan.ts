// PostgreSQL scan: the queries are in the shared checks file, which
// hooks/scan_engines.py (_scan_postgres) runs too, so TypeScript teams need no
// Python. The logic around them is kept in step with the Python scanner.
import { readFileSync } from "node:fs";
import type pg from "pg";
import { CHECKS, q } from "./checks.js";
import { MIGRATION } from "./migrate.js";

/** Exactly the tables migrations/001_postgresql.sql skips (@excluded in the
 *  checks file), so a table the migration protects is never skipped here.
 *  Skipped tables are reported. */
export const DEFAULT_EXCLUDED = CHECKS().excluded;

export interface TableReport {
  schema: string;
  table: string;
  protected: boolean;
  has_tenant_col: true;
  has_rls_policy: boolean;
  owner: string;
  rls_enabled: boolean;
  rls_forced: boolean;
  policy_mode: "permissive" | "restrictive";
  missing_policies: string[];
  extra_permissive_policies: string[];
  altered_policies: string[];
  stale_base_policy: boolean;
  predicate_check: string;
  /** The context the policies use: signed, plain, or altered (neither); null without policies. */
  tenant_context: "signed" | "plain" | "altered" | null;
}

export type Context = "signed" | "plain";

/** The migration's predicate for dbfw.context signed (default) or plain. */
export function predicate(column: string, context: Context): string {
  return context === "plain"
    ? `${ident(column)} = NULLIF(current_setting('app.current_tenant', true), '') ` +
      "OR db_firewall._firewall_is_bypass_role(current_user::text)"
    : `${ident(column)} = (SELECT db_firewall._firewall_tenant()) ` +
      "OR (SELECT db_firewall._firewall_is_bypass_role(current_user::text))";
}

// The tables and their policies: @query scan_tables.


const CMD: Record<string, string> = { sel: "SELECT", ins: "INSERT", upd: "UPDATE", del: "DELETE" };

export const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

/** fnmatch-style glob (*, ?, [abc], [!abc]), as the Python scanner matches. */
export function globMatch(pattern: string, name: string): boolean {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === "*") re += ".*";
    else if (ch === "?") re += ".";
    else if (ch === "[") {
      // As fnmatch: a leading "!" negates, then a leading "]" is literal.
      let j = i + 1;
      if (pattern[j] === "!") j++;
      if (pattern[j] === "]") j++;
      const end = pattern.indexOf("]", j);
      if (end < 0) { re += "\\["; continue; }
      // fnmatch drops a reversed range ([z-a]) instead of failing.
      let body = pattern.slice(i + 1, end).replace(/(.)-(.)/g, (m, a, b) => (a > b ? "" : m)).replace(/\\/g, "\\\\");
      if (body.startsWith("!")) body = "^" + body.slice(1).replace(/[[\]]/g, "\\$&");
      else body = (body.startsWith("^") ? "\\" : "") + body.replace(/[[\]]/g, "\\$&");  // "^": a literal, as fnmatch reads it
      re += `[${body}]`;
      i = end;
    } else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  // "s": * and ? match a newline too, as in fnmatch.
  try { return new RegExp(`^${re}$`, "s").test(name); } catch { return false; }
}

/**
 * The firewall predicate exactly as PostgreSQL deparses it for this table: a
 * policy with the migration's predicate on a temporary copy of the table's
 * columns, read back, then rolled back. Exact comparison catches a changed
 * cast, constant or function overload.
 */
async function reference(client: pg.ClientBase, rel: string, column: string, context: Context):
    Promise<[string | null, string | null]> {
  const pred = predicate(column, context);
  await client.query("BEGIN");
  try {
    await client.query(`CREATE TEMP TABLE _fw_ref (LIKE ${rel})`);
    await client.query(`CREATE POLICY _fw_ref_p ON pg_temp._fw_ref USING (${pred}) WITH CHECK (${pred})`);
    const { rows } = await client.query(q("reference_qual"));
    return rows[0] ? [rows[0].qual, null] : [null, "no result"];
  } catch (err) {
    return [null, String((err as Error).message).split("\n")[0] ?? "error"];
  } finally {
    await client.query("ROLLBACK");
  }
}

export interface ScanResult { tables: TableReport[]; excluded: string[] }

const norm = (x: string) => x.replace(/\s+/g, " ").trim();

/**
 * Every function the migration creates must match it (body, SECURITY DEFINER,
 * settings, volatility, language, return type), with no extra db_firewall._firewall_*
 * function: the policies call some of them, others sign, and a changed body
 * (say, a session-setting "maintenance switch") opens every table while the
 * policies still look exact. Every db_firewall._firewall_* object must have one
 * owner, or only superusers: an object another role planted keeps its owner.
 */
export async function firewallObjects(client: pg.ClientBase): Promise<{ ok: boolean; detail: string }> {
  const sql = readFileSync(MIGRATION, "utf8");
  const want = [...sql.matchAll(/CREATE OR REPLACE FUNCTION db_firewall\.(_firewall_\w+)\(([^)]*)\)\s*RETURNS (\w+) AS \$\$([\s\S]*?)\$\$ LANGUAGE (\w+)([^;]*);/g)]
    .map(([, name, args, ret, body, lang, tail]) => ({
      name: name!, sig: args!.split(",").map((a) => a.trim().split(/\s+/)[1]?.toLowerCase()).filter(Boolean).join(", "),
      ret: ret!.toLowerCase(), body: body!, lang: lang!.toLowerCase(), tail: tail!,
    }));
  const diff: string[] = [];
  for (const w of want) {
    const { rows: [f] } = await client.query(q("fw_function"), [`db_firewall.${w.name}(${w.sig})`]);
    if (!f) { diff.push(`${w.name} (missing)`); continue; }
    const path = /SET search_path = ([^\n;]+?)\s*$/m.exec(w.tail)?.[1];
    const what = [
      norm(f.prosrc) !== norm(w.body) && "body",
      f.prosecdef !== /SECURITY DEFINER/.test(w.tail) && "SECURITY DEFINER",
      JSON.stringify(f.proconfig) !== JSON.stringify(path ? [`search_path=${path}`] : null) && "settings",
      f.provolatile !== (/STABLE/.test(w.tail) ? "s" : /IMMUTABLE/.test(w.tail) ? "i" : "v") && "volatility",
      (f.lanname !== w.lang || f.ret !== w.ret) && "language or return type",
    ].filter(Boolean);
    if (what.length) diff.push(`${w.name} (${what.join(", ")})`);
  }
  const { rows: extra } = await client.query(q("fw_extra"), [want.map((w) => `${w.name}(${w.sig})`)]);
  if (extra.length) diff.push(`extra ${extra.map((e) => e.fn).join(", ")}`);
  const { rows: owners } = await client.query(q("fw_owners"));
  const mixed = owners.length > 1 && owners.some((o) => !o.super);
  if (mixed) {
    diff.push(`more than one owner (${owners.map((o) => `${o.owner}: ${o.objects}`).join("; ")}): ` +
              "objects another role planted? drop those and re-run the migration");
  }
  return { ok: diff.length === 0, detail: diff.length
    ? `differ from the migration: ${diff.join("; ")}${mixed ? "" : ": re-run the migration"}`
    : "match the migration, one owner" };
}

/** Run fn with search_path = pg_catalog, pg_temp, so a planted operator in
 *  another schema cannot hide in how a policy reads, then put it back. */
export async function withCatalogPath<T>(client: pg.ClientBase, fn: () => Promise<T>): Promise<T> {
  const { rows: [r] } = await client.query(
    "SELECT current_setting('search_path') AS old, set_config('search_path', 'pg_catalog, pg_temp', false)");
  try {
    return await fn();
  } finally {
    await client.query("SELECT set_config('search_path', $1, false)", [r.old]);
  }
}

/** Scan every table in the schemas that has the tenant column. */
export function scan(client: pg.ClientBase, opts: {
  schemas?: string[]; column?: string; exclude?: string[]; context?: Context;
} = {}): Promise<ScanResult> {
  return withCatalogPath(client, () => scanTables(client, opts));
}

async function scanTables(client: pg.ClientBase, opts: {
  schemas?: string[]; column?: string; exclude?: string[]; context?: Context;
}): Promise<ScanResult> {
  const context: Context = opts.context ?? "signed";
  // The predicate calls these: when they differ, no table is protected.
  const objects = await firewallObjects(client).catch((e) => ({ ok: false, detail: (e as Error).message }));
  const schemas = opts.schemas?.length ? opts.schemas : ["public"];
  const column = opts.column ?? "tenant_id";
  const exclude = opts.exclude ?? DEFAULT_EXCLUDED;
  const out: TableReport[] = [], excluded: string[] = [];
  for (const schema of schemas) {
  const { rows } = await client.query(q("scan_tables"), [schema, column]);
  for (const r of rows) {
    if (exclude.some((p) => globMatch(p, r.table))) { excluded.push(`${schema}.${r.table}`); continue; }
    const policies: [string, string, string[], string | null, string | null][] = r.policies;
    const [ref, why] = policies.length ? await reference(client, r.ref_rel, column, context) : [null, null];
    const unverified = policies.length > 0 && ref === null;
    const alteredFrom = (want: string) => policies.filter(([name, cmd, roles, qual, check]) => {
      const op = name.slice(name.lastIndexOf("_") + 1);
      const wantQual = ["sel", "upd", "del"].includes(op) ? want : null;
      const wantCheck = ["ins", "upd"].includes(op) ? want : null;
      return !(roles.length === 1 && roles[0] === "public") || cmd !== CMD[op]
        || qual !== wantQual || check !== wantCheck;
    }).map(([name]) => name).sort();
    const altered = ref === null ? [] : alteredFrom(ref);
    // Policies in the other context count as altered; the report names it.
    let found: TableReport["tenant_context"] = policies.length && !unverified && !altered.length ? context : null;
    if (policies.length && !unverified && altered.length) {
      const other: Context = context === "signed" ? "plain" : "signed";
      const [ref2] = await reference(client, r.ref_rel, column, other);
      found = ref2 !== null && !alteredFrom(ref2).length ? other : "altered";
    }
    const extra: string[] = [...r.extra].sort();
    out.push({
      schema, table: r.table, has_tenant_col: true, has_rls_policy: r.missing.length === 0, owner: r.owner,
      rls_enabled: r.enabled, rls_forced: r.forced,
      policy_mode: r.restrictive ? "restrictive" : "permissive",
      missing_policies: [...r.missing].sort(),
      extra_permissive_policies: extra,
      altered_policies: altered,
      tenant_context: found,
      stale_base_policy: r.base && extra.some((e) => !e.endsWith("_base")),
      predicate_check: unverified
        ? `unavailable: ${why} (run outside a read-only transaction, with the TEMP privilege and SELECT on the table)`
        : !objects.ok ? `firewall functions ${objects.detail}` : "ok",
      protected: r.enabled && r.forced && r.missing.length === 0 && altered.length === 0 && !unverified
        && objects.ok && (r.restrictive || extra.length === 0),
    });
  }
  }
  return { tables: out, excluded };
}
