// PostgreSQL scan: the same checks as hooks/scan_engines.py (_scan_postgres),
// so TypeScript teams need no Python. Keep the two in step.
import { readFileSync } from "node:fs";
import type pg from "pg";
import { MIGRATION } from "./migrate.js";

/** Exactly the tables migrations/001_postgresql.sql skips, so a table the
 *  migration protects is never skipped here. Skipped tables are reported. */
export const DEFAULT_EXCLUDED = [
  "_firewall_*", "schema_migrations", "alembic_version", "knex_migrations", "prisma_migrations",
  "__diesel_schema_migrations", "flyway_schema_history",
];

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
      "OR public._firewall_is_bypass_role(current_user::text)"
    : `${ident(column)} = (SELECT public._firewall_tenant()) ` +
      "OR (SELECT public._firewall_is_bypass_role(current_user::text))";
}

// Exact schema.table match. Protected = RLS enabled AND forced AND all four
// firewall policies AND their exact shape AND, when they are permissive, no
// other permissive policy (PostgreSQL ORs permissive policies).
const SQL = `
  WITH t AS (
    SELECT c.oid, n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity,
           'fw_' || left(md5(n.nspname || '.' || c.relname), 12) AS stem,
           'firewall_rls_' || c.relname AS legacy
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p') AND n.nspname = $1
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $2
                    AND a.attnum > 0 AND NOT a.attisdropped))
  SELECT t.relname AS table, t.relrowsecurity AS enabled, t.relforcerowsecurity AS forced,
    pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = t.oid)) AS owner,
    (CASE WHEN (SELECT relispartition FROM pg_class WHERE oid = t.oid) THEN pg_partition_root(t.oid)
          ELSE t.oid END)::regclass::text AS ref_rel,
    ARRAY(SELECT op FROM unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op
          WHERE NOT EXISTS (SELECT 1 FROM pg_policies p
                            WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                              AND p.policyname IN (t.stem || '_' || op, t.legacy || '_' || op))) AS missing,
    ARRAY(SELECT p.policyname::text FROM pg_policies p
          WHERE p.schemaname = t.nspname AND p.tablename = t.relname AND p.permissive = 'PERMISSIVE'
            AND p.policyname NOT IN (SELECT pre || '_' || op FROM unnest(ARRAY[t.stem, t.legacy]) AS pre,
                                     unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op)) AS extra,
    COALESCE((SELECT count(*) = 4 AND bool_and(p.permissive = 'RESTRICTIVE') FROM pg_policies p
              WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                AND p.policyname IN (t.stem || '_sel', t.stem || '_ins',
                                     t.stem || '_upd', t.stem || '_del')), false) AS restrictive,
    COALESCE((SELECT json_agg(json_build_array(p.policyname, p.cmd, p.roles, p.qual, p.with_check))
              FROM pg_policies p
              WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                AND p.policyname IN (SELECT pre || '_' || op FROM unnest(ARRAY[t.stem, t.legacy]) AS pre,
                                     unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op)), '[]') AS policies,
    EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = t.nspname AND p.tablename = t.relname
              AND p.policyname = t.stem || '_base') AS base
  FROM t ORDER BY t.relname`;

const CMD: Record<string, string> = { sel: "SELECT", ins: "INSERT", upd: "UPDATE", del: "DELETE" };

export const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

/** fnmatch-style glob (*, ?, [abc], [!abc]), as the Python scanner matches. */
export function globMatch(pattern: string, name: string): boolean {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === "*") re += ".*";
    else if (ch === "?") re += ".";
    else if (ch === "[" && pattern.indexOf("]", i + 2) > i) {
      const end = pattern.indexOf("]", i + 2);
      let body = pattern.slice(i + 1, end).replace(/\\/g, "\\\\");
      if (body.startsWith("!")) body = "^" + body.slice(1);
      re += `[${body}]`;
      i = end;
    } else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`).test(name);
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
    const { rows } = await client.query(
      "SELECT qual FROM pg_policies WHERE tablename = '_fw_ref' AND policyname = '_fw_ref_p' " +
      "AND schemaname = pg_my_temp_schema()::regnamespace::text");
    return rows[0] ? [rows[0].qual, null] : [null, "no result"];
  } catch (err) {
    return [null, String((err as Error).message).split("\n")[0] ?? "error"];
  } finally {
    await client.query("ROLLBACK");
  }
}

export interface ScanResult { tables: TableReport[]; excluded: string[] }

// The functions the policies, the signing and the session reset depend on:
// name, migration args, catalog args.
const FUNCTIONS: [string, string, string][] = [
  ["_firewall_is_bypass_role", "p_role TEXT", "text"], ["_firewall_tenant", "", ""],
  ["_firewall_sign", "p_tenant TEXT", "text"], ["_firewall_nonce", "", ""],
  ["_firewall_reset_session", "p_keep JSONB", "jsonb"], ["_firewall_session_settings", "", ""],
];
const norm = (x: string) => x.replace(/\s+/g, " ").trim();

/**
 * The policies call these functions, so a changed body (say, a session-setting
 * "maintenance switch") opens every table while the policies still look exact.
 * Each must match the migration (body, SECURITY DEFINER, settings,
 * volatility), and every public._firewall_* object must have one owner: an
 * object another role planted before the migration ran keeps that owner.
 */
export async function firewallObjects(client: pg.ClientBase): Promise<{ ok: boolean; detail: string }> {
  const sql = readFileSync(MIGRATION, "utf8");
  const diff: string[] = [];
  for (const [name, args, sig] of FUNCTIONS) {
    const m = new RegExp(`FUNCTION public\\.${name}\\(${args}\\)\\s*RETURNS (\\w+) AS \\$\\$([\\s\\S]*?)\\$\\$ ` +
                         "LANGUAGE (\\w+)([^;]*);").exec(sql);
    const { rows: [f] } = await client.query(
      `SELECT prosrc, prosecdef, proconfig, provolatile, l.lanname, format_type(prorettype, NULL) AS ret
       FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.oid = to_regprocedure($1)`,
      [`public.${name}(${sig})`]);
    if (!m || !f) { diff.push(`${name} (missing)`); continue; }
    const [, ret, body, lang, tail] = m;
    const path = /SET search_path = ([^\n;]+?)\s*$/m.exec(tail!)?.[1];
    const what = [
      norm(f.prosrc) !== norm(body!) && "body",
      f.prosecdef !== /SECURITY DEFINER/.test(tail!) && "SECURITY DEFINER",
      JSON.stringify(f.proconfig) !== JSON.stringify(path ? [`search_path=${path}`] : null) && "settings",
      f.provolatile !== (/STABLE/.test(tail!) ? "s" : /IMMUTABLE/.test(tail!) ? "i" : "v") && "volatility",
      (f.lanname !== lang!.toLowerCase() || f.ret !== ret!.toLowerCase()) && "language or return type",
    ].filter(Boolean);
    if (what.length) diff.push(`${name} (${what.join(", ")})`);
  }
  const { rows: owners } = await client.query(
    `SELECT pg_get_userbyid(o.owner) AS owner, string_agg(o.name, ', ' ORDER BY o.name) AS objects
     FROM (SELECT relname::text AS name, relowner AS owner FROM pg_class
           WHERE relnamespace = 'public'::regnamespace AND relname LIKE '#_firewall#_%' ESCAPE '#'
           UNION ALL SELECT proname::text, proowner FROM pg_proc
           WHERE pronamespace = 'public'::regnamespace AND proname LIKE '#_firewall#_%' ESCAPE '#') o
     GROUP BY o.owner ORDER BY count(*) DESC`);
  if (owners.length > 1) {
    diff.push(`more than one owner (${owners.map((o) => `${o.owner}: ${o.objects}`).join("; ")}): ` +
              "objects another role planted? drop those and re-run migrate");
  }
  return { ok: diff.length === 0, detail: diff.length
    ? `differ from the migration: ${diff.join("; ")}${owners.length > 1 ? "" : ": re-run migrate"}`
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
  const { rows } = await client.query(SQL, [schema, column]);
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
