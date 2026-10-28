// PostgreSQL scan: the same checks as hooks/scan_engines.py (_scan_postgres),
// so TypeScript teams need no Python. Keep the two in step.
import type pg from "pg";

/** Tables the Python config skips by default (config/firewall.yaml excluded_tables). */
export const DEFAULT_EXCLUDED = [
  "_firewall_*", "schema_migrations", "alembic_version", "knex_migrations", "prisma_migrations",
  "__diesel_schema_migrations", "flyway_schema_history", "app_config", "feature_flags",
];

export interface TableReport {
  table: string;
  protected: boolean;
  rls_enabled: boolean;
  rls_forced: boolean;
  policy_mode: "permissive" | "restrictive";
  missing_policies: string[];
  extra_permissive_policies: string[];
  altered_policies: string[];
  stale_base_policy: boolean;
  predicate_check: string;
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

function globMatch(pattern: string, name: string): boolean {
  const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
  return re.test(name);
}

/**
 * The firewall predicate exactly as PostgreSQL deparses it for this table: a
 * policy with the migration's predicate on a temporary copy of the table's
 * columns, read back, then rolled back. Exact comparison catches a changed
 * cast, constant or function overload.
 */
async function reference(client: pg.ClientBase, schema: string, table: string, column: string):
    Promise<[string | null, string | null]> {
  const pred = `${ident(column)} = NULLIF(current_setting('app.current_tenant', true), '') ` +
    "OR public._firewall_is_bypass_role(current_user::text)";
  await client.query("BEGIN");
  try {
    await client.query(`CREATE TEMP TABLE _fw_ref (LIKE ${ident(schema)}.${ident(table)})`);
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

/** Scan every table in schema that has the tenant column. */
export async function scan(client: pg.ClientBase, opts: {
  schema?: string; column?: string; exclude?: string[];
} = {}): Promise<TableReport[]> {
  const schema = opts.schema ?? "public", column = opts.column ?? "tenant_id";
  const exclude = opts.exclude ?? DEFAULT_EXCLUDED;
  const { rows } = await client.query(SQL, [schema, column]);
  const out: TableReport[] = [];
  for (const r of rows) {
    if (exclude.some((p) => globMatch(p, r.table))) continue;
    const policies: [string, string, string[], string | null, string | null][] = r.policies;
    const [ref, why] = policies.length ? await reference(client, schema, r.table, column) : [null, null];
    const unverified = policies.length > 0 && ref === null;
    const altered = ref === null ? [] : policies.filter(([name, cmd, roles, qual, check]) => {
      const op = name.slice(name.lastIndexOf("_") + 1);
      const wantQual = ["sel", "upd", "del"].includes(op) ? ref : null;
      const wantCheck = ["ins", "upd"].includes(op) ? ref : null;
      return !(roles.length === 1 && roles[0] === "public") || cmd !== CMD[op]
        || qual !== wantQual || check !== wantCheck;
    }).map(([name]) => name).sort();
    const extra: string[] = [...r.extra].sort();
    out.push({
      table: r.table,
      rls_enabled: r.enabled, rls_forced: r.forced,
      policy_mode: r.restrictive ? "restrictive" : "permissive",
      missing_policies: [...r.missing].sort(),
      extra_permissive_policies: extra,
      altered_policies: altered,
      stale_base_policy: r.base && extra.some((e) => !e.endsWith("_base")),
      predicate_check: unverified
        ? `unavailable: ${why} (run outside a read-only transaction, with the TEMP privilege and SELECT on the table)`
        : "ok",
      protected: r.enabled && r.forced && r.missing.length === 0 && altered.length === 0 && !unverified
        && (r.restrictive || extra.length === 0),
    });
  }
  return out;
}
