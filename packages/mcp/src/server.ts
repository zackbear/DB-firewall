// An MCP server whose every tool call runs as one tenant. The tenant is
// fixed when the server is made (a CLI flag in stdio mode, a verified token
// per HTTP request), never taken from the model: no tool has a tenant field.
// withTenant() signs the tenant for each transaction, PostgreSQL row-level
// security does the rest, and the session is reset after each call.
import type pg from "pg";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { TENANT_KEY_ENV, assertSafeRole, validateTenantId, withTenant } from "@db-firewall/pg";

export const VERSION = "0.1.0";

export interface ServerOptions {
  /** A pool for the app role: a normal role, not a superuser or BYPASSRLS. */
  pool: pg.Pool;
  /** The schema the tools list and describe (queries can name any table the role can read). */
  schema: string;
  /** Allow INSERT, UPDATE and DELETE (still inside the tenant). Default: read only. */
  allowWrites?: boolean;
  /** Rows a query returns at most (default 100). */
  maxRows?: number;
  /** statement_timeout for each call, in milliseconds (default 5000). */
  statementTimeoutMs?: number;
  /** Bytes of row JSON a query returns at most (default 1000000). A row larger than this comes back as its size only. */
  maxBytes?: number;
  /** Start even though sessions of this role can read each other's SQL text (see checkSetup). */
  allowQueryText?: boolean;
}

// The migration's own check (checks/postgresql.sql, query_text): can a role
// this one can act as read other sessions' SQL text?
const QUERY_TEXT = `SELECT EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
  AND (has_table_privilege(m.oid, 'pg_catalog.pg_stat_activity', 'SELECT')
       OR has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')
       OR has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_backend_activity(integer)', 'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_proc f WHERE f.proname = 'pg_stat_statements'
                    AND has_function_privilege(m.oid, f.oid, 'EXECUTE'))
       OR EXISTS (SELECT 1 FROM pg_class v WHERE v.relname = 'pg_stat_statements' AND v.relkind = 'v'
                    AND has_table_privilege(m.oid, v.oid, 'SELECT')))) AS can,
  EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
    AND has_function_privilege(m.oid, 'pg_catalog.pg_notify(text, text)', 'EXECUTE')) AS notify`;

/**
 * Check once at start-up: the key is set, the role cannot skip RLS, and its
 * sessions cannot read each other's SQL text. All tenants share the role
 * (the HTTP server, or one stdio process per tenant), so through
 * pg_stat_activity one tenant could read another's queries, literal values
 * included. It also refuses a role that can run pg_notify() (messages to every
 * listener in the database). `db-firewall migrate --harden --app-role <role>`
 * revokes both.
 */
export async function checkSetup(opts: ServerOptions): Promise<void> {
  if (!process.env[TENANT_KEY_ENV]) {
    throw new Error(`DB Firewall MCP: set ${TENANT_KEY_ENV} (the key the migration installed): ` +
                    "without it a signed database shows no rows");
  }
  await assertSafeRole(opts.pool);
  const { can, notify } = (await opts.pool.query(QUERY_TEXT)).rows[0];
  if (!opts.allowQueryText && can) {
    throw new Error("DB Firewall MCP: sessions of this role can read each other's SQL text (pg_stat_activity, " +
                    "pg_stat_statements), so one tenant could read another's queries. Run " +
                    "db-firewall migrate --harden --app-role <role>, or pass --allow-query-text " +
                    "when one tenant only uses this role");
  }
  // A read-only tenant could still send any payload to every listener in the
  // database (a job queue, a cache) with SELECT pg_notify(...).
  if (notify) {
    throw new Error("DB Firewall MCP: this role can run pg_notify(), so SQL a tenant runs could send messages to " +
                    "every listener in the database. Run db-firewall migrate --harden --app-role <role>, or " +
                    "REVOKE EXECUTE ON FUNCTION pg_notify(text, text) FROM PUBLIC");
  }
}

// The model's SQL runs in two steps.
//  1. Alone, as a check: DECLARE CURSOR takes exactly one SELECT, WITH, VALUES
//     or TABLE statement; with writes allowed, PREPARE also takes INSERT,
//     UPDATE, DELETE and MERGE. Both refuse EXPLAIN (its plans and row counts
//     show other tenants' rows), SET, COMMIT, COPY, LISTEN and the like. A
//     statement that passes is complete on its own, so it cannot close the
//     wrapper of step 2.
//  2. Wrapped: PostgreSQL turns each row into JSON text, replaces a row larger
//     than maxBytes with its size, and stops at maxRows and maxBytes. So a
//     huge result never reaches this process.
/** Error text, cut short: PostgreSQL can put a huge value in a message (a constant it computed while planning). */
const MAX_ERROR = 2000;
const errorText = (e: unknown): string => {
  const m = String((e as Error)?.message ?? e);
  return m.length > MAX_ERROR ? `${m.slice(0, MAX_ERROR)}... (${m.length} characters)` : m;
};

const READ_KINDS = "read only: one SELECT, WITH, VALUES or TABLE statement";
const WRITE_KINDS = "one SELECT, WITH, VALUES, TABLE, INSERT, UPDATE, DELETE or MERGE statement " +
  "(MERGE needs PostgreSQL 17)";

/** The rows of `from` (alias `alias`) as JSON text, within the limits, plus one row past them if any. */
function capped(from: string, alias: string, maxRows: number, maxBytes: number, total: boolean): string {
  return `SELECT j, n, run${total ? ", total" : ""} FROM (
    SELECT CASE WHEN n <= ${maxBytes} THEN j END AS j, n,
           sum(least(n, ${maxBytes})) OVER (ROWS UNBOUNDED PRECEDING) AS run${total ? ", count(*) OVER () AS total" : ""}
    FROM (SELECT j, octet_length(j) AS n FROM (SELECT row_to_json(${alias}.*)::text AS j FROM ${from}) AS _s0) AS _s1) AS _s2
  WHERE run - least(n, ${maxBytes}) <= ${maxBytes} LIMIT ${maxRows + 1}`;
}

/** The JSON of a result, built from the rows' own JSON text (big numbers keep their digits). */
function result(rows: { j: string | null; n: string; run: string }[], maxRows: number, maxBytes: number,
                extra = ""): string {
  const out: string[] = [];
  let truncated = false;
  for (const r of rows) {
    if (out.length === maxRows || Number(r.run) > maxBytes) { truncated = true; break; }
    out.push(r.j ?? JSON.stringify({ _dbfw_row_too_large_bytes: Number(r.n) }));
  }
  return `{${extra}"rows":[${out.join(",")}],"truncated":${truncated}}`;
}

function text(value: unknown, isError = false) {
  return { content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value) }],
           ...(isError ? { isError: true } : {}) };
}

/** One MCP server bound to one tenant. */
export function createServer(opts: ServerOptions, tenantId: string): McpServer {
  const tenant = validateTenantId(tenantId);
  const maxRows = opts.maxRows ?? 100;
  const timeout = opts.statementTimeoutMs ?? 5000;
  const maxBytes = opts.maxBytes ?? 1_000_000;
  if (!Number.isInteger(maxRows) || maxRows < 1) throw new RangeError("maxRows must be a positive integer");
  if (!Number.isInteger(timeout) || timeout < 1) throw new RangeError("statementTimeoutMs must be a positive integer");
  if (!Number.isInteger(maxBytes) || maxBytes < 1) throw new RangeError("maxBytes must be a positive integer");

  // One transaction as the tenant: a time limit, and read only unless writes
  // are allowed. Both are set after withTenant's own query, which PostgreSQL
  // allows for READ ONLY; SQL the model sends cannot set READ WRITE again.
  const run = <T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> =>
    withTenant(opts.pool, tenant, async (c: pg.PoolClient) => {
      // The schema first for unqualified names (pg_catalog is searched before it).
      await c.query("SELECT set_config('statement_timeout', $1, true), set_config('search_path', quote_ident($2), true)",
                    [String(timeout), opts.schema]);
      if (!opts.allowWrites) await c.query("SET TRANSACTION READ ONLY");
      return fn(c);
    });
  const safely = async (fn: () => Promise<ReturnType<typeof text>>) => {
    try { return await fn(); } catch (e) { return text(`Error: ${errorText(e)}`, true); }
  };

  const server = new McpServer({ name: "db-firewall", version: VERSION });

  server.registerTool("list_tables", {
    description: `Tables in schema ${opts.schema} that this database role can use.`,
    annotations: { readOnlyHint: true },
  }, () => safely(async () => text(await run(async (c) => (await c.query(
    "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 " +
    "AND table_name NOT LIKE '\\_firewall\\_%' ORDER BY 1", [opts.schema])).rows.map((r) => r.table_name)))));

  server.registerTool("describe_table", {
    description: `The columns of one table in schema ${opts.schema}.`,
    inputSchema: { table: z.string().min(1).max(63) },
    annotations: { readOnlyHint: true },
  }, ({ table }) => safely(async () => text(await run(async (c) => (await c.query(
    "SELECT column_name, data_type, is_nullable FROM information_schema.columns " +
    "WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position", [opts.schema, table])).rows))));

  server.registerTool("query", {
    description: "Run one SQL statement and get its rows as JSON. Only the current tenant's rows are visible" +
      (opts.allowWrites ? "; INSERT, UPDATE, DELETE and MERGE are allowed for this tenant only."
                        : "; the transaction is read only (SELECT, WITH, VALUES, TABLE).") +
      ` At most ${maxRows} rows and ${maxBytes} bytes come back. EXPLAIN is not available.`,
    inputSchema: { sql: z.string().min(1).max(100_000) },
    annotations: { readOnlyHint: !opts.allowWrites },
  }, ({ sql }) => safely(async () => text(await run(async (c) => {
    // queryMode "extended": PostgreSQL refuses a string with more than one statement.
    const ext = (t: string): Promise<any> => c.query({ text: t, queryMode: "extended" } as any);
    const q = sql.replace(/;\s*$/, "");
    await c.query("SAVEPOINT _dbfw_mcp");
    try {
      await ext(`DECLARE _dbfw_mcp NO SCROLL CURSOR FOR\n${q}\n`);
    } catch (e) {
      await c.query("ROLLBACK TO SAVEPOINT _dbfw_mcp");
      if (!opts.allowWrites) throw new Error(`${errorText(e)} (${READ_KINDS})`);
      try {
        await ext(`PREPARE _dbfw_mcp AS\n${q}\n`);
      } catch (e2) {
        throw new Error(`${errorText(e2)} (${WRITE_KINDS})`);
      }
      await c.query("DEALLOCATE _dbfw_mcp");
      await c.query("SAVEPOINT _dbfw_mcp_w");
      try {
        const r = await ext(`WITH _w AS (\n${q}\n) ${capped("_w", "_w", maxRows, maxBytes, true)}`);
        return result(r.rows, maxRows, maxBytes, `"rowCount":${Number(r.rows[0]?.total ?? 0)},`);
      } catch (e3: any) {
        // INSERT, UPDATE, DELETE or MERGE without RETURNING: it returns no rows.
        if (e3?.code !== "0A000" || !/RETURNING clause/.test(e3?.message ?? "")) throw e3;
        await c.query("ROLLBACK TO SAVEPOINT _dbfw_mcp_w");
        const r = await ext(q);
        return JSON.stringify({ command: r.command, rowCount: r.rowCount });
      }
    }
    await c.query("CLOSE _dbfw_mcp");
    // The inner LIMIT stops the scan at the row cap (the byte cap filters, it does not stop).
    const r = await ext(capped(`(SELECT * FROM (\n${q}\n) AS _q0 LIMIT ${maxRows + 1}) AS _q`, "_q", maxRows, maxBytes, false));
    return result(r.rows, maxRows, maxBytes);
  }))));

  return server;
}
