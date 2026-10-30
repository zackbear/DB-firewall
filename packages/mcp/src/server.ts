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
}

/** Check once at start-up: the key is set and the role cannot skip RLS. */
export async function checkSetup(opts: ServerOptions): Promise<void> {
  if (!process.env[TENANT_KEY_ENV]) {
    throw new Error(`DB Firewall MCP: set ${TENANT_KEY_ENV} (the key the migration installed): ` +
                    "without it a signed database shows no rows");
  }
  await assertSafeRole(opts.pool);
}

// The first keyword, after spaces and comments: SELECT-like statements go
// through a cursor, so a big result is never read whole.
const READS = new Set(["select", "with", "values", "table"]);
function firstWord(sql: string): string {
  const s = sql.replace(/^(?:\s+|--[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)*/, "");
  return (s.match(/^[a-z]+/i)?.[0] ?? "").toLowerCase();
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
  if (!Number.isInteger(maxRows) || maxRows < 1) throw new RangeError("maxRows must be a positive integer");
  if (!Number.isInteger(timeout) || timeout < 1) throw new RangeError("statementTimeoutMs must be a positive integer");

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
    try { return await fn(); } catch (e) { return text(`Error: ${(e as Error).message}`, true); }
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
      (opts.allowWrites ? "; writes are allowed for this tenant only." : "; the transaction is read only.") +
      ` At most ${maxRows} rows come back.`,
    inputSchema: { sql: z.string().min(1).max(100_000) },
    annotations: { readOnlyHint: !opts.allowWrites },
  }, ({ sql }) => safely(async () => text(await run(async (c) => {
    // queryMode "extended": PostgreSQL refuses a string with more than one statement.
    if (READS.has(firstWord(sql))) {
      await c.query({ text: `DECLARE _dbfw_mcp NO SCROLL CURSOR FOR ${sql}`, queryMode: "extended" } as any);
      const r = await c.query(`FETCH ${maxRows + 1} FROM _dbfw_mcp`);
      return { rows: r.rows.slice(0, maxRows), truncated: r.rows.length > maxRows };
    }
    const r: any = await c.query({ text: sql, queryMode: "extended" } as any);
    return { command: r.command, rowCount: r.rowCount, rows: (r.rows ?? []).slice(0, maxRows),
             truncated: (r.rows?.length ?? 0) > maxRows };
  }))));

  return server;
}
