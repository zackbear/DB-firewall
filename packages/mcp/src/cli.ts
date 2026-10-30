#!/usr/bin/env node
// db-firewall-mcp: stdio (one tenant per process) or --http (tenant from a
// verified token per request). Logs go to stderr: stdout is the protocol.
import { parseArgs } from "node:util";
import pg from "pg";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { checkSetup, createServer } from "./server.js";
import { startHttp } from "./http.js";

const USAGE = `db-firewall-mcp: an MCP server for PostgreSQL where every tool call runs as one tenant.

  db-firewall-mcp --tenant <id> [options]                 stdio, one tenant (Claude Desktop, Claude Code)
  db-firewall-mcp --http --jwt-secret-env <VAR> --issuer <iss> --audience <aud> [options]
                                                          HTTP, the tenant from a verified JWT per request
  db-firewall-mcp --http --jwks-url <url> --issuer <iss> --audience <aud> [options]

  --url <postgres-url>      the app role's database URL (default: DATABASE_URL)
  --schema <name>           the schema list_tables and describe_table show (default: public)
  --tenant <id>             stdio: the tenant (default: DB_FIREWALL_MCP_TENANT)
  --allow-writes            allow INSERT, UPDATE and DELETE, still inside the tenant (default: read only)
  --max-rows <n>            rows a query returns at most (default: 100)
  --max-bytes <n>           bytes of row JSON a query returns at most (default: 1000000)
  --statement-timeout <ms>  per call (default: 5000)
  --port <n>                HTTP port (default: 3333); --host <addr> (default: 127.0.0.1)
  --jwt-secret-env <VAR>    the environment variable that holds the HS256 secret
  --jwks-url <url>          or the identity provider's JWKS URL
  --issuer <iss> --audience <aud>  HTTP: required, the iss and aud tokens must carry
  --tenant-claim <name>     HTTP: the claim that holds the tenant (default: tenant_id)

  DB_FIREWALL_TENANT_KEY must be set: the key the migration installed.`;

function int(v: string | undefined, d: number, name: string): number {
  if (v === undefined) return d;
  if (!/^\d+$/.test(v) || Number(v) < 1) throw new Error(`--${name} must be a positive integer`);
  return Number(v);
}

async function main(): Promise<number> {
  const { values: a } = parseArgs({ strict: true, options: {
    url: { type: "string" }, schema: { type: "string" }, tenant: { type: "string" },
    "allow-writes": { type: "boolean" }, "max-rows": { type: "string" }, "max-bytes": { type: "string" },
    "statement-timeout": { type: "string" },
    http: { type: "boolean" }, port: { type: "string" }, host: { type: "string" },
    "jwt-secret-env": { type: "string" }, "jwks-url": { type: "string" },
    issuer: { type: "string" }, audience: { type: "string" }, "tenant-claim": { type: "string" },
    help: { type: "boolean" },
  } });
  if (a.help) { process.stderr.write(USAGE + "\n"); return 0; }
  const url = a.url ?? process.env.DATABASE_URL;
  if (!url) throw new Error("give --url or DATABASE_URL");
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  const opts = {
    pool, schema: a.schema ?? "public", allowWrites: !!a["allow-writes"],
    maxRows: int(a["max-rows"], 100, "max-rows"), maxBytes: int(a["max-bytes"], 1_000_000, "max-bytes"),
    statementTimeoutMs: int(a["statement-timeout"], 5000, "statement-timeout"),
  };
  await checkSetup(opts);

  if (a.http) {
    const secretVar = a["jwt-secret-env"];
    if (secretVar && !process.env[secretVar]) throw new Error(`${secretVar} is not set`);
    const port = int(a.port, 3333, "port");
    await startHttp({ ...opts, port, host: a.host, jwtSecret: secretVar ? process.env[secretVar] : undefined,
                      jwksUrl: a["jwks-url"], issuer: a.issuer ?? "", audience: a.audience ?? "",
                      tenantClaim: a["tenant-claim"] });
    process.stderr.write(`db-firewall-mcp: http://${a.host ?? "127.0.0.1"}:${port}/mcp` +
                         `${opts.allowWrites ? " (writes allowed)" : " (read only)"}\n`);
    return -1;                                   // keep running
  }
  const tenant = a.tenant ?? process.env.DB_FIREWALL_MCP_TENANT;
  if (!tenant) throw new Error("give --tenant (or DB_FIREWALL_MCP_TENANT), or --http");
  await createServer(opts, tenant).connect(new StdioServerTransport());
  return -1;
}

main().then((code) => { if (code >= 0) process.exit(code); },
            (e) => { process.stderr.write(`db-firewall-mcp: ${(e as Error).message}\n`); process.exit(2); });
