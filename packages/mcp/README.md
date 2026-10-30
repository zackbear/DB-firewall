# @db-firewall/mcp

> Not on npm yet: until it is, build it from this repo (`npm ci && npm run build` in `packages/ts`, then here) and run `node dist/cli.js` where the examples say `npx @db-firewall/mcp`.

An MCP server for PostgreSQL where every tool call runs as one tenant. PostgreSQL row-level security, installed by the DB Firewall migration, decides which rows the call can see or change. The tenant comes from the server: a command-line flag (stdio), or a verified JWT on each request (HTTP). It never comes from the model, and no tool has a tenant argument.

## Before you start

1. Run the migration as an admin role, so every table with the tenant column has its policies and the database has a key:

   ```bash
   export DB_FIREWALL_TENANT_KEY=$(openssl rand -hex 32)
   npx db-firewall migrate --url "$ADMIN_URL" --schema app
   ```

2. Give the server its own app role: a normal login role, not a superuser, without `BYPASSRLS`, with only the grants the agent needs (`SELECT` alone for a read-only agent). The server refuses to start as a role that can skip RLS.
3. Check isolation as that role: `npx db-firewall verify --url "$APP_URL" --schema app --tenant acme`.

The server needs `DB_FIREWALL_TENANT_KEY` (the same key) to sign the tenant for each transaction. Without the key, a signed database shows no rows.

## stdio: one tenant per process (Claude Desktop, Claude Code)

```json
{
  "mcpServers": {
    "company-db": {
      "command": "npx",
      "args": ["-y", "@db-firewall/mcp", "--tenant", "acme", "--schema", "app"],
      "env": { "DATABASE_URL": "postgres://app_user:...@db:5432/app", "DB_FIREWALL_TENANT_KEY": "..." }
    }
  }
}
```

## HTTP: the tenant from a verified token per request

```bash
npx @db-firewall/mcp --http --schema app --jwt-secret-env MCP_JWT_SECRET \
  --issuer my-app --audience db-firewall-mcp          # http://127.0.0.1:3333/mcp
```

- Each request needs `Authorization: Bearer <JWT>`. The server checks the signature, `exp` (required), and the issuer and audience you give. Then it reads the tenant from the `tenant_id` claim (`--tenant-claim` changes it).
- `--jwt-secret-env <VAR>` names the variable that holds an HS256 secret of at least 32 bytes. Or use `--jwks-url <url>` for an identity provider's keys (RS256, PS256, ES256, EdDSA).
- A missing, forged, expired or tenant-less token gets `401`, and nothing runs. The reply gives no reason.
- Streamable HTTP, stateless: a new MCP server, bound to the token's tenant, serves each request.
- It listens on `127.0.0.1` by default (`--host`, `--port`). Put TLS and the public address in front of it.

Your app signs a short-lived token for the signed-in user's tenant, from your own auth, and passes it to its MCP client. [`examples/nextjs-agent`](../../examples/nextjs-agent) does this with the Vercel AI SDK.

## Tools

| Tool | What it does |
|---|---|
| `list_tables` | The tables in `--schema` that the role can use (not the firewall's own). |
| `describe_table` | The columns of one table in `--schema`. |
| `query` | One SQL statement. Its rows come back as JSON, at most `--max-rows` (default 100), with `truncated` when there were more. |

Each call is one transaction:
- The tenant is signed for this transaction only, and SQL the model sends cannot switch it.
- The transaction is `READ ONLY` unless you pass `--allow-writes`. With writes, a row for another tenant fails the policy's `WITH CHECK`.
- `statement_timeout` is `--statement-timeout` (default 5000 ms).
- `search_path` is `--schema`.
- A string with more than one statement is refused.
- After the call, the session is reset. A connection whose session was tampered with is closed, not reused.

## What it does not do

- **It does not limit what SQL the role may run.** The database role and its grants do that. Grant only what the agent needs.
- **It does not hide side channels that RLS leaves open.** A `UNIQUE` or foreign-key error, or timing, can show that another tenant has a value. `verify --strict` lists the keys that leave out the tenant column.
- **It does not keep the tenant's own data from the model.** Every row the tenant can see can reach the model, and the model's provider.

## As a library

```ts
import pg from "pg";
import { checkSetup, createServer } from "@db-firewall/mcp";

const opts = { pool: new pg.Pool({ connectionString: process.env.DATABASE_URL }), schema: "app" };
await checkSetup(opts);                    // the key is set; the role cannot skip RLS
const server = createServer(opts, "acme"); // an McpServer bound to tenant acme: connect any transport
```

`startHttp(opts)` from `@db-firewall/mcp/http` starts the HTTP server.

## Tests

`DBFW_PG_URL=postgres://postgres@localhost:5432/test npm test` runs the live tests against a real database. They cover:
- each tenant sees only its own rows, also when the SQL tries to switch tenants;
- read only by default;
- one statement per call;
- writes only inside the tenant;
- the row cap;
- refusal to start as a superuser or without the key;
- the HTTP token checks.
