# @db-firewall/mcp

> Not on npm yet: until it is, build it from this repo (`npm ci && npm run build` in `packages/ts`, then here) and run `node dist/cli.js` where the examples say `npx @db-firewall/mcp`.

An MCP server for PostgreSQL where every tool call runs as one tenant. PostgreSQL row-level security, installed by the DB Firewall migration, decides which rows the call can see or change. The tenant comes from the server: a command-line flag (stdio), or a verified JWT on each request (HTTP). It never comes from the model, and no tool has a tenant argument.

## Before you start

1. Run the migration as an admin role, so every table with the tenant column has its policies and the database has a key:

   ```bash
   export DB_FIREWALL_TENANT_KEY=$(openssl rand -hex 32)
   npx db-firewall migrate --url "$ADMIN_URL" --schema app --harden --app-role app_user
   ```

   `--harden` matters here. All tenants share the app role, and sessions of one role can read each other's SQL text, literal values included, in `pg_stat_activity`. The server refuses to start while the role can do that. `--allow-query-text` overrides this, but use it only when one tenant uses the role.

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

- Each request is a `POST` with `Authorization: Bearer <JWT>`. The server checks the signature, `exp`, `iss` and `aud`. Then it reads the tenant from the `tenant_id` claim (`--tenant-claim` changes it). `--issuer` and `--audience` are required: without them, any token from a shared identity provider would do.
- `--jwt-secret-env <VAR>` names the variable that holds an HS256 secret of at least 32 bytes. Or use `--jwks-url <url>` for an identity provider's keys (RS256, PS256, ES256, EdDSA).
- A missing, forged, expired or tenant-less token gets `401`, and nothing runs. The reply gives no reason.
- Streamable HTTP, stateless: a new MCP server, bound to the token's tenant, serves each request. `GET` and `DELETE` (a stream, a session) get `405`.
- It listens on `127.0.0.1` by default (`--host`, `--port`). Put TLS and the public address in front of it.

Your app signs a short-lived token for the signed-in user's tenant, from your own auth, and passes it to its MCP client. [`examples/nextjs-agent`](../../examples/nextjs-agent) does this with the Vercel AI SDK.

## Tools

| Tool | What it does |
|---|---|
| `list_tables` | The tables in `--schema` that the role can use (not the firewall's own). |
| `describe_table` | The columns of one table in `--schema`. |
| `query` | One SQL statement: `SELECT`, `WITH`, `VALUES` or `TABLE`; with `--allow-writes` also `INSERT`, `UPDATE`, `DELETE` and `MERGE` (`MERGE` needs PostgreSQL 17). Its rows come back as JSON, at most `--max-rows` (default 100) and `--max-bytes` (default 1000000), with `truncated` when there were more. A row larger than `--max-bytes` comes back as its size. |

Each call is one transaction:
- The tenant is signed for this transaction only, and SQL the model sends cannot switch it.
- The transaction is `READ ONLY` unless you pass `--allow-writes`. With writes, a row for another tenant fails the policy's `WITH CHECK`.
- `statement_timeout` is `--statement-timeout` (default 5000 ms).
- `search_path` is `--schema`.
- The statement is first checked alone, as a cursor (reads) or a prepared statement (writes). So it is exactly one statement of the kinds above. `EXPLAIN`, `SET`, `COMMIT`, `COPY`, `LISTEN` and other commands are refused. `EXPLAIN ANALYZE` would show plans and row counts of other tenants' rows.
- Then PostgreSQL turns each row into JSON and applies the row and byte limits, so a huge result never reaches the server.
- After the call, the session is reset. A connection whose session was tampered with is closed, not reused.
- An error message is cut to 2,000 characters, because PostgreSQL can put a huge value in one.

## What it does not do

- **It does not limit what SQL the role may run.** The database role and its grants do that. Grant only what the agent needs.
- **It does not hide every side channel that RLS leaves open.** A `UNIQUE` or foreign-key error (with writes), or timing, can show that another tenant has a value. `verify --strict` lists the keys that leave out the tenant column. `EXPLAIN` is refused for this reason.
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
- the row and byte caps, also for a 20 MB row;
- refusal to start as a superuser, without the key, or while the role can read other sessions' SQL;
- error messages cut short;
- the HTTP token checks, `POST` only, and the required issuer and audience.
