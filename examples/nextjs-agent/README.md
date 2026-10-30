# Agent starter: Next.js, Claude and DB Firewall

A chat agent that answers questions about a company's data in PostgreSQL. Two demo companies (tenants) share the same tables. The agent queries them through the DB Firewall MCP server, and PostgreSQL row-level security shows each signed-in user only their own company's rows, whatever SQL the model writes.

```
browser ──cookie──▶ Next.js /api/chat ──token (tenant)──▶ db-firewall-mcp ──signed tenant──▶ PostgreSQL (RLS)
                     (Claude, AI SDK)                      (HTTP, one tenant per request)
```

- **Sign-in.** The session cookie names the user and their tenant. The model never sees or chooses the tenant.
- **One token per request.** For each chat request, the app signs a 5-minute token with the user's tenant and gives it to its MCP client.
- **The MCP server.** It checks the token, signs the tenant for each transaction, and runs the model's SQL as a normal role inside that tenant. It is read only.

## Run it

You need Node 22, Docker and an Anthropic API key.

```bash
cd examples/nextjs-agent
docker compose up -d                       # PostgreSQL 17 with the demo data (db/seed.sql)
cp .env.example .env.local                 # fill in the three secrets and ANTHROPIC_API_KEY
npm ci
(cd ../../packages/ts && npm ci && npm run build)
(cd ../../packages/cli && npm ci && npm run build)
(cd ../../packages/mcp && npm ci && npm run build)
npm run db:migrate                         # install the policies, then verify as app_user
npm run mcp &                              # the MCP server on http://127.0.0.1:3333/mcp
npm run dev                                # http://localhost:3000
```

Make each secret with `openssl rand -hex 32`.

Sign in as Alice (Acme) and ask "Which customers do we have?". Then ask for Globex's invoices, or click the example that tries SQL with `tenant_id <> ...`: the rows of the other company never come back. Sign out, sign in as Bob (Globex), and you see Globex's data.

## Make it yours

- **Sign-in.** Replace the demo login (`lib/session.ts`, `app/api/login`) with your own auth. Take the tenant from your user's organization on the server, never from the request body.
- **Schema.** Put your tables in a schema with a `tenant_id` column, and run `npx db-firewall migrate` after each schema change. Make keys include the tenant, as `db/seed.sql` does: `PRIMARY KEY (tenant_id, id)`, and foreign keys on `(tenant_id, ...)`. `verify --strict` lists keys that do not.
- **Grants.** Give the app role only what the agent needs. The MCP server is read only unless it runs with `--allow-writes`. Writes stay inside the tenant.
- **Deploy.** Run the MCP server next to the app, on a private address. Keep `MCP_JWT_SECRET`, `SESSION_SECRET` and `DB_FIREWALL_TENANT_KEY` in your secret store.

## Test

`DBFW_PG_URL=postgres://postgres@localhost:5432/test npm test` (an admin URL to a test database). The test:
- loads the seed;
- runs the migration;
- starts the real MCP server over HTTP;
- drives the agent with a mock model, so it needs no API key, and checks that each tenant's tool results hold only its own rows, also for SQL that tries to switch tenants or name the other one;
- checks that a forged session cookie is refused.

This is a demo. Its sign-in has no password.
