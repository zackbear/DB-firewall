// End to end, without an Anthropic key: a mock model asks the agent's MCP
// tools for every customer and invoice. The real MCP server (HTTP, token per
// request) and PostgreSQL decide what comes back. DBFW_PG_URL: an admin URL.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV4 } from "ai/test";

const ADMIN_URL = process.env.DBFW_PG_URL;
if (!ADMIN_URL && process.env.DBFW_REQUIRE_LIVE) throw new Error("DBFW_REQUIRE_LIVE set but DBFW_PG_URL is not");
const live = { skip: ADMIN_URL ? false : "DBFW_PG_URL not set" };
const ROOT = new URL("../../../", import.meta.url);
const KEY = "7c".repeat(32);

Object.assign(process.env, { DB_FIREWALL_TENANT_KEY: KEY, MCP_JWT_SECRET: "m".repeat(40), SESSION_SECRET: "s".repeat(40) });

const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
                outputTokens: { total: 1, text: 1, reasoning: 0 } };
/** A model that calls query with the SQL, then answers "done". */
function model(sql: string) {
  return new MockLanguageModelV4({ doStream: [
    { stream: simulateReadableStream({ chunks: [
      { type: "tool-call", toolCallId: "c1", toolName: "query", input: JSON.stringify({ sql }) },
      { type: "finish", finishReason: { unified: "tool-calls", raw: undefined }, usage }] as any }) },
    { stream: simulateReadableStream({ chunks: [
      { type: "text-start", id: "t" }, { type: "text-delta", id: "t", delta: "done" }, { type: "text-end", id: "t" },
      { type: "finish", finishReason: { unified: "stop", raw: undefined }, usage }] as any }) },
  ] });
}

describe("the starter agent", live, () => {
  let server: any;
  before(async () => {
    const admin = new pg.Client({ connectionString: ADMIN_URL }); await admin.connect();
    try {
      await admin.query("DROP SCHEMA IF EXISTS app CASCADE; DROP ROLE IF EXISTS app_user");
      await admin.query(readFileSync(new URL("../db/seed.sql", import.meta.url), "utf8"));
    } finally { await admin.end(); }
    const cli = fileURLToPath(new URL("packages/cli/dist/cli.js", ROOT));
    const m = spawnSync(process.execPath, [cli, "migrate", "--url", ADMIN_URL!, "--schema", "app"], { encoding: "utf8" });
    assert.equal(m.status, 0, m.stderr);
    const appUrl = new URL(ADMIN_URL!); appUrl.username = "app_user"; appUrl.password = "app_user_dev_password";
    const { startHttp } = await import(new URL("packages/mcp/dist/http.js", ROOT).href);
    const pool = new pg.Pool({ connectionString: appUrl.toString() });
    server = await startHttp({ pool, schema: "app", port: 0, jwtSecret: process.env.MCP_JWT_SECRET,
                               issuer: "starter", audience: "db-firewall-mcp" });
    server.on("close", () => pool.end());
    process.env.MCP_URL = `http://127.0.0.1:${server.address().port}/mcp`;
  });
  after(async () => {
    await new Promise((r) => server?.close(r));
    const admin = new pg.Client({ connectionString: ADMIN_URL }); await admin.connect();
    try { await admin.query("DROP SCHEMA IF EXISTS app CASCADE; DROP OWNED BY app_user; DROP ROLE IF EXISTS app_user"); }
    finally { await admin.end(); }
  });

  for (const [tenant, mine, theirs] of [["acme", "Blue Mountain Coffee", "Montego Bay Resorts"],
                                        ["globex", "Montego Bay Resorts", "Blue Mountain Coffee"]]) {
    it(`${tenant}: the tools see ${tenant}'s rows only, whatever SQL the model sends`, async () => {
      const { runAgent } = await import("../lib/agent.ts");
      for (const sql of ["SELECT name FROM customers ORDER BY name",
                         "SELECT name FROM customers WHERE tenant_id <> current_setting('app.current_tenant')",
                         "SELECT set_config('app.current_tenant', 'globex', true), (SELECT string_agg(name, ',') FROM customers)"]) {
        const result = await runAgent({ tenant, model: model(sql), messages: [{ role: "user", content: "list customers" }] });
        const steps = await result.steps;
        const output = JSON.stringify(steps[0]!.toolResults);
        assert.ok(!output.includes(theirs), `${sql}: ${output}`);
        if (sql.startsWith("SELECT name FROM customers ORDER")) assert.ok(output.includes(mine), output);
        assert.equal(await result.text, "done");
      }
    });
  }

  it("session cookies: a forged or expired one is no session", async () => {
    const { readSession, signSession } = await import("../lib/session.ts");
    const good = await signSession("alice@acme.test");
    assert.deepEqual(await readSession(good), { email: "alice@acme.test", tenant: "acme" });
    const [h, , s] = good.split(".");
    const forged = `${h}.${Buffer.from(JSON.stringify({ sub: "alice@acme.test", tenant: "globex", exp: 9e9 })).toString("base64url")}.${s}`;
    assert.equal(await readSession(forged), null);
    assert.equal(await readSession(undefined), null);
  });
});
