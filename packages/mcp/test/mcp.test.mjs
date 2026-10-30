// Live: DBFW_PG_URL is an admin URL. Schema mcp_app with docs (tenant A: id 1,
// tenant B: id 2) under the real migration, and a normal login role for the
// server. Each tool call must see one tenant only, whatever SQL it is given.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import pg from "pg";
import { SignJWT } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const ADMIN_URL = process.env.DBFW_PG_URL;
if (!ADMIN_URL && process.env.DBFW_REQUIRE_LIVE) throw new Error("DBFW_REQUIRE_LIVE set but DBFW_PG_URL is not");
const live = { skip: ADMIN_URL ? false : "DBFW_PG_URL not set" };
const S = "mcp_app", ROLE = "dbfw_mcp", PW = "DbfwMcp_2026x", KEY = "6b".repeat(32);
const SECRET = "s".repeat(40);
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
process.env.DB_FIREWALL_TENANT_KEY = KEY;

function appUrl() { const u = new URL(ADMIN_URL); u.username = ROLE; u.password = PW; return u.toString(); }
async function admin(text) {
  const c = new pg.Client({ connectionString: ADMIN_URL }); await c.connect();
  try { return await c.query(text); } finally { await c.end(); }
}
const json = (r) => JSON.parse(r.content[0].text);

async function stdio(args) {
  const client = new Client({ name: "test", version: "1" });
  await client.connect(new StdioClientTransport({
    command: "node", args: [CLI, "--url", appUrl(), "--schema", S, ...args],
    env: { ...process.env, DB_FIREWALL_TENANT_KEY: KEY }, stderr: "pipe" }));
  return client;
}

describe("db-firewall-mcp", live, () => {
  before(async () => {
    await admin(`DROP SCHEMA IF EXISTS ${S} CASCADE; CREATE SCHEMA ${S};
      DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}')
        THEN CREATE ROLE ${ROLE} LOGIN PASSWORD '${PW}'; END IF; END $$;
      CREATE TABLE ${S}.docs (id int PRIMARY KEY, tenant_id text NOT NULL, body text);
      INSERT INTO ${S}.docs VALUES (1, 'A', 'a-doc'), (2, 'B', 'b-secret');
      GRANT USAGE ON SCHEMA ${S} TO ${ROLE}; GRANT SELECT, INSERT, UPDATE, DELETE ON ${S}.docs TO ${ROLE};
      SELECT set_config('dbfw.schema', '${S}', false), set_config('dbfw.tenant_key', '${KEY}', false);`);
    await admin(readFileSync(new URL("../../../migrations/001_postgresql.sql", import.meta.url), "utf8")
      .replace("BEGIN;", `BEGIN; SET LOCAL dbfw.schema = '${S}'; SET LOCAL dbfw.tenant_key = '${KEY}';`));
  });
  after(async () => { await admin(`DROP SCHEMA IF EXISTS ${S} CASCADE`); });

  it("stdio: no tool takes a tenant, and each sees tenant A only", async () => {
    const c = await stdio(["--tenant", "A"]);
    try {
      const { tools } = await c.listTools();
      assert.deepEqual(tools.map((t) => t.name).sort(), ["describe_table", "list_tables", "query"]);
      for (const t of tools) assert.ok(!JSON.stringify(t.inputSchema).includes("tenant"), t.name);
      assert.deepEqual(json(await c.callTool({ name: "list_tables", arguments: {} })), ["docs"]);
      const q = json(await c.callTool({ name: "query", arguments: { sql: "SELECT id, body FROM docs ORDER BY id" } }));
      assert.deepEqual(q.rows, [{ id: 1, body: "a-doc" }]);
      // SQL that tries to switch tenants, or to see the other one
      for (const sql of ["SELECT set_config('app.current_tenant', 'B', true), (SELECT count(*) FROM docs)",
                         "/* x */ SELECT * FROM docs WHERE tenant_id = 'B'"]) {
        const r = await c.callTool({ name: "query", arguments: { sql } });
        assert.ok(!r.content[0].text.includes("b-secret"), sql);
      }
      const cols = json(await c.callTool({ name: "describe_table", arguments: { table: "docs" } }));
      assert.deepEqual(cols.map((x) => x.column_name), ["id", "tenant_id", "body"]);
    } finally { await c.close(); }
  });

  it("stdio: read only by default; one statement per call; the transaction stays read only", async () => {
    const c = await stdio(["--tenant", "A"]);
    try {
      for (const [sql, msg] of [["INSERT INTO docs VALUES (9, 'A', 'x')", /read only/],
                                ["SELECT 1; DELETE FROM docs", /multiple commands/],
                                ["SET TRANSACTION READ WRITE", /read only/],
                                ["WITH d AS (DELETE FROM docs RETURNING *) SELECT * FROM d", /data-modifying/],
                                ["COMMIT", /read only/],
                                ["EXPLAIN ANALYZE SELECT * FROM docs WHERE body = 'b-secret'", /read only/]]) {
        const r = await c.callTool({ name: "query", arguments: { sql } });
        assert.equal(r.isError, true, sql);
        assert.match(r.content[0].text, msg, sql);
      }
      // PostgreSQL nests block comments: this is one comment, then SELECT 1 (PostgreSQL decides, not a regex)
      const nested = json(await c.callTool({ name: "query", arguments: { sql: "/* /* */ commit */ SELECT 1 AS one" } }));
      assert.deepEqual(nested.rows, [{ one: 1 }]);
    } finally { await c.close(); }
    assert.equal((await admin(`SELECT count(*)::int AS n FROM ${S}.docs`)).rows[0].n, 2);
  });

  it("stdio --allow-writes: writes for its own tenant, never for another", async () => {
    const c = await stdio(["--tenant", "A", "--allow-writes"]);
    try {
      const ok = json(await c.callTool({ name: "query", arguments: { sql: "INSERT INTO docs VALUES (3, 'A', 'new') RETURNING id" } }));
      assert.deepEqual(ok.rows, [{ id: 3 }]);
      const bad = await c.callTool({ name: "query", arguments: { sql: "INSERT INTO docs VALUES (4, 'B', 'planted')" } });
      assert.equal(bad.isError, true);
      assert.match(bad.content[0].text, /row-level security/);
      const upd = json(await c.callTool({ name: "query", arguments: { sql: "UPDATE docs SET body = 'x' WHERE id = 2" } }));
      assert.equal(upd.rowCount, 0);                                   // B's row is not there for A
      const mine = json(await c.callTool({ name: "query", arguments: { sql: "UPDATE docs SET body = 'y' WHERE id = 3" } }));
      assert.deepEqual(mine, { command: "UPDATE", rowCount: 1 });
      const ret = json(await c.callTool({ name: "query", arguments: { sql: "DELETE FROM docs WHERE id = 3 RETURNING id, body" } }));
      assert.deepEqual(ret, { rowCount: 1, rows: [{ id: 3, body: "y" }], truncated: false });
      for (const sql of ["EXPLAIN ANALYZE SELECT * FROM docs WHERE body = 'b-secret'", "SET ROLE postgres",
                         "COPY docs TO STDOUT", "COMMIT"]) {
        const r = await c.callTool({ name: "query", arguments: { sql } });
        assert.equal(r.isError, true, sql);
      }
    } finally { await c.close(); await admin(`DELETE FROM ${S}.docs WHERE id > 2`); }
  });

  it("caps the rows a query returns", async () => {
    const c = await stdio(["--tenant", "A", "--max-rows", "2"]);
    try {
      const q = json(await c.callTool({ name: "query", arguments: { sql: "SELECT g FROM generate_series(1, 10) g" } }));
      assert.deepEqual(q.rows, [{ g: 1 }, { g: 2 }]);
      assert.equal(q.truncated, true);
      const all = json(await c.callTool({ name: "query", arguments: { sql: "VALUES (1), (2);" } }));
      assert.deepEqual(all, { rows: [{ column1: 1 }, { column1: 2 }], truncated: false });
      const big = json(await c.callTool({ name: "query", arguments: { sql: "SELECT 12345678901234567890::numeric AS n" } }));
      assert.equal(JSON.stringify(big.rows), '[{"n":12345678901234567000}]');   // JSON numbers, as PostgreSQL writes them
    } finally { await c.close(); }
  });

  it("caps the bytes in PostgreSQL: a huge row or result never reaches the server", async () => {
    const c = await stdio(["--tenant", "A", "--max-bytes", "1000"]);
    try {
      const one = json(await c.callTool({ name: "query", arguments: { sql: "SELECT repeat('x', 20000000) AS x" } }));
      assert.deepEqual(one, { rows: [{ _dbfw_row_too_large_bytes: 20000008 }], truncated: false });
      const many = json(await c.callTool({ name: "query", arguments: {
        sql: "SELECT repeat('y', 300) AS y FROM generate_series(1, 50)" } }));
      assert.equal(many.truncated, true);
      assert.ok(JSON.stringify(many.rows).length <= 1000 + 400, String(JSON.stringify(many.rows).length));
      // a comment at the end, and a wrapper the SQL tries to close, stay inside
      const cmt = await c.callTool({ name: "query", arguments: { sql: "SELECT 1 AS a -- the end" } });
      assert.deepEqual(json(cmt).rows, [{ a: 1 }]);
      const out = await c.callTool({ name: "query", arguments: { sql: "SELECT 1) AS _q) s, (SELECT repeat('z', 5000)) z --" } });
      assert.equal(out.isError, true);
    } finally { await c.close(); }
  });

  it("refuses to start as a superuser, or without the key", async () => {
    const { spawnSync } = await import("node:child_process");
    const asAdmin = spawnSync("node", [CLI, "--url", ADMIN_URL, "--tenant", "A"], { env: process.env, encoding: "utf8" });
    assert.equal(asAdmin.status, 2);
    assert.match(asAdmin.stderr, /superuser|BYPASSRLS/);
    const noKey = spawnSync("node", [CLI, "--url", appUrl(), "--tenant", "A"],
                            { env: { ...process.env, DB_FIREWALL_TENANT_KEY: "" }, encoding: "utf8" });
    assert.equal(noKey.status, 2);
    assert.match(noKey.stderr, /DB_FIREWALL_TENANT_KEY/);
  });

  describe("http", () => {
    let server, url;
    before(async () => {
      const { startHttp } = await import("../dist/http.js");
      const pool = new pg.Pool({ connectionString: appUrl() });
      server = await startHttp({ pool, schema: S, port: 0, jwtSecret: SECRET, issuer: "starter", audience: "db-firewall-mcp" });
      server.on("close", () => pool.end());
      url = new URL(`http://127.0.0.1:${server.address().port}/mcp`);
    });
    after(() => new Promise((r) => server.close(r)));

    const token = (claims, secret = SECRET, exp = "5m") => new SignJWT(claims).setProtectedHeader({ alg: "HS256" })
      .setIssuer("starter").setAudience("db-firewall-mcp").setExpirationTime(exp).sign(new TextEncoder().encode(secret));
    async function connect(auth) {
      const c = new Client({ name: "test", version: "1" });
      await c.connect(new StreamableHTTPClientTransport(url, { requestInit: { headers: auth ? { authorization: auth } : {} } }));
      return c;
    }

    it("the tenant comes from the verified token", async () => {
      for (const [tenant, body] of [["A", "a-doc"], ["B", "b-secret"]]) {
        const c = await connect(`Bearer ${await token({ tenant_id: tenant })}`);
        try {
          const q = json(await c.callTool({ name: "query", arguments: { sql: "SELECT body FROM docs" } }));
          assert.deepEqual(q.rows, [{ body }]);
        } finally { await c.close(); }
      }
    });

    it("answers only POST: GET (a stream) and DELETE get 405", async () => {
      for (const method of ["GET", "DELETE"]) {
        const r = await fetch(url, { method, headers: { authorization: `Bearer ${await token({ tenant_id: "A" })}`,
                                                       accept: "text/event-stream" } });
        assert.equal(r.status, 405, method);
        await r.body?.cancel();
      }
    });

    it("needs the issuer and the audience", async () => {
      const { startHttp } = await import("../dist/http.js");
      const pool = new pg.Pool({ connectionString: appUrl() });
      try {
        for (const o of [{ issuer: "starter" }, { audience: "db-firewall-mcp" }, {}]) {
          await assert.rejects(startHttp({ pool, schema: S, port: 0, jwtSecret: SECRET, ...o }), /issuer and the audience/);
        }
      } finally { await pool.end(); }
    });

    it("refuses a missing, forged, expired or tenant-less token with 401", async () => {
      const bad = [undefined, `Bearer ${await token({ tenant_id: "A" }, "x".repeat(40))}`,
                   `Bearer ${await token({ tenant_id: "A" }, SECRET, "-1m")}`, `Bearer ${await token({ sub: "u" })}`,
                   `Bearer ${await new SignJWT({ tenant_id: "A" }).setProtectedHeader({ alg: "HS256" })
                     .setIssuer("starter").setAudience("db-firewall-mcp").sign(new TextEncoder().encode(SECRET))}`];  // no exp
      for (const auth of bad) {
        const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json",
          accept: "application/json, text/event-stream", ...(auth ? { authorization: auth } : {}) },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
        assert.equal(r.status, 401, String(auth).slice(0, 30));
      }
    });
  });
});
