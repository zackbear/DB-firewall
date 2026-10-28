// Live CLI tests: run dist/cli.js against PostgreSQL. DBFW_PG_URL is an admin
// URL; the tests create schema cli_app and the app role dbfw_cli.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";

const ADMIN_URL = process.env.DBFW_PG_URL;
if (!ADMIN_URL && process.env.DBFW_REQUIRE_LIVE) throw new Error("DBFW_REQUIRE_LIVE set but DBFW_PG_URL is not");
const live = { skip: ADMIN_URL ? false : "DBFW_PG_URL not set" };
const S = "cli_app", ROLE = "dbfw_cli", PW = "DbfwCli_2026x";
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

function appUrl() { const u = new URL(ADMIN_URL); u.username = ROLE; u.password = PW; return u.toString(); }
function run(args, env = {}) {
  return new Promise((resolve) => execFile("node", [CLI, ...args],
    { env: { ...process.env, DATABASE_URL: "", ...env } },
    (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr })));
}
const json = async (args) => { const r = await run([...args, "--json"]); return { ...r, data: JSON.parse(r.stdout) }; };
async function sql(text) {
  const c = new pg.Client({ connectionString: ADMIN_URL }); await c.connect();
  try { return (await c.query(text)).rows; } finally { await c.end(); }
}
const byTable = (rows) => Object.fromEntries(rows.map((t) => [t.table, t]));

describe("usage", () => {
  it("no command or no URL exits 2", async () => {
    assert.equal((await run([])).code, 2);
    assert.equal((await run(["scan"])).code, 2);
  });
  it("ships the repository's migration unchanged", () => {
    assert.equal(readFileSync(new URL("../sql/001_postgresql.sql", import.meta.url), "utf8"),
                 readFileSync(new URL("../../../migrations/001_postgresql.sql", import.meta.url), "utf8"));
  });
});

describe("migrate, scan, verify", live, () => {
  before(async () => {
    await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE; CREATE SCHEMA ${S};
      DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}')
        THEN CREATE ROLE ${ROLE} LOGIN PASSWORD '${PW}'; END IF; END $$;
      CREATE TABLE ${S}.docs (id int, tenant_id text);
      INSERT INTO ${S}.docs VALUES (1, 'A'), (2, 'B');
      CREATE TABLE ${S}.open_t (id int, tenant_id text);
      INSERT INTO ${S}.open_t VALUES (1, 'A'), (2, 'B');
      GRANT USAGE ON SCHEMA ${S} TO ${ROLE};`);
  });
  after(async () => { await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE`); });
  const scope = ["--schema", S];

  it("migrate installs the policies and reports the tables", async () => {
    const r = await json(["migrate", "--url", ADMIN_URL, ...scope]);
    assert.equal(r.code, 0, r.stderr);
    assert.ok(byTable(r.data.tables).docs.protected);
    // After the migration: a table with no RLS, and a permissive policy that widens open_t.
    await sql(`CREATE TABLE ${S}.late (id int, tenant_id text); INSERT INTO ${S}.late VALUES (1, 'A'), (2, 'B');
      CREATE POLICY open_all ON ${S}.open_t USING (true);
      GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ${S} TO ${ROLE};`);
  });

  it("scan --strict fails on unprotected tables and says why", async () => {
    const r = await json(["scan", "--url", ADMIN_URL, ...scope, "--strict"]);
    assert.equal(r.code, 1);
    const t = byTable(r.data);
    assert.equal(t.docs.protected, true);
    assert.equal(t.late.rls_enabled, false);
    assert.deepEqual(t.open_t.extra_permissive_policies, ["open_all"]);
    const text = await run(["scan", "--url", ADMIN_URL, ...scope]);
    assert.equal(text.code, 0);
    assert.match(text.stdout, /FAIL\s+late\s+\(permissive; RLS off/);
  });

  it("verify as the app role passes on a protected table", async () => {
    const r = await json(["verify", "--url", appUrl(), ...scope, "--tenant", "A",
                          "--exclude", "late", "--exclude", "open_t"]);
    assert.equal(r.code, 0, JSON.stringify(r.data.checks, null, 1));
    const checks = r.data.checks.filter((c) => c.table === "docs");
    assert.deepEqual(checks.map((c) => c.ok), [true, true, true, true]);
    assert.match(checks.find((c) => c.check === "cross-tenant insert refused").detail, /RLS/);
  });

  it("verify fails where another tenant's rows are reachable", async () => {
    const r = await json(["verify", "--url", appUrl(), ...scope, "--tenant", "A"]);
    assert.equal(r.code, 1);
    const fail = r.data.checks.filter((c) => c.ok === false).map((c) => `${c.table}: ${c.check}`);
    assert.ok(fail.includes("late: no tenant sees nothing"), fail.join("; "));
    assert.ok(fail.includes("late: tenant sees only its rows"));
    assert.ok(fail.includes("open_t: tenant sees only its rows"));      // open_all widens it
    assert.ok(fail.includes("late: cross-tenant insert refused"));
  });

  it("verify as a superuser fails the role check", async () => {
    const { rows } = { rows: await sql("SELECT rolsuper FROM pg_roles WHERE rolname = current_user") };
    if (!rows[0].rolsuper) return;
    const r = await json(["verify", "--url", ADMIN_URL, ...scope, "--tenant", "A", "--exclude", "late",
                          "--exclude", "open_t"]);
    assert.equal(r.code, 1);
    assert.match(r.data.checks[0].detail, /superuser/);
  });

  it("scan flags a policy altered to restrict nothing", async () => {
    const [{ stem }] = await sql(`SELECT 'fw_' || left(md5('${S}.docs'), 12) AS stem`);
    await sql(`ALTER POLICY ${stem}_sel ON ${S}.docs USING (current_setting('app.current_tenant', true) IS NOT NULL)`);
    const r = await json(["scan", "--url", ADMIN_URL, ...scope]);
    assert.deepEqual(byTable(r.data).docs.altered_policies, [`${stem}_sel`]);
    assert.equal(byTable(r.data).docs.protected, false);
  });

  it("migrate --mode restrictive accepts the app's own policies", async () => {
    const r = await json(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive"]);
    assert.equal(r.code, 0, r.stderr);
    const t = byTable(r.data.tables);
    assert.equal(t.docs.protected, true);                        // the altered policy was re-created
    assert.equal(t.open_t.protected, true);                      // open_all now ANDs with the tenant
    assert.equal(t.open_t.policy_mode, "restrictive");
    const v = await json(["verify", "--url", appUrl(), ...scope, "--tenant", "A"]);
    assert.equal(v.code, 0, JSON.stringify(v.data.checks.filter((c) => c.ok === false)));
  });

  it("an invalid mode exits 2", async () => {
    assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "sideways"])).code, 2);
  });
});
