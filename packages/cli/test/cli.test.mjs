// Live CLI tests: run dist/cli.js against PostgreSQL. DBFW_PG_URL is an admin
// URL; the tests create schema cli_app and the app role dbfw_cli.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";

const ADMIN_URL = process.env.DBFW_PG_URL;
const DB = ADMIN_URL ? new URL(ADMIN_URL).pathname.slice(1) : "";
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
  const APP = () => ["--url", appUrl(), ...scope];
  const scope = ["--schema", S];
  const failed = (checks) => checks.filter((c) => c.ok === false).map((c) => `${c.table}: ${c.check}`);
  before(async () => {
    await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE; DROP SCHEMA IF EXISTS ${S}_other CASCADE; CREATE SCHEMA ${S};
      DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}')
        THEN CREATE ROLE ${ROLE} LOGIN PASSWORD '${PW}'; END IF; END $$;
      CREATE TABLE ${S}.docs (id serial, tenant_id text);
      INSERT INTO ${S}.docs (tenant_id) VALUES ('A'), ('B');
      CREATE TABLE ${S}.open_t (id int, tenant_id text);
      INSERT INTO ${S}.open_t VALUES (1, 'A'), (2, 'B');
      CREATE TABLE ${S}.feature_flags (id int, tenant_id text);     -- the migration protects it
      GRANT USAGE ON SCHEMA ${S} TO ${ROLE};`);
  });
  after(async () => {
    await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE; DROP SCHEMA IF EXISTS ${S}_other CASCADE;
      DELETE FROM public._firewall_bypass_roles WHERE role_name = '${ROLE}';
      REVOKE ALL ON public._firewall_bypass_roles FROM ${ROLE};`);
  });
  // An isolated change for one test, undone after it.
  async function withChange(apply, undo, fn) { await sql(apply); try { await fn(); } finally { await sql(undo); } }
  const clean = ["--exclude", "late", "--exclude", "open_t", "--exclude", "_firewall_*"];

  it("migrate installs the policies and reports the tables, feature_flags included", async () => {
    const r = await json(["migrate", "--url", ADMIN_URL, ...scope]);
    assert.equal(r.code, 0, r.stderr);
    const t = byTable(r.data.tables);
    assert.ok(t.docs.protected && t.feature_flags.protected);
    await sql(`CREATE TABLE ${S}.late (id int, tenant_id text); INSERT INTO ${S}.late VALUES (1, 'A'), (2, 'B');
      CREATE POLICY open_all ON ${S}.open_t USING (true);
      GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ${S} TO ${ROLE};
      GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${S} TO ${ROLE};`);
  });

  it("scan --strict fails on unprotected tables and says why", async () => {
    const r = await json(["scan", "--url", ADMIN_URL, ...scope, "--strict"]);
    assert.equal(r.code, 1);
    const t = byTable(r.data.tables);
    assert.equal(t.docs.protected, true);
    assert.equal(t.late.rls_enabled, false);
    assert.deepEqual(t.open_t.extra_permissive_policies, ["open_all"]);
    const text = await run(["scan", "--url", ADMIN_URL, ...scope]);
    assert.match(text.stdout, new RegExp(`FAIL\\s+${S}\\.late\\s+\\(permissive; RLS off`));
  });

  it("excluded tables are listed, not skipped silently", async () => {
    const r = await json(["scan", "--url", ADMIN_URL, ...scope, "--exclude", "feature_*"]);
    assert.deepEqual(r.data.excluded, [`${S}.feature_flags`]);
    assert.match((await run(["scan", "--url", ADMIN_URL, ...scope, "--exclude", "feature_[f]*"])).stdout,
                 /Skipped \(excluded\): cli_app\.feature_flags/);
  });

  it("no table found fails (wrong column or schema)", async () => {
    assert.equal((await run(["scan", "--url", ADMIN_URL, ...scope, "--column", "tenantid", "--strict"])).code, 1);
    const v = await json(["verify", ...APP(), "--column", "tenantid", "--tenant", "A"]);
    assert.equal(v.code, 1);
    assert.ok(failed(v.data.checks).includes("-: tables found"));
  });

  it("verify passes as the app role on protected tables, read-only by default", async () => {
    const [{ before }] = await sql(`SELECT last_value AS before FROM ${S}.docs_id_seq`);
    const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
    assert.equal(r.code, 0, failed(r.data.checks).join("; "));
    assert.ok(!r.data.checks.some((c) => c.check === "cross-tenant insert refused"));
    const [{ after }] = await sql(`SELECT last_value AS after FROM ${S}.docs_id_seq`);
    assert.equal(after, before);                                   // nothing written, no sequence used
  });

  it("--write-probe adds the cross-tenant insert check", async () => {
    const r = await json(["verify", ...APP(), "--tenant", "A", ...clean, "--write-probe"]);
    assert.equal(r.code, 0, failed(r.data.checks).join("; "));
    assert.match(r.data.checks.find((c) => c.table === `${S}.docs` && c.check === "cross-tenant insert refused")
      .detail, /RLS/);
  });

  it("an inconclusive probe is not a pass (exit 3)", async () => {
    await withChange(`CREATE FUNCTION ${S}.boom() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no'; END $$;
        CREATE TRIGGER t_boom BEFORE INSERT ON ${S}.docs FOR EACH ROW EXECUTE FUNCTION ${S}.boom();`,
      `DROP TRIGGER t_boom ON ${S}.docs; DROP FUNCTION ${S}.boom();`, async () => {
        const r = await run(["verify", ...APP(), "--tenant", "A", ...clean, "--write-probe"]);
        assert.equal(r.code, 3, r.stdout);
        assert.match(r.stdout, /inconclusive: not a pass/);
      });
  });

  it("verify fails where another tenant's rows are reachable", async () => {
    const r = await json(["verify", ...APP(), "--tenant", "A"]);
    assert.equal(r.code, 1);
    const f = failed(r.data.checks);
    for (const want of [`${S}.late: no tenant sees nothing`, `${S}.late: tenant sees only its rows`,
                        `${S}.open_t: tenant sees only its rows`]) {
      assert.ok(f.includes(want), `${want} not in ${f.join("; ")}`);
    }
  });

  it("a tenant with no rows proves nothing and fails", async () => {
    const r = await json(["verify", ...APP(), "--tenant", "NO_SUCH_TENANT", ...clean]);
    assert.equal(r.code, 1);
    assert.ok(failed(r.data.checks).includes("-: tenant has rows"));
  });

  const blockers = [
    ["a role it can SET ROLE to has BYPASSRLS", "-: role",
     `CREATE ROLE dbfw_cli_bypass NOLOGIN BYPASSRLS; GRANT dbfw_cli_bypass TO ${ROLE};`,
     `REVOKE dbfw_cli_bypass FROM ${ROLE}; DROP ROLE dbfw_cli_bypass;`],
    ["it owns the table", `${S}.docs: role does not own the table`,
     `ALTER TABLE ${S}.docs OWNER TO ${ROLE};`,
     // An owner change merges the role's own grant into the owner entry: grant it back.
     `ALTER TABLE ${S}.docs OWNER TO CURRENT_USER; GRANT SELECT, INSERT ON ${S}.docs TO ${ROLE};`],
    ["it can write the bypass list", "-: cannot write firewall tables",
     `GRANT INSERT ON public._firewall_bypass_roles TO ${ROLE};`,
     `REVOKE INSERT ON public._firewall_bypass_roles FROM ${ROLE};`],
    ["it has TRUNCATE", `${S}.docs: no TRUNCATE`,
     `GRANT TRUNCATE ON ${S}.docs TO ${ROLE};`, `REVOKE TRUNCATE ON ${S}.docs FROM ${ROLE};`],
    ["a view runs as a superuser", "-: no RLS-bypassing views or functions",
     `CREATE VIEW ${S}.v_docs AS SELECT * FROM ${S}.docs; GRANT SELECT ON ${S}.v_docs TO ${ROLE};`,
     `DROP VIEW ${S}.v_docs;`],
    ["a materialized view", "-: no RLS-bypassing views or functions",
     `CREATE MATERIALIZED VIEW ${S}.m_docs AS SELECT * FROM ${S}.docs; GRANT SELECT ON ${S}.m_docs TO ${ROLE};`,
     `DROP MATERIALIZED VIEW ${S}.m_docs;`],
    ["a SECURITY DEFINER function", "-: no RLS-bypassing views or functions",
     `CREATE FUNCTION ${S}.all_docs() RETURNS SETOF ${S}.docs LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM ${S}.docs';
      GRANT EXECUTE ON FUNCTION ${S}.all_docs() TO ${ROLE};`, `DROP FUNCTION ${S}.all_docs();`],
    ["a tenant table in another schema", "-: no tenant tables in other schemas",
     `CREATE SCHEMA ${S}_other; CREATE TABLE ${S}_other.docs (id int, tenant_id text);
      GRANT USAGE ON SCHEMA ${S}_other TO ${ROLE}; GRANT SELECT ON ${S}_other.docs TO ${ROLE};`,
     `DROP SCHEMA ${S}_other CASCADE;`],
    // Round 2: ownership of public / the firewall objects, column grants, view chains, other schemas.
    ["it owns the database (so schema public)", "-: does not own firewall objects",
     `ALTER DATABASE ${DB} OWNER TO ${ROLE};`, `ALTER DATABASE ${DB} OWNER TO CURRENT_USER;`],
    ["it owns a firewall function", "-: does not own firewall objects",
     `ALTER FUNCTION public._firewall_is_bypass_role(text) OWNER TO ${ROLE};`,
     `ALTER FUNCTION public._firewall_is_bypass_role(text) OWNER TO CURRENT_USER;`],
    ["it has a column grant on the bypass list", "-: cannot write firewall tables",
     `GRANT INSERT (role_name) ON public._firewall_bypass_roles TO ${ROLE};`,
     `REVOKE INSERT (role_name) ON public._firewall_bypass_roles FROM ${ROLE};`],
    ["a definer view is readable through a column grant", "-: no RLS-bypassing views or functions",
     `CREATE VIEW ${S}.col_v AS SELECT * FROM ${S}.docs; GRANT SELECT (id) ON ${S}.col_v TO ${ROLE};`,
     `DROP VIEW ${S}.col_v;`],
    ["a view on a view", "-: no RLS-bypassing views or functions",
     `CREATE VIEW ${S}.inner_v AS SELECT * FROM ${S}.docs; CREATE VIEW ${S}.outer_v AS SELECT * FROM ${S}.inner_v;
      GRANT SELECT ON ${S}.outer_v TO ${ROLE};`, `DROP VIEW ${S}.outer_v; DROP VIEW ${S}.inner_v;`],
    ["a materialized view over an invoker view", "-: no RLS-bypassing views or functions",
     `CREATE VIEW ${S}.base_v WITH (security_invoker = true) AS SELECT * FROM ${S}.docs;
      CREATE MATERIALIZED VIEW ${S}.mv AS SELECT * FROM ${S}.base_v; GRANT SELECT ON ${S}.mv TO ${ROLE};`,
     `DROP MATERIALIZED VIEW ${S}.mv; DROP VIEW ${S}.base_v;`],
    ["a view in another schema", "-: no RLS-bypassing views or functions",
     `CREATE SCHEMA ${S}_other; CREATE VIEW ${S}_other.all_docs AS SELECT * FROM ${S}.docs;
      GRANT USAGE ON SCHEMA ${S}_other TO ${ROLE}; GRANT SELECT ON ${S}_other.all_docs TO ${ROLE};`,
     `DROP SCHEMA ${S}_other CASCADE;`],
    ["a SECURITY DEFINER function in another schema", "-: no RLS-bypassing views or functions",
     `CREATE SCHEMA ${S}_other; GRANT USAGE ON SCHEMA ${S}_other TO ${ROLE};
      CREATE FUNCTION ${S}_other.dump() RETURNS SETOF ${S}.docs LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM ${S}.docs';`,
     `DROP SCHEMA ${S}_other CASCADE;`],
    ["a column grant on a tenant table in another schema", "-: no tenant tables in other schemas",
     `CREATE SCHEMA ${S}_other; CREATE TABLE ${S}_other.copy (id int, tenant_id text);
      GRANT USAGE ON SCHEMA ${S}_other TO ${ROLE}; GRANT SELECT (id) ON ${S}_other.copy TO ${ROLE};`,
     `DROP SCHEMA ${S}_other CASCADE;`],
    // Round 3: SET-only roles, unreachable unprotected tables, matviews over functions,
    // extension members, foreign tables, LEAKPROOF functions.
    ["a SET-only role can write the bypass list", "-: cannot write firewall tables",
     `CREATE ROLE dbfw_cli_w NOLOGIN; GRANT INSERT ON public._firewall_bypass_roles TO dbfw_cli_w;
      GRANT dbfw_cli_w TO ${ROLE} WITH INHERIT FALSE;`,
     `REVOKE dbfw_cli_w FROM ${ROLE}; REVOKE ALL ON public._firewall_bypass_roles FROM dbfw_cli_w; DROP ROLE dbfw_cli_w;`],
    ["an unprotected table it has no grant on", `${S}.ledger: policies`,
     `CREATE TABLE ${S}.ledger (id int, tenant_id text);`, `DROP TABLE ${S}.ledger;`],
    ["a materialized view over a function", "-: no RLS-bypassing views or functions",
     `CREATE FUNCTION ${S}.all_ids() RETURNS TABLE (id int) LANGUAGE sql STABLE AS 'SELECT id FROM ${S}.docs';
      CREATE MATERIALIZED VIEW ${S}.ids_mv AS SELECT * FROM ${S}.all_ids(); GRANT SELECT ON ${S}.ids_mv TO ${ROLE};`,
     `DROP MATERIALIZED VIEW ${S}.ids_mv; DROP FUNCTION ${S}.all_ids();`],
    ["a SECURITY DEFINER function attached to an extension", "-: no RLS-bypassing views or functions",
     `CREATE FUNCTION ${S}.export_docs() RETURNS SETOF ${S}.docs LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM ${S}.docs';
      ALTER EXTENSION plpgsql ADD FUNCTION ${S}.export_docs();`,
     `ALTER EXTENSION plpgsql DROP FUNCTION ${S}.export_docs(); DROP FUNCTION ${S}.export_docs();`],
    ["a foreign table", "-: no RLS-bypassing views or functions",
     `CREATE FOREIGN DATA WRAPPER dbfw_cli_fdw; CREATE SERVER dbfw_cli_srv FOREIGN DATA WRAPPER dbfw_cli_fdw;
      CREATE FOREIGN TABLE ${S}.docs_remote (id int, tenant_id text) SERVER dbfw_cli_srv;
      GRANT SELECT ON ${S}.docs_remote TO ${ROLE};`,
     `DROP FOREIGN TABLE ${S}.docs_remote; DROP SERVER dbfw_cli_srv; DROP FOREIGN DATA WRAPPER dbfw_cli_fdw;`],
    ["a LEAKPROOF function", "-: no RLS-bypassing views or functions",
     `CREATE FUNCTION ${S}.peek(text) RETURNS boolean LANGUAGE sql LEAKPROOF AS 'SELECT true';`,
     `DROP FUNCTION ${S}.peek(text);`],
  ];
  for (const [why, check, apply, undo] of blockers) {
    it(`verify fails when ${why}`, async () => {
      await withChange(apply, undo, async () => {
        const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
        assert.equal(r.code, 1, `exit ${r.code}`);
        assert.ok(failed(r.data.checks).includes(check), failed(r.data.checks).join("; "));
      });
    });
  }

  it("a security_invoker view is fine (RLS applies through it)", async () => {
    await withChange(`CREATE VIEW ${S}.vi_docs WITH (security_invoker = true) AS SELECT * FROM ${S}.docs;
                      GRANT SELECT ON ${S}.vi_docs TO ${ROLE};`, `DROP VIEW ${S}.vi_docs;`, async () => {
      const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      assert.equal(r.code, 0, failed(r.data.checks).join("; "));
    });
  });

  it("security_invoker spelled 1 is an invoker view", async () => {
    await withChange(`CREATE VIEW ${S}.vi1 WITH (security_invoker = 1) AS SELECT * FROM ${S}.docs;
                      GRANT SELECT ON ${S}.vi1 TO ${ROLE};`, `DROP VIEW ${S}.vi1;`, async () => {
      const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      assert.equal(r.code, 0, failed(r.data.checks).join("; "));
    });
  });

  it("partitions read through their parent pass", async () => {
    await withChange(`CREATE TABLE ${S}.parts (id int, tenant_id text) PARTITION BY LIST (tenant_id);
        CREATE TABLE ${S}.parts_a PARTITION OF ${S}.parts FOR VALUES IN ('A');
        CREATE TABLE ${S}.parts_b PARTITION OF ${S}.parts FOR VALUES IN ('B');
        INSERT INTO ${S}.parts VALUES (1, 'A'), (2, 'B'); GRANT SELECT ON ${S}.parts TO ${ROLE};`,
      `DROP TABLE ${S}.parts;`, async () => {
        assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope])).code, 0);
        const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
        assert.equal(r.code, 0, failed(r.data.checks).join("; "));
        const parts = r.data.checks.filter((c) => c.table === `${S}.parts_a`);
        assert.ok(parts.find((c) => c.check === "policies").ok);          // reference taken from the root
        assert.match(parts.find((c) => c.check === "row checks").detail, /no direct reads/);
      });
  });

  it("verify as a superuser fails the role check", async () => {
    const rows = await sql("SELECT rolsuper FROM pg_roles WHERE rolname = current_user");
    if (!rows[0].rolsuper) return;
    const r = await json(["verify", "--url", ADMIN_URL, ...scope, "--tenant", "A", ...clean]);
    assert.equal(r.code, 1);
    assert.match(r.data.checks[0].detail, /superuser/);
  });

  it("scan flags a policy altered to restrict nothing", async () => {
    const [{ stem }] = await sql(`SELECT 'fw_' || left(md5('${S}.docs'), 12) AS stem`);
    await sql(`ALTER POLICY ${stem}_sel ON ${S}.docs USING (current_setting('app.current_tenant', true) IS NOT NULL)`);
    const r = await json(["scan", "--url", ADMIN_URL, ...scope]);
    assert.deepEqual(byTable(r.data.tables).docs.altered_policies, [`${stem}_sel`]);
    assert.equal(byTable(r.data.tables).docs.protected, false);
  });

  it("migrate --mode restrictive accepts the app's own policies", async () => {
    const r = await json(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive"]);
    assert.equal(r.code, 0, r.stderr);
    const t = byTable(r.data.tables);
    assert.equal(t.docs.protected, true);                        // the altered policy was re-created
    assert.equal(t.open_t.protected, true);                      // open_all now ANDs with the tenant
    assert.equal(t.open_t.policy_mode, "restrictive");
    const v = await json(["verify", ...APP(), "--tenant", "A", "--exclude", "_firewall_*"]);
    assert.equal(v.code, 0, failed(v.data.checks).join("; "));
  });

  it("an invalid mode exits 2", async () => {
    assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "sideways"])).code, 2);
  });
});
