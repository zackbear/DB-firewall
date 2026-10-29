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
// The app's signing key: migrate installs it, verify signs with it.
const KEY = "5a".repeat(32);
process.env.DB_FIREWALL_TENANT_KEY = KEY;

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
  it("globs match as Python's fnmatch: [!a] negates, [^a] is a literal ^ or a", async () => {
    const { globMatch } = await import("../dist/scan.js");
    assert.deepEqual(["app.b", "app.a", "app.^"].map((n) => globMatch("app.[^a]", n)), [false, true, true]);
    assert.deepEqual(["app.b", "app.a"].map((n) => globMatch("app.[!a]", n)), [true, false]);
    assert.equal(globMatch("app.f(*)", "app.f(text, integer)"), true);
    // A leading "]" is literal, also after "!".
    assert.deepEqual(["]", "a", "b"].map((n) => globMatch("[]a]", n)), [true, true, false]);
    assert.deepEqual(["]", "a", "b"].map((n) => globMatch("[!]a]", n)), [false, false, true]);
  });
  it("ships the repository's migration unchanged", () => {
    assert.equal(readFileSync(new URL("../sql/001_postgresql.sql", import.meta.url), "utf8"),
                 readFileSync(new URL("../../../migrations/001_postgresql.sql", import.meta.url), "utf8"));
  });
  it("a file check passes only on ok = true; an error fails it, and an info line never fails", async () => {
    const { fileCheck } = await import("../dist/verify.js");
    const client = (row) => ({ query: async () => { if (row instanceof Error) throw row; return { rows: [row] }; } });
    const c = { name: "x", info: false, sql: "SELECT 1" };
    assert.equal((await fileCheck(client({ ok: true, detail: "d" }), c)).ok, true);
    for (const row of [{ ok: null, detail: "d" }, { ok: false, detail: "d" }, { ok: "t", detail: "d" }, new Error("boom")]) {
      assert.equal((await fileCheck(client(row), c)).ok, false, JSON.stringify(row));
    }
    assert.equal((await fileCheck(client(new Error("boom")), { ...c, info: true })).ok, true);
  });
  it("ships the repository's shared checks unchanged, and they parse", async () => {
    assert.equal(readFileSync(new URL("../sql/checks_postgresql.sql", import.meta.url), "utf8"),
                 readFileSync(new URL("../../../checks/postgresql.sql", import.meta.url), "utf8"));
    const { CHECKS, parseChecks } = await import("../dist/checks.js");
    const c = CHECKS();
    assert.equal(c.excluded[0], "_firewall_*");
    assert.ok(c.checks.some((x) => x.name === "role") && c.queries.strict_readable);
    assert.throws(() => parseChecks("-- @qery x\nSELECT 1"), /unknown line/);
  });
});

describe("migrate, scan, verify", live, () => {
  const APP = () => ["--url", appUrl(), ...scope];
  const scope = ["--schema", S];
  const failed = (checks) => checks.filter((c) => c.ok === false).map((c) => `${c.table}: ${c.check}`);
  let major = 0;
  before(async () => {
    major = Math.floor(Number((await sql("SHOW server_version_num"))[0].server_version_num) / 10000);
    await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE; DROP SCHEMA IF EXISTS ${S}_other CASCADE; CREATE SCHEMA ${S};
      DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}')
        THEN CREATE ROLE ${ROLE} LOGIN PASSWORD '${PW}'; END IF; END $$;
      CREATE TABLE ${S}.docs (id serial, tenant_id text);
      INSERT INTO ${S}.docs (tenant_id) VALUES ('A'), ('B');
      REVOKE CREATE ON SCHEMA public FROM PUBLIC;          -- PostgreSQL 14 grants it
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
    assert.match(text.stdout, new RegExp(`FAIL\\s+${S}\\.late\\s+\\(permissive, no policies; RLS off`));
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

  // The ways to reach another tenant's rows, and safe patterns that must pass,
  // are in the attack corpus (tests/attacks/postgresql.sql, test/attacks.test.mjs).

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

  it("plain context: scan and verify fail, scan --context plain accepts it", async () => {
    assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--context", "plain"])).code, 0);
    try {
      const r = await json(["scan", "--url", ADMIN_URL, ...scope]);
      assert.equal(byTable(r.data.tables).docs.protected, false);
      assert.equal(byTable(r.data.tables).docs.tenant_context, "plain");
      assert.match((await run(["scan", "--url", ADMIN_URL, ...scope])).stdout, /plain tenant context/);
      const p = await json(["scan", "--url", ADMIN_URL, ...scope, "--context", "plain"]);
      assert.equal(byTable(p.data.tables).docs.protected, true);
      const v = await json(["verify", ...APP(), "--tenant", "A", "--exclude", "_firewall_*"]);
      assert.equal(v.code, 1);
      assert.ok(failed(v.data.checks).includes(`${S}.docs: unsigned tenant sees nothing`));
    } finally {
      assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive"])).code, 0);
    }
  });

  it("verify needs the key, and a wrong key proves nothing", async () => {
    assert.equal((await run(["verify", ...APP(), "--tenant", "A"], { DB_FIREWALL_TENANT_KEY: "" })).code, 2);
    assert.equal((await run(["verify", ...APP(), "--tenant", "A"], { DB_FIREWALL_TENANT_KEY: "abcd" })).code, 2);
    const r = await run(["verify", ...APP(), "--tenant", "A", "--exclude", "_firewall_*", "--json"],
                        { DB_FIREWALL_TENANT_KEY: "6b".repeat(32) });
    const checks = JSON.parse(r.stdout).checks;
    assert.equal(r.code, 1);
    assert.match(checks.find((c) => c.check === "tenant has rows").detail, /db-firewall key/);
  });

  it("migrate refuses _firewall_* objects another role planted", async () => {
    await withChange(`GRANT CREATE ON SCHEMA public TO ${ROLE}; SET ROLE ${ROLE};
        CREATE TABLE public._firewall_planted (k bytea); RESET ROLE;`,
      `DROP TABLE public._firewall_planted; REVOKE CREATE ON SCHEMA public FROM ${ROLE};`, async () => {
        const r = await run(["migrate", "--url", ADMIN_URL, ...scope]);
        assert.equal(r.code, 2);
        assert.match(r.stderr, /planted/);
      });
  });

  it("scan reports a policy bound to a planted operator", async () => {
    const [{ stem }] = await sql(`SELECT 'fw_' || left(md5('${S}.vdocs'), 12) AS stem`);
    await withChange(`CREATE TABLE ${S}.vdocs (id int, tenant_id varchar(36));
        CREATE FUNCTION public.rv_any(varchar, text) RETURNS boolean LANGUAGE sql AS 'SELECT true';
        CREATE OPERATOR public.= (LEFTARG = varchar, RIGHTARG = text, FUNCTION = public.rv_any);`,
      `DROP TABLE ${S}.vdocs; DROP OPERATOR public.= (varchar, text); DROP FUNCTION public.rv_any(varchar, text);`,
      async () => {
        assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive"])).code, 0);
        assert.equal(byTable((await json(["scan", "--url", ADMIN_URL, ...scope])).data.tables).vdocs.protected, true);
        await sql(`SET search_path = public; ALTER POLICY ${stem}_sel ON ${S}.vdocs USING
          (tenant_id = (SELECT public._firewall_tenant()) OR (SELECT public._firewall_is_bypass_role(current_user::text)))`);
        const t = byTable((await json(["scan", "--url", ADMIN_URL, ...scope])).data.tables).vdocs;
        assert.equal(t.protected, false);
        assert.ok(t.altered_policies.includes(`${stem}_sel`));
      });
  });

  it("the info lines report signals and role defaults, without failing", async () => {
    await withChange(`ALTER ROLE ${ROLE} SET statement_timeout = '9s';`, `ALTER ROLE ${ROLE} RESET statement_timeout;`,
      async () => {
        const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
        assert.equal(r.code, 0, failed(r.data.checks).join("; "));
        const info = Object.fromEntries(r.data.checks.filter((c) => c.check.endsWith("(info)")).map((c) => [c.check, c]));
        assert.match(info["signals other sessions (info)"].detail, /^yes/);
        assert.match(info["role defaults (info)"].detail, /statement_timeout=9s/);
      });
  });

  it("migrate --harden-signals revokes backend signals (superuser), and verify sees it", async () => {
    const restore = "GRANT EXECUTE ON FUNCTION pg_catalog.pg_terminate_backend(integer, bigint), " +
                    "pg_catalog.pg_cancel_backend(integer) TO PUBLIC";
    try {
      assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive", "--harden-signals"])).code, 0);
      const [{ can }] = await sql(`SELECT has_function_privilege('${ROLE}', 'pg_catalog.pg_terminate_backend(integer, bigint)', 'EXECUTE') AS can`);
      assert.equal(can, false);
      const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      assert.match(r.data.checks.find((c) => c.check === "signals other sessions (info)").detail, /^no/);
    } finally {
      await sql(restore);
    }
  });

  // What migrate --harden revokes from PUBLIC besides grants, and how to give it back.
  const RESTORE = "GRANT EXECUTE ON FUNCTION pg_catalog.pg_terminate_backend(integer, bigint), " +
    "pg_catalog.pg_cancel_backend(integer), pg_catalog.pg_stat_get_activity(integer), " +
    "pg_catalog.pg_stat_get_backend_activity(integer) TO PUBLIC; GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC";

  describe("verify --strict (allowlist)", () => {
    // The excluded tables are readable but outside the scan: allowlist them.
    const strict = ["--strict", "--allow-global", `${S}.late`, "--allow-global", `${S}.open_t`];
    const NO_ACTIVITY = "REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC; REVOKE EXECUTE ON FUNCTION " +
      "pg_catalog.pg_stat_get_activity(integer), pg_catalog.pg_stat_get_backend_activity(integer) FROM PUBLIC";
    const verifyStrict = (...more) => json(["verify", ...APP(), "--tenant", "A", ...clean, ...strict, ...more]);
    const failedWith = async (check, pattern, ...more) => {
      const r = await verifyStrict(...more);
      assert.equal(r.code, 1);
      const c = r.data.checks.find((x) => x.check === check);
      assert.equal(c.ok, false, check);
      assert.match(c.detail, pattern);
    };
    before(() => sql(NO_ACTIVITY));
    after(() => sql(RESTORE));
    it("passes when everything readable is protected tenant data", async () => {
      const r = await verifyStrict();
      assert.equal(r.code, 0, failed(r.data.checks).join("; "));
      assert.ok(r.data.checks.some((c) => c.check === "strict: only tenant data readable" && c.ok));
    });
    it("fails while the role can read other sessions' SQL (plain verify: an info line)", async () => {
      await withChange("GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC", NO_ACTIVITY, async () => {
        await failedWith("strict: cannot read other sessions' SQL", /^yes/);
        const plain = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
        assert.equal(plain.code, 0, failed(plain.data.checks).join("; "));
        assert.match(plain.data.checks.find((c) => c.check === "reads other sessions' SQL (info)").detail, /^yes/);
      });
    });
    it("a readable table without the tenant column fails until allowlisted; invoker views over it too", async (t) => {
      if (major < 15) return t.skip("security_invoker needs PostgreSQL 15");
      await withChange(`CREATE TABLE ${S}.settings (k text); GRANT SELECT ON ${S}.settings TO ${ROLE};
          CREATE VIEW ${S}.my_docs WITH (security_invoker = true) AS SELECT * FROM ${S}.docs;
          CREATE VIEW ${S}.all_settings WITH (security_invoker = true) AS SELECT * FROM ${S}.settings;
          GRANT SELECT ON ${S}.my_docs, ${S}.all_settings TO ${ROLE};`,
        `DROP VIEW ${S}.my_docs, ${S}.all_settings; DROP TABLE ${S}.settings;`, async () => {
          const r = await verifyStrict();
          assert.equal(r.code, 1);
          const d = r.data.checks.find((c) => c.check === "strict: only tenant data readable").detail;
          assert.match(d, new RegExp(`${S}\\.all_settings, ${S}\\.settings`));
          assert.doesNotMatch(d, /my_docs/);                            // an invoker view over protected data
          const ok = await verifyStrict("--allow-global", `${S}.settings`);
          assert.equal(ok.code, 0, failed(ok.data.checks).join("; "));
        });
    });
    it("a SECURITY DEFINER function fails until allowlisted by its signature (in both checks)", async () => {
      await withChange(`CREATE FUNCTION ${S}.now_utc() RETURNS timestamptz LANGUAGE sql SECURITY DEFINER AS 'SELECT now()';
          CREATE TABLE ${S}.now_utc (k text); GRANT SELECT ON ${S}.now_utc TO ${ROLE};`,
        `DROP FUNCTION ${S}.now_utc(); DROP TABLE ${S}.now_utc;`, async () => {
          const r = await verifyStrict("--allow-global", `${S}.now_utc`);     // the table only
          assert.ok(failed(r.data.checks).includes("-: strict: no SECURITY DEFINER functions"));
          assert.ok(failed(r.data.checks).includes("-: no RLS-bypassing views or functions"));
          const ok = await verifyStrict("--allow-global", `${S}.now_utc`, "--allow-global", `${S}.now_utc()`);
          assert.equal(ok.code, 0, failed(ok.data.checks).join("; "));
        });
    });
    it("--allow-query-text accepts other sessions' SQL (an info line)", async () => {
      await withChange("GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC", NO_ACTIVITY, async () => {
        const r = await verifyStrict("--allow-query-text");
        assert.equal(r.code, 0, failed(r.data.checks).join("; "));
        assert.ok(r.data.checks.some((c) => c.check === "reads other sessions' SQL (info)"));
      });
    });
    it("--allow-global without --strict exits 2", async () => {
      assert.equal((await run(["verify", ...APP(), "--tenant", "A", "--allow-global", `${S}.x`])).code, 2);
    });
  });

  it("migrate --harden --app-role removes what verify fails on, by any grantor and in default privileges", async () => {
    await sql(`CREATE TABLE ${S}.notes (n text); GRANT SELECT, TRIGGER, TRUNCATE ON ${S}.notes TO ${ROLE};
               GRANT CREATE ON SCHEMA ${S} TO ${ROLE}; GRANT CREATE ON DATABASE ${DB} TO ${ROLE};
               CREATE ROLE dbfw_cli_mid; GRANT USAGE ON SCHEMA ${S} TO dbfw_cli_mid;
               GRANT TRIGGER ON ${S}.notes TO dbfw_cli_mid WITH GRANT OPTION;
               SET ROLE dbfw_cli_mid; GRANT TRIGGER ON ${S}.notes TO ${ROLE}; RESET ROLE;
               ALTER DEFAULT PRIVILEGES IN SCHEMA ${S} GRANT ALL ON TABLES TO ${ROLE};`);
    try {
      const before = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      for (const c of ["-: cannot create in any schema", "-: cannot create triggers"]) {
        assert.ok(failed(before.data.checks).includes(c), c);
      }
      const r = await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive", "--harden", "--app-role", ROLE]);
      assert.equal(r.code, 0, r.stderr);
      await sql(`CREATE TABLE ${S}.later (n text)`);              // after harden: default privileges
      const after = await json(["verify", ...APP(), "--tenant", "A", ...clean, "--exclude", "later"]);
      assert.equal(after.code, 0, failed(after.data.checks).join("; "));
      const [p] = await sql(`SELECT has_table_privilege('${ROLE}', '${S}.notes', 'SELECT') AS sel,
                                    has_table_privilege('${ROLE}', '${S}.notes', 'TRIGGER, TRUNCATE') AS notes,
                                    has_table_privilege('${ROLE}', '${S}.later', 'TRIGGER, TRUNCATE') AS later,
                                    has_table_privilege('${ROLE}', 'pg_catalog.pg_stat_activity', 'SELECT') AS activity`);
      assert.deepEqual({ ...p }, { sel: true, notes: false, later: false, activity: false });
    } finally {
      await sql(`DROP TABLE ${S}.notes, ${S}.later; REVOKE CREATE ON DATABASE ${DB} FROM ${ROLE};
                 ALTER DEFAULT PRIVILEGES IN SCHEMA ${S} REVOKE ALL ON TABLES FROM ${ROLE};
                 DROP OWNED BY dbfw_cli_mid; DROP ROLE dbfw_cli_mid; ${RESTORE}`);
    }
  });

  it("an app session's temporary table does not fail verify", async () => {
    const held = new pg.Client({ connectionString: appUrl() }); await held.connect();
    try {
      await held.query("CREATE TEMP TABLE scratch (x int)");
      const r = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      assert.equal(r.code, 0, failed(r.data.checks).join("; "));
    } finally { await held.end(); }
  });

  it("migrate --harden refuses when the app role owns a domain, and verify fails on it", async () => {
    await withChange(`CREATE DOMAIN ${S}.sec AS text; ALTER DOMAIN ${S}.sec OWNER TO ${ROLE}`, `DROP DOMAIN ${S}.sec`, async () => {
      const v = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      assert.ok(failed(v.data.checks).includes("-: owns no database objects"));
      const r = await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive", "--harden", "--app-role", ROLE]);
      assert.equal(r.code, 2);
      assert.match(r.stderr, new RegExp(`owner of type ${S}.sec`));
    });
  });

  it("migrate --harden refuses when the app role owns a schema, and verify fails on it", async () => {
    await withChange(`CREATE SCHEMA ${S}_own AUTHORIZATION ${ROLE}`, `DROP SCHEMA ${S}_own`, async () => {
      const v = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
      assert.ok(failed(v.data.checks).includes("-: cannot create in any schema"));
      const r = await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive", "--harden", "--app-role", ROLE]);
      assert.equal(r.code, 2);
      assert.match(r.stderr, new RegExp(`owner of schema ${S}_own`));
    });
  });

  it("migrate --ddl-guard protects a new table at once, refuses weakening one, and verify reports it", async () => {
    const drop = "DROP EVENT TRIGGER IF EXISTS _firewall_ddl_guard; DROP EVENT TRIGGER IF EXISTS _firewall_ddl_drop_guard";
    try {
      const m = await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "restrictive", "--ddl-guard"]);
      assert.equal(m.code, 0, m.stderr);
      await sql(`CREATE TABLE ${S}.guarded (id int, tenant_id text)`);
      const t = byTable((await json(["scan", "--url", ADMIN_URL, ...scope])).data.tables);
      assert.ok(t.guarded.protected, JSON.stringify(t.guarded));
      await assert.rejects(sql(`ALTER TABLE ${S}.guarded DISABLE ROW LEVEL SECURITY`), /DB Firewall/);
      const [{ stem }] = await sql(`SELECT 'fw_' || left(md5('${S}.guarded'), 12) AS stem`);
      await assert.rejects(sql(`DROP POLICY ${stem}_sel ON ${S}.guarded`), /DB Firewall/);
      const v = await json(["verify", ...APP(), "--tenant", "A", ...clean, "--exclude", "guarded"]);
      assert.match(v.data.checks.find((c) => c.check === "DDL guard (info)").detail, /^on/);
    } finally {
      await sql(`${drop}; DROP TABLE IF EXISTS ${S}.guarded`);
    }
    const v = await json(["verify", ...APP(), "--tenant", "A", ...clean]);
    assert.match(v.data.checks.find((c) => c.check === "DDL guard (info)").detail, /^off/);
  });

  it("key prints the database's key", async () => {
    const r = await run(["key", "--url", ADMIN_URL]);
    assert.equal(r.code, 0);
    assert.equal(r.stdout.trim(), KEY);
  });

  it("an invalid mode exits 2", async () => {
    assert.equal((await run(["migrate", "--url", ADMIN_URL, ...scope, "--mode", "sideways"])).code, 2);
  });
});
