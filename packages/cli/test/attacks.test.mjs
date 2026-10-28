// The attack corpus (tests/attacks/postgresql.sql): every known way to reach
// another tenant's rows. For each case, verify must fail the named check, and
// the leak query, when there is one, must show the other tenant's data (so
// the attack is real on this server version). Safe patterns must pass.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import pg from "pg";
import { sign } from "../dist/key.js";

const ADMIN_URL = process.env.DBFW_PG_URL;
if (!ADMIN_URL && process.env.DBFW_REQUIRE_LIVE) throw new Error("DBFW_REQUIRE_LIVE set but DBFW_PG_URL is not");
const live = { skip: ADMIN_URL ? false : "DBFW_PG_URL not set" };
// Pinned, so a case cannot disappear in silence: change it with the corpus.
const ATTACKS = 91, PASSES = 6;
const S = "atk", ROLE = "dbfw_atk", PW = "DbfwAtk_2026x";
const DB = ADMIN_URL ? new URL(ADMIN_URL).pathname.slice(1) : "";
const KEY = "5a".repeat(32);
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const CORPUS = new URL("../../../tests/attacks/postgresql.sql", import.meta.url);
const SECRET = "b-secret";

/** The cases in the corpus file, placeholders filled in. A mistake in the
 *  file (an unknown or repeated directive, a bad value) throws: a directive
 *  dropped in silence would make a case test something else. */
export function parseCorpus(text, vars) {
  const fill = (s) => s.replace(/\{(S|ROLE|DB)\}/g, (_, k) => vars[k]);
  const cases = [];
  let cur = null, part = null, n = 0;
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    n++;
    const bad = (why) => { throw new Error(`corpus line ${n}: ${why}: ${line}`); };
    if (/^\s+--\s*@/.test(line)) bad("an indented directive");
    const head = line.match(/^-- @(attack|pass) (\S.*)$/);
    if (head) {
      cur = { kind: head[1], name: head[2].trim(), mode: "plain", args: [], min: 0, setup: [], undo: [], seen: new Set() };
      cases.push(cur); part = null; continue;
    }
    if (!/^--\s*@/.test(line)) {
      if (part && !/^-- -{4,}/.test(line)) cur[part].push(line);
      continue;
    }
    const d = line.match(/^-- @(check|mode|args|min|leak|setup|undo)(?: (\S.*))?$/);
    if (!d) bad("an unknown directive");
    if (!cur) bad("a directive before the first case");
    const [, key, value = ""] = d;
    if (cur.seen.has(key)) bad(`a second @${key}`);
    cur.seen.add(key);
    if (key === "setup" || key === "undo") { if (value) bad(`@${key} takes no value`); part = key; continue; }
    if (part) bad(`@${key} after @setup`);
    if (!value) bad(`@${key} needs a value`);
    if (key === "mode" && !["plain", "strict"].includes(value)) bad("@mode is plain or strict");
    if (key === "min" && !/^1\d$/.test(value)) bad("@min is a major version");
    if (key === "check" && cur.kind === "pass") bad("a @pass case has no @check");
    if (key === "args") cur.args = fill(value).split(/\s+/);
    else if (key === "min") cur.min = Number(value);
    else cur[key] = fill(value.trim());
  }
  for (const c of cases) {
    c.setup = fill(c.setup.join("\n")).trim(); c.undo = fill(c.undo.join("\n")).trim(); delete c.seen;
  }
  return cases;
}

function appUrl() { const u = new URL(ADMIN_URL); u.username = ROLE; u.password = PW; return u.toString(); }
function run(args) {
  return new Promise((resolve) => execFile("node", [CLI, ...args],
    { env: { ...process.env, DATABASE_URL: "", DB_FIREWALL_TENANT_KEY: KEY } },
    (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr })));
}
async function sql(text) {
  const c = new pg.Client({ connectionString: ADMIN_URL }); await c.connect();
  try { return await c.query(text); } finally { await c.end(); }
}
async function verify(c) {
  const r = await run(["verify", "--url", appUrl(), "--schema", S, "--tenant", "A", "--json",
                       ...(c.mode === "strict" ? ["--strict"] : []), ...c.args]);
  const data = JSON.parse(r.stdout || "{}");
  return { code: r.code, failed: (data.checks ?? []).filter((x) => x.ok === false).map((x) => `${x.table}: ${x.check}`),
           stderr: r.stderr };
}
/** The leak query as the app, tenant A signed, rolled back: its rows and notices. */
async function leak(text) {
  const c = new pg.Client({ connectionString: appUrl() });
  const notices = [];
  c.on("notice", (n) => notices.push(n.message));
  await c.connect();
  try {
    await c.query("BEGIN");
    const { rows: [{ n }] } = await c.query("SELECT public._firewall_nonce() AS n");
    await c.query("SELECT set_config('app.current_tenant', 'A', true), set_config('app.tenant_sig', $1, true)",
                  [sign(Buffer.from(KEY, "hex"), n, "A")]);
    const res = await c.query(text);
    const rows = (Array.isArray(res) ? res : [res]).flatMap((r) => r.rows ?? []);
    return JSON.stringify(rows) + "\n" + notices.join("\n");
  } finally {
    await c.query("ROLLBACK").catch(() => {});
    await c.end();
  }
}

// What a fresh server grants PUBLIC that verify fails on, and how to give it back.
const NO_ACTIVITY = "REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC; REVOKE EXECUTE ON FUNCTION " +
  "pg_catalog.pg_stat_get_activity(integer), pg_catalog.pg_stat_get_backend_activity(integer) FROM PUBLIC";
const RESTORE = "GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC; GRANT EXECUTE ON FUNCTION " +
  "pg_catalog.pg_stat_get_activity(integer), pg_catalog.pg_stat_get_backend_activity(integer) TO PUBLIC";

describe("corpus parser", () => {
  const v = { S: "s", ROLE: "r", DB: "d" };
  const ok = "-- @attack x\n-- @check -: role\n-- @setup\nSELECT {S};\n-- @undo\nSELECT 2;\n";
  it("reads a case, also with CRLF line ends", () => {
    for (const text of [ok, ok.replace(/\n/g, "\r\n")]) {
      const [c] = parseCorpus(text, v);
      assert.deepEqual([c.check, c.setup, c.undo], ["-: role", "SELECT s;", "SELECT 2;"]);
    }
  });
  for (const bad of ["-- @mod strict", "-- @min15", "  -- @mode strict", "-- @mode Strict", "-- @check -: x", "-- @min 1x"]) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      assert.throws(() => parseCorpus(ok.replace("-- @setup", `${bad}\n-- @setup`), v), /corpus line/);
    });
  }
});

describe("attack corpus", live, () => {
  const cases = parseCorpus(readFileSync(CORPUS, "utf8"), { S, ROLE, DB });
  let major = 0;
  before(async () => {
    major = Math.floor(Number((await sql("SHOW server_version_num")).rows[0].server_version_num) / 10000);
    await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE; DROP SCHEMA IF EXISTS ${S}_other CASCADE;
      DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}')
        THEN CREATE ROLE ${ROLE} LOGIN PASSWORD '${PW}'; END IF; END $$;
      REVOKE CREATE ON SCHEMA public FROM PUBLIC;          -- PostgreSQL 14 grants it
      CREATE SCHEMA ${S}; GRANT USAGE ON SCHEMA ${S} TO ${ROLE};
      CREATE TABLE ${S}.docs (id serial, tenant_id text, body text);
      INSERT INTO ${S}.docs (tenant_id, body) VALUES ('A', 'a-secret'), ('B', '${SECRET}');
      GRANT SELECT, INSERT, UPDATE, DELETE ON ${S}.docs TO ${ROLE}; GRANT USAGE ON SEQUENCE ${S}.docs_id_seq TO ${ROLE};
      ${NO_ACTIVITY};`);
    const m = await run(["migrate", "--url", ADMIN_URL, "--schema", S]);
    assert.equal(m.code, 0, m.stderr);
  });
  after(async () => {
    await sql(`DROP SCHEMA IF EXISTS ${S} CASCADE; DROP SCHEMA IF EXISTS ${S}_other CASCADE; ${RESTORE};`);
  });

  it("the corpus parses: every case has a check (or passes), a setup and an undo", () => {
    assert.equal(cases.filter((c) => c.kind === "attack").length, ATTACKS, "attacks (update ATTACKS with the corpus)");
    assert.equal(cases.filter((c) => c.kind === "pass").length, PASSES, "safe patterns (update PASSES)");
    for (const c of cases) {
      assert.ok(c.setup && c.undo, `${c.name}: setup and undo`);
      if (c.kind === "attack") assert.match(c.check ?? "", /^\S+: /, `${c.name}: @check table: check`);
    }
    assert.equal(new Set(cases.map((c) => c.name)).size, cases.length, "names are unique");
  });

  for (const mode of ["plain", "strict"]) {
    it(`the fixture passes verify (${mode}) before and after the corpus`, async () => {
      const r = await verify({ mode, args: [] });
      assert.equal(r.code, 0, r.failed.join("; ") + r.stderr);
    });
  }

  for (const c of cases) {
    it(`${c.kind === "attack" ? "fails" : "passes"}: ${c.name}`, async (t) => {
      if (major < c.min) return t.skip(`needs PostgreSQL ${c.min}`);
      await sql(c.setup);
      try {
        if (c.leak) assert.ok((await leak(c.leak)).includes(SECRET), `the attack does not leak on PostgreSQL ${major}`);
        const r = await verify(c);
        if (c.kind === "pass") {
          assert.equal(r.code, 0, r.failed.join("; ") + r.stderr);
        } else {
          assert.equal(r.code, 1, `exit ${r.code}: ${r.stderr}`);
          assert.ok(r.failed.includes(c.check), `${c.check} not in: ${r.failed.join("; ")}`);
        }
      } finally {
        await sql(c.undo);
      }
    });
  }

  for (const mode of ["plain", "strict"]) {
    it(`the fixture passes verify (${mode}) after the corpus (every undo is complete)`, async () => {
      const r = await verify({ mode, args: [] });
      assert.equal(r.code, 0, r.failed.join("; ") + r.stderr);
    });
  }
});
