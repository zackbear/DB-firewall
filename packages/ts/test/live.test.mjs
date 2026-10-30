// Live tests against PostgreSQL with the DB Firewall migration. Skipped
// without DBFW_PG_URL (CI sets it).
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/node-postgres";
import { integer, pgSchema, text } from "drizzle-orm/pg-core";
import { sql as dsql } from "drizzle-orm";
import {
  assertSafeRole, bindTenant, currentTenant, runWithTenant, validateTenantId,
  withTenant, withTenantPg,
} from "../dist/index.js";
import { ADMIN_URL, SCHEMA, adminQuery, appUrl, live, setup } from "./setup.mjs";
const ids = (rows) => rows.map((r) => Number(r.id)).sort();
const SELECT = `SELECT id FROM ${SCHEMA}.docs`;
const docs = pgSchema(SCHEMA).table("docs", { id: integer("id"), tenantId: text("tenant_id") });

// Session state SQL run inside fn could leave for the connection's next user
// (another tenant): a temp view shadowing a table, a SQL-level prepared
// statement, a custom setting as a drop box, a search_path. withTenant must
// undo all of it, after fn returns and after fn throws.
const PLANT = ["CREATE TEMP VIEW docs AS SELECT 99 AS id", "PREPARE agent_plant AS SELECT 1",
               "SELECT set_config('rv.loot', 'B-secret', false)", "SET search_path = pg_temp, public",
               "SELECT pg_advisory_lock(66, 2)"];
const PROBE = "SELECT (SELECT count(*) FROM pg_class WHERE relnamespace = pg_my_temp_schema())::int AS temp, " +
  "(SELECT count(*) FROM pg_prepared_statements WHERE from_sql)::int AS prep, " +
  "coalesce(current_setting('rv.loot', true), '') AS loot, current_setting('search_path') AS path, " +
  "(SELECT count(*) FROM pg_locks WHERE locktype = 'advisory')::int AS locks";
const CLEAN = { temp: 0, prep: 0, loot: "", path: '"$user", public', locks: 0 };
// fn breaks the transaction around the reset: leaves it aborted, releases its
// savepoint and throws, or shadows the jsonb type the reset call casts to.
const BREAKS = {
  aborted: async (raw, h) => { await raw(h, "SELECT 1/0").catch(() => {}); },
  "failed statement": async (raw, h) => { await raw(h, "RELEASE SAVEPOINT nope").catch(() => {}); throw new Error("boom"); },
  "temp type": async (raw, h) => { await raw(h, "CREATE TYPE pg_temp.jsonb AS (x int)"); },
};
// A deferred trigger fires at COMMIT. Planted in a schema the app can CREATE
// in (verify fails on that), it would run after a reset done before COMMIT.
const DEFERRED = [
  "CREATE TABLE ts_plant.t (x int)",
  "CREATE FUNCTION ts_plant.f() RETURNS trigger LANGUAGE plpgsql AS " +
    "$$ BEGIN PERFORM set_config('search_path', 'ts_plant, public', false); RETURN NULL; END $$",
  "CREATE CONSTRAINT TRIGGER late AFTER INSERT ON ts_plant.t DEFERRABLE INITIALLY DEFERRED " +
    "FOR EACH ROW EXECUTE FUNCTION ts_plant.f()",
  "INSERT INTO ts_plant.t VALUES (1)",
];
async function assertDeferredTriggerReset(db, raw) {
  await adminQuery("DROP SCHEMA IF EXISTS ts_plant CASCADE; CREATE SCHEMA ts_plant; " +
                   "GRANT CREATE, USAGE ON SCHEMA ts_plant TO dbfw_ts");
  try {
    await withTenant(db, "A", async (h) => { for (const q of DEFERRED) await raw(h, q); });
    const [state] = await withTenant(db, "B", (h) => raw(h, PROBE));
    assert.equal(state.path, '"$user", public');
  } finally {
    await adminQuery("DROP SCHEMA IF EXISTS ts_plant CASCADE");
  }
}
async function assertResets(db, raw) {
  for (const fails of [false, true]) {
    const planted = withTenant(db, "A", async (h) => {
      for (const q of PLANT) await raw(h, q);
      if (fails) throw new Error("boom");
    });
    if (fails) await assert.rejects(planted, /boom/); else await planted;
    const [state] = await withTenant(db, "B", (h) => raw(h, PROBE));
    assert.deepEqual({ ...state }, CLEAN, fails ? "after fn threw" : "after fn returned");
  }
  for (const [how, breakIt] of Object.entries(BREAKS)) {
    // Whether the call throws differs by driver; what matters is the next borrower.
    await withTenant(db, "A", async (h) => { for (const q of PLANT) await raw(h, q); await breakIt(raw, h); })
      .catch(() => {});
    const [state] = await withTenant(db, "B", (h) => raw(h, PROBE));
    assert.deepEqual({ ...state }, CLEAN, `after fn ${how}`);
  }
}

describe("tenant ids", () => {
  for (const bad of ["", "a\u0000b", "a\nb", "a\\b", "__BYPASS__", "__bypass__", 7, undefined]) {
    it(`refuses ${JSON.stringify(bad)}`, () => assert.throws(() => validateTenantId(bad)));
  }
  it("fails closed with no tenant, before touching the database", async () => {
    const db = { query: () => { throw new Error("must not be called"); }, connectionParameters: {} };
    await assert.rejects(withTenant(db, async () => 1), /no tenant/);
  });
  it("refuses an object that only looks like a client (pool wrappers such as pg-promise)", async () => {
    const wrapper = { query: async () => ({ rows: [] }), connect: async () => ({}) };
    await assert.rejects(withTenant(wrapper, "A", async () => 1), /wrapper/);
    await assert.rejects(withTenantPg(wrapper, "A", async () => 1), /pg.Pool or a pg.Client/);
  });
  it("scopes nest and do not leak between concurrent calls", async () => {
    const seen = await Promise.all(["A", "B"].map((t) =>
      runWithTenant(t, async () => { await new Promise((r) => setTimeout(r, 5)); return currentTenant(); })));
    assert.deepEqual(seen, ["A", "B"]);
    assert.equal(currentTenant(), undefined);
  });
});

describe("node-postgres", live, () => {
  let pool, admin;
  before(async () => { await setup(); pool = new pg.Pool({ connectionString: appUrl(), max: 1 }); });
  after(async () => { await pool?.end(); });

  it("reads only the tenant's rows", async () => {
    assert.deepEqual(ids(await withTenantPg(pool, "A", async (c) => (await c.query(SELECT)).rows)), [1]);
    assert.deepEqual(ids(await withTenant(pool, "B", async (c) => (await c.query(SELECT)).rows)), [2]);
  });
  it("the pooled connection comes back with no tenant (max: 1, same connection)", async () => {
    await withTenant(pool, "A", async (c) => c.query(SELECT));
    const { rows } = await pool.query("SELECT current_setting('app.current_tenant', true) AS t");
    assert.ok(!rows[0].t, `leaked tenant ${rows[0].t}`);
    assert.deepEqual(ids((await pool.query(SELECT)).rows), []);     // RLS: no tenant, no rows
  });
  it("cross-tenant insert is refused by RLS", async () => {
    await assert.rejects(withTenant(pool, "A", (c) =>
      c.query(`INSERT INTO ${SCHEMA}.docs VALUES (50, 'B', 'x')`)), /row-level security/);
  });
  it("an error rolls back and leaves the connection usable", async () => {
    await assert.rejects(withTenant(pool, "A", async (c) => {
      await c.query(`UPDATE ${SCHEMA}.docs SET body = 'changed' WHERE id = 1`);
      throw new Error("boom");
    }), /boom/);
    const rows = await adminQuery(`SELECT body FROM ${SCHEMA}.docs WHERE id = 1`);
    assert.equal(rows[0].body, "a-doc");
    assert.deepEqual(ids(await withTenant(pool, "A", async (c) => (await c.query(SELECT)).rows)), [1]);
  });
  it("the handle stops working when fn returns (no late query on the next borrower)", async () => {
    let kept;                                     // what a stray timer or closure would hold
    await withTenant(pool, "A", async (c) => { kept = c; });
    assert.throws(() => kept.query(SELECT), TypeError);
    await assert.rejects(withTenant(pool, "A", async (c) => c), TypeError);   // returning it fails too
  });
  it("a nested call on the handle is refused", async () => {
    await assert.rejects(withTenant(pool, "A", (c) => withTenant(c, "B", async () => 1)), /nested/);
  });
  it("release() inside fn is refused, and the connection stays ours", async () => {
    await assert.rejects(withTenant(pool, "A", async (c) => { c.release(); }), /release\(\) is not allowed/);
    assert.deepEqual(ids(await withTenant(pool, "A", async (c) => (await c.query(SELECT)).rows)), [1]);
  });
  it("an event listener gets a wrapped emitter and plain event data, and is removed after fn", async () => {
    let emitter, calls = 0, notice;
    await withTenant(pool, "A", async (c) => {
      c.on("notice", function (msg) { emitter = this; notice = msg; calls++; });
      await c.query("DO $$ BEGIN RAISE NOTICE 'hi'; END $$");
    });
    assert.equal(calls, 1);
    assert.equal(notice.message, "hi");                      // event data stays usable
    assert.throws(() => emitter.query, TypeError);           // the emitter does not
    // The next borrower's notice must not reach the old listener (and must not crash).
    await withTenant(pool, "B", (c) => c.query("DO $$ BEGIN RAISE NOTICE 'again'; END $$"));
    assert.equal(calls, 1);
  });
  it("rows collected from query events stay usable after fn", async () => {
    const rows = [];
    await withTenant(pool, "A", (c) => new Promise((resolve, reject) => {
      const q = c.query(new pg.Query(SELECT));
      q.on("row", (row) => rows.push(row)).on("end", resolve).on("error", reject);
    }));
    assert.deepEqual(ids(rows), [1]);
  });
  it("raw objects reached through the handle stop working too", async () => {
    let conn;
    await withTenant(pool, "A", async (c) => { conn = c.connection; });
    assert.throws(() => conn.query, TypeError);
  });
  for (const [how, sql] of [["SET LOCAL", "SET LOCAL app.current_tenant = 'B'"],
                           ["set_config", "SELECT set_config('app.current_tenant', 'B', true)"]]) {
    it(`SQL run inside fn cannot switch tenants (${how})`, async () => {
      const rows = await withTenant(pool, "A", async (c) => {
        await c.query(sql);
        return (await c.query(SELECT)).rows;
      });
      assert.deepEqual(ids(rows), []);                  // B's row stays hidden: B is not signed
    });
  }
  it("a forged or replayed signature sees nothing", async () => {
    const sig = await withTenant(pool, "A", async (c) =>
      (await c.query("SELECT current_setting('app.tenant_sig') AS s")).rows[0].s);
    const seen = async (tenant, s) => {
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        await c.query("SELECT set_config('app.current_tenant', $1, true), set_config('app.tenant_sig', $2, true)",
                      [tenant, s]);
        return ids((await c.query(SELECT)).rows);
      } finally { await c.query("ROLLBACK"); c.release(); }
    };
    assert.deepEqual(await seen("A", sig), []);           // new transaction, new nonce
    assert.deepEqual(await seen("B", "0".repeat(64)), []);
  });
  it("without the key the context is unsigned and shows nothing", async () => {
    const saved = process.env.DB_FIREWALL_TENANT_KEY;
    delete process.env.DB_FIREWALL_TENANT_KEY;
    try {
      assert.deepEqual(ids(await withTenant(pool, "A", async (c) => (await c.query(SELECT)).rows)), []);
    } finally { process.env.DB_FIREWALL_TENANT_KEY = saved; }
    process.env.DB_FIREWALL_TENANT_KEY = "abcd";
    try {
      await assert.rejects(withTenant(pool, "A", async () => {}), /32 to 64 bytes/);
    } finally { process.env.DB_FIREWALL_TENANT_KEY = saved; }
  });
  it("session state left by fn is reset for the next borrower", async () => {
    await assertResets(pool, async (c, q) => (await c.query(q)).rows);
  });
  it("a deferred trigger cannot undo the reset (reset after COMMIT)", async () => {
    await assertDeferredTriggerReset(pool, async (c, q) => (await c.query(q)).rows);
  });
  it("fn ending its own backend fails the call, not the process", async () => {
    await assert.rejects(withTenant(pool, "A", (c) => c.query("SELECT pg_terminate_backend(pg_backend_pid())")));
    assert.deepEqual(ids(await withTenant(pool, "A", async (c) => (await c.query(SELECT)).rows)), [1]);
  });
  it("a connection whose driver statement fn removed is discarded", async () => {
    const Q = { name: "docs_q", text: SELECT };
    const pid = await withTenant(pool, "A", async (c) => {
      await c.query(Q);
      await c.query("DEALLOCATE docs_q");
      return (await c.query("SELECT pg_backend_pid() AS p")).rows[0].p;
    });
    const next = await withTenant(pool, "A", async (c) => {
      assert.deepEqual(ids((await c.query(Q)).rows), [1]);              // works: a new connection
      return (await c.query("SELECT pg_backend_pid() AS p")).rows[0].p;
    });
    assert.notEqual(next, pid);
  });
  it("a session-level tenant set inside fn does not survive the release", async () => {
    await withTenant(pool, "A", (c) => c.query("SET app.current_tenant = 'B'"));
    assert.deepEqual(ids((await pool.query(SELECT)).rows), []);
  });
  it("assertSafeRole accepts the app role and refuses a superuser and a bypass role", async () => {
    await assertSafeRole(pool);
    admin = new pg.Pool({ connectionString: ADMIN_URL, max: 1 });
    try {
      const { rows } = await admin.query("SELECT rolsuper FROM pg_roles WHERE rolname = current_user");
      if (rows[0].rolsuper) await assert.rejects(assertSafeRole(admin), /superuser/);
    } finally { await admin.end(); }
    await adminQuery("INSERT INTO db_firewall._firewall_bypass_roles (role_name) VALUES ('dbfw_ts')");
    try {
      await assert.rejects(assertSafeRole(pool), /_firewall_bypass_roles/);
    } finally {
      await adminQuery("DELETE FROM db_firewall._firewall_bypass_roles WHERE role_name = 'dbfw_ts'");
    }
  });
});

describe("postgres.js", live, () => {
  let sql;
  before(async () => { await setup(); sql = postgres(appUrl(), { max: 1, onnotice: () => {} }); });
  after(async () => { await sql?.end(); });

  it("reads only the tenant's rows, nothing leaks after", async () => {
    assert.deepEqual(ids(await withTenant(sql, "A", (tx) => tx.unsafe(SELECT))), [1]);
    assert.deepEqual(ids(await withTenant(sql, "B", (tx) => tx`SELECT id FROM ts_app.docs`)), [2]);
    assert.deepEqual(ids(await sql.unsafe(SELECT)), []);
    await assertSafeRole(sql);
  });
  it("session state left by fn is reset for the next borrower", async () => {
    await assertResets(sql, (tx, q) => tx.unsafe(q));
  });
  it("a deferred trigger cannot undo the reset (reset after COMMIT)", async () => {
    await assertDeferredTriggerReset(sql, (tx, q) => tx.unsafe(q));
  });
  it("a transaction fn left aborted fails the call", async () => {
    await assert.rejects(withTenant(sql, "A", async (tx) => { await tx.unsafe("SELECT 1/0").catch(() => {}); }),
                         /aborted/);
  });
  it("tx.savepoint works and a nested begin is refused", async () => {
    const rows = await withTenant(sql, "A", (tx) => tx.savepoint((sp) => sp`SELECT id FROM ts_app.docs`));
    assert.deepEqual(ids(rows), [1]);
    await assert.rejects(withTenant(sql, "A", async (tx) => tx.begin(async () => 1)), /not allowed/);
    await assert.rejects(withTenant(sql, "A", (tx) => tx.savepoint(async () => { throw new Error("inner"); })), /inner/);
  });
  it("late queries and nested calls are refused", async () => {
    let kept;
    await withTenant(sql, "A", async (tx) => { kept = tx; });
    assert.throws(() => kept.unsafe(SELECT), TypeError);
    await assert.rejects(withTenant(sql, "A", (tx) => withTenant(tx, "B", async () => 1)), /nested/);
  });
  it("an array of queries returned from fn works (postgres.js pattern)", async () => {
    const [a, b] = await withTenant(sql, "A", (tx) => [tx`SELECT id FROM ts_app.docs`, tx`SELECT 1 AS one`]);
    assert.deepEqual(ids(a), [1]);
    assert.equal(b[0].one, 1);
  });
  it("a savepoint handle kept after fn stops working", async () => {
    let sp;
    await withTenant(sql, "A", (tx) => tx.savepoint(async (s) => { sp = s; }));
    assert.throws(() => sp.unsafe(SELECT), TypeError);
  });
  it("a query created inside fn and awaited after it is refused", async () => {
    let pending;
    await withTenant(sql, "A", async (tx) => { pending = tx`SELECT id FROM ts_app.docs`; });
    await assert.rejects(Promise.resolve().then(() => pending), TypeError);
  });
});

describe("Drizzle", live, () => {
  let pool, db;
  before(async () => {
    await setup();
    pool = new pg.Pool({ connectionString: appUrl(), max: 1 });
    db = drizzle(pool);
  });
  after(async () => { await pool?.end(); });

  it("reads only the tenant's rows, nothing leaks after", async () => {
    const read = async (tx) => (await tx.execute(dsql.raw(SELECT))).rows;
    assert.deepEqual(ids(await withTenant(db, "A", read)), [1]);
    assert.deepEqual(ids(await withTenant(db, "B", read)), [2]);
    assert.deepEqual(ids((await db.execute(dsql.raw(SELECT))).rows), []);
    await assertSafeRole(db);
  });
  it("session state left by fn is reset for the next borrower", async () => {
    await assertResets(db, async (tx, q) => (await tx.execute(dsql.raw(q))).rows);
  });
  it("a deferred trigger cannot undo the reset (reset after COMMIT)", async () => {
    await assertDeferredTriggerReset(db, async (tx, q) => (await tx.execute(dsql.raw(q))).rows);
  });
  it("relational queries (tx.query) work", async () => {
    const rdb = drizzle(pool, { schema: { docs } });
    assert.deepEqual(ids(await withTenant(rdb, "A", (tx) => tx.query.docs.findMany())), [1]);
  });
  it("a transaction fn left aborted fails the call", async () => {
    await assert.rejects(withTenant(db, "A", async (tx) => { await tx.execute(dsql.raw("SELECT 1/0")).catch(() => {}); }),
                         /aborted/);
  });
  it("late queries, nested calls and a raw Drizzle transaction are refused", async () => {
    let kept;
    await withTenant(db, "A", async (tx) => { kept = tx; });
    assert.throws(() => kept.execute(dsql.raw(SELECT)), TypeError);
    await assert.rejects(withTenant(db, "A", (tx) => withTenant(tx, "B", async () => 1)), /nested/);
    await assert.rejects(db.transaction((tx) => withTenant(tx, "B", async () => 1)), /not a transaction/);
  });
  it("a query builder awaited inside fn works; one awaited after it is refused", async () => {
    const rows = await withTenant(db, "A", async (tx) => tx.select({ id: docs.id }).from(docs));
    assert.deepEqual(ids(rows), [1]);                          // results stay usable
    let builder, session;
    await withTenant(db, "A", async (tx) => { builder = tx.select().from(docs); session = tx.session; });
    await assert.rejects(Promise.resolve().then(() => builder), TypeError);
    assert.throws(() => session.execute, TypeError);
  });
  it("a nested Drizzle transaction works inside fn, its handle stops working after", async () => {
    let inner;
    const rows = await withTenant(db, "A", (tx) => tx.transaction(async (t) => {
      inner = t;
      return t.select({ id: docs.id }).from(docs);
    }));
    assert.deepEqual(ids(rows), [1]);
    assert.throws(() => inner.select, TypeError);
  });
  it("a value read through a property descriptor is wrapped too", async () => {
    let session;
    await withTenant(db, "A", async (tx) => { session = Object.getOwnPropertyDescriptor(tx, "session")?.value; });
    if (session) assert.throws(() => session.execute, TypeError);
  });
});

describe("bindTenant (AI SDK tool set)", live, () => {
  let pool;
  before(async () => { await setup(); pool = new pg.Pool({ connectionString: appUrl(), max: 2 }); });
  after(async () => { await pool?.end(); });

  // An AI SDK-shaped tool: the model chooses the arguments, never the tenant.
  const tools = () => ({
    listDocs: {
      description: "List documents",
      execute: async ({ tenant_id: ignored } = {}) =>
        ids(await withTenant(pool, async (c) => (await c.query(SELECT)).rows)),
    },
    note: "not a tool",
  });

  it("each request's tools see only that request's tenant, even if the model names another", async () => {
    const [a, b] = await Promise.all([
      bindTenant(tools(), "A").listDocs.execute({ tenant_id: "B" }),
      bindTenant(tools(), "B").listDocs.execute({ tenant_id: "A" }),
    ]);
    assert.deepEqual([a, b], [[1], [2]]);
  });
  it("unbound tools fail closed", async () => {
    await assert.rejects(tools().listDocs.execute(), /no tenant/);
  });
  it("copies non-tool values and refuses a bad tenant at bind time", () => {
    assert.equal(bindTenant(tools(), "A").note, "not a tool");
    assert.throws(() => bindTenant(tools(), "__bypass__"));
  });
});
