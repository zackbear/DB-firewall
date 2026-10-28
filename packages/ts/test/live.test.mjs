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
  it("an event listener gets a wrapped emitter", async () => {
    let emitter;
    await withTenant(pool, "A", async (c) => {
      c.on("notice", function () { emitter = this; });
      await c.query("DO $$ BEGIN RAISE NOTICE 'hi'; END $$");
      c.removeAllListeners?.("notice");
    });
    assert.ok(emitter, "listener ran");
    assert.throws(() => emitter.query, TypeError);
  });
  it("raw objects reached through the handle stop working too", async () => {
    let conn;
    await withTenant(pool, "A", async (c) => { conn = c.connection; });
    assert.throws(() => conn.query, TypeError);
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
    await adminQuery("INSERT INTO public._firewall_bypass_roles (role_name) VALUES ('dbfw_ts')");
    try {
      await assert.rejects(assertSafeRole(pool), /_firewall_bypass_roles/);
    } finally {
      await adminQuery("DELETE FROM public._firewall_bypass_roles WHERE role_name = 'dbfw_ts'");
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
