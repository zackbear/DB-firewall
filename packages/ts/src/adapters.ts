import { type Entered, type Run, SessionResetError, enter, resetOutside } from "./sign.js";
import { resolveTenant } from "./tenant.js";

// Structural types: the package has no runtime dependency on any driver.

/** node-postgres Pool (pg.Pool) or a pooled / standalone client. */
export interface PgQueryable {
  query(text: string, values?: unknown[]): Promise<{ rows: any[] }>;
}
export interface PgPool extends PgQueryable {
  connect(): Promise<PgQueryable & { release(err?: Error | boolean): void }>;
  totalCount: number;
}
/** postgres.js instance (the `sql` returned by postgres()). */
export interface PostgresJs {
  begin<T>(fn: (tx: PostgresJsTx) => Promise<T>): Promise<T>;
  unsafe(query: string, params?: unknown[]): Promise<any[]>;
}
export interface PostgresJsTx {
  unsafe(query: string, params?: unknown[]): Promise<any[]>;
}
/** Drizzle PostgreSQL database (any driver). */
export interface DrizzleDb {
  transaction<T>(fn: (tx: DrizzleTx) => Promise<T>): Promise<T>;
  execute(query: unknown): Promise<unknown>;
}
export interface DrizzleTx {
  execute(query: unknown): Promise<unknown>;
}

// A Drizzle or driver result as rows.
const rowsOf = (res: any): any[] => (Array.isArray(res) ? res : res?.rows ?? []);

// Detection is exact: an object that only looks like a client (a pool wrapper
// such as pg-promise) would run BEGIN, the tenant and COMMIT on different
// pooled connections. Anything not recognised is refused.
function isPgPool(db: any): db is PgPool {
  return typeof db?.connect === "function" && typeof db?.query === "function"
    && typeof db?.totalCount === "number" && typeof db?.idleCount === "number";
}
function isPgClient(db: any): db is PgQueryable {
  return typeof db?.query === "function" && typeof db?.connectionParameters === "object"
    && db.connectionParameters !== null && typeof db?.totalCount !== "number";
}
function isPostgresJs(db: any): db is PostgresJs {
  return typeof db === "function" && typeof db.begin === "function" && typeof db.unsafe === "function";
}
function isDrizzle(db: any): db is DrizzleDb {
  return typeof db?.transaction === "function" && typeof db?.execute === "function"
    && typeof db?.select === "function" && typeof db?.rollback !== "function";
}
function isDrizzleTx(db: any): boolean {
  return typeof db?.transaction === "function" && typeof db?.rollback === "function";
}

// Handles given to fn. A handle passed back into withTenant is a nested call:
// refused, since an inner tenant would outlive its savepoint (Drizzle) or
// commit the outer transaction early (pg).
const handles = new WeakSet<object>();

// Lifecycle calls fn must not make: releasing or ending the connection while
// this function still owns it hands it to the next borrower mid-transaction.
// begin / reserve: a nested transaction would COMMIT this one early.
const BLOCKED = new Set<PropertyKey>(["release", "connect", "end", "begin", "reserve"]);
// Methods that call back with a handle (a nested Drizzle transaction, a
// postgres.js savepoint): the callback gets wrapped arguments and `this`.
const HANDLE_CALLBACKS = new Set<PropertyKey>(["transaction", "savepoint"]);
// Event listeners added inside fn: `this` (the emitter) is wrapped, the event
// data (rows, notices) stays plain, and the listener is removed when fn
// settles, so it never runs for the connection's next borrower.
const LISTENER_METHODS = new Set<PropertyKey>([
  "on", "once", "addListener", "prependListener", "prependOnceListener",
]);

/**
 * Run fn with a handle that stops working when fn settles. Everything reached
 * through it (a property such as tx.session, a method result such as a Drizzle
 * query builder or a pending postgres.js query) is wrapped the same way, so a
 * query fired or awaited after fn settles throws instead of running on the
 * connection's next borrower. Native promises pass through, so results (rows)
 * stay usable after fn returns.
 */
async function withHandle<H extends object, T>(target: H, fn: (h: H) => Promise<T>): Promise<T> {
  let open = true;
  const listeners: Array<[any, unknown, (...a: unknown[]) => unknown]> = [];   // emitter, event, fn
  const wrapped = new WeakMap<object, any>();     // target -> its wrapper (stable identity)
  const targets = new WeakMap<object, object>();  // wrapper -> target
  const check = () => {
    if (!open) throw new TypeError("DB Firewall: database handle used after withTenant() finished");
  };
  const wrap = (value: any): any => {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
    if (Object.getPrototypeOf(value) === Promise.prototype) return value;   // results, not handles
    const known = wrapped.get(value);
    if (known) return known;
    const proxy = new Proxy(value, {
      get(t, key) {
        check();
        if (BLOCKED.has(key)) {
          return () => { throw new TypeError(`DB Firewall: ${String(key)}() is not allowed inside withTenant()`); };
        }
        const v = Reflect.get(t, key, t);
        if (typeof v !== "function") return wrap(v);
        // Methods run on the real object (private state, Promise internals),
        // and what they return is wrapped.
        return (...args: unknown[]) => {
          check();
          let passed = args;
          if (HANDLE_CALLBACKS.has(key)) {
            passed = args.map((a) => typeof a === "function"
              ? function (this: unknown, ...cbArgs: unknown[]) {
                  return (a as (...x: unknown[]) => unknown).apply(wrap(this), cbArgs.map(wrap));
                }
              : a);
          } else if (LISTENER_METHODS.has(key) && typeof args[1] === "function") {
            const listener = args[1] as (...x: unknown[]) => unknown;
            const bound = function (this: unknown, ...eventArgs: unknown[]) {
              return listener.apply(wrap(this), eventArgs);
            };
            listeners.push([t, args[0], bound]);
            passed = [args[0], bound, ...args.slice(2)];
          }
          return wrap(Reflect.apply(v, t, passed));
        };
      },
      getOwnPropertyDescriptor(t, key) {
        check();
        const d = Reflect.getOwnPropertyDescriptor(t, key);
        if (d && "value" in d && d.configurable) d.value = wrap(d.value);   // invariants allow it only then
        return d;
      },
      apply(t, thisArg, args) {
        check();
        const self = (thisArg && targets.get(thisArg)) ?? thisArg;
        return wrap(Reflect.apply(t as (...a: unknown[]) => unknown, self, args));
      },
      set(t, key, v) { check(); return Reflect.set(t, key, v, t); },
      has(t, key) { check(); return Reflect.has(t, key); },
    });
    wrapped.set(value, proxy);
    targets.set(proxy, value);
    return proxy;
  };
  const handle = wrap(target) as H;
  handles.add(handle);
  try {
    return await fn(handle);
  } finally {
    open = false;
    for (const [emitter, event, bound] of listeners) emitter.removeListener?.(event, bound);
  }
}

function refuseNested(db: unknown): void {
  if ((typeof db === "object" || typeof db === "function") && db !== null && handles.has(db)) {
    throw new TypeError("DB Firewall: nested withTenant() on a handle it gave you; " +
                        "use that handle directly, or pass the pool / database");
  }
  if (isDrizzleTx(db)) {
    throw new TypeError("DB Firewall: pass the Drizzle database, not a transaction");
  }
}

/**
 * A transaction on one node-postgres client, then the session reset outside
 * it (after COMMIT, so a deferred trigger cannot undo it). tx runs the
 * transaction and calls enter() in it. A pooled client is destroyed when the
 * reset failed or fn tampered with the driver's prepared statements; a
 * standalone client cannot be, so the call throws SessionResetError instead.
 */
interface ClientState { entered?: Entered; suspect?: Error }

async function onClient<T>(client: PgQueryable, pooled: { release(err?: Error | boolean): void } | undefined,
                           tx: (state: ClientState) => Promise<T>): Promise<T> {
  const run: Run = async (text, values) => (await client.query(text, values)).rows;
  const state: ClientState = {};
  let failed: Error | undefined, discard = false, threw = false;
  // SQL in fn can end its own backend (pg_terminate_backend): node-postgres
  // then emits 'error' on the client, which would crash the process with no
  // listener. Mark the client suspect instead; it is destroyed below.
  const onError = (err: Error) => { state.suspect = err; };
  (client as any).on?.("error", onError);
  try {
    return await tx(state);
  } catch (err) {
    threw = true;
    throw err;
  } finally {
    if (state.entered && !state.suspect) {
      // The statements node-postgres believes it prepared on this connection
      // (also those prepared during fn): if fn removed one, the cache is stale.
      const cached = Object.keys((client as any).connection?.parsedStatements ?? {});
      const entered = { ...state.entered, drivers: [...new Set([...state.entered.drivers, ...cached])] };
      try { discard = await resetOutside(run, entered); } catch (e) { failed = e as Error; }
    }
    (client as any).removeListener?.("error", onError);
    pooled?.release(state.suspect ?? failed ?? (discard ? new Error("DB Firewall: session tampered with") : undefined));
    if (failed && !pooled && !threw) {
      // eslint-disable-next-line no-unsafe-finally
      throw new SessionResetError(`DB Firewall: could not reset the session (${failed.message}); ` +
                                  "do not reuse this client");
    }
  }
}

/**
 * node-postgres: BEGIN, set the tenant for this transaction only, run fn with
 * the transaction's client, then COMMIT (ROLLBACK if fn throws), then reset the
 * session. A Pool lends one client for the call and gets it back clean. Pass a
 * Pool, or a client that is not inside a transaction: this function's COMMIT
 * would also commit a transaction the caller opened.
 */
export async function withTenantPg<T>(
  db: PgPool | PgQueryable, tenantOrFn: string | ((client: PgQueryable) => Promise<T>),
  maybeFn?: (client: PgQueryable) => Promise<T>,
): Promise<T> {
  refuseNested(db);
  if (!isPgPool(db) && !isPgClient(db)) {
    throw new TypeError("DB Firewall: withTenantPg needs a pg.Pool or a pg.Client / PoolClient");
  }
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  const pooled = isPgPool(db) ? await db.connect() : undefined;
  const client: PgQueryable = pooled ?? db;
  return onClient(client, pooled, async (state) => {
    try {
      await client.query("BEGIN");
    } catch (err) {
      state.suspect = err as Error;                     // the connection is suspect: discard it
      throw err;
    }
    try {
      state.entered = await enter(async (text, values) => (await client.query(text, values)).rows, tenant);
      const result = await withHandle(client, fn);
      const done: any = await client.query("COMMIT");
      if (done?.command === "ROLLBACK") {            // fn left the transaction aborted
        throw new SessionResetError("DB Firewall: the function left the transaction aborted; it was rolled back");
      }
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch((e) => { state.suspect = e as Error; });
      throw err;
    }
  });
}

/** postgres.js resolves an array of queries returned from a transaction. */
const settle = async (x: unknown) => (Array.isArray(x) ? Promise.all(x) : x);

/**
 * A reserved postgres.js connection, so the transaction and the session reset
 * after it run on one connection. Reserved connections have no begin() or
 * savepoint(), so these are added: begin(fn) runs BEGIN, fn, COMMIT (ROLLBACK
 * on error) and savepoint(fn) the same with a savepoint, as postgres.js does.
 */
async function reservePostgres(sql: PostgresJs): Promise<any> {
  const r: any = await (sql as any).reserve();
  let n = 0;
  const around = async (open: string, close: string, undo: string, fn: (s: unknown) => unknown) => {
    await r.unsafe(open);
    try {
      const res = await settle(await fn(r));
      const done: any = await r.unsafe(close);
      if (done?.command === "ROLLBACK") {              // fn left the transaction aborted
        throw new SessionResetError("DB Firewall: the function left the transaction aborted; it was rolled back");
      }
      return res;
    } catch (err) {
      await r.unsafe(undo).catch(() => {});
      throw err;
    }
  };
  const fnOf = (a: unknown, b?: unknown) => (typeof a === "function" ? a : b) as (s: unknown) => unknown;
  r.begin = (a: unknown, b?: unknown) => around("BEGIN", "COMMIT", "ROLLBACK", fnOf(a, b));
  r.savepoint = (a: unknown, b?: unknown) => {
    const name = `_dbfw_sp${n++}`;
    return around(`SAVEPOINT ${name}`, `RELEASE SAVEPOINT ${name}`, `ROLLBACK TO SAVEPOINT ${name}`, fnOf(a, b));
  };
  return r;
}

/**
 * On a reserved postgres.js connection: tx runs the transaction (r.begin) and
 * calls enter() in it; then the session is reset outside it. postgres.js does
 * not survive a reserved connection being ended (it throws from its socket
 * code), so a connection whose reset failed is never released: nothing else
 * can use it, at the cost of one pool slot. A connection whose prepared
 * statements fn tampered with is released (the SQL-level ones are gone; at
 * worst postgres.js's statement cache fails on it, which leaks nothing).
 */
async function onReserved<T>(r: any, tx: (state: ClientState) => Promise<T>): Promise<T> {
  const run: Run = (text, values) => r.unsafe(text, values);
  const state: ClientState = {};
  let failed: Error | undefined, threw = false;
  try {
    return await tx(state);
  } catch (err) {
    threw = true;
    throw err;
  } finally {
    if (state.entered) {
      try { await resetOutside(run, state.entered); } catch (e) { failed = e as Error; }
    }
    if (!failed) r.release();
    else if (!threw) {
      // eslint-disable-next-line no-unsafe-finally
      throw new SessionResetError(`DB Firewall: could not reset the session (${failed.message}); ` +
                                  "the connection was retired (kept reserved, never reused)");
    }
  }
}

/**
 * postgres.js: a reserved connection, BEGIN, tenant set first, fn gets the
 * transaction's sql (tx`...`, tx.unsafe, tx.savepoint), COMMIT, then the
 * session reset.
 */
export async function withTenantPostgres<T>(
  sql: PostgresJs, tenantOrFn: string | ((tx: PostgresJsTx) => Promise<T>),
  maybeFn?: (tx: PostgresJsTx) => Promise<T>,
): Promise<T> {
  refuseNested(sql);
  if (!isPostgresJs(sql)) throw new TypeError("DB Firewall: withTenantPostgres needs a postgres() instance");
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  const r = await reservePostgres(sql);
  return onReserved(r, (state) => r.begin(async () => {
    state.entered = await enter((text, values) => r.unsafe(text, values), tenant);
    // Settle an array of queries here, while the handle is still open.
    return withHandle(r, async (h: PostgresJsTx) => (await settle(await fn(h))) as T);
  }));
}

/**
 * Drizzle: db.transaction(), tenant set first with Drizzle's own sql template.
 * The transaction runs on one connection this function holds (a pg client, or
 * a reserved postgres.js connection), with the same dialect, schema and
 * logger, and the session is reset after COMMIT.
 */
export async function withTenantDrizzle<T>(
  db: DrizzleDb, tenantOrFn: string | ((tx: DrizzleTx) => Promise<T>),
  maybeFn?: (tx: DrizzleTx) => Promise<T>,
): Promise<T> {
  refuseNested(db);
  if (!isDrizzle(db)) throw new TypeError("DB Firewall: withTenantDrizzle needs a Drizzle database");
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  const { sql } = await import("drizzle-orm");       // optional peer: only Drizzle users need it
  // Drizzle's own sql template; $n placeholders map to the values in order.
  const runOn = (tx: DrizzleTx): Run => async (text, values = []) => {
    const parts = text.split(/\$\d+/);
    return rowsOf(await tx.execute(sql.join(parts.flatMap((p, i) =>
      i < values.length ? [sql.raw(p), sql`${values[i]}`] : [sql.raw(p)]))));
  };
  const base = (db as any).$client;
  if (isPostgresJs(base)) {
    const r = await reservePostgres(base);
    let bound: DrizzleDb;
    try {
      bound = rebind(db, r);
    } catch (err) { r.release(); throw err; }
    return onReserved(r, (state) => bound.transaction(async (tx) => {
      state.entered = await enter(runOn(tx), tenant);
      const result = await withHandle(tx, fn);
      await alive(runOn(tx));
      return result;
    }));
  }
  if (isPgPool(base) || isPgClient(base)) {
    const pooled = isPgPool(base) ? await base.connect() : undefined;
    const client: PgQueryable = pooled ?? base;
    let bound: DrizzleDb;
    try {
      bound = rebind(db, client);
    } catch (err) { pooled?.release(); throw err; }
    return onClient(client, pooled, (state) => bound.transaction(async (tx) => {
      state.entered = await enter(runOn(tx), tenant);
      const result = await withHandle(tx, fn);
      await alive(runOn(tx));
      return result;
    }));
  }
  throw new TypeError("DB Firewall: withTenantDrizzle supports Drizzle on node-postgres or postgres.js");
}

/** Drizzle hides COMMIT's result, and COMMIT of an aborted transaction rolls it
 *  back without an error: probe first, so the call fails instead. */
async function alive(run: Run): Promise<void> {
  try {
    await run("SELECT 1");
  } catch (err) {
    throw new SessionResetError(`DB Firewall: the function left the transaction aborted (${(err as Error).message})`);
  }
}

/** The same Drizzle database (dialect, relational schema, session options such
 *  as the logger) on one client. Fails closed if Drizzle's shape is unknown. */
function rebind(db: DrizzleDb, client: unknown): DrizzleDb {
  const d = db as any;
  if (typeof d.constructor !== "function" || typeof d.session?.constructor !== "function" || !d.dialect || !d._) {
    throw new TypeError("DB Firewall: unsupported Drizzle version (cannot hold one connection for the call)");
  }
  // The relational config Drizzle built (for tx.query.*), not only the tables.
  const schema = d._.schema
    ? { schema: d._.schema, fullSchema: d._.fullSchema, tableNamesMap: d._.tableNamesMap } : undefined;
  const session = new d.session.constructor(client, d.dialect, schema, d.session.options);
  return new d.constructor(d.dialect, session, schema);
}

/**
 * Run fn in one transaction as one tenant, on a node-postgres Pool or client,
 * a postgres.js instance, or a Drizzle database. The tenant is the explicit
 * one, else the one from runWithTenant() / bindTenant(); with neither it
 * throws before touching the database (fail closed). fn gets a handle that
 * stops working when fn settles.
 */
export async function withTenant<T>(db: unknown, tenantOrFn: string | ((tx: any) => Promise<T>),
                                    maybeFn?: (tx: any) => Promise<T>): Promise<T> {
  refuseNested(db);
  if (isDrizzle(db)) return withTenantDrizzle(db, tenantOrFn, maybeFn);
  if (isPostgresJs(db)) return withTenantPostgres(db, tenantOrFn, maybeFn);
  if (isPgPool(db) || isPgClient(db)) return withTenantPg(db, tenantOrFn, maybeFn);
  throw new TypeError(
    "DB Firewall: withTenant() supports pg.Pool / pg.Client, postgres.js and Drizzle databases; " +
    "a wrapper (pg-promise, Knex, ...) could run each statement on a different connection");
}

/** Run one read-only statement outside any tenant (used by assertSafeRole). */
export async function queryRows(db: unknown, text: string): Promise<any[]> {
  if (isDrizzle(db)) {
    return rowsOf(await db.execute(text));
  }
  if (isPostgresJs(db)) return db.unsafe(text);
  if (isPgPool(db) || isPgClient(db)) return (await db.query(text)).rows;
  throw new TypeError("DB Firewall: unsupported database client (pg.Pool / pg.Client, " +
                      "postgres.js or a Drizzle database)");
}

function split<F>(tenantOrFn: string | F, maybeFn?: F): [string, F] {
  if (typeof tenantOrFn === "function") return [resolveTenant(), tenantOrFn as F];
  if (typeof maybeFn !== "function") throw new TypeError("DB Firewall: withTenant needs a function");
  return [resolveTenant(tenantOrFn as string), maybeFn];
}
