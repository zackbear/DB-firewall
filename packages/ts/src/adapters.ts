import { CLEAR_TENANT, scoped } from "./sign.js";
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
const BLOCKED = new Set<PropertyKey>(["release", "connect", "end"]);
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
 * node-postgres: BEGIN, set the tenant for this transaction only, run fn with
 * the transaction's client, then COMMIT (ROLLBACK if fn throws). A Pool lends
 * one client for the call and gets it back clean. Pass a Pool, or a client
 * that is not inside a transaction: this function's COMMIT would also commit
 * a transaction the caller opened.
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
  let failed: Error | undefined;
  try {
    try {
      await client.query("BEGIN");
    } catch (err) {
      failed = err as Error;          // the connection is suspect: discard it
      throw err;
    }
    try {
      const result = await scoped(async (text, values) => (await client.query(text, values)).rows, tenant,
                                  () => withHandle(client, fn));
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch((e) => { failed = e as Error; });
      throw err;
    }
  } finally {
    if (!failed) {                    // pooled or not: no session-level tenant survives
      await client.query(CLEAR_TENANT).catch((e) => { failed = e as Error; });
    }
    pooled?.release(failed);          // a failed ROLLBACK or clear destroys the connection
  }
}

/** postgres.js: sql.begin(), tenant set first, fn gets the transaction's sql. */
export async function withTenantPostgres<T>(
  sql: PostgresJs, tenantOrFn: string | ((tx: PostgresJsTx) => Promise<T>),
  maybeFn?: (tx: PostgresJsTx) => Promise<T>,
): Promise<T> {
  refuseNested(sql);
  if (!isPostgresJs(sql)) throw new TypeError("DB Firewall: withTenantPostgres needs a postgres() instance");
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  return sql.begin(async (tx) => {
    // postgres.js resolves an array of queries returned from begin(): settle it
    // here, while the handle is still open.
    return scoped((text, values) => tx.unsafe(text, values), tenant, () => withHandle(tx, async (h) => {
      const result: unknown = await fn(h);
      return (Array.isArray(result) ? await Promise.all(result) : result) as T;
    }));
  });
}

/** Drizzle: db.transaction(), tenant set first with Drizzle's own sql template. */
export async function withTenantDrizzle<T>(
  db: DrizzleDb, tenantOrFn: string | ((tx: DrizzleTx) => Promise<T>),
  maybeFn?: (tx: DrizzleTx) => Promise<T>,
): Promise<T> {
  refuseNested(db);
  if (!isDrizzle(db)) throw new TypeError("DB Firewall: withTenantDrizzle needs a Drizzle database");
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  const { sql } = await import("drizzle-orm");       // optional peer: only Drizzle users need it
  return db.transaction(async (tx) => {
    // Drizzle's own sql template; $n placeholders map to the values in order.
    const run = async (text: string, values: unknown[] = []) => {
      const parts = text.split(/\$\d+/);
      return rowsOf(await tx.execute(sql.join(parts.flatMap((p, i) =>
        i < values.length ? [sql.raw(p), sql`${values[i]}`] : [sql.raw(p)]))));
    };
    return scoped(run, tenant, () => withHandle(tx, fn));
  });
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
