import { TENANT_SETTING, resolveTenant } from "./tenant.js";

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

const SET_TENANT = `SELECT set_config('${TENANT_SETTING}', $1, true)`;

function isPgPool(db: any): db is PgPool {
  return typeof db?.connect === "function" && typeof db?.query === "function"
    && typeof db?.totalCount === "number";
}
function isPgClient(db: any): db is PgQueryable {
  return typeof db?.query === "function" && typeof db?.connect === "function"
    && typeof db?.totalCount !== "number";
}
function isPostgresJs(db: any): db is PostgresJs {
  return typeof db === "function" && typeof db.begin === "function" && typeof db.unsafe === "function";
}
function isDrizzle(db: any): db is DrizzleDb {
  return typeof db?.transaction === "function" && typeof db?.execute === "function"
    && typeof db?.select === "function";
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
      await client.query(SET_TENANT, [tenant]);
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch((e) => { failed = e as Error; });
      throw err;
    }
  } finally {
    pooled?.release(failed);          // a failed ROLLBACK destroys the connection
  }
}

/** postgres.js: sql.begin(), tenant set first, fn gets the transaction's sql. */
export async function withTenantPostgres<T>(
  sql: PostgresJs, tenantOrFn: string | ((tx: PostgresJsTx) => Promise<T>),
  maybeFn?: (tx: PostgresJsTx) => Promise<T>,
): Promise<T> {
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  return sql.begin(async (tx) => {
    await tx.unsafe(SET_TENANT, [tenant]);
    return fn(tx);
  });
}

/** Drizzle: db.transaction(), tenant set first with Drizzle's own sql template. */
export async function withTenantDrizzle<T>(
  db: DrizzleDb, tenantOrFn: string | ((tx: DrizzleTx) => Promise<T>),
  maybeFn?: (tx: DrizzleTx) => Promise<T>,
): Promise<T> {
  const [tenant, fn] = split(tenantOrFn, maybeFn);
  const { sql } = await import("drizzle-orm");       // optional peer: only Drizzle users need it
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config(${TENANT_SETTING}, ${tenant}, true)`);
    return fn(tx);
  });
}

/**
 * Run fn in one transaction as one tenant, on a node-postgres Pool or client,
 * a postgres.js instance, or a Drizzle database. The tenant is the explicit
 * one, else the one from runWithTenant() / bindTenant(); with neither it
 * throws before touching the database (fail closed).
 */
export function withTenant<T>(db: unknown, tenantOrFn: string | ((tx: any) => Promise<T>),
                              maybeFn?: (tx: any) => Promise<T>): Promise<T> {
  if (isDrizzle(db)) return withTenantDrizzle(db, tenantOrFn, maybeFn);
  if (isPostgresJs(db)) return withTenantPostgres(db, tenantOrFn, maybeFn);
  if (isPgPool(db) || isPgClient(db)) return withTenantPg(db, tenantOrFn, maybeFn);
  return Promise.reject(new TypeError(
    "DB Firewall: withTenant() supports node-postgres, postgres.js and Drizzle; " +
    "use withTenantPg / withTenantPostgres / withTenantDrizzle for a wrapped client"));
}

/** Run one read-only statement outside any tenant (used by assertSafeRole). */
export async function queryRows(db: unknown, text: string): Promise<any[]> {
  if (isDrizzle(db)) {
    const res: any = await db.execute(text);
    return Array.isArray(res) ? res : res.rows;
  }
  if (isPostgresJs(db)) return db.unsafe(text);
  if (isPgPool(db) || isPgClient(db)) return (await db.query(text)).rows;
  throw new TypeError("DB Firewall: unsupported database client");
}

function split<F>(tenantOrFn: string | F, maybeFn?: F): [string, F] {
  if (typeof tenantOrFn === "function") return [resolveTenant(), tenantOrFn as F];
  if (typeof maybeFn !== "function") throw new TypeError("DB Firewall: withTenant needs a function");
  return [resolveTenant(tenantOrFn as string), maybeFn];
}
