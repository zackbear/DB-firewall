"""DB Firewall: ProtectedCursor, ProtectedConnection and protect()."""

import logging
from typing import Optional

from .engines import DBEngine, detect_engine
from .context import TenantContext
from .db_context import _CONTEXT_SETTERS, clear_db_context
from .introspection import _conn_table_cache
from .rewrite import check_no_tenant, rewrite_query, validate_tenant_id
from .config import db_context_enabled, load_config
from .resolution import is_excluded, resolve_tenant
from .audit import log_query, write_assignment

logger = logging.getLogger("db_firewall")

# ============================================================================
# PROTECTED CURSOR — Intercepts all SQL execution
# ============================================================================

# Driver methods that run SQL. The wrappers implement the ones they know; any
# other attribute with one of these names (or an ``execute*`` / ``copy*``
# prefix) is refused instead of delegated, so a new driver entry point fails
# closed rather than bypassing the firewall (H5).
_SQL_METHOD_NAMES = frozenset({
    "stream", "callproc", "executescript", "exec_driver_sql", "run", "query",
    "copy_expert", "copy_from", "copy_to", "execute_batch", "execute_values"})


def _is_sql_method(name: str) -> bool:
    return name in _SQL_METHOD_NAMES or name.startswith(("execute", "copy"))


class ProtectedCursor:
    """Wraps a DB-API cursor to enforce tenant isolation on every query."""

    def __init__(self, cursor, tenant_id: str, config: dict,
                 connection=None, engine: str = DBEngine.UNKNOWN, bypass: bool = False):
        self._cursor = cursor
        self._tenant_id = tenant_id
        self._config = config
        self._connection = connection
        self._engine = engine
        self._bypass = bypass           # DB user in excluded_users: not scoped

    def _guard(self, sql: str) -> str:
        """Rewrite (tenant set) or fail-closed check (no tenant); one code
        path for execute / executemany / stream / copy (H7)."""
        if self._bypass:
            pass
        elif self._tenant_id:
            sql = rewrite_query(sql, self._tenant_id, self._config,
                                self._connection, self._engine)
        elif self._config.get("fail_mode", "closed") == "closed":
            check_no_tenant(sql, self._config, self._connection, self._engine)
        log_query(self._tenant_id, sql, self._config)
        return sql

    def execute(self, sql: str, params=None, **kwargs):
        sql = self._guard(sql)
        logger.debug(f"DB Firewall: Executing: {sql[:200]}")
        if params:
            return self._cursor.execute(sql, params, **kwargs)
        return self._cursor.execute(sql, **kwargs)

    def executemany(self, sql: str, params_list, **kwargs):
        sql = self._guard(sql)
        return self._cursor.executemany(sql, params_list, **kwargs)

    def stream(self, sql: str, params=None, **kwargs):            # psycopg3
        sql = self._guard(sql)
        return self._cursor.stream(sql, params, **kwargs)

    def copy(self, sql: str, params=None, **kwargs):              # psycopg3
        sql = self._guard(sql)              # COPY is never allow-listed with a tenant
        return self._cursor.copy(sql, params, **kwargs)

    def __getattr__(self, name):
        if _is_sql_method(name):
            raise PermissionError(f"DB Firewall: cursor.{name}() is not mediated; refused")
        return getattr(self._cursor, name)

    def __iter__(self):
        return iter(self._cursor)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._cursor.close()


# ============================================================================
# PROTECTED CONNECTION — The main wrapper
# ============================================================================

class ProtectedConnection:
    """Wraps a DB-API connection with tenant isolation."""

    def __init__(self, connection, tenant_id: str, config: dict, engine: str,
                 bypass: bool = False):
        self._connection = connection
        self._tenant_id = tenant_id
        self._config = config
        self._engine = engine
        self._bypass = bypass
        self._db_context = not bypass and db_context_enabled(config, engine)

        if tenant_id is not None:
            validate_tenant_id(tenant_id)

        # Set database-level context if engine supports it (and an audit row)
        setter = _CONTEXT_SETTERS.get(engine) if self._db_context else None
        if setter and tenant_id:
            try:
                setter(connection, tenant_id)
                write_assignment(connection, engine, tenant_id, config)
                logger.info(f"DB Firewall: Set DB-level context for {engine}")
            except Exception as e:
                # Silent fallback would leave the DB layer unguarded: fail closed.
                if config.get("fail_mode", "closed") == "closed":
                    raise
                logger.warning(f"DB Firewall: Could not set DB context: {e}; "
                               "fail_mode=open, middleware-only enforcement")

        # The shared request context is deliberately NOT changed here: a
        # connection can outlive the scope it was made in, and restoring a
        # context out of order brings back a stale tenant. Cursors carry
        # self._tenant_id, which is all the enforcement needs.

    def cursor(self, *args, **kwargs):
        raw_cursor = self._connection.cursor(*args, **kwargs)
        return ProtectedCursor(
            raw_cursor, self._tenant_id, self._config,
            self._connection, self._engine, self._bypass
        )

    # psycopg3 / sqlite3 connection-level shortcuts: route through a
    # ProtectedCursor so they are mediated like cursor.execute() (H5).
    def execute(self, sql: str, params=None, **kwargs):
        cur = self.cursor()
        cur.execute(sql, params, **kwargs)
        return cur

    def executemany(self, sql: str, params_list, **kwargs):
        cur = self.cursor()
        cur.executemany(sql, params_list, **kwargs)
        return cur

    def stream(self, sql: str, params=None, **kwargs):
        return self.cursor().stream(sql, params, **kwargs)

    def copy(self, sql: str, params=None, **kwargs):
        return self.cursor().copy(sql, params, **kwargs)

    def pipeline(self, *args, **kwargs):
        # Pipeline mode batches round trips; statements still come from this
        # wrapper's cursors, so delegating the context manager is safe.
        return self._connection.pipeline(*args, **kwargs)

    def __getattr__(self, name):
        if _is_sql_method(name):
            raise PermissionError(f"DB Firewall: connection.{name}() is not mediated; refused")
        return getattr(self._connection, name)

    def __enter__(self):
        return self

    def release(self):
        """Drop the DB-side tenant context without closing the
        underlying connection. Call before handing it back to a pool.

        PostgreSQL: the transaction-local tenant dies with the transaction
        regardless. A SESSION-scoped value is cleared transactionally here and
        committed only when no transaction is open; if you release() inside an
        open transaction that is then rolled back, the pool's ``reset`` hook
        must be ``pool_checkin`` (which rolls back, clears and commits)."""
        if self._db_context:
            clear_db_context(self._connection, self._engine)

    def __exit__(self, *args):
        self.release()
        self._connection.__exit__(*args) if hasattr(self._connection, '__exit__') else None

    def close(self):
        self.release()
        self._connection.close()


# ============================================================================
# PUBLIC API
# ============================================================================

def protect(connection, tenant_id: Optional[str] = None,
            config: Optional[dict] = None) -> ProtectedConnection:
    """
    Wrap any database connection with tenant isolation.

    Args:
        connection: Any DB-API 2.0 connection (psycopg2, mysql-connector, etc.)
        tenant_id:  Explicit tenant ID. If None: the request's TenantContext,
                    then the config "resolution" sources in order (default:
                    TENANT_ID env var, then _firewall_tenant_map).
        config:     Override configuration dict. If None, load_config():
                    DB_FIREWALL_CONFIG, else defaults.

    A connection whose DB user is in excluded_users is returned unscoped.

    Returns:
        ProtectedConnection that silently filters all queries.
    """
    if config is None:
        config = load_config()

    engine = detect_engine(connection)
    _conn_table_cache(connection).clear()   # schema may have changed since last protect()

    if is_excluded(connection, engine, config):
        return ProtectedConnection(connection, None, config, engine, bypass=True)

    if tenant_id is None:
        tenant_id = TenantContext.get()     # always first: never overridden by config
    if tenant_id is None:
        tenant_id = resolve_tenant(connection, engine, config)

    if tenant_id is None and config.get("fail_mode") == "closed":
        logger.warning("DB Firewall: No tenant resolved. All DML will be blocked.")

    return ProtectedConnection(connection, tenant_id, config, engine)
