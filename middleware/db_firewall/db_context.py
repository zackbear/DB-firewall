"""DB Firewall: Database-side tenant context: set, clear, pool check-in."""

import hashlib
import hmac
import json
import logging
import os
import weakref
from typing import Optional

from .engines import placeholder, DBEngine, _is_autocommit, _pg_transaction_idle, detect_engine

logger = logging.getLogger("db_firewall")

# ============================================================================
# DATABASE-SPECIFIC CONTEXT SETTERS
# ============================================================================

TENANT_KEY_ENV = "DB_FIREWALL_TENANT_KEY"
_warned_unsigned = False

# The session settings and role a connection had when the middleware first set
# a tenant on it, before any SQL it protects ran: what the reset on release()
# and pool_checkin() restores. Taken later, it would restore settings that SQL
# (an agent's, say) changed, such as a search_path to a planted view.
_baselines: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_DEFAULT_BASELINE = json.dumps({"role": "none"})


# Connections released inside an open transaction: the app commits after the
# reset, and a deferred trigger firing at that COMMIT could undo it. The next
# _set_context_postgres on such a connection resets again first.
_reset_pending: "weakref.WeakSet" = weakref.WeakSet()

_RESET = "db_firewall._firewall_reset_session(%s::pg_catalog.text::pg_catalog.jsonb)"


def _remember_baseline(connection, settings) -> None:
    if settings is None:
        return
    try:
        _baselines.setdefault(connection, settings if isinstance(settings, str) else json.dumps(settings))
    except TypeError:               # a driver connection that takes no weak reference
        pass


def _baseline(connection) -> str:
    try:
        return _baselines.get(connection, _DEFAULT_BASELINE)
    except TypeError:
        return _DEFAULT_BASELINE


def tenant_key() -> Optional[bytes]:
    """The signing key from DB_FIREWALL_TENANT_KEY (hex), or None when unset."""
    raw = os.environ.get(TENANT_KEY_ENV, "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise RuntimeError(f"DB Firewall: {TENANT_KEY_ENV} must be hex") from None
    if not 32 <= len(key) <= 64:
        raise RuntimeError(f"DB Firewall: {TENANT_KEY_ENV} must be 32 to 64 bytes")
    return key


def sign_tenant(key: bytes, nonce: str, tenant_id: str) -> str:
    """hex(HMAC-SHA256(key, nonce:tenant)), as db_firewall._firewall_sign() computes it."""
    return hmac.new(key, f"{nonce}:{tenant_id}".encode("utf-8"), hashlib.sha256).hexdigest()


def _set_context_postgres(connection, tenant_id: str):
    """Set tenant via a TRANSACTION-local GUC (set_config(..., true)).

    Session scope (false) survives commit and leaks to the next borrower of a
    pooled connection. Local scope dies with the transaction, so it needs one:
    in the DB-API default (autocommit=False) the driver opens it implicitly.

    Signed context (the migration's default): app.tenant_sig signs the tenant
    for this transaction with DB_FIREWALL_TENANT_KEY, so SQL run later in the
    transaction cannot switch tenants. Without the key the tenant is set
    unsigned, which a signed database treats as no tenant (no rows).
    """
    if _is_autocommit(connection):
        raise RuntimeError(
            "DB Firewall: PostgreSQL tenant context is transaction-local and "
            "cannot be set on an autocommit connection. Disable autocommit "
            "(connection.autocommit = False). Only fail_mode: open falls back "
            "to middleware-only enforcement, with a warning."
        )
    global _warned_unsigned
    key = tenant_key()
    cursor = connection.cursor()
    try:
        pending = connection in _reset_pending
    except TypeError:
        pending = False
    if pending:
        cursor.execute(f"SELECT {_RESET}", (_baseline(connection),))
        _reset_pending.discard(connection)
    if key is None:
        if not _warned_unsigned:
            _warned_unsigned = True
            logger.warning(f"DB Firewall: {TENANT_KEY_ENV} is not set: the PostgreSQL tenant "
                           "context is unsigned. A database migrated with the default signed "
                           "context then shows no rows. Set it, or migrate with tenant_context: plain.")
        cursor.execute("SELECT set_config('app.current_tenant', %s, true), "
                       "db_firewall._firewall_session_settings()::text", (tenant_id,))
        _remember_baseline(connection, cursor.fetchone()[1])
    else:
        cursor.execute("SELECT db_firewall._firewall_nonce(), db_firewall._firewall_session_settings()::text")
        nonce, settings = cursor.fetchone()
        _remember_baseline(connection, settings)
        sig = sign_tenant(key, nonce, tenant_id)
        cursor.execute("SELECT set_config('app.current_tenant', %s, true), "
                       "set_config('app.tenant_sig', %s, true)", (tenant_id, sig))
    cursor.close()


def _clear_context_postgres(connection):
    # Belt for session-scoped values (e.g. set by _firewall_set_tenant() SQL).
    # Transaction-local values are already dropped by commit/rollback.
    #
    # GUC changes are transactional: a clear issued inside a transaction the
    # caller later rolls back (or a pool rolls back on return) is undone and
    # the old session value comes back for the next borrower. When no
    # transaction is open the clear opens one of its own, so commit it here.
    # When the caller's transaction is open we must not decide its fate; the
    # pool reset hook (pool_checkin) rolls back first and then clears.
    was_idle = _pg_transaction_idle(connection)
    cursor = connection.cursor()
    # _firewall_reset_session also undoes session state SQL run on this
    # connection may have left for its next user (another tenant): temp
    # objects, SQL-level prepared statements, custom settings, cursors,
    # LISTEN, advisory locks. It restores the settings and role the connection
    # had before the middleware first set a tenant on it.
    cursor.execute("SELECT set_config('app.current_tenant', '', false), "
                   f"set_config('app.tenant_sig', '', false), {_RESET}", (_baseline(connection),))
    cursor.close()
    if not was_idle:
        try:
            _reset_pending.add(connection)
        except TypeError:           # no weak reference: pool_checkin is then the only safe path
            pass
    if was_idle and not _is_autocommit(connection) and hasattr(connection, "commit"):
        connection.commit()


def _set_context_mysql(connection, tenant_id: str):
    """Set tenant via MySQL session variable."""
    cursor = connection.cursor()
    cursor.execute("SET @_fw_tenant_id = %s", (tenant_id,))
    cursor.close()


def _clear_context_mysql(connection):
    cursor = connection.cursor()
    cursor.execute("SET @_fw_tenant_id = NULL")
    cursor.close()


def _set_context_sqlserver(connection, tenant_id: str):
    """Set tenant via SQL Server SESSION_CONTEXT."""
    cursor = connection.cursor()
    # pyodbc binds "?", pymssql binds "%s": use the driver's own marker.
    cursor.execute(f"EXEC sp_set_session_context @key=N'tenant_id', @value={placeholder(connection)}",
                   (tenant_id,))
    cursor.close()


def _clear_context_sqlserver(connection):
    cursor = connection.cursor()
    cursor.execute("EXEC sp_set_session_context @key=N'tenant_id', @value=NULL")
    cursor.close()


def _set_context_oracle(connection, tenant_id: str):
    """Set tenant via Oracle application context."""
    cursor = connection.cursor()
    cursor.execute(
        "BEGIN PKG_SAAS_SECURITY.set_tenant(:1); END;",
        (tenant_id,)
    )
    cursor.close()


def _clear_context_oracle(connection):
    # clear_tenant is defined in migrations/004_oracle.sql
    cursor = connection.cursor()
    cursor.execute("BEGIN PKG_SAAS_SECURITY.clear_tenant; END;")
    cursor.close()


_CONTEXT_SETTERS = {
    DBEngine.POSTGRESQL: _set_context_postgres,
    DBEngine.MYSQL: _set_context_mysql,
    DBEngine.SQLSERVER: _set_context_sqlserver,
    DBEngine.ORACLE: _set_context_oracle,
}

_CONTEXT_CLEARERS = {
    DBEngine.POSTGRESQL: _clear_context_postgres,
    DBEngine.MYSQL: _clear_context_mysql,
    DBEngine.SQLSERVER: _clear_context_sqlserver,
    DBEngine.ORACLE: _clear_context_oracle,
}


def clear_db_context(connection, engine: Optional[str] = None) -> None:
    """Clear the DB-side tenant context on a raw connection. Logs, never raises."""
    if engine is None:
        engine = detect_engine(connection)
    clearer = _CONTEXT_CLEARERS.get(engine)
    if not clearer:
        return
    try:
        clearer(connection)
    except Exception as e:
        if engine == DBEngine.POSTGRESQL:
            # The session reset failed: the connection may carry another
            # tenant's traps, so it must not be used again.
            _close(connection)
            logger.error(f"DB Firewall: could not reset the PostgreSQL session; connection closed: {e}")
            return
        logger.warning(f"DB Firewall: Could not clear DB context ({engine}): {e}")


def _close(connection) -> None:
    try:
        connection.close()
    except Exception:
        pass


def pool_checkin(connection, engine: Optional[str] = None) -> None:
    """
    Reset hook for connection pools: clears tenant context on a raw connection
    being returned to the pool and leaves it idle (no open transaction).

    Hook it in:
        psycopg_pool.ConnectionPool(dsn, reset=pool_checkin)
        sqlalchemy: event.listen(engine.pool, "checkin",
                                 lambda dbapi_conn, rec: pool_checkin(dbapi_conn))

    This hook is REQUIRED for PostgreSQL pools where a SESSION-scoped value
    may exist (_firewall_set_tenant() SQL, auto-resolve, legacy code):
    ProtectedConnection.release() clears it transactionally, and a pool that
    rolls back on return undoes that clear. Here we roll back first, then
    clear and commit, so the clear survives whatever the borrower left open.
    """
    if engine is None:
        engine = detect_engine(connection)
    clearer = _CONTEXT_CLEARERS.get(engine)
    if not clearer:
        return  # engine without DB-side context: nothing to clear (benign)
    try:
        # Discard whatever transaction the borrower left open (pools do this
        # before calling us anyway) so the clear below is not rolled back later.
        if not _is_autocommit(connection) and hasattr(connection, "rollback"):
            connection.rollback()
        clearer(connection)
        # The clear statement opens an implicit transaction in non-autocommit
        # mode; commit it so it sticks (no-op when the clearer already did).
        if not _is_autocommit(connection) and hasattr(connection, "commit"):
            connection.commit()
    except Exception as e:
        # A dead connection must NOT be returned to the pool with stale
        # context: re-raise so the pool (psycopg_pool reset=, SQLAlchemy
        # checkin) discards it. Only swallow when the connection is healthy.
        if getattr(connection, "closed", False) or _is_connection_error(e):
            raise
        if engine == DBEngine.POSTGRESQL:
            # The session reset failed (SQL the borrower ran may have broken
            # it on purpose): close the connection, and raise so the pool
            # discards it, instead of handing its state to the next borrower.
            _close(connection)
            raise
        logger.warning(f"DB Firewall: Could not clear DB context ({engine}): {e}")


def _is_connection_error(exc: BaseException) -> bool:
    """DB-API OperationalError/InterfaceError (any driver) signal a broken link."""
    return any(k.__name__ in ("OperationalError", "InterfaceError")
               for k in type(exc).__mro__)
