"""DB Firewall: Table introspection: does a table carry the tenant column (cached)."""

import re
import time
import logging
import threading
import weakref
from typing import Optional, Dict

from .engines import DBEngine, _pg_transaction_idle

logger = logging.getLogger("db_firewall")

# ============================================================================
# TABLE INTROSPECTION
# ============================================================================

# Metadata answers are cached per connection (cleared by protect()) and, when
# the driver exposes a DSN, per (engine, dsn, table) across connections. Both
# expire after TABLE_CACHE_TTL seconds and only ever hold successful lookups:
# a failed lookup raises (fail closed) and is never cached (C9).
TABLE_CACHE_TTL = 60.0
_table_cache: Dict[tuple, tuple] = {}            # key -> (has_col, expires_at)
_cache_lock = threading.Lock()
_conn_cache: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_META_SAVEPOINT = "__dbfw_meta"


def _conn_table_cache(connection) -> Dict[tuple, tuple]:
    try:
        return _conn_cache.setdefault(connection, {})
    except TypeError:               # connection object is not weak-referenceable
        return {}


def _conn_dsn(connection) -> Optional[str]:
    dsn = getattr(connection, "dsn", None)                       # psycopg2
    if dsn is None:
        dsn = getattr(getattr(connection, "info", None), "dsn", None)   # psycopg3
    return dsn if isinstance(dsn, str) else None


def _in_transaction(connection) -> Optional[bool]:
    """True when the connection has an open (or aborted) transaction, False
    when idle, None when the driver does not say."""
    idle = _pg_transaction_idle(connection)
    if idle is not None:
        return not idle
    in_txn = getattr(connection, "in_transaction", None)         # sqlite3, mysql-connector
    return bool(in_txn) if isinstance(in_txn, bool) else None


def _fold_table_name(table_name: str, quoted: bool, engine: str) -> str:
    """Unquoted identifiers fold to the engine's canonical case; quoted ones
    keep theirs (C4)."""
    if quoted:
        return table_name
    if engine in (DBEngine.POSTGRESQL, DBEngine.MYSQL, DBEngine.SQLITE):
        return table_name.lower()
    if engine == DBEngine.ORACLE:
        return table_name.upper()
    return table_name                       # sqlserver: compared case-insensitively


def _has_tenant_column(connection, table_name: str, engine: str,
                       tenant_column: str, quoted: bool = False) -> bool:
    """Check if a table has the tenant column. Raises on lookup failure."""
    name = _fold_table_name(table_name, quoted, engine)
    key = (engine, _conn_dsn(connection), name, tenant_column)
    now = time.monotonic()
    local = _conn_table_cache(connection)
    hit = local.get(key)
    if hit is None and key[1] is not None:
        with _cache_lock:
            hit = _table_cache.get(key)
    if hit is not None and hit[1] > now:
        return hit[0]
    has_col = _has_tenant_column_uncached(connection, name, engine, tenant_column)
    entry = (has_col, now + TABLE_CACHE_TTL)
    local[key] = entry
    if key[1] is not None:
        with _cache_lock:
            _table_cache[key] = entry
    return has_col


def _has_tenant_column_uncached(connection, table_name: str, engine: str,
                                tenant_column: str) -> bool:
    """One metadata query. Runs inside a SAVEPOINT when a transaction is open
    so a failure here (or a previous statement's error) cannot be mistaken
    for "no tenant column"; any failure propagates."""
    in_txn = _in_transaction(connection)
    cursor = connection.cursor()
    try:
        if in_txn:
            cursor.execute(f"SAVEPOINT {_META_SAVEPOINT}")
        try:
            has_col = _lookup_tenant_column(cursor, table_name, engine, tenant_column)
        except Exception:
            if in_txn:
                try:
                    cursor.execute(f"ROLLBACK TO SAVEPOINT {_META_SAVEPOINT}")
                except Exception:
                    pass
            raise
        if in_txn:
            cursor.execute(f"RELEASE SAVEPOINT {_META_SAVEPOINT}")
        return has_col
    except Exception as e:
        raise PermissionError(
            f"DB Firewall: could not verify tenant column on {table_name!r} "
            f"({type(e).__name__}: {str(e).splitlines()[0][:120]}); query refused") from e
    finally:
        try:
            cursor.close()
        except Exception:
            pass


def _lookup_tenant_column(cursor, table_name: str, engine: str, tenant_column: str) -> bool:
    if engine == DBEngine.POSTGRESQL:
        cursor.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = %s",
            (table_name, tenant_column))
    elif engine == DBEngine.MYSQL:
        cursor.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = %s AND table_schema = DATABASE()",
            (table_name, tenant_column))
    elif engine == DBEngine.SQLSERVER:
        cursor.execute(
            "SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE LOWER(TABLE_NAME) = LOWER(?) AND LOWER(COLUMN_NAME) = LOWER(?)",
            (table_name, tenant_column))
    elif engine == DBEngine.ORACLE:
        cursor.execute(
            "SELECT 1 FROM all_tab_columns "
            "WHERE LOWER(table_name) = LOWER(:1) AND LOWER(column_name) = LOWER(:2)",
            (table_name, tenant_column))
    elif engine == DBEngine.SQLITE:
        if not re.fullmatch(r"\w+", table_name):
            raise ValueError("unsafe table name")
        cursor.execute(f'PRAGMA table_info("{table_name}")')
        return any(row[1].lower() == tenant_column.lower() for row in cursor.fetchall())
    else:
        raise RuntimeError(f"no column metadata lookup for engine {engine!r}")
    return cursor.fetchone() is not None
