"""
DB Firewall — Universal AI Agent Tenant Isolation Middleware
=============================================================
Drop-in middleware that wraps any Python database connection with
automatic tenant isolation. Works with any DB-API 2.0 connection
(psycopg2, mysql-connector, pyodbc, sqlite3) and any ORM
(SQLAlchemy, Django, Peewee, Tortoise).

Usage:
    from db_firewall import protect, set_tenant

    # Wrap any connection
    conn = psycopg2.connect(...)
    safe_conn = protect(conn, tenant_id="TENANT_A")

    # Or auto-resolve from environment / mapping
    safe_conn = protect(conn)

    # All queries are now silently filtered
    cursor = safe_conn.cursor()
    cursor.execute("SELECT * FROM orders")  # Only returns TENANT_A rows
"""

import os
import re
import time
import json
import logging
import hashlib
import threading
import functools
import contextvars
import uuid
import weakref
from pathlib import Path
from typing import Optional, Dict, List, Any, Union
from datetime import datetime, timezone
from contextlib import contextmanager

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:                                    # package import (middleware.db_firewall)
    from . import sql_rewriter as _sqlr
except ImportError:                     # flat import (sys.path += middleware/)
    import sql_rewriter as _sqlr

logger = logging.getLogger("db_firewall")

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    "tenant_column": "tenant_id",
    "fail_mode": "closed",
    # "ast" (sqlglot, scopes CTEs/UNION/joins/INSERT..SELECT) or "regex" (legacy,
    # refuses those shapes). "ast" raises ImportError when sqlglot is missing.
    "rewriter": "ast",
    # INSERT ... (tenant_id) VALUES (%s): the bound value is the caller's, not
    # the firewall's. Refused unless this is true (then RLS WITH CHECK is the
    # only guard on it).
    "allow_tenant_placeholder": False,
    # Web integrations: trust the X-Tenant-ID request header only when an
    # upstream gateway sets it after authenticating the caller. Any client can
    # send that header, so it is off by default. ?tenant_id= is never trusted.
    "trust_tenant_header": False,
    "protect": {"select": True, "insert": True, "update": True, "delete": True},
    "audit": {"enabled": True, "table_name": "_firewall_audit_log", "retention_days": 90},
    # Empty by default: managed Postgres (Supabase, Neon, RDS) apps often connect
    # as "postgres", so a built-in bypass list would disable the firewall entirely.
    "excluded_users": [],
    "excluded_tables": [
        "_firewall_*", "schema_migrations", "alembic_version",
        "knex_migrations", "prisma_migrations", "flyway_schema_history",
        "__diesel_schema_migrations", "app_config", "feature_flags"
    ],
}


def load_config(project_root: Optional[str] = None) -> dict:
    """Load configuration from .db-firewall.yaml or environment."""
    config = DEFAULT_CONFIG.copy()

    search_paths = []
    if project_root:
        search_paths.append(Path(project_root))
    search_paths.extend([Path.cwd(), Path.home()])

    for base in search_paths:
        for name in [".db-firewall.yaml", ".db-firewall.yml", ".db-firewall.json"]:
            cfg_path = base / name
            if cfg_path.exists():
                with open(cfg_path) as f:
                    if name.endswith(".json"):
                        user_config = json.load(f)
                    elif HAS_YAML:
                        user_config = yaml.safe_load(f)
                    else:
                        logger.warning("PyYAML not installed; using default config")
                        continue
                config.update(user_config or {})
                logger.info(f"DB Firewall: Loaded config from {cfg_path}")
                return _apply_env_overrides(config)

    return _apply_env_overrides(config)


def _apply_env_overrides(config: dict) -> dict:
    """Environment variables win over both defaults and a discovered config file."""
    for env, key in (("DB_FIREWALL_TENANT_COLUMN", "tenant_column"),
                     ("DB_FIREWALL_FAIL_MODE", "fail_mode"),
                     ("DB_FIREWALL_REWRITER", "rewriter")):
        if os.environ.get(env):
            config[key] = os.environ[env]
    return config


# ============================================================================
# DATABASE ENGINE DETECTION
# ============================================================================

class DBEngine:
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLSERVER = "sqlserver"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


def detect_engine(connection) -> str:
    """Auto-detect database engine from connection object."""
    module = type(connection).__module__
    cls_name = type(connection).__name__

    engine_map = {
        "psycopg2": DBEngine.POSTGRESQL,
        "psycopg": DBEngine.POSTGRESQL,
        "asyncpg": DBEngine.POSTGRESQL,
        "pg8000": DBEngine.POSTGRESQL,
        "mysql": DBEngine.MYSQL,
        "pymysql": DBEngine.MYSQL,
        "MySQLdb": DBEngine.MYSQL,
        "pyodbc": DBEngine.SQLSERVER,  # Could be any ODBC; we'll refine
        "pymssql": DBEngine.SQLSERVER,
        "cx_Oracle": DBEngine.ORACLE,
        "oracledb": DBEngine.ORACLE,
        "sqlite3": DBEngine.SQLITE,
        "sqlite": DBEngine.SQLITE,
        "aiosqlite": DBEngine.SQLITE,
    }

    for key, engine in engine_map.items():
        if key in module or key in cls_name:
            return engine

    # Check pyodbc driver string
    if hasattr(connection, 'getinfo'):
        try:
            driver = connection.getinfo(17)  # SQL_DBMS_NAME
            if 'sql server' in driver.lower():
                return DBEngine.SQLSERVER
            elif 'mysql' in driver.lower():
                return DBEngine.MYSQL
            elif 'oracle' in driver.lower():
                return DBEngine.ORACLE
            elif 'postgres' in driver.lower():
                return DBEngine.POSTGRESQL
        except Exception:
            pass

    logger.warning(f"DB Firewall: Unknown engine for {module}.{cls_name}")
    return DBEngine.UNKNOWN


# ============================================================================
# TENANT CONTEXT MANAGER
# ============================================================================

_TENANT_VAR: contextvars.ContextVar = contextvars.ContextVar("db_firewall_tenant", default=None)


class TenantContext:
    """Request-scoped tenant store.

    A ContextVar keeps each thread AND each asyncio task separate. threading.local
    did not: two async requests on one event-loop thread overwrote each other's
    tenant, and sync endpoints run in a thread pool never saw it at all.
    """

    @classmethod
    def set(cls, tenant_id: str):
        _TENANT_VAR.set(tenant_id)

    @classmethod
    def get(cls) -> Optional[str]:
        return _TENANT_VAR.get()

    @classmethod
    def clear(cls):
        _TENANT_VAR.set(None)

    @classmethod
    def enter(cls, tenant_id: Optional[str]) -> contextvars.Token:
        """Set exactly this tenant (None included) for a scope; hides any
        ambient value. Pair with exit(token)."""
        return _TENANT_VAR.set(tenant_id)

    @classmethod
    def exit(cls, token: Optional[contextvars.Token]) -> None:
        """Restore the tenant that was set before enter(). A token from another
        context cannot be reset, so fail closed by clearing instead."""
        if token is None:
            return
        try:
            _TENANT_VAR.reset(token)
        except (ValueError, RuntimeError) as e:
            logger.warning(f"DB Firewall: tenant scope ended in a different context ({e}); "
                           "clearing the tenant here (fail closed)")
            _TENANT_VAR.set(None)

    @classmethod
    def require(cls) -> str:
        tenant = cls.get()
        if not tenant:
            raise PermissionError("DB Firewall: No tenant context set. Access denied.")
        return tenant


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


# ============================================================================
# SQL QUERY REWRITING — THE INVISIBLE WHERE CLAUSE
# ============================================================================

# Regex patterns for table-name extraction (pre-filter only: the AST rewriter
# makes the real decision). Optional schema prefix; quotes may follow the
# keyword directly (FROM"orders").
_IDENT = r'[`"\[]?(\w+)[`"\]]?'
_TABLE_PATTERNS = [
    re.compile(rf'\b{kw}(?:\s+|(?=[`"\[]))(?:{_IDENT}\s*\.\s*)?{_IDENT}', re.IGNORECASE)
    for kw in ("FROM", "JOIN", "INTO", "UPDATE", r"DELETE\s+FROM", "USING",
               "COPY", r"TRUNCATE(?:\s+TABLE)?")
]

_SELECT_RE = re.compile(r'\bSELECT\b', re.IGNORECASE)
_INSERT_RE = re.compile(r'\bINSERT\b', re.IGNORECASE)
_UPDATE_RE = re.compile(r'\bUPDATE\b', re.IGNORECASE)
_DELETE_RE = re.compile(r'\bDELETE\b', re.IGNORECASE)
_WHERE_RE = re.compile(r'\bWHERE\b', re.IGNORECASE)


def _extract_tables(sql: str) -> List[str]:
    """Extract table names from a SQL query."""
    tables = set()
    for pattern in _TABLE_PATTERNS:
        for match in pattern.finditer(sql):
            tables.add(match.group(2))      # group 1 = optional schema
    return list(tables)


_DML_STARTS = ("SELECT", "INSERT", "UPDATE", "DELETE")
# Shapes the regex rewriter cannot scope safely; rejected when a protected table
# is involved (fail closed) instead of being passed through half-filtered.
_UNSAFE_STARTS = ("WITH", "(", "TABLE")
_SET_OP_RE = re.compile(r'\b(UNION|INTERSECT|EXCEPT)\b', re.IGNORECASE)
_FROM_RE = re.compile(r'\bFROM\b', re.IGNORECASE)
_USING_RE = re.compile(r'\bUSING\b', re.IGNORECASE)
_TABLE_CMD_RE = re.compile(r'^\s*TABLE\s+([`"\[]?\w+[`"\]]?)', re.IGNORECASE)
_CLAUSE_RE = re.compile(r'\b(ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|FETCH|FOR)\b',
                        re.IGNORECASE)


# Shared with the AST rewriter (middleware/sql_rewriter.py).
_blank_literals = _sqlr.blank_literals
_strip_sql = _sqlr.strip_sql


def _toplevel_match(regex, clean: str):
    """First match of ``regex`` in ``clean`` that sits at parenthesis depth 0."""
    for m in regex.finditer(clean):
        if clean.count("(", 0, m.start()) == clean.count(")", 0, m.start()):
            return m
    return None


def _reject_unsafe_shape(clean: str) -> None:
    """Fail closed on statement shapes the WHERE injector cannot scope."""
    head = clean.lstrip().upper()
    why = None
    if head.startswith(_UNSAFE_STARTS):
        why = "CTE / parenthesised / TABLE statement"
    elif re.search(r';\s*\S', clean):
        why = "multiple statements"
    elif _toplevel_match(_SET_OP_RE, clean):
        why = "UNION/INTERSECT/EXCEPT"
    elif head.startswith("UPDATE") and _toplevel_match(_FROM_RE, clean):
        why = "UPDATE ... FROM"
    elif head.startswith("DELETE") and _toplevel_match(_USING_RE, clean):
        why = "DELETE ... USING"
    if why:
        raise PermissionError(
            f"DB Firewall: unsupported statement shape ({why}); "
            "cannot be safely scoped to a tenant")


def _is_excluded_table(table: str, excluded: List[str]) -> bool:
    """Check if table matches exclusion patterns."""
    import fnmatch
    for pattern in excluded:
        if fnmatch.fnmatch(table, pattern):
            return True
    return False


# Backslash: MySQL treats \' as an escape, so 'A\' would swallow the closing quote.
# Backslash: MySQL treats \' as an escape, so a tenant ending in \ would swallow
# the closing quote of the injected literal.
_BAD_TENANT_CHARS = ("\x00", "\n", "\r", "\\")


def validate_tenant_id(tenant_id: str) -> str:
    """Reject tenant ids that cannot be safely embedded in SQL or session state."""
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("DB Firewall: tenant_id must be a non-empty string")
    if any(c in tenant_id for c in _BAD_TENANT_CHARS):
        raise ValueError("DB Firewall: tenant_id contains NUL/newline/backslash characters")
    if _sqlr._PH_PREFIX in tenant_id:
        raise ValueError("DB Firewall: tenant_id contains the reserved placeholder token")
    return tenant_id


def _sql_literal(tenant_id: str) -> str:
    """Return tenant_id as a quoted SQL string literal (single quotes doubled)."""
    validate_tenant_id(tenant_id)
    return "'" + tenant_id.replace("'", "''") + "'"


def rewrite_query(sql: str, tenant_id: str, config: dict,
                  connection=None, engine: str = None) -> str:
    """
    Rewrite a SQL query to inject tenant isolation WHERE clauses.
    This is the middleware-level enforcement for engines without native RLS.

    ``config["rewriter"]``: "ast" (default, sqlglot) parses EVERY statement:
    only SELECT/INSERT/UPDATE/DELETE (and WITH-wrapped forms), transaction
    control and harmless SET/RESET get through; every protected table
    reference is scoped (CTEs, UNION branches, joins, subqueries,
    INSERT..SELECT) and what cannot be proven scoped is refused. "regex" is
    the legacy injector that refuses multi-scope shapes outright.
    """
    if not sql or not sql.strip():
        return sql

    # No tenant → don't rewrite (fail-closed is enforced by check_no_tenant)
    if tenant_id is None:
        return sql

    protect = config.get("protect", {})
    is_protected = _protected_predicate(config, connection, engine)

    if config.get("rewriter", "ast") != "regex":
        validate_tenant_id(tenant_id)
        # ImportError (sqlglot missing) propagates: never silently fall back.
        return _sqlr.rewrite(
            sql, tenant_id, config.get("tenant_column", "tenant_id"), is_protected, engine,
            protect_ops=protect,
            allow_tenant_placeholder=bool(config.get("allow_tenant_placeholder", False)))

    return _rewrite_query_regex(sql, tenant_id, config, is_protected)


def _protected_predicate(config: dict, connection, engine):
    """``is_protected(name, quoted)`` for one statement: excluded_tables glob
    (on the engine-folded name) first, then the live column check. Without a
    connection every non-excluded table counts as protected."""
    tenant_col = config.get("tenant_column", "tenant_id")
    excluded = config.get("excluded_tables", [])
    memo: Dict[tuple, bool] = {}

    def is_protected(table: str, quoted: bool = False) -> bool:
        key = (table, quoted)
        if key not in memo:
            folded = _fold_table_name(table, quoted, engine or DBEngine.UNKNOWN)
            memo[key] = not (_is_excluded_table(table, excluded)
                             or _is_excluded_table(folded, excluded)) and (
                connection is None
                or _has_tenant_column(connection, table, engine, tenant_col, quoted))
        return memo[key]
    return is_protected


def check_no_tenant(sql: str, config: dict, connection=None, engine: str = None) -> None:
    """fail_mode=closed with no tenant: raise PermissionError unless the
    statement is on the pass-through list or touches no protected table."""
    if not sql or not sql.strip():
        return
    if config.get("rewriter", "ast") != "regex":
        _sqlr.rewrite(sql, None, config.get("tenant_column", "tenant_id"),
                      _protected_predicate(config, connection, engine), engine)
        return
    if _strip_sql(sql).lstrip().upper().startswith(_DML_STARTS + _UNSAFE_STARTS):
        raise PermissionError(_sqlr._NO_TENANT_MSG)


def _rewrite_query_regex(sql: str, tenant_id: str, config: dict, is_protected) -> str:
    """Legacy path: regex table extraction gates the single-WHERE injector."""
    protect = config.get("protect", {})
    # All keyword detection runs on a copy with string literals and comments
    # blanked out, so 'UNION' inside a literal is not a set operation and a
    # WHERE inside a literal cannot misplace the injected predicate.
    clean = _strip_sql(sql)
    head = clean.lstrip().upper()

    tables = _extract_tables(clean)
    m = _TABLE_CMD_RE.match(clean)
    if m:
        tables.append(m.group(1).strip('`"[]'))
    protected_tables = [t for t in tables if is_protected(t)]

    # Non-DML (DDL, utility) is passed through — unless it names a protected
    # table (CREATE TABLE AS SELECT, MERGE INTO, COPY, TRUNCATE): fail closed.
    if not head.startswith(_DML_STARTS + _UNSAFE_STARTS):
        if protected_tables:
            raise PermissionError(
                "DB Firewall: non-DML statement references protected table(s) "
                f"{sorted(protected_tables)}; refused")
        return sql

    # Per-operation opt-out
    for op in ("select", "insert", "update", "delete"):
        if head.startswith(op.upper()) and not protect.get(op, True):
            return sql

    if not protected_tables:
        return sql

    validate_tenant_id(tenant_id)
    return _rewrite_regex(sql, clean, tenant_id, config.get("tenant_column", "tenant_id"))


def _rewrite_regex(sql: str, clean: str, tenant_id: str, tenant_col: str) -> str:
    """Legacy injector: one WHERE predicate on single-table-shaped statements."""
    head = clean.lstrip().upper()
    # A protected table in a shape we cannot scope → refuse, never half-filter
    _reject_unsafe_shape(clean)

    # For SELECT/UPDATE/DELETE: inject WHERE clause
    if head.startswith(("SELECT", "UPDATE", "DELETE")):
        tenant_predicate = f"{tenant_col} = {_sql_literal(tenant_id)}"

        where = _toplevel_match(_WHERE_RE, clean)
        if where:
            # Inject after the real (top-level, non-literal) WHERE
            sql = sql[:where.end()] + f" {tenant_predicate} AND" + sql[where.end():]
        else:
            # Find insertion point (before ORDER BY, GROUP BY, LIMIT, etc.)
            insert_before = _toplevel_match(_CLAUSE_RE, clean)
            if insert_before:
                pos = insert_before.start()
                sql = sql[:pos] + f" WHERE {tenant_predicate} " + sql[pos:]
            else:
                # Append after the last real token, i.e. before any trailing
                # comment (otherwise the predicate would be commented out).
                code_end = len(clean.rstrip())
                body = sql[:code_end].rstrip(';').rstrip()
                sql = body + f" WHERE {tenant_predicate}" + sql[code_end:]

    return sql


# ============================================================================
# DATABASE-SPECIFIC CONTEXT SETTERS
# ============================================================================

def _is_autocommit(connection) -> bool:
    return bool(getattr(connection, "autocommit", False))


def _set_context_postgres(connection, tenant_id: str):
    """Set tenant via a TRANSACTION-local GUC (set_config(..., true)).

    Session scope (false) survives commit and leaks to the next borrower of a
    pooled connection. Local scope dies with the transaction, so it needs one:
    in the DB-API default (autocommit=False) the driver opens it implicitly.
    """
    if _is_autocommit(connection):
        raise RuntimeError(
            "DB Firewall: PostgreSQL tenant context is transaction-local and "
            "cannot be set on an autocommit connection. Disable autocommit "
            "(connection.autocommit = False) or use tenant_scope() with "
            "middleware-only enforcement."
        )
    cursor = connection.cursor()
    cursor.execute("SELECT set_config('app.current_tenant', %s, true)", (tenant_id,))
    cursor.close()


def _pg_transaction_idle(connection) -> Optional[bool]:
    """True when no transaction is open (psycopg2 and psycopg3 both expose
    libpq's PQTRANS_IDLE == 0 as connection.info.transaction_status).
    None when the driver does not tell."""
    status = getattr(getattr(connection, "info", None), "transaction_status", None)
    if status is None:
        return None
    return int(status) == 0


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
    cursor.execute("SELECT set_config('app.current_tenant', '', false)")
    cursor.close()
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
    cursor.execute("EXEC sp_set_session_context @key=N'tenant_id', @value=?", (tenant_id,))
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
        logger.warning(f"DB Firewall: Could not clear DB context ({engine}): {e}")


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
        logger.warning(f"DB Firewall: Could not clear DB context ({engine}): {e}")


def _is_connection_error(exc: BaseException) -> bool:
    """DB-API OperationalError/InterfaceError (any driver) signal a broken link."""
    return any(k.__name__ in ("OperationalError", "InterfaceError")
               for k in type(exc).__mro__)


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
                 connection=None, engine: str = DBEngine.UNKNOWN):
        self._cursor = cursor
        self._tenant_id = tenant_id
        self._config = config
        self._connection = connection
        self._engine = engine

    def _guard(self, sql: str) -> str:
        """Rewrite (tenant set) or fail-closed check (no tenant); one code
        path for execute / executemany / stream / copy (H7)."""
        if self._tenant_id:
            return rewrite_query(sql, self._tenant_id, self._config,
                                 self._connection, self._engine)
        if self._config.get("fail_mode", "closed") == "closed":
            check_no_tenant(sql, self._config, self._connection, self._engine)
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

    def __init__(self, connection, tenant_id: str, config: dict, engine: str):
        self._connection = connection
        self._tenant_id = tenant_id
        self._config = config
        self._engine = engine

        if tenant_id is not None:
            validate_tenant_id(tenant_id)

        # Set database-level context if engine supports it
        setter = _CONTEXT_SETTERS.get(engine)
        if setter and tenant_id:
            try:
                setter(connection, tenant_id)
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
            self._connection, self._engine
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
        tenant_id:  Explicit tenant ID. If None, resolves from:
                    1. The request's TenantContext
                    2. DB user mapping table
                    3. TENANT_ID environment variable
        config:     Override configuration dict. If None, loads from
                    .db-firewall.yaml or defaults.

    Returns:
        ProtectedConnection that silently filters all queries.
    """
    if config is None:
        config = load_config()

    engine = detect_engine(connection)
    _conn_table_cache(connection).clear()   # schema may have changed since last protect()

    # Resolve tenant
    if tenant_id is None:
        tenant_id = TenantContext.get()
    if tenant_id is None:
        tenant_id = os.environ.get("TENANT_ID")
    if tenant_id is None:
        tenant_id = _resolve_tenant_from_map(connection, engine)

    if tenant_id is None and config.get("fail_mode") == "closed":
        logger.warning("DB Firewall: No tenant resolved. All DML will be blocked.")

    return ProtectedConnection(connection, tenant_id, config, engine)


_TENANT_MAP_SQL = {
    DBEngine.POSTGRESQL: ("SELECT tenant_id FROM _firewall_tenant_map "
                          "WHERE db_user = current_user AND is_active = TRUE"),
    DBEngine.MYSQL: ("SELECT tenant_id FROM _firewall_tenant_map "
                     "WHERE db_user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1) AND is_active = 1"),
    DBEngine.SQLSERVER: ("SELECT tenant_id FROM _firewall_tenant_map "
                         "WHERE db_user = SYSTEM_USER AND is_active = 1"),
}


def _resolve_tenant_from_map(connection, engine: str) -> Optional[str]:
    """Look the tenant up in _firewall_tenant_map. A missing table or grant
    must not abort the caller's open transaction (M1): the probe runs inside
    a SAVEPOINT that is rolled back on failure."""
    sql = _TENANT_MAP_SQL.get(engine)
    if sql is None:
        return None
    in_txn = _in_transaction(connection)
    cursor = connection.cursor()
    try:
        if in_txn:
            cursor.execute(f"SAVEPOINT {_META_SAVEPOINT}")
        try:
            cursor.execute(sql)
            row = cursor.fetchone()
        except Exception as e:
            logger.debug(f"DB Firewall: Could not auto-resolve tenant: {e}")
            if in_txn:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {_META_SAVEPOINT}")
            elif in_txn is False and not _is_autocommit(connection):
                connection.rollback()       # the implicit transaction was ours alone
            return None
        if in_txn:
            cursor.execute(f"RELEASE SAVEPOINT {_META_SAVEPOINT}")
        return row[0] if row else None
    except Exception as e:
        logger.debug(f"DB Firewall: Could not auto-resolve tenant: {e}")
        return None
    finally:
        try:
            cursor.close()
        except Exception:
            pass


def set_tenant(tenant_id: str):
    """Set tenant for the current request context (thread or asyncio task)."""
    TenantContext.set(tenant_id)


def get_tenant() -> Optional[str]:
    """Get the tenant of the current request context."""
    return TenantContext.get()


def clear_tenant():
    """Clear the tenant of the current request context."""
    TenantContext.clear()


@contextmanager
def tenant_scope(tenant_id: str):
    """Context manager for tenant isolation. Restores the outer tenant on exit,
    so nested scopes and scopes inside a request do not wipe it."""
    token = TenantContext.enter(tenant_id)
    try:
        yield
    finally:
        TenantContext.exit(token)


# ============================================================================
# FRAMEWORK INTEGRATIONS
# ============================================================================

TENANT_HEADER = "X-Tenant-ID"


def _trust_header(trust_tenant_header: Optional[bool]) -> bool:
    """Explicit argument wins; otherwise the trust_tenant_header config key (default off)."""
    config = load_config()
    if config.get("fail_mode") == "open":
        logger.warning("DB Firewall: web integration with fail_mode=open: requests without "
                       "a verified tenant run UNSCOPED. Use fail_mode=closed in production.")
    if trust_tenant_header is not None:
        return bool(trust_tenant_header)
    return bool(config.get("trust_tenant_header", False))


_warned_untrusted_header = False


def _request_tenant(verified, headers, trust_header: bool) -> Optional[str]:
    """Pick the tenant for one web request.

    The verified source (session, JWT claim, auth layer) wins. The X-Tenant-ID
    header is used only when trusted. The query string is never used. An
    invalid value returns None; callers set that None for the whole request,
    so it fails closed even when some other tenant is already in the context.
    """
    global _warned_untrusted_header
    tenant = verified
    if tenant is None and headers.get(TENANT_HEADER) is not None:
        if trust_header:
            tenant = headers.get(TENANT_HEADER)
        elif not _warned_untrusted_header:
            _warned_untrusted_header = True
            logger.warning("DB Firewall: X-Tenant-ID header ignored (trust_tenant_header is off). "
                           "Pass tenant_id_source=... or enable trust behind an auth gateway.")
    if tenant is None or tenant == "":
        return None
    # JWT / session ids may be int or UUID. Anything else (bool, bytes, list) is a bug upstream.
    if isinstance(tenant, bool) or not isinstance(tenant, (str, int, uuid.UUID)):
        logger.warning(f"DB Firewall: ignoring tenant id of type {type(tenant).__name__}")
        return None
    try:
        return validate_tenant_id(str(tenant))
    except ValueError as e:
        logger.warning(f"DB Firewall: ignoring invalid tenant id from request: {e}")
        return None


class _ScopedStream:
    """Iterate a streaming body as the request's tenant, inside a private copy
    of the context. A WSGI server reads the body after the middleware has
    returned. The caller's context is never changed, so a body read late, read
    in pieces, finalized by the garbage collector, or interleaved with another
    stream cannot set a tenant in some other request."""

    def __init__(self, tenant: Optional[str], content):
        self._ctx = contextvars.copy_context()
        self._ctx.run(_TENANT_VAR.set, tenant)
        self._it = iter(content)

    def __iter__(self):
        return self

    def __next__(self):
        return self._ctx.run(next, self._it)

    def close(self):                    # Django calls this when the response closes
        close = getattr(self._it, "close", None)
        if close is not None:
            self._ctx.run(close)


def _django_default_source(request):
    tenant = getattr(request, "tenant_id", None)
    if tenant is None:
        session = getattr(request, "session", None)
        tenant = session.get("tenant_id") if session is not None else None
    return tenant


def django_middleware_class(tenant_id_source=None, trust_tenant_header: Optional[bool] = None):
    """
    Returns a Django middleware class that sets tenant context per-request.

    Usage (Django settings take a dotted path, not a call):
        # myapp/middleware.py
        TenantMiddleware = django_middleware_class()
        # settings.py
        MIDDLEWARE = [..., 'myapp.middleware.TenantMiddleware']

    tenant_id_source: callable(request) -> tenant id from a verified source.
        Default: request.tenant_id (set by your auth middleware) or session["tenant_id"].
    trust_tenant_header: also accept X-Tenant-ID when no verified tenant is
        found. Only for a gateway that sets it after auth. Default: config key.
    """
    source = tenant_id_source or _django_default_source
    trust = _trust_header(trust_tenant_header)

    class DBFirewallMiddleware:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            tenant = _request_tenant(source(request), request.headers, trust)
            # Enter even when None: hides any tenant left in this context.
            token = TenantContext.enter(tenant)
            try:
                response = self.get_response(request)
            finally:
                TenantContext.exit(token)   # runs even when the view raises
            content = getattr(response, "streaming_content", None)
            if getattr(response, "streaming", False) and content is not None \
                    and not hasattr(content, "__aiter__"):  # async bodies: [Unverified], not wrapped
                response.streaming_content = _ScopedStream(tenant, content)
            return response

    return DBFirewallMiddleware


def sqlalchemy_event_hooks(engine_instance):
    """
    Attach tenant isolation to a SQLAlchemy engine.

    Usage:
        from sqlalchemy import create_engine
        from db_firewall import sqlalchemy_event_hooks

        engine = create_engine(...)
        sqlalchemy_event_hooks(engine)
    """
    from sqlalchemy import event

    def _apply_tenant(dbapi_connection):
        tenant = TenantContext.get()
        if tenant:
            db_engine = detect_engine(dbapi_connection)
            setter = _CONTEXT_SETTERS.get(db_engine)
            if setter:
                setter(dbapi_connection, tenant)

    # Per-checkout, not per-connect: a pooled connection serves many tenants.
    # Postgres uses a transaction-local GUC, so it dies with the transaction.
    @event.listens_for(engine_instance, "checkout")
    def on_checkout(dbapi_connection, connection_record, connection_proxy):
        _apply_tenant(dbapi_connection)

    # ...and therefore it must be re-applied for every transaction a long-lived
    # Connection/Session opens after its first commit()/rollback(). SQLAlchemy
    # fires "begin" when it starts each new transaction. Setting the GUC twice
    # in one transaction (checkout, then begin) is harmless: same value.
    @event.listens_for(engine_instance, "begin")
    def on_begin(conn):
        _apply_tenant(conn.connection.dbapi_connection)

    @event.listens_for(engine_instance, "checkin")
    def on_checkin(dbapi_connection, connection_record):
        if dbapi_connection is not None:
            pool_checkin(dbapi_connection)

    # retval=True: SQLAlchemy only uses the returned (statement, parameters)
    # with this flag; without it the rewrite was computed and thrown away (H6).
    @event.listens_for(engine_instance, "before_cursor_execute", retval=True)
    def before_execute(conn, cursor, statement, parameters, context, executemany):
        tenant = TenantContext.get()
        config = load_config()
        dbapi_conn = conn.connection.dbapi_connection
        db_engine = detect_engine(dbapi_conn)

        if tenant and statement:
            new_statement = rewrite_query(statement, tenant, config, dbapi_conn, db_engine)
            if new_statement != statement:
                context._firewall_original = statement
            return new_statement, parameters

        if not tenant and config.get("fail_mode", "closed") == "closed":
            check_no_tenant(statement, config, dbapi_conn, db_engine)
        return statement, parameters


def fastapi_middleware(app, tenant_id_source=None, trust_tenant_header: Optional[bool] = None):
    """
    FastAPI (or Starlette) middleware that sets tenant context per-request.

    Usage:
        from db_firewall import fastapi_middleware
        fastapi_middleware(app, tenant_id_source=lambda req: req.state.user.tenant_id)

    tenant_id_source: callable(request) -> tenant id from a verified source.
        Default: request.state.tenant_id (set by your auth middleware).
    trust_tenant_header: also accept X-Tenant-ID when no verified tenant is
        found. Only for a gateway that sets it after auth. Default: config key.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    source = tenant_id_source or (lambda req: getattr(req.state, "tenant_id", None))
    trust = _trust_header(trust_tenant_header)

    class TenantMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            # Enter even when None: hides any tenant left in this context.
            token = TenantContext.enter(_request_tenant(source(request), request.headers, trust))
            try:
                return await call_next(request)
            finally:
                TenantContext.exit(token)

    app.add_middleware(TenantMiddleware)


def _flask_default_source():
    from flask import g, session
    tenant = getattr(g, "tenant_id", None)
    return session.get("tenant_id") if tenant is None else tenant


def flask_hooks(app, tenant_id_source=None, trust_tenant_header: Optional[bool] = None):
    """
    Flask before/after request hooks for tenant isolation.

    Usage:
        from db_firewall import flask_hooks
        flask_hooks(app, tenant_id_source=lambda: g.tenant_id)

    tenant_id_source: callable() -> tenant id from a verified source.
        Default: g.tenant_id (set by your auth hook) or session["tenant_id"].
        Call flask_hooks() AFTER registering your auth before_request hook,
        and on the app, not a blueprint: blueprint hooks run too late.
    Streaming responses: Flask runs teardown before the body is read, so a
    streaming generator must open its own tenant_scope(tenant) or use
    protect(conn, tenant_id=...).
    trust_tenant_header: also accept X-Tenant-ID when no verified tenant is
        found. Only for a gateway that sets it after auth. Default: config key.
    """
    source = tenant_id_source or _flask_default_source
    trust = _trust_header(trust_tenant_header)

    @app.before_request
    def set_tenant_from_request():
        from flask import request, g
        # Enter even when None: hides any tenant left in this context.
        g._firewall_token = TenantContext.enter(_request_tenant(source(), request.headers, trust))

    @app.teardown_request
    def clear_tenant_after_request(exception=None):
        from flask import g
        TenantContext.exit(g.pop("_firewall_token", None))


# ============================================================================
# CLI — Run migrations
# ============================================================================

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def run_migration(connection, engine: Optional[str] = None):
    """
    Run the appropriate migration script for the detected database engine.
    Call this once during deployment / setup.
    """
    if engine is None:
        engine = detect_engine(connection)

    engine_file_map = {
        DBEngine.POSTGRESQL: "001_postgresql.sql",
        DBEngine.MYSQL: "002_mysql.sql",
        DBEngine.SQLSERVER: "003_sqlserver.sql",
        DBEngine.ORACLE: "004_oracle.sql",
    }

    filename = engine_file_map.get(engine)
    if not filename:
        logger.info(f"DB Firewall: No migration needed for {engine} (middleware-only enforcement)")
        return

    migration_path = MIGRATIONS_DIR / filename
    if not migration_path.is_file():
        # Returning here would leave the database without row-level security.
        raise FileNotFoundError(f"DB Firewall: migration file not found: {migration_path}")

    sql = migration_path.read_text()
    cursor = connection.cursor()

    # Split on GO for SQL Server, semicolons for others
    if engine == DBEngine.SQLSERVER:
        statements = re.split(r'\bGO\b', sql, flags=re.IGNORECASE)
    else:
        statements = [sql]  # Let the driver handle multi-statement

    for stmt in statements:
        stmt = stmt.strip()
        if stmt:
            try:
                cursor.execute(stmt)
            except Exception as e:
                logger.error(f"DB Firewall: Migration error: {e}")
                raise

    connection.commit()
    cursor.close()
    logger.info(f"DB Firewall: Migration applied for {engine}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DB Firewall CLI")
    # ponytail: "info" only. Apply migrations with psql/mysql/sqlcmd (README)
    # or run_migration(conn); audit coverage with hooks/scanner.py.
    parser.add_argument("command", choices=["info"])
    args = parser.parse_args()

    print(f"DB Firewall v1.0 — Universal AI Agent Tenant Isolation")
    print(f"Config: {json.dumps(load_config(), indent=2)}")
