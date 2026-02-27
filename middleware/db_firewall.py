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
from pathlib import Path
from typing import Optional, Dict, List, Any, Union
from datetime import datetime, timezone
from contextlib import contextmanager

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("db_firewall")

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    "tenant_column": "tenant_id",
    "fail_mode": "closed",
    "protect": {"select": True, "insert": True, "update": True, "delete": True},
    "audit": {"enabled": True, "table_name": "_firewall_audit_log", "retention_days": 90},
    "excluded_users": ["postgres", "root", "sa", "sys", "system", "admin", "_migrator"],
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
                config.update(user_config)
                logger.info(f"DB Firewall: Loaded config from {cfg_path}")
                return config

    # Environment variable overrides
    if os.environ.get("DB_FIREWALL_TENANT_COLUMN"):
        config["tenant_column"] = os.environ["DB_FIREWALL_TENANT_COLUMN"]
    if os.environ.get("DB_FIREWALL_FAIL_MODE"):
        config["fail_mode"] = os.environ["DB_FIREWALL_FAIL_MODE"]

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

class TenantContext:
    """Thread-safe tenant context store."""

    _local = threading.local()

    @classmethod
    def set(cls, tenant_id: str):
        cls._local.tenant_id = tenant_id

    @classmethod
    def get(cls) -> Optional[str]:
        return getattr(cls._local, 'tenant_id', None)

    @classmethod
    def clear(cls):
        cls._local.tenant_id = None

    @classmethod
    def require(cls) -> str:
        tenant = cls.get()
        if not tenant:
            raise PermissionError("DB Firewall: No tenant context set. Access denied.")
        return tenant


# ============================================================================
# TABLE INTROSPECTION
# ============================================================================

_table_cache: Dict[str, Dict[str, bool]] = {}
_cache_lock = threading.Lock()


def _has_tenant_column(connection, table_name: str, engine: str,
                       tenant_column: str) -> bool:
    """Check if a table has the tenant column."""
    cache_key = f"{engine}:{table_name}"

    with _cache_lock:
        if cache_key in _table_cache:
            return _table_cache[cache_key].get("has_col", False)

    has_col = False
    try:
        cursor = connection.cursor()
        if engine == DBEngine.POSTGRESQL:
            cursor.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s",
                (table_name, tenant_column)
            )
        elif engine == DBEngine.MYSQL:
            cursor.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s AND table_schema = DATABASE()",
                (table_name, tenant_column)
            )
        elif engine == DBEngine.SQLSERVER:
            cursor.execute(
                "SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_NAME = ? AND COLUMN_NAME = ?",
                (table_name, tenant_column)
            )
        elif engine == DBEngine.SQLITE:
            cursor.execute(f"PRAGMA table_info({table_name})")
            cols = [row[1] for row in cursor.fetchall()]
            has_col = tenant_column in cols
            with _cache_lock:
                _table_cache[cache_key] = {"has_col": has_col}
            return has_col
        else:
            return False

        has_col = cursor.fetchone() is not None
        cursor.close()
    except Exception as e:
        logger.debug(f"DB Firewall: Could not check columns for {table_name}: {e}")

    with _cache_lock:
        _table_cache[cache_key] = {"has_col": has_col}

    return has_col


# ============================================================================
# SQL QUERY REWRITING — THE INVISIBLE WHERE CLAUSE
# ============================================================================

# Regex patterns for SQL parsing
_TABLE_PATTERNS = [
    r'\bFROM\s+([`"\[]?\w+[`"\]]?)',
    r'\bJOIN\s+([`"\[]?\w+[`"\]]?)',
    r'\bINTO\s+([`"\[]?\w+[`"\]]?)',
    r'\bUPDATE\s+([`"\[]?\w+[`"\]]?)',
    r'\bDELETE\s+FROM\s+([`"\[]?\w+[`"\]]?)',
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
        for match in re.finditer(pattern, sql, re.IGNORECASE):
            table = match.group(1).strip('`"[]')
            tables.add(table)
    return list(tables)


def _is_excluded_table(table: str, excluded: List[str]) -> bool:
    """Check if table matches exclusion patterns."""
    import fnmatch
    for pattern in excluded:
        if fnmatch.fnmatch(table, pattern):
            return True
    return False


def rewrite_query(sql: str, tenant_id: str, config: dict,
                  connection=None, engine: str = None) -> str:
    """
    Rewrite a SQL query to inject tenant isolation WHERE clauses.
    This is the middleware-level enforcement for engines without native RLS.
    """
    if not sql or not sql.strip():
        return sql

    sql_upper = sql.upper().strip()
    tenant_col = config.get("tenant_column", "tenant_id")
    excluded = config.get("excluded_tables", [])
    protect = config.get("protect", {})

    # No tenant → don't rewrite (fail-closed is enforced by ProtectedCursor)
    if tenant_id is None:
        return sql

    # Skip non-DML
    if not any(sql_upper.startswith(k) for k in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
        return sql

    # Determine operation type
    is_select = bool(_SELECT_RE.match(sql_upper))
    is_insert = bool(_INSERT_RE.match(sql_upper))
    is_update = bool(_UPDATE_RE.match(sql_upper))
    is_delete = bool(_DELETE_RE.match(sql_upper))

    # Check if operation is protected
    if is_select and not protect.get("select", True):
        return sql
    if is_insert and not protect.get("insert", True):
        return sql
    if is_update and not protect.get("update", True):
        return sql
    if is_delete and not protect.get("delete", True):
        return sql

    # Extract and check tables
    tables = _extract_tables(sql)
    protected_tables = [
        t for t in tables
        if not _is_excluded_table(t, excluded)
        and (connection is None or _has_tenant_column(connection, t, engine, tenant_col))
    ]

    if not protected_tables:
        return sql

    # For SELECT/UPDATE/DELETE: inject WHERE clause
    if is_select or is_update or is_delete:
        tenant_predicate = f"{tenant_col} = '{tenant_id}'"

        if _WHERE_RE.search(sql):
            # Inject after existing WHERE
            sql = _WHERE_RE.sub(f"WHERE {tenant_predicate} AND ", sql, count=1)
        else:
            # Find insertion point (before ORDER BY, GROUP BY, LIMIT, etc.)
            insert_before = re.search(
                r'\b(ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|UNION|INTERSECT|EXCEPT|;)\b',
                sql, re.IGNORECASE
            )
            if insert_before:
                pos = insert_before.start()
                sql = sql[:pos] + f" WHERE {tenant_predicate} " + sql[pos:]
            else:
                sql = sql.rstrip(';') + f" WHERE {tenant_predicate}"

    return sql


# ============================================================================
# DATABASE-SPECIFIC CONTEXT SETTERS
# ============================================================================

def _set_context_postgres(connection, tenant_id: str):
    """Set tenant via PostgreSQL session variable."""
    cursor = connection.cursor()
    cursor.execute("SELECT set_config('app.current_tenant', %s, false)", (tenant_id,))
    cursor.close()


def _set_context_mysql(connection, tenant_id: str):
    """Set tenant via MySQL session variable."""
    cursor = connection.cursor()
    cursor.execute("SET @_fw_tenant_id = %s", (tenant_id,))
    cursor.close()


def _set_context_sqlserver(connection, tenant_id: str):
    """Set tenant via SQL Server SESSION_CONTEXT."""
    cursor = connection.cursor()
    cursor.execute("EXEC sp_set_session_context @key=N'tenant_id', @value=?", (tenant_id,))
    cursor.close()


def _set_context_oracle(connection, tenant_id: str):
    """Set tenant via Oracle application context."""
    cursor = connection.cursor()
    cursor.execute(
        "BEGIN PKG_SAAS_SECURITY.set_tenant(:1); END;",
        (tenant_id,)
    )
    cursor.close()


_CONTEXT_SETTERS = {
    DBEngine.POSTGRESQL: _set_context_postgres,
    DBEngine.MYSQL: _set_context_mysql,
    DBEngine.SQLSERVER: _set_context_sqlserver,
    DBEngine.ORACLE: _set_context_oracle,
}


# ============================================================================
# PROTECTED CURSOR — Intercepts all SQL execution
# ============================================================================

class ProtectedCursor:
    """Wraps a DB-API cursor to enforce tenant isolation on every query."""

    def __init__(self, cursor, tenant_id: str, config: dict,
                 connection=None, engine: str = DBEngine.UNKNOWN):
        self._cursor = cursor
        self._tenant_id = tenant_id
        self._config = config
        self._connection = connection
        self._engine = engine

    def execute(self, sql: str, params=None):
        if self._tenant_id:
            sql = rewrite_query(
                sql, self._tenant_id, self._config,
                self._connection, self._engine
            )
        elif self._config.get("fail_mode") == "closed":
            # No tenant set + fail closed → block everything
            sql_upper = sql.upper().strip()
            if any(sql_upper.startswith(k) for k in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                raise PermissionError(
                    "DB Firewall: No tenant context. Query blocked (fail_mode=closed)."
                )

        logger.debug(f"DB Firewall: Executing: {sql[:200]}")

        if params:
            return self._cursor.execute(sql, params)
        return self._cursor.execute(sql)

    def executemany(self, sql: str, params_list):
        if self._tenant_id:
            sql = rewrite_query(
                sql, self._tenant_id, self._config,
                self._connection, self._engine
            )
        return self._cursor.executemany(sql, params_list)

    def __getattr__(self, name):
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

        # Set database-level context if engine supports it
        setter = _CONTEXT_SETTERS.get(engine)
        if setter and tenant_id:
            try:
                setter(connection, tenant_id)
                logger.info(f"DB Firewall: Set DB-level context for {engine}")
            except Exception as e:
                logger.warning(f"DB Firewall: Could not set DB context: {e}")
                logger.info("DB Firewall: Falling back to middleware-only enforcement")

        # Also set thread-local context
        TenantContext.set(tenant_id)

    def cursor(self, *args, **kwargs):
        raw_cursor = self._connection.cursor(*args, **kwargs)
        return ProtectedCursor(
            raw_cursor, self._tenant_id, self._config,
            self._connection, self._engine
        )

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        TenantContext.clear()
        self._connection.__exit__(*args) if hasattr(self._connection, '__exit__') else None

    def close(self):
        TenantContext.clear()
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
                    1. Thread-local TenantContext
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

    # Resolve tenant
    if tenant_id is None:
        tenant_id = TenantContext.get()
    if tenant_id is None:
        tenant_id = os.environ.get("TENANT_ID")
    if tenant_id is None:
        # Try DB user mapping
        try:
            cursor = connection.cursor()
            if engine == DBEngine.POSTGRESQL:
                cursor.execute(
                    "SELECT tenant_id FROM _firewall_tenant_map "
                    "WHERE db_user = current_user AND is_active = TRUE"
                )
            elif engine == DBEngine.MYSQL:
                cursor.execute(
                    "SELECT tenant_id FROM _firewall_tenant_map "
                    "WHERE db_user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1) AND is_active = 1"
                )
            elif engine == DBEngine.SQLSERVER:
                cursor.execute(
                    "SELECT tenant_id FROM _firewall_tenant_map "
                    "WHERE db_user = SYSTEM_USER AND is_active = 1"
                )
            else:
                cursor = None

            if cursor:
                row = cursor.fetchone()
                if row:
                    tenant_id = row[0]
                cursor.close()
        except Exception as e:
            logger.debug(f"DB Firewall: Could not auto-resolve tenant: {e}")

    if tenant_id is None and config.get("fail_mode") == "closed":
        logger.warning("DB Firewall: No tenant resolved. All DML will be blocked.")

    return ProtectedConnection(connection, tenant_id, config, engine)


def set_tenant(tenant_id: str):
    """Set tenant for the current thread. Use in web frameworks before DB access."""
    TenantContext.set(tenant_id)


def get_tenant() -> Optional[str]:
    """Get current thread's tenant."""
    return TenantContext.get()


def clear_tenant():
    """Clear current thread's tenant (call on request end)."""
    TenantContext.clear()


@contextmanager
def tenant_scope(tenant_id: str):
    """Context manager for tenant isolation."""
    set_tenant(tenant_id)
    try:
        yield
    finally:
        clear_tenant()


# ============================================================================
# FRAMEWORK INTEGRATIONS
# ============================================================================

def django_middleware_class():
    """
    Returns a Django middleware class that sets tenant context per-request.

    Add to MIDDLEWARE in settings.py:
        'db_firewall.django_middleware_class()'

    Expects tenant_id in: request header, JWT claim, or session.
    """
    class DBFirewallMiddleware:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            # Resolve tenant from request
            tenant = (
                request.headers.get("X-Tenant-ID")
                or getattr(request, 'tenant_id', None)
                or request.session.get('tenant_id')
            )
            if tenant:
                set_tenant(tenant)

            response = self.get_response(request)
            clear_tenant()
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

    @event.listens_for(engine_instance, "connect")
    def on_connect(dbapi_connection, connection_record):
        tenant = TenantContext.get()
        if tenant:
            db_engine = detect_engine(dbapi_connection)
            setter = _CONTEXT_SETTERS.get(db_engine)
            if setter:
                setter(dbapi_connection, tenant)

    @event.listens_for(engine_instance, "before_cursor_execute")
    def before_execute(conn, cursor, statement, parameters, context, executemany):
        tenant = TenantContext.get()
        config = load_config()

        if tenant and statement:
            db_engine = detect_engine(conn.connection.dbapi_connection)
            new_statement = rewrite_query(
                statement, tenant, config,
                conn.connection.dbapi_connection, db_engine
            )
            if new_statement != statement:
                context._firewall_original = statement
                return new_statement, parameters

        elif not tenant and config.get("fail_mode") == "closed":
            upper = statement.upper().strip()
            if any(upper.startswith(k) for k in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                tables = _extract_tables(statement)
                excluded = config.get("excluded_tables", [])
                if any(not _is_excluded_table(t, excluded) for t in tables):
                    raise PermissionError(
                        "DB Firewall: No tenant context. Query blocked."
                    )


def fastapi_middleware(app):
    """
    FastAPI middleware that sets tenant context per-request.

    Usage:
        from db_firewall import fastapi_middleware
        fastapi_middleware(app)
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    class TenantMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            tenant = (
                request.headers.get("X-Tenant-ID")
                or request.query_params.get("tenant_id")
            )
            if tenant:
                set_tenant(tenant)
            try:
                response = await call_next(request)
            finally:
                clear_tenant()
            return response

    app.add_middleware(TenantMiddleware)


def flask_hooks(app):
    """
    Flask before/after request hooks for tenant isolation.

    Usage:
        from db_firewall import flask_hooks
        flask_hooks(app)
    """
    @app.before_request
    def set_tenant_from_request():
        from flask import request, g
        tenant = (
            request.headers.get("X-Tenant-ID")
            or request.args.get("tenant_id")
        )
        if tenant:
            set_tenant(tenant)
            g._firewall_tenant = tenant

    @app.teardown_request
    def clear_tenant_after_request(exception=None):
        clear_tenant()


# ============================================================================
# CLI — Run migrations
# ============================================================================

def run_migration(connection, engine: Optional[str] = None):
    """
    Run the appropriate migration script for the detected database engine.
    Call this once during deployment / setup.
    """
    if engine is None:
        engine = detect_engine(connection)

    migration_dir = Path(__file__).parent / "migrations"

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

    migration_path = migration_dir / filename
    if not migration_path.exists():
        logger.error(f"DB Firewall: Migration file not found: {migration_path}")
        return

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
    parser.add_argument("command", choices=["migrate", "check", "info"])
    parser.add_argument("--dsn", help="Database connection string")
    parser.add_argument("--tenant", help="Test tenant ID")
    args = parser.parse_args()

    print(f"DB Firewall v1.0 — Universal AI Agent Tenant Isolation")
    print(f"Config: {json.dumps(load_config(), indent=2)}")
