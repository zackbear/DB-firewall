"""DB Firewall: Database engine detection and connection-state helpers."""

import logging
import sys
from typing import Optional

logger = logging.getLogger("db_firewall")

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


_ENGINE_MAP = {
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


def detect_engine(connection) -> str:
    """Auto-detect database engine from connection object."""
    module = type(connection).__module__
    cls_name = type(connection).__name__


    # pyodbc talks to any DBMS: ask the driver below, never assume SQL Server.
    generic_odbc = "pyodbc" in module or "pyodbc" in cls_name
    for key, engine in _ENGINE_MAP.items():
        if key != "pyodbc" and (key in module or key in cls_name):
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
    if generic_odbc:
        logger.warning("DB Firewall: pyodbc connection did not report a known DBMS "
                       "(getinfo(SQL_DBMS_NAME)); treated as unknown")

    logger.warning(f"DB Firewall: Unknown engine for {module}.{cls_name}")
    return DBEngine.UNKNOWN


def _is_autocommit(connection) -> bool:
    return bool(getattr(connection, "autocommit", False))


def _pg_transaction_idle(connection) -> Optional[bool]:
    """True when no transaction is open (psycopg2 and psycopg3 both expose
    libpq's PQTRANS_IDLE == 0 as connection.info.transaction_status).
    None when the driver does not tell."""
    status = getattr(getattr(connection, "info", None), "transaction_status", None)
    if status is None:
        return None
    return int(status) == 0


_PLACEHOLDERS = {"qmark": "?", "numeric": ":1", "named": ":1",
                 "format": "%s", "pyformat": "%s"}


def placeholder(connection) -> str:
    """The driver's positional parameter marker (psycopg %s, pyodbc ?, oracledb :1)."""
    module = sys.modules.get(type(connection).__module__.split(".")[0])
    return _PLACEHOLDERS.get(getattr(module, "paramstyle", "format"), "%s")
