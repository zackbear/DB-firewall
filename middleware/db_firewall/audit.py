"""DB Firewall: audit rows for tenant assignments, audit purge, query logging.

Columns match the migrations' audit tables (PostgreSQL, MySQL, SQL Server:
_firewall_audit_log; Oracle: VPD_AUDIT_LOG). The row is written on the same
connection, in the same transaction as the tenant context: a rollback drops it.
"""

import logging
from typing import Optional

from .config import engine_options
from .engines import DBEngine, placeholder

logger = logging.getLogger("db_firewall")
query_logger = logging.getLogger("db_firewall.audit")

_INSERT_SQL = {
    DBEngine.POSTGRESQL: ("INSERT INTO {t} (client_addr, tenant_id, auth_method) "
                          "VALUES (inet_client_addr(), {ph}, 'middleware')"),
    DBEngine.MYSQL: ("INSERT INTO {t} (connection_id, db_user, client_host, tenant_id, auth_method) "
                     "VALUES (CONNECTION_ID(), CURRENT_USER(), SUBSTRING_INDEX(USER(), '@', -1), "
                     "{ph}, 'middleware')"),
    DBEngine.SQLSERVER: ("INSERT INTO {t} (client_host, tenant_id, auth_method) "
                         "VALUES (HOST_NAME(), {ph}, 'middleware')"),
    DBEngine.ORACLE: ("INSERT INTO {t} (session_id, db_user, os_user, ip_address, tenant_id, auth_method) "
                      "VALUES (SYS_CONTEXT('USERENV', 'SID'), USER, SYS_CONTEXT('USERENV', 'OS_USER'), "
                      "SYS_CONTEXT('USERENV', 'IP_ADDRESS'), {ph}, 'MIDDLEWARE')"),
}

_PURGE_SQL = {
    DBEngine.POSTGRESQL: "DELETE FROM {t} WHERE assigned_at < NOW() - make_interval(days => {ph})",
    DBEngine.MYSQL: "DELETE FROM {t} WHERE assigned_at < NOW() - INTERVAL {ph} DAY",
    DBEngine.SQLSERVER: "DELETE FROM {t} WHERE assigned_at < DATEADD(day, -{ph}, SYSUTCDATETIME())",
    DBEngine.ORACLE: "DELETE FROM {t} WHERE assigned_at < SYSTIMESTAMP - NUMTODSINTERVAL({ph}, 'DAY')",
}


def audit_table(config: dict, engine: str) -> str:
    """engines.<engine>.audit_table, else audit.table_name (both validated by load_config)."""
    return (engine_options(config, engine).get("audit_table")
            or (config.get("audit") or {}).get("table_name") or "_firewall_audit_log")


def audit_enabled(config: dict) -> bool:
    return bool((config.get("audit") or {}).get("enabled", False))


def write_assignment(connection, engine: str, tenant_id: str, config: dict) -> None:
    """One audit row for a DB-side tenant assignment. Raises on failure; the
    caller decides by fail_mode, as for the context itself."""
    sql = _INSERT_SQL.get(engine)
    if sql is None or not audit_enabled(config):
        return
    cursor = connection.cursor()
    try:
        cursor.execute(sql.format(t=audit_table(config, engine), ph=placeholder(connection)),
                       (tenant_id,))
    finally:
        cursor.close()


def purge_audit(connection, config: Optional[dict] = None, engine: Optional[str] = None,
                retention_days: Optional[int] = None) -> int:
    """Delete audit rows older than retention_days (default: audit.retention_days).
    Returns the number of rows deleted. Does not commit: the caller does."""
    from .config import load_config
    from .engines import detect_engine
    config = config if config is not None else load_config()
    engine = engine or detect_engine(connection)
    sql = _PURGE_SQL.get(engine)
    if sql is None:
        raise ValueError(f"DB Firewall: no audit table for engine {engine!r}")
    days = retention_days if retention_days is not None else \
        int((config.get("audit") or {}).get("retention_days", 90))
    if days < 0:
        raise ValueError("DB Firewall: retention_days must be 0 or more")
    cursor = connection.cursor()
    try:
        cursor.execute(sql.format(t=audit_table(config, engine), ph=placeholder(connection)),
                       (int(days),))
        return cursor.rowcount
    finally:
        cursor.close()


def log_query(tenant_id: Optional[str], sql: str, config: dict) -> None:
    """audit.log_queries: log each statement as executed (after rewriting) to
    the "db_firewall.audit" logger at INFO. The SQL may hold personal data."""
    if (config.get("audit") or {}).get("log_queries"):
        query_logger.info("tenant=%s sql=%s", tenant_id, sql)
