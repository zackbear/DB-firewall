"""DB Firewall: Migration runner."""

import re
import logging
from pathlib import Path
from typing import Optional

from .config import engine_options, load_config
from .db_context import tenant_key
from .engines import DBEngine, _is_autocommit, detect_engine, placeholder

logger = logging.getLogger("db_firewall")

# ============================================================================
# CLI — Run migrations
# ============================================================================

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"


_MIGRATION_FILES = {
    DBEngine.POSTGRESQL: "001_postgresql.sql",
    DBEngine.MYSQL: "002_mysql.sql",
    DBEngine.SQLSERVER: "003_sqlserver.sql",
    DBEngine.ORACLE: "004_oracle.sql",
}


# The Oracle script uses SQL*Plus commands (DEFINE, "/"): run it with sqlplus.
_CLIENT_ONLY = {
    DBEngine.ORACLE: "sqlplus <dba>@<db> @migrations/004_oracle.sql (set SCHEMA_OWNER, TENANT_COLUMN first)",
}


def _set_migration_settings(connection, cursor, engine: str, config: dict) -> None:
    """Pass the tenant column (and the PostgreSQL schema, policy mode, tenant
    context and DB_FIREWALL_TENANT_KEY, when set) to the script."""
    col = config.get("tenant_column", "tenant_id")
    if engine == DBEngine.POSTGRESQL:
        opts = engine_options(config, engine)
        key = tenant_key()
        if key:
            # Keep the key out of the server log where this role may (a
            # superuser): statement and parameter logging off for this session.
            cursor.execute("SELECT set_config('log_statement', 'none', false), "
                           "set_config('log_min_duration_statement', '-1', false), "
                           "set_config('log_parameter_max_length', '0', false), "
                           "set_config('log_parameter_max_length_on_error', '0', false) "
                           "FROM pg_roles WHERE rolname = current_user AND rolsuper")
        cursor.execute("SELECT set_config('dbfw.tenant_column', %s, false), "
                       "set_config('dbfw.schema', %s, false), "
                       "set_config('dbfw.policy_mode', %s, false), "
                       "set_config('dbfw.context', %s, false), "
                       "set_config('dbfw.tenant_key', %s, false)",
                       (col, opts.get("schema") or "public", opts.get("policy_mode") or "permissive",
                        opts.get("tenant_context") or "signed", key.hex() if key else ""))
    elif engine == DBEngine.MYSQL:
        cursor.execute("SET @dbfw_tenant_column = %s", (col,))
    elif engine == DBEngine.SQLSERVER:
        cursor.execute(f"EXEC sp_set_session_context N'dbfw.tenant_column', {placeholder(connection)}",
                       (col,))


def _mysql_statements(sql: str) -> list:
    """Split a mysql-client script on its DELIMITER (default ";")."""
    statements, buf, delim = [], [], ";"
    for line in sql.splitlines():
        if line.strip().upper().startswith("DELIMITER "):
            delim = line.split(None, 1)[1].strip()
            continue
        if not buf and (not line.strip() or line.lstrip().startswith("--")):
            continue
        buf.append(line)
        if line.rstrip().endswith(delim):
            statements.append("\n".join(buf).rstrip()[:-len(delim)])
            buf = []
    if "".join(buf).strip():
        statements.append("\n".join(buf))
    return statements


def _execute_script(cursor, engine: str, sql: str) -> None:
    """SQL Server batches split on GO; MySQL on DELIMITER; others whole."""
    if engine == DBEngine.SQLSERVER:
        statements = re.split(r'\bGO\b', sql, flags=re.IGNORECASE)
    elif engine == DBEngine.MYSQL:
        statements = _mysql_statements(sql)
    else:
        statements = [sql]
    for stmt in statements:
        stmt = stmt.strip()
        if stmt:
            try:
                cursor.execute(stmt)
            except Exception as e:
                logger.error(f"DB Firewall: Migration error: {e}")
                raise


def run_migration(connection, engine: Optional[str] = None, config: Optional[dict] = None):
    """
    Run the migration script for the detected database engine, with the
    tenant column from config (default load_config()). On MySQL it also runs
    the trigger DDL that _firewall_apply_all() returns. Oracle needs sqlplus.
    Call this once during deployment / setup.
    """
    if engine is None:
        engine = detect_engine(connection)
    if engine in _CLIENT_ONLY:
        raise NotImplementedError(f"DB Firewall: run the {engine} migration with its client: "
                                  f"{_CLIENT_ONLY[engine]}")

    filename = _MIGRATION_FILES.get(engine)
    if not filename:
        logger.info(f"DB Firewall: No migration needed for {engine} (middleware-only enforcement)")
        return

    migration_path = MIGRATIONS_DIR / filename
    if not migration_path.is_file():
        # Returning here would leave the database without row-level security.
        raise FileNotFoundError(f"DB Firewall: migration file not found: {migration_path}")

    if config is None:
        config = load_config()
    sql = migration_path.read_text()
    cursor = connection.cursor()
    _set_migration_settings(connection, cursor, engine, config)
    try:
        _execute_script(cursor, engine, sql)
    except Exception:
        if engine == DBEngine.POSTGRESQL:
            # The script clears dbfw.tenant_key when it succeeds; a failed run
            # must not leave the key readable in this session.
            try:
                if not _is_autocommit(connection):
                    connection.rollback()
                cursor.execute("SELECT set_config('dbfw.tenant_key', '', false)")
                if not _is_autocommit(connection):
                    connection.commit()
            except Exception:
                pass
        raise
    if engine == DBEngine.MYSQL:
        cursor.execute("CALL _firewall_apply_all()")
        ddl = cursor.fetchone()[0]
        while cursor.nextset():     # the CALL's status result
            pass
        statements = _mysql_statements(ddl)
        created = sum(s.lstrip().startswith("CREATE TRIGGER") for s in statements)
        if created != ddl.count("CREATE TRIGGER"):      # never report success without triggers
            raise RuntimeError("DB Firewall: could not split the trigger DDL from "
                               "_firewall_apply_all(); no triggers were created")
        _execute_script(cursor, engine, ddl)
    connection.commit()
    cursor.close()
    logger.info(f"DB Firewall: Migration applied for {engine}")
