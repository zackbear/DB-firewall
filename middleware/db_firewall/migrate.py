"""DB Firewall: Migration runner."""

import re
import logging
from pathlib import Path
from typing import Optional

from .config import engine_options, load_config
from .engines import DBEngine, detect_engine, placeholder

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


# Scripts that use client-only commands (MySQL DELIMITER, SQL*Plus DEFINE and
# "/") cannot run through a DB-API driver: run them with the engine's client.
_CLIENT_ONLY = {
    DBEngine.MYSQL: "mysql -e \"SET @dbfw_tenant_column='<col>'; source migrations/002_mysql.sql\"",
    DBEngine.ORACLE: "sqlplus <dba>@<db> @migrations/004_oracle.sql (set SCHEMA_OWNER, TENANT_COLUMN first)",
}


def _set_migration_settings(connection, cursor, engine: str, config: dict) -> None:
    """Pass the tenant column (and the PostgreSQL schema) to the script."""
    col = config.get("tenant_column", "tenant_id")
    if engine == DBEngine.POSTGRESQL:
        schema = engine_options(config, engine).get("schema") or "public"
        cursor.execute("SELECT set_config('dbfw.tenant_column', %s, false), "
                       "set_config('dbfw.schema', %s, false)", (col, schema))
    elif engine == DBEngine.SQLSERVER:
        cursor.execute(f"EXEC sp_set_session_context N'dbfw.tenant_column', {placeholder(connection)}",
                       (col,))


def run_migration(connection, engine: Optional[str] = None, config: Optional[dict] = None):
    """
    Run the migration script for the detected database engine, with the
    tenant column from config (default load_config()). PostgreSQL and SQL
    Server only: MySQL and Oracle scripts need their own client.
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

    # Split on GO for SQL Server; other drivers take the script whole
    if engine == DBEngine.SQLSERVER:
        statements = re.split(r'\bGO\b', sql, flags=re.IGNORECASE)
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

    connection.commit()
    cursor.close()
    logger.info(f"DB Firewall: Migration applied for {engine}")
