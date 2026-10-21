"""DB Firewall: Migration runner."""

import re
import logging
from pathlib import Path
from typing import Optional

from .engines import DBEngine, detect_engine

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


def run_migration(connection, engine: Optional[str] = None):
    """
    Run the appropriate migration script for the detected database engine.
    Call this once during deployment / setup.
    """
    if engine is None:
        engine = detect_engine(connection)


    filename = _MIGRATION_FILES.get(engine)
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
