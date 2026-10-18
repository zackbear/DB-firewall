"""
DB Firewall — Auto-Scanner & CI/CD Hook
==========================================
Scans a database for tables with tenant_id columns that are NOT yet
protected by the firewall. Fails the build if unprotected tables exist.

Usage:
    # As a pre-deploy check
    python -m db_firewall.scanner --dsn postgresql://user:pass@host/db

    # In CI/CD (returns exit code 1 if unprotected tables found)
    python -m db_firewall.scanner --dsn $DATABASE_URL --strict

    # Generate missing migration
    python -m db_firewall.scanner --dsn $DATABASE_URL --fix
"""

import sys
import os
import json
import argparse
from typing import List, Dict, Tuple, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from middleware.db_firewall import (
    detect_engine, load_config, DBEngine, _is_excluded_table
)


def get_connection(dsn: str):
    """Create a connection from a DSN string."""
    if dsn.startswith("postgresql://") or dsn.startswith("postgres://"):
        import psycopg2
        return psycopg2.connect(dsn)
    elif dsn.startswith("mysql://") or dsn.startswith("mysql+"):
        import mysql.connector
        # Parse basic mysql:// URL
        from urllib.parse import urlparse
        u = urlparse(dsn)
        return mysql.connector.connect(
            host=u.hostname, port=u.port or 3306,
            user=u.username, password=u.password,
            database=u.path.lstrip('/')
        )
    elif dsn.startswith("mssql://") or dsn.startswith("sqlserver://"):
        import pyodbc
        return pyodbc.connect(dsn)
    elif dsn.startswith("sqlite"):
        import sqlite3
        path = dsn.replace("sqlite:///", "").replace("sqlite://", "")
        return sqlite3.connect(path)
    else:
        raise ValueError(f"Unsupported DSN format: {dsn[:20]}...")


def scan_tables(connection, engine: str, config: dict) -> Dict[str, dict]:
    """
    Scan database and return status of all tables with tenant_id columns.
    Returns: {table_name: {"has_tenant_col": bool, "has_rls": bool, "protected": bool}}
    """
    cursor = connection.cursor()
    tenant_col = config.get("tenant_column", "tenant_id")
    excluded = config.get("excluded_tables", [])
    results = {}

    # Get all tables with tenant_id
    if engine == DBEngine.POSTGRESQL:
        cursor.execute("""
            SELECT c.table_name,
                   EXISTS (
                       SELECT 1 FROM pg_policies p
                       WHERE p.tablename = c.table_name
                         AND p.policyname LIKE 'firewall_rls_%'
                   ) as has_policy,
                   (SELECT relrowsecurity FROM pg_class
                    WHERE relname = c.table_name) as rls_enabled
            FROM information_schema.columns c
            JOIN information_schema.tables t
                ON c.table_name = t.table_name AND c.table_schema = t.table_schema
            WHERE c.column_name = %s
                AND t.table_type = 'BASE TABLE'
                AND c.table_schema = 'public'
            ORDER BY c.table_name
        """, (tenant_col,))

        for row in cursor.fetchall():
            table = row[0]
            if _is_excluded_table(table, excluded):
                continue
            results[table] = {
                "has_tenant_col": True,
                "has_rls_policy": bool(row[1]),
                "rls_enabled": bool(row[2]),
                "protected": bool(row[1]) and bool(row[2])
            }

    elif engine == DBEngine.MYSQL:
        cursor.execute("""
            SELECT c.TABLE_NAME
            FROM INFORMATION_SCHEMA.COLUMNS c
            JOIN INFORMATION_SCHEMA.TABLES t
                ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
            WHERE c.COLUMN_NAME = %s
                AND t.TABLE_TYPE = 'BASE TABLE'
                AND c.TABLE_SCHEMA = DATABASE()
            ORDER BY c.TABLE_NAME
        """, (tenant_col,))

        for row in cursor.fetchall():
            table = row[0]
            if _is_excluded_table(table, excluded):
                continue

            # Check for view and triggers
            has_view = False
            has_triggers = False
            try:
                cursor.execute(f"SELECT 1 FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_NAME = 'v_{table}'")
                has_view = cursor.fetchone() is not None

                cursor.execute(f"SELECT 1 FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_NAME = '_fw_bi_{table}'")
                has_triggers = cursor.fetchone() is not None
            except Exception:
                pass

            results[table] = {
                "has_tenant_col": True,
                "has_secure_view": has_view,
                "has_triggers": has_triggers,
                "protected": has_view and has_triggers
            }

    elif engine == DBEngine.SQLSERVER:
        cursor.execute("""
            SELECT c.TABLE_NAME
            FROM INFORMATION_SCHEMA.COLUMNS c
            JOIN INFORMATION_SCHEMA.TABLES t
                ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
            WHERE c.COLUMN_NAME = ?
                AND t.TABLE_TYPE = 'BASE TABLE'
            ORDER BY c.TABLE_NAME
        """, (tenant_col,))

        for row in cursor.fetchall():
            table = row[0]
            if _is_excluded_table(table, excluded):
                continue

            has_policy = False
            try:
                cursor.execute(
                    "SELECT 1 FROM sys.security_policies WHERE name = ?",
                    (f"firewall_rls_{table}",)
                )
                has_policy = cursor.fetchone() is not None
            except Exception:
                pass

            results[table] = {
                "has_tenant_col": True,
                "has_rls_policy": has_policy,
                "protected": has_policy
            }

    elif engine == DBEngine.SQLITE:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for row in cursor.fetchall():
            table = row[0]
            if _is_excluded_table(table, excluded):
                continue

            cursor.execute(f"PRAGMA table_info({table})")
            cols = [r[1] for r in cursor.fetchall()]
            if tenant_col in cols:
                results[table] = {
                    "has_tenant_col": True,
                    "protected": False,  # SQLite has no native RLS
                    "note": "Requires middleware-only enforcement"
                }

    cursor.close()
    return results


def print_report(results: Dict[str, dict], engine: str):
    """Print a human-readable security report."""
    if not results:
        print("✅ No tables with tenant_id found. Nothing to protect.")
        return

    protected = {k: v for k, v in results.items() if v.get("protected")}
    unprotected = {k: v for k, v in results.items() if not v.get("protected")}

    print(f"\n{'='*60}")
    print(f"  DB FIREWALL — Security Scan Report ({engine})")
    print(f"{'='*60}\n")
    print(f"  Total tables with tenant_id:  {len(results)}")
    print(f"  Protected:                    {len(protected)}")
    print(f"  ⚠️  UNPROTECTED:               {len(unprotected)}")

    if protected:
        print(f"\n  ✅ Protected Tables:")
        for table in sorted(protected.keys()):
            print(f"     • {table}")

    if unprotected:
        print(f"\n  ❌ UNPROTECTED Tables (AI agents can access all rows):")
        for table, info in sorted(unprotected.items()):
            note = info.get("note", "")
            print(f"     • {table}  {note}")
        print(f"\n  ⚠️  Run the migration to protect these tables.")

    print(f"\n{'='*60}\n")


_OPEN_RULES = ("allow read, write: if true", "allow read: if true", "allow write: if true",
               "allow read,write: if true", "allow write, read: if true")


def check_firestore_rules(path: str) -> List[str]:
    """Return offending lines in a firestore.rules file that grant open access."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return [line.strip() for line in text.splitlines()
            if any(rule in " ".join(line.split()) for rule in _OPEN_RULES)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DB Firewall Scanner")
    parser.add_argument("--dsn", help="Database connection string")
    parser.add_argument("--strict", action="store_true",
                        help="Exit with code 1 if unprotected tables found")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--config", help="Path to config directory")
    parser.add_argument("--firestore-rules", metavar="PATH",
                        help="Fail if this firestore.rules file contains an open 'if true' rule")

    args = parser.parse_args()

    if args.firestore_rules:
        bad = check_firestore_rules(args.firestore_rules)
        if bad:
            print(f"❌ {args.firestore_rules}: open Firestore rules found:")
            for line in bad:
                print(f"     • {line}")
            sys.exit(1)
        print(f"✅ {args.firestore_rules}: no open rules.")
        if not args.dsn:
            sys.exit(0)

    if not args.dsn:
        parser.error("--dsn is required (or pass --firestore-rules PATH)")

    config = load_config(args.config)
    conn = get_connection(args.dsn)
    engine = detect_engine(conn)

    results = scan_tables(conn, engine, config)
    conn.close()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results, engine)

    unprotected = [k for k, v in results.items() if not v.get("protected")]
    if args.strict and unprotected:
        print(f"❌ STRICT MODE: {len(unprotected)} unprotected tables. Build FAILED.")
        sys.exit(1)
