"""
DB Firewall — Auto-Scanner & CI/CD Hook
==========================================
Scans a database for tables with tenant_id columns that are NOT yet
protected by the firewall. Fails the build if unprotected tables exist.

Usage:
    # As a pre-deploy check
    python -m hooks.scanner --dsn postgresql://user:pass@host/db
    python -m hooks.scanner --dsn oracle://user:pass@host:1521/FREEPDB1

    # In CI/CD (returns exit code 1 if unprotected tables found)
    python -m hooks.scanner --dsn $DATABASE_URL --strict
"""

import sys
import os
import json
import re
import argparse
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from middleware.db_firewall import detect_engine, load_config  # noqa: E402
from hooks.scan_engines import scan_tables  # noqa: E402,F401  (re-exported)


def get_connection(dsn: str):
    """Create a connection from a DSN string."""
    if dsn.startswith("postgresql://") or dsn.startswith("postgres://"):
        try:
            import psycopg                      # psycopg 3
            return psycopg.connect(dsn)
        except ImportError:
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
    elif dsn.startswith("oracle://"):
        import oracledb                     # thin mode: no Oracle client install needed
        from urllib.parse import urlparse, unquote
        u = urlparse(dsn)
        return oracledb.connect(user=unquote(u.username or ""), password=unquote(u.password or ""),
                                dsn=f"{u.hostname}:{u.port or 1521}{u.path}")
    elif dsn.startswith("sqlite"):
        import sqlite3
        path = dsn.replace("sqlite:///", "").replace("sqlite://", "")
        return sqlite3.connect(path)
    else:
        raise ValueError(f"Unsupported DSN format: {dsn[:20]}...")


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
        print("\n  ✅ Protected Tables:")
        for table in sorted(protected.keys()):
            print(f"     • {table}")

    if unprotected:
        print("\n  ❌ UNPROTECTED Tables (AI agents can access all rows):")
        for table, info in sorted(unprotected.items()):
            note = info.get("note", "")
            print(f"     • {table}  {note}")
        print("\n  ⚠️  Run the migration to protect these tables.")

    print(f"\n{'='*60}\n")


_FS_OPS = r"(?:read|write|get|list|create|update|delete)"
# `allow <op>[, <op>...] : if true` with any whitespace (including newlines)
# around the commas, the colon and inside the condition.
_OPEN_RULE_RE = re.compile(
    r"\ballow\s+" + _FS_OPS + r"(?:\s*,\s*" + _FS_OPS + r")*\s*:\s*if\s+true\b")


def check_firestore_rules(path: str) -> List[str]:
    """Return offending rules in a firestore.rules file that grant open access.

    Matches on the whitespace-normalized file, so `allow read, write : if true;`
    and a condition split across lines are caught, not only the literal
    `allow read, write: if true` spelling.
    """
    with open(path, encoding="utf-8") as fh:
        normalized = " ".join(fh.read().split())
    return [m.group(0) for m in _OPEN_RULE_RE.finditer(normalized)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DB Firewall Scanner")
    parser.add_argument("--dsn", help="Database connection string")
    parser.add_argument("--strict", action="store_true",
                        help="Exit with code 1 if unprotected tables found")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--config", help="Config file or folder (default: DB_FIREWALL_CONFIG)")
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
