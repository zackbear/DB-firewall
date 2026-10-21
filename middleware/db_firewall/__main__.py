"""CLI: python -m middleware.db_firewall info (or python -m db_firewall info from middleware/)."""

import argparse
import json

from .config import load_config

parser = argparse.ArgumentParser(prog="python -m middleware.db_firewall", description="DB Firewall CLI")
# ponytail: "info" only. Apply migrations with psql/mysql/sqlcmd (README)
# or run_migration(conn); audit coverage with hooks/scanner.py.
parser.add_argument("command", choices=["info"])
args = parser.parse_args()

print("DB Firewall v1.0 — Universal AI Agent Tenant Isolation")
print(f"Config: {json.dumps(load_config(), indent=2)}")
