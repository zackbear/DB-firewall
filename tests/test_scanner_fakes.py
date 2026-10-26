"""Scanner logic per engine with scripted cursors (no MySQL, SQL Server or
Oracle server here; Oracle is also tested live in tests/test_oracle_live.py)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from hooks.scan_engines import scan_tables  # noqa: E402
from middleware.db_firewall import DBEngine, load_config  # noqa: E402


class Script:
    """Cursor that answers each execute() with the next scripted result."""

    def __init__(self, answers):
        self.answers, self.log = list(answers), []

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.log.append((sql, params))
        self.rows = self.answers.pop(0)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def close(self):
        pass


def test_mysql_needs_view_and_all_three_triggers():
    conn = Script([[("app", "orders"), ("app", "items")],
                   [(1,)], [(3,)],          # orders: view + 3 triggers
                   [(1,)], [(1,)]])         # items: view + only 1 trigger
    report = scan_tables(conn, DBEngine.MYSQL, load_config())
    assert report["orders"]["protected"] and not report["items"]["protected"]
    assert conn.log[0][1] == ("tenant_id", None)                # schema None = DATABASE()
    assert conn.log[2][1] == ("app", "_fw_bi_orders", "_fw_bu_orders", "_fw_bd_orders")


def test_sqlserver_policy_by_name():
    conn = Script([[("orders",), ("items",)], [(1,)], []])
    report = scan_tables(conn, DBEngine.SQLSERVER, load_config())
    assert report["orders"]["protected"] and not report["items"]["protected"]
    assert conn.log[1][1] == ("firewall_rls_orders",)


def test_oracle_needs_full_policy():
    cfg = load_config()
    cfg["engines"] = {"oracle": {"schema": "app_user"}}
    conn = Script([[("ORDERS", 1, 1), ("ITEMS", 0, 1), ("NOTES", 0, 0)]])
    report = scan_tables(conn, DBEngine.ORACLE, cfg)
    assert [t for t, r in report.items() if r["protected"]] == ["ORDERS"]
    assert report["ITEMS"]["has_vpd_policy"] and not report["ITEMS"]["full_vpd_policy"]
    assert conn.log[0][1] == ("APP_USER", "tenant_id")


def test_excluded_tables_skipped_case_insensitively_on_oracle():
    cfg = load_config()
    cfg["excluded_tables"] = ["audit_*"]
    conn = Script([[("AUDIT_TRAIL", 0, 0)]])
    assert scan_tables(conn, DBEngine.ORACLE, cfg) == {}


def test_unknown_engine_fails_instead_of_passing():
    with pytest.raises(ValueError):
        scan_tables(Script([]), DBEngine.UNKNOWN, load_config())
