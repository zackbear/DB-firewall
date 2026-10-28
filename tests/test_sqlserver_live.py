"""
Live SQL Server 2022 tests: run_migration() with a custom tenant column, the
security policy it creates, the Python middleware's SQL Server paths (pymssql)
and the scanner.

Opt-in. Set DBFW_MSSQL_DSN=mssql://user:password@host:port/database and run
tests/live_setup/sqlserver_before.sql in that database first. The test runs
the migration itself through run_migration().
"""

import copy
import os
import sys
from urllib.parse import unquote, urlparse

import pytest

DSN = os.environ.get("DBFW_MSSQL_DSN")
if not DSN:
    pytest.skip("DBFW_MSSQL_DSN not set; skipping live SQL Server tests", allow_module_level=True)
pymssql = pytest.importorskip("pymssql")
pytest.importorskip("sqlglot")

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
from hooks.scan_engines import scan_tables  # noqa: E402
from middleware.db_firewall import (DBEngine, detect_engine, load_config, pool_checkin,  # noqa: E402
                                    protect, purge_audit, run_migration)

U = urlparse(DSN)


def _connect():
    return pymssql.connect(server=U.hostname, port=str(U.port or 1433), user=unquote(U.username),
                           password=unquote(U.password), database=U.path.lstrip("/"))


def _cfg():
    c = copy.deepcopy(load_config())
    c["tenant_column"] = "org_id"
    return c


@pytest.fixture(scope="module", autouse=True)
def migrated():
    c = _connect()
    run_migration(c, DBEngine.SQLSERVER, _cfg())
    cur = c.cursor()
    cur.execute("DELETE FROM dbo._firewall_tenant_map")
    cur.execute("INSERT INTO dbo._firewall_tenant_map (db_user, tenant_id) VALUES (SYSTEM_USER, N'A')")
    c.commit()
    c.close()


@pytest.fixture
def cfg():
    return _cfg()


@pytest.fixture
def conn():
    c = _connect()
    c.cursor().execute("EXEC sp_set_session_context @key = N'tenant_id', @value = NULL")
    yield c
    c.rollback()
    c.close()


def _ids(cursor, table="dbo.orders"):
    cursor.execute(f"SELECT id FROM {table} ORDER BY id")
    return [r[0] for r in cursor.fetchall()]


def test_engine_detected(conn):
    assert detect_engine(conn) == DBEngine.SQLSERVER


def test_policy_created_for_custom_column_only(conn):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sys.security_policies ORDER BY name")
    assert [r[0] for r in cur.fetchall()] == ["firewall_rls_orders"]


def test_rls_fails_closed_without_tenant(conn):
    assert _ids(conn.cursor()) == []


def test_protect_scopes_both_layers(conn, cfg):
    pc = protect(conn, tenant_id="A", config=cfg)
    assert _ids(pc.cursor()) == [1]                       # middleware rewrite
    assert _ids(conn.cursor()) == [1]                     # raw cursor: RLS, same session
    pc.release()
    assert _ids(conn.cursor()) == []


def test_block_predicate_stops_cross_tenant_insert(conn, cfg):
    protect(conn, tenant_id="A", config=cfg)
    with pytest.raises(pymssql.Error):
        conn.cursor().execute("INSERT INTO dbo.orders VALUES (91, N'B')")   # raw: RLS layer


def test_audit_row_and_purge(conn, cfg):
    cfg["audit"]["enabled"] = True
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM dbo._firewall_audit_log WHERE auth_method = 'middleware'")
    before = cur.fetchone()[0]
    protect(conn, tenant_id="A", config=cfg)
    cur.execute("SELECT COUNT(*) FROM dbo._firewall_audit_log WHERE auth_method = 'middleware'")
    assert cur.fetchone()[0] == before + 1
    cur.execute("UPDATE dbo._firewall_audit_log SET assigned_at = DATEADD(day, -100, SYSUTCDATETIME()) "
                "WHERE auth_method = 'middleware'")
    assert purge_audit(conn, cfg, DBEngine.SQLSERVER) >= 1


def test_resolution_from_map_and_session_var(conn, cfg):
    conn.cursor().execute("EXEC sp_set_session_context @key = N'tenant_id', @value = N'B'")
    cfg["resolution"] = [{"source": "session_var"}]
    assert protect(conn, config=cfg)._tenant_id == "B"
    conn.cursor().execute("EXEC sp_set_session_context @key = N'tenant_id', @value = NULL")
    cfg["resolution"] = [{"source": "db_user_map"}]
    assert protect(conn, config=cfg)._tenant_id == "A"


def test_excluded_user(conn, cfg):
    cfg["excluded_users"] = [unquote(U.username)]
    pc = protect(conn, config=cfg)
    assert pc._bypass
    assert _ids(pc.cursor()) == []                        # RLS still applies


def test_pool_checkin_clears(conn, cfg):
    protect(conn, tenant_id="A", config=cfg)
    pool_checkin(conn)
    assert _ids(conn.cursor()) == []


def test_scanner(conn, cfg):
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS dbo.late_table")
    cur.execute("CREATE TABLE dbo.late_table (id INT, org_id NVARCHAR(64))")   # after the migration
    report = scan_tables(conn, DBEngine.SQLSERVER, cfg)
    cur.execute("DROP TABLE dbo.late_table")
    assert report["orders"]["protected"] is True
    assert report["late_table"]["protected"] is False
    assert "plain" not in report and "notes" not in report
