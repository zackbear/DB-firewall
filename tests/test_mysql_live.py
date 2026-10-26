"""
Live MySQL 8.4 tests: the views + triggers migration with a custom tenant
column, the Python middleware's MySQL paths, and the scanner.

Opt-in. Set DBFW_MYSQL_DSN=mysql://user:password@host:port/database for an
admin user (the test creates the app user dbfw_app) and run
tests/live_setup/mysql_before.sql in that database first. The test runs the
migration itself through run_migration().
"""

import copy
import os
import sys
from urllib.parse import unquote, urlparse

import pytest

DSN = os.environ.get("DBFW_MYSQL_DSN")
if not DSN:
    pytest.skip("DBFW_MYSQL_DSN not set; skipping live MySQL tests", allow_module_level=True)
pymysql = pytest.importorskip("pymysql")
pytest.importorskip("sqlglot")

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
from hooks.scan_engines import scan_tables  # noqa: E402
from middleware.db_firewall import (DBEngine, detect_engine, load_config, pool_checkin,  # noqa: E402
                                    protect, purge_audit, run_migration)

U = urlparse(DSN)
APP_PW = "DbfwApp_2026x"


def _connect(user=None, password=None):
    return pymysql.connect(host=U.hostname, port=U.port or 3306, user=user or unquote(U.username),
                           password=password or unquote(U.password), database=U.path.lstrip("/"))


def _cfg():
    c = copy.deepcopy(load_config())
    c["tenant_column"] = "org_id"
    return c


@pytest.fixture(scope="module", autouse=True)
def migrated():
    c = _connect()
    run_migration(c, DBEngine.MYSQL, _cfg())
    cur = c.cursor()
    cur.execute("DROP USER IF EXISTS 'dbfw_app'@'%'")
    cur.execute(f"CREATE USER 'dbfw_app'@'%' IDENTIFIED BY '{APP_PW}'")
    cur.execute(f"GRANT SELECT ON `{U.path.lstrip('/')}`.`v_orders` TO 'dbfw_app'@'%'")
    cur.execute("DELETE FROM _firewall_tenant_map")
    cur.execute("INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES "
                "(SUBSTRING_INDEX(CURRENT_USER(), '@', 1), 'A'), ('dbfw_app', 'B')")
    c.commit()
    c.close()


@pytest.fixture
def cfg():
    return _cfg()


@pytest.fixture
def conn():
    c = _connect()
    c.cursor().execute("SET @_fw_tenant_id = NULL")
    yield c
    c.rollback()
    c.close()


def _ids(cursor, table="v_orders"):
    cursor.execute(f"SELECT id FROM {table} ORDER BY id")
    return [r[0] for r in cursor.fetchall()]


def test_engine_detected(conn):
    assert detect_engine(conn) == DBEngine.MYSQL


def test_migration_built_view_and_triggers_for_custom_column(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM information_schema.views "
                "WHERE table_schema = DATABASE() AND table_name = 'v_orders'")
    assert cur.fetchone()[0] == 1
    cur.execute("SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = DATABASE() "
                "AND event_object_table IN ('orders', 'vault') AND trigger_name LIKE '\\_fw\\_b%'")
    assert cur.fetchone()[0] == 6
    cur.execute("SELECT COUNT(*) FROM information_schema.views "
                "WHERE table_schema = DATABASE() AND table_name = 'v_plain'")
    assert cur.fetchone()[0] == 0                         # plain has tenant_id, not org_id


def test_view_fails_closed_without_tenant(conn):
    assert _ids(conn.cursor()) == []


def test_view_resolves_the_caller_not_the_definer():
    app = _connect("dbfw_app", APP_PW)     # mapped to B; the view's definer is mapped to A
    try:
        assert _ids(app.cursor()) == [2]
    finally:
        app.close()


def test_trigger_blocks_null_tenant_insert(conn, cfg):
    protect(conn, tenant_id="A", config=cfg)
    with pytest.raises(pymysql.err.OperationalError, match="Cross-tenant INSERT"):
        conn.cursor().execute("INSERT INTO orders VALUES (92, NULL)")


def test_trigger_blocks_insert_without_tenant(conn):
    with pytest.raises(pymysql.err.OperationalError, match="No tenant context"):
        conn.cursor().execute("INSERT INTO orders VALUES (90, 'A')")


def test_protect_scopes_both_layers(conn, cfg):
    pc = protect(conn, tenant_id="A", config=cfg)
    assert _ids(pc.cursor(), "orders") == [1]             # middleware rewrite on the base table
    assert _ids(conn.cursor()) == [1]                     # raw cursor: the view, same session
    pc.release()
    assert _ids(conn.cursor()) == []


def test_trigger_blocks_cross_tenant_insert(conn, cfg):
    protect(conn, tenant_id="A", config=cfg)
    with pytest.raises(pymysql.err.OperationalError, match="Cross-tenant INSERT"):
        conn.cursor().execute("INSERT INTO orders VALUES (91, 'B')")   # raw: trigger layer


def test_audit_row_and_purge(conn, cfg):
    cfg["audit"]["enabled"] = True
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM _firewall_audit_log WHERE auth_method = 'middleware'")
    before = cur.fetchone()[0]
    protect(conn, tenant_id="A", config=cfg)
    cur.execute("SELECT COUNT(*) FROM _firewall_audit_log WHERE auth_method = 'middleware'")
    assert cur.fetchone()[0] == before + 1
    cur.execute("UPDATE _firewall_audit_log SET assigned_at = NOW() - INTERVAL 100 DAY "
                "WHERE auth_method = 'middleware'")
    assert purge_audit(conn, cfg, DBEngine.MYSQL) >= 1


def test_resolution_from_map_and_session_var(conn, cfg):
    conn.cursor().execute("SET @_fw_tenant_id = 'B'")
    cfg["resolution"] = [{"source": "session_var"}]
    assert protect(conn, config=cfg)._tenant_id == "B"
    conn.cursor().execute("SET @_fw_tenant_id = NULL")
    cfg["resolution"] = [{"source": "db_user_map"}]
    assert protect(conn, config=cfg)._tenant_id == "A"


def test_excluded_user(conn, cfg):
    cfg["excluded_users"] = [unquote(U.username)]
    pc = protect(conn, config=cfg)
    assert pc._bypass
    assert _ids(pc.cursor()) == []                        # the view still applies


def test_pool_checkin_clears(conn, cfg):
    protect(conn, tenant_id="A", config=cfg)
    pool_checkin(conn)
    assert _ids(conn.cursor()) == []


def test_scanner(conn, cfg):
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS late_table")
    cur.execute("CREATE TABLE late_table (id INT, org_id VARCHAR(64))")   # after the migration
    report = scan_tables(conn, DBEngine.MYSQL, cfg)
    cur.execute("DROP TABLE late_table")
    assert report["orders"]["protected"] is True
    assert report["vault"]["protected"] is True
    assert report["late_table"]["protected"] is False
    assert "plain" not in report and "notes" not in report
