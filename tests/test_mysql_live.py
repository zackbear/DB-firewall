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
LONG = "a_table_name_that_is_longer_than_fifty_seven_characters_xyz"


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
    db = U.path.lstrip('/')
    # Exactly the README grant recipe.
    cur.execute(f"GRANT SELECT ON `{db}`.`v_orders` TO 'dbfw_app'@'%'")
    cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.`orders` TO 'dbfw_app'@'%'")
    cur.execute(f"GRANT INSERT ON `{db}`.`_firewall_audit_log` TO 'dbfw_app'@'%'")
    cur.execute(f"GRANT EXECUTE ON PROCEDURE `{db}`.`_firewall_init_connection` TO 'dbfw_app'@'%'")
    cur.execute("DELETE FROM _firewall_tenant_map")
    # Only the app user is mapped: a mapped user gets its tenant from the map
    # even with no session tenant, which the fail-closed tests rule out.
    cur.execute("INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES ('dbfw_app', 'B')")
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
                "AND event_object_table IN ('orders', 'vault', %s) AND trigger_name LIKE '#_fw#_b%%' ESCAPE '#'",
                (LONG,))
    assert cur.fetchone()[0] == 9
    cur.execute("SELECT COUNT(*) FROM information_schema.views "
                "WHERE table_schema = DATABASE() AND table_name = 'v_plain'")
    assert cur.fetchone()[0] == 0                         # plain has tenant_id, not org_id


def test_migration_under_no_backslash_escapes():
    c = _connect()
    try:
        c.cursor().execute("SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_BACKSLASH_ESCAPES')")
        run_migration(c, DBEngine.MYSQL, _cfg())             # re-run, routines re-created in this mode
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = DATABASE() "
                    "AND trigger_name LIKE '#_fw#_b%' ESCAPE '#'")
        assert cur.fetchone()[0] == 9
        cur.execute("SELECT COUNT(*) FROM information_schema.views WHERE table_schema = DATABASE() "
                    "AND table_name LIKE 'v#__firewall%' ESCAPE '#'")
        assert cur.fetchone()[0] == 0                         # no views on the firewall's own tables
    finally:
        c.close()


def test_view_fails_closed_without_tenant(conn):
    assert _ids(conn.cursor()) == []


def test_view_resolves_the_caller_not_the_definer():
    app = _connect("dbfw_app", APP_PW)     # mapped to B; the view's definer is mapped to A
    try:
        assert _ids(app.cursor()) == [2]
    finally:
        app.close()


def test_bypass_marker_and_tenant_match_are_exact(conn):
    cur = conn.cursor()
    for value in ("__bypass__", "__BYPÄSS__", "b"):          # row 2 belongs to "B"
        cur.execute("SET @_fw_tenant_id = %s", (value,))
        assert _ids(cur) == []
    with pytest.raises(pymysql.err.OperationalError, match="Cross-tenant INSERT"):
        cur.execute("INSERT INTO orders VALUES (93, 'A')")


def test_middleware_refuses_setting_the_variable(conn, cfg):
    pc = protect(conn, tenant_id="A", config=cfg)
    for sql in ("SET @a = 1, @_fw_tenant_id = '__BYPASS__'",
                "SET @'_fw_tenant_i\\d' = '__BYPASS__'", "SET @_fw_tenänt_id = '__BYPASS__'"):
        with pytest.raises(PermissionError):
            pc.cursor().execute(sql)
    cur = conn.cursor()
    cur.execute("SELECT _firewall_is_bypass(), @_fw_tenant_id")
    assert cur.fetchone() == (0, "A")


def test_readme_grants_are_enough_for_the_app(cfg):
    cfg["audit"]["enabled"] = True
    admin = _connect()                     # a migration re-run drops routine grants: grant again
    admin.cursor().execute(f"GRANT EXECUTE ON PROCEDURE `{U.path.lstrip('/')}`."
                           "`_firewall_init_connection` TO 'dbfw_app'@'%'")
    admin.close()
    app = _connect("dbfw_app", APP_PW)
    try:
        app.cursor().execute("CALL _firewall_init_connection()")      # pool hook: map -> B
        pc = protect(app, tenant_id="B", config=cfg)                   # audit row as the app
        cur = pc.cursor()
        cur.execute("UPDATE orders SET id = 20 WHERE id = 2")           # rolled back below
        assert cur.rowcount == 1
        cur.execute("DELETE FROM orders WHERE id = 1")                 # A's row: scoped away
        assert cur.rowcount == 0
        assert _ids(app.cursor()) == [20]                              # raw read through the view
        with pytest.raises(pymysql.err.OperationalError):
            app.cursor().execute("CALL _firewall_apply_all()")         # no EXECUTE on it
    finally:
        app.rollback()
        app.close()


@pytest.mark.parametrize("rewriter", ["ast", "regex"])
def test_executable_comments_refused(conn, cfg, rewriter):
    cfg["rewriter"] = rewriter
    cur = protect(conn, tenant_id="A", config=cfg).cursor()
    for sql in ("SELECT id FROM orders WHERE id > 0 /*! OR 1=1 */", "/*!DELETE FROM orders*/"):
        with pytest.raises(PermissionError):
            cur.execute(sql)
    assert _ids(conn.cursor(), "orders") == [1, 2]       # nothing deleted (raw admin read)


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
    cur = conn.cursor()
    cur.execute("INSERT INTO _firewall_tenant_map (db_user, tenant_id) "
                "VALUES (SUBSTRING_INDEX(CURRENT_USER(), '@', 1), 'A')")
    cfg["resolution"] = [{"source": "db_user_map"}]
    assert protect(conn, config=cfg)._tenant_id == "A"    # rolled back by the fixture


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
    assert report[LONG]["protected"] is True                 # hashed name stem
    assert report["late_table"]["protected"] is False
    assert "plain" not in report and "notes" not in report
