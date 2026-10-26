"""
Live Oracle (Oracle Database Free 23ai) tests: VPD migration with a custom
tenant column, the Python middleware's Oracle paths, and the scanner.

Opt-in. Set DBFW_ORA_DSN=user/password@host:port/service for the schema owner
the migration was run for, after tests/oracle_setup.sql and the migration:

    sqlplus app/pw@//localhost:1521/FREEPDB1 @tests/oracle_setup.sql
    sqlplus system/pw@//localhost:1521/FREEPDB1 @migrations/004_oracle.sql
      (with SCHEMA_OWNER = that user and TENANT_COLUMN = 'ORG_ID')
    sqlplus app/pw@//localhost:1521/FREEPDB1 @tests/oracle_after_migration.sql
"""

import copy
import os
import sys

import pytest

DSN = os.environ.get("DBFW_ORA_DSN")
if not DSN:
    pytest.skip("DBFW_ORA_DSN not set; skipping live Oracle tests", allow_module_level=True)
oracledb = pytest.importorskip("oracledb")
pytest.importorskip("sqlglot")

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
from hooks.scan_engines import scan_tables  # noqa: E402
from middleware.db_firewall import (DBEngine, detect_engine, load_config, pool_checkin,  # noqa: E402
                                    protect, tenant_scope)

USER, rest = DSN.split("/", 1)
PASSWORD, ADDRESS = rest.split("@", 1)


@pytest.fixture
def cfg():
    c = copy.deepcopy(load_config())
    c["tenant_column"] = "org_id"
    return c


@pytest.fixture
def conn():
    c = oracledb.connect(user=USER, password=PASSWORD, dsn=ADDRESS)
    c.cursor().execute("BEGIN PKG_SAAS_SECURITY.clear_tenant; END;")   # no logon-trigger tenant
    yield c
    c.rollback()
    c.close()


def _ids(cursor, table="ORDERS"):
    cursor.execute(f"SELECT id FROM {table} ORDER BY id")
    return [r[0] for r in cursor.fetchall()]


def test_engine_detected(conn):
    assert detect_engine(conn) == DBEngine.ORACLE


def test_vpd_fails_closed_without_tenant(conn):
    assert _ids(conn.cursor()) == []


def test_protect_scopes_both_layers(conn, cfg):
    pc = protect(conn, tenant_id="A", config=cfg)
    assert _ids(pc.cursor()) == [1]                       # middleware rewrite on org_id
    assert _ids(conn.cursor()) == [1]                     # raw cursor: VPD on the same session
    pc.release()
    assert _ids(conn.cursor()) == []                      # clear_tenant ran


def test_set_tenant_does_not_commit_caller_work(conn, cfg):
    cur = conn.cursor()
    cur.execute("INSERT INTO NOTES (id, body) VALUES (99, 'uncommitted')")
    protect(conn, tenant_id="A", config=cfg)              # calls set_tenant (audits)
    conn.rollback()
    cur.execute("SELECT COUNT(*) FROM NOTES WHERE id = 99")
    assert cur.fetchone()[0] == 0                         # set_tenant did not commit it


def test_set_tenant_writes_audit_row(conn, cfg):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM VPD_AUDIT_LOG WHERE tenant_id = 'A'")
    before = cur.fetchone()[0]
    protect(conn, tenant_id="A", config=cfg)
    cur.execute("SELECT COUNT(*) FROM VPD_AUDIT_LOG WHERE tenant_id = 'A'")
    assert cur.fetchone()[0] == before + 1


def test_insert_with_other_tenant_blocked(conn, cfg):
    pc = protect(conn, tenant_id="A", config=cfg)
    with pytest.raises(Exception):
        pc.cursor().execute("INSERT INTO ORDERS (id, org_id) VALUES (50, 'B')")


def test_resolution_from_map_and_session_var(conn, cfg):
    cur = conn.cursor()
    cur.execute("BEGIN PKG_SAAS_SECURITY.set_tenant('B'); END;")
    cfg["resolution"] = [{"source": "session_var"}]
    assert protect(conn, config=cfg)._tenant_id == "B"
    cur.execute("BEGIN PKG_SAAS_SECURITY.clear_tenant; END;")
    cfg["resolution"] = [{"source": "db_user_map"}]
    assert protect(conn, config=cfg)._tenant_id == "A"    # TENANT_USER_MAP row for this user


def test_excluded_user_bypasses_middleware_not_vpd(conn, cfg):
    cfg["excluded_users"] = [USER.upper()]
    pc = protect(conn, config=cfg)
    assert pc._bypass
    assert _ids(pc.cursor()) == []                        # VPD still applies: no context set


def test_pool_checkin_clears_context(conn, cfg):
    protect(conn, tenant_id="A", config=cfg)
    pool_checkin(conn)
    assert _ids(conn.cursor()) == []


def test_request_tenant_and_rewrite_on_join(conn, cfg):
    with tenant_scope("B"):
        pc = protect(conn, config=cfg)
    cur = pc.cursor()
    cur.execute("SELECT o.id FROM ORDERS o JOIN ORDERS p ON p.id = o.id ORDER BY o.id")
    assert [r[0] for r in cur.fetchall()] == [2]


def test_scanner(conn, cfg):
    report = scan_tables(conn, DBEngine.ORACLE, cfg)
    assert report["ORDERS"]["protected"] is True
    assert report["LATE_TABLE"]["protected"] is False     # created after the migration
    assert "PLAIN" not in report and "NOTES" not in report  # no org_id column
    assert "VPD_AUDIT_LOG" not in report and "TENANT_USER_MAP" not in report
