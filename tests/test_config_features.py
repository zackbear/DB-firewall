"""
The config sections that used to be documentation only: excluded_users,
audit, resolution and engines. Fake drivers for the logic; live PostgreSQL
(DBFW_PG_DSN) for the SQL each feature sends.
"""

import copy
import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
pytest.importorskip("sqlglot")
import db_firewall  # noqa: E402
from db_firewall import (DBEngine, ProtectedConnection, load_config, protect,  # noqa: E402
                         purge_audit, tenant_scope)
from db_firewall.resolution import resolve_tenant  # noqa: E402

DSN = os.environ.get("DBFW_PG_DSN")
live = pytest.mark.skipif(not DSN, reason="DBFW_PG_DSN not set")


class Cursor:
    def __init__(self, conn):
        self.conn, self.rowcount = conn, 0

    def execute(self, sql, params=None):
        self.conn.log.append((sql, params))
        for needle, value in self.conn.answers.items():
            if needle in sql:
                if isinstance(value, Exception):
                    raise value
                self.row = (value,)
                return
        self.row = None

    def fetchone(self):
        return self.row

    def close(self):
        pass


def fake(module="pymysql", **answers):
    cls = type("Connection", (), {"__module__": module,
                                  "cursor": lambda self, *a: Cursor(self),
                                  "rollback": lambda self: None,
                                  "commit": lambda self: None})
    conn = cls()
    conn.log, conn.answers = [], answers
    return conn


@pytest.fixture
def cfg():
    return copy.deepcopy(load_config())


def _write(tmp_path, **cfg):
    path = tmp_path / "fw.json"
    path.write_text(json.dumps(cfg))
    return str(path)


# ---------------------------------------------------------------- validation

class TestValidation:
    @pytest.mark.parametrize("bad", [
        {"resolution": [{"source": "magic"}]},
        {"resolution": ["env_var"]},
        {"resolution": [{"source": "db_user_map", "table": "t; DROP TABLE x"}]},
        {"excluded_users": "postgres"},
        {"excluded_users": [""]},
        {"audit": {"table_name": "log; --"}},
        {"engines": {"oracle": {"audit_table": "a b"}}},
    ])
    def test_bad_settings_raise(self, tmp_path, bad):
        with pytest.raises(ValueError):
            load_config(project_root=_write(tmp_path, **bad))

    def test_defaults_keep_old_behaviour(self, cfg):
        assert cfg["audit"]["enabled"] is False
        assert [e["source"] for e in cfg["resolution"]] == ["env_var", "db_user_map"]
        assert db_firewall.db_context_enabled(cfg, DBEngine.POSTGRESQL)


# ---------------------------------------------------------------- resolution

class TestResolution:
    def test_order_is_configurable(self, cfg, monkeypatch):
        monkeypatch.setenv("TENANT_ID", "ENV")
        conn = fake(**{"_firewall_tenant_map": "MAP"})
        assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "ENV"
        cfg["resolution"].reverse()
        assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "MAP"

    def test_disabled_source_skipped_and_custom_env_name(self, cfg, monkeypatch):
        monkeypatch.setenv("TENANT_ID", "ENV")
        monkeypatch.setenv("APP_TENANT", "APP")
        cfg["resolution"] = [{"source": "env_var", "variable": "TENANT_ID", "enabled": False},
                             {"source": "env_var", "variable": "APP_TENANT"}]
        assert resolve_tenant(fake(), DBEngine.MYSQL, cfg) == "APP"

    def test_custom_map_table(self, cfg):
        cfg["resolution"] = [{"source": "db_user_map", "table": "tenants.map"}]
        conn = fake(**{"FROM tenants.map": "T"})
        assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "T"

    def test_invalid_value_skipped_with_warning(self, cfg, monkeypatch, caplog):
        monkeypatch.setenv("TENANT_ID", "bad\\id")
        conn = fake(**{"_firewall_tenant_map": "MAP"})
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "MAP"
        assert "ignoring tenant from env_var" in caplog.text

    def test_session_var_per_engine(self, cfg):
        cfg["resolution"] = [{"source": "session_var"}]
        assert resolve_tenant(fake(**{"@_fw_tenant_id": "S"}), DBEngine.MYSQL, cfg) == "S"
        assert resolve_tenant(fake("oracledb", **{"CTX_SAAS": "O"}), DBEngine.ORACLE, cfg) == "O"
        assert resolve_tenant(fake("sqlite3"), DBEngine.SQLITE, cfg) is None

    def test_connection_param(self, cfg):
        cfg["resolution"] = [{"source": "connection_param", "param_name": "tenant_id"}]
        conn = fake()
        conn.dsn = "mysql://h/db?tenant_id=P&x=1"
        assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "P"
        conn.tenant_id = "ATTR"
        assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "ATTR"

    def test_request_tenant_always_wins(self, cfg, monkeypatch):
        monkeypatch.setenv("TENANT_ID", "ENV")
        with tenant_scope("REQ"):
            assert protect(fake("sqlite3"), config=cfg)._tenant_id == "REQ"


# ---------------------------------------------------------------- excluded_users

class TestExcludedUsers:
    def test_listed_user_is_not_scoped(self, cfg):
        cfg["excluded_users"] = ["svc_migrator"]
        conn = fake(**{"CURRENT_USER()": "svc_migrator"})
        pc = protect(conn, config=cfg)
        assert pc._bypass and pc._tenant_id is None
        pc.cursor().execute("DELETE FROM orders")
        assert conn.log[-1][0] == "DELETE FROM orders"      # unscoped, no refusal

    def test_other_user_still_scoped(self, cfg, monkeypatch):
        monkeypatch.setattr(db_firewall, "_has_tenant_column", lambda *a, **k: True)
        cfg["excluded_users"] = ["svc_migrator"]
        conn = fake(**{"SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1)": "app"})
        pc = protect(conn, config=cfg)
        assert not pc._bypass
        with pytest.raises(PermissionError):                   # no tenant: refused
            pc.cursor().execute("SELECT * FROM orders")

    def test_failed_lookup_is_not_excluded(self, cfg):
        cfg["excluded_users"] = ["svc_migrator"]
        conn = fake(**{"CURRENT_USER()": RuntimeError("no")})
        assert not protect(conn, config=cfg)._bypass

    def test_no_lookup_when_list_is_empty(self, cfg):
        conn = fake()
        protect(conn, tenant_id="A", config=cfg)
        assert not any("CURRENT_USER" in sql for sql, _ in conn.log)

    def test_match_is_exact(self, cfg):
        cfg["excluded_users"] = ["SVC"]
        assert not protect(fake(**{"CURRENT_USER()": "svc"}), config=cfg)._bypass


# ---------------------------------------------------------------- audit + engines

class TestAuditAndEngines:
    def test_audit_row_written_with_context(self, cfg):
        cfg["audit"]["enabled"] = True
        conn = fake()
        ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL)
        sql, params = conn.log[-1]
        assert sql.startswith("INSERT INTO _firewall_audit_log") and params == ("A",)

    def test_oracle_audit_left_to_the_package(self, cfg):
        cfg["audit"]["enabled"] = True
        conn = fake("oracledb")
        ProtectedConnection(conn, "A", cfg, DBEngine.ORACLE)
        assert [sql for sql, _ in conn.log] == ["BEGIN PKG_SAAS_SECURITY.set_tenant(:1); END;"]

    def test_audit_failure_fails_closed(self, cfg):
        cfg["audit"]["enabled"] = True
        conn = fake(**{"INSERT INTO": RuntimeError("no table")})
        with pytest.raises(RuntimeError):
            ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL)
        cfg["fail_mode"] = "open"
        ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL)     # warns, middleware-only

    def test_use_flag_off_skips_db_context(self, cfg):
        cfg["engines"]["mysql"] = {"use_views": False}
        cfg["audit"]["enabled"] = True
        conn = fake()
        ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL).release()
        assert conn.log == []                                   # no SET, no audit, no clear

    def test_log_queries(self, cfg, caplog):
        cfg["audit"]["log_queries"] = True
        conn = fake("sqlite3")
        monkey = protect(conn, tenant_id="A", config=cfg).cursor()
        db_firewall.introspection._conn_table_cache(conn)
        with caplog.at_level(logging.INFO, logger="db_firewall.audit"):
            monkey._bypass = True
            monkey.execute("SELECT 1")
        assert "tenant=A sql=SELECT 1" in caplog.text

    def test_purge_rejects_negative_and_unknown(self, cfg):
        with pytest.raises(ValueError):
            purge_audit(fake(), cfg, DBEngine.MYSQL, retention_days=-1)
        with pytest.raises(ValueError):
            purge_audit(fake("sqlite3"), cfg, DBEngine.SQLITE)


# ---------------------------------------------------------------- live PostgreSQL

@pytest.fixture
def pg():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(open(os.path.join(os.path.dirname(__file__), '..', 'migrations',
                                        '001_postgresql.sql')).read())
        admin.execute("DROP TABLE IF EXISTS cf_orders")
        admin.execute("CREATE TABLE cf_orders (id int, tenant_id text)")
        admin.execute("INSERT INTO cf_orders VALUES (1,'A'),(2,'B')")
    conn = psycopg.connect(DSN)
    yield conn
    conn.close()
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP TABLE IF EXISTS cf_orders")


@live
class TestLivePostgres:
    def test_excluded_user_sees_all_rows(self, pg, cfg):
        cfg["excluded_users"] = [pg.execute("SELECT current_user").fetchone()[0]]
        cur = protect(pg, config=cfg).cursor()
        cur.execute("SELECT id FROM cf_orders ORDER BY id")
        assert cur.fetchall() == [(1,), (2,)]

    def test_audit_row_and_purge(self, pg, cfg):
        cfg["audit"]["enabled"] = True
        before = pg.execute("SELECT count(*) FROM _firewall_audit_log WHERE auth_method = 'middleware'").fetchone()[0]
        protect(pg, tenant_id="A", config=cfg)
        after = pg.execute("SELECT count(*) FROM _firewall_audit_log WHERE auth_method = 'middleware'").fetchone()[0]
        assert after == before + 1
        pg.execute("UPDATE _firewall_audit_log SET assigned_at = now() - interval '100 days' "
                   "WHERE auth_method = 'middleware'")
        assert purge_audit(pg, cfg, DBEngine.POSTGRESQL) >= 1
        assert purge_audit(pg, cfg, DBEngine.POSTGRESQL) == 0
        pg.rollback()

    def test_session_var_source(self, pg, cfg):
        pg.execute("SELECT set_config('app.current_tenant', 'S', true)")
        cfg["resolution"] = [{"source": "session_var", "variable": "app.current_tenant"}]
        assert protect(pg, config=cfg)._tenant_id == "S"
        pg.rollback()

    def test_use_rls_false_sets_no_guc(self, pg, cfg):
        cfg["engines"]["postgresql"] = {"use_rls": False}
        protect(pg, tenant_id="A", config=cfg)
        assert pg.execute("SELECT current_setting('app.current_tenant', true)").fetchone()[0] in (None, "")
        pg.rollback()

    def test_sqlalchemy_excluded_user_and_audit(self, pg, cfg):
        sa = pytest.importorskip("sqlalchemy")
        from psycopg.conninfo import conninfo_to_dict
        d = conninfo_to_dict(DSN)
        url = f"postgresql+psycopg://{d.get('user', 'postgres')}@{d.get('host', 'localhost')}:{d.get('port', 5432)}/{d['dbname']}"
        user = pg.execute("SELECT current_user").fetchone()[0]
        pg.rollback()

        eng = sa.create_engine(url)
        cfg["excluded_users"] = [user]
        db_firewall.sqlalchemy_event_hooks(eng, config=cfg)
        with eng.connect() as c:                      # no tenant, but excluded: all rows
            assert [r[0] for r in c.execute(sa.text("SELECT id FROM cf_orders ORDER BY id"))] == [1, 2]
        eng.dispose()

        eng = sa.create_engine(url)
        cfg2 = copy.deepcopy(load_config())
        cfg2["audit"]["enabled"] = True
        db_firewall.sqlalchemy_event_hooks(eng, config=cfg2)
        with tenant_scope("A"), eng.connect() as c:
            assert [r[0] for r in c.execute(sa.text("SELECT id FROM cf_orders"))] == [1]
            n = c.execute(sa.text("SELECT count(*) FROM _firewall_audit_log "
                                  "WHERE auth_method = 'middleware' AND tenant_id = 'A'")).scalar()
            assert n >= 1
        eng.dispose()
