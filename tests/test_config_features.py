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
from db_firewall.db_context import _set_context_postgres  # noqa: E402
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
        {"engines": {"postgresql": {"policy_mode": "sideways"}}},
        {"engines": {"postgresql": {"policy_mode": ""}}},
        {"engines": {"postgresql": {"policy_mode": False}}},
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

    @pytest.mark.parametrize("bad", ["", "bad\\id", "a\nb"])
    def test_invalid_env_value_fails_closed(self, cfg, monkeypatch, bad):
        monkeypatch.setenv("TENANT_ID", bad)
        conn = fake(**{"_firewall_tenant_map": "MAP"})
        with pytest.raises(ValueError):                 # never falls through to the map
            resolve_tenant(conn, DBEngine.MYSQL, cfg)

    def test_empty_db_value_is_unset(self, cfg):
        cfg["resolution"] = [{"source": "session_var"}, {"source": "db_user_map"}]
        conn = fake(**{"@_fw_tenant_id": "", "_firewall_tenant_map": "MAP"})
        assert resolve_tenant(conn, DBEngine.MYSQL, cfg) == "MAP"

    def test_custom_session_var_name(self, cfg):
        cfg["resolution"] = [{"source": "session_var", "variable": "app.org"}]
        conn = fake("psycopg2", **{"current_setting": "S"})
        with pytest.raises(ValueError, match="app.current_tenant only"):     # cannot be signed
            resolve_tenant(conn, DBEngine.POSTGRESQL, cfg)
        cfg["engines"]["postgresql"]["tenant_context"] = "plain"
        assert resolve_tenant(conn, DBEngine.POSTGRESQL, cfg) == "S"
        assert conn.log[-1][1] == ("app.org",)

    def test_oracle_default_map_table(self, cfg):
        cfg["resolution"] = [{"source": "db_user_map"}]
        conn = fake("oracledb", **{"FROM TENANT_USER_MAP": "O"})
        assert resolve_tenant(conn, DBEngine.ORACLE, cfg) == "O"

    @pytest.mark.parametrize("table", ["t WHERE 1=1 OR 1", "tmap#", "a b"])
    def test_dict_config_table_names_are_checked(self, cfg, table):
        cfg["resolution"] = [{"source": "db_user_map", "table": table}]
        with pytest.raises(ValueError):
            protect(fake(), config=cfg)
        cfg["audit"]["table_name"] = table
        with pytest.raises(ValueError):
            purge_audit(fake(), cfg, DBEngine.MYSQL)

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

    def test_bypass_with_request_tenant_sets_no_db_context(self, cfg):
        cfg["excluded_users"] = ["svc"]
        cfg["audit"]["enabled"] = True
        conn = fake(**{"CURRENT_USER()": "svc"})
        with tenant_scope("A"):
            assert protect(conn, config=cfg)._bypass
        assert not any("_fw_tenant_id" in sql or "INSERT" in sql for sql, _ in conn.log)

    def test_sqlalchemy_apply_tenant_skips_excluded_and_use_off(self, cfg):
        from db_firewall.sqlalchemy_hooks import _apply_tenant
        cfg["audit"]["enabled"] = True
        cfg["excluded_users"] = ["svc"]
        excluded, off = fake(**{"CURRENT_USER()": "svc"}), fake(**{"CURRENT_USER()": "app"})
        cfg_off = copy.deepcopy(cfg)
        cfg_off["engines"]["mysql"] = {"use_views": False}
        with tenant_scope("A"):
            _apply_tenant(excluded, cfg)
            _apply_tenant(off, cfg_off)
            used = fake(**{"CURRENT_USER()": "app"})
            _apply_tenant(used, cfg)
        for conn in (excluded, off):
            assert not any("_fw_tenant_id" in sql or "INSERT" in sql for sql, _ in conn.log)
        assert any(sql.startswith("SET @_fw_tenant_id") for sql, _ in used.log)
        assert any(sql.startswith("INSERT INTO _firewall_audit_log") for sql, _ in used.log)

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

    def test_purge_retention_days(self, cfg):
        conn = fake()
        purge_audit(conn, cfg, DBEngine.MYSQL)
        purge_audit(conn, cfg, DBEngine.MYSQL, retention_days=7)
        cfg["audit"]["retention_days"] = 30
        purge_audit(conn, cfg, DBEngine.MYSQL)
        assert [p for _, p in conn.log] == [(90,), (7,), (30,)]

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
        # Install the test key: without it a fresh database generates its own.
        admin.execute("SELECT set_config('dbfw.tenant_key', %s, false)",
                      (os.environ["DB_FIREWALL_TENANT_KEY"],))
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
        _set_context_postgres(pg, "S")                      # signed for this transaction
        cfg["resolution"] = [{"source": "session_var", "variable": "app.current_tenant"}]
        assert protect(pg, config=cfg)._tenant_id == "S"
        pg.rollback()

    def test_session_var_ignores_an_unsigned_tenant(self, pg, cfg):
        # SQL the app ran can set app.current_tenant; resolving it would sign it.
        pg.execute("SELECT set_config('app.current_tenant', 'S', true)")
        cfg["resolution"] = [{"source": "session_var", "variable": "app.current_tenant"}]
        assert resolve_tenant(pg, DBEngine.POSTGRESQL, cfg) is None
        pg.rollback()
        cfg["resolution"] = [{"source": "session_var", "variable": "app.other"}]
        with pytest.raises(ValueError, match="app.current_tenant only"):
            protect(pg, config=cfg)
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


# ---------------------------------------------------------------- MySQL layer guard

class TestMySQLGuard:
    @pytest.mark.parametrize("rewriter", ["ast", "regex"])
    @pytest.mark.parametrize("sql", [
        "SET @a = 1, @_fw_tenant_id = '__BYPASS__'",
        "SET @`_fw_tenant_id` = 'B'",
        "SET @'_fw_tenant_id' = 'B'",
        "SELECT @_FW_TENANT_ID := 'B'",
        "CALL _firewall_set_tenant('B')",
        "CALL _firewall_apply_all()",
        "SET @dbfw_tenant_column = 'owner'",
        "SET @'_fw_tenant_i\\d' = '__BYPASS__'",               # MySQL drops the backslash
        'SET @"_fw_tenant_i\\d" = \'__BYPASS__\'',
        "SET @_fw_tenänt_id = '__BYPASS__'",                    # accent-insensitive names
        "SELECT @'_fw_tenant_i\\d' := '__BYPASS__'",
        "SET @s = 'x'",
        "PREPARE st FROM 'SET @x = 1'",
        "EXECUTE st",
        "CALL _firewall_init_connection()",
        "DO SLEEP(1)",
        "/*!DELETE FROM orders*/",
        "/*M!DELETE FROM orders*/",
        "SELECT id FROM orders WHERE id > 0 /*! OR 1=1 */",
        "SELECT id FROM orders /*!80000 , @y := 1 */",
    ])
    def test_statements_naming_the_layer_are_refused(self, cfg, rewriter, sql):
        from db_firewall.rewrite import check_no_tenant, rewrite_query
        cfg["rewriter"] = rewriter
        with pytest.raises(PermissionError):
            rewrite_query(sql, "A", cfg, None, DBEngine.MYSQL)
        with pytest.raises(PermissionError):
            check_no_tenant(sql, cfg, None, DBEngine.MYSQL)

    @pytest.mark.parametrize("sql", [
        "SELECT o.id, o.org_id FROM (SELECT 1) t, orders o",
        "SELECT * FROM (SELECT 1) t, orders",
        "SELECT id, org_id FROM (orders)",
        "SELECT o.id FROM (SELECT 1) t STRAIGHT_JOIN orders o",
    ])
    def test_regex_refuses_shapes_that_hide_a_table(self, cfg, sql):
        from db_firewall.rewrite import rewrite_query
        cfg["rewriter"] = "regex"
        with pytest.raises(PermissionError, match="unsupported statement shape"):
            rewrite_query(sql, "A", cfg, None, DBEngine.POSTGRESQL)

    def test_regex_still_scopes_plain_shapes(self, cfg):
        from db_firewall.rewrite import rewrite_query
        cfg["rewriter"] = "regex"
        out = rewrite_query("SELECT a, f(b, c) FROM orders WHERE x IN (1, 2) LIMIT 1",
                            "A", cfg, None, DBEngine.POSTGRESQL)
        assert "tenant_id = 'A'" in out

    @pytest.mark.parametrize("engine", [DBEngine.MYSQL, DBEngine.UNKNOWN, DBEngine.SQLITE, None])
    def test_regex_refused_where_no_database_layer(self, cfg, engine):
        from db_firewall.rewrite import check_no_tenant, rewrite_query
        cfg["rewriter"] = "regex"
        with pytest.raises(PermissionError, match="rewriter 'regex' is refused"):
            rewrite_query("SELECT id FROM orders", "A", cfg, None, engine)
        with pytest.raises(PermissionError, match="rewriter 'regex' is refused"):
            check_no_tenant("SELECT id FROM orders", cfg, None, engine)

    def test_mcp_wrapper_refuses_regex(self, cfg):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from hooks.mcp_wrapper import intercept_sql_in_tool_call
        cfg["rewriter"] = "regex"
        msg = {"method": "tools/call", "params": {"name": "q", "arguments": {
            "sql": "SELECT id, org_id FROM orders --id-2"}}}
        with pytest.raises(PermissionError):
            intercept_sql_in_tool_call(msg, "A", cfg)

    @pytest.mark.parametrize("dbms,engine", [("MySQL", DBEngine.MYSQL), ("Microsoft SQL Server",
                                             DBEngine.SQLSERVER), ("", DBEngine.UNKNOWN)])
    def test_pyodbc_engine_comes_from_the_driver(self, dbms, engine):
        conn = type("Connection", (), {"__module__": "pyodbc",
                                       "getinfo": lambda self, k: dbms})()
        assert db_firewall.detect_engine(conn) == engine

    def test_unknown_engine_gets_the_mysql_check(self, cfg):
        from db_firewall.rewrite import rewrite_query
        with pytest.raises(PermissionError):
            rewrite_query("SET @_fw_tenänt_id = '__BYPASS__'", "A", cfg, None, DBEngine.UNKNOWN)

    def test_at_sign_in_literals_and_other_engines_is_fine(self, cfg):
        from db_firewall.rewrite import rewrite_query
        assert rewrite_query("SELECT 'a@b' FROM t", "A", cfg, None, DBEngine.MYSQL)
        assert rewrite_query("SELECT * FROM t WHERE j @> '{}'", "A", cfg, None, DBEngine.POSTGRESQL)

    @pytest.mark.parametrize("tenant", ["__BYPASS__", "__bypass__", "__Bypass__"])
    def test_bypass_marker_is_not_a_tenant(self, tenant):
        from db_firewall.rewrite import validate_tenant_id
        with pytest.raises(ValueError):
            validate_tenant_id(tenant)


def test_regex_rewriter_warns_once(cfg, monkeypatch):
    from db_firewall import rewrite
    monkeypatch.setattr(rewrite, "_regex_warned", False)
    cfg["rewriter"] = "regex"
    with pytest.warns(FutureWarning, match="deprecated"):
        rewrite.rewrite_query("SELECT 1", "A", cfg, None, DBEngine.POSTGRESQL)
    assert rewrite._regex_warned
