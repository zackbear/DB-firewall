"""
Engine-specific code paths with fake DB-API objects, so they run without a
MySQL, SQL Server or Oracle server: engine detection, DB-side tenant context,
fail-closed setup, cursor mediation, pool check-in and tenant-map lookup.
"""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
import db_firewall  # noqa: E402
from db_firewall import (  # noqa: E402
    DBEngine, ProtectedConnection, ProtectedCursor, clear_db_context, detect_engine,
    load_config, pool_checkin, protect,
)

pytest.importorskip("sqlglot")


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None, **kw):
        self.conn.log.append((sql, params))
        if self.conn.fail_on and self.conn.fail_on in sql:
            raise self.conn.error
        return self

    def executemany(self, sql, seq, **kw):
        self.conn.log.append((sql, list(seq)))

    def stream(self, sql, params=None, **kw):
        self.conn.log.append((sql, params))
        return iter(())

    def copy(self, sql, params=None, **kw):
        self.conn.log.append((sql, params))

    def fetchone(self):
        return self.conn.row

    def close(self):
        pass

    def __iter__(self):
        return iter([(1,)])

    rowcount = 0


class FakeConn:
    def __init__(self, module="pymysql.connections", row=None, fail_on=None,
                 error=RuntimeError("boom"), in_transaction=None, autocommit=False):
        self.log, self.row, self.fail_on, self.error = [], row, fail_on, error
        self.rollbacks = self.commits = 0
        self.closed = False
        self.autocommit = autocommit
        if in_transaction is not None:
            self.in_transaction = in_transaction
        type(self).__module__ = module

    def cursor(self, *a, **k):
        return FakeCursor(self)

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def fake(module, **kw):
    cls = type("Connection", (FakeConn,), {})   # fresh class: __module__ is per class
    return cls(module=module, **kw)


@pytest.fixture
def cfg():
    return load_config()


class TestDetectEngine:
    @pytest.mark.parametrize("module,engine", [
        ("psycopg2.extensions", DBEngine.POSTGRESQL), ("psycopg", DBEngine.POSTGRESQL),
        ("pymysql.connections", DBEngine.MYSQL), ("MySQLdb.connections", DBEngine.MYSQL),
        ("pymssql._pymssql", DBEngine.SQLSERVER), ("oracledb.connection", DBEngine.ORACLE),
        ("cx_Oracle", DBEngine.ORACLE), ("sqlite3", DBEngine.SQLITE),
    ])
    def test_by_module(self, module, engine):
        assert detect_engine(fake(module)) == engine

    @pytest.mark.parametrize("dbms,engine", [
        ("Microsoft SQL Server", DBEngine.SQLSERVER), ("MySQL", DBEngine.MYSQL),
        ("Oracle", DBEngine.ORACLE), ("PostgreSQL", DBEngine.POSTGRESQL),
    ])
    def test_odbc_driver_name(self, dbms, engine):
        conn = fake("vendor.odbc")
        conn.getinfo = lambda code: dbms
        assert detect_engine(conn) == engine

    def test_unknown_logs(self, caplog):
        conn = fake("vendor.odbc")
        conn.getinfo = lambda code: 1 / 0
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            assert detect_engine(conn) == DBEngine.UNKNOWN
        assert "Unknown engine" in caplog.text


class TestDbContext:
    @pytest.mark.parametrize("module,needle", [
        ("pymysql", "@_fw_tenant_id"), ("pymssql", "sp_set_session_context"),
        ("oracledb", "PKG_SAAS_SECURITY.set_tenant"),
    ])
    def test_tenant_is_bound_never_interpolated(self, cfg, module, needle):
        conn = fake(module)
        ProtectedConnection(conn, "T'1", cfg, detect_engine(conn))
        sql, params = conn.log[0]
        assert needle in sql and "T'1" not in sql and params == ("T'1",)

    @pytest.mark.parametrize("module,needle", [
        ("pymysql", "@_fw_tenant_id = NULL"), ("pymssql", "@value=NULL"),
        ("oracledb", "clear_tenant"),
    ])
    def test_release_clears(self, cfg, module, needle):
        conn = fake(module)
        pc = ProtectedConnection(conn, "A", cfg, detect_engine(conn))
        pc.release()
        assert needle in conn.log[-1][0]

    def test_setter_failure_fails_closed(self, cfg):
        conn = fake("pymysql", fail_on="SET @_fw")
        with pytest.raises(RuntimeError):
            ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL)

    def test_setter_failure_open_mode_warns(self, cfg, caplog):
        cfg["fail_mode"] = "open"
        conn = fake("pymysql", fail_on="SET @_fw")
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL)
        assert "middleware-only enforcement" in caplog.text

    def test_clear_failure_is_logged_not_raised(self, caplog):
        conn = fake("pymysql", fail_on="NULL")
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            clear_db_context(conn)
        assert "Could not clear DB context" in caplog.text

    def test_clear_unknown_engine_noop(self):
        conn = fake("sqlite3")
        clear_db_context(conn)
        assert conn.log == []

    def test_bad_tenant_rejected(self, cfg):
        with pytest.raises(ValueError):
            ProtectedConnection(fake("pymysql"), "A\\", cfg, DBEngine.MYSQL)


class TestPoolCheckin:
    def test_rolls_back_clears_commits(self):
        conn = fake("pymysql")
        pool_checkin(conn)
        assert conn.rollbacks == 1 and conn.commits == 1
        assert "NULL" in conn.log[-1][0]

    def test_healthy_error_is_logged(self, caplog):
        conn = fake("pymysql", fail_on="NULL")
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            pool_checkin(conn)
        assert "Could not clear DB context" in caplog.text

    def test_connection_error_is_raised(self):
        class OperationalError(Exception):
            pass
        conn = fake("pymysql", fail_on="NULL", error=OperationalError("gone"))
        with pytest.raises(OperationalError):
            pool_checkin(conn)

    def test_closed_connection_error_is_raised(self):
        conn = fake("pymysql", fail_on="NULL")
        conn.closed = True
        with pytest.raises(RuntimeError):
            pool_checkin(conn)

    def test_engine_without_context_noop(self):
        conn = fake("sqlite3")
        pool_checkin(conn)
        assert conn.rollbacks == 0 and conn.log == []


class TestCursorMediation:
    def _cursor(self, cfg, tenant="A"):
        conn = fake("pymysql")
        return conn, ProtectedCursor(FakeCursor(conn), tenant, cfg, None, DBEngine.MYSQL)

    @pytest.mark.parametrize("method", ["execute", "stream"])
    def test_scoped(self, cfg, method):
        conn, cur = self._cursor(cfg)
        getattr(cur, method)("SELECT * FROM orders")
        assert "tenant_id = 'A'" in conn.log[-1][0]

    def test_executemany_scoped(self, cfg):
        conn, cur = self._cursor(cfg)
        cur.executemany("UPDATE orders SET n = %s", [(1,), (2,)])
        assert "tenant_id = 'A'" in conn.log[-1][0]

    def test_copy_refused(self, cfg):
        _, cur = self._cursor(cfg)
        with pytest.raises(PermissionError):
            cur.copy("COPY orders TO STDOUT")

    @pytest.mark.parametrize("name", ["callproc", "executescript", "copy_expert",
                                      "execute_values", "run", "query"])
    def test_unmediated_methods_refused(self, cfg, name):
        _, cur = self._cursor(cfg)
        with pytest.raises(PermissionError):
            getattr(cur, name)

    def test_plain_attributes_delegate_and_iterate(self, cfg):
        _, cur = self._cursor(cfg)
        assert cur.rowcount == 0 and list(cur) == [(1,)]

    def test_no_tenant_closed_refuses_protected_table(self, cfg):
        _, cur = self._cursor(cfg, tenant=None)
        with pytest.raises(PermissionError):
            cur.execute("SELECT * FROM orders")

    def test_no_tenant_open_passes(self, cfg):
        cfg["fail_mode"] = "open"
        conn, cur = self._cursor(cfg, tenant=None)
        cur.execute("SELECT * FROM orders")
        assert conn.log[-1][0] == "SELECT * FROM orders"

    def test_context_manager_closes(self, cfg):
        _, cur = self._cursor(cfg)
        with cur as c:
            assert c is cur


class TestConnectionShortcuts:
    def test_connection_methods_route_through_cursor(self, cfg, monkeypatch):
        monkeypatch.setattr(db_firewall, "_has_tenant_column", lambda *a, **k: True)
        conn = fake("sqlite3")
        pc = ProtectedConnection(conn, "A", cfg, DBEngine.SQLITE)
        pc.execute("SELECT * FROM orders")
        pc.executemany("DELETE FROM orders WHERE id = ?", [(1,)])
        list(pc.stream("SELECT * FROM orders"))
        assert all("tenant_id = 'A'" in sql for sql, _ in conn.log)

    def test_unmediated_connection_method_refused(self, cfg):
        pc = ProtectedConnection(fake("sqlite3"), "A", cfg, DBEngine.SQLITE)
        with pytest.raises(PermissionError):
            pc.executescript

    def test_close_and_exit_release(self, cfg):
        conn = fake("pymysql")
        with ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL):
            pass
        assert "NULL" in conn.log[-1][0]
        ProtectedConnection(conn, "A", cfg, DBEngine.MYSQL).close()
        assert conn.closed


class TestProtectResolution:
    def test_env_tenant_beats_map(self, cfg, monkeypatch):
        monkeypatch.setenv("TENANT_ID", "ENV")
        conn = fake("pymysql", row=("MAP",))
        assert protect(conn, config=cfg)._tenant_id == "ENV"

    def test_map_used_last(self, cfg, monkeypatch):
        monkeypatch.delenv("TENANT_ID", raising=False)
        conn = fake("pymysql", row=("MAP",))
        assert protect(conn, config=cfg)._tenant_id == "MAP"

    def test_nothing_resolved_logs(self, cfg, monkeypatch, caplog):
        monkeypatch.delenv("TENANT_ID", raising=False)
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            assert protect(fake("pymysql"), config=cfg)._tenant_id is None
        assert "No tenant resolved" in caplog.text


class TestTenantMap:
    def test_unsupported_engine(self):
        assert db_firewall._resolve_tenant_from_map(fake("sqlite3"), DBEngine.SQLITE) is None

    def test_in_transaction_uses_savepoint(self):
        conn = fake("pymysql", row=("T",), in_transaction=True)
        assert db_firewall._resolve_tenant_from_map(conn, DBEngine.MYSQL) == "T"
        sqls = [s for s, _ in conn.log]
        assert sqls[0].startswith("SAVEPOINT") and sqls[-1].startswith("RELEASE SAVEPOINT")

    def test_failure_in_transaction_rolls_back_to_savepoint(self):
        conn = fake("pymysql", fail_on="_firewall_tenant_map", in_transaction=True)
        assert db_firewall._resolve_tenant_from_map(conn, DBEngine.MYSQL) is None
        assert conn.log[-1][0].startswith("ROLLBACK TO SAVEPOINT")

    def test_failure_when_idle_rolls_back(self):
        conn = fake("pymysql", fail_on="_firewall_tenant_map", in_transaction=False)
        assert db_firewall._resolve_tenant_from_map(conn, DBEngine.MYSQL) is None
        assert conn.rollbacks == 1

    def test_savepoint_failure_returns_none(self):
        conn = fake("pymysql", fail_on="SAVEPOINT", in_transaction=True)
        assert db_firewall._resolve_tenant_from_map(conn, DBEngine.MYSQL) is None
