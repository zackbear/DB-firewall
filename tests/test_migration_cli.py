"""run_migration finds the repo's migrations/ folder and fails loudly when a
file is missing. The CLI offers only commands that do something."""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
import db_firewall  # noqa: E402
from db_firewall import DBEngine, run_migration  # noqa: E402


class FakeConn:
    def __init__(self):
        self.executed, self.commits = [], 0

    def cursor(self):
        return self

    def execute(self, sql, *a):
        self.executed.append(sql)

    def close(self):
        pass

    def commit(self):
        self.commits += 1


def test_postgres_migration_file_is_found_and_run(monkeypatch):
    conn = FakeConn()
    run_migration(conn, DBEngine.POSTGRESQL, {"tenant_column": "org_id"})
    # With DB_FIREWALL_TENANT_KEY (conftest): logging off, then the settings, then the script.
    assert "log_statement" in conn.executed[0] and "dbfw.tenant_key" in conn.executed[1]
    assert len(conn.executed) == 3 and "_firewall_tenant_map" in conn.executed[2]
    assert conn.commits == 1
    monkeypatch.delenv("DB_FIREWALL_TENANT_KEY")
    conn = FakeConn()
    run_migration(conn, DBEngine.POSTGRESQL, {"tenant_column": "org_id"})
    assert "dbfw.tenant_column" in conn.executed[0]          # no key: settings first, then the script
    assert len(conn.executed) == 2 and "_firewall_tenant_map" in conn.executed[1]


def test_sqlserver_migration_split_on_go():
    conn = FakeConn()
    run_migration(conn, DBEngine.SQLSERVER)
    assert len(conn.executed) > 1
    assert not any(s.strip().upper() == "GO" for s in conn.executed)


def test_missing_migration_file_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(db_firewall, "MIGRATIONS_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        run_migration(FakeConn(), DBEngine.SQLSERVER)


def test_oracle_script_is_refused():
    with pytest.raises(NotImplementedError):
        run_migration(FakeConn(), DBEngine.ORACLE)


def test_mysql_split_on_delimiter():
    from middleware.db_firewall.migrate import _mysql_statements
    stmts = _mysql_statements("DELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1; END //\n"
                              "DELIMITER ;\n-- note\nCALL p();\n")
    assert stmts == ["CREATE PROCEDURE p() BEGIN SELECT 1; END ", "CALL p()"]


def test_engine_without_migration_is_a_noop():
    conn = FakeConn()
    run_migration(conn, DBEngine.SQLITE)
    assert conn.executed == [] and conn.commits == 0


def _cli(*args):
    root = os.path.join(os.path.dirname(__file__), '..')
    env = {k: v for k, v in os.environ.items() if not k.startswith("DB_FIREWALL_")}
    return subprocess.run([sys.executable, "-m", "middleware.db_firewall", *args],
                          cwd=root, capture_output=True, timeout=30, env=env)


def test_cli_info_prints_config():
    out = _cli("info")
    assert out.returncode == 0 and b'"fail_mode": "closed"' in out.stdout


@pytest.mark.parametrize("cmd", ["migrate", "check"])
def test_cli_rejects_commands_that_did_nothing(cmd):
    assert _cli(cmd).returncode == 2
