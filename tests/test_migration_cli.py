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


def test_postgres_migration_file_is_found_and_run():
    conn = FakeConn()
    run_migration(conn, DBEngine.POSTGRESQL)
    assert len(conn.executed) == 1 and "_firewall_tenant_map" in conn.executed[0]
    assert conn.commits == 1


def test_sqlserver_migration_split_on_go():
    conn = FakeConn()
    run_migration(conn, DBEngine.SQLSERVER)
    assert len(conn.executed) > 1
    assert not any(s.strip().upper() == "GO" for s in conn.executed)


def test_missing_migration_file_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(db_firewall, "MIGRATIONS_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        run_migration(FakeConn(), DBEngine.MYSQL)


def test_engine_without_migration_is_a_noop():
    conn = FakeConn()
    run_migration(conn, DBEngine.SQLITE)
    assert conn.executed == [] and conn.commits == 0


def _cli(*args):
    path = os.path.join(os.path.dirname(__file__), '..', 'middleware', 'db_firewall.py')
    env = {k: v for k, v in os.environ.items() if not k.startswith("DB_FIREWALL_")}
    return subprocess.run([sys.executable, path, *args], capture_output=True, timeout=30, env=env)


def test_cli_info_prints_config():
    out = _cli("info")
    assert out.returncode == 0 and b'"fail_mode": "closed"' in out.stdout


@pytest.mark.parametrize("cmd", ["migrate", "check"])
def test_cli_rejects_commands_that_did_nothing(cmd):
    assert _cli(cmd).returncode == 2
