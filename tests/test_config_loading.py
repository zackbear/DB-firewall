"""
Config is read only from an explicit path: load_config(project_root) or the
DB_FIREWALL_CONFIG env var. No silent current-folder or home-folder search,
so a file dropped in the working directory cannot change the policy.
"""

import copy
import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
import db_firewall  # noqa: E402
from db_firewall import DEFAULT_CONFIG, load_config  # noqa: E402

ENV_KEYS = ("DB_FIREWALL_CONFIG", "DB_FIREWALL_TENANT_COLUMN",
            "DB_FIREWALL_FAIL_MODE", "DB_FIREWALL_REWRITER")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(db_firewall, "_warned_orphan_config", False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(tmp_path)


def _write(path, **cfg):
    path.write_text(json.dumps(cfg))
    return path


class TestNoDiscovery:
    def test_cwd_file_is_ignored(self, tmp_path):
        _write(tmp_path / ".db-firewall.json", fail_mode="open")
        assert load_config()["fail_mode"] == "closed"

    def test_home_file_is_ignored(self, tmp_path):
        _write(tmp_path / "home" / ".db-firewall.json", fail_mode="open")
        assert load_config()["fail_mode"] == "closed"

    def test_cwd_file_warns_once(self, tmp_path, caplog):
        _write(tmp_path / ".db-firewall.json", fail_mode="open")
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            load_config()
            load_config()
        assert caplog.text.count("DB_FIREWALL_CONFIG") == 1

    def test_no_warning_when_path_is_explicit(self, tmp_path, caplog):
        _write(tmp_path / ".db-firewall.json", fail_mode="open")
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            load_config(project_root=str(tmp_path))
        assert "DB_FIREWALL_CONFIG" not in caplog.text


class TestExplicitPath:
    def test_project_root_dir(self, tmp_path):
        root = tmp_path / "app"
        root.mkdir()
        _write(root / ".db-firewall.json", tenant_column="org_id")
        assert load_config(project_root=str(root))["tenant_column"] == "org_id"

    @pytest.mark.parametrize("via", ["arg", "env"])
    def test_named_dir_without_file_raises(self, tmp_path, monkeypatch, via):
        root = tmp_path / "app"
        root.mkdir()
        (root / "firewall.json").write_text('{"tenant_column": "org_id"}')   # wrong name
        (root / ".db-firewall.yaml").mkdir()                               # a folder, not a file
        if via == "env":
            monkeypatch.setenv("DB_FIREWALL_CONFIG", str(root))
        with pytest.raises(FileNotFoundError):
            load_config(project_root=str(root) if via == "arg" else None)

    @pytest.mark.parametrize("body", ["null", "[]", '[["fail_mode", "open"]]', '"x"', "3", ""])
    def test_non_mapping_file_raises(self, tmp_path, body):
        cfg = tmp_path / "fw.json"
        cfg.write_text(body)
        with pytest.raises(ValueError, match="fw.json"):
            load_config(project_root=str(cfg))

    def test_empty_yaml_raises(self, tmp_path):
        pytest.importorskip("yaml")
        cfg = tmp_path / "fw.yaml"
        cfg.write_text("")
        with pytest.raises(ValueError, match="must hold a mapping"):
            load_config(project_root=str(cfg))

    def test_project_root_file(self, tmp_path):
        cfg = _write(tmp_path / "firewall.json", tenant_column="org_id")
        assert load_config(project_root=str(cfg))["tenant_column"] == "org_id"

    def test_env_var_file(self, tmp_path, monkeypatch):
        cfg = _write(tmp_path / "custom.json", tenant_column="org_id")
        monkeypatch.setenv("DB_FIREWALL_CONFIG", str(cfg))
        assert load_config()["tenant_column"] == "org_id"

    def test_env_var_dir(self, tmp_path, monkeypatch):
        root = tmp_path / "app"
        root.mkdir()
        _write(root / ".db-firewall.json", tenant_column="org_id")
        monkeypatch.setenv("DB_FIREWALL_CONFIG", str(root))
        assert load_config()["tenant_column"] == "org_id"

    def test_argument_wins_over_env(self, tmp_path, monkeypatch):
        arg = _write(tmp_path / "arg.json", tenant_column="from_arg")
        env = _write(tmp_path / "env.json", tenant_column="from_env")
        monkeypatch.setenv("DB_FIREWALL_CONFIG", str(env))
        assert load_config(project_root=str(arg))["tenant_column"] == "from_arg"

    @pytest.mark.parametrize("via", ["arg", "env"])
    def test_missing_explicit_path_raises(self, tmp_path, monkeypatch, via):
        missing = str(tmp_path / "nope.yaml")
        if via == "env":
            monkeypatch.setenv("DB_FIREWALL_CONFIG", missing)
            with pytest.raises(FileNotFoundError):
                load_config()
        else:
            with pytest.raises(FileNotFoundError):
                load_config(project_root=missing)

    def test_yaml_without_pyyaml_raises(self, tmp_path, monkeypatch):
        cfg = tmp_path / "fw.yaml"
        cfg.write_text("fail_mode: open\n")
        monkeypatch.setattr(db_firewall, "HAS_YAML", False)
        with pytest.raises(ImportError):
            load_config(project_root=str(cfg))

    def test_env_overrides_still_win(self, tmp_path, monkeypatch):
        cfg = _write(tmp_path / "fw.json", fail_mode="closed")
        monkeypatch.setenv("DB_FIREWALL_FAIL_MODE", "open")
        assert load_config(project_root=str(cfg))["fail_mode"] == "open"


class TestDefaultsIsolation:
    def test_mutating_result_leaves_defaults_alone(self, monkeypatch):
        snapshot = copy.deepcopy(DEFAULT_CONFIG)
        monkeypatch.setattr(db_firewall, "DEFAULT_CONFIG", copy.deepcopy(DEFAULT_CONFIG))
        cfg = load_config()
        cfg["protect"]["select"] = False
        cfg["excluded_tables"].append("orders")
        assert db_firewall.DEFAULT_CONFIG == snapshot


class TestSqlAlchemyLoadsOnce:
    def test_config_not_reread_per_query(self, monkeypatch):
        sa = pytest.importorskip("sqlalchemy")
        pytest.importorskip("sqlglot")
        calls = []
        real = db_firewall.load_config
        monkeypatch.setattr(db_firewall, "load_config",
                            lambda *a, **k: calls.append(1) or real(*a, **k))
        eng = sa.create_engine("sqlite://", poolclass=sa.pool.StaticPool)
        db_firewall.sqlalchemy_event_hooks(eng)
        loads_at_setup = len(calls)
        with eng.connect() as c:
            for _ in range(3):
                c.execute(sa.text("SELECT 1"))
        assert len(calls) == loads_at_setup == 1

    def test_explicit_config_is_used(self):
        sa = pytest.importorskip("sqlalchemy")
        pytest.importorskip("sqlglot")
        eng = sa.create_engine("sqlite://", poolclass=sa.pool.StaticPool)
        with eng.begin() as c:
            c.execute(sa.text("CREATE TABLE orders (id INTEGER, org_id TEXT)"))
            c.execute(sa.text("INSERT INTO orders VALUES (1,'A'),(2,'B')"))
        cfg = load_config()
        cfg["tenant_column"] = "org_id"
        db_firewall.sqlalchemy_event_hooks(eng, config=cfg)
        with db_firewall.tenant_scope("A"), eng.connect() as c:
            rows = c.execute(sa.text("SELECT id FROM orders")).fetchall()
        assert rows == [(1,)]
