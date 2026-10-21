"""db_firewall is a package. Setting a name on it must reach the module that
owns the name and every module that imported it, as with the old single file."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
import db_firewall  # noqa: E402
from db_firewall import introspection, sqlalchemy_hooks, web, wrappers  # noqa: E402


def test_setting_reaches_owner(monkeypatch):
    monkeypatch.setattr(db_firewall, "TABLE_CACHE_TTL", 5.0)
    assert introspection.TABLE_CACHE_TTL == 5.0


def test_function_patch_reaches_importers(monkeypatch):
    fake = lambda *a, **k: {}    # noqa: E731
    monkeypatch.setattr(db_firewall, "load_config", fake)
    assert wrappers.load_config is web.load_config is sqlalchemy_hooks.load_config is fake


def test_patch_is_undone(monkeypatch):
    real = db_firewall.load_config
    with monkeypatch.context() as m:
        m.setattr(db_firewall, "load_config", lambda: {})
    assert wrappers.load_config is real and db_firewall.load_config is real


def test_both_import_paths_expose_the_api():
    import importlib
    pkg = importlib.import_module("middleware.db_firewall")
    for name in ("protect", "rewrite_query", "load_config", "tenant_scope",
                 "django_middleware_class", "sqlalchemy_event_hooks", "run_migration"):
        assert callable(getattr(pkg, name)) and callable(getattr(db_firewall, name))
