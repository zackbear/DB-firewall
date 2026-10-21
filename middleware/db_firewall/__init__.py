"""
DB Firewall — Universal AI Agent Tenant Isolation Middleware
=============================================================
Drop-in middleware that wraps any Python database connection with
automatic tenant isolation. Works with any DB-API 2.0 connection
(psycopg2, mysql-connector, pyodbc, sqlite3) and any ORM
(SQLAlchemy, Django, Peewee, Tortoise).

Usage:
    from db_firewall import protect, set_tenant

    # Wrap any connection
    conn = psycopg2.connect(...)
    safe_conn = protect(conn, tenant_id="TENANT_A")

    # Or auto-resolve from environment / mapping
    safe_conn = protect(conn)

    # All queries are now silently filtered
    cursor = safe_conn.cursor()
    cursor.execute("SELECT * FROM orders")  # Only returns TENANT_A rows

Layout (each module imports only from the ones before it):
    config, engines, context, introspection, rewrite, db_context,
    wrappers, web, sqlalchemy_hooks, migrate
"""

import sys
import types

from . import (config, engines, context, introspection, rewrite, db_context,
               wrappers, web, sqlalchemy_hooks, migrate)

_SUBMODULES = (config, engines, context, introspection, rewrite, db_context,
               wrappers, web, sqlalchemy_hooks, migrate)

# Re-export every top-level name, so `db_firewall.X` keeps working for the
# public API and for the internals the hooks and tests use.
_OWNER = {}
for _mod in _SUBMODULES:
    for _name, _value in vars(_mod).items():
        if not _name.startswith("__"):
            _OWNER.setdefault(_name, _mod)       # first module in order defines it
            globals().setdefault(_name, _value)
del _mod, _name, _value

_MISSING = object()


class _Package(types.ModuleType):
    """Setting db_firewall.X (TABLE_CACHE_TTL, DEFAULT_CONFIG, a monkeypatch)
    reaches the module that owns X and every module that imported the same
    object, so the setting takes effect as it did in the single-file module."""

    def __setattr__(self, name, value):
        owner = _OWNER.get(name)
        if owner is not None:
            old = owner.__dict__.get(name, _MISSING)
            for mod in _SUBMODULES:
                if mod is owner or (old is not _MISSING and mod.__dict__.get(name, _MISSING) is old):
                    setattr(mod, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _Package
