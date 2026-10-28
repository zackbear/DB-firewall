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
    resolution, audit, wrappers, streams, web, sqlalchemy_hooks, migrate
"""

import sys
import types

from . import (config, engines, context, introspection, rewrite, db_context,
               resolution, audit, wrappers, streams, web, sqlalchemy_hooks, migrate)

_SUBMODULES = (config, engines, context, introspection, rewrite, db_context,
               resolution, audit, wrappers, streams, web, sqlalchemy_hooks, migrate)

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

# Names a submodule rebinds with `global` at run time (the log-once flags).
# They are not copied onto the package, so reads stay live (module __getattr__).
# tests/test_package_layout.py fails if a new `global` name is missing here.
_LIVE = {"_warned_untrusted_header", "_warned_orphan_config", "_regex_warned", "_warned_unsigned"}
for _name in _LIVE:
    globals().pop(_name, None)


def __getattr__(name):
    if name in _LIVE:
        return getattr(_OWNER[name], name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class _Package(types.ModuleType):
    """Setting or deleting db_firewall.X (TABLE_CACHE_TTL, DEFAULT_CONFIG, a
    monkeypatch) reaches the module that owns X and every module that imported
    the same object, so it takes effect as it did in the single-file module."""

    def _holders(self, name):
        owner = _OWNER.get(name)
        if owner is None:
            return []
        old = owner.__dict__.get(name, _MISSING)
        return [m for m in _SUBMODULES if m is owner or
                (old is not _MISSING and m.__dict__.get(name, _MISSING) is old)]

    def __setattr__(self, name, value):
        if name in _LIVE:                       # remember what a later delete restores
            owner = _OWNER[name]
            _LIVE_SAVED.setdefault(name, []).append(owner.__dict__.get(name, _MISSING))
        # After a delete, restore to every module that held the name, not just the owner.
        for mod in _DELETED.pop(name, None) or self._holders(name):
            setattr(mod, name, value)
        if name not in _LIVE:
            super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in _LIVE:
            # The package never holds a live flag, so a delete (pytest >= 9.2
            # undoes a monkeypatch that way) restores the owner's earlier value
            # instead of removing the flag the code reads with `global`.
            saved = _LIVE_SAVED.get(name)
            if not saved:
                raise AttributeError(name)
            prev = saved.pop()
            owner = _OWNER[name]
            if prev is _MISSING:
                owner.__dict__.pop(name, None)
            else:
                setattr(owner, name, prev)
            return
        holders = self._holders(name)
        for mod in holders:
            delattr(mod, name)
        if holders:
            _DELETED[name] = holders
        if name not in _LIVE:
            super().__delattr__(name)


_DELETED = {}       # name -> modules it was deleted from, for the undo
_LIVE_SAVED = {}    # live flag -> owner values replaced through the package (a stack)


sys.modules[__name__].__class__ = _Package
