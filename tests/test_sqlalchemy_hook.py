"""H6: the SQLAlchemy before_cursor_execute hook must actually replace the
statement (retval=True) — sqlite in-memory, no server needed."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
sa = pytest.importorskip("sqlalchemy")
pytest.importorskip("sqlglot")
from sqlalchemy import create_engine, text  # noqa: E402

from db_firewall import sqlalchemy_event_hooks, TenantContext  # noqa: E402


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.delenv("DB_FIREWALL_CONFIG", raising=False)   # defaults
    eng = create_engine("sqlite://", poolclass=sa.pool.StaticPool,
                        connect_args={"check_same_thread": False})
    with eng.begin() as c:
        c.execute(text("CREATE TABLE orders (id INTEGER, tenant_id TEXT, note TEXT)"))
        c.execute(text("INSERT INTO orders VALUES (1,'A','a1'),(2,'A','a2'),(3,'B','TRAP')"))
        c.execute(text("CREATE TABLE app_config (k TEXT)"))
        c.execute(text("INSERT INTO app_config VALUES ('shared')"))
    sqlalchemy_event_hooks(eng)
    yield eng
    TenantContext.clear()
    eng.dispose()


def test_rewritten_statement_is_what_executes(engine):
    """Before: the hook computed the scoped SQL and returned it without
    retval=True, so SQLAlchemy ran the original → 3 rows incl. TRAP."""
    TenantContext.set("A")
    with engine.connect() as c:
        rows = c.execute(text("SELECT id, tenant_id FROM orders ORDER BY id")).fetchall()
        assert rows == [(1, 'A'), (2, 'A')]
        rows = c.execute(text("SELECT id FROM orders WHERE id = :i"), {"i": 3}).fetchall()
        assert rows == []
        assert c.execute(text("SELECT k FROM app_config")).fetchall() == [('shared',)]
        # executemany path: INSERT is stamped, bound parameters survive
        c.execute(text("INSERT INTO orders (id, note) VALUES (:i, :n)"),
                  [{"i": 10, "n": "x"}, {"i": 11, "n": "y"}])
        assert c.execute(text("SELECT tenant_id FROM orders WHERE id >= 10")).fetchall() \
            == [('A',), ('A',)]


def test_no_tenant_fail_closed_only_for_protected_tables(engine):
    TenantContext.clear()
    with engine.connect() as c:
        assert c.execute(text("SELECT 1")).scalar() == 1
        assert c.execute(text("SELECT k FROM app_config")).fetchall() == [('shared',)]
        with pytest.raises(PermissionError, match="No tenant context"):
            c.execute(text("SELECT * FROM orders"))
