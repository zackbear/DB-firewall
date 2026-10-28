"""
PostgreSQL policy_mode: restrictive, live. The tenant policies AND with the
app's own policies (Supabase, Drizzle pgPolicy), so an app policy can narrow
rows inside the tenant but never widen past it.

    DBFW_PG_DSN="host=localhost port=55432 dbname=dbfw_test user=postgres" pytest tests/test_pg_restrictive_live.py
"""

import copy
import os
import sys

import pytest

DSN = os.environ.get("DBFW_PG_DSN")
if not DSN:
    pytest.skip("DBFW_PG_DSN not set; skipping live PostgreSQL tests", allow_module_level=True)
psycopg = pytest.importorskip("psycopg")

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
from hooks.scan_engines import scan_tables  # noqa: E402
from middleware.db_firewall import DBEngine, load_config, run_migration  # noqa: E402

SCHEMA, ROLE = "rs_app", "rs_app_user"


def _cfg(mode):
    c = copy.deepcopy(load_config())
    c["engines"]["postgresql"].update(schema=SCHEMA, policy_mode=mode)
    return c


def _migrate(mode):
    with psycopg.connect(DSN) as c:
        run_migration(c, DBEngine.POSTGRESQL, _cfg(mode))


@pytest.fixture(scope="module", autouse=True)
def setup():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
        c.execute(f"CREATE SCHEMA {SCHEMA}")
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') "
                  f"THEN CREATE ROLE {ROLE} NOLOGIN; END IF; END $$")
        # docs: the app's own per-user policy. plain: no app policy.
        c.execute(f"CREATE TABLE {SCHEMA}.docs (id int, tenant_id text, owner text)")
        c.execute(f"INSERT INTO {SCHEMA}.docs VALUES (1, 'A', 'u1'), (2, 'A', 'u2'), (3, 'B', 'u1')")
        c.execute(f"CREATE POLICY app_owner ON {SCHEMA}.docs FOR ALL "
                  "USING (owner = current_setting('app.user', true)) "
                  "WITH CHECK (owner = current_setting('app.user', true))")
        c.execute(f"CREATE TABLE {SCHEMA}.plain (id int, tenant_id text)")
        c.execute(f"INSERT INTO {SCHEMA}.plain VALUES (1, 'A'), (2, 'B')")
        c.execute(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {ROLE}")
        c.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {SCHEMA} TO {ROLE}")
    _migrate("restrictive")
    yield
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")


def _ids(table, tenant=None, user=None):
    """Rows the app role sees, as tenant (and app user), in one transaction."""
    with psycopg.connect(DSN) as c:
        c.execute(f"SET LOCAL ROLE {ROLE}")
        if tenant:
            c.execute("SELECT set_config('app.current_tenant', %s, true)", (tenant,))
        if user:
            c.execute("SELECT set_config('app.user', %s, true)", (user,))
        return [r[0] for r in c.execute(f"SELECT id FROM {SCHEMA}.{table} ORDER BY id").fetchall()]


def _policies(table):
    with psycopg.connect(DSN) as c:
        return {r[0]: r[1] for r in c.execute(
            "SELECT policyname, permissive FROM pg_policies WHERE schemaname = %s AND tablename = %s",
            (SCHEMA, table)).fetchall()}


def test_app_policy_narrows_inside_the_tenant():
    assert _ids("docs", "A", "u1") == [1]          # not 2 (other user), not 3 (tenant B)
    assert _ids("docs", "B", "u1") == [3]


def test_table_without_app_policy_gets_base_policy():
    pols = _policies("plain")
    assert sum(k.endswith("_base") and v == "PERMISSIVE" for k, v in pols.items()) == 1
    assert sum(v == "RESTRICTIVE" for v in pols.values()) == 4
    assert _ids("plain", "A") == [1]
    assert not any(k.endswith("_base") for k in _policies("docs"))   # docs has its own


def test_fails_closed_without_tenant():
    assert _ids("plain") == [] and _ids("docs", user="u1") == []


def test_cross_tenant_write_blocked():
    with psycopg.connect(DSN) as c:
        c.execute(f"SET LOCAL ROLE {ROLE}")
        c.execute("SELECT set_config('app.current_tenant', 'A', true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"INSERT INTO {SCHEMA}.plain VALUES (9, 'B')")


def test_scanner_accepts_app_policies_in_restrictive_mode():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"CREATE POLICY open_all ON {SCHEMA}.docs USING (true)")   # widens only within tenant
        try:
            report = scan_tables(c, DBEngine.POSTGRESQL, _cfg("restrictive"))
            assert _ids("docs", "A") == [1, 2]                                # open_all: all of A, never B
        finally:
            c.execute(f"DROP POLICY open_all ON {SCHEMA}.docs")
    assert report["docs"]["protected"] and report["docs"]["policy_mode"] == "restrictive"
    assert report["plain"]["protected"]


def test_permissive_rerun_removes_base_and_scanner_flags_app_policy():
    _migrate("permissive")
    try:
        assert not any(k.endswith("_base") for k in _policies("plain"))
        with psycopg.connect(DSN) as c:
            report = scan_tables(c, DBEngine.POSTGRESQL, _cfg("permissive"))
        assert report["docs"]["protected"] is False                # app_owner ORs with the tenant
        assert report["docs"]["extra_permissive_policies"] == ["app_owner"]
        assert report["plain"]["protected"] is True
    finally:
        _migrate("restrictive")


def test_invalid_mode_raises():
    with pytest.raises(Exception, match="policy_mode"):
        _migrate("sideways")
