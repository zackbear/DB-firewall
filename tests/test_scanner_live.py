"""
CI scanner against live PostgreSQL: a table counts as protected only when RLS
is enabled AND forced (table owners bypass unforced RLS) and all four firewall
policies exist on that exact schema.table.

    DBFW_PG_DSN="host=localhost port=55432 dbname=dbfw_test user=postgres" pytest tests/test_scanner_live.py
"""

import json
import os
import subprocess
import sys

import pytest

DSN = os.environ.get("DBFW_PG_DSN")
if not DSN:
    pytest.skip("DBFW_PG_DSN not set; skipping live scanner tests", allow_module_level=True)
psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import conninfo_to_dict  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
from hooks.scanner import scan_tables  # noqa: E402
from middleware.db_firewall import DBEngine, load_config  # noqa: E402

FULL, NO_RLS, NOT_FORCED, SEL_ONLY, SHADOW = (
    "sc_full", "sc_no_rls", "sc_not_forced", "sc_sel_only", "sc_shadow")
NOT_ENABLED, LEGACY, OPEN_EXTRA, RESTRICT_EXTRA, PART, DROPPED, LEGACY_SHADOW = (
    "sc_not_enabled", "sc_legacy", "sc_open_extra", "sc_restrict_extra", "sc_part",
    "sc_dropped", "sc_legacy_shadow")
ALL = (FULL, NO_RLS, NOT_FORCED, SEL_ONLY, SHADOW, NOT_ENABLED, LEGACY, OPEN_EXTRA,
       RESTRICT_EXTRA, LEGACY_SHADOW)
OPS = {"sel": "SELECT", "ins": "INSERT", "upd": "UPDATE", "del": "DELETE"}


def _policies(c, schema, table, ops, legacy=False):
    stem = (f"firewall_rls_{table}" if legacy else
            c.execute("SELECT 'fw_' || left(md5(%s || '.' || %s), 12)", (schema, table)).fetchone()[0])
    for suffix in ops:
        clause = "WITH CHECK (true)" if suffix == "ins" else "USING (true)"
        c.execute(f'CREATE POLICY "{stem}_{suffix}" ON {schema}.{table} FOR {OPS[suffix]} {clause}')


@pytest.fixture(scope="module")
def db():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS sc_other CASCADE")
        c.execute("CREATE SCHEMA sc_other")
        c.execute(f"DROP TABLE IF EXISTS public.{PART}, public.{DROPPED}")
        for t in ALL:
            c.execute(f"DROP TABLE IF EXISTS public.{t}")
            c.execute(f"CREATE TABLE public.{t} (id int, tenant_id text)")
        for t in (FULL, NOT_FORCED, SEL_ONLY, LEGACY, OPEN_EXTRA, RESTRICT_EXTRA):
            c.execute(f"ALTER TABLE public.{t} ENABLE ROW LEVEL SECURITY")
        for t in (FULL, SEL_ONLY, NOT_ENABLED, LEGACY, OPEN_EXTRA, RESTRICT_EXTRA):
            c.execute(f"ALTER TABLE public.{t} FORCE ROW LEVEL SECURITY")
        for t in (FULL, NOT_ENABLED, OPEN_EXTRA, RESTRICT_EXTRA):
            _policies(c, "public", t, OPS)
        _policies(c, "public", LEGACY, OPS, legacy=True)
        c.execute(f"CREATE POLICY open_all ON public.{OPEN_EXTRA} USING (true)")
        c.execute(f"CREATE POLICY narrow ON public.{RESTRICT_EXTRA} AS RESTRICTIVE USING (id > 0)")
        # Partitioned table with tenant_id; a table whose tenant_id column was dropped.
        c.execute(f"CREATE TABLE public.{PART} (id int, tenant_id text) PARTITION BY RANGE (id)")
        c.execute(f"CREATE TABLE public.{DROPPED} (id int, tenant_id text)")
        c.execute(f"ALTER TABLE public.{DROPPED} DROP COLUMN tenant_id")
        # Legacy-named policies on a same-named table in another schema must not count.
        c.execute(f"CREATE TABLE sc_other.{LEGACY_SHADOW} (id int, tenant_id text)")
        c.execute(f"ALTER TABLE public.{LEGACY_SHADOW} ENABLE ROW LEVEL SECURITY")
        c.execute(f"ALTER TABLE public.{LEGACY_SHADOW} FORCE ROW LEVEL SECURITY")
        _policies(c, "sc_other", LEGACY_SHADOW, OPS, legacy=True)
        _policies(c, "public", NOT_FORCED, OPS)
        _policies(c, "public", SEL_ONLY, ["sel"])
        # Same name in another schema, fully protected: must not vouch for public.sc_shadow.
        c.execute(f"CREATE TABLE sc_other.{SHADOW} (id int, tenant_id text)")
        c.execute(f"ALTER TABLE sc_other.{SHADOW} ENABLE ROW LEVEL SECURITY")
        c.execute(f"ALTER TABLE sc_other.{SHADOW} FORCE ROW LEVEL SECURITY")
        _policies(c, "public", SHADOW, [])          # nothing on the public one
        _policies(c, "sc_other", SHADOW, OPS)
        yield c
        for t in ALL + (PART, DROPPED):
            c.execute(f"DROP TABLE IF EXISTS public.{t}")
        c.execute("DROP SCHEMA sc_other CASCADE")


@pytest.fixture(scope="module")
def results(db):
    return scan_tables(db, DBEngine.POSTGRESQL, load_config())


@pytest.mark.parametrize("table", [FULL, LEGACY, RESTRICT_EXTRA])
def test_fully_protected(results, table):
    assert results[table]["protected"] is True


def test_extra_permissive_policy_reported(results):
    assert results[OPEN_EXTRA]["extra_permissive_policies"] == ["open_all"]


def test_partitioned_scanned_dropped_column_ignored(results):
    assert results[PART]["protected"] is False
    assert DROPPED not in results


@pytest.mark.parametrize("table", [NO_RLS, NOT_FORCED, SEL_ONLY, SHADOW, NOT_ENABLED,
                                   OPEN_EXTRA, LEGACY_SHADOW])
def test_not_protected(results, table):
    assert results[table]["protected"] is False


def test_not_forced_reported(results):
    assert results[NOT_FORCED]["rls_enabled"] is True
    assert results[NOT_FORCED]["rls_forced"] is False


def test_missing_policies_reported(results):
    assert results[SEL_ONLY]["missing_policies"] == ["del", "ins", "upd"]


def test_excluded_tables_skipped(db):
    cfg = load_config()
    cfg["excluded_tables"] = ["sc_*"]
    assert not any(t.startswith("sc_") for t in scan_tables(db, DBEngine.POSTGRESQL, cfg))


def _url():
    d = conninfo_to_dict(DSN)
    host = d.get("host", "localhost")
    return f"postgresql://{d.get('user', 'postgres')}@{host}:{d.get('port', 5432)}/{d['dbname']}"


def test_cli_strict_fails_build(db):
    env = {k: v for k, v in os.environ.items() if not k.startswith("DB_FIREWALL_")}
    out = subprocess.run([sys.executable, "-m", "hooks.scanner", "--dsn", _url(), "--strict", "--json"],
                         cwd=ROOT, capture_output=True, timeout=60, env=env)
    assert out.returncode == 1, out.stderr.decode()
    report = json.loads(out.stdout.decode().split("\n❌")[0])
    assert report[FULL]["protected"] is True and report[NOT_FORCED]["protected"] is False


def test_real_migration_passes_scanner():
    """The migration's own policies must satisfy the scanner (names, FORCE, all four ops)."""
    from psycopg.conninfo import make_conninfo
    from middleware.db_firewall import run_migration
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP DATABASE IF EXISTS dbfw_scan_tmp")
        admin.execute("CREATE DATABASE dbfw_scan_tmp")
    try:
        with psycopg.connect(make_conninfo(DSN, dbname="dbfw_scan_tmp")) as c:
            c.execute("CREATE TABLE orders (id int, tenant_id text)")
            c.commit()
            run_migration(c, DBEngine.POSTGRESQL)
            assert scan_tables(c, DBEngine.POSTGRESQL, load_config())["orders"]["protected"] is True
    finally:
        with psycopg.connect(DSN, autocommit=True) as admin:
            admin.execute("DROP DATABASE IF EXISTS dbfw_scan_tmp")


def test_migration_and_scanner_with_custom_column_and_schema():
    """tenant_column org_id in schema app: the migration protects it, the scanner
    passes it, and RLS scopes rows by org_id for a non-owner role."""
    from psycopg.conninfo import make_conninfo
    from middleware.db_firewall import run_migration
    cfg = load_config()
    cfg["tenant_column"] = "org_id"
    cfg["engines"] = {"postgresql": {"schema": "app"}}
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP DATABASE IF EXISTS dbfw_scan_col")
        admin.execute("CREATE DATABASE dbfw_scan_col")
    try:
        with psycopg.connect(make_conninfo(DSN, dbname="dbfw_scan_col")) as c:
            c.execute("CREATE SCHEMA app")
            c.execute("CREATE TABLE app.orders (id int, org_id text)")
            c.execute("CREATE TABLE app.plain (id int, tenant_id text)")      # wrong column: untouched
            c.execute("INSERT INTO app.orders VALUES (1,'A'),(2,'B')")
            c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbfw_col_app') "
                      "THEN CREATE ROLE dbfw_col_app LOGIN; END IF; END $$")
            c.execute("GRANT USAGE ON SCHEMA app TO dbfw_col_app")
            c.execute("GRANT SELECT ON app.orders TO dbfw_col_app")
            c.commit()
            run_migration(c, DBEngine.POSTGRESQL, cfg)
            report = scan_tables(c, DBEngine.POSTGRESQL, cfg)
            assert report["orders"]["protected"] is True and "plain" not in report
            assert scan_tables(c, DBEngine.POSTGRESQL, load_config()) == {}   # public has none
        with psycopg.connect(make_conninfo(DSN, dbname="dbfw_scan_col", user="dbfw_col_app")) as app:
            app.execute("SELECT set_config('app.current_tenant', 'A', true)")
            assert app.execute("SELECT id FROM app.orders").fetchall() == [(1,)]
    finally:
        with psycopg.connect(DSN, autocommit=True) as admin:
            admin.execute("DROP DATABASE IF EXISTS dbfw_scan_col")
