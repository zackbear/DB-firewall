"""
DB Firewall — pooled-connection context leak tests (PostgreSQL, opt-in)
=======================================================================
Proves that tenant context does not survive a connection's return to a pool.

Opt in with a DSN to a scratch database you own (superuser role, since the
fixture creates roles/tables and applies migrations/001_postgresql.sql):

    DBFW_PG_DSN="host=/tmp port=5433 dbname=dbfw_test user=postgres" \
        python3 -m pytest tests/test_pool_leak.py -v

Without DBFW_PG_DSN the module is skipped.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))

DSN = os.environ.get("DBFW_PG_DSN")
if not DSN:
    pytest.skip("DBFW_PG_DSN not set; skipping PostgreSQL pool-leak tests",
                allow_module_level=True)

psycopg = pytest.importorskip("psycopg")
psycopg_pool = pytest.importorskip("psycopg_pool")
from psycopg.conninfo import make_conninfo  # noqa: E402

from db_firewall import protect, TenantContext  # noqa: E402

MIGRATION = os.path.join(os.path.dirname(__file__), '..', 'migrations', '001_postgresql.sql')
TABLE = "dbfw_leak_orders"
APP_ROLE = "dbfw_app"          # non-owner, non-superuser: RLS actually applies
APP_DSN = make_conninfo(DSN, user=APP_ROLE)
CONFIG = {"tenant_column": "tenant_id", "fail_mode": "closed",
          "protect": {"select": True, "insert": True, "update": True, "delete": True},
          "excluded_tables": ["_firewall_*"]}


def _release(pc):
    """Return the raw connection to the pool without closing it.
    Falls back to the pre-fix behaviour (thread-local only) when release() is absent,
    so the mutation check runs against old middleware code."""
    rel = getattr(pc, "release", None)
    if rel:
        rel()
    else:
        TenantContext.clear()


def _current_tenant(conn):
    return conn.execute("SELECT current_setting('app.current_tenant', true)").fetchone()[0]


@pytest.fixture(scope="module", autouse=True)
def schema():
    """Create app role + tenant table, apply the migration twice (idempotency)."""
    sql = open(MIGRATION).read()
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(f"""
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                    CREATE ROLE {APP_ROLE} LOGIN;
                END IF;
            END $$""")
        conn.execute(f"DROP TABLE IF EXISTS {TABLE}")
        conn.execute(f"CREATE TABLE {TABLE} (id serial primary key, tenant_id text not null, item text)")
        conn.execute(f"INSERT INTO {TABLE} (tenant_id, item) VALUES ('A','a1'),('A','a2'),('B','b1')")
        conn.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
        conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO {APP_ROLE}")
        if conn.execute("SELECT to_regclass('_firewall_bypass_roles')").fetchone()[0]:
            conn.execute("DELETE FROM _firewall_bypass_roles")
        conn.execute(sql)   # pass 1
        conn.execute(sql)   # pass 2 must also succeed (idempotent)
        assert conn.execute("SELECT count(*) FROM _firewall_bypass_roles").fetchone()[0] == 0
        assert _policies(conn, TABLE) == _expected_policies("public", TABLE)
    yield


def _policies(conn, table):
    return {r[0] for r in conn.execute(
        "SELECT polname FROM pg_policy WHERE polrelid = %s::regclass", (table,))}


def _expected_policies(schema, table):
    import hashlib
    stem = "fw_" + hashlib.md5(f"{schema}.{table}".encode()).hexdigest()[:12]
    return {f"{stem}_{s}" for s in ("sel", "ins", "upd", "del")}


@pytest.fixture
def pool():
    # max_size=1 → every borrow is the same physical connection
    p = psycopg_pool.ConnectionPool(DSN, min_size=1, max_size=1, open=True)
    yield p
    p.close()


def _pool_leak_setup(pool):
    """Borrow, protect as A, do work + commit (as a real app would), release."""
    with pool.connection() as raw:
        pc = protect(raw, "A", CONFIG)
        assert _current_tenant(raw) == "A"
        cur = pc.cursor()
        cur.execute(f"SELECT count(*) FROM {TABLE}")
        assert cur.fetchone()[0] == 2
        raw.commit()
        _release(pc)
        TenantContext.clear()


def test_context_does_not_leak_to_next_borrower(pool):
    """Steps 1+2: after A's protected use, a bare borrow must see no tenant."""
    _pool_leak_setup(pool)
    with pool.connection() as raw:
        leaked = _current_tenant(raw)
        assert leaked in (None, ""), f"tenant context leaked across pool checkout: {leaked!r}"


def test_reprotect_same_connection_switches_tenant():
    """Step 3: protect as A then B on the same physical conn → B wins, RLS shows B only."""
    with psycopg.connect(APP_DSN) as raw:
        protect(raw, "A", CONFIG)
        assert _current_tenant(raw) == "A"
        pb = protect(raw, "B", CONFIG)
        assert _current_tenant(raw) == "B"
        rows = raw.execute(f"SELECT tenant_id FROM {TABLE}").fetchall()   # raw SQL: RLS only
        assert rows == [("B",)]
        pb.release()
        raw.rollback()
        assert raw.execute(f"SELECT count(*) FROM {TABLE}").fetchone()[0] == 0   # fail closed


def test_rls_denies_without_context_for_app_role():
    with psycopg.connect(APP_DSN) as raw:
        assert raw.execute(f"SELECT count(*) FROM {TABLE}").fetchone()[0] == 0


def test_temp_table_cannot_shadow_bypass_roles():
    """C1 regression: _firewall_is_bypass_role() is SECURITY DEFINER and callable by
    any role (policies evaluate as the caller). Without a pinned search_path, an app
    role could shadow _firewall_bypass_roles with a temp table listing itself and
    every RLS policy would return all tenants' rows. Must stay at 0 rows."""
    with psycopg.connect(APP_DSN) as raw:
        raw.execute("CREATE TEMP TABLE _firewall_bypass_roles(role_name text)")
        raw.execute("INSERT INTO _firewall_bypass_roles VALUES (current_user)")
        raw.execute("SET search_path = pg_temp, public")
        assert raw.execute("SELECT _firewall_is_bypass_role(current_user::text)").fetchone()[0] is False
        rows = raw.execute(f"SELECT tenant_id FROM {TABLE}").fetchall()
        assert rows == [], f"temp-table shadow of _firewall_bypass_roles bypassed RLS: {rows!r}"
        raw.rollback()


def test_autocommit_connection_raises():
    """Step 4: transaction-local context cannot be set on autocommit → loud failure."""
    with psycopg.connect(DSN, autocommit=True) as raw:
        with pytest.raises(RuntimeError, match="autocommit"):
            protect(raw, "A", CONFIG)
        TenantContext.clear()


def test_pool_checkin_reset_hook_clears_session_scope():
    """pool_checkin as psycopg_pool reset= clears even a session-scoped value."""
    from db_firewall import pool_checkin
    p = psycopg_pool.ConnectionPool(DSN, min_size=1, max_size=1, open=True, reset=pool_checkin)
    try:
        with p.connection() as raw:
            raw.execute("SELECT set_config('app.current_tenant', 'LEGACY', false)")
            raw.commit()
        with p.connection() as raw:
            assert _current_tenant(raw) in (None, "")
    finally:
        p.close()


# ============================================================================
# Migration upgrade path (P1-a) and long table names (P2-b)
# ============================================================================

LEGACY_MIGRATION_REF = "origin/main:migrations/001_postgresql.sql"


def _legacy_migration_sql():
    import subprocess
    repo = os.path.join(os.path.dirname(__file__), '..')
    try:
        return subprocess.check_output(["git", "-C", repo, "show", LEGACY_MIGRATION_REF],
                                       stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip(f"{LEGACY_MIGRATION_REF} not available")


def test_upgrade_from_legacy_migration_removes_hardcoded_bypass():
    """P1-a: permissive policies OR together, so a legacy policy with the hardcoded
    postgres/admin/_migrator bypass must be dropped by the new migration, both the
    legacy per-command names and the older single 'firewall_rls_<table>' name."""
    legacy_sql = _legacy_migration_sql()
    new_sql = open(MIGRATION).read()
    scratch = "dbfw_upgrade_scratch"
    table = "upg_orders"
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {scratch}")
        admin.execute(f"CREATE DATABASE {scratch}")
    scratch_dsn = make_conninfo(DSN, dbname=scratch)
    try:
        with psycopg.connect(scratch_dsn, autocommit=True) as conn:
            conn.execute(f"CREATE TABLE {table} (id serial primary key, tenant_id text not null)")
            conn.execute(f"INSERT INTO {table} (tenant_id) VALUES ('A'),('B')")
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
            conn.execute(f"GRANT SELECT ON {table} TO {APP_ROLE}")
            conn.execute(legacy_sql)
            # The oldest generation used one policy for ALL commands under the bare name.
            conn.execute(f"""CREATE POLICY firewall_rls_{table} ON {table} USING (
                tenant_id = NULLIF(current_setting('app.current_tenant', true), '')
                OR current_user IN ('postgres', 'admin', '_migrator'))""")
            before = _policies(conn, table)
            assert f"firewall_rls_{table}" in before and f"firewall_rls_{table}_sel" in before

            conn.execute(new_sql)   # upgrade

            after = _policies(conn, table)
            assert after == _expected_policies("public", table), after
            assert not any(p.startswith("firewall_rls_") for p in after)
            quals = [r[0] for r in conn.execute(
                "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polrelid = %s::regclass",
                (table,))]
            assert not any("_migrator" in q for q in quals if q), quals
        with psycopg.connect(make_conninfo(scratch_dsn, user=APP_ROLE)) as app:
            assert app.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    finally:
        with psycopg.connect(DSN, autocommit=True) as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {scratch} WITH (FORCE)")


def test_long_table_name_gets_four_policies():
    """P2-b: 'firewall_rls_<55 chars>_sel' exceeds 63 bytes; the truncated names
    collided and CREATE POLICY failed. Hash-stem names fit for any table name."""
    table = "t_" + "x" * 53
    assert len(table) == 55
    sql = open(MIGRATION).read()
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.execute(f"CREATE TABLE {table} (id serial primary key, tenant_id text not null)")
        try:
            conn.execute(sql)
            conn.execute(sql)   # idempotent on the long name too
            pols = _policies(conn, table)
            assert len(pols) == 4, pols
            assert pols == _expected_policies("public", table)
            assert all(len(p) <= 63 for p in pols)
        finally:
            conn.execute(f"DROP TABLE IF EXISTS {table}")


# ============================================================================
# Legacy SESSION-scoped value vs rollback-on-return (P2-a)
# ============================================================================

def _set_legacy_session_value(pool, value="LEGACY"):
    raw = pool.getconn()
    raw.execute("SELECT set_config('app.current_tenant', %s, false)", (value,))
    raw.commit()
    pool.putconn(raw)


def _protect_work_release(pool, commit_before_release):
    import warnings
    raw = pool.getconn()
    pc = protect(raw, "A", CONFIG)
    cur = pc.cursor()
    cur.execute(f"SELECT count(*) FROM {TABLE}")
    assert cur.fetchone()[0] == 2
    if commit_before_release:
        raw.commit()
    pc.release()
    TenantContext.clear()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # psycopg_pool warns when it rolls back
        pool.putconn(raw)                 # getconn/putconn: NO commit, pool rolls back


def test_release_after_commit_persists_clear_under_default_reset():
    """commit() then release() with the pool's default rollback-on-return: the
    clear ran outside any transaction and was committed by release() itself."""
    p = psycopg_pool.ConnectionPool(DSN, min_size=1, max_size=1, open=True)
    try:
        _set_legacy_session_value(p)
        _protect_work_release(p, commit_before_release=True)
        raw = p.getconn()
        try:
            assert _current_tenant(raw) in (None, "")
        finally:
            p.putconn(raw)
    finally:
        p.close()


def test_release_in_open_transaction_cleared_by_pool_checkin_reset():
    """release() inside a still-open transaction, no commit, pool rolls back on
    return: the transactional clear is undone, so the reset hook must roll back,
    clear and commit for the next borrower to see no tenant."""
    from db_firewall import pool_checkin
    p = psycopg_pool.ConnectionPool(DSN, min_size=1, max_size=1, open=True, reset=pool_checkin)
    try:
        _set_legacy_session_value(p)
        _protect_work_release(p, commit_before_release=False)
        raw = p.getconn()
        try:
            assert _current_tenant(raw) in (None, "")
        finally:
            p.putconn(raw)
    finally:
        p.close()


# ============================================================================
# SQLAlchemy: tenant context must survive commit() on a long-lived Connection (P1-c)
# ============================================================================

def test_sqlalchemy_tenant_context_reapplied_after_commit():
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy import create_engine, text
    from db_firewall import sqlalchemy_event_hooks

    # creator= keeps the test DSN-agnostic; app role so RLS applies.
    engine = create_engine("postgresql+psycopg://",
                           creator=lambda: psycopg.connect(APP_DSN),
                           pool_size=1, max_overflow=0)
    sqlalchemy_event_hooks(engine)
    TenantContext.set("A")
    try:
        with engine.connect() as c:
            assert c.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar() == 2
            c.commit()
            assert c.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar() == 2, \
                "tenant context lost after commit() on a long-lived connection"
            c.rollback()
            assert c.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar() == 2
    finally:
        TenantContext.clear()
        engine.dispose()
