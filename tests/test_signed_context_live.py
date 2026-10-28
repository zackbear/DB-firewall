"""
PostgreSQL signed tenant context (tenant_context: signed, the default), live.
SQL run inside a tenant's transaction can set app.current_tenant, but it
cannot sign it, so it cannot reach another tenant's rows.

    DBFW_PG_DSN="host=localhost port=55432 dbname=dbfw_test user=postgres" pytest tests/test_signed_context_live.py
"""

import copy
import logging
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
from middleware.db_firewall import db_context  # noqa: E402
from middleware.db_firewall.db_context import _set_context_postgres, sign_tenant  # noqa: E402

SCHEMA, ROLE = "sg_app", "sg_app_user"


def _cfg(context="signed"):
    c = copy.deepcopy(load_config())
    c["engines"]["postgresql"].update(schema=SCHEMA, tenant_context=context)
    return c


def _migrate(context="signed"):
    with psycopg.connect(DSN) as c:
        run_migration(c, DBEngine.POSTGRESQL, _cfg(context))


@pytest.fixture(scope="module", autouse=True)
def setup():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
        c.execute(f"CREATE SCHEMA {SCHEMA}")
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') "
                  f"THEN CREATE ROLE {ROLE} NOLOGIN; END IF; END $$")
        c.execute(f"CREATE TABLE {SCHEMA}.docs (id int, tenant_id text)")
        c.execute(f"INSERT INTO {SCHEMA}.docs VALUES (1, 'A'), (2, 'B')")
        c.execute(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {ROLE}")
        c.execute(f"GRANT SELECT, INSERT ON {SCHEMA}.docs TO {ROLE}")
    _migrate()
    yield
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")


def _as_app(steps):
    """Run steps(conn) as the app role in one transaction; return the ids it sees."""
    with psycopg.connect(DSN) as c:
        c.execute(f"SET LOCAL ROLE {ROLE}")
        steps(c)
        return [r[0] for r in c.execute(f"SELECT id FROM {SCHEMA}.docs ORDER BY id").fetchall()]


def test_signed_tenant_sees_its_rows():
    assert _as_app(lambda c: _set_context_postgres(c, "A")) == [1]
    assert _as_app(lambda c: _set_context_postgres(c, "B")) == [2]


@pytest.mark.parametrize("switch", [
    "SET LOCAL app.current_tenant = 'B'",
    "SELECT set_config('app.current_tenant', 'B', true)",
    "SET app.current_tenant = 'B'",
])
def test_sql_in_the_transaction_cannot_switch_tenants(switch):
    assert _as_app(lambda c: (_set_context_postgres(c, "A"), c.execute(switch))) == []


def test_unsigned_forged_and_replayed_contexts_see_nothing():
    assert _as_app(lambda c: c.execute("SET LOCAL app.current_tenant = 'A'")) == []
    assert _as_app(lambda c: c.execute(
        "SELECT set_config('app.current_tenant', 'B', true), set_config('app.tenant_sig', %s, true)",
        ("0" * 64,))) == []
    saved = {}

    def keep(c):
        _set_context_postgres(c, "A")
        saved["sig"] = c.execute("SELECT current_setting('app.tenant_sig')").fetchone()[0]
    assert _as_app(keep) == [1]
    assert _as_app(lambda c: c.execute(
        "SELECT set_config('app.current_tenant', 'A', true), set_config('app.tenant_sig', %s, true)",
        (saved["sig"],))) == []                                   # a new transaction: new nonce


def test_signature_is_standard_hmac():
    with psycopg.connect(DSN) as c:
        key, nonce, sig = c.execute("SELECT encode(key, 'hex'), public._firewall_nonce(), "
                                    "public._firewall_sign('Acme:ü') FROM public._firewall_keys").fetchone()
    assert key == os.environ["DB_FIREWALL_TENANT_KEY"]            # installed from the environment
    assert sig == sign_tenant(bytes.fromhex(key), nonce, "Acme:ü")


def test_cross_tenant_insert_after_a_switch_is_refused():
    with psycopg.connect(DSN) as c:
        c.execute(f"SET LOCAL ROLE {ROLE}")
        _set_context_postgres(c, "A")
        c.execute("SET LOCAL app.current_tenant = 'B'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"INSERT INTO {SCHEMA}.docs VALUES (9, 'B')")


@pytest.mark.parametrize("sql", [
    "SELECT public._firewall_sign('B')",
    "SELECT public._firewall_set_tenant('B')",
    "SELECT key FROM public._firewall_keys",
    "INSERT INTO public._firewall_bypass_roles VALUES ('sg_app_user')",
])
def test_app_role_cannot_sign_read_the_key_or_bypass(sql):
    with psycopg.connect(DSN) as c:
        c.execute(f"SET LOCAL ROLE {ROLE}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)


def test_grants_from_default_privileges_are_revoked():
    # Supabase-style: the platform grants every new object to its roles directly.
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT SELECT ON public._firewall_keys TO {ROLE}")
        c.execute(f"GRANT EXECUTE ON FUNCTION public._firewall_sign(text) TO {ROLE}")
        c.execute(f"GRANT INSERT ON public._firewall_bypass_roles TO {ROLE}")
    _migrate()
    with psycopg.connect(DSN) as c:
        rows = c.execute(
            "SELECT count(*) FROM (SELECT relacl AS acl FROM pg_class WHERE oid IN "
            "('public._firewall_keys'::regclass, 'public._firewall_bypass_roles'::regclass) "
            "UNION ALL SELECT proacl FROM pg_proc WHERE oid = 'public._firewall_sign(text)'::regprocedure) a, "
            "aclexplode(a.acl) x WHERE x.grantee = %s::regrole", (ROLE,)).fetchone()[0]
    assert rows == 0


def test_no_key_warns_once_and_sees_nothing(monkeypatch, caplog):
    monkeypatch.delenv("DB_FIREWALL_TENANT_KEY")
    monkeypatch.setattr(db_context, "_warned_unsigned", False)
    with caplog.at_level(logging.WARNING, logger="db_firewall"):
        assert _as_app(lambda c: _set_context_postgres(c, "A")) == []
        assert _as_app(lambda c: _set_context_postgres(c, "A")) == []
    assert sum("DB_FIREWALL_TENANT_KEY is not set" in r.message for r in caplog.records) == 1


def test_bad_key_is_refused(monkeypatch):
    monkeypatch.setenv("DB_FIREWALL_TENANT_KEY", "abcd")
    with pytest.raises(RuntimeError, match="32 to 64 bytes"):
        _as_app(lambda c: _set_context_postgres(c, "A"))


def test_scanner_reports_the_context():
    with psycopg.connect(DSN) as c:
        assert scan_tables(c, DBEngine.POSTGRESQL, _cfg())["docs"]["tenant_context"] == "signed"
    _migrate("plain")
    try:
        with psycopg.connect(DSN) as c:
            signed = scan_tables(c, DBEngine.POSTGRESQL, _cfg())["docs"]
            plain = scan_tables(c, DBEngine.POSTGRESQL, _cfg("plain"))["docs"]
        assert signed["protected"] is False and signed["tenant_context"] == "plain"
        assert plain["protected"] is True and plain["tenant_context"] == "plain"
        # plain context: any SQL in the transaction can switch tenants
        assert _as_app(lambda c: c.execute("SET LOCAL app.current_tenant = 'B'")) == [2]
    finally:
        _migrate()


def test_invalid_context_is_refused():
    from middleware.db_firewall.config import validate_config
    with pytest.raises(ValueError, match="tenant_context"):
        validate_config({"engines": {"postgresql": {"tenant_context": "sideways"}}})
