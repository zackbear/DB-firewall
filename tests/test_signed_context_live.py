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


# ---------------------------------------------------------------- review findings

def test_release_resets_session_state_left_for_the_next_user():
    """SQL run on a connection must not leave traps for its next user (another
    tenant): a temp view shadowing a table, a SQL-level prepared statement, a
    custom setting as a drop box."""
    with psycopg.connect(DSN) as c:
        c.execute(f"SET ROLE {ROLE}")
        c.execute("SET statement_timeout = '7s'")                     # the app's own: kept
        _set_context_postgres(c, "A")
        c.execute("CREATE TEMP VIEW docs AS SELECT 99 AS id")
        c.execute("PREPARE agent_plant AS SELECT 1")
        c.execute("SELECT set_config('rv.loot', 'B-secret', false)")
        c.commit()
        db_context.pool_checkin(c)
        state = c.execute(
            "SELECT (SELECT count(*) FROM pg_class WHERE relnamespace = pg_my_temp_schema()), "
            "(SELECT count(*) FROM pg_prepared_statements WHERE from_sql), "
            "coalesce(current_setting('rv.loot', true), ''), current_setting('statement_timeout'), "
            "current_user").fetchone()
    assert state == (0, 0, "", "7s", ROLE)


def test_migration_refuses_objects_another_role_planted():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT CREATE ON SCHEMA public TO {ROLE}")
        c.execute(f"SET ROLE {ROLE}")
        c.execute("CREATE TABLE public._firewall_planted (k bytea)")
        c.execute("RESET ROLE")
    try:
        with pytest.raises(psycopg.errors.RaiseException, match="planted"):
            _migrate()
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute("DROP TABLE public._firewall_planted")
            c.execute(f"REVOKE CREATE ON SCHEMA public FROM {ROLE}")


def test_planted_operator_cannot_open_the_policies():
    """With CREATE on public, a role can add `varchar = text` that returns true.
    The migration binds the predicate in pg_catalog, so the policy stays exact;
    a policy bound to the planted operator is reported as altered."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"CREATE TABLE {SCHEMA}.vdocs (id int, tenant_id varchar(36))")
        c.execute(f"INSERT INTO {SCHEMA}.vdocs VALUES (1, 'A'), (2, 'B')")
        c.execute(f"GRANT SELECT ON {SCHEMA}.vdocs TO {ROLE}")
        c.execute(f"GRANT CREATE ON SCHEMA public TO {ROLE}")
        c.execute(f"SET ROLE {ROLE}")
        c.execute("CREATE FUNCTION public.rv_any(varchar, text) RETURNS boolean LANGUAGE sql AS 'SELECT true'")
        c.execute("CREATE OPERATOR public.= (LEFTARG = varchar, RIGHTARG = text, FUNCTION = public.rv_any)")
        c.execute("RESET ROLE")
    try:
        _migrate()
        with psycopg.connect(DSN) as c:
            c.execute(f"SET LOCAL ROLE {ROLE}")
            c.execute("SET LOCAL search_path = public")
            assert c.execute(f"SELECT id FROM {SCHEMA}.vdocs").fetchall() == []          # no tenant: nothing
        with psycopg.connect(DSN, autocommit=True) as c:
            stem = c.execute("SELECT 'fw_' || left(md5(%s), 12)", (f"{SCHEMA}.vdocs",)).fetchone()[0]
            c.execute("SET search_path = public")                         # binds "=" to the planted operator
            c.execute(f"ALTER POLICY {stem}_sel ON {SCHEMA}.vdocs USING (tenant_id = (SELECT public._firewall_tenant()) "
                      "OR (SELECT public._firewall_is_bypass_role(current_user::text)))")
            report = scan_tables(c, DBEngine.POSTGRESQL, _cfg())["vdocs"]
            assert report["protected"] is False and f"{stem}_sel" in report["altered_policies"]
            assert c.execute("SHOW search_path").fetchone()[0] == "public"      # the scanner put it back
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE {SCHEMA}.vdocs")
            c.execute("DROP OPERATOR public.= (varchar, text)")
            c.execute("DROP FUNCTION public.rv_any(varchar, text)")
            c.execute(f"REVOKE CREATE ON SCHEMA public FROM {ROLE}")


def test_reading_the_tenant_map_stays_allowed_writing_does_not():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT SELECT, INSERT ON public._firewall_tenant_map TO {ROLE}")
        c.execute(f"GRANT SELECT (key) ON public._firewall_keys TO {ROLE}")          # a column grant
    _migrate()
    with psycopg.connect(DSN) as c:
        privs = c.execute(
            "SELECT has_table_privilege(%s, 'public._firewall_tenant_map', 'SELECT'), "
            "has_table_privilege(%s, 'public._firewall_tenant_map', 'INSERT'), "
            "has_any_column_privilege(%s, 'public._firewall_keys', 'SELECT')", (ROLE, ROLE, ROLE)).fetchone()
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"REVOKE ALL ON public._firewall_tenant_map FROM {ROLE}")
    assert privs == (True, False, False)


def test_scanner_fails_when_a_firewall_function_was_changed():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("CREATE OR REPLACE FUNCTION public._firewall_tenant() RETURNS TEXT AS $f$ "
                  "SELECT NULLIF(current_setting('app.current_tenant', true), ''); "
                  "$f$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp")
        try:
            report = scan_tables(c, DBEngine.POSTGRESQL, _cfg())["docs"]
        finally:
            _migrate()
    assert report["protected"] is False and "_firewall_tenant (body)" in report["predicate_check"]


def test_checkin_restores_the_settings_from_before_not_the_agents():
    """The reset restores the settings the connection had when the middleware
    first set a tenant on it, not the ones SQL changed afterwards."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sg_other') "
                  "THEN CREATE ROLE sg_other NOLOGIN; END IF; END $$")
        c.execute(f"GRANT sg_other TO {ROLE}")
    try:
        with psycopg.connect(DSN) as c:
            c.execute(f"SET ROLE {ROLE}")
            c.commit()
            _set_context_postgres(c, "A")                                 # baseline: before any agent SQL
            c.execute("SET search_path = sg_evil, public")
            c.execute("SET statement_timeout = '4s'")
            c.execute("SET ROLE sg_other")
            c.commit()
            db_context.pool_checkin(c)
            state = c.execute("SELECT current_setting('search_path'), current_setting('statement_timeout'), "
                              "current_user").fetchone()
        assert state == ('"$user", public', "0", ROLE)
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"REVOKE sg_other FROM {ROLE}")
            c.execute("DROP ROLE sg_other")


def test_a_reset_the_agent_broke_closes_the_connection():
    """SQL can leave a transaction_* setting the restore cannot apply inside a
    transaction, or break the reset some other way. Check-in must then close
    the connection and raise, never hand it on."""
    with psycopg.connect(DSN) as c:
        c.execute(f"SET ROLE {ROLE}")
        c.commit()
        _set_context_postgres(c, "A")
        c.execute("PREPARE agent_plant AS SELECT 1")
        c.execute("COMMIT")
        c.execute("SET transaction_deferrable = on")                    # left for the restore
        c.commit()
        try:
            db_context.pool_checkin(c)
        except Exception:
            assert c.closed
        else:                                                            # the restore skipped it: clean
            assert c.execute("SELECT count(*) FROM pg_prepared_statements WHERE from_sql").fetchone()[0] == 0
    with psycopg.connect(DSN) as c:
        c.execute(f"SET ROLE {ROLE}")
        c.commit()
        _set_context_postgres(c, "A")
        c.commit()
        # Make the reset itself fail: a snapshot that is not JSON.
        orig = db_context._baseline
        db_context._baseline = lambda conn: "not json"
        try:
            with pytest.raises(Exception):
                db_context.pool_checkin(c)
            assert c.closed
        finally:
            db_context._baseline = orig


def test_release_inside_a_transaction_is_reset_again_at_the_next_tenant():
    """release() inside an open transaction resets before the app's COMMIT; a
    deferred trigger firing at that COMMIT (it needs CREATE in a schema, which
    verify fails) must not reach the next tenant."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS sg_plant CASCADE")
        c.execute("CREATE SCHEMA sg_plant")
        c.execute(f"GRANT CREATE, USAGE ON SCHEMA sg_plant TO {ROLE}")
    try:
        with psycopg.connect(DSN) as c:
            c.execute(f"SET ROLE {ROLE}")
            c.commit()
            _set_context_postgres(c, "A")
            c.execute("CREATE TABLE sg_plant.t (x int)")
            c.execute("CREATE FUNCTION sg_plant.f() RETURNS trigger LANGUAGE plpgsql AS "
                      "$$ BEGIN PERFORM set_config('search_path', 'sg_plant, public', false); RETURN NULL; END $$")
            c.execute("CREATE CONSTRAINT TRIGGER late AFTER INSERT ON sg_plant.t DEFERRABLE INITIALLY DEFERRED "
                      "FOR EACH ROW EXECUTE FUNCTION sg_plant.f()")
            c.execute("INSERT INTO sg_plant.t VALUES (1)")
            db_context.clear_db_context(c, DBEngine.POSTGRESQL)          # release(), transaction still open
            c.commit()                                                     # the trigger fires here
            assert c.execute("SHOW search_path").fetchone()[0] == "sg_plant, public"
            c.commit()
            _set_context_postgres(c, "B")                                  # the next tenant
            assert c.execute("SHOW search_path").fetchone()[0] == '"$user", public'
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute("DROP SCHEMA sg_plant CASCADE")


def test_migration_revokes_trigger_and_truncate_on_protected_tables():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT TRIGGER, TRUNCATE ON {SCHEMA}.docs TO {ROLE}")
        c.execute(f"GRANT TRIGGER ON {SCHEMA}.docs TO PUBLIC")
    _migrate()
    with psycopg.connect(DSN) as c:
        privs = c.execute(f"SELECT has_table_privilege(%s, '{SCHEMA}.docs', 'TRIGGER'), "
                          f"has_table_privilege(%s, '{SCHEMA}.docs', 'TRUNCATE'), "
                          f"has_table_privilege(%s, '{SCHEMA}.docs', 'SELECT')", (ROLE, ROLE, ROLE)).fetchone()
    assert privs == (False, False, True)


def test_reset_drops_the_last_tenants_sequence_values():
    """currval/lastval would show the next borrower the previous tenant's ids."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"CREATE TABLE {SCHEMA}.seqd (id serial, tenant_id text)")
        c.execute(f"GRANT SELECT, INSERT ON {SCHEMA}.seqd TO {ROLE}")
        c.execute(f"GRANT USAGE ON SEQUENCE {SCHEMA}.seqd_id_seq TO {ROLE}")
    _migrate()
    try:
        with psycopg.connect(DSN) as c:
            c.execute(f"SET ROLE {ROLE}")
            c.commit()
            _set_context_postgres(c, "B")
            c.execute(f"INSERT INTO {SCHEMA}.seqd (tenant_id) VALUES ('B')")
            c.commit()
            db_context.pool_checkin(c)
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):   # lastval not yet defined
                c.execute("SELECT lastval()")
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE {SCHEMA}.seqd")


def test_harden_signals_revokes_backend_signals_and_is_off_by_default():
    sql = ("SELECT has_function_privilege(%s, 'pg_catalog.pg_terminate_backend(integer, bigint)', 'EXECUTE'), "
           "has_function_privilege(%s, 'pg_catalog.pg_cancel_backend(integer)', 'EXECUTE')")
    with psycopg.connect(DSN) as c:
        assert c.execute(sql, (ROLE, ROLE)).fetchone() == (True, True)          # default: unchanged
    cfg = _cfg()
    cfg["engines"]["postgresql"]["harden_signals"] = True
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN) as c:
            assert c.execute(sql, (ROLE, ROLE)).fetchone() == (False, False)
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute("GRANT EXECUTE ON FUNCTION pg_catalog.pg_terminate_backend(integer, bigint), "
                      "pg_catalog.pg_cancel_backend(integer) TO PUBLIC")


def test_harden_signals_must_be_a_boolean():
    from middleware.db_firewall.config import validate_config
    with pytest.raises(ValueError, match="harden_signals"):
        validate_config({"engines": {"postgresql": {"harden_signals": "yes"}}})
