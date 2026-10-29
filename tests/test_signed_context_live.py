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
        key, nonce, sig = c.execute("SELECT encode(key, 'hex'), db_firewall._firewall_nonce(), "
                                    "db_firewall._firewall_sign('Acme:ü') FROM db_firewall._firewall_keys").fetchone()
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
    "SELECT db_firewall._firewall_sign('B')",
    "SELECT db_firewall._firewall_set_tenant('B')",
    "SELECT key FROM db_firewall._firewall_keys",
    "INSERT INTO db_firewall._firewall_bypass_roles VALUES ('sg_app_user')",
])
def test_app_role_cannot_sign_read_the_key_or_bypass(sql):
    with psycopg.connect(DSN) as c:
        c.execute(f"SET LOCAL ROLE {ROLE}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)


def test_grants_from_default_privileges_are_revoked():
    # Supabase-style: the platform grants every new object to its roles directly.
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT SELECT ON db_firewall._firewall_keys TO {ROLE}")
        c.execute(f"GRANT EXECUTE ON FUNCTION db_firewall._firewall_sign(text) TO {ROLE}")
        c.execute(f"GRANT INSERT ON db_firewall._firewall_bypass_roles TO {ROLE}")
    _migrate()
    with psycopg.connect(DSN) as c:
        rows = c.execute(
            "SELECT count(*) FROM (SELECT relacl AS acl FROM pg_class WHERE oid IN "
            "('db_firewall._firewall_keys'::regclass, 'db_firewall._firewall_bypass_roles'::regclass) "
            "UNION ALL SELECT proacl FROM pg_proc WHERE oid = 'db_firewall._firewall_sign(text)'::regprocedure) a, "
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
            c.execute(f"ALTER POLICY {stem}_sel ON {SCHEMA}.vdocs USING (tenant_id = (SELECT db_firewall._firewall_tenant()) "
                      "OR (SELECT db_firewall._firewall_is_bypass_role(current_user::text)))")
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
        c.execute(f"GRANT SELECT, INSERT ON db_firewall._firewall_tenant_map TO {ROLE}")
        c.execute(f"GRANT SELECT (key) ON db_firewall._firewall_keys TO {ROLE}")          # a column grant
    _migrate()
    with psycopg.connect(DSN) as c:
        privs = c.execute(
            "SELECT has_table_privilege(%s, 'db_firewall._firewall_tenant_map', 'SELECT'), "
            "has_table_privilege(%s, 'db_firewall._firewall_tenant_map', 'INSERT'), "
            "has_any_column_privilege(%s, 'db_firewall._firewall_keys', 'SELECT')", (ROLE, ROLE, ROLE)).fetchone()
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"REVOKE ALL ON db_firewall._firewall_tenant_map FROM {ROLE}")
    assert privs == (True, False, False)


def test_scanner_fails_when_a_firewall_function_was_changed():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("CREATE OR REPLACE FUNCTION db_firewall._firewall_tenant() RETURNS TEXT AS $f$ "
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


def test_harden_revokes_create_trigger_and_truncate_for_the_app_role():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"CREATE TABLE {SCHEMA}.notes (n text)")
        c.execute(f"GRANT SELECT, TRIGGER, TRUNCATE ON {SCHEMA}.notes TO {ROLE}")
        c.execute(f"GRANT CREATE ON SCHEMA {SCHEMA} TO {ROLE}")
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(harden=True, app_role=ROLE)
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN) as c:
            privs = c.execute(
                f"SELECT has_table_privilege(%s, '{SCHEMA}.notes', 'TRIGGER'), "
                f"has_table_privilege(%s, '{SCHEMA}.notes', 'TRUNCATE'), "
                f"has_table_privilege(%s, '{SCHEMA}.notes', 'SELECT'), has_schema_privilege(%s, '{SCHEMA}', 'CREATE'), "
                "has_function_privilege(%s, 'pg_catalog.pg_terminate_backend(integer, bigint)', 'EXECUTE'), "
                "has_table_privilege(%s, 'pg_catalog.pg_stat_activity', 'SELECT')",
                (ROLE,) * 6).fetchone()
        assert privs == (False, False, True, False, False, False)
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE {SCHEMA}.notes")
            c.execute("GRANT EXECUTE ON FUNCTION pg_catalog.pg_terminate_backend(integer, bigint), "
                      "pg_catalog.pg_cancel_backend(integer), pg_catalog.pg_stat_get_activity(integer), "
                      "pg_catalog.pg_stat_get_backend_activity(integer) TO PUBLIC")
            c.execute("GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC")


@pytest.mark.parametrize("pg, match", [({"harden": "yes"}, "harden"), ({"app_role": ""}, "app_role")])
def test_harden_options_are_checked(pg, match):
    from middleware.db_firewall.config import validate_config
    with pytest.raises(ValueError, match=match):
        validate_config({"engines": {"postgresql": pg}})


def _drop_guard():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP EVENT TRIGGER IF EXISTS _firewall_ddl_guard")
        c.execute("DROP EVENT TRIGGER IF EXISTS _firewall_ddl_drop_guard")


def _npol(c, rel):
    return c.execute(f"SELECT count(*) FROM pg_policy WHERE polrelid = '{rel}'::regclass").fetchone()[0]


def test_ddl_guard_protects_new_tables_and_refuses_weakening():
    """Event triggers are database-wide: the test removes them at the end."""
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(ddl_guard=True)
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"CREATE TABLE {SCHEMA}.later (id int, tenant_id text)")
            c.execute(f"INSERT INTO {SCHEMA}.later VALUES (1, 'A'), (2, 'B')")
            c.execute(f"GRANT SELECT ON {SCHEMA}.later TO {ROLE}")
        assert scan_tables(psycopg.connect(DSN), DBEngine.POSTGRESQL, _cfg())["later"]["protected"]
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"CREATE TABLE {SCHEMA}.cta AS SELECT 1 AS id, 'A'::text AS tenant_id")
            assert _npol(c, f"{SCHEMA}.cta") == 4
            c.execute(f"DROP TABLE {SCHEMA}.cta")
        stem = psycopg.connect(DSN).execute(f"SELECT 'fw_' || left(md5('{SCHEMA}.later'), 12)").fetchone()[0]
        refused = [f"ALTER TABLE {SCHEMA}.later DISABLE ROW LEVEL SECURITY",
                   f"ALTER TABLE {SCHEMA}.later NO FORCE ROW LEVEL SECURITY",
                   f"DROP POLICY {stem}_sel ON {SCHEMA}.later",
                   f"ALTER POLICY {stem}_sel ON {SCHEMA}.later USING (true)",
                   f"CREATE POLICY open_all ON {SCHEMA}.later USING (true)",             # permissive mode: ORs
                   f"ALTER TABLE {SCHEMA}.later DROP COLUMN tenant_id CASCADE"]
        for sql in refused:
            with psycopg.connect(DSN, autocommit=True) as c, pytest.raises(psycopg.Error, match="DB Firewall"):
                c.execute(sql)
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"CREATE POLICY narrow ON {SCHEMA}.later AS RESTRICTIVE USING (id > 0)")   # narrows: fine
            c.execute(f"DROP POLICY narrow ON {SCHEMA}.later")
            c.execute(f"ALTER TABLE {SCHEMA}.later RENAME TO later2")                       # protected again
        assert scan_tables(psycopg.connect(DSN), DBEngine.POSTGRESQL, _cfg())["later2"]["protected"]
        with psycopg.connect(DSN) as c:                                                     # a re-run passes the guard
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE {SCHEMA}.later2")                                       # dropping the table is fine
    finally:
        _drop_guard()
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE IF EXISTS {SCHEMA}.later, {SCHEMA}.later2")


def test_ddl_guard_is_a_boolean():
    from middleware.db_firewall.config import validate_config
    with pytest.raises(ValueError, match="ddl_guard"):
        validate_config({"engines": {"postgresql": {"ddl_guard": "yes"}}})


def test_ddl_guard_resists_a_table_owner():
    """Review findings for PR 18: a role that owns a table in a protected
    schema, and can CREATE in public, cannot use the guard to become a
    superuser, skip it, or take its table out of protection."""
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(ddl_guard=True)
    atk = "sg_atk"
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{atk}') "
                  f"THEN CREATE ROLE {atk} LOGIN; END IF; END $$")
        c.execute(f"GRANT CREATE, USAGE ON SCHEMA public, {SCHEMA} TO {atk}")
        c.execute("DROP SCHEMA IF EXISTS sg_other CASCADE; CREATE SCHEMA sg_other")
        c.execute(f"GRANT CREATE, USAGE ON SCHEMA sg_other TO {atk}")
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c:
            # A planted overload with name arguments, an exact match for the old
            # call: refused when created (the guard also calls with text casts).
            with pytest.raises(psycopg.Error, match="where the firewall keeps its own objects"):
                c.execute("CREATE FUNCTION public._firewall_protect(a name, b name, x text, y text, z text) RETURNS void "
                          f"LANGUAGE plpgsql AS $f$ BEGIN EXECUTE 'ALTER ROLE {atk} SUPERUSER'; END $f$")
            c.execute(f"CREATE TABLE {SCHEMA}.bait (id int, tenant_id text)")
        with psycopg.connect(DSN, autocommit=True) as c:
            assert c.execute(f"SELECT rolsuper FROM pg_roles WHERE rolname = '{atk}'").fetchone()[0] is False
            assert c.execute(f"SELECT count(*) FROM pg_policy WHERE polrelid = '{SCHEMA}.bait'::regclass").fetchone()[0] == 4
        stem = psycopg.connect(DSN).execute(f"SELECT 'fw_' || left(md5('{SCHEMA}.bait'), 12)").fetchone()[0]
        with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c:
            # Tables the command does not name get the tenant column: each is
            # protected by the end of that command, not by a later one.
            for sql, tables in [
                (f"CREATE TABLE {SCHEMA}.pp (id int, tenant_id text) PARTITION BY LIST (tenant_id)", ["pp"]),
                (f"CREATE TABLE {SCHEMA}.pp_d PARTITION OF {SCHEMA}.pp DEFAULT", ["pp_d"]),
                (f"CREATE TABLE {SCHEMA}.par (id int); CREATE TABLE {SCHEMA}.kid () INHERITS ({SCHEMA}.par); "
                 f"ALTER TABLE {SCHEMA}.par ADD COLUMN tenant_id text", ["par", "kid"]),
                (f"CREATE TYPE {SCHEMA}.ct AS (id int); CREATE TABLE {SCHEMA}.typed OF {SCHEMA}.ct; "
                 f"ALTER TYPE {SCHEMA}.ct ADD ATTRIBUTE tenant_id text CASCADE", ["typed"]),
                (f"CREATE TABLE {SCHEMA}.lp (id int, tid text) PARTITION BY LIST (id); "
                 f"CREATE TABLE {SCHEMA}.lp1 PARTITION OF {SCHEMA}.lp FOR VALUES IN (1); "
                 f"ALTER TABLE {SCHEMA}.lp RENAME COLUMN tid TO tenant_id", ["lp", "lp1"]),
            ]:
                c.execute(sql)
                for t in tables:
                    assert _npol(c, f"{SCHEMA}.{t}") == 4, t
            c.execute(f"GRANT TRUNCATE, TRIGGER ON {SCHEMA}.bait TO {ROLE}")              # revoked again
            assert c.execute(f"SELECT has_table_privilege('{ROLE}', '{SCHEMA}.bait', 'TRUNCATE') "
                             f"OR has_table_privilege('{ROLE}', '{SCHEMA}.bait', 'TRIGGER')").fetchone()[0] is False
        for sql in [f"CREATE TABLE sg_other.leak PARTITION OF {SCHEMA}.pp FOR VALUES IN ('B')",   # gets B's inserts
                    f"CREATE TABLE {SCHEMA}._firewall_leak PARTITION OF {SCHEMA}.pp FOR VALUES IN ('B')",
                    f"CREATE TABLE sg_other.leak (id int, tenant_id text); "
                    f"ALTER TABLE {SCHEMA}.pp ATTACH PARTITION sg_other.leak FOR VALUES IN ('B')",
                    # neither table named: ALTER TYPE ... CASCADE gives both the column
                    f"CREATE TYPE {SCHEMA}.ct2 AS (id int); CREATE TABLE {SCHEMA}.typed2 OF {SCHEMA}.ct2; "
                    f"CREATE TABLE sg_other.kid2 () INHERITS ({SCHEMA}.typed2); "
                    f"ALTER TYPE {SCHEMA}.ct2 ADD ATTRIBUTE tenant_id text CASCADE"]:
            with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c, \
                    pytest.raises(psycopg.Error, match="gets the rows written to it"):
                c.execute(sql)
        refused = [
            f"SET dbfw.ddl_guard_skip = 'on'; ALTER TABLE {SCHEMA}.bait DISABLE ROW LEVEL SECURITY",   # not theirs to skip
            f"SET dbfw.guard_call = ''; ALTER TABLE {SCHEMA}.bait DISABLE ROW LEVEL SECURITY",   # no call of the guard's
            f"CREATE POLICY {stem}_base ON {SCHEMA}.bait AS PERMISSIVE USING (true)",   # the firewall's name
            f"CREATE TABLE sg_other.up (id int, tenant_id text) PARTITION BY LIST (tenant_id); "
            f"ALTER TABLE sg_other.up ATTACH PARTITION {SCHEMA}.bait FOR VALUES IN ('A')",
            f"CREATE TABLE sg_other.sink (id int, t text); CREATE RULE r_leak AS ON INSERT TO {SCHEMA}.bait "
            f"DO ALSO INSERT INTO sg_other.sink VALUES (NEW.id, NEW.tenant_id)",
            f"CREATE TYPE sg_other.tid AS ENUM ('A', 'B'); "                             # its cast would decide
            f"CREATE TABLE {SCHEMA}.t3 (id int, tenant_id sg_other.tid)",
            # An overload with a default argument makes the firewall's own calls ambiguous.
            "CREATE FUNCTION public._firewall_tenant(x int DEFAULT 0) RETURNS text LANGUAGE sql AS $$ SELECT 'A' $$",
            "CREATE FUNCTION public.fw_x() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$; "
            "ALTER FUNCTION public.fw_x() RENAME TO _firewall_x",
            f"CREATE COLLATION sg_other.ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false); "
            f"CREATE TABLE {SCHEMA}.t4 (id int, tenant_id text COLLATE sg_other.ci)",
            # A rule that comes along when the table is protected for the first time.
            f"CREATE TABLE sg_other.orders (id int, tenant_id text); CREATE TABLE sg_other.sink2 (id int, t text); "
            f"CREATE RULE r2 AS ON INSERT TO sg_other.orders DO ALSO INSERT INTO sg_other.sink2 VALUES (NEW.id, NEW.tenant_id); "
            f"ALTER TABLE sg_other.orders SET SCHEMA {SCHEMA}",
            f"CREATE TABLE {SCHEMA}.r3 (id int); CREATE TABLE sg_other.sink3 (id int); "
            f"CREATE RULE r3 AS ON INSERT TO {SCHEMA}.r3 DO ALSO INSERT INTO sg_other.sink3 VALUES (NEW.id); "
            f"ALTER TABLE {SCHEMA}.r3 ADD COLUMN tenant_id text",
            # Commands that rename a table or a column under another tag.
            f"ALTER INDEX {SCHEMA}.bait RENAME TO schema_migrations",
            f"ALTER VIEW {SCHEMA}.bait RENAME COLUMN tenant_id TO tid",
            f"ALTER MATERIALIZED VIEW {SCHEMA}.bait RENAME COLUMN tenant_id TO tid",
            f"CREATE TABLE {SCHEMA}.schema_migrations (id int, tenant_id text); "
            f"CREATE POLICY open ON {SCHEMA}.schema_migrations USING (true); "
            f"ALTER INDEX {SCHEMA}.schema_migrations RENAME TO invoices",
            f"ALTER POLICY {stem}_sel ON {SCHEMA}.bait RENAME TO mine",
            f"CREATE POLICY {stem}_x ON {SCHEMA}.bait USING (true)",                  # named like the stem
            f"ALTER TABLE {SCHEMA}.bait RENAME COLUMN tenant_id TO tid",
            f"ALTER TABLE {SCHEMA}.bait RENAME TO schema_migrations",
            f"ALTER TABLE {SCHEMA}.bait SET SCHEMA sg_other",
            f"CREATE TABLE {SCHEMA}._firewall_p (id int, tenant_id text); ALTER TABLE {SCHEMA}.bait INHERIT {SCHEMA}._firewall_p",
        ]
        for sql in refused:
            with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c, pytest.raises(psycopg.Error, match="DB Firewall"):
                c.execute(sql)
        with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c:
            c.execute(f"CREATE TABLE {SCHEMA}.own (x int); CREATE POLICY everyone ON {SCHEMA}.own USING (true)")
            with pytest.raises(psycopg.Error, match="permissive policy of its own"):
                c.execute(f"ALTER TABLE {SCHEMA}.own ADD COLUMN tenant_id text")
        for sql in [f"ALTER SCHEMA {SCHEMA} RENAME TO {SCHEMA}_x",                # a superuser, without the skip
                    f"SET session_replication_role = replica; ALTER TABLE {SCHEMA}.bait DISABLE ROW LEVEL SECURITY",
                    "CREATE FOREIGN DATA WRAPPER sg_fdw; CREATE SERVER sg_srv FOREIGN DATA WRAPPER sg_fdw; "
                    f"CREATE FOREIGN TABLE sg_other.ft PARTITION OF {SCHEMA}.pp FOR VALUES IN ('Z') SERVER sg_srv"]:
            with psycopg.connect(DSN, autocommit=True) as c, pytest.raises(psycopg.Error, match="DB Firewall"):
                c.execute(sql)
        with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c, \
                pytest.raises(psycopg.Error, match="permission denied"):           # only the owner writes it
            c.execute("INSERT INTO db_firewall._firewall_guard_calls VALUES (pg_backend_pid(), 'x')")
        # EXPLAIN ANALYZE CREATE TABLE AS fires no event trigger (PostgreSQL):
        # the next command, whatever it is, protects the table.
        with psycopg.connect(f"{DSN} user={atk}", autocommit=True) as c:
            c.execute(f"EXPLAIN (ANALYZE) CREATE TABLE {SCHEMA}.ex AS SELECT 1 AS id, 'A'::text AS tenant_id")
            assert _npol(c, f"{SCHEMA}.ex") == 0
            c.execute("CREATE FUNCTION sg_other.any_cmd() RETURNS int LANGUAGE sql AS 'SELECT 1'")   # any command
            assert _npol(c, f"{SCHEMA}.ex") == 4
        # An open transaction that ran the guard does not hold up another role's DDL.
        with psycopg.connect(f"{DSN} user={atk}") as hold, psycopg.connect(DSN, autocommit=True) as other:
            hold.execute(f"GRANT TRUNCATE ON {SCHEMA}.bait TO {ROLE}")                 # revoked again, still open
            hold.execute(f"CREATE TABLE {SCHEMA}.held (id int, tenant_id text)")       # protected, still open
            other.execute("SET lock_timeout = '2s'")
            other.execute(f"CREATE TABLE {SCHEMA}.free (id int, tenant_id text)")
            assert _npol(other, f"{SCHEMA}.free") == 4
            hold.rollback()
        with psycopg.connect(DSN, autocommit=True) as c:                          # a schema the migration lists
            c.execute("INSERT INTO db_firewall._firewall_protected_schemas (schema_name, tenant_column, policy_mode, context) "
                      "VALUES ('sg_ghost', 'tenant_id', 'permissive', 'signed')")
            c.execute("CREATE SCHEMA sg_ghost CREATE TABLE g (id int, tenant_id text)")
            assert _npol(c, "sg_ghost.g") == 4
    finally:
        _drop_guard()
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE IF EXISTS {SCHEMA}.bait, {SCHEMA}.own, {SCHEMA}._firewall_p, {SCHEMA}.pp, {SCHEMA}.free, {SCHEMA}.ex, "
                      f"{SCHEMA}.kid, {SCHEMA}.par, {SCHEMA}.typed, {SCHEMA}.lp")
            c.execute(f"DROP TYPE IF EXISTS {SCHEMA}.ct")
            c.execute("DROP SCHEMA IF EXISTS sg_ghost CASCADE; "
                      "DELETE FROM db_firewall._firewall_protected_schemas WHERE schema_name = 'sg_ghost'")
            c.execute("DROP FUNCTION IF EXISTS public._firewall_protect(name, name, text, text, text)")
            c.execute("DROP SCHEMA IF EXISTS sg_other CASCADE")
            c.execute("DROP FOREIGN DATA WRAPPER IF EXISTS sg_fdw CASCADE")
            c.execute(f"REVOKE CREATE, USAGE ON SCHEMA public, {SCHEMA} FROM {atk}")
            c.execute(f"DROP OWNED BY {atk}; DROP ROLE {atk}")


def test_ddl_guard_in_restrictive_mode():
    """Restrictive mode: a new table gets the four policies and "<stem>_base";
    the app may add a permissive policy (the tenant policies still bound it),
    but not one with the firewall's names."""
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(ddl_guard=True, policy_mode="restrictive")
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"CREATE TABLE {SCHEMA}.rt (id int, tenant_id text)")
            stem = c.execute(f"SELECT 'fw_' || left(md5('{SCHEMA}.rt'), 12)").fetchone()[0]
            assert _npol(c, f"{SCHEMA}.rt") == 5
            c.execute(f"CREATE POLICY mine ON {SCHEMA}.rt AS PERMISSIVE USING (id > 0)")
            for sql in [f"CREATE POLICY {stem}_base2 ON {SCHEMA}.rt USING (true)",
                        f"ALTER POLICY {stem}_base ON {SCHEMA}.rt USING (id > 1)",
                        f"ALTER TABLE {SCHEMA}.rt NO FORCE ROW LEVEL SECURITY"]:
                with pytest.raises(psycopg.Error, match="DB Firewall"):
                    c.execute(sql)
    finally:
        _drop_guard()
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE IF EXISTS {SCHEMA}.rt")
        _migrate()


def test_ddl_guard_with_many_tables():
    """GRANT ALL ON ALL TABLES with 500 protected tables: the guard revokes
    TRUNCATE and TRIGGER again without nesting a guard per REVOKE, and an
    unrelated command stays cheap."""
    import time
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(ddl_guard=True)
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DO $$ BEGIN FOR i IN 1..500 LOOP "
                      f"EXECUTE format('CREATE TABLE {SCHEMA}.m%s (id int, tenant_id text)', i); END LOOP; END $$")
            c.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO {ROLE}")
            assert c.execute(f"SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                             f"WHERE n.nspname = '{SCHEMA}' AND c.relname ~ '^m[0-9]+$' "
                             f"AND (has_table_privilege('{ROLE}', c.oid, 'TRUNCATE') "
                             f"OR has_table_privilege('{ROLE}', c.oid, 'TRIGGER') "
                             f"OR NOT has_table_privilege('{ROLE}', c.oid, 'SELECT'))").fetchone()[0] == 0
            start = time.monotonic()
            c.execute("CREATE TEMP TABLE sg_tmp (x int)")
            assert time.monotonic() - start < 1.0          # generous: a set query, not a loop per table
    finally:
        _drop_guard()
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DO $$ BEGIN FOR i IN 1..500 LOOP "
                      f"EXECUTE format('DROP TABLE IF EXISTS {SCHEMA}.m%s', i); END LOOP; END $$")
        _migrate()



def test_migration_moves_firewall_objects_out_of_public():
    """An install from before schema db_firewall: the objects are in public.
    The migration moves them (SET SCHEMA keeps each object), so the key, the
    policies of every schema and the rows stay."""
    with psycopg.connect(DSN, autocommit=True) as c:
        key = c.execute("SELECT key FROM db_firewall._firewall_keys").fetchone()[0]
        for (sig,) in c.execute("SELECT oid::regprocedure::text FROM pg_proc "
                                "WHERE pronamespace = 'db_firewall'::regnamespace").fetchall():
            c.execute(f"DROP FUNCTION IF EXISTS public.{sig.split('.', 1)[1]}")    # the placeholder
            c.execute(f"ALTER ROUTINE {sig} SET SCHEMA public")
        for (rel,) in c.execute("SELECT relname FROM pg_class WHERE relnamespace = 'db_firewall'::regnamespace "
                                "AND relkind = 'r'").fetchall():
            c.execute(f"DROP VIEW IF EXISTS public.{rel}")
            c.execute(f"ALTER TABLE db_firewall.{rel} SET SCHEMA public")
    _migrate()
    with psycopg.connect(DSN, autocommit=True) as c:
        assert c.execute("SELECT count(*) FROM pg_proc p WHERE pronamespace = 'public'::regnamespace "
                         "AND proname LIKE '\\_firewall\\_%' AND obj_description(p.oid, 'pg_proc') "
                         "IS DISTINCT FROM 'DB Firewall: moved to db_firewall'").fetchone()[0] == 0   # placeholders only
        assert c.execute("SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                         "AND relname LIKE '\\_firewall\\_%' AND relkind <> 'v'").fetchone()[0] == 0
        assert c.execute("SELECT key FROM db_firewall._firewall_keys").fetchone()[0] == key
    assert _as_app(lambda c: _set_context_postgres(c, "A")) == [1]


def test_only_the_owner_creates_in_the_firewall_schema():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT CREATE ON SCHEMA db_firewall TO {ROLE}")
    _migrate()                                                       # revokes it
    with psycopg.connect(DSN, autocommit=True) as c:
        assert c.execute(f"SELECT has_schema_privilege('{ROLE}', 'db_firewall', 'CREATE')").fetchone()[0] is False
        c.execute(f"GRANT CREATE ON SCHEMA db_firewall TO {ROLE}")
        c.execute(f"SET ROLE {ROLE}")
        c.execute("CREATE FUNCTION db_firewall._firewall_tenant(x int DEFAULT 0) RETURNS text "
                  "LANGUAGE sql AS $$ SELECT 'A' $$")
        c.execute("RESET ROLE")
    try:
        with pytest.raises(psycopg.errors.RaiseException, match="planted"):
            _migrate()
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute("DROP FUNCTION db_firewall._firewall_tenant(int)")
            c.execute(f"REVOKE CREATE ON SCHEMA db_firewall FROM {ROLE}")
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(schema="db_firewall")
    with psycopg.connect(DSN) as c, pytest.raises(Exception, match="db_firewall"):
        run_migration(c, DBEngine.POSTGRESQL, cfg)


def test_an_overload_planted_in_public_breaks_nothing():
    """The policies and the firewall's functions call db_firewall: a role that
    can CREATE in public can no longer make those calls ambiguous."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT CREATE ON SCHEMA public TO {ROLE}")
        c.execute(f"SET ROLE {ROLE}")
        c.execute("CREATE FUNCTION public._firewall_tenant(x int DEFAULT 0) RETURNS text LANGUAGE sql AS $$ SELECT 'B' $$")
        c.execute("CREATE FUNCTION public._firewall_sign(p text, x int DEFAULT 0) RETURNS text LANGUAGE sql AS $$ SELECT 'x' $$")
        c.execute("RESET ROLE")
    try:
        assert _as_app(lambda c: _set_context_postgres(c, "A")) == [1]
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"CREATE TABLE {SCHEMA}.later3 (id int, tenant_id text)")
            c.execute(f"SELECT db_firewall._firewall_protect('{SCHEMA}', 'later3', 'tenant_id', 'permissive', 'signed')")
            assert _npol(c, f"{SCHEMA}.later3") == 4
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE IF EXISTS {SCHEMA}.later3")
            c.execute("DROP FUNCTION IF EXISTS public._firewall_tenant(int), public._firewall_sign(text, int)")
            c.execute(f"REVOKE CREATE ON SCHEMA public FROM {ROLE}")


def test_firewall_relations_keep_only_what_the_app_needs():
    """Section 8 covers every relation in db_firewall: TRIGGER on the audit log
    would run the app's function inside _firewall_set_tenant, as its owner."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA db_firewall TO {ROLE}")
        c.execute(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA db_firewall TO {ROLE}")
    try:
        _migrate()
        with psycopg.connect(DSN, autocommit=True) as c:
            privs = c.execute(
                "SELECT c.relname, string_agg(a.privilege_type, ',' ORDER BY a.privilege_type) FROM pg_class c, "
                "aclexplode(c.relacl) a WHERE c.relnamespace = 'db_firewall'::regnamespace "
                "AND a.grantee = %s::regrole GROUP BY 1 ORDER BY 1", (ROLE,)).fetchall()
        assert privs == [("_firewall_audit_log", "INSERT"), ("_firewall_audit_log_id_seq", "USAGE"),
                         ("_firewall_bypass_roles", "SELECT"), ("_firewall_tenant_map", "SELECT")]
    finally:
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA db_firewall FROM {ROLE}")
            c.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA db_firewall FROM {ROLE}")


def test_old_names_in_public_fail_closed():
    """App code from before the move reaches placeholders that fail, not an
    object another role could create under the old name."""
    with psycopg.connect(DSN, autocommit=True) as c:                 # the migration makes them
        c.execute("DROP VIEW IF EXISTS public._firewall_tenant_map, public._firewall_audit_log; "
                  "DROP FUNCTION IF EXISTS public._firewall_nonce()")
    _migrate()
    with psycopg.connect(DSN, autocommit=True) as c:
        with pytest.raises(psycopg.Error, match="moved to schema db_firewall"):
            c.execute("SELECT public._firewall_nonce()")
        assert c.execute("SELECT count(*) FROM public._firewall_tenant_map").fetchone()[0] == 0
        with pytest.raises(psycopg.Error):
            c.execute("INSERT INTO public._firewall_audit_log (tenant_id) VALUES ('A')")
        c.execute(f"GRANT CREATE ON SCHEMA public TO {ROLE}")
        try:
            c.execute(f"SET ROLE {ROLE}")
            with pytest.raises(psycopg.Error):
                c.execute("CREATE TABLE public._firewall_tenant_map (db_user text, tenant_id text, is_active bool)")
        finally:
            c.execute("RESET ROLE")
            c.execute(f"REVOKE CREATE ON SCHEMA public FROM {ROLE}")


def test_upgrade_with_an_old_ddl_guard_installed():
    """An install from before the move, with the DDL guard on: the old guard
    reads public tables the upgrade moves. The upgrade pauses it, and leaves
    it as it was (enabled always)."""
    import re
    from middleware.db_firewall.migrate import MIGRATIONS_DIR
    sql = (MIGRATIONS_DIR / "001_postgresql.sql").read_text()
    cfg = _cfg()
    cfg["engines"]["postgresql"].update(ddl_guard=True)
    try:
        with psycopg.connect(DSN) as c:
            run_migration(c, DBEngine.POSTGRESQL, cfg)
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute("ALTER EVENT TRIGGER _firewall_ddl_guard DISABLE; ALTER EVENT TRIGGER _firewall_ddl_drop_guard DISABLE")
            for (sig,) in c.execute("SELECT oid::regprocedure::text FROM pg_proc "
                                    "WHERE pronamespace = 'db_firewall'::regnamespace").fetchall():
                c.execute(f"DROP FUNCTION IF EXISTS public.{sig.split('.', 1)[1]}")    # the placeholder
                c.execute(f"ALTER ROUTINE {sig} SET SCHEMA public")
            for (rel,) in c.execute("SELECT relname FROM pg_class WHERE relnamespace = 'db_firewall'::regnamespace "
                                    "AND relkind = 'r'").fetchall():
                c.execute(f"DROP VIEW IF EXISTS public.{rel}")
                c.execute(f"ALTER TABLE db_firewall.{rel} SET SCHEMA public")
            # The old guard's bodies read public tables.
            for name in ("_firewall_ddl_guard", "_firewall_ddl_drop_guard"):
                body = re.search(rf"CREATE OR REPLACE FUNCTION db_firewall\.{name}\(\).*?\$\$ LANGUAGE plpgsql[^;]*;",
                                 sql, re.S).group(0)
                c.execute(body.replace("db_firewall._firewall_", "public._firewall_"))
            c.execute("ALTER EVENT TRIGGER _firewall_ddl_guard ENABLE ALWAYS; "
                      "ALTER EVENT TRIGGER _firewall_ddl_drop_guard ENABLE ALWAYS")
        _migrate()                                                    # without ddl_guard: must still pass
        with psycopg.connect(DSN, autocommit=True) as c:
            assert c.execute("SELECT string_agg(evtenabled::text, '') FROM pg_event_trigger "
                             "WHERE evtname LIKE '\\_firewall\\_ddl\\_%'").fetchone()[0] == "AA"
            c.execute(f"CREATE TABLE {SCHEMA}.after_up (id int, tenant_id text)")
            assert _npol(c, f"{SCHEMA}.after_up") == 4
    finally:
        _drop_guard()
        with psycopg.connect(DSN, autocommit=True) as c:
            c.execute(f"DROP TABLE IF EXISTS {SCHEMA}.after_up")
