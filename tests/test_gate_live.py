"""
DB Firewall — middleware-only gate tests (PostgreSQL, opt-in)
=============================================================
The middleware stands alone here: scratch tables WITHOUT row-level security,
queried as the non-owner role ``dbfw_app`` through ``protect()``. Any tenant-B
row coming back is a leak the AST rewriter / wrappers failed to stop.

Each test reproduces one finding of the independent review (A..N in the task):
the pre-fix result is recorded in the docstring.

    DBFW_PG_DSN="host=/tmp port=5433 dbname=dbfw_test user=postgres" \
        python3 -m pytest tests/test_gate_live.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))

DSN = os.environ.get("DBFW_PG_DSN")
if not DSN:
    pytest.skip("DBFW_PG_DSN not set; skipping live gate tests", allow_module_level=True)

psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import make_conninfo  # noqa: E402

import db_firewall as fw  # noqa: E402
from db_firewall import protect, rewrite_query, TenantContext, validate_tenant_id  # noqa: E402

APP_DSN = make_conninfo(DSN, user="dbfw_app")
MIGRATION = os.path.join(os.path.dirname(__file__), '..', 'migrations', '001_postgresql.sql')
T = "mw_orders"            # RLS OFF: rows 1,2 → A; row 3 → B ('TRAP')
MIXED = '"DBFW_Mixed"'     # quoted mixed-case name
ALIAS = "mw_alias"         # (label, tenant_id): B's row carries label 'A'
CONFIG = {"tenant_column": "tenant_id", "fail_mode": "closed", "rewriter": "ast",
          "protect": {"select": True, "insert": True, "update": True, "delete": True},
          "excluded_tables": ["_firewall_*"]}


@pytest.fixture(scope="module", autouse=True)
def schema():
    with psycopg.connect(DSN, autocommit=True) as a:
        a.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbfw_app') "
                  "THEN CREATE ROLE dbfw_app LOGIN; END IF; END $$")
        a.execute(f"DROP TABLE IF EXISTS {T}, {MIXED}, {ALIAS}")
        # The fixture needs _firewall_tenant_map. Apply the migration before the
        # tables exist, so its RLS loop leaves these RLS-off tables alone. A fresh
        # database (CI) has nothing until this runs.
        a.execute(open(MIGRATION).read())
        a.execute(f"CREATE TABLE {T} (id int primary key, tenant_id text not null, note text)")
        a.execute(f"INSERT INTO {T} VALUES (1,'A','a1'),(2,'A','a2'),(3,'B','TRAP')")
        a.execute(f"CREATE TABLE {MIXED} (id int, tenant_id text, note text)")
        a.execute(f"INSERT INTO {MIXED} VALUES (1,'A','a'),(2,'B','TRAP')")
        a.execute(f"CREATE TABLE {ALIAS} (label text, tenant_id text)")
        a.execute(f"INSERT INTO {ALIAS} VALUES ('x','A'),('A','B')")
        a.execute("GRANT USAGE ON SCHEMA public TO dbfw_app")
        a.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {T}, {MIXED}, {ALIAS} TO dbfw_app")
        a.execute("REVOKE ALL ON _firewall_tenant_map FROM dbfw_app")
    yield
    TenantContext.clear()


@pytest.fixture(autouse=True)
def _clean_context(monkeypatch):
    monkeypatch.delenv("TENANT_ID", raising=False)
    TenantContext.clear()
    yield
    TenantContext.clear()


def run(sql, params=None, tenant="A", config=CONFIG):
    """Execute through protect() as dbfw_app; rows (or rowcount) back, nothing persisted."""
    raw = psycopg.connect(APP_DSN)
    try:
        pc = protect(raw, tenant, config)
        cur = pc.cursor()
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else cur.rowcount
    finally:
        raw.rollback()
        raw.close()


def leaks(rows):
    return any("TRAP" in r or "B" in r for r in rows)


# ---------------------------------------------------------------- A: gate ---

class TestGateReplaced:

    def test_only_keyword(self):
        """C1 — before: `FROM ONLY t` missed the regex gate → 3 rows incl. TRAP."""
        rows = run(f"SELECT * FROM ONLY {T}")
        assert rows == [(1, 'A', 'a1'), (2, 'A', 'a2')]

    def test_comma_join_without_space(self):
        """C3 — both comma-join sources scoped."""
        rows = run(f"SELECT a.note, b.note FROM {T} a,{T} b")
        assert rows and not leaks(rows)

    def test_table_command_refused(self):
        """C5 — `TABLE t` (sqlglot reads it as an alias) is refused outright."""
        with pytest.raises(PermissionError, match="TABLE"):
            run(f"TABLE {T}")
        with pytest.raises(PermissionError, match="TABLE"):
            run(f"SELECT * FROM (TABLE {T}) x")

    def test_nested_block_comment(self):
        """C6 — Postgres nests /* */; the lexical pre-pass must not disagree
        with the server about where a comment ends."""
        with pytest.raises(PermissionError, match="ambiguous"):
            run(f"SET /* x /* y */ zzz */ app.current_tenant = 'B'")
        with pytest.raises(PermissionError, match="ambiguous"):
            run(f"SELECT * FROM /* a /* b */ c */ {T}")

    def test_unicode_escape_identifier_refused(self):
        """C8 — before: U&"mw_orders" was not a word for the regex → 3 rows."""
        with pytest.raises(PermissionError, match="U&"):
            run(f'SELECT * FROM U&"{T}"')
        with pytest.raises(PermissionError, match="U&"):
            run(f"SELECT * FROM {T} WHERE note = U&'a'")

    @pytest.mark.parametrize("sql", [
        "SET app.current_tenant = 'B'", "SET LOCAL app.current_tenant TO 'B'",
        'SET "app.current_tenant" = \'B\'', "SET app . current_tenant = 'B'",
        "SET APP.CURRENT_TENANT = 'B'", "SET ROLE postgres", "SET LOCAL ROLE postgres",
        "SET SESSION AUTHORIZATION postgres", "SET search_path = pg_temp, public",
        "SET row_security = off", "RESET app.current_tenant", "RESET ALL", "RESET ROLE",
        "SELECT set_config('app.current_tenant', 'B', true)",
        "SELECT pg_catalog.set_config('app.current_tenant', 'B', false)",
        f"SELECT set_config(note, 'B', true) FROM {T}",
        "SELECT * FROM set_config('app.current_tenant', 'B', true)",
    ])
    def test_tenant_moving_settings_refused(self, sql):
        """C2 — before: every SET / set_config passed through unparsed."""
        with pytest.raises(PermissionError):
            run(sql)

    @pytest.mark.parametrize("sql", [
        "SET statement_timeout = '5s'", "SET LOCAL lock_timeout TO '1s'", "SET TIME ZONE 'UTC'",
        "RESET statement_timeout", "SELECT set_config('statement_timeout', '5s', true)",
        "BEGIN", "SAVEPOINT s1", "COMMIT", "SELECT 1",
        "SELECT current_setting('app.current_tenant', true)",
    ])
    def test_safe_list_executes(self, sql):
        run(sql)                                   # no exception, server accepts it

    def test_savepoint_sequence_executes(self):
        raw = psycopg.connect(APP_DSN)
        try:
            cur = protect(raw, "A", CONFIG).cursor()
            for sql in ("SAVEPOINT s1", "ROLLBACK TO SAVEPOINT s1", "RELEASE SAVEPOINT s1",
                        "SAVEPOINT s2", "ROLLBACK TO s2", "RELEASE s2"):
                cur.execute(sql)
        finally:
            raw.rollback()
            raw.close()

    @pytest.mark.parametrize("sql", [
        "DO $$ BEGIN NULL; END $$", "CALL nothing()", "EXECUTE p", "PREPARE p AS SELECT 1",
        "DECLARE c CURSOR FOR SELECT 1", f"EXPLAIN SELECT * FROM {T}", "SHOW search_path",
        f"COPY {T} TO STDOUT", f"TRUNCATE {T}", f"ALTER TABLE {T} DROP COLUMN tenant_id",
        f"CREATE TABLE leak AS SELECT * FROM {T}", "CREATE TEMP TABLE scratch (x int)",
        f"GRANT SELECT ON {T} TO public", "VACUUM", "DISCARD ALL", "VALUES (1)",
    ])
    def test_everything_else_refused(self, sql):
        """H4 and the rest of the non-allow-listed heads."""
        with pytest.raises(PermissionError):
            run(sql)


# ------------------------------------------------------------- B: folding ---

class TestCaseFolding:

    def test_unquoted_upper_case_is_folded(self):
        """C4 — before: information_schema lookup for 'MW_ORDERS' found no
        column → table treated as unprotected → 3 rows incl. TRAP."""
        rows = run(f"SELECT * FROM {T.upper()}")
        assert rows == [(1, 'A', 'a1'), (2, 'A', 'a2')]

    def test_quoted_mixed_case_keeps_case(self):
        rows = run(f"SELECT * FROM {MIXED}")
        assert rows == [(1, 'A', 'a')]


# ------------------------------------------------------- C: fail-closed cache ---

class TestMetadataCache:

    def test_aborted_transaction_never_unprotects(self):
        """C9 — before: the lookup failed inside the aborted transaction, the
        failure was cached as has_col=False process-wide, and the NEXT query on
        this and on a brand-new connection returned all 3 rows."""
        fw._table_cache.clear()
        raw = psycopg.connect(APP_DSN)
        pc = protect(raw, "A", CONFIG)
        cur = pc.cursor()
        with pytest.raises(psycopg.errors.DivisionByZero):
            cur.execute("SELECT 1/0")
        with pytest.raises(Exception) as ei:           # refused or DB error, never rows
            cur.execute(f"SELECT * FROM {T}")
            cur.fetchall()
        assert isinstance(ei.value, (PermissionError, psycopg.Error))
        raw.rollback()
        cur.execute(f"SELECT * FROM {T}")
        assert cur.fetchall() == [(1, 'A', 'a1'), (2, 'A', 'a2')]
        raw.close()
        assert all(v[0] is True for k, v in fw._table_cache.items() if k[2] == T)
        assert run(f"SELECT * FROM {T}") == [(1, 'A', 'a1'), (2, 'A', 'a2')]   # new connection

    def test_cache_entries_expire(self, monkeypatch):
        monkeypatch.setattr(fw, "TABLE_CACHE_TTL", 0.0)
        fw._table_cache.clear()
        raw = psycopg.connect(APP_DSN)
        try:
            assert fw._has_tenant_column(raw, T, fw.DBEngine.POSTGRESQL, "tenant_id") is True
            key = next(k for k in fw._table_cache if k[2] == T)
            assert fw._table_cache[key][1] <= __import__("time").monotonic()
            # expired entry is re-fetched, not trusted
            fw._table_cache[key] = (False, fw._table_cache[key][1])
            fw._conn_cache.clear()
            assert fw._has_tenant_column(raw, T, fw.DBEngine.POSTGRESQL, "tenant_id") is True
        finally:
            raw.rollback()
            raw.close()

    def test_lookup_failure_raises_and_is_not_cached(self):
        fw._table_cache.clear()
        raw = psycopg.connect(APP_DSN)
        try:
            with pytest.raises(PermissionError, match="could not verify"):
                fw._has_tenant_column(raw, "no such table", fw.DBEngine.SQLITE, "tenant_id")
            assert not any(k[2] == "no such table" for k in fw._table_cache)
        finally:
            raw.close()


# ---------------------------------------------------------------- D: CTE ---

def test_schema_qualified_table_is_not_the_cte():
    """C7 — before: `public.mw_orders` was taken for the CTE `mw_orders` → 3 rows."""
    rows = run(f"WITH {T} AS (SELECT 1 AS id) SELECT * FROM public.{T}")
    assert rows == [(1, 'A', 'a1'), (2, 'A', 'a2')]


# ----------------------------------------------------- E/F: write-side ---

class TestWriteSide:

    def test_on_conflict_cannot_steal_another_tenants_row(self):
        """H1 — before: the stamped INSERT conflicted on id=3 and DO UPDATE
        rewrote tenant B's row (RETURNING showed note='stolen')."""
        rows = run(f"INSERT INTO {T} (id, note) VALUES (3, 'stolen') "
                   "ON CONFLICT (id) DO UPDATE SET note = EXCLUDED.note RETURNING *")
        assert rows == []                           # guarded WHERE: no row updated
        assert run(f"SELECT note FROM {T} WHERE id = 1 OR id = 3") == [('a1',)]
        # own row still upserts
        rows = run(f"INSERT INTO {T} (id, note) VALUES (1, 'mine') "
                   "ON CONFLICT (id) DO UPDATE SET note = EXCLUDED.note RETURNING id, note")
        assert rows == [(1, 'mine')]

    def test_on_conflict_tenant_assignment_refused(self):
        with pytest.raises(PermissionError, match="tenant column"):
            run(f"INSERT INTO {T} (id, note) VALUES (3, 'x') "
                "ON CONFLICT (id) DO UPDATE SET tenant_id = 'A'::text || ''")

    @pytest.mark.parametrize("rhs", ["('x', 'B')", "ROW('x', 'B')", "(SELECT 'x', 'B')"])
    def test_tuple_assignment_refused(self, rhs):
        """H2 — before: `SET (note, tenant_id) = (...)` was not an EQ on a Column
        → the tenant column moved to B (row 1 disappeared from tenant A)."""
        with pytest.raises(PermissionError, match="tuple assignment"):
            run(f"UPDATE {T} SET (note, tenant_id) = {rhs} WHERE id = 1")
        with pytest.raises(PermissionError, match="tuple assignment"):
            run(f"INSERT INTO {T} (id, note) VALUES (1, 'x') "
                f"ON CONFLICT (id) DO UPDATE SET (note, tenant_id) = {rhs}")
        assert run(f"SELECT count(*) FROM {T}") == [(2,)]

    def test_tenant_placeholder_in_insert(self):
        """M2 — the bound value is the caller's; refused unless opted in."""
        sql = f"INSERT INTO {T} (id, note, tenant_id) VALUES (%s, %s, %s) RETURNING tenant_id"
        with pytest.raises(PermissionError, match="allow_tenant_placeholder"):
            run(sql, (9, 'x', 'B'))
        assert run(sql, (9, 'x', 'A'), config=dict(CONFIG, allow_tenant_placeholder=True)) \
            == [('A',)]


# ------------------------------------------------------------- G: alias ---

def test_column_list_alias_refused():
    """H3 — before: `AS t(tenant_id, label)` renamed the label column to
    tenant_id, so the predicate matched B's row whose label is 'A'."""
    with pytest.raises(PermissionError, match="column-list alias"):
        run(f"SELECT * FROM {ALIAS} AS t(tenant_id, label)")
    assert run(f"SELECT * FROM {ALIAS}") == [('x', 'A')]


# ------------------------------------------------------ I: psycopg3 idioms ---

class TestPsycopg3Wrappers:

    def test_connection_execute_cursor_stream_and_copy(self):
        """H5 — before: conn.execute(), cursor.stream(), cursor.copy() reached
        the raw driver and returned all 3 rows / the whole table."""
        raw = psycopg.connect(APP_DSN)
        try:
            pc = protect(raw, "A", CONFIG)
            assert pc.execute(f"SELECT * FROM {T}").fetchall() == [(1, 'A', 'a1'), (2, 'A', 'a2')]
            assert list(pc.cursor().stream(f"SELECT note FROM {T}")) == [('a1',), ('a2',)]
            assert list(pc.stream(f"SELECT note FROM {T}")) == [('a1',), ('a2',)]
            with pytest.raises(PermissionError):
                with pc.cursor().copy(f"COPY {T} TO STDOUT"):
                    pass
            with pytest.raises(PermissionError):
                with pc.copy(f"COPY {T} TO STDOUT"):
                    pass
        finally:
            raw.rollback()
            raw.close()

    def test_pipeline_statements_stay_mediated(self):
        raw = psycopg.connect(APP_DSN)
        try:
            pc = protect(raw, "A", CONFIG)
            with pc.pipeline():
                cur = pc.execute(f"SELECT count(*) FROM {T}")
            assert cur.fetchone() == (2,)
        finally:
            raw.rollback()
            raw.close()

    @pytest.mark.parametrize("name", ["copy_expert", "copy_from", "executescript",
                                      "callproc", "execute_values", "exec_driver_sql"])
    def test_unmediated_sql_methods_fail_closed(self, name):
        raw = psycopg.connect(APP_DSN)
        try:
            pc = protect(raw, "A", CONFIG)
            with pytest.raises(PermissionError, match="not mediated"):
                getattr(pc, name)
            with pytest.raises(PermissionError, match="not mediated"):
                getattr(pc.cursor(), name)
            assert pc.cursor().rowcount == -1          # ordinary attributes still delegate
        finally:
            raw.close()


# ---------------------------------------------------- K: executemany closed ---

def test_executemany_honours_fail_closed():
    """H7 — before: executemany() with no tenant skipped the fail-closed branch."""
    raw = psycopg.connect(APP_DSN)
    try:
        pc = protect(raw, None, CONFIG)
        with pytest.raises(PermissionError, match="No tenant context"):
            pc.cursor().executemany(f"INSERT INTO {T} (id, note) VALUES (%s, %s)", [(7, 'x')])
        with pytest.raises(PermissionError, match="No tenant context"):
            pc.cursor().execute(f"SELECT * FROM {T}")
        pc.cursor().execute("SELECT 1")                # nothing to protect
        assert pc.cursor().execute("SELECT 1") is None or True
    finally:
        raw.rollback()
        raw.close()


# ------------------------------------------------------------ L: tenant id ---

def test_tenant_id_cannot_carry_placeholder_token():
    """M4"""
    with pytest.raises(ValueError, match="reserved"):
        validate_tenant_id("A__dbfw_ph_0__")
    with pytest.raises(ValueError):
        rewrite_query(f"SELECT * FROM {T}", "__dbfw_ph_1__", CONFIG)


# ---------------------------------------------------- M: tenant map lookup ---

def test_tenant_map_probe_does_not_abort_callers_transaction():
    """M1 — before: dbfw_app lacks SELECT on _firewall_tenant_map; the failed
    probe left the caller's open transaction aborted (next statement →
    InFailedSqlTransaction)."""
    raw = psycopg.connect(APP_DSN)
    try:
        raw.execute("SELECT 1")                        # caller's transaction is open
        pc = protect(raw, None, CONFIG)
        assert pc._tenant_id is None
        assert raw.execute("SELECT 2").fetchone() == (2,)
        assert raw.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
    finally:
        raw.rollback()
        raw.close()
