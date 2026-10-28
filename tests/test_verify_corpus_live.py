"""
The PostgreSQL attack corpus (tests/attacks/postgresql.sql) against the Python
verify (hooks/verify.py), as packages/cli/test/attacks.test.mjs runs it
against `db-firewall verify`: for each attack its leak query, when it has one,
must show data tenant A must not see, and verify must fail the named check.
Safe patterns must pass. Both tools run the shared checks file, so both must
give the same answers on every case.

    DBFW_PG_DSN="host=localhost port=55432 dbname=dbfw_test user=postgres" pytest tests/test_verify_corpus_live.py
"""

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hooks import pg_checks, verify as pyverify  # noqa: E402
from middleware.db_firewall import DBEngine, load_config, run_migration  # noqa: E402
from middleware.db_firewall.db_context import sign_tenant  # noqa: E402

CORPUS = ROOT / "tests" / "attacks" / "postgresql.sql"
CLI = ROOT / "packages" / "cli" / "dist" / "cli.js"
SECRET = "b-secret"
KEY = bytes.fromhex("5a" * 32)
S, ROLE = "atk_py", "dbfw_atk_py"
# Pinned with packages/cli/test/attacks.test.mjs: change both with the corpus.
ATTACKS, PASSES = 91, 6
NO_ACTIVITY = ("REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC; REVOKE EXECUTE ON FUNCTION "
               "pg_catalog.pg_stat_get_activity(integer), pg_catalog.pg_stat_get_backend_activity(integer) FROM PUBLIC")
RESTORE = ("GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC; GRANT EXECUTE ON FUNCTION "
           "pg_catalog.pg_stat_get_activity(integer), pg_catalog.pg_stat_get_backend_activity(integer) TO PUBLIC")


def parse_corpus(text, variables):
    """The cases, placeholders filled in. Same grammar and the same refusals as
    parseCorpus() in packages/cli/test/attacks.test.mjs."""
    def fill(s):
        return re.sub(r"\{(S|ROLE|DB)\}", lambda m: variables[m.group(1)], s)
    cases, cur, part = [], None, None
    for n, line in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        def bad(why):
            raise ValueError(f"corpus line {n}: {why}: {line}")
        if re.match(r"^\s+--\s*@", line):
            bad("an indented directive")
        head = re.match(r"^-- @(attack|pass) (\S.*)$", line)
        if head:
            cur = {"kind": head.group(1), "name": head.group(2).strip(), "mode": "plain", "args": [], "min": 0,
                   "setup": [], "undo": [], "seen": set()}
            cases.append(cur)
            part = None
            continue
        if not re.match(r"^--\s*@", line):
            if part and not re.match(r"^-- -{4,}", line):
                cur[part].append(line)
            continue
        d = re.match(r"^-- @(check|mode|args|min|leak|setup|undo)(?: (\S.*))?$", line)
        if not d:
            bad("an unknown directive")
        if cur is None:
            bad("a directive before the first case")
        key, value = d.group(1), d.group(2) or ""
        if key in cur["seen"]:
            bad(f"a second @{key}")
        cur["seen"].add(key)
        if key in ("setup", "undo"):
            if value:
                bad(f"@{key} takes no value")
            part = key
            continue
        if part:
            bad(f"@{key} after @setup")
        if not value:
            bad(f"@{key} needs a value")
        if key == "mode" and value not in ("plain", "strict"):
            bad("@mode is plain or strict")
        if key == "min" and not re.match(r"^1\d$", value):
            bad("@min is a major version")
        if key == "check" and cur["kind"] == "pass":
            bad("a @pass case has no @check")
        if key == "args":
            cur["args"] = fill(value).split()
        elif key == "min":
            cur["min"] = int(value)
        else:
            cur[key] = fill(value.strip())
    for c in cases:
        c["setup"], c["undo"] = fill("\n".join(c["setup"])).strip(), fill("\n".join(c["undo"])).strip()
        del c["seen"]
    return cases


def test_parser_rejects_mistakes():
    v = {"S": "s", "ROLE": "r", "DB": "d"}
    ok = "-- @attack x\n-- @check -: role\n-- @setup\nSELECT {S};\n-- @undo\nSELECT 2;\n"
    for text in (ok, ok.replace("\n", "\r\n")):
        [c] = parse_corpus(text, v)
        assert (c["check"], c["setup"], c["undo"]) == ("-: role", "SELECT s;", "SELECT 2;")
    for bad in ("-- @mod strict", "-- @min15", "  -- @mode strict", "-- @mode Strict", "-- @check -: x", "-- @min 1x"):
        with pytest.raises(ValueError, match="corpus line"):
            parse_corpus(ok.replace("-- @setup", f"{bad}\n-- @setup"), v)


def test_shared_checks_file_parses():
    checks = pg_checks.CHECKS()
    assert checks.excluded[0] == "_firewall_*"
    names = [c.name for c in checks.checks]
    assert len(names) == len(set(names)) and "role" in names
    for q in ("scan_tables", "strict_readable", "bypass_functions", "table_privileges"):
        assert q in checks.queries
    with pytest.raises(ValueError, match="unknown line"):
        pg_checks.parse_checks("-- @qery x\nSELECT 1")
    assert pg_checks._pyformat("SELECT $2, $1 LIKE 'a%'", ("x", "y")) == ("SELECT %s, %s LIKE 'a%%'", ("y", "x"))


DSN = os.environ.get("DBFW_PG_DSN")
live = pytest.mark.skipif(not DSN, reason="DBFW_PG_DSN not set; skipping live PostgreSQL tests")
CASES = parse_corpus(CORPUS.read_text(), {"S": S, "ROLE": ROLE, "DB": "{DB}"})


def test_corpus_counts():
    assert sum(c["kind"] == "attack" for c in CASES) == ATTACKS
    assert sum(c["kind"] == "pass" for c in CASES) == PASSES
    assert len({c["name"] for c in CASES}) == len(CASES)


def _admin(sql):
    import psycopg
    with psycopg.connect(DSN, autocommit=True) as c:
        db = c.execute("SELECT current_database()").fetchone()[0]
        c.execute(sql.replace("{DB}", '"' + db.replace('"', '""') + '"'))


def _app():
    import psycopg
    return psycopg.connect(f"{DSN} user={ROLE}", autocommit=True)


@pytest.fixture(scope="module")
def fixture():
    import psycopg
    with psycopg.connect(DSN, autocommit=True) as c:
        major = c.execute("SHOW server_version_num").fetchone()[0]
        c.execute(f"DROP SCHEMA IF EXISTS {S} CASCADE")
        c.execute(f"DROP SCHEMA IF EXISTS {S}_other CASCADE")
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') "
                  f"THEN CREATE ROLE {ROLE} LOGIN; END IF; END $$")
        c.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")     # PostgreSQL 14 grants it
        c.execute(f"CREATE SCHEMA {S}; GRANT USAGE ON SCHEMA {S} TO {ROLE}")
        c.execute(f"CREATE TABLE {S}.docs (id serial, tenant_id text, body text)")
        c.execute(f"INSERT INTO {S}.docs (tenant_id, body) VALUES ('A', 'a-secret'), ('B', '{SECRET}')")
        c.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {S}.docs TO {ROLE}; "
                  f"GRANT USAGE ON SEQUENCE {S}.docs_id_seq TO {ROLE}")
        c.execute(NO_ACTIVITY)
    cfg = load_config()
    cfg["engines"]["postgresql"].update(schema=S, tenant_context="signed")
    with psycopg.connect(DSN) as c:
        run_migration(c, DBEngine.POSTGRESQL, cfg)
    yield int(major) // 10000
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(f"DROP SCHEMA IF EXISTS {S} CASCADE")
        c.execute(f"DROP SCHEMA IF EXISTS {S}_other CASCADE")
        c.execute(RESTORE)


def _node(mode="plain", args=()):
    """The same verify through the Node CLI: its checks, or None when it is not built."""
    import json as _json
    import shutil
    import subprocess
    if not (CLI.exists() and shutil.which("node")):
        if os.environ.get("DBFW_REQUIRE_PARITY"):
            pytest.fail("DBFW_REQUIRE_PARITY set but packages/cli is not built (npm ci && npm run build)")
        return None
    from psycopg.conninfo import conninfo_to_dict
    d = conninfo_to_dict(DSN)
    url = f"postgres://{ROLE}@{d.get('host', 'localhost')}:{d.get('port', 5432)}/{d['dbname']}"
    r = subprocess.run(["node", str(CLI), "verify", "--url", url, "--schema", S, "--tenant", "A", "--json",
                        *(["--strict"] if mode == "strict" else []), *args],
                       capture_output=True, text=True, env={**os.environ, "DB_FIREWALL_TENANT_KEY": KEY.hex()})
    return _json.loads(r.stdout)["checks"]


def _verify(mode="plain", args=()):
    allow, query_text, rest = [], False, list(args)
    while rest:                         # the corpus uses only these two flags
        flag = rest.pop(0)
        if flag == "--allow-global":
            allow.append(rest.pop(0))
        elif flag == "--allow-query-text":
            query_text = True
        else:
            raise ValueError(f"unknown verify argument {flag}")
    with _app() as conn:
        result = pyverify.verify(conn, "A", KEY, [S], strict=mode == "strict", allow_global=allow,
                                 allow_query_text=query_text)
    failed = [f"{c['table']}: {c['check']}" for c in result["checks"] if c["ok"] is False]
    node = _node(mode, args)
    if node is not None:                # both tools: the same checks, results and details
        assert result["checks"] == node
    return pyverify.exit_code(result), failed


def _leak(sql):
    """The leak query as the app, tenant A signed, rolled back: its rows and notices."""
    notices = []
    with _app() as conn:
        conn.add_notice_handler(lambda d: notices.append(d.message_primary))
        cur = conn.cursor()
        cur.execute("BEGIN")
        try:
            nonce = cur.execute("SELECT public._firewall_nonce()").fetchone()[0]
            cur.execute("SELECT set_config('app.current_tenant', 'A', true), set_config('app.tenant_sig', %s, true)",
                        (sign_tenant(KEY, nonce, "A"),))
            rows = []
            # One statement at a time: psycopg sends a parameterless multi-statement
            # query as one, but returns only the last result.
            cur.execute(sql)
            while True:
                if cur.description:
                    rows += cur.fetchall()
                if not cur.nextset():
                    break
            return repr(rows) + "\n" + "\n".join(notices)
        finally:
            cur.execute("ROLLBACK")


@live
@pytest.mark.parametrize("mode", ["plain", "strict"])
def test_fixture_passes_before(fixture, mode):
    code, failed = _verify(mode)
    assert code == 0, failed


@live
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_case(fixture, case):
    if fixture < case["min"]:
        pytest.skip(f"needs PostgreSQL {case['min']}")
    _admin(case["setup"])
    try:
        if case.get("leak"):
            assert SECRET in _leak(case["leak"]), f"the attack does not leak on PostgreSQL {fixture}"
        code, failed = _verify(case["mode"], case["args"])
        if case["kind"] == "pass":
            assert code == 0, failed
        else:
            assert code == 1, failed
            assert case["check"] in failed, failed
    finally:
        _admin(case["undo"])


@live
@pytest.mark.parametrize("mode", ["plain", "strict"])
def test_fixture_passes_after(fixture, mode):
    code, failed = _verify(mode)
    assert code == 0, failed


@live
def test_cli_exit_codes(fixture, capsys, monkeypatch):
    import json as _json
    from psycopg.conninfo import conninfo_to_dict
    d = conninfo_to_dict(DSN)
    url = f"postgresql://{ROLE}@{d.get('host', 'localhost')}:{d.get('port', 5432)}/{d['dbname']}"
    assert pyverify.main(["--dsn", url, "--tenant", "A", "--schema", S, "--json"]) == 0
    out = _json.loads(capsys.readouterr().out)
    assert {c["check"] for c in out["checks"]} >= {"role", "tenant sees only its rows", "no RLS-bypassing views or functions"}
    assert [t["table"] for t in out["tables"]] == ["docs"]
    assert pyverify.main(["--dsn", url, "--tenant", "A", "--schema", S]) == 0
    assert "All checks passed." in capsys.readouterr().out
    assert pyverify.main(["--dsn", url, "--tenant", "NO_SUCH", "--schema", S]) == 1      # no rows: proves nothing
    assert pyverify.main(["--dsn", url, "--tenant", "A", "--allow-global", "x.y"]) == 2   # needs --strict
    monkeypatch.delenv("DB_FIREWALL_TENANT_KEY")
    assert pyverify.main(["--dsn", url, "--tenant", "A"]) == 2                            # no key


@live
@pytest.mark.parametrize("strict", [False, True], ids=["plain", "strict"])
def test_same_answers_as_the_node_cli(fixture, strict):
    """On a database with several failures, the Python verify and
    `db-firewall verify` give the same checks, results and details, in order."""
    import json as _json
    import shutil
    import subprocess
    if not (CLI.exists() and shutil.which("node")):
        if os.environ.get("DBFW_REQUIRE_PARITY"):
            pytest.fail("DBFW_REQUIRE_PARITY set but packages/cli is not built (npm ci && npm run build)")
        pytest.skip("packages/cli not built")
    from psycopg.conninfo import conninfo_to_dict
    d = conninfo_to_dict(DSN)
    url = f"postgres://{ROLE}@{d.get('host', 'localhost')}:{d.get('port', 5432)}/{d['dbname']}"
    _admin(f"""CREATE TABLE {S}.late (id int, tenant_id text); INSERT INTO {S}.late VALUES (1, 'B');
               CREATE TABLE {S}.notes (x text); CREATE VIEW {S}.v AS SELECT * FROM {S}.docs;
               GRANT SELECT ON {S}.late, {S}.notes, {S}.v TO {ROLE}""")
    try:
        args = ["--strict"] if strict else []
        r = subprocess.run(["node", str(CLI), "verify", "--url", url, "--schema", S, "--tenant", "A", "--json", *args],
                           capture_output=True, text=True, env={**os.environ, "DB_FIREWALL_TENANT_KEY": KEY.hex()})
        node = _json.loads(r.stdout)
        with _app() as conn:
            py = pyverify.verify(conn, "A", KEY, [S], strict=strict)
        assert r.returncode == pyverify.exit_code(py) == 1
        assert py["checks"] == node["checks"]
        assert [t["table"] for t in py["tables"]] == [t["table"] for t in node["tables"]]
        assert py["excluded"] == node["excluded"]
    finally:
        _admin(f"DROP VIEW {S}.v; DROP TABLE {S}.late, {S}.notes")


# ---------------------------------------------------------------- fail closed
class _Cur:
    """A cursor that returns one row, or raises."""
    def __init__(self, row):
        self.row, self.sql = row, []

    def execute(self, sql, params=None):
        self.sql.append(sql)
        if isinstance(self.row, Exception):
            raise self.row

    def fetchone(self):
        return self.row


def test_checks_fail_closed():
    c = pg_checks.GlobalCheck("x", False, "SELECT 1")
    assert pyverify._file_check(_Cur((True, "d")), c)["ok"] is True
    for row in [(None, "d"), (False, "d"), ("t", "d"), RuntimeError("boom")]:
        assert pyverify._file_check(_Cur(row), c)["ok"] is False, row
    assert pyverify._file_check(_Cur(RuntimeError("boom")), c._replace(info=True))["ok"] is True
    assert pyverify._guard("x", lambda: 1 / 0)["ok"] is False
    assert pyverify.exit_code({"checks": [{"ok": True}, {"ok": None}]}) == 3
    assert pyverify.exit_code({"checks": [{"ok": None}, {"ok": False}]}) == 1
    assert pyverify.exit_code({"checks": [{"ok": True}]}) == 0


def test_allowlist_kinds():
    assert pyverify._allowed_fn(["app.f(*)"], "app.f(text)")
    assert not pyverify._allowed_fn(["app.*"], "app.f(text)")          # a relation entry never clears a function
    assert not pyverify._allowed_rel(["app.f(*)"], "app.f(1)")         # a function entry never clears a relation
    assert pyverify._allowed_rel(["app.[!x]*"], "app.countries")
    assert not pyverify._allowed_rel(["app.[z-a]"], "app.b")           # a reversed range matches nothing
    with pytest.raises(ValueError, match="parameter"):
        pg_checks._pyformat("SELECT 1", ("unused",))                    # a parameter the query does not take


@live
def test_inconclusive_results_are_not_a_pass(fixture):
    """A row check that errors, a table readable only after SET ROLE, and a
    write probe refused by something other than RLS: inconclusive (exit 3)."""
    _admin(f"""CREATE POLICY boom ON {S}.docs AS RESTRICTIVE USING (1 / 0 = 1);""")
    try:
        with _app() as conn:
            r = pyverify.verify(conn, "A", KEY, [S])
        rows = [c for c in r["checks"] if c["check"] == "row checks"]
        assert rows and rows[0]["ok"] is None and "division by zero" in rows[0]["detail"]
        assert pyverify.exit_code(r) != 0              # inconclusive, and "tenant has rows" fails
    finally:
        _admin(f"DROP POLICY boom ON {S}.docs")
    _admin(f"""CREATE FUNCTION {S}.no() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'no'; END $f$;
               CREATE TRIGGER no BEFORE INSERT ON {S}.docs FOR EACH ROW EXECUTE FUNCTION {S}.no();""")
    try:
        with _app() as conn:
            r = pyverify.verify(conn, "A", KEY, [S], write_probe=True)
        probe = [c for c in r["checks"] if c["check"] == "cross-tenant insert refused"]
        assert probe and probe[0]["ok"] is None and pyverify.exit_code(r) == 3
    finally:
        _admin(f"DROP TRIGGER no ON {S}.docs; DROP FUNCTION {S}.no()")
    _admin(f"""CREATE ROLE {ROLE}_rd NOLOGIN; GRANT SELECT ON {S}.docs TO {ROLE}_rd;
               REVOKE SELECT ON {S}.docs FROM {ROLE}; ALTER ROLE {ROLE} NOINHERIT; GRANT {ROLE}_rd TO {ROLE};""")
    try:
        with _app() as conn:
            r = pyverify.verify(conn, "A", KEY, [S])
        rows = [c for c in r["checks"] if c["check"] == "row checks"]
        assert rows and rows[0]["ok"] is None and "SET ROLE" in rows[0]["detail"]
    finally:
        _admin(f"""ALTER ROLE {ROLE} INHERIT; REVOKE {ROLE}_rd FROM {ROLE}; GRANT SELECT ON {S}.docs TO {ROLE};
                   REVOKE ALL ON {S}.docs FROM {ROLE}_rd; DROP ROLE {ROLE}_rd;""")


@live
def test_verify_switches_the_connection_to_autocommit(fixture):
    """The search_path pin must outlive the row checks' ROLLBACK."""
    import psycopg
    with psycopg.connect(f"{DSN} user={ROLE}") as conn:
        assert pyverify.exit_code(pyverify.verify(conn, "A", KEY, [S])) == 0
        assert conn.autocommit
