"""
DB Firewall verify for PostgreSQL: connect as the app's own role and test the
isolation, not just the policies' presence. The same checks as
`npx db-firewall verify` (packages/cli/src/verify.ts): both run the shared
checks file (checks/postgresql.sql), and the attack corpus
(tests/attacks/postgresql.sql) runs against both.

Read-only by default: every row check runs in a transaction that is rolled
back, and nothing is written unless --write-probe is given.

Usage:
    DB_FIREWALL_TENANT_KEY=<hex> python -m hooks.verify --dsn "$APP_URL" --tenant acme
    python -m hooks.verify --dsn "$APP_URL" --tenant acme --strict --allow-global public.countries

Exit codes: 0 all checks passed; 1 a check failed; 2 usage or connection
error; 3 no failure, but a check was inconclusive (not a pass).
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hooks import pg_checks  # noqa: E402
from hooks.scan_engines import _pg_firewall_objects, _scan_postgres  # noqa: E402
from middleware.db_firewall.db_context import TENANT_KEY_ENV, sign_tenant, tenant_key  # noqa: E402

RLS_VIOLATION = "42501"           # insufficient_privilege: what an RLS refusal raises
MARK = "__dbfw_verify_other__"


def ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _msg(err: Exception) -> str:
    return (str(err).strip().splitlines() or ["error"])[0]


def _check(table, check, ok, detail):
    return {"table": table, "check": check, "ok": ok, "detail": detail}


def _guard(name, fn):
    """A global check; a query error fails it (a precondition that cannot be checked is not met)."""
    try:
        ok, detail = fn()
        return _check("-", name, ok, detail)
    except Exception as e:
        return _check("-", name, False, f"could not check (is the migration installed?): {_msg(e)}")


def _info(name, fn):
    """An information line: always ok, also when its query fails."""
    try:
        _, detail = fn()
        return _check("-", name, True, detail)
    except Exception as e:
        return _check("-", name, True, f"could not read: {_msg(e)}")


def _file_check(cur, c: "pg_checks.GlobalCheck"):
    def run():
        pg_checks.run(cur, c.sql)
        ok, detail = cur.fetchone()
        return ok is True, str(detail)
    return _info(c.name, run) if c.info else _guard(c.name, run)


def _glob(pattern: str, name: str) -> bool:
    try:
        return fnmatch.fnmatchcase(name, pattern)
    except re.error:                      # a reversed range ([z-a]): no match
        return False


# --allow-global: an entry with "(" names functions with their arguments
# (schema.name(argtypes), as verify prints them); one without names relations.
def _allowed_rel(globs, name):
    return any("(" not in g and _glob(g, name) for g in globs)


def _allowed_fn(globs, sig):
    return any("(" in g and _glob(g, sig) for g in globs)


def _listed(names):
    return ", ".join(names[:25]) + (f", and {len(names) - 25} more" if len(names) > 25 else "")


def role_checks(cur) -> List[dict]:
    """The @check and @info blocks of the checks file, in order (the "strict:"
    ones run only with --strict), then the firewall functions."""
    out = [_file_check(cur, c) for c in pg_checks.CHECKS().checks if not c.name.startswith("strict:")]

    def objects():
        why = _pg_firewall_objects(cur)
        return (why is None, why or "match the migration, one owner")
    out.append(_guard("firewall functions unchanged", objects))
    return out


def _in_tx(cur, ctx, fn):
    """Run fn in a transaction with that context (None: no tenant; (tenant,
    None): unsigned; (tenant, key): signed), and always roll back."""
    cur.execute("BEGIN")
    try:
        if ctx and ctx[1] is not None:
            nonce = pg_checks.query(cur, "nonce")[0]["n"]
            cur.execute("SELECT set_config('app.current_tenant', %s, true), set_config('app.tenant_sig', %s, true)",
                        (ctx[0], sign_tenant(ctx[1], nonce, ctx[0])))
        elif ctx:
            cur.execute("SELECT set_config('app.current_tenant', %s, true)", (ctx[0],))
        return fn()
    finally:
        cur.execute("ROLLBACK")


def _summary(t) -> str:
    if t.get("tenant_context") == "plain":
        return "plain tenant context: SQL the app runs can switch tenants (re-run migrate)"
    parts = []
    if not t["rls_enabled"]:
        parts.append("RLS off")
    elif not t["rls_forced"]:
        parts.append("RLS not forced")
    if t["missing_policies"]:
        parts.append("missing " + ",".join(t["missing_policies"]))
    if t["altered_policies"]:
        parts.append("altered " + ",".join(t["altered_policies"]))
    if t["policy_mode"] == "permissive" and t["extra_permissive_policies"]:
        parts.append("extra permissive " + ",".join(t["extra_permissive_policies"]))
    if t["predicate_check"] != "ok":
        parts.append(t["predicate_check"])
    return "; ".join(parts) or "not protected"


def _write_probe(cur, label, name, column, signed):
    try:
        _in_tx(cur, signed, lambda: cur.execute(f"INSERT INTO {name} ({ident(column)}) VALUES (%s)", (MARK,)))
        return _check(label, "cross-tenant insert refused", False, "a row for another tenant was accepted (rolled back)")
    except Exception as e:
        code = getattr(e, "sqlstate", None) or getattr(e, "pgcode", None)
        if code == RLS_VIOLATION and re.search(r"row-level security", _msg(e), re.I):
            return _check(label, "cross-tenant insert refused", True, "refused by RLS")
        return _check(label, "cross-tenant insert refused", None, f"inconclusive: {_msg(e)}")


def _bypass_objects(cur, column, allow):
    def run():
        views = pg_checks.query(cur, "bypass_views", column)
        foreign = pg_checks.query(cur, "bypass_foreign", column)
        rules = pg_checks.query(cur, "bypass_rules")
        fns = pg_checks.query(cur, "bypass_functions")
        # --allow-global clears only a function (named with its arguments) or a
        # foreign table without the tenant column; never a view or a rule.
        items = ([f"{'materialized view' if v['matview'] else 'view'} {v['name']} (owner {v['owner']})" for v in views]
                 + [f"foreign table {f['name']}" for f in foreign if f["tenant"] or not _allowed_rel(allow, f["name"])]
                 + [f"rule {r['name']} (use a trigger)" for r in rules]
                 + [f"{'LEAKPROOF' if f['leakproof'] else 'SECURITY DEFINER'} function {f['name']} (owner {f['owner']})"
                    for f in fns if not _allowed_fn(allow, f["name"])])
        return (not items, "the role can read through: " + "; ".join(items) if items else "none found")
    return _guard("no RLS-bypassing views or functions", run)


def _query_text(cur, strict):
    def run():
        can = pg_checks.query(cur, "query_text")[0]["can"]
        return (not can,
                "yes: SQL one tenant runs can read the query text of another tenant's session (pg_stat_activity, "
                "pg_stat_statements), literal values included (send values as parameters; migrate --harden revokes it, "
                "or --allow-query-text where only the provider can)" if can
                else "no (pg_stat_activity and pg_stat_statements revoked)")
    return (_guard("strict: cannot read other sessions' SQL", run) if strict
            else _info("reads other sessions' SQL (info)", run))


def _strict_checks(cur, protected, allow, allow_query_text):
    def readable():
        rows = pg_checks.query(cur, "strict_readable", json.dumps([[t["schema"], t["table"]] for t in protected]))
        stats = re.compile(r"\.pg_stat_statements(_info)?$")
        bad = sorted(r["name"] for r in rows
                     if not _allowed_rel(allow, r["name"])
                     and not (allow_query_text and stats.search(r["name"]))
                     and not (r["safe"] or (r["invoker"] and not r["broken"]
                                            and all(_allowed_rel(allow, b) for b in r["blockers"]))))
        return (not bad, f"readable but not protected tenant data: {_listed(bad)} "
                         "(protect them, revoke, or --allow-global schema.name)" if bad
                else "everything readable is protected tenant data or allowlisted")

    def definer():
        bad = [r["sig"] for r in pg_checks.query(cur, "strict_definer") if not _allowed_fn(allow, r["sig"])]
        return (not bad, f"runs as its owner: {_listed(bad)} (drop it or make it SECURITY INVOKER, "
                         "or --allow-global 'schema.name(args)')" if bad
                else "none outside the firewall's own (or allowlisted)")

    out = [_guard("strict: only tenant data readable", readable)]
    out += [_file_check(cur, c) for c in pg_checks.CHECKS().checks if c.name.startswith("strict:")]
    out += [_guard("strict: no SECURITY DEFINER functions", definer), _query_text(cur, not allow_query_text)]
    return out


def _other_schemas(cur, schemas, column):
    def run():
        names = [r["name"] for r in pg_checks.query(cur, "other_schemas", list(schemas), column)]
        return (not names, f"not checked, readable: {', '.join(names)} (add --schema)" if names else "none readable")
    return _guard("no tenant tables in other schemas", run)


def verify(connection, tenant: str, key: bytes, schemas: Optional[List[str]] = None, column: str = "tenant_id",
           exclude: Optional[List[str]] = None, write_probe: bool = False, strict: bool = False,
           allow_global: Optional[List[str]] = None, allow_query_text: bool = False) -> dict:
    """{checks, tables, excluded}, as `db-firewall verify --json` prints them.
    connection: the app role's, in autocommit mode."""
    schemas = list(schemas or ["public"])
    exclude = pg_checks.CHECKS().excluded if exclude is None else list(exclude)
    allow = list(allow_global or [])
    cur = connection.cursor()
    # Every check runs with search_path = pg_catalog, pg_temp: a planted "="
    # must not make "tenant sees only its rows" count another tenant's rows as own.
    cur.execute("SELECT current_setting('search_path'), set_config('search_path', 'pg_catalog, pg_temp', false)")
    old_path = cur.fetchone()[0]
    try:
        checks = role_checks(cur)
        tables, excluded = [], []
        for schema in schemas:
            for table, report in _scan_postgres(cur, column, [], {"schema": schema, "tenant_context": "signed"}).items():
                if any(_glob(p, table) for p in exclude):
                    excluded.append(f"{schema}.{table}")
                else:
                    tables.append(report)
        if not tables:
            checks.append(_check("-", "tables found", False,
                                 f"no table with column {column} in {', '.join(schemas)} (wrong --column or --schema?)"))
        signed = (tenant, key)
        own_rows = 0
        for t in tables:
            label, name = f"{t['schema']}.{t['table']}", f"{ident(t['schema'])}.{ident(t['table'])}"
            priv = pg_checks.query(cur, "table_privileges", name, column)[0]
            checks.append(_check(label, "role does not own the table", not priv["owns"],
                                 f"owned by {t['owner']}, which this role can act as: it can disable RLS" if priv["owns"]
                                 else f"owned by {t['owner']}"))
            checks.append(_check(label, "no TRUNCATE", not priv["truncate"],
                                 "TRUNCATE is granted and RLS does not apply to it" if priv["truncate"] else "not granted"))
            checks.append(_check(label, "policies", t["protected"],
                                 f"{t['policy_mode']} policies in place" if t["protected"] else _summary(t)))
            if not priv["can_select"]:
                checks.append(_check(label, "row checks", None, "readable only after SET ROLE to another role: run verify as that role")
                              if priv["some_role_selects"]
                              else _check(label, "row checks", True, f"no role it can use can SELECT {column}: no direct reads"))
                continue

            def count():
                cur.execute(f"SELECT count(*) FROM {name}")
                return int(cur.fetchone()[0])
            try:
                none = _in_tx(cur, None, count)
                checks.append(_check(label, "no tenant sees nothing", none == 0, f"{none} rows visible"))
                unsigned = _in_tx(cur, (tenant, None), count)
                checks.append(_check(label, "unsigned tenant sees nothing", unsigned == 0,
                                     f"{unsigned} rows visible: SQL the app runs can switch tenants" if unsigned else "0 rows"))

                def split():
                    cur.execute(f"SELECT count(*) FILTER (WHERE {ident(column)} IS DISTINCT FROM %s), "
                                f"count(*) FILTER (WHERE {ident(column)} = %s) FROM {name}", (tenant, tenant))
                    foreign, own = cur.fetchone()
                    return int(foreign), int(own)
                foreign, own = _in_tx(cur, signed, split)
                own_rows += own
                checks.append(_check(label, "tenant sees only its rows", foreign == 0,
                                     f"{own} own rows, {foreign} rows of another tenant visible"))
            except Exception as e:
                checks.append(_check(label, "row checks", None, f"query failed: {_msg(e)}"))
                continue
            if write_probe:
                checks.append(_write_probe(cur, label, name, column, signed))
        if tables and own_rows == 0:
            checks.append(_check("-", "tenant has rows", False,
                                 f"tenant {tenant} sees no rows in any table, so the row checks prove nothing: use a tenant "
                                 f"that has data, and check that {TENANT_KEY_ENV} is the database's key (db-firewall key)"))
        checks.append(_bypass_objects(cur, column, allow))
        checks.append(_other_schemas(cur, schemas, column))
        if strict:
            checks += _strict_checks(cur, [t for t in tables if t["protected"]], allow, allow_query_text)
        else:
            checks.append(_query_text(cur, False))
        return {"checks": checks, "tables": tables, "excluded": excluded}
    finally:
        cur.execute("SELECT set_config('search_path', %s, false)", (old_path,))
        cur.close()


def checks_text(checks) -> str:
    mark = {True: "OK  ", False: "FAIL", None: "--  "}
    return "".join(f"{mark[c['ok']]}  {c['table']:<24} {c['check']:<36} {c['detail']}\n" for c in checks)


def exit_code(result) -> int:
    failed = sum(1 for c in result["checks"] if c["ok"] is False)
    unsure = sum(1 for c in result["checks"] if c["ok"] is None)
    return 1 if failed else 3 if unsure else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m hooks.verify",
                                description="DB Firewall verify: test tenant isolation as the app's own role (PostgreSQL)")
    p.add_argument("--dsn", default=os.environ.get("DATABASE_URL"), help="the app role's connection string")
    p.add_argument("--tenant", required=True, help="a tenant id that has rows in your data")
    p.add_argument("--schema", action="append", help="schema to check (repeatable; default public)")
    p.add_argument("--column", default="tenant_id", help="the tenant column")
    p.add_argument("--exclude", action="append", help="skip tables matching this glob (repeatable; replaces the defaults)")
    p.add_argument("--write-probe", action="store_true", help="also try a cross-tenant insert (rolled back)")
    p.add_argument("--strict", action="store_true", help="fail on anything readable that is not protected tenant data")
    p.add_argument("--allow-global", action="append", help="--strict: schema.name (or schema.name(argtypes)) shared by all tenants")
    p.add_argument("--allow-query-text", action="store_true", help="--strict: accept that the role reads other sessions' SQL")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if not a.dsn:
        print("verify: --dsn (or DATABASE_URL) is required", file=sys.stderr)
        return 2
    if (a.allow_global or a.allow_query_text) and not a.strict:
        print("verify: --allow-global and --allow-query-text need --strict", file=sys.stderr)
        return 2
    try:
        key = tenant_key()
    except RuntimeError as e:
        print(f"verify: {e}", file=sys.stderr)
        return 2
    if key is None:
        print(f"verify: set {TENANT_KEY_ENV} to the key the app signs with (db-firewall key prints it)", file=sys.stderr)
        return 2
    try:
        from hooks.scanner import get_connection
        conn = get_connection(a.dsn)
        conn.autocommit = True
    except Exception as e:
        print(f"verify: cannot connect: {_msg(e)}", file=sys.stderr)
        return 2
    try:
        result = verify(conn, a.tenant, key, a.schema, a.column, a.exclude, a.write_probe, a.strict,
                        a.allow_global, a.allow_query_text)
    finally:
        conn.close()
    code = exit_code(result)
    if a.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        failed = sum(1 for c in result["checks"] if c["ok"] is False)
        unsure = sum(1 for c in result["checks"] if c["ok"] is None)
        skipped = f"Skipped (excluded): {', '.join(result['excluded'])}\n" if result["excluded"] else ""
        tail = (f"\n{failed} check(s) FAILED{f', {unsure} inconclusive' if unsure else ''}.\n" if failed
                else f"\nNo failures, but {unsure} check(s) inconclusive: not a pass.\n" if unsure
                else "\nAll checks passed.\n")
        sys.stdout.write(checks_text(result["checks"]) + skipped + tail)
    return code


if __name__ == "__main__":
    sys.exit(main())
