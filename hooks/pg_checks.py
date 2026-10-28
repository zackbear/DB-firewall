"""
The shared PostgreSQL checks (checks/postgresql.sql): `db-firewall scan` and
`db-firewall verify` (packages/cli) run the same file, so the Python and
TypeScript tools find the same things. Same grammar as packages/cli/src/checks.ts.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, NamedTuple

CHECKS_FILE = Path(__file__).resolve().parents[1] / "checks" / "postgresql.sql"


class GlobalCheck(NamedTuple):
    name: str
    info: bool
    sql: str


class Checks(NamedTuple):
    excluded: List[str]               # the tables the migration skips
    checks: List[GlobalCheck]         # @check and @info blocks, in file order
    queries: Dict[str, str]


def parse_checks(text: str) -> Checks:
    """"-- @excluded", "-- @check", "-- @info" and "-- @query" lines start a
    block, which runs to the next "-- @" line."""
    excluded, checks, queries = [], [], {}
    cur = None

    def flush():
        if cur is None:
            return
        kind, name, lines = cur
        sql = "\n".join(lines).strip()
        if not sql:
            raise ValueError(f"checks: {name} has no SQL")
        if kind == "query":
            if name in queries:
                raise ValueError(f"checks: a second @query {name}")
            queries[name] = sql
        else:
            if any(c.name == name for c in checks):
                raise ValueError(f"checks: a second check {name}")
            checks.append(GlobalCheck(name, kind == "info", sql))

    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.startswith("-- @"):
            # Comment lines stay out of the SQL: a "$1" in one is no parameter.
            if cur is not None and not line.lstrip().startswith("--"):
                cur[2].append(line)
            continue
        m = re.match(r"^-- @(excluded|check|info|query) (\S.*)$", line)
        if not m:
            raise ValueError(f"checks: unknown line {line}")
        flush()
        cur = None
        if m.group(1) == "excluded":
            excluded.extend(m.group(2).split())
        else:
            cur = (m.group(1), m.group(2).strip(), [])
    flush()
    return Checks(excluded, checks, queries)


@lru_cache(maxsize=1)
def CHECKS() -> Checks:
    return parse_checks(CHECKS_FILE.read_text(encoding="utf-8"))


def _pyformat(sql: str, params) -> tuple:
    """$1, $2 ... to the DB-API "%s" style (psycopg 3 and psycopg2), in the
    order they appear; a literal "%" doubles."""
    order = []

    def ref(m):
        order.append(int(m.group(1)) - 1)
        return "%s"
    text = re.sub(r"\$(\d+)", ref, sql.replace("%", "%%"))
    if set(order) != set(range(len(params))):     # as PostgreSQL: a missing or unused parameter fails
        raise ValueError(f"checks: the query takes ${sorted(set(order))} but got {len(params)} parameter(s)")
    return text, tuple(params[i] for i in order)


def run(cursor, sql: str, *params):
    """Run a block of the file with its $n parameters; returns the cursor."""
    text, args = _pyformat(sql, params)
    cursor.execute(text, args)          # always with params: "%%" is read as "%"
    return cursor


def query(cursor, name: str, *params):
    """Run @query <name>; returns its rows as dicts."""
    sql = CHECKS().queries.get(name)
    if sql is None:
        raise KeyError(f"checks: no @query {name}")
    run(cursor, sql, *params)
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]
