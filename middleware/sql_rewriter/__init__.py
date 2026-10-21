"""
DB Firewall — sqlglot AST rewriter
==================================
Adds ``<qualifier>.<tenant_col> = '<tenant>'`` to every reference of a
protected table in a statement, or raises PermissionError when the statement
cannot be proven scoped (fail closed).

Entry point: :func:`rewrite`. Placement rules:

* FROM / JOIN sources → WHERE of the nearest enclosing SELECT (or UPDATE/DELETE).
* The null-supplying side of an outer join (right side of LEFT JOIN, left side
  of RIGHT JOIN) → that join's ON clause, which keeps the outer-join semantics.
  FULL JOIN sides and joins without ON (USING / NATURAL) fall back to WHERE,
  which is always safe (it can only drop rows).
* INSERT: the tenant column is appended to the column list and stamped into
  every VALUES tuple / SELECT branch; a conflicting literal is rejected and a
  parameter placeholder is left to the driver.
* CTE bodies, derived tables, subqueries and every set-operation branch are
  scoped independently; CTE names are never treated as tables.

Every statement goes through :func:`rewrite` (there is no regex pre-filter):
only SELECT / set operations / INSERT / UPDATE / DELETE (optionally WITH-
wrapped or parenthesised) are rewritten; transaction control and SET/RESET of
harmless settings pass through; everything else is refused.
"""

import re  # noqa: F401  (re-exported for callers that used sql_rewriter.re)
from typing import Callable, Optional

try:
    import sqlglot
    from sqlglot import exp
    from sqlglot.errors import SqlglotError
except ImportError:          # pragma: no cover - exercised only without sqlglot
    sqlglot = None
    exp = None
    SqlglotError = Exception

from . import lexing, astutil, writes
from .lexing import (DIALECTS, INSTALL_HINT, _KEYWORD_TABLES, _NO_TENANT_MSG, _PH_RE,
                     _mask_placeholders, _reject, passthrough, strip_sql)
from .astutil import _DENIED, _and_into, _cte_names_visible, _owner, _placement, _qualifier
from .writes import _OP_OF, _check_assignments, _check_set_config, _stamp_insert

# Re-export every helper name, so sql_rewriter.X keeps working for db_firewall
# (blank_literals, strip_sql, _PH_PREFIX, ...) and the tests.
for _mod in (lexing, astutil, writes):
    for _name, _value in vars(_mod).items():
        if not _name.startswith("__"):
            globals().setdefault(_name, _value)
del _mod, _name, _value


def rewrite(sql: str, tenant_id: Optional[str], tenant_col: str,
            is_protected_table: Callable[[str, bool], bool],
            dialect: Optional[str] = None, *,
            protect_ops: Optional[dict] = None,
            allow_tenant_placeholder: bool = False) -> str:
    """Scope ``sql`` to ``tenant_id``. ``dialect`` is a DB Firewall engine
    name (postgresql, mysql, ...) or None. ``is_protected_table(name, quoted)``
    decides per table reference. Returns ``sql`` unchanged when no protected
    table is referenced (or when the statement is on the pass-through list);
    raises PermissionError when the statement is not an allow-listed kind or
    cannot be proven scoped.

    ``tenant_id=None`` is the fail-closed check: the same allow-list applies
    and any reference to a protected table raises PermissionError."""
    if sqlglot is None:
        raise ImportError(INSTALL_HINT)
    if passthrough(sql) is not None:
        return sql
    root, read, originals = _parse(sql, dialect)
    body = _check_shape(root, sql)
    if protect_ops is not None and not protect_ops.get(_OP_OF.get(type(body), "select"), True):
        return sql                                # per-operation opt-out
    if not _scope_tables(root, tenant_id, tenant_col, is_protected_table,
                         allow_tenant_placeholder):
        return sql
    for upd in root.find_all(exp.Update):
        _check_assignments(upd.expressions, tenant_col, tenant_id)
    out = root.sql(dialect=read, comments=False)
    return _PH_RE.sub(lambda m: originals[int(m.group(1))], out)


def _parse(sql: str, dialect: Optional[str]):
    """Exactly one statement, parsed with placeholders masked: (root, read, originals)."""
    if dialect and dialect not in DIALECTS:
        # An unknown engine name would fall back to the generic grammar, which
        # misreads engine keywords (e.g. `FROM ONLY t` -> table "ONLY" AS t).
        raise _reject(f"unknown SQL dialect {dialect!r}")
    read = DIALECTS.get(dialect or "")
    masked, originals = _mask_placeholders(sql, read)
    try:
        stmts = [s for s in sqlglot.parse(masked, read=read) if s is not None]
    except SqlglotError as e:
        raise _reject(f"unparseable SQL: {str(e).splitlines()[0][:80]}")
    if len(stmts) != 1:
        raise _reject("multiple statements" if stmts else "empty statement")
    return stmts[0], read, originals


def _check_shape(root, sql: str):
    """Refuse every statement kind outside the allow-list; return the DML body."""
    for node in root.walk():
        if isinstance(node, exp.Select) and node.args.get("into"):
            raise _reject("SELECT INTO")
        if isinstance(node, _DENIED):
            raise _reject(type(node).__name__)
        if isinstance(node, (exp.Table, exp.Column)) and node.name.upper() in _KEYWORD_TABLES:
            raise _reject(f"{node.name.upper()} command")  # keyword misread as a table/alias
    body = root.this if isinstance(root, exp.Subquery) else root
    if not isinstance(body, (exp.Select, exp.SetOperation, exp.Insert, exp.Update, exp.Delete)):
        raise _reject(f"{type(body).__name__}: only SELECT/INSERT/UPDATE/DELETE, "
                      "transaction control and harmless SET pass the firewall")
    _check_set_config(root, strip_sql(sql))
    return body


def _scope_tables(root, tenant_id, tenant_col, is_protected_table, allow_ph) -> bool:
    """Add the tenant predicate to every protected table reference. True if any."""
    literal = exp.Literal.string(tenant_id) if tenant_id is not None else None
    skip = set()
    for d in root.find_all(exp.Delete):           # MySQL "DELETE t1 FROM t1 ..." targets
        skip.update(id(t) for t in d.args.get("tables") or ())
    used = {}       # id(owner) -> set of qualifiers, to catch ambiguous repeats
    changed = False
    for table in list(root.find_all(exp.Table)):
        parent = table.parent
        if id(table) in skip or isinstance(parent, exp.Lock) or _cte_names_visible(table):
            continue                                  # FOR UPDATE OF t names, not sources
        if not table.name:
            raise _reject("table reference without a resolvable name")
        if not is_protected_table(table.name, bool(getattr(table.this, "quoted", False))):
            continue
        if tenant_id is None:
            raise PermissionError(_NO_TENANT_MSG)
        changed = True
        _scope_table(table, tenant_col, tenant_id, literal, allow_ph, used)
    return changed


def _scope_table(table, tenant_col, tenant_id, literal, allow_ph, used) -> None:
    parent = table.parent
    alias = table.args.get("alias")
    if alias is not None and alias.args.get("columns"):
        raise _reject("column-list alias on a protected table")  # t AS x(a, b) renames tenant_col
    if isinstance(parent, exp.Subquery) and not table.args.get("joins"):
        raise _reject("parenthesised bare table")  # (t) AS x hides the qualifier
    if isinstance(parent, (exp.Insert, exp.Schema)):
        _stamp_insert(parent if isinstance(parent, exp.Insert) else parent.parent,
                      tenant_col, tenant_id, literal, allow_ph)
        return
    owner = _owner(table)
    if owner is None:
        raise _reject(f"table in {type(parent).__name__}")
    qual = _qualifier(table)
    if qual.name in used.setdefault(id(owner), set()):
        raise _reject(f"table {qual.name!r} referenced twice in one scope")
    used[id(owner)].add(qual.name)
    pred = exp.EQ(this=exp.Column(this=exp.to_identifier(tenant_col), table=qual),
                  expression=literal.copy())
    join = _placement(table)
    if join is not None and join.args.get("on") is not None:
        _and_into(join, "on", pred)
    else:
        _and_into(owner, "where", pred)
