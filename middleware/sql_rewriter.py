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

import re
from typing import Callable, List, Optional, Tuple

try:
    import sqlglot
    from sqlglot import exp
    from sqlglot.errors import SqlglotError
except ImportError:          # pragma: no cover - exercised only without sqlglot
    sqlglot = None
    exp = None
    SqlglotError = Exception

INSTALL_HINT = ("DB Firewall: the AST rewriter needs sqlglot "
                "(pip install 'sqlglot>=25'); set rewriter: \"regex\" to opt out")

DIALECTS = {"postgresql": "postgres", "mysql": "mysql", "sqlserver": "tsql",
            "oracle": "oracle", "sqlite": "sqlite"}

_PH_PREFIX = "__dbfw_ph_"
# Names sqlglot can produce when it misparses an engine keyword as a table or alias.
_KEYWORD_TABLES = {"TABLE", "ONLY", "LATERAL", "UNNEST"}
_PH_RE = re.compile(r"__dbfw_ph_(\d+)__")
# Driver placeholders that sqlglot either rejects or rewrites: %(name)s, %s,
# $1, ?, ?1, :name, :1.  '?' is skipped for postgres (jsonb operator; psycopg
# uses %s).  ':' must not be part of '::' or follow a word char (array slices).
_PLACEHOLDER_RE = re.compile(
    r"%\([A-Za-z_]\w*\)s|%s|\$\d+|(?<![:\w]):[A-Za-z_]\w*|(?<![:\w]):\d+|\?\d*")
_PLACEHOLDER_NO_QMARK_RE = re.compile(
    r"%\([A-Za-z_]\w*\)s|%s|\$\d+|(?<![:\w]):[A-Za-z_]\w*|(?<![:\w]):\d+")

# --- statement allow-list (lexical, on the literal/comment-blanked text) -----
# Transaction control the app needs; nothing here touches data or settings.
_TXN_RE = re.compile(
    r"^\s*(?:BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT)"
    r"(?:\s*,|\s+(?:WORK|TRANSACTION|AND\s+(?:NO\s+)?CHAIN|ISOLATION\s+LEVEL\s+\w+(?:\s+READ)?"
    r"|READ\s+(?:WRITE|ONLY)|(?:NOT\s+)?DEFERRABLE))*\s*;?\s*$", re.I)
_SAVEPOINT_RE = re.compile(
    r"^\s*(?:SAVEPOINT|RELEASE(?:\s+SAVEPOINT)?|ROLLBACK(?:\s+(?:WORK|TRANSACTION))?"
    r"\s+TO(?:\s+SAVEPOINT)?)\s+(?:\"[^\"]+\"|[A-Za-z_]\w*)\s*;?\s*$", re.I)
# SET [LOCAL|SESSION] <name> ... / RESET <name>. <name> may be quoted and dotted
# with spaces around the dots (Postgres folds all of these to one GUC name).
_NAME = r'(?:"[^"]*"|[@A-Za-z_][\w$@]*)(?:\s*\.\s*(?:"[^"]*"|[A-Za-z_][\w$]*))*'
_SET_RE = re.compile(rf"^\s*SET\s+(?:(?:LOCAL|SESSION)\s+)?({_NAME})", re.I)
_RESET_RE = re.compile(rf"^\s*RESET\s+({_NAME})", re.I)
_SET_OR_RESET_RE = re.compile(r"^\s*(?:SET|RESET)\b", re.I)
# Settings that move the tenant, the role or name resolution: never from the app.
DENIED_SETTINGS = frozenset({
    "app.current_tenant", "role", "session_authorization", "authorization", "session",
    "search_path", "row_security", "all", "@_fw_tenant_id"})
_UNICODE_ESCAPE_RE = re.compile(r"\bU&\s*[\"']", re.I)
_SET_CONFIG_RE = re.compile(r"\bset_config\b", re.I)
_NO_TENANT_MSG = "DB Firewall: No tenant context. Query blocked (fail_mode=closed)."


def _reject(why: str) -> "PermissionError":
    return PermissionError(f"DB Firewall: unsupported statement shape ({why}); "
                           "cannot be safely scoped to a tenant")


def _setting_name(raw: str) -> str:
    """Fold a SET/RESET target the way the server does: drop quotes and the
    whitespace around dots, lower-case."""
    return re.sub(r'[\s"]', "", raw).lower()


def passthrough(sql: str) -> Optional[str]:
    """Statements that bypass the parser: transaction control and SET/RESET of
    a setting outside :data:`DENIED_SETTINGS`. Returns ``sql`` when it is one
    of those, None when it must be parsed, raises PermissionError when it is a
    denied SET/RESET, several statements, or carries a ``U&`` escape."""
    clean = strip_sql(sql)
    if re.search(r";\s*\S", clean):
        raise _reject("multiple statements")
    if _UNICODE_ESCAPE_RE.search(clean):
        raise _reject("U& unicode-escaped identifier or literal")
    if _TXN_RE.match(clean) or _SAVEPOINT_RE.match(clean):
        return sql
    m = _SET_RE.match(clean) or _RESET_RE.match(clean)
    if m:
        name = _setting_name(m.group(1))
        if name in DENIED_SETTINGS:
            raise _reject(f"SET/RESET of {name}")
        return sql
    if _SET_OR_RESET_RE.match(clean):
        raise _reject("SET/RESET with an unrecognised target")
    return None


# ----------------------------------------------------------------------------
# Lexical helpers (no sqlglot needed; db_firewall's regex path reuses them)
# ----------------------------------------------------------------------------

def blank_literals(sql: str, backslash_escapes: bool,
                   nested_comments: bool = False) -> Optional[str]:
    """Return ``sql`` with the contents of '...' literals and all -- / /* */
    comments replaced by spaces (same length, so positions line up), or None
    when a literal/comment is unterminated. ``nested_comments`` follows the
    SQL standard / PostgreSQL rule that /* */ nest."""
    out, i, n = [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "'":
            out.append("'")
            i += 1
            while True:
                if i >= n:
                    return None
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":      # '' escape
                        out.append("  ")
                        i += 2
                        continue
                    out.append("'")
                    i += 1
                    break
                if backslash_escapes and sql[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append(" " if sql[i] != "\n" else "\n")
                i += 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif sql.startswith("/*", i):
            depth, j = 1, i + 2
            while depth and j < n:
                if sql.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                elif nested_comments and sql.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                else:
                    j += 1
            if depth:
                return None
            out.append(" " * (j - i))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def strip_sql(sql: str) -> str:
    """Literal/comment-blanked copy of ``sql``. Raises PermissionError when the
    text cannot be tokenised unambiguously (unterminated literal/comment, a
    backslash-quote or a nested block comment, whose meaning differs between
    engines)."""
    plain = blank_literals(sql, backslash_escapes=False)
    mysql = blank_literals(sql, backslash_escapes=True)
    nested = blank_literals(sql, backslash_escapes=False, nested_comments=True)
    if plain is None or mysql is None or plain != mysql or plain != nested:
        raise _reject("ambiguous or unterminated string literal/comment")
    return plain


def _mask_placeholders(sql: str, dialect: Optional[str]) -> Tuple[str, List[str]]:
    """Replace driver placeholders (outside literals/comments) with unique
    identifiers sqlglot round-trips verbatim. Returns (masked_sql, originals)."""
    if _PH_PREFIX in sql:
        raise _reject("reserved placeholder token in statement")
    clean = strip_sql(sql)
    regex = _PLACEHOLDER_NO_QMARK_RE if dialect == "postgres" else _PLACEHOLDER_RE
    originals, out, last = [], [], 0
    for m in regex.finditer(clean):
        out.append(sql[last:m.start()])
        out.append(f"{_PH_PREFIX}{len(originals)}__")
        originals.append(m.group(0))
        last = m.end()
    out.append(sql[last:])
    return "".join(out), originals


def _is_placeholder(node) -> bool:
    return isinstance(node, exp.Column) and node.name.startswith(_PH_PREFIX)


# ----------------------------------------------------------------------------
# AST helpers
# ----------------------------------------------------------------------------

_OWNERS = (exp.Select, exp.Update, exp.Delete) if exp else ()
_DENIED = ((exp.Create, exp.Merge, exp.TruncateTable, exp.Copy, exp.Command,
            exp.Drop, exp.Alter, exp.Into) if exp else ())


def _is_query(node) -> bool:
    return isinstance(node, (exp.Select, exp.SetOperation))


def _with(node):
    """The node's WITH clause (arg key is 'with_' in sqlglot>=28, 'with' before)."""
    return node.args.get("with_") or node.args.get("with")


def _owner(node):
    """Nearest enclosing SELECT / UPDATE / DELETE, or None."""
    p = node.parent
    while p is not None and not isinstance(p, _OWNERS):
        p = p.parent
    return p


def _cte_names_visible(table) -> bool:
    """True when ``table`` refers to a CTE rather than a real table: its name
    is defined by an enclosing WITH *before* the point of use (or recursively
    inside its own body). A schema/catalog-qualified name is never a CTE."""
    if table.args.get("db") or table.args.get("catalog"):
        return False
    name = table.name
    node, inner_cte = table, None
    while node.parent is not None:
        parent = node.parent
        if isinstance(parent, exp.CTE):
            inner_cte = parent
        with_ = _with(parent)
        if with_ is not None:
            ctes = with_.expressions
            names = [c.alias for c in ctes]
            if name in names:
                if inner_cte is not None and inner_cte in ctes:
                    i, j = names.index(name), ctes.index(inner_cte)
                    if i < j or (i == j and with_.args.get("recursive")):
                        return True
                    # a later (or own, non-recursive) CTE name → the real table
                else:
                    return True
            inner_cte = None  # a new WITH scope starts above
        node = parent
    return False


def _levels(table):
    """Yield (joins_list, position, container) for every join list ``table``
    takes part in, innermost first. position -1 = left-most base of the list."""
    node, own = table, True
    while node is not None:
        if own and node.args.get("joins"):
            yield node.args["joins"], -1, node
        par = node.parent
        if isinstance(par, exp.Join):
            lst = par.parent.args.get("joins") or []
            yield lst, lst.index(par), par.parent
            node, own = par.parent, False
            if isinstance(node, _OWNERS):
                return
        elif isinstance(par, exp.From):
            yield (par.parent.args.get("joins") or []), -1, par.parent
            return
        elif isinstance(par, exp.Subquery) and not _is_query(node):
            node, own = par, False          # parenthesised join group
        else:
            return


def _placement(table):
    """Return the Join whose ON must carry the predicate (table is on a
    null-supplying side), or None for WHERE."""
    for lst, pos, _ in _levels(table):
        if pos >= 0:
            side = lst[pos].side
            if side == "LEFT":
                return lst[pos]
            if side == "FULL":
                return None
        for j in lst[pos + 1:]:
            if j.side == "RIGHT":
                return j
            if j.side == "FULL":
                return None
    return None


def _qualifier(table):
    """Identifier used to qualify the tenant column (alias wins)."""
    alias = table.args.get("alias")
    return (alias.this if alias else table.this).copy()


def _and_into(node, key: str, pred):
    cur = node.args.get(key)
    if isinstance(cur, exp.Where):
        cur = cur.this
    combined = exp.and_(pred, cur, copy=False) if cur is not None else pred
    node.set(key, exp.Where(this=combined) if key == "where" else combined)


def _ident_eq(ident, name: str) -> bool:
    return ident.name == name or (not ident.quoted and ident.name.lower() == name.lower())


def _ident_like(ident, name: str) -> bool:
    """Case-insensitive even when quoted: MySQL/SQL Server fold quoted names
    too, so for *rejection* checks the loose match is the safe one."""
    return ident.name.lower() == name.lower()


def _is_tenant_col(node, tenant_col: str) -> bool:
    return isinstance(node, exp.Column) and _ident_like(node.this, tenant_col)


# ----------------------------------------------------------------------------
# INSERT / UPDATE write-side checks
# ----------------------------------------------------------------------------

def _value_ok(node, tenant_id: str, allow_ph: bool) -> bool:
    if _is_placeholder(node):
        if allow_ph:
            return True
        raise _reject("INSERT binds the tenant column to a parameter placeholder; "
                      "set allow_tenant_placeholder: true to let the driver supply it")
    return isinstance(node, exp.Literal) and node.is_string and node.this == tenant_id


def _check_tenant_values(src, idx: int, tenant_id: str, allow_ph: bool) -> None:
    """Every row produced by ``src`` must carry the tenant literal (or, when
    allowed, a placeholder) at column ``idx``."""
    if isinstance(src, exp.Values):
        rows = [t.expressions for t in src.expressions]
    elif isinstance(src, exp.Select):
        if any(isinstance(e, exp.Star) or (isinstance(e, exp.Column) and e.is_star)
               for e in src.expressions):
            raise _reject("INSERT ... SELECT * with an explicit tenant column")
        rows = [src.expressions]
    elif isinstance(src, exp.SetOperation):
        _check_tenant_values(src.this, idx, tenant_id, allow_ph)
        _check_tenant_values(src.expression, idx, tenant_id, allow_ph)
        return
    elif isinstance(src, exp.Subquery):
        _check_tenant_values(src.this, idx, tenant_id, allow_ph)
        return
    else:
        raise _reject("INSERT source")
    for row in rows:
        if idx >= len(row) or not _value_ok(row[idx], tenant_id, allow_ph):
            raise _reject("INSERT supplies a different tenant value")


def _append_tenant_value(src, literal) -> None:
    if isinstance(src, exp.Values):
        for t in src.expressions:
            t.append("expressions", literal.copy())
    elif isinstance(src, exp.Select):
        src.append("expressions", literal.copy())
    elif isinstance(src, exp.SetOperation):
        _append_tenant_value(src.this, literal)
        _append_tenant_value(src.expression, literal)
    elif isinstance(src, exp.Subquery):
        _append_tenant_value(src.this, literal)
    else:
        raise _reject("INSERT source")


def _stamp_insert(ins, tenant_col: str, tenant_id: str, literal, allow_ph: bool) -> None:
    schema = ins.this
    if not isinstance(schema, exp.Schema) or ins.expression is None:
        raise _reject("INSERT into a protected table without a column list")
    idx = next((i for i, c in enumerate(schema.expressions) if _ident_eq(c, tenant_col)), None)
    if idx is None:
        schema.append("expressions", exp.to_identifier(tenant_col))
        _append_tenant_value(ins.expression, literal)
    else:
        _check_tenant_values(ins.expression, idx, tenant_id, allow_ph)
    conflict = ins.args.get("conflict")
    if conflict is None or not conflict.expressions:
        return                                  # no conflict clause / DO NOTHING
    if conflict.args.get("duplicate"):
        # MySQL ON DUPLICATE KEY UPDATE has no WHERE: the existing row (which
        # may belong to another tenant) cannot be guarded, so refuse.
        raise _reject("ON DUPLICATE KEY UPDATE on a protected table")
    _check_assignments(conflict.expressions, tenant_col, tenant_id)
    # DO UPDATE only touches the conflicting row when it is ours.
    pred = exp.EQ(this=exp.Column(this=exp.to_identifier(tenant_col),
                                  table=_qualifier(schema.this)),
                  expression=literal.copy())
    _and_into(conflict, "where", pred)


def _check_assignments(assignments, tenant_col: str, tenant_id: str) -> None:
    """SET tenant_col = <anything but the tenant literal> would move rows
    across tenants. Tuple forms ``SET (a, tenant_col) = (…) / ROW(…) /
    (SELECT …)`` cannot be checked value-by-value and are refused outright."""
    for a in assignments or ():
        if not isinstance(a, exp.EQ):
            raise _reject("unrecognised assignment form")
        lhs = a.this
        if isinstance(lhs, exp.Tuple):
            if any(_is_tenant_col(c, tenant_col) for c in lhs.expressions):
                raise _reject("tuple assignment to the tenant column")
            continue
        if not isinstance(lhs, exp.Column):
            raise _reject("unrecognised assignment target")
        if _is_tenant_col(lhs, tenant_col) and not (
                isinstance(a.expression, exp.Literal) and a.expression.is_string
                and a.expression.this == tenant_id):
            raise _reject("assignment to the tenant column")


# ----------------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------------

_OP_OF = {exp.Insert: "insert", exp.Update: "update", exp.Delete: "delete"} if exp else {}


def _check_set_config(root, clean: str) -> None:
    """``set_config('app.current_tenant', …)`` (any schema prefix) moves the
    tenant from inside a SELECT: the first argument must be a string literal
    outside :data:`DENIED_SETTINGS`."""
    seen = 0
    for node in root.find_all(exp.Anonymous):
        if node.name.lower() != "set_config":
            continue
        seen += 1
        target = node.expressions[0] if node.expressions else None
        if not (isinstance(target, exp.Literal) and target.is_string) \
                or _setting_name(target.this) in DENIED_SETTINGS:
            raise _reject("set_config() of a denied or non-literal setting")
    if seen != len(_SET_CONFIG_RE.findall(clean)):
        raise _reject("set_config() in an unrecognised position")   # e.g. FROM set_config(...)


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
    root = stmts[0]
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
    if protect_ops is not None and not protect_ops.get(_OP_OF.get(type(body), "select"), True):
        return sql                                # per-operation opt-out

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
        alias = table.args.get("alias")
        if alias is not None and alias.args.get("columns"):
            raise _reject("column-list alias on a protected table")  # t AS x(a, b) renames tenant_col
        if isinstance(parent, exp.Subquery) and not table.args.get("joins"):
            raise _reject("parenthesised bare table")  # (t) AS x hides the qualifier
        if isinstance(parent, (exp.Insert, exp.Schema)):
            _stamp_insert(parent if isinstance(parent, exp.Insert) else parent.parent,
                          tenant_col, tenant_id, literal, allow_tenant_placeholder)
            continue
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
    if not changed:
        return sql
    for upd in root.find_all(exp.Update):
        _check_assignments(upd.expressions, tenant_col, tenant_id)
    out = root.sql(dialect=read, comments=False)
    return _PH_RE.sub(lambda m: originals[int(m.group(1))], out)
