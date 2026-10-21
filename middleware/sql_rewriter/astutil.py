"""DB Firewall SQL rewriter: AST helpers: scopes, owners, qualifiers, predicate placement."""

try:
    from sqlglot import exp
except ImportError:          # pragma: no cover - exercised only without sqlglot
    exp = None


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
