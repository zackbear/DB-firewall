"""DB Firewall SQL rewriter: INSERT / UPDATE write-side checks and set_config detection."""

try:
    from sqlglot import exp
except ImportError:          # pragma: no cover - exercised only without sqlglot
    exp = None

from .lexing import DENIED_SETTINGS, _SET_CONFIG_RE, _is_placeholder, _reject, _setting_name
from .astutil import _and_into, _ident_eq, _is_tenant_col, _qualifier

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
