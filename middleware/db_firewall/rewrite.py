"""DB Firewall: SQL query rewriting: tenant validation, AST and legacy regex rewriters."""

import re
import logging
from typing import Dict, List

try:                                    # package import (middleware.db_firewall)
    from .. import sql_rewriter as _sqlr
except ImportError:                     # flat import (sys.path += middleware/)
    import sql_rewriter as _sqlr

from .engines import DBEngine
from .introspection import _fold_table_name, _has_tenant_column

logger = logging.getLogger("db_firewall")

# ============================================================================
# SQL QUERY REWRITING — THE INVISIBLE WHERE CLAUSE
# ============================================================================

# Regex patterns for table-name extraction (pre-filter only: the AST rewriter
# makes the real decision). Optional schema prefix; quotes may follow the
# keyword directly (FROM"orders").
_IDENT = r'[`"\[]?(\w+)[`"\]]?'
_TABLE_PATTERNS = [
    re.compile(rf'\b{kw}(?:\s+|(?=[`"\[]))(?:{_IDENT}\s*\.\s*)?{_IDENT}', re.IGNORECASE)
    for kw in ("FROM", "JOIN", "INTO", "UPDATE", r"DELETE\s+FROM", "USING",
               "COPY", r"TRUNCATE(?:\s+TABLE)?")
]

_SELECT_RE = re.compile(r'\bSELECT\b', re.IGNORECASE)
_INSERT_RE = re.compile(r'\bINSERT\b', re.IGNORECASE)
_UPDATE_RE = re.compile(r'\bUPDATE\b', re.IGNORECASE)
_DELETE_RE = re.compile(r'\bDELETE\b', re.IGNORECASE)
_WHERE_RE = re.compile(r'\bWHERE\b', re.IGNORECASE)


def _extract_tables(sql: str) -> List[str]:
    """Extract table names from a SQL query."""
    tables = set()
    for pattern in _TABLE_PATTERNS:
        for match in pattern.finditer(sql):
            tables.add(match.group(2))      # group 1 = optional schema
    return list(tables)


_DML_STARTS = ("SELECT", "INSERT", "UPDATE", "DELETE")
# Shapes the regex rewriter cannot scope safely; rejected when a protected table
# is involved (fail closed) instead of being passed through half-filtered.
_UNSAFE_STARTS = ("WITH", "(", "TABLE")
_SET_OP_RE = re.compile(r'\b(UNION|INTERSECT|EXCEPT)\b', re.IGNORECASE)
_FROM_RE = re.compile(r'\bFROM\b', re.IGNORECASE)
_USING_RE = re.compile(r'\bUSING\b', re.IGNORECASE)
_TABLE_CMD_RE = re.compile(r'^\s*TABLE\s+([`"\[]?\w+[`"\]]?)', re.IGNORECASE)
_CLAUSE_RE = re.compile(r'\b(ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|FETCH|FOR)\b',
                        re.IGNORECASE)


# Shared with the AST rewriter (middleware/sql_rewriter/lexing.py).
_blank_literals = _sqlr.blank_literals
_strip_sql = _sqlr.strip_sql


def _toplevel_match(regex, clean: str):
    """First match of ``regex`` in ``clean`` that sits at parenthesis depth 0."""
    for m in regex.finditer(clean):
        if clean.count("(", 0, m.start()) == clean.count(")", 0, m.start()):
            return m
    return None


def _reject_unsafe_shape(clean: str) -> None:
    """Fail closed on statement shapes the WHERE injector cannot scope."""
    head = clean.lstrip().upper()
    why = None
    if head.startswith(_UNSAFE_STARTS):
        why = "CTE / parenthesised / TABLE statement"
    elif re.search(r';\s*\S', clean):
        why = "multiple statements"
    elif _toplevel_match(_SET_OP_RE, clean):
        why = "UNION/INTERSECT/EXCEPT"
    elif head.startswith("UPDATE") and _toplevel_match(_FROM_RE, clean):
        why = "UPDATE ... FROM"
    elif head.startswith("DELETE") and _toplevel_match(_USING_RE, clean):
        why = "DELETE ... USING"
    if why:
        raise PermissionError(
            f"DB Firewall: unsupported statement shape ({why}); "
            "cannot be safely scoped to a tenant")


def _is_excluded_table(table: str, excluded: List[str]) -> bool:
    """Check if table matches exclusion patterns."""
    import fnmatch
    for pattern in excluded:
        if fnmatch.fnmatch(table, pattern):
            return True
    return False


# Backslash: MySQL treats \' as an escape, so a tenant ending in \ would swallow
# the closing quote of the injected literal.
_BAD_TENANT_CHARS = ("\x00", "\n", "\r", "\\")


def validate_tenant_id(tenant_id: str) -> str:
    """Reject tenant ids that cannot be safely embedded in SQL or session state."""
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("DB Firewall: tenant_id must be a non-empty string")
    if tenant_id.casefold() == "__bypass__":
        raise ValueError("DB Firewall: __BYPASS__ is reserved (MySQL bypass marker)")
    if any(c in tenant_id for c in _BAD_TENANT_CHARS):
        raise ValueError("DB Firewall: tenant_id contains NUL/newline/backslash characters")
    if _sqlr._PH_PREFIX in tenant_id:
        raise ValueError("DB Firewall: tenant_id contains the reserved placeholder token")
    return tenant_id


def _sql_literal(tenant_id: str) -> str:
    """Return tenant_id as a quoted SQL string literal (single quotes doubled)."""
    validate_tenant_id(tenant_id)
    return "'" + tenant_id.replace("'", "''") + "'"


# The MySQL layer keys on the user variable @_fw_tenant_id and these routines.
_FIREWALL_NAMES_RE = re.compile(
    r"_fw_tenant_id|_firewall_(?:set_tenant|clear_tenant|apply_all|init_connection)"
    r"|dbfw_tenant_column", re.I)
# MySQL folds variable names (escapes, accents: @'_fw_tenant_i\d', @_fw_tenänt_id),
# so matching the name is not enough: on MySQL no user variable gets through at
# all (an "@" outside single-quoted literals and comments), nor the statements
# that run SQL built at run time. The ast rewriter refuses those heads too.
_MYSQL_DYNAMIC_RE = re.compile(r"^\s*(?:PREPARE|EXECUTE|DEALLOCATE|CALL|DO|HANDLER)\b", re.I)


def _refuse_firewall_names(sql: str, engine: str = None) -> None:
    if _FIREWALL_NAMES_RE.search(sql):
        raise PermissionError("DB Firewall: statement names the firewall's tenant "
                              "variable or routines; refused")
    if engine == DBEngine.MYSQL:
        clean = _strip_sql(sql)
        if "@" in clean or _MYSQL_DYNAMIC_RE.match(clean):
            raise PermissionError("DB Firewall: MySQL user variables and dynamic SQL "
                                  "(PREPARE/EXECUTE/CALL/DO/HANDLER) are refused")


def rewrite_query(sql: str, tenant_id: str, config: dict,
                  connection=None, engine: str = None) -> str:
    """
    Rewrite a SQL query to inject tenant isolation WHERE clauses.
    This is the middleware-level enforcement for engines without native RLS.

    ``config["rewriter"]``: "ast" (default, sqlglot) parses EVERY statement:
    only SELECT/INSERT/UPDATE/DELETE (and WITH-wrapped forms), transaction
    control and harmless SET/RESET get through; every protected table
    reference is scoped (CTEs, UNION branches, joins, subqueries,
    INSERT..SELECT) and what cannot be proven scoped is refused. "regex" is
    the legacy injector that refuses multi-scope shapes outright.
    """
    if not sql or not sql.strip():
        return sql
    _refuse_firewall_names(sql, engine)

    # No tenant → don't rewrite (fail-closed is enforced by check_no_tenant)
    if tenant_id is None:
        return sql

    protect = config.get("protect", {})
    is_protected = _protected_predicate(config, connection, engine)

    if config.get("rewriter", "ast") != "regex":
        validate_tenant_id(tenant_id)
        # ImportError (sqlglot missing) propagates: never silently fall back.
        return _sqlr.rewrite(
            sql, tenant_id, config.get("tenant_column", "tenant_id"), is_protected, engine,
            protect_ops=protect,
            allow_tenant_placeholder=bool(config.get("allow_tenant_placeholder", False)))

    return _rewrite_query_regex(sql, tenant_id, config, is_protected)


def _protected_predicate(config: dict, connection, engine):
    """``is_protected(name, quoted)`` for one statement: excluded_tables glob
    (on the engine-folded name) first, then the live column check. Without a
    connection every non-excluded table counts as protected."""
    tenant_col = config.get("tenant_column", "tenant_id")
    excluded = config.get("excluded_tables", [])
    memo: Dict[tuple, bool] = {}

    def is_protected(table: str, quoted: bool = False) -> bool:
        key = (table, quoted)
        if key not in memo:
            folded = _fold_table_name(table, quoted, engine or DBEngine.UNKNOWN)
            memo[key] = not (_is_excluded_table(table, excluded)
                             or _is_excluded_table(folded, excluded)) and (
                connection is None
                or _has_tenant_column(connection, table, engine, tenant_col, quoted))
        return memo[key]
    return is_protected


def check_no_tenant(sql: str, config: dict, connection=None, engine: str = None) -> None:
    """fail_mode=closed with no tenant: raise PermissionError unless the
    statement is on the pass-through list or touches no protected table."""
    if not sql or not sql.strip():
        return
    _refuse_firewall_names(sql, engine)
    if config.get("rewriter", "ast") != "regex":
        _sqlr.rewrite(sql, None, config.get("tenant_column", "tenant_id"),
                      _protected_predicate(config, connection, engine), engine)
        return
    if _strip_sql(sql).lstrip().upper().startswith(_DML_STARTS + _UNSAFE_STARTS):
        raise PermissionError(_sqlr._NO_TENANT_MSG)


def _rewrite_query_regex(sql: str, tenant_id: str, config: dict, is_protected) -> str:
    """Legacy path: regex table extraction gates the single-WHERE injector."""
    protect = config.get("protect", {})
    # All keyword detection runs on a copy with string literals and comments
    # blanked out, so 'UNION' inside a literal is not a set operation and a
    # WHERE inside a literal cannot misplace the injected predicate.
    clean = _strip_sql(sql)
    head = clean.lstrip().upper()

    tables = _extract_tables(clean)
    m = _TABLE_CMD_RE.match(clean)
    if m:
        tables.append(m.group(1).strip('`"[]'))
    protected_tables = [t for t in tables if is_protected(t)]

    # Non-DML (DDL, utility) is passed through — unless it names a protected
    # table (CREATE TABLE AS SELECT, MERGE INTO, COPY, TRUNCATE): fail closed.
    if not head.startswith(_DML_STARTS + _UNSAFE_STARTS):
        if protected_tables:
            raise PermissionError(
                "DB Firewall: non-DML statement references protected table(s) "
                f"{sorted(protected_tables)}; refused")
        return sql

    # Per-operation opt-out
    for op in ("select", "insert", "update", "delete"):
        if head.startswith(op.upper()) and not protect.get(op, True):
            return sql

    if not protected_tables:
        return sql

    validate_tenant_id(tenant_id)
    return _rewrite_regex(sql, clean, tenant_id, config.get("tenant_column", "tenant_id"))


def _rewrite_regex(sql: str, clean: str, tenant_id: str, tenant_col: str) -> str:
    """Legacy injector: one WHERE predicate on single-table-shaped statements."""
    head = clean.lstrip().upper()
    # A protected table in a shape we cannot scope → refuse, never half-filter
    _reject_unsafe_shape(clean)

    # For SELECT/UPDATE/DELETE: inject WHERE clause
    if head.startswith(("SELECT", "UPDATE", "DELETE")):
        tenant_predicate = f"{tenant_col} = {_sql_literal(tenant_id)}"

        where = _toplevel_match(_WHERE_RE, clean)
        if where:
            # Inject after the real (top-level, non-literal) WHERE
            sql = sql[:where.end()] + f" {tenant_predicate} AND" + sql[where.end():]
        else:
            # Find insertion point (before ORDER BY, GROUP BY, LIMIT, etc.)
            insert_before = _toplevel_match(_CLAUSE_RE, clean)
            if insert_before:
                pos = insert_before.start()
                sql = sql[:pos] + f" WHERE {tenant_predicate} " + sql[pos:]
            else:
                # Append after the last real token, i.e. before any trailing
                # comment (otherwise the predicate would be commented out).
                code_end = len(clean.rstrip())
                body = sql[:code_end].rstrip(';').rstrip()
                sql = body + f" WHERE {tenant_predicate}" + sql[code_end:]

    return sql
