"""DB Firewall SQL rewriter: Statement allow-list, literal blanking, placeholder masking."""

import re
from typing import List, Optional, Tuple

try:
    from sqlglot import exp
except ImportError:          # pragma: no cover - exercised only without sqlglot
    exp = None


INSTALL_HINT = ("DB Firewall: the AST rewriter needs sqlglot "
                "(pip install -r requirements.txt, which pins the tested version)")

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
    "app.current_tenant", "app.tenant_sig", "role", "session_authorization", "authorization", "session",
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
            skipped = _skip_literal(sql, i, backslash_escapes)
            if skipped is None:
                return None
            chunk, i = skipped
            out.append(chunk)
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif sql.startswith("/*", i):
            j = _skip_block_comment(sql, i, nested_comments)
            if j is None:
                return None
            out.append(" " * (j - i))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _skip_literal(sql: str, i: int, backslash_escapes: bool) -> Optional[Tuple[str, int]]:
    """Blank the '...' literal opening at i: (blanked text, index after it), or None if open."""
    out, n = ["'"], len(sql)
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
            return "".join(out), i + 1
        if backslash_escapes and sql[i] == "\\" and i + 1 < n:
            out.append("  ")
            i += 2
            continue
        out.append(" " if sql[i] != "\n" else "\n")
        i += 1


def _skip_block_comment(sql: str, i: int, nested: bool) -> Optional[int]:
    """Index just after the /* */ comment opening at i, or None if unterminated."""
    depth, j, n = 1, i + 2, len(sql)
    while depth and j < n:
        if sql.startswith("*/", j):
            depth, j = depth - 1, j + 2
        elif nested and sql.startswith("/*", j):
            depth, j = depth + 1, j + 2
        else:
            j += 1
    return None if depth else j


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
