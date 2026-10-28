"""DB Firewall: tenant resolution for protect() and the excluded-user bypass."""

import logging
import os
import re
import weakref
from typing import Optional

from .config import check_table_name, engine_options
from .engines import DBEngine, _is_autocommit, placeholder
from .introspection import _META_SAVEPOINT, _conn_dsn, _in_transaction
from .rewrite import validate_tenant_id

logger = logging.getLogger("db_firewall")

def probe(connection, sql: str, params=None):
    """First column of the first row, or None. A failure (missing table,
    grant, aborted transaction) never aborts the caller's open transaction:
    the probe runs inside a SAVEPOINT that is rolled back on failure."""
    in_txn = _in_transaction(connection)
    cursor = connection.cursor()
    try:
        if in_txn:
            cursor.execute(f"SAVEPOINT {_META_SAVEPOINT}")
        try:
            cursor.execute(sql, params) if params else cursor.execute(sql)
            row = cursor.fetchone()
        except Exception as e:
            logger.debug(f"DB Firewall: probe failed: {e}")
            if in_txn:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {_META_SAVEPOINT}")
            elif in_txn is False and not _is_autocommit(connection):
                connection.rollback()       # the implicit transaction was ours alone
            return None
        if in_txn:
            cursor.execute(f"RELEASE SAVEPOINT {_META_SAVEPOINT}")
        return row[0] if row else None
    except Exception as e:
        logger.debug(f"DB Firewall: probe failed: {e}")
        return None
    finally:
        try:
            cursor.close()
        except Exception:
            pass


# The DB user as each engine reports it (Oracle: upper case unless quoted).
_DB_USER_SQL = {
    DBEngine.POSTGRESQL: "SELECT current_user",
    DBEngine.MYSQL: "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1)",
    DBEngine.SQLSERVER: "SELECT SYSTEM_USER",
    DBEngine.ORACLE: "SELECT USER FROM dual",
}

_MAP_USER_EXPR = {
    DBEngine.POSTGRESQL: ("current_user", "TRUE"),
    DBEngine.MYSQL: ("SUBSTRING_INDEX(CURRENT_USER(), '@', 1)", "1"),
    DBEngine.SQLSERVER: ("SYSTEM_USER", "1"),
    DBEngine.ORACLE: ("USER", "'Y'"),
}
# The Oracle migration names its map TENANT_USER_MAP (is_active 'Y'/'N').
_DEFAULT_MAP_TABLE = {DBEngine.ORACLE: "TENANT_USER_MAP"}

# Where each engine keeps a DB-side tenant set by the migration's procedures.
_SESSION_VAR_SQL = {
    DBEngine.POSTGRESQL: "SELECT NULLIF(current_setting({ph}, true), '')",
    DBEngine.MYSQL: "SELECT @_fw_tenant_id",
    DBEngine.SQLSERVER: "SELECT CAST(SESSION_CONTEXT(N'tenant_id') AS NVARCHAR(128))",
    DBEngine.ORACLE: "SELECT SYS_CONTEXT('CTX_SAAS', 'tenant_id') FROM dual",
}


def db_user(connection, engine: str) -> Optional[str]:
    sql = _DB_USER_SQL.get(engine)
    return probe(connection, sql) if sql else None


def _resolve_tenant_from_map(connection, engine: str,
                             table: str = "_firewall_tenant_map") -> Optional[str]:
    """The active tenant map row for the current DB user."""
    expr = _MAP_USER_EXPR.get(engine)
    if expr is None:
        return None
    if table == "_firewall_tenant_map":
        table = _DEFAULT_MAP_TABLE.get(engine, table)
    check_table_name(table)
    user, true = expr
    sql = f"SELECT tenant_id FROM {table} WHERE db_user = {user} AND is_active = {true}"
    return probe(connection, sql)


def _from_session_var(connection, engine: str, entry: dict, config: dict) -> Optional[str]:
    sql = _SESSION_VAR_SQL.get(engine)
    if sql is None:
        return None
    if engine == DBEngine.POSTGRESQL and \
            (engine_options(config, engine).get("tenant_context") or "signed").lower() != "plain":
        # Signed context: only a tenant signed for this transaction counts.
        # A plain setting may come from SQL the app ran (or an earlier user of
        # the connection); taking it here would sign it. Other variables
        # cannot be signed, so they are refused.
        if entry.get("variable", "app.current_tenant") != "app.current_tenant":
            raise ValueError("DB Firewall: session_var with tenant_context: signed reads "
                             "app.current_tenant only")
        return probe(connection, "SELECT public._firewall_tenant()")
    if engine == DBEngine.POSTGRESQL:
        ph = placeholder(connection)
        return probe(connection, sql.format(ph=ph), (entry.get("variable", "app.current_tenant"),))
    return probe(connection, sql)


def _from_connection_param(connection, entry: dict) -> Optional[str]:
    name = entry.get("param_name", "tenant_id")
    value = getattr(connection, name, None)
    if value is None:
        match = re.search(rf"(?:^|[\s;&?]){re.escape(name)}=([^\s;&]+)", _conn_dsn(connection) or "")
        value = match.group(1) if match else None
    return value


def _source_value(connection, engine: str, entry: dict, config: dict) -> Optional[str]:
    source = entry["source"]
    if source == "env_var":
        return os.environ.get(entry.get("variable", "TENANT_ID"))
    if source == "db_user_map":
        return _resolve_tenant_from_map(connection, engine,
                                        entry.get("table", "_firewall_tenant_map"))
    if source == "session_var":
        return _from_session_var(connection, engine, entry, config)
    return _from_connection_param(connection, entry)


def resolve_tenant(connection, engine: str, config: dict) -> Optional[str]:
    """First tenant found by the enabled resolution sources, in order.
    A source with no value is skipped. A value that is set but is not a valid
    tenant id raises ValueError (fail closed): the next source is NOT tried,
    so a broken TENANT_ID never binds the connection to another tenant."""
    for entry in config.get("resolution") or []:
        if not entry.get("enabled", True):
            continue
        value = _source_value(connection, engine, entry, config)
        # An empty DB value means "not set"; an empty env var is set (and invalid).
        if value is None or (value == "" and entry["source"] != "env_var"):
            continue
        return validate_tenant_id(str(value))
    return None


_warned_bypass: set = set()
_excluded_cache: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def is_excluded(connection, engine: str, config: dict, cache: bool = False) -> bool:
    """True when the connection's DB user is listed in excluded_users. Exact
    match on the name the database reports. A failed lookup is not excluded
    (fail closed). cache=True remembers the answer per connection object."""
    users = config.get("excluded_users") or []
    if not users:
        return False
    if cache:
        try:
            if connection in _excluded_cache:
                return _excluded_cache[connection]
        except TypeError:           # not weak-referenceable: look up every time
            cache = False
    user = db_user(connection, engine)
    excluded = user is not None and user in users
    if excluded and user not in _warned_bypass:
        _warned_bypass.add(user)
        logger.warning(f"DB Firewall: DB user {user!r} is in excluded_users: "
                       "its connections are NOT scoped by the middleware")
    if cache:
        _excluded_cache[connection] = excluded
    return excluded
