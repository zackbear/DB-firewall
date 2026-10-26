"""DB Firewall: SQLAlchemy engine event hooks."""

import logging
from typing import Optional

from .context import TenantContext
from .db_context import _CONTEXT_SETTERS, pool_checkin
from .rewrite import check_no_tenant, rewrite_query
from .engines import detect_engine
from .config import db_context_enabled, load_config
from .resolution import is_excluded
from .audit import log_query, write_assignment

logger = logging.getLogger("db_firewall")

def _apply_tenant(dbapi_connection, config):
    """Set the DB-side tenant (and its audit row) unless the engine's
    use_* option is off or the DB user is in excluded_users."""
    tenant = TenantContext.get()
    if not tenant:
        return
    db_engine = detect_engine(dbapi_connection)
    setter = _CONTEXT_SETTERS.get(db_engine)
    if setter and db_context_enabled(config, db_engine) \
            and not is_excluded(dbapi_connection, db_engine, config, cache=True):
        setter(dbapi_connection, tenant)
        write_assignment(dbapi_connection, db_engine, tenant, config)


def _before_execute(conn, statement, parameters, context, config):
    tenant = TenantContext.get()
    dbapi_conn = conn.connection.dbapi_connection
    db_engine = detect_engine(dbapi_conn)

    if is_excluded(dbapi_conn, db_engine, config, cache=True):
        pass                                        # excluded_users: not scoped
    elif tenant and statement:
        new_statement = rewrite_query(statement, tenant, config, dbapi_conn, db_engine)
        if new_statement != statement:
            context._firewall_original = statement
        statement = new_statement
    elif not tenant and config.get("fail_mode", "closed") == "closed":
        check_no_tenant(statement, config, dbapi_conn, db_engine)
    log_query(tenant, statement, config)
    return statement, parameters


def sqlalchemy_event_hooks(engine_instance, config: Optional[dict] = None):
    """
    Attach tenant isolation to a SQLAlchemy engine.

    Usage:
        from sqlalchemy import create_engine
        from db_firewall import sqlalchemy_event_hooks

        engine = create_engine(...)
        sqlalchemy_event_hooks(engine)   # reads config once; pass config= to override
    """
    from sqlalchemy import event
    if config is None:
        config = load_config()

    # Per-checkout, not per-connect: a pooled connection serves many tenants.
    # Postgres uses a transaction-local GUC, so it dies with the transaction.
    @event.listens_for(engine_instance, "checkout")
    def on_checkout(dbapi_connection, connection_record, connection_proxy):
        _apply_tenant(dbapi_connection, config)

    # ...and therefore it must be re-applied for every transaction a long-lived
    # Connection/Session opens after its first commit()/rollback(). SQLAlchemy
    # fires "begin" when it starts each new transaction. Setting the GUC twice
    # in one transaction (checkout, then begin) is harmless: same value.
    @event.listens_for(engine_instance, "begin")
    def on_begin(conn):
        _apply_tenant(conn.connection.dbapi_connection, config)

    @event.listens_for(engine_instance, "checkin")
    def on_checkin(dbapi_connection, connection_record):
        if dbapi_connection is not None and db_context_enabled(config, detect_engine(dbapi_connection)):
            pool_checkin(dbapi_connection)

    # retval=True: SQLAlchemy only uses the returned (statement, parameters)
    # with this flag; without it the rewrite was computed and thrown away (H6).
    @event.listens_for(engine_instance, "before_cursor_execute", retval=True)
    def before_execute(conn, cursor, statement, parameters, context, executemany):
        return _before_execute(conn, statement, parameters, context, config)
