"""DB Firewall: SQLAlchemy engine event hooks."""

import logging
from typing import Optional

from .context import TenantContext
from .db_context import _CONTEXT_SETTERS, pool_checkin
from .rewrite import check_no_tenant, rewrite_query
from .engines import detect_engine
from .config import load_config

logger = logging.getLogger("db_firewall")

def _apply_tenant(dbapi_connection):
    tenant = TenantContext.get()
    if tenant:
        db_engine = detect_engine(dbapi_connection)
        setter = _CONTEXT_SETTERS.get(db_engine)
        if setter:
            setter(dbapi_connection, tenant)


def _before_execute(conn, statement, parameters, context, config):
    tenant = TenantContext.get()
    dbapi_conn = conn.connection.dbapi_connection
    db_engine = detect_engine(dbapi_conn)

    if tenant and statement:
        new_statement = rewrite_query(statement, tenant, config, dbapi_conn, db_engine)
        if new_statement != statement:
            context._firewall_original = statement
        return new_statement, parameters

    if not tenant and config.get("fail_mode", "closed") == "closed":
        check_no_tenant(statement, config, dbapi_conn, db_engine)
    return statement, parameters


def sqlalchemy_event_hooks(engine_instance, config: Optional[dict] = None):
    """
    Attach tenant isolation to a SQLAlchemy engine.

    Usage:
        from sqlalchemy import create_engine
        from db_firewall import sqlalchemy_event_hooks

        engine = create_engine(...)
        sqlalchemy_event_hooks(engine)   # config read once here, not per query
    """
    from sqlalchemy import event
    if config is None:
        config = load_config()

    # Per-checkout, not per-connect: a pooled connection serves many tenants.
    # Postgres uses a transaction-local GUC, so it dies with the transaction.
    @event.listens_for(engine_instance, "checkout")
    def on_checkout(dbapi_connection, connection_record, connection_proxy):
        _apply_tenant(dbapi_connection)

    # ...and therefore it must be re-applied for every transaction a long-lived
    # Connection/Session opens after its first commit()/rollback(). SQLAlchemy
    # fires "begin" when it starts each new transaction. Setting the GUC twice
    # in one transaction (checkout, then begin) is harmless: same value.
    @event.listens_for(engine_instance, "begin")
    def on_begin(conn):
        _apply_tenant(conn.connection.dbapi_connection)

    @event.listens_for(engine_instance, "checkin")
    def on_checkin(dbapi_connection, connection_record):
        if dbapi_connection is not None:
            pool_checkin(dbapi_connection)

    # retval=True: SQLAlchemy only uses the returned (statement, parameters)
    # with this flag; without it the rewrite was computed and thrown away (H6).
    @event.listens_for(engine_instance, "before_cursor_execute", retval=True)
    def before_execute(conn, cursor, statement, parameters, context, executemany):
        return _before_execute(conn, statement, parameters, context, config)
