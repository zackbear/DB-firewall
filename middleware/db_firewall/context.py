"""DB Firewall: Request-scoped tenant context (ContextVar) and its helpers."""

import logging
import contextvars
from typing import Optional
from contextlib import contextmanager

logger = logging.getLogger("db_firewall")

# ============================================================================
# TENANT CONTEXT MANAGER
# ============================================================================

_TENANT_VAR: contextvars.ContextVar = contextvars.ContextVar("db_firewall_tenant", default=None)


class TenantContext:
    """Request-scoped tenant store.

    A ContextVar keeps each thread AND each asyncio task separate. threading.local
    did not: two async requests on one event-loop thread overwrote each other's
    tenant, and sync endpoints run in a thread pool never saw it at all.
    """

    @classmethod
    def set(cls, tenant_id: str):
        _TENANT_VAR.set(tenant_id)

    @classmethod
    def get(cls) -> Optional[str]:
        return _TENANT_VAR.get()

    @classmethod
    def clear(cls):
        _TENANT_VAR.set(None)

    @classmethod
    def enter(cls, tenant_id: Optional[str]) -> contextvars.Token:
        """Set exactly this tenant (None included) for a scope; hides any
        ambient value. Pair with exit(token)."""
        return _TENANT_VAR.set(tenant_id)

    @classmethod
    def exit(cls, token: Optional[contextvars.Token]) -> None:
        """Restore the tenant that was set before enter(). A token from another
        context cannot be reset, so fail closed by clearing instead."""
        if token is None:
            return
        try:
            _TENANT_VAR.reset(token)
        except (ValueError, RuntimeError) as e:
            logger.warning(f"DB Firewall: tenant scope ended in a different context ({e}); "
                           "clearing the tenant here (fail closed)")
            _TENANT_VAR.set(None)

    @classmethod
    def require(cls) -> str:
        tenant = cls.get()
        if not tenant:
            raise PermissionError("DB Firewall: No tenant context set. Access denied.")
        return tenant


def set_tenant(tenant_id: str):
    """Set tenant for the current request context (thread or asyncio task)."""
    TenantContext.set(tenant_id)


def get_tenant() -> Optional[str]:
    """Get the tenant of the current request context."""
    return TenantContext.get()


def clear_tenant():
    """Clear the tenant of the current request context."""
    TenantContext.clear()


@contextmanager
def tenant_scope(tenant_id: str):
    """Context manager for tenant isolation. Restores the outer tenant on exit,
    so nested scopes and scopes inside a request do not wipe it."""
    token = TenantContext.enter(tenant_id)
    try:
        yield
    finally:
        TenantContext.exit(token)
