"""DB Firewall: Framework integrations: Django, FastAPI, Flask."""

import logging
import uuid
from typing import Optional

from .context import TenantContext
from .config import load_config
from .rewrite import validate_tenant_id
from .streams import _scope_streaming

logger = logging.getLogger("db_firewall")

# ============================================================================
# FRAMEWORK INTEGRATIONS
# ============================================================================

TENANT_HEADER = "X-Tenant-ID"


def _trust_header(trust_tenant_header: Optional[bool]) -> bool:
    """Explicit argument wins; otherwise the trust_tenant_header config key (default off)."""
    config = load_config()
    if config.get("fail_mode") == "open":
        logger.warning("DB Firewall: web integration with fail_mode=open: requests without "
                       "a verified tenant run UNSCOPED. Use fail_mode=closed in production.")
    if trust_tenant_header is not None:
        return bool(trust_tenant_header)
    return bool(config.get("trust_tenant_header", False))


_warned_untrusted_header = False


def _request_tenant(verified, headers, trust_header: bool) -> Optional[str]:
    """Pick the tenant for one web request.

    The verified source (session, JWT claim, auth layer) wins. The X-Tenant-ID
    header is used only when trusted. The query string is never used. An
    invalid value returns None; callers set that None for the whole request,
    so it fails closed even when some other tenant is already in the context.
    """
    global _warned_untrusted_header
    tenant = verified
    if tenant is None and headers.get(TENANT_HEADER) is not None:
        if trust_header:
            tenant = headers.get(TENANT_HEADER)
        elif not _warned_untrusted_header:
            _warned_untrusted_header = True
            logger.warning("DB Firewall: X-Tenant-ID header ignored (trust_tenant_header is off). "
                           "Pass tenant_id_source=... or enable trust behind an auth gateway.")
    if tenant is None or tenant == "":
        return None
    # JWT / session ids may be int or UUID. Anything else (bool, bytes, list) is a bug upstream.
    if isinstance(tenant, bool) or not isinstance(tenant, (str, int, uuid.UUID)):
        logger.warning(f"DB Firewall: ignoring tenant id of type {type(tenant).__name__}")
        return None
    try:
        return validate_tenant_id(str(tenant))
    except ValueError as e:
        logger.warning(f"DB Firewall: ignoring invalid tenant id from request: {e}")
        return None


def _django_default_source(request):
    tenant = getattr(request, "tenant_id", None)
    if tenant is None:
        session = getattr(request, "session", None)
        tenant = session.get("tenant_id") if session is not None else None
    return tenant


class _DjangoTenantMiddleware:
    """Base for django_middleware_class(); the subclass sets _source and _trust."""
    # Django runs a sync+async capable middleware natively in either mode.
    sync_capable = True
    async_capable = True

    def __init__(self, get_response):
        from asgiref.sync import iscoroutinefunction, markcoroutinefunction
        self.get_response = get_response
        self._async = iscoroutinefunction(get_response)
        if self._async:
            markcoroutinefunction(self)
        elif iscoroutinefunction(self._source):
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured(
                "DB Firewall: an async tenant_id_source needs the middleware to run in "
                "async mode (ASGI, with only async-capable middleware after it).")

    def __call__(self, request):
        if self._async:
            return self.__acall__(request)
        tenant = _request_tenant(self._source(request), request.headers, self._trust)
        # Enter even when None: hides any tenant left in this context.
        token = TenantContext.enter(tenant)
        try:
            response = self.get_response(request)
        finally:
            TenantContext.exit(token)   # runs even when the view raises
        return _scope_streaming(response, tenant)

    async def __acall__(self, request):
        from asgiref.sync import iscoroutinefunction, sync_to_async
        # A sync source may touch the session (a database read): run it off the event loop.
        verified = (await self._source(request) if iscoroutinefunction(self._source)
                    else await sync_to_async(self._source)(request))
        tenant = _request_tenant(verified, request.headers, self._trust)
        token = TenantContext.enter(tenant)
        try:
            response = await self.get_response(request)
        finally:
            TenantContext.exit(token)
        return _scope_streaming(response, tenant)


def django_middleware_class(tenant_id_source=None, trust_tenant_header: Optional[bool] = None):
    """
    Returns a Django middleware class that sets tenant context per-request.

    Usage (Django settings take a dotted path, not a call):
        # myapp/middleware.py
        TenantMiddleware = django_middleware_class()
        # settings.py
        MIDDLEWARE = [..., 'myapp.middleware.TenantMiddleware']

    tenant_id_source: callable(request) -> tenant id from a verified source.
        Default: request.tenant_id (set by your auth middleware) or session["tenant_id"].
    trust_tenant_header: also accept X-Tenant-ID when no verified tenant is
        found. Only for a gateway that sets it after auth. Default: config key.
    """
    source = tenant_id_source or _django_default_source
    trust = _trust_header(trust_tenant_header)

    return type("DBFirewallMiddleware", (_DjangoTenantMiddleware,),
                {"_source": staticmethod(source), "_trust": trust})


def fastapi_middleware(app, tenant_id_source=None, trust_tenant_header: Optional[bool] = None):
    """
    FastAPI (or Starlette) middleware that sets tenant context per-request.

    Usage:
        from db_firewall import fastapi_middleware
        fastapi_middleware(app, tenant_id_source=lambda req: req.state.user.tenant_id)

    tenant_id_source: callable(request) -> tenant id from a verified source.
        Default: request.state.tenant_id (set by your auth middleware).
    trust_tenant_header: also accept X-Tenant-ID when no verified tenant is
        found. Only for a gateway that sets it after auth. Default: config key.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    source = tenant_id_source or (lambda req: getattr(req.state, "tenant_id", None))
    trust = _trust_header(trust_tenant_header)

    class TenantMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            # Enter even when None: hides any tenant left in this context.
            token = TenantContext.enter(_request_tenant(source(request), request.headers, trust))
            try:
                return await call_next(request)
            finally:
                TenantContext.exit(token)

    app.add_middleware(TenantMiddleware)


def _flask_default_source():
    from flask import g, session
    tenant = getattr(g, "tenant_id", None)
    return session.get("tenant_id") if tenant is None else tenant


def flask_hooks(app, tenant_id_source=None, trust_tenant_header: Optional[bool] = None):
    """
    Flask before/after request hooks for tenant isolation.

    Usage:
        from db_firewall import flask_hooks
        flask_hooks(app, tenant_id_source=lambda: g.tenant_id)

    tenant_id_source: callable() -> tenant id from a verified source.
        Default: g.tenant_id (set by your auth hook) or session["tenant_id"].
        Call flask_hooks() AFTER registering your auth before_request hook,
        and on the app, not a blueprint: blueprint hooks run too late.
    Streaming responses: Flask runs teardown before the body is read, so a
    streaming generator must open its own tenant_scope(tenant) or use
    protect(conn, tenant_id=...).
    trust_tenant_header: also accept X-Tenant-ID when no verified tenant is
        found. Only for a gateway that sets it after auth. Default: config key.
    """
    source = tenant_id_source or _flask_default_source
    trust = _trust_header(trust_tenant_header)

    @app.before_request
    def set_tenant_from_request():
        from flask import request, g
        # Enter even when None: hides any tenant left in this context.
        g._firewall_token = TenantContext.enter(_request_tenant(source(), request.headers, trust))

    @app.teardown_request
    def clear_tenant_after_request(exception=None):
        from flask import g
        TenantContext.exit(g.pop("_firewall_token", None))
