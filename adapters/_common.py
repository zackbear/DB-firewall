"""Shared helpers for the NoSQL adapters: fail-closed tenant checks."""

import re
from typing import Union

TenantId = Union[str, int]

# ASCII control chars (incl. NUL, newline, DEL) are never allowed in a tenant id.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Redis glob metacharacters plus our own separator; an id containing one of
# these could widen a `prefix:<id>:*` pattern or forge another tenant's prefix.
_REDIS_FORBIDDEN = set("*?[]:\\")


class TenantRequired(PermissionError):
    """Raised when an operation runs without a valid tenant, or would escape it."""


def require_tenant(tenant_id) -> TenantId:
    """Fail closed: None / '' / wrong type never silently become 'all tenants'."""
    if tenant_id is None or tenant_id == "":
        raise TenantRequired("tenant_id is required (fail closed)")
    return validate_tenant(tenant_id)


def validate_tenant(tenant_id, *, redis_safe: bool = False) -> TenantId:
    """Accept only str/int tenant ids without control characters.

    With ``redis_safe=True`` also reject glob and separator characters.
    """
    if isinstance(tenant_id, bool) or not isinstance(tenant_id, (str, int)):
        raise TenantRequired(f"tenant_id must be str or int, got {type(tenant_id).__name__}")
    s = str(tenant_id)
    if not s or _CONTROL.search(s):
        raise TenantRequired("tenant_id contains control characters or is empty")
    if redis_safe and (set(s) & _REDIS_FORBIDDEN):
        raise TenantRequired("tenant_id may not contain any of * ? [ ] : \\ (Redis glob/separator)")
    return tenant_id


def blocked(name: str, why: str = ""):
    """Return a method that always raises; used for explicitly denied operations."""

    def _raise(*_a, **_k):
        raise TenantRequired(f"'{name}' is blocked by DB Firewall{': ' + why if why else ''}")

    _raise.__name__ = name
    _raise.__doc__ = f"BLOCKED: {why or 'cannot be tenant-scoped'}"
    return _raise
