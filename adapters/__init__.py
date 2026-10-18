"""
DB Firewall — NoSQL adapters
============================
Tenant isolation wrappers for stores that have no SQL WHERE clause to rewrite.

    from adapters.mongodb import protect_collection, protect_database
    from adapters.redis import protect_redis, acl_rules_for
    from adapters.firestore import protect_firestore, generate_rules

Importing this package never imports a driver; each adapter imports its own
driver lazily (and only where it actually needs it).
"""

from ._common import TenantRequired, require_tenant, validate_tenant  # noqa: F401

__all__ = ["TenantRequired", "require_tenant", "validate_tenant"]
