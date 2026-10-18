"""
DB Firewall — Firestore adapter
===============================
Two layers:

1. Middleware: ``protect_firestore(client, tenant_id, mode=...)``
   * ``mode="subcollection"`` (recommended) — every collection lives under
     ``tenants/<tenant>/<name>``; isolation is structural (path-based).
   * ``mode="field"`` — flat collections; every query gets
     ``where(tenant_field == tenant)`` and every doc read/write is verified.
2. Server-native: ``generate_rules(...)`` emits a ``firestore.rules`` file so the
   Firestore backend enforces the same boundary from the auth token claim.

    fs = protect_firestore(client, "TENANT_A")           # subcollection mode
    fs.collection("orders").document("o1").set({...})     # -> tenants/TENANT_A/orders/o1
    fs.document("orders/o1")                              # TenantRequired (raw path)

No driver import: the wrapper only calls methods on the client you pass in.
"""

from typing import Any, Dict, Iterable, Optional

from ._common import TenantRequired, require_tenant, blocked

MODES = ("subcollection", "field")


# ============================================================ field-mode wrappers
class FieldQuery:
    """Chainable query that always starts with ``where(tenant_field == tenant)``."""

    def __init__(self, query, tenant, field):
        self._q, self._t, self._f = query, tenant, field

    def _wrap(self, q):
        return FieldQuery(q, self._t, self._f)

    def where(self, *args, **kw):
        # Positional form: where(field, op, value) — refuse a foreign tenant value.
        if len(args) == 3 and args[0] == self._f and not (args[1] == "==" and args[2] == self._t):
            raise TenantRequired(f"where() may not filter {self._f!r} to a foreign value")
        return self._wrap(self._q.where(*args, **kw))

    def __getattr__(self, name):
        if name in ("order_by", "limit", "limit_to_last", "offset", "start_at", "start_after",
                    "end_at", "end_before", "select"):
            return lambda *a, **k: self._wrap(getattr(self._q, name)(*a, **k))
        if name in ("stream", "get", "count", "on_snapshot"):
            return getattr(self._q, name)
        if name.startswith("_"):
            raise AttributeError(name)
        raise TenantRequired(f"Query.{name} is not tenant-scoped; blocked")


class FieldCollection(FieldQuery):
    """Field-mode collection: scoped query + verified document access."""

    def __init__(self, col, tenant, field):
        super().__init__(col.where(field, "==", tenant), tenant, field)
        self._c = col

    @property
    def id(self):
        return self._c.id

    def document(self, doc_id: Optional[str] = None) -> "FieldDocument":
        return FieldDocument(self._c.document(doc_id) if doc_id else self._c.document(),
                             self._t, self._f)

    def add(self, data: Dict[str, Any], document_id: Optional[str] = None):
        return self._c.add(_stamp(data, self._t, self._f), document_id)


class FieldDocument:
    """Field-mode document: reads verify tenant_field after fetch, writes stamp/verify it."""

    def __init__(self, ref, tenant, field):
        self._d, self._t, self._f = ref, tenant, field

    @property
    def id(self):
        return self._d.id

    @property
    def path(self):
        return self._d.path

    def _owned(self) -> bool:
        """True if the doc is absent or belongs to this tenant; False if foreign."""
        snap = self._d.get()
        return (not snap.exists) or (snap.to_dict() or {}).get(self._f) == self._t

    def get(self, *a, **k):
        snap = self._d.get(*a, **k)
        if snap.exists and (snap.to_dict() or {}).get(self._f) != self._t:
            return None  # fail closed: foreign doc looks like it does not exist
        return snap

    def set(self, data: Dict[str, Any], merge: bool = False, **k):
        if not self._owned():
            raise TenantRequired("document belongs to another tenant")
        return self._d.set(_stamp(data, self._t, self._f), merge=merge, **k)

    def update(self, data: Dict[str, Any], **k):
        if self._f in data and data[self._f] != self._t:
            raise TenantRequired(f"update may not change {self._f!r}")
        if not self._owned():
            raise TenantRequired("document belongs to another tenant")
        return self._d.update(data, **k)

    def delete(self, **k):
        if not self._owned():
            raise TenantRequired("document belongs to another tenant")
        return self._d.delete(**k)

    def collection(self, name: str) -> FieldCollection:
        return FieldCollection(self._d.collection(name), self._t, self._f)

    @property
    def raw(self):
        """UNSCOPED DocumentReference. Admin use ONLY."""
        return self._d


def _stamp(data: Dict[str, Any], tenant, field) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise TenantRequired("data must be a dict")
    if field in data and data[field] != tenant:
        raise TenantRequired(f"data sets {field!r} to a foreign value")
    return {**data, field: tenant}


# ==================================================================== batch
class ProtectedBatch:
    """Write batch that only accepts tenant-owned refs and stamps data."""

    def __init__(self, batch, owner: "ProtectedFirestore"):
        self._b, self._o = batch, owner

    def _ref(self, ref, check_owner: bool):
        if isinstance(ref, FieldDocument):
            if check_owner and not ref._owned():
                raise TenantRequired("document belongs to another tenant")
            return ref.raw
        if self._o.mode == "subcollection" and getattr(ref, "path", "").startswith(self._o.root + "/"):
            return ref
        raise TenantRequired("batch only accepts refs obtained through the protected client")

    def set(self, ref, data, merge: bool = False):
        self._b.set(self._ref(ref, True), _stamp(data, self._o.tenant_id, self._o.tenant_field), merge=merge)
        return self

    def update(self, ref, data):
        if self._o.tenant_field in data and data[self._o.tenant_field] != self._o.tenant_id:
            raise TenantRequired(f"update may not change {self._o.tenant_field!r}")
        self._b.update(self._ref(ref, True), data)
        return self

    def delete(self, ref):
        self._b.delete(self._ref(ref, True))
        return self

    def commit(self, *a, **k):
        return self._b.commit(*a, **k)


# ================================================================== client
class ProtectedFirestore:
    def __init__(self, client, tenant_id, mode: str = "subcollection",
                 tenant_field: str = "tenant_id", tenants_collection: str = "tenants"):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self._c = client
        self.tenant_id = str(require_tenant(tenant_id))
        if "/" in self.tenant_id:
            raise TenantRequired("tenant_id may not contain '/' (path separator)")
        self.mode, self.tenant_field = mode, tenant_field
        self.root = f"{tenants_collection}/{self.tenant_id}"
        self._tenant_doc = client.collection(tenants_collection).document(self.tenant_id)

    @property
    def raw(self):
        """UNSCOPED Firestore client. Admin use ONLY."""
        return self._c

    def collection(self, name: str):
        if "/" in name:
            raise TenantRequired("collection name may not contain '/'")
        if self.mode == "subcollection":
            return self._tenant_doc.collection(name)  # structurally scoped reference
        return FieldCollection(self._c.collection(name), self.tenant_id, self.tenant_field)

    def collection_group(self, name: str):
        """Collection-group queries span ALL tenants, so a tenant_field filter is
        auto-applied in both modes. In subcollection mode this REQUIRES that every
        document also carries ``tenant_field`` (stamp it on write)."""
        return FieldQuery(self._c.collection_group(name).where(self.tenant_field, "==", self.tenant_id),
                          self.tenant_id, self.tenant_field)

    def batch(self) -> ProtectedBatch:
        return ProtectedBatch(self._c.batch(), self)

    document = blocked("document", "raw path access escapes the tenant; go through collection()")
    transaction = blocked("transaction", "unwrapped transactions can read/write any path")
    collections = blocked("collections", "lists root collections across tenants")

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        raise TenantRequired(f"Client.{name} is not tenant-scoped; blocked")


def protect_firestore(client, tenant_id, mode: str = "subcollection",
                      tenant_field: str = "tenant_id") -> ProtectedFirestore:
    """Return a tenant-scoped wrapper over a ``google.cloud.firestore.Client``."""
    return ProtectedFirestore(client, tenant_id, mode, tenant_field)


# ============================================================ security rules
def generate_rules(tenant_claim: str = "tenant_id", collections: Optional[Iterable[str]] = None,
                   mode: str = "subcollection", tenant_field: str = "tenant_id",
                   tenants_collection: str = "tenants") -> str:
    """Emit a ``firestore.rules`` file enforcing the tenant boundary server-side.

    The tenant comes from a custom auth claim (``request.auth.token.<tenant_claim>``),
    which must be set by trusted backend code, never by the client.
    Everything not matched explicitly is denied.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    claim = f"request.auth.token.{tenant_claim}"
    out = ["rules_version = '2';", "service cloud.firestore {", "  match /databases/{database}/documents {"]
    if mode == "subcollection":
        out += [
            f"    match /{tenants_collection}/{{tenantId}}/{{document=**}} {{",
            f"      allow read, write: if request.auth != null && {claim} == tenantId;",
            "    }",
        ]
    else:
        if not collections:
            raise ValueError("field mode needs an explicit list of collections")
        for name in collections:
            out += [
                f"    match /{name}/{{docId}} {{",
                f"      allow read: if request.auth != null && resource.data.{tenant_field} == {claim};",
                f"      allow create: if request.auth != null && request.resource.data.{tenant_field} == {claim};",
                f"      allow update: if request.auth != null && resource.data.{tenant_field} == {claim}",
                f"                    && request.resource.data.{tenant_field} == {claim};",
                f"      allow delete: if request.auth != null && resource.data.{tenant_field} == {claim};",
                "    }",
            ]
    out += ["    match /{document=**} {", "      allow read, write: if false;", "    }", "  }", "}"]
    return "\n".join(out) + "\n"
