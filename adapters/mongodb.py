"""
DB Firewall — MongoDB adapter
=============================
Wraps a pymongo ``Collection`` so every read/write is confined to one tenant.

    from adapters.mongodb import protect_collection, protect_database
    orders = protect_collection(db.orders, tenant_id="TENANT_A")
    orders.find({"status": "open"})        # -> {'$and': [{'tenant_id': 'TENANT_A'}, {...}]}
    orders.insert_one({"total": 5})        # tenant_id stamped automatically

Enforcement is middleware-only: MongoDB has no row-level security, so the
second layer must be per-tenant databases/credentials or field-level
encryption. Keep admin credentials away from agents.

No driver import is needed: the wrapper only touches the object you pass in.
"""

from typing import Any, Dict, Iterable, List, Optional

from ._common import TenantRequired, require_tenant, blocked

# Stages that read other collections or write; only allowed with an explicit flag.
CROSS_STAGES = frozenset({"$lookup", "$unionWith", "$graphLookup", "$merge", "$out", "$facet"})


class ProtectedCollection:
    """Tenant-scoped view of a collection. Unlisted methods do not exist (fail closed)."""

    def __init__(self, collection, tenant_id, tenant_field: str = "tenant_id"):
        self._c = collection
        self._t = require_tenant(tenant_id)
        self._f = tenant_field

    # ------------------------------------------------------------------ helpers
    @property
    def raw(self):
        """UNSCOPED collection. Bypasses every tenant check. Admin/migration use ONLY."""
        return self._c

    @property
    def tenant_id(self):
        return self._t

    @property
    def name(self) -> str:
        return self._c.name

    def _touches_tenant_field(self, key: str) -> bool:
        return key == self._f or key.startswith(self._f + ".")

    def _check_filter(self, flt: Any) -> None:
        """Reject filters that mention tenant_field with anything but our tenant."""
        if isinstance(flt, dict):
            for k, v in flt.items():
                if self._touches_tenant_field(k) and v != self._t:
                    raise TenantRequired(f"filter sets {self._f!r} to a foreign value")
                self._check_filter(v)
        elif isinstance(flt, (list, tuple)):
            for item in flt:
                self._check_filter(item)

    def _scope(self, flt: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """{'$and': [tenant, user]} — a user key or $or can never override ours."""
        flt = flt or {}
        if not isinstance(flt, dict):
            raise TenantRequired("filter must be a dict")
        self._check_filter(flt)
        return {"$and": [{self._f: self._t}, flt]} if flt else {self._f: self._t}

    def _stamp(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of doc with tenant_field set; reject foreign values."""
        if not isinstance(doc, dict):
            raise TenantRequired("document must be a dict")
        if self._f in doc and doc[self._f] != self._t:
            raise TenantRequired(f"document sets {self._f!r} to a foreign value")
        out = dict(doc)
        out[self._f] = self._t
        return out

    def _check_update(self, update: Any, upsert: bool = False) -> Any:
        """Validate an update spec; add $setOnInsert tenant stamp for upserts."""
        if isinstance(update, list):
            raise TenantRequired("aggregation-pipeline updates are not supported by the firewall")
        if not isinstance(update, dict):
            raise TenantRequired("update must be a dict")
        sets_tenant = False
        for op, spec in update.items():
            if not isinstance(spec, dict):
                continue
            for k, v in spec.items():
                if self._touches_tenant_field(k):
                    if op in ("$set", "$setOnInsert") and k == self._f and v == self._t:
                        sets_tenant = True
                        continue
                    raise TenantRequired(f"update {op} may not modify {self._f!r}")
                if op == "$rename" and self._touches_tenant_field(str(v)):
                    raise TenantRequired(f"$rename may not target {self._f!r}")
        if upsert and not sets_tenant:
            update = dict(update)
            update["$setOnInsert"] = {**update.get("$setOnInsert", {}), self._f: self._t}
        return update

    # -------------------------------------------------------------------- reads
    def find(self, filter=None, *args, **kw):
        return self._c.find(self._scope(filter), *args, **kw)

    def find_one(self, filter=None, *args, **kw):
        if filter is not None and not isinstance(filter, dict):  # find_one(ObjectId)
            filter = {"_id": filter}
        return self._c.find_one(self._scope(filter), *args, **kw)

    def count_documents(self, filter=None, *args, **kw):
        return self._c.count_documents(self._scope(filter), *args, **kw)

    def estimated_document_count(self, **kw):
        """Routed to count_documents: the estimate is collection-wide, not per tenant."""
        return self._c.count_documents(self._scope(None))

    def distinct(self, key, filter=None, *args, **kw):
        return self._c.distinct(key, self._scope(filter), *args, **kw)

    def aggregate(self, pipeline: Iterable[Dict[str, Any]], *args,
                  allow_cross_collection: bool = False, **kw):
        """Prepends a tenant $match. $lookup/$unionWith/$graphLookup/$facet/$merge/$out
        are refused unless ``allow_cross_collection=True``: they read other
        collections (which the firewall cannot scope) or write results out."""
        pipeline = list(pipeline)
        for stage in pipeline:
            if not isinstance(stage, dict) or len(stage) != 1:
                raise TenantRequired("malformed aggregation stage")
            (name,) = stage
            if name in CROSS_STAGES and not allow_cross_collection:
                raise TenantRequired(f"{name} is blocked: it reaches other collections or writes")
        return self._c.aggregate([{"$match": {self._f: self._t}}] + pipeline, *args, **kw)

    # ------------------------------------------------------------------- writes
    def insert_one(self, document, *args, **kw):
        return self._c.insert_one(self._stamp(document), *args, **kw)

    def insert_many(self, documents, *args, **kw):
        return self._c.insert_many([self._stamp(d) for d in documents], *args, **kw)

    def update_one(self, filter, update, upsert=False, *args, **kw):
        return self._c.update_one(self._scope(filter), self._check_update(update, upsert),
                                  upsert, *args, **kw)

    def update_many(self, filter, update, upsert=False, *args, **kw):
        return self._c.update_many(self._scope(filter), self._check_update(update, upsert),
                                   upsert, *args, **kw)

    def replace_one(self, filter, replacement, upsert=False, *args, **kw):
        return self._c.replace_one(self._scope(filter), self._stamp(replacement), upsert, *args, **kw)

    def delete_one(self, filter, *args, **kw):
        return self._c.delete_one(self._scope(filter), *args, **kw)

    def delete_many(self, filter, *args, **kw):
        return self._c.delete_many(self._scope(filter), *args, **kw)

    def find_one_and_update(self, filter, update, *args, upsert=False, **kw):
        return self._c.find_one_and_update(self._scope(filter), self._check_update(update, upsert),
                                           *args, upsert=upsert, **kw)

    def find_one_and_replace(self, filter, replacement, *args, **kw):
        return self._c.find_one_and_replace(self._scope(filter), self._stamp(replacement), *args, **kw)

    def find_one_and_delete(self, filter, *args, **kw):
        return self._c.find_one_and_delete(self._scope(filter), *args, **kw)

    def bulk_write(self, requests: List[Any], *args, **kw):
        """Rebuilds each pymongo operation with a scoped filter / stamped document."""
        from pymongo.operations import (  # lazy: only needed for bulk ops
            DeleteMany, DeleteOne, InsertOne, ReplaceOne, UpdateMany, UpdateOne,
        )
        out = []
        for op in requests:
            if isinstance(op, InsertOne):
                out.append(InsertOne(self._stamp(op._doc)))
            elif isinstance(op, (UpdateOne, UpdateMany)):
                up = op._upsert or False
                out.append(type(op)(self._scope(op._filter), self._check_update(op._doc, up),
                                    upsert=up, array_filters=op._array_filters,
                                    collation=op._collation, hint=op._hint))
            elif isinstance(op, ReplaceOne):
                out.append(ReplaceOne(self._scope(op._filter), self._stamp(op._doc),
                                      upsert=op._upsert or False, collation=op._collation,
                                      hint=op._hint))
            elif isinstance(op, (DeleteOne, DeleteMany)):
                out.append(type(op)(self._scope(op._filter), collation=op._collation, hint=op._hint))
            else:
                raise TenantRequired(f"unsupported bulk op {type(op).__name__}")
        return self._c.bulk_write(out, *args, **kw)

    # ------------------------------------------------------------------ blocked
    drop = blocked("drop", "destroys all tenants' data")
    rename = blocked("rename", "collection-wide operation")
    watch = blocked("watch", "change streams cannot be reliably tenant-scoped")
    map_reduce = blocked("map_reduce", "runs arbitrary JS over the whole collection")
    database = property(blocked("database", "escapes the collection; use protect_database"))

    def __getattr__(self, item):
        # Only reached for names not defined above: fail closed instead of leaking the raw object.
        if item.startswith("_"):  # dunder/private probes (copy, repr helpers) get a normal miss
            raise AttributeError(item)
        raise TenantRequired(f"Collection.{item} is not tenant-scoped; use .raw explicitly if intended")


class ProtectedDatabase:
    """``db["name"]`` / ``db.name`` return ProtectedCollection objects."""

    def __init__(self, db, tenant_id, tenant_field: str = "tenant_id"):
        self._db, self._t, self._f = db, require_tenant(tenant_id), tenant_field

    def __getitem__(self, name: str) -> ProtectedCollection:
        if name.startswith("system."):
            raise TenantRequired("system collections are blocked")
        return ProtectedCollection(self._db[name], self._t, self._f)

    def __getattr__(self, name: str) -> ProtectedCollection:
        if name.startswith("_"):
            raise AttributeError(name)
        return self[name]

    @property
    def raw(self):
        """UNSCOPED database. Admin/migration use ONLY."""
        return self._db


def protect_collection(collection, tenant_id, tenant_field: str = "tenant_id") -> ProtectedCollection:
    """Return a tenant-scoped wrapper over a pymongo (or mongomock) collection."""
    return ProtectedCollection(collection, tenant_id, tenant_field)


def protect_database(db, tenant_id, tenant_field: str = "tenant_id") -> ProtectedDatabase:
    """Return a wrapper whose collections are all tenant-scoped."""
    return ProtectedDatabase(db, tenant_id, tenant_field)
