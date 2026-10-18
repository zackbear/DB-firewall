"""Firestore adapter tests.

Runs against a small in-memory FAKE client (no emulator / google-cloud-firestore
needed). The fake mirrors the subset of the real API the adapter touches:
collection / document / where / order_by / limit / stream / get / set / update /
delete / add / collection_group / batch. It has NOT been run against the real
emulator; see README "NoSQL stores".
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from adapters import TenantRequired  # noqa: E402
from adapters.firestore import protect_firestore, generate_rules  # noqa: E402


# ----------------------------------------------------------------- fake client
class Snap:
    def __init__(self, ref, data):
        self.reference, self.id, self._d = ref, ref.id, data

    @property
    def exists(self):
        return self._d is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class Query:
    def __init__(self, client, paths_fn, filters=()):
        self._c, self._paths, self._filters = client, paths_fn, list(filters)

    def where(self, field, op, value):
        assert op == "=="
        return Query(self._c, self._paths, self._filters + [(field, value)])

    def order_by(self, *_a, **_k):
        return self

    def limit(self, *_a):
        return self

    def stream(self):
        for p in self._paths():
            d = self._c.store[p]
            if all(d.get(f) == v for f, v in self._filters):
                yield Snap(Doc(self._c, p), d)

    def get(self):
        return list(self.stream())


class Collection(Query):
    def __init__(self, client, path):
        self.path, self.id = path, path.rsplit("/", 1)[-1]
        depth = path.count("/") + 2
        super().__init__(client, lambda: sorted(
            p for p in client.store if p.startswith(path + "/") and p.count("/") == depth - 1))

    def document(self, doc_id=None):
        doc_id = doc_id or f"auto{len(self._c.store)}"
        return Doc(self._c, f"{self.path}/{doc_id}")

    def add(self, data, document_id=None):
        ref = self.document(document_id)
        ref.set(data)
        return None, ref


class Doc:
    def __init__(self, client, path):
        self._c, self.path, self.id = client, path, path.rsplit("/", 1)[-1]

    def get(self):
        return Snap(self, self._c.store.get(self.path))

    def set(self, data, merge=False):
        cur = self._c.store.get(self.path, {}) if merge else {}
        self._c.store[self.path] = {**cur, **data}

    def update(self, data):
        if self.path not in self._c.store:
            raise KeyError(self.path)
        self._c.store[self.path].update(data)

    def delete(self):
        self._c.store.pop(self.path, None)

    def collection(self, name):
        return Collection(self._c, f"{self.path}/{name}")


class Batch:
    def __init__(self):
        self.ops = []

    def set(self, ref, data, merge=False):
        self.ops.append(lambda: ref.set(data, merge=merge))

    def update(self, ref, data):
        self.ops.append(lambda: ref.update(data))

    def delete(self, ref):
        self.ops.append(lambda: ref.delete())

    def commit(self):
        for op in self.ops:
            op()


class FakeClient:
    def __init__(self):
        self.store = {}

    def collection(self, name):
        return Collection(self, name)

    def document(self, path):
        return Doc(self, path)

    def collection_group(self, name):
        return Query(self, lambda: sorted(
            p for p in self.store if p.rsplit("/", 2)[-2] == name))

    def batch(self):
        return Batch()

    def transaction(self):
        return object()


# -------------------------------------------------------------------- fixtures
@pytest.fixture
def client():
    return FakeClient()


def ids(stream):
    return sorted(s.id for s in stream)


# ---------------------------------------------------------- subcollection mode
class TestSubcollectionMode:
    def test_paths_are_scoped(self, client):
        a = protect_firestore(client, "A")
        a.collection("orders").document("o1").set({"total": 1})
        assert "tenants/A/orders/o1" in client.store
        b = protect_firestore(client, "B")
        assert not b.collection("orders").document("o1").get().exists
        assert ids(b.collection("orders").stream()) == []
        assert ids(a.collection("orders").stream()) == ["o1"]

    def test_b_cannot_update_or_delete_a(self, client):
        protect_firestore(client, "A").collection("orders").document("o1").set({"total": 1})
        b = protect_firestore(client, "B")
        b.collection("orders").document("o1").delete()  # deletes tenants/B/orders/o1: no-op
        assert client.store["tenants/A/orders/o1"] == {"total": 1}

    def test_collection_group_auto_filtered(self, client):
        protect_firestore(client, "A").collection("orders").document("o1").set({"tenant_id": "A"})
        protect_firestore(client, "B").collection("orders").document("o2").set({"tenant_id": "B"})
        client.store["tenants/B/orders/o3"] = {}  # no tenant field: invisible to everyone
        assert ids(protect_firestore(client, "A").collection_group("orders").stream()) == ["o1"]
        with pytest.raises(TenantRequired):
            protect_firestore(client, "A").collection_group("orders").where("tenant_id", "==", "B")

    def test_raw_access_blocked(self, client):
        a = protect_firestore(client, "A")
        for name in ("document", "transaction", "collections", "get_all"):
            with pytest.raises(TenantRequired):
                getattr(a, name)("tenants/B/orders/o1")
        with pytest.raises(TenantRequired):
            a.collection("../evil")

    def test_batch_scoped(self, client):
        a = protect_firestore(client, "A")
        batch = a.batch()
        batch.set(a.collection("orders").document("o1"), {"x": 1})
        with pytest.raises(TenantRequired):
            batch.set(client.document("tenants/B/orders/o1"), {"x": 1})
        batch.commit()
        assert client.store["tenants/A/orders/o1"] == {"x": 1, "tenant_id": "A"}

    @pytest.mark.parametrize("tenant", [None, "", "A/B", "A\n", 2.5])
    def test_bad_tenant_raises(self, client, tenant):
        with pytest.raises(TenantRequired):
            protect_firestore(client, tenant)


# ------------------------------------------------------------------ field mode
@pytest.fixture
def seeded(client):
    client.store.update({
        "orders/o1": {"tenant_id": "A", "total": 1},
        "orders/o2": {"tenant_id": "A", "total": 2},
        "orders/o3": {"tenant_id": "B", "total": 3},
    })
    return client


class TestFieldMode:
    def test_query_scoped(self, seeded):
        a = protect_firestore(seeded, "A", mode="field")
        assert ids(a.collection("orders").stream()) == ["o1", "o2"]
        assert ids(a.collection("orders").where("total", "==", 3).stream()) == []
        assert ids(a.collection("orders").order_by("total").limit(5).get()) == ["o1", "o2"]
        with pytest.raises(TenantRequired):
            a.collection("orders").where("tenant_id", "==", "B")

    def test_document_read_verified(self, seeded):
        a = protect_firestore(seeded, "A", mode="field")
        assert a.collection("orders").document("o1").get().to_dict()["total"] == 1
        assert a.collection("orders").document("o3").get() is None
        assert not a.collection("orders").document("nope").get().exists

    def test_writes_stamp_and_verify(self, seeded):
        a = protect_firestore(seeded, "A", mode="field")
        col = a.collection("orders")
        col.document("o9").set({"total": 9})
        assert seeded.store["orders/o9"]["tenant_id"] == "A"
        _, ref = col.add({"total": 10})
        assert seeded.store[ref.path]["tenant_id"] == "A"
        col.document("o1").update({"total": 11})
        assert seeded.store["orders/o1"]["total"] == 11
        for bad in (lambda: col.document("o3").set({"total": 0}),
                    lambda: col.document("o3").update({"total": 0}),
                    lambda: col.document("o3").delete(),
                    lambda: col.document("o1").set({"tenant_id": "B"}),
                    lambda: col.document("o1").update({"tenant_id": "B"}),
                    lambda: col.add({"tenant_id": "B"})):
            with pytest.raises(TenantRequired):
                bad()
        assert seeded.store["orders/o3"] == {"tenant_id": "B", "total": 3}
        col.document("o1").delete()
        assert "orders/o1" not in seeded.store

    def test_batch_field_mode(self, seeded):
        a = protect_firestore(seeded, "A", mode="field")
        col = a.collection("orders")
        batch = a.batch()
        batch.update(col.document("o1"), {"total": 5}).set(col.document("new"), {"z": 1})
        with pytest.raises(TenantRequired):
            batch.delete(col.document("o3"))
        with pytest.raises(TenantRequired):
            batch.delete(seeded.document("orders/o3"))  # raw ref refused in field mode
        batch.commit()
        assert seeded.store["orders/o1"]["total"] == 5
        assert seeded.store["orders/new"] == {"z": 1, "tenant_id": "A"}

    def test_query_unknown_method_blocked(self, seeded):
        a = protect_firestore(seeded, "A", mode="field")
        with pytest.raises(TenantRequired):
            a.collection("orders").list_documents()


# --------------------------------------------------------------- rules output
class TestRulesGenerator:
    def test_subcollection_rules(self):
        r = generate_rules(tenant_claim="org")
        assert "rules_version = '2';" in r
        assert "match /tenants/{tenantId}/{document=**}" in r
        assert "request.auth != null && request.auth.token.org == tenantId" in r
        assert "allow read, write: if false;" in r
        assert "if true" not in r

    def test_field_rules(self):
        r = generate_rules(collections=["orders", "customers"], mode="field", tenant_field="tenant_id")
        for c in ("orders", "customers"):
            assert f"match /{c}/{{docId}}" in r
        assert "allow read: if request.auth != null && resource.data.tenant_id == request.auth.token.tenant_id;" in r
        assert "allow create: if request.auth != null && request.resource.data.tenant_id == request.auth.token.tenant_id;" in r
        assert "allow update: if request.auth != null && resource.data.tenant_id == request.auth.token.tenant_id\n" in r
        assert "allow delete: if request.auth != null && resource.data.tenant_id == request.auth.token.tenant_id;" in r
        assert "allow read, write: if false;" in r
        with pytest.raises(ValueError):
            generate_rules(mode="field")  # collections required
