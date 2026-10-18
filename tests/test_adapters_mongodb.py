"""MongoDB adapter tests — run against mongomock (no mongod needed)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
mongomock = pytest.importorskip("mongomock")
from pymongo import InsertOne, UpdateOne, DeleteMany  # noqa: E402

from adapters import TenantRequired  # noqa: E402
from adapters.mongodb import protect_collection, protect_database  # noqa: E402


@pytest.fixture
def raw():
    col = mongomock.MongoClient().db.orders
    col.insert_many([
        {"_id": 1, "tenant_id": "A", "status": "open", "total": 10},
        {"_id": 2, "tenant_id": "A", "status": "closed", "total": 20},
        {"_id": 3, "tenant_id": "B", "status": "open", "total": 99},
    ])
    return col


@pytest.fixture
def a(raw):
    return protect_collection(raw, "A")


@pytest.fixture
def b(raw):
    return protect_collection(raw, "B")


class TestReads:
    def test_find_scoped(self, a):
        assert {d["_id"] for d in a.find()} == {1, 2}
        assert {d["_id"] for d in a.find({"status": "open"})} == {1}

    def test_find_one_foreign_id_is_none(self, a):
        assert a.find_one({"_id": 3}) is None
        assert a.find_one(3) is None

    def test_counts(self, a, b):
        assert a.count_documents({}) == 2
        assert b.count_documents({}) == 1
        assert a.estimated_document_count() == 2

    def test_distinct(self, a):
        assert sorted(a.distinct("status")) == ["closed", "open"]
        assert a.distinct("total") == [10, 20]

    def test_or_cannot_widen(self, a):
        docs = list(a.find({"$or": [{"tenant_id": "A"}, {"total": 99}]}))
        assert {d["_id"] for d in docs} == {1, 2}

    def test_filter_naming_foreign_tenant_raises(self, a):
        with pytest.raises(TenantRequired):
            a.find({"tenant_id": "B"})
        with pytest.raises(TenantRequired):
            a.find({"tenant_id": {"$in": ["A", "B"]}})
        with pytest.raises(TenantRequired):
            a.find({"$or": [{"tenant_id": "B"}]})

    def test_aggregate_scoped(self, a):
        out = list(a.aggregate([{"$group": {"_id": None, "sum": {"$sum": "$total"}}}]))
        assert out[0]["sum"] == 30

    @pytest.mark.parametrize("stage", ["$lookup", "$unionWith", "$graphLookup", "$merge", "$out", "$facet"])
    def test_aggregate_cross_stages_blocked(self, a, stage):
        with pytest.raises(TenantRequired):
            a.aggregate([{stage: {}}])

    def test_aggregate_cross_stage_allowed_with_flag(self, a):
        # mongomock may not implement every stage; we only assert the firewall lets it through.
        try:
            a.aggregate([{"$out": "x"}], allow_cross_collection=True)
        except TenantRequired:
            pytest.fail("flag should bypass the stage block")
        except Exception:
            pass


class TestWrites:
    def test_insert_stamps(self, a, raw):
        a.insert_one({"_id": 4, "total": 1})
        assert raw.find_one({"_id": 4})["tenant_id"] == "A"
        a.insert_many([{"_id": 5}, {"_id": 6, "tenant_id": "A"}])
        assert raw.count_documents({"tenant_id": "A"}) == 5

    def test_insert_foreign_tenant_raises(self, a):
        with pytest.raises(TenantRequired):
            a.insert_one({"tenant_id": "B"})
        with pytest.raises(TenantRequired):
            a.insert_many([{"x": 1}, {"tenant_id": "B"}])

    def test_update_cannot_touch_foreign(self, a, raw):
        a.update_many({}, {"$set": {"status": "x"}})
        assert raw.find_one({"_id": 3})["status"] == "open"
        r = a.update_one({"_id": 3}, {"$set": {"status": "x"}})
        assert r.matched_count == 0

    @pytest.mark.parametrize("update", [
        {"$set": {"tenant_id": "B"}},
        {"$unset": {"tenant_id": ""}},
        {"$rename": {"tenant_id": "old"}},
        {"$rename": {"foo": "tenant_id"}},
        {"$set": {"tenant_id.sub": 1}},
        {"$inc": {"tenant_id": 1}},
    ])
    def test_update_tenant_field_override_raises(self, a, update):
        with pytest.raises(TenantRequired):
            a.update_one({"_id": 1}, update)

    def test_pipeline_update_rejected(self, a):
        with pytest.raises(TenantRequired):
            a.update_one({"_id": 1}, [{"$set": {"x": 1}}])

    def test_upsert_stamps_tenant(self, a, raw):
        # mongomock does not lift _id out of $and on upsert (real MongoDB does),
        # so look the row up by its payload.
        a.update_one({"_id": 10}, {"$set": {"x": 1}}, upsert=True)
        assert raw.find_one({"x": 1})["tenant_id"] == "A"

    def test_replace_stamps_and_rejects_foreign(self, a, raw):
        a.replace_one({"_id": 1}, {"total": 5})
        assert raw.find_one({"_id": 1}) == {"_id": 1, "total": 5, "tenant_id": "A"}
        with pytest.raises(TenantRequired):
            a.replace_one({"_id": 1}, {"tenant_id": "B"})

    def test_delete_scoped(self, a, raw):
        a.delete_many({})
        assert raw.count_documents({}) == 1
        assert raw.find_one()["tenant_id"] == "B"

    def test_find_one_and_x(self, a, raw):
        assert a.find_one_and_update({"_id": 3}, {"$set": {"x": 1}}) is None
        assert a.find_one_and_delete({"_id": 3}) is None
        assert a.find_one_and_replace({"_id": 1}, {"z": 1})["_id"] == 1
        assert raw.find_one({"_id": 1})["tenant_id"] == "A"
        with pytest.raises(TenantRequired):
            a.find_one_and_update({"_id": 1}, {"$set": {"tenant_id": "B"}})

    def test_bulk_write_scoped(self, a, raw, monkeypatch):
        # mongomock 4.3 predates pymongo 4.19's bulk `sort` kwarg; apply the
        # rewritten ops by hand so we test the firewall's scoping, not mongomock.
        def apply(ops, *a_, **k_):
            for op in ops:
                if isinstance(op, InsertOne):
                    raw.insert_one(op._doc)
                elif isinstance(op, UpdateOne):
                    raw.update_one(op._filter, op._doc, upsert=bool(op._upsert))
                elif isinstance(op, DeleteMany):
                    raw.delete_many(op._filter)
        monkeypatch.setattr(raw, "bulk_write", apply)
        a.bulk_write([
            InsertOne({"_id": 7}),
            UpdateOne({"_id": 3}, {"$set": {"status": "hacked"}}),
            DeleteMany({"status": "open"}),
        ])
        assert raw.find_one({"_id": 7})["tenant_id"] == "A"
        assert raw.find_one({"_id": 3})["status"] == "open"   # B untouched
        assert raw.find_one({"_id": 1}) is None               # A's open order deleted
        with pytest.raises(TenantRequired):
            a.bulk_write([InsertOne({"tenant_id": "B"})])


class TestFailClosed:
    @pytest.mark.parametrize("tenant", [None, "", "a\nb", 1.5, True, ["A"]])
    def test_bad_tenant_raises(self, raw, tenant):
        with pytest.raises(TenantRequired):
            protect_collection(raw, tenant)

    def test_int_tenant_ok(self, raw):
        raw.insert_one({"tenant_id": 7, "v": 1})
        assert protect_collection(raw, 7).count_documents({}) == 1

    @pytest.mark.parametrize("name", ["drop", "rename", "watch", "map_reduce", "create_index", "options"])
    def test_unwrapped_methods_blocked(self, a, name):
        with pytest.raises(TenantRequired):
            getattr(a, name)()

    def test_database_property_blocked(self, a):
        with pytest.raises(TenantRequired):
            a.database

    def test_raw_escape_hatch_is_explicit(self, a, raw):
        assert a.raw is raw

    def test_protect_database(self, raw):
        db = protect_database(raw.database, "B")
        assert db["orders"].count_documents({}) == 1
        assert db.orders.count_documents({}) == 1
        with pytest.raises(TenantRequired):
            db["system.users"]
        with pytest.raises(TenantRequired):
            protect_database(raw.database, None)
