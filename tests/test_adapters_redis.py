"""Redis adapter tests — need a real Redis (default localhost:6390, override REDIS_URL).

    redis-server --port 6390 --daemonize yes --save '' --appendonly no
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
redis = pytest.importorskip("redis")

from adapters import TenantRequired  # noqa: E402
from adapters.redis import protect_redis, acl_rules_for, acl_setuser_args  # noqa: E402

URL = os.environ.get("REDIS_URL", "redis://localhost:6390/0")


@pytest.fixture(scope="module")
def admin():
    r = redis.Redis.from_url(URL, decode_responses=True)
    try:
        r.ping()
    except Exception:
        pytest.skip(f"no Redis at {URL}")
    r.flushall()
    yield r
    r.flushall()


@pytest.fixture
def a(admin):
    return protect_redis(admin, "A")


@pytest.fixture
def b(admin):
    return protect_redis(admin, "B")


class TestIsolation:
    def test_a_writes_b_cannot_read(self, a, b, admin):
        a.set("cart", "apples")
        assert a.get("cart") == "apples"
        assert b.get("cart") is None
        assert admin.get("tenant:A:cart") == "apples"

    def test_delete_exists_mget_mset(self, a, b):
        a.mset({"k1": "1", "k2": "2"})
        assert a.mget("k1", "k2") == ["1", "2"]
        assert b.mget("k1", "k2") == [None, None]
        assert a.exists("k1", "k2") == 2
        assert b.delete("k1", "k2") == 0
        assert a.delete("k1", "k2") == 2

    def test_hash_list_set_zset(self, a, b):
        a.hset("h", "f", "v")
        assert a.hgetall("h") == {"f": "v"} and b.hgetall("h") == {}
        a.rpush("l", "x", "y")
        assert a.lrange("l", 0, -1) == ["x", "y"] and b.lrange("l", 0, -1) == []
        a.sadd("s", "m")
        assert a.smembers("s") == {"m"} and b.smembers("s") == set()
        a.zadd("z", {"m": 1})
        assert a.zrange("z", 0, -1) == ["m"] and b.zrange("z", 0, -1) == []
        assert a.incr("n") == 1 and b.incr("n") == 1
        a.expire("n", 100)
        assert a.ttl("n") > 0 and b.ttl("n") == -1

    def test_rename_stays_in_tenant(self, a, admin):
        a.set("old", "1")
        a.rename("old", "new")
        assert admin.get("tenant:A:new") == "1"

    def test_keys_and_scan_confined(self, a, b, admin):
        a.set("p1", "1"); a.set("p2", "2"); b.set("p1", "b")
        assert sorted(a.keys("p*")) == ["p1", "p2"]
        assert sorted(a.keys("*")) == sorted(a.keys("*"))  # confined, stripped names
        assert "tenant:B:p1" not in a.keys("*")
        _, found = a.scan(0, match="*", count=1000)
        assert set(found) >= {"p1", "p2"} and not any(k.startswith("tenant:B") for k in found)
        assert set(a.scan_iter(match="p?")) == {"p1", "p2"}
        # a pattern like "*" cannot escape: it is prefixed, not appended
        assert all(admin.exists(f"tenant:A:{k}") for k in a.keys("*"))

    def test_bytes_keys(self, admin):
        r = protect_redis(redis.Redis.from_url(URL), "A")
        r.set(b"bk", b"v")
        assert r.get(b"bk") == b"v" and admin.get("tenant:A:bk") == "v"

    def test_pipeline(self, a, b):
        p = a.pipeline()
        assert p.set("pk", "1").incr("pc") is p  # chaining returns wrapper
        p.execute()
        assert a.get("pk") == "1" and b.get("pk") is None
        with pytest.raises(TenantRequired):
            a.pipeline().flushdb()
        with pytest.raises(TenantRequired):
            a.pipeline().scan()  # same rules apply inside a pipeline
        with pytest.raises(TenantRequired):
            a.execute()


class TestBlocked:
    @pytest.mark.parametrize("name", ["flushdb", "flushall", "eval", "evalsha", "script_load",
                                      "config_get", "dbsize", "randomkey", "migrate", "move",
                                      "swapdb", "select", "info", "acl_setuser", "client_list",
                                      "publish", "bgsave"])
    def test_blocked_commands_raise(self, a, name):
        with pytest.raises(TenantRequired):
            getattr(a, name)("x")

    def test_scan_without_pattern_blocked(self, a):
        with pytest.raises(TenantRequired):
            a.scan()
        with pytest.raises(TenantRequired):
            list(a.scan_iter())

    def test_execute_command_unknown_blocked(self, a):
        with pytest.raises(TenantRequired):
            a.execute_command("FLUSHALL")
        with pytest.raises(TenantRequired):
            a.execute_command("KEYS", "*")  # execute_command only allows plain key commands
        a.execute_command("SET", "ec", "1")
        assert a.execute_command("GET", "ec") == "1"
        assert a.execute_command("DEL", "ec") == 1

    @pytest.mark.parametrize("tenant", [None, "", "A*", "A?", "A[", "A:B", "A\\", "A\n", 1.5])
    def test_bad_tenant_raises(self, admin, tenant):
        with pytest.raises(TenantRequired):
            protect_redis(admin, tenant)

    def test_bad_prefix_raises(self, admin):
        with pytest.raises(TenantRequired):
            protect_redis(admin, "A", prefix="t:*")

    def test_raw_is_explicit(self, a, admin):
        assert a.raw is admin


class TestACL:
    def test_rule_string(self):
        rule = acl_rules_for("A")
        assert rule.startswith("on ~tenant:A:* ")
        for frag in ("+@all", "-@dangerous", "-keys", "-flushdb", "-flushall", "-eval"):
            assert frag in rule
        with pytest.raises(TenantRequired):
            acl_rules_for("A*")

    def test_server_side_acl_isolation(self, admin):
        if int(admin.info("server")["redis_version"].split(".")[0]) < 6:
            pytest.skip("ACLs need Redis 6+")
        admin.set("tenant:B:secret", "b-only")
        admin.set("tenant:A:mine", "a-only")
        admin.acl_setuser(**acl_setuser_args("A", password="pw"))
        try:
            ua = redis.Redis.from_url(URL, username="tenant_A", password="pw", decode_responses=True)
            assert ua.get("tenant:A:mine") == "a-only"
            with pytest.raises(redis.exceptions.NoPermissionError):
                ua.get("tenant:B:secret")
            with pytest.raises(redis.exceptions.NoPermissionError):
                ua.set("tenant:B:secret", "pwned")
            with pytest.raises(redis.exceptions.NoPermissionError):
                ua.keys("*")
            with pytest.raises(redis.exceptions.NoPermissionError):
                ua.flushall()
            # Both layers together: middleware prefixing + server ACL
            both = protect_redis(ua, "A")
            both.set("via-both", "1")
            assert admin.get("tenant:A:via-both") == "1"
        finally:
            admin.acl_deluser("tenant_A")
