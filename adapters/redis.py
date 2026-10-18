"""
DB Firewall — Redis adapter
===========================
Two layers, like the SQL side:

1. Middleware (this file): ``protect_redis(client, tenant)`` rewrites every key
   to ``<prefix>:<tenant>:<key>`` and blocks commands that cannot be scoped.
2. Server-native (stronger): ``acl_rules_for(tenant)`` / ``acl_setuser_args``
   produce a Redis 6+ ACL user whose key permissions are ``~<prefix>:<tenant>:*``.
   Even if the middleware is bypassed, the server refuses foreign keys.

    from adapters.redis import protect_redis, acl_setuser_args
    r = protect_redis(redis.Redis(), tenant_id="TENANT_A")
    r.set("cart", "...")           # really writes tenant:TENANT_A:cart
    r.keys("*")                    # confined to tenant:TENANT_A:*
    r.flushdb()                    # TenantRequired

    admin.acl_setuser(**acl_setuser_args("TENANT_A", password="s3cret"))

No driver import: the wrapper only calls methods on the client you pass in.
"""

from typing import Any, Dict, List, Union

from ._common import TenantRequired, require_tenant, validate_tenant, blocked

# Commands whose FIRST positional argument is the key.
_FIRST_KEY = """
get set setex setnx psetex getset getdel getex append strlen incr incrby incrbyfloat decr decrby
setrange getrange expire pexpire expireat pexpireat ttl pttl persist type
hget hset hsetnx hmset hmget hgetall hdel hexists hkeys hvals hlen hincrby hincrbyfloat hscan
lpush rpush lpushx rpushx lpop rpop lrange llen lindex lset lrem ltrim linsert lpos
sadd smembers srem sismember smismember scard spop srandmember sscan
zadd zrange zrevrange zrangebyscore zrevrangebyscore zrem zscore zcard zcount zincrby zrank
zrevrank zremrangebyrank zremrangebyscore zpopmin zpopmax zscan
""".split()
# Commands where EVERY positional argument is a key.
_ALL_KEYS = "delete exists mget unlink touch sunion sinter sdiff".split()
# Commands with exactly two keys (src, dst).
_TWO_KEYS = "rename renamenx rpoplpush smove lmove".split()

_KEY_KWARGS = ("name", "key", "src", "dst", "source", "destination")


class ProtectedRedis:
    """Tenant-scoped wrapper over redis-py ``Redis`` (or a ``Pipeline``)."""

    def __init__(self, client, tenant_id, prefix: str = "tenant", _is_pipeline: bool = False):
        require_tenant(tenant_id)
        validate_tenant(tenant_id, redis_safe=True)
        if any(ch in prefix for ch in "*?[]:\\") or not prefix:
            raise TenantRequired("prefix may not be empty or contain * ? [ ] : \\")
        self._r, self._t, self._p = client, str(tenant_id), prefix
        self._ns = f"{prefix}:{self._t}:"
        self._pipe = _is_pipeline

    # ---------------------------------------------------------------- helpers
    @property
    def raw(self):
        """UNSCOPED client. Bypasses every tenant check. Admin use ONLY."""
        return self._r

    @property
    def namespace(self) -> str:
        return self._ns

    def _k(self, key: Union[str, bytes]) -> Union[str, bytes]:
        if isinstance(key, bytes):
            return self._ns.encode() + key
        if not isinstance(key, str):
            raise TenantRequired(f"key must be str/bytes, got {type(key).__name__}")
        return self._ns + key

    def _unk(self, key: Union[str, bytes]) -> Union[str, bytes]:
        ns = self._ns.encode() if isinstance(key, bytes) else self._ns
        return key[len(ns):] if key.startswith(ns) else key

    def _ret(self, result):
        # Pipeline methods return the pipeline for chaining; never leak the raw one.
        return self if self._pipe and result is self._r else result

    def _call(self, name: str, keys_at: str, args: tuple, kwargs: dict):
        args = list(args)
        if keys_at == "first" and args:
            args[0] = self._k(args[0])
        elif keys_at == "all":
            args = [self._k(a) for a in args]
        elif keys_at == "two":
            args = [self._k(a) if i < 2 else a for i, a in enumerate(args)]
        for kw in _KEY_KWARGS:
            if kw in kwargs:
                kwargs[kw] = self._k(kwargs[kw])
        return self._ret(getattr(self._r, name)(*args, **kwargs))

    # Generated key-rewriting methods ------------------------------------------
    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in _FIRST_KEY:
            where = "first"
        elif name in _ALL_KEYS:
            where = "all"
        elif name in _TWO_KEYS:
            where = "two"
        else:  # fail closed: unknown commands never reach the raw client
            raise TenantRequired(f"Redis.{name} is not tenant-scoped; blocked")
        return lambda *a, **k: self._call(name, where, a, k)

    # Explicit multi-key / pattern commands ------------------------------------
    def mset(self, mapping: Dict[Any, Any], *a, **k):
        return self._ret(self._r.mset({self._k(key): v for key, v in mapping.items()}, *a, **k))

    def keys(self, pattern: Union[str, bytes] = "*", **k) -> List[Any]:
        """Allowed only because the pattern is forced under the tenant prefix."""
        return [self._unk(x) for x in self._r.keys(self._k(pattern), **k)]

    def scan(self, cursor: int = 0, match=None, count=None, **k):
        """``match`` is required (no pattern = whole keyspace); it is prefixed."""
        if match is None:
            raise TenantRequired("scan without a match pattern is blocked")
        cur, found = self._r.scan(cursor, match=self._k(match), count=count, **k)
        return cur, [self._unk(x) for x in found]

    def scan_iter(self, match=None, count=None, **k):
        if match is None:
            raise TenantRequired("scan_iter without a match pattern is blocked")
        for x in self._r.scan_iter(match=self._k(match), count=count, **k):
            yield self._unk(x)

    def execute_command(self, cmd: str, *args, **k):
        """Only known key-space commands pass; everything else is refused."""
        name = cmd.lower().replace(" ", "_")
        if name == "del":
            name = "delete"
        return self.__getattr__(name)(*args, **k)  # strict: key-command tables only

    # Pipelines -----------------------------------------------------------------
    def pipeline(self, transaction: bool = True, shard_hint=None) -> "ProtectedRedis":
        """A pipeline wrapper enforcing the same key rewriting and command blocks."""
        return ProtectedRedis(self._r.pipeline(transaction=transaction, shard_hint=shard_hint),
                              self._t, self._p, _is_pipeline=True)

    def execute(self, *a, **k):
        if not self._pipe:
            raise TenantRequired("execute() is only valid on a pipeline")
        return self._r.execute(*a, **k)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self._pipe:
            self._r.reset()

    # Blocked -------------------------------------------------------------------
    flushdb = blocked("flushdb", "wipes every tenant")
    flushall = blocked("flushall", "wipes every tenant")
    eval = blocked("eval", "scripts can touch any key")
    evalsha = blocked("evalsha", "scripts can touch any key")
    script_load = blocked("script_load", "scripts can touch any key")
    register_script = blocked("register_script", "scripts can touch any key")
    fcall = blocked("fcall", "functions can touch any key")
    config_get = blocked("config_get", "server configuration")
    config_set = blocked("config_set", "server configuration")
    dbsize = blocked("dbsize", "leaks cross-tenant cardinality")
    randomkey = blocked("randomkey", "may return another tenant's key")
    migrate = blocked("migrate", "moves keys between servers")
    move = blocked("move", "moves keys between databases")
    swapdb = blocked("swapdb", "swaps whole databases")
    select = blocked("select", "changes database")
    info = blocked("info", "server-wide information")
    acl_setuser = blocked("acl_setuser", "ACL changes are admin-only; use the raw client")


def protect_redis(client, tenant_id, prefix: str = "tenant") -> ProtectedRedis:
    """Return a tenant-scoped wrapper over a redis-py client."""
    return ProtectedRedis(client, tenant_id, prefix)


# ---------------------------------------------------------------- server-side ACL
# Commands denied on top of -@dangerous (which already covers keys/flush*/config/...).
ACL_DENIED = ["-keys", "-flushdb", "-flushall", "-eval", "-evalsha", "-script", "-function",
              "-fcall", "-fcall_ro", "-config", "-debug", "-migrate", "-move", "-swapdb",
              "-select", "-randomkey", "-dbsize", "-scan"]


def acl_rules_for(tenant_id, prefix: str = "tenant") -> str:
    """Redis ACL rule string for a per-tenant user (paste into ``ACL SETUSER <name> ...``).

    This is the stronger, server-side layer: the server itself refuses any key
    outside ``<prefix>:<tenant>:*`` regardless of client code.
    Note ``-scan`` is included because SCAN is not key-scoped by ACLs; drop it
    (and use ``protect_redis().scan``) if the tenant needs iteration.
    """
    require_tenant(tenant_id)
    validate_tenant(tenant_id, redis_safe=True)
    return f"on ~{prefix}:{tenant_id}:* resetchannels +@all -@dangerous " + " ".join(ACL_DENIED)


def acl_setuser_args(tenant_id, password: str, prefix: str = "tenant",
                     username: str = None) -> Dict[str, Any]:
    """kwargs for ``redis.Redis.acl_setuser(**args)`` creating the per-tenant user."""
    require_tenant(tenant_id)
    validate_tenant(tenant_id, redis_safe=True)
    return {
        "username": username or f"{prefix}_{tenant_id}",
        "enabled": True,
        "reset": True,  # start from a clean slate, not the default user's ~*
        "passwords": [f"+{password}"],
        "keys": [f"{prefix}:{tenant_id}:*"],
        "categories": ["+@all", "-@dangerous"],
        "commands": ACL_DENIED,
        "reset_channels": True,
    }
