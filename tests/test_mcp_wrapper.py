"""
MCP stdio proxy: every SQL-looking string in a tools/call, at any depth,
is scoped to the tenant. What cannot be scoped is answered with a JSON-RPC
error and never reaches the child server. Lines the proxy cannot parse are
dropped, because the child may parse them differently.
"""

import json
import os
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
pytest.importorskip("sqlglot")
from hooks.mcp_wrapper import handle_line, intercept_sql_in_tool_call, looks_like_sql  # noqa: E402
from middleware.db_firewall import load_config  # noqa: E402

SCOPED = "SELECT * FROM orders WHERE orders.tenant_id = 'A'"


@pytest.fixture
def cfg():
    return load_config()


def _call(arguments, id_=1, **extra):
    msg = {"jsonrpc": "2.0", "method": "tools/call",
           "params": {"name": "select_rows", "arguments": arguments, **extra}}
    if id_ is not None:
        msg["id"] = id_
    return msg


def _line(obj):
    return (json.dumps(obj) + "\n").encode()


def _run(obj_or_bytes, cfg):
    raw = obj_or_bytes if isinstance(obj_or_bytes, bytes) else _line(obj_or_bytes)
    fwd, reply = handle_line(raw, "A", cfg)
    return (json.loads(fwd) if fwd else None), (json.loads(reply) if reply else None)


class TestLooksLikeSql:
    @pytest.mark.parametrize("s", [
        "SELECT * FROM orders", "select 1", "  \n\tDELETE FROM orders",
        "WITH x AS (SELECT 1) SELECT * FROM x", "(SELECT * FROM orders)",
        ";WITH x AS (SELECT 1) SELECT 1", "/* c */ UPDATE orders SET a = 1",
        "-- c\nINSERT INTO orders VALUES (1)", "# c\nREPLACE INTO orders VALUES (1)",
        "/* /* */ */ DELETE FROM orders", "/*!DELETE FROM orders*/",
        "EXEC sp_who", "IF 1=1 DELETE FROM orders", "COPY orders TO STDOUT",
        "MERGE INTO orders USING x ON 1=1 WHEN MATCHED THEN DELETE",
        "sp_executesql N'SELECT * FROM orders'", "xp_cmdshell 'dir'",
        "lbl: SELECT * FROM orders", "CHECK TABLE orders", "RECEIVE * FROM q",
        "a: b: SELECT * FROM orders", "lbl: sp_executesql N'SELECT 1'",
    ])
    def test_sql(self, s):
        assert looks_like_sql(s)

    @pytest.mark.parametrize("s", [
        "", "hello", "Please pick a colour", "select_rows", "orders", "42",
        "https://example.com/select", "Total -- about 40", "Note: ring me later",
        "a::text",
    ])
    def test_not_sql(self, s):
        assert not looks_like_sql(s)


class TestScoping:
    @pytest.mark.parametrize("arguments,path", [
        ({"sql": "SELECT * FROM orders"}, ("sql",)),
        ({"sql_query": "SELECT * FROM orders"}, ("sql_query",)),
        ({"input": {"query": "SELECT * FROM orders"}}, ("input", "query")),
        ({"queries": ["SELECT 1", "SELECT * FROM orders"]}, ("queries", 1)),
    ])
    def test_sql_anywhere_is_scoped(self, cfg, arguments, path):
        out = intercept_sql_in_tool_call(_call(arguments), "A", cfg)["params"]["arguments"]
        for key in path:
            out = out[key]
        assert out == SCOPED

    def test_prose_and_tool_name_untouched(self, cfg):
        msg = intercept_sql_in_tool_call(_call({"note": "hello", "n": 3, "ok": True}), "A", cfg)
        assert msg["params"]["name"] == "select_rows"
        assert msg["params"]["arguments"] == {"note": "hello", "n": 3, "ok": True}

    def test_sql_outside_arguments_is_scoped(self, cfg):
        msg = intercept_sql_in_tool_call(_call({}, sql="SELECT * FROM orders"), "A", cfg)
        assert msg["params"]["sql"] == SCOPED

    def test_sql_in_object_key_refused(self, cfg):
        with pytest.raises(PermissionError):
            intercept_sql_in_tool_call(_call({"SELECT * FROM orders": 1}), "A", cfg)

    @pytest.mark.parametrize("args", [{"table": "orders"}, {"values": [1]}, {"set": {"a": 1}},
                                      {"check": True}, {"start": 1, "end": 5}, {"desc": "x"}])
    def test_keyword_named_keys_pass(self, cfg, args):
        assert intercept_sql_in_tool_call(_call(dict(args)), "A", cfg)["params"]["arguments"] == args

    def test_non_string_name_is_scoped(self, cfg):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": {"sql": "SELECT * FROM orders"}}}
        assert intercept_sql_in_tool_call(msg, "A", cfg)["params"]["name"]["sql"] == SCOPED

    def test_list_params_are_scoped(self, cfg):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["SELECT * FROM orders"]}
        assert intercept_sql_in_tool_call(msg, "A", cfg)["params"] == [SCOPED]

    def test_other_methods_pass(self, cfg):
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        assert intercept_sql_in_tool_call(dict(msg), "A", cfg) == msg

    @pytest.mark.parametrize("arguments", [None, [], "x"])
    def test_odd_arguments_do_not_crash(self, cfg, arguments):
        fwd, reply = _run(_call(arguments), cfg)
        assert reply is None and fwd["params"]["arguments"] == arguments


class TestHandleLine:
    def test_scoped_call_forwarded(self, cfg):
        fwd, reply = _run(_call({"sql": "SELECT * FROM orders"}), cfg)
        assert reply is None and fwd["params"]["arguments"]["sql"] == SCOPED

    @pytest.mark.parametrize("sql", [
        "CREATE TABLE t AS SELECT * FROM orders", "SELECT 1; DELETE FROM orders",
        "/*!DELETE FROM orders*/", "/* /* */ */ DELETE FROM orders",
    ])
    def test_refused_sql_gets_error_and_is_not_forwarded(self, cfg, sql):
        fwd, reply = _run(_call({"q": sql}, id_=7), cfg)
        assert fwd is None
        assert reply["id"] == 7 and reply["error"]["code"] == -32000
        assert "DB Firewall" in reply["error"]["message"]

    def test_refused_notification_is_dropped_silently(self, cfg):
        assert handle_line(_line(_call({"q": "DROP TABLE orders"}, id_=None)), "A", cfg) == (None, None)

    def test_batch_splits_allowed_and_refused(self, cfg):
        batch = [_call({"q": "SELECT * FROM orders"}, id_=1),
                 _call({"q": "DROP TABLE orders"}, id_=2)]
        fwd, reply = _run(batch, cfg)
        assert [m["id"] for m in fwd] == [1]
        assert fwd[0]["params"]["arguments"]["q"] == SCOPED
        assert [r["id"] for r in reply] == [2]

    @pytest.mark.parametrize("raw", [
        b"not json\n",
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"q":"SELECT * FROM orders\xff"}}}\n',
        b'"just a string"\n',
    ])
    def test_unparseable_line_is_dropped(self, cfg, raw):
        assert handle_line(raw, "A", cfg) == (None, None)

    def test_deeply_nested_line_is_dropped(self, cfg):
        raw = b'{"a":' * 200_000 + b'1' + b'}' * 200_000 + b"\n"
        assert handle_line(raw, "A", cfg) == (None, None)

    def test_deep_arguments_refused_not_crashed(self, cfg):
        # Deep enough to exceed the Python recursion limit in the scoping walk,
        # shallow enough for the C JSON decoder on 3.12+ (3.11 drops it at parse).
        deep = "[" * 1500 + '"SELECT * FROM orders"' + "]" * 1500
        raw = ('{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"arguments":{"q":'
               + deep + '}}}\n').encode()
        fwd, reply = handle_line(raw, "A", cfg)
        assert fwd is None
        if sys.version_info >= (3, 12):
            assert json.loads(reply)["id"] == 9

    def test_nan_line_is_dropped(self, cfg):
        raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"n":NaN}}}\n'
        assert handle_line(raw, "A", cfg) == (None, None)

    def test_blank_line_ignored(self, cfg):
        assert handle_line(b"\n", "A", cfg) == (None, None)


CHILD = textwrap.dedent("""
    import sys
    for line in sys.stdin:
        sys.stdout.write("CHILD " + line)
        sys.stdout.flush()
""")


class TestProxyProcess:
    def _wrapper(self, tmp_path, tenant, stdin):
        child = tmp_path / "child.py"
        child.write_text(CHILD)
        env = {**os.environ, "PYTHONPATH": ROOT}
        env.pop("DB_FIREWALL_CONFIG", None)
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "hooks", "mcp_wrapper.py"),
             "--tenant", tenant, "--", sys.executable, str(child)],
            input=stdin, capture_output=True, timeout=30, env=env)

    def test_end_to_end(self, tmp_path):
        stdin = (_line(_call({"q": "SELECT * FROM orders"}, id_=1))
                 + _line(_call({"q": "DROP TABLE orders"}, id_=2))
                 + b"garbage\n")
        out = self._wrapper(tmp_path, "A", stdin)
        lines = out.stdout.decode().splitlines()
        child = [json.loads(l[len("CHILD "):]) for l in lines if l.startswith("CHILD ")]
        errors = [json.loads(l) for l in lines if not l.startswith("CHILD ")]
        assert [m["params"]["arguments"]["q"] for m in child] == [SCOPED]
        assert [e["id"] for e in errors] == [2]
        assert out.returncode == 0

    def test_bad_tenant_exits(self, tmp_path):
        out = self._wrapper(tmp_path, "A\\", b"")
        assert out.returncode == 2
        assert b"tenant" in out.stderr.lower()
