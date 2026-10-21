"""
Request-scoped tenant context and framework integrations.

Covers:
- asyncio tasks on one thread each keep their own tenant (ContextVar, not threading.local)
- web integrations never trust X-Tenant-ID or ?tenant_id= unless explicitly told to
- tenant_id_source (verified session / JWT) wins over the header
- invalid tenant ids from a request are ignored, so the request fails closed
- Django clears the tenant even when the view raises
"""

import asyncio
import os
import sys
import threading
from types import SimpleNamespace

import logging

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
import sqlite3  # noqa: E402
import uuid  # noqa: E402

import db_firewall  # noqa: E402
from db_firewall import (  # noqa: E402
    TenantContext, clear_tenant, django_middleware_class, fastapi_middleware,
    flask_hooks, get_tenant, protect, set_tenant, tenant_scope,
)

CONFIG = {"fail_mode": "closed", "rewriter": "ast"}


def _conn(tenant=None):
    return protect(sqlite3.connect(":memory:"), tenant_id=tenant, config=CONFIG)

HEADER = "X-Tenant-ID"


@pytest.fixture(autouse=True)
def _clean_context():
    clear_tenant()
    yield
    clear_tenant()


# ============================================================================
# Context store
# ============================================================================

class TestContextIsolation:

    def test_async_tasks_on_one_thread_keep_own_tenant(self):
        seen = {}

        async def request(tenant, pause):
            set_tenant(tenant)
            await asyncio.sleep(pause)      # the other task runs and sets its tenant here
            seen[tenant] = get_tenant()

        async def both():
            await asyncio.gather(request("A", 0.02), request("B", 0.0))

        asyncio.run(both())
        assert seen == {"A": "A", "B": "B"}

    def test_threads_keep_own_tenant(self):
        seen = {}
        barrier = threading.Barrier(2)

        def request(tenant):
            set_tenant(tenant)
            barrier.wait()                  # both threads have set a tenant
            seen[tenant] = get_tenant()

        threads = [threading.Thread(target=request, args=(t,)) for t in ("A", "B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert seen == {"A": "A", "B": "B"}

    def test_nested_tenant_scope_restores_outer(self):
        with tenant_scope("A"):
            with tenant_scope("B"):
                assert get_tenant() == "B"
            assert get_tenant() == "A"
        assert get_tenant() is None

    def test_protect_does_not_change_shared_tenant(self):
        set_tenant("A")                     # the request's tenant
        conn = _conn("B")
        assert get_tenant() == "A"
        conn.close()
        assert get_tenant() == "A"

    def test_connection_from_old_request_closed_in_new_request(self):
        old = TenantContext.enter("A")      # request A on a reused worker thread
        conn = _conn()                      # inherits A for its own cursors
        TenantContext.exit(old)
        new = TenantContext.enter("C")      # request C on the same thread
        conn.close()
        assert get_tenant() == "C"          # must not bring back A
        TenantContext.exit(new)

    def test_release_inside_scope_leaves_no_stale_tenant(self):
        conn = _conn("A")
        with tenant_scope("B"):
            conn.release()
        assert get_tenant() is None

    def test_close_after_scope_leaves_no_stale_tenant(self):
        with tenant_scope("A"):
            conn = _conn()
        conn.close()
        assert get_tenant() is None

    def test_cross_context_exit_fails_closed_with_warning(self, caplog):
        token = TenantContext.enter("A")
        set_tenant("B")

        def other_thread():
            TenantContext.exit(token)       # token from another context
            seen.append(get_tenant())

        seen = []
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            t = threading.Thread(target=other_thread)
            t.start()
            t.join()
        assert seen == [None]
        assert "different context" in caplog.text
        assert get_tenant() == "B"          # the creating context is untouched


# ============================================================================
# Django (duck-typed request; no Django install needed)
# ============================================================================

def _django_request(headers=None, session=None, **attrs):
    req = SimpleNamespace(headers=headers or {}, **attrs)
    if session is not None:
        req.session = session
    return req


def _run_django(request, **kwargs):
    seen = {}

    def view(req):
        seen["tenant"] = get_tenant()
        return "ok"

    middleware = django_middleware_class(**kwargs)(view)
    middleware(request)
    return seen["tenant"]


class TestDjango:

    def test_header_ignored_by_default(self):
        assert _run_django(_django_request(headers={HEADER: "B"})) is None

    def test_header_used_when_trusted(self):
        assert _run_django(_django_request(headers={HEADER: "B"}), trust_tenant_header=True) == "B"

    def test_session_is_default_source(self):
        assert _run_django(_django_request(session={"tenant_id": "A"})) == "A"

    def test_request_attribute_is_default_source(self):
        assert _run_django(_django_request(tenant_id="A")) == "A"

    def test_source_wins_over_trusted_header(self):
        req = _django_request(headers={HEADER: "B"})
        tenant = _run_django(req, tenant_id_source=lambda r: "A", trust_tenant_header=True)
        assert tenant == "A"

    def test_integer_tenant_from_source_is_accepted(self):
        assert _run_django(_django_request(), tenant_id_source=lambda r: 42) == "42"

    def test_invalid_header_value_is_ignored(self):
        req = _django_request(headers={HEADER: "A\nB"})
        assert _run_django(req, trust_tenant_header=True) is None

    def test_anonymous_request_hides_ambient_tenant(self):
        set_tenant("A")                     # stray tenant left in this context
        assert _run_django(_django_request()) is None
        assert get_tenant() == "A"          # restored after the request

    def test_invalid_id_hides_ambient_tenant(self):
        set_tenant("A")
        req = _django_request(headers={HEADER: "A\nB"})
        assert _run_django(req, trust_tenant_header=True) is None

    def test_zero_id_does_not_fall_through_to_session(self):
        req = _django_request(tenant_id=0, session={"tenant_id": "B"})
        assert _run_django(req) == "0"

    @pytest.mark.parametrize("bad", [True, b"A", ["A"], 1.5])
    def test_wrong_type_from_source_is_ignored(self, bad):
        assert _run_django(_django_request(), tenant_id_source=lambda r: bad) is None

    def test_uuid_from_source_is_accepted(self):
        tid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        assert _run_django(_django_request(), tenant_id_source=lambda r: tid) == str(tid)

    def test_trust_from_config_file(self, tmp_path, monkeypatch):
        (tmp_path / ".db-firewall.json").write_text('{"trust_tenant_header": true}')
        monkeypatch.setenv("DB_FIREWALL_CONFIG", str(tmp_path / ".db-firewall.json"))
        assert _run_django(_django_request(headers={HEADER: "B"})) == "B"

    def test_streaming_body_runs_as_request_tenant(self):
        set_tenant("Z")                     # ambient tenant that must not leak in

        def view(req):
            body = (get_tenant() for _ in range(2))   # read lazily, after middleware returns
            return SimpleNamespace(streaming=True, streaming_content=body)

        response = django_middleware_class(tenant_id_source=lambda r: "A")(view)(_django_request())
        assert get_tenant() == "Z"          # restored before the body is read
        assert list(response.streaming_content) == ["A", "A"]
        assert get_tenant() == "Z"

    def _streaming_view(self, chunks=3):
        def view(req):
            body = (get_tenant() for _ in range(chunks))
            return SimpleNamespace(streaming=True, streaming_content=body)
        return view

    def test_late_finalized_stream_does_not_touch_later_request(self):
        import gc
        mw = django_middleware_class(tenant_id_source=lambda r: "A")(self._streaming_view())
        stream = mw(_django_request()).streaming_content
        assert next(stream) == "A"          # partly read, never closed
        token = TenantContext.enter("D")    # next request on the same thread
        del stream
        gc.collect()                        # finalized mid-request
        assert get_tenant() == "D"
        TenantContext.exit(token)

    def test_interleaved_streams_keep_own_tenant(self):
        mw_c = django_middleware_class(tenant_id_source=lambda r: "C")(self._streaming_view())
        mw_d = django_middleware_class(tenant_id_source=lambda r: "D")(self._streaming_view())
        c = mw_c(_django_request()).streaming_content
        d = mw_d(_django_request()).streaming_content
        seen = [next(c), next(d), next(c), next(d)]
        assert seen == ["C", "D", "C", "D"]
        assert get_tenant() is None         # the caller's context is untouched

    def test_ignored_header_logged_once(self, caplog, monkeypatch):
        monkeypatch.setattr(db_firewall, "_warned_untrusted_header", False)
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            _run_django(_django_request(headers={HEADER: "B"}))
            _run_django(_django_request(headers={HEADER: "B"}))
        assert caplog.text.count("X-Tenant-ID header ignored") == 1

    def test_fail_open_logged_at_setup(self, caplog, tmp_path, monkeypatch):
        (tmp_path / ".db-firewall.json").write_text('{"fail_mode": "open"}')
        monkeypatch.setenv("DB_FIREWALL_CONFIG", str(tmp_path / ".db-firewall.json"))
        with caplog.at_level(logging.WARNING, logger="db_firewall"):
            django_middleware_class()
        assert "fail_mode=open" in caplog.text

    def test_tenant_cleared_when_view_raises(self):
        def view(req):
            raise RuntimeError("view failed")

        middleware = django_middleware_class(tenant_id_source=lambda r: "A")(view)
        with pytest.raises(RuntimeError):
            middleware(_django_request())
        assert get_tenant() is None


# ============================================================================
# FastAPI / Starlette
# ============================================================================

starlette_testclient = pytest.importorskip("starlette.testclient", reason="starlette + httpx not installed")


def _starlette_client(**kwargs):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def async_view(request):
        return PlainTextResponse(str(get_tenant()))

    def sync_view(request):                 # Starlette runs this in a thread pool
        return PlainTextResponse(str(get_tenant()))

    app = Starlette(routes=[Route("/async", async_view), Route("/sync", sync_view)])
    fastapi_middleware(app, **kwargs)
    return starlette_testclient.TestClient(app)


class TestFastAPI:

    def test_header_and_query_ignored_by_default(self):
        client = _starlette_client()
        assert client.get("/async?tenant_id=B", headers={HEADER: "B"}).text == "None"

    def test_header_used_when_trusted(self):
        client = _starlette_client(trust_tenant_header=True)
        assert client.get("/async", headers={HEADER: "B"}).text == "B"

    def test_query_string_never_trusted(self):
        client = _starlette_client(trust_tenant_header=True)
        assert client.get("/async?tenant_id=B").text == "None"

    def test_source_used_for_async_and_sync_endpoints(self):
        client = _starlette_client(tenant_id_source=lambda req: "A")
        assert client.get("/async").text == "A"
        assert client.get("/sync").text == "A"

    @pytest.mark.parametrize("path", ["/async", "/sync"])
    def test_anonymous_request_hides_ambient_tenant(self, path):
        from starlette.middleware.base import BaseHTTPMiddleware

        class Stray(BaseHTTPMiddleware):    # code that sets a tenant before ours runs
            async def dispatch(self, request, call_next):
                set_tenant("A")
                return await call_next(request)

        client = _starlette_client()
        client.app.add_middleware(Stray)
        assert client.get(path).text == "None"

    def test_outer_tenant_restored_after_request(self):
        from starlette.middleware.base import BaseHTTPMiddleware
        after = []

        class Outer(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                set_tenant("A")
                response = await call_next(request)
                after.append(get_tenant())
                return response

        client = _starlette_client(tenant_id_source=lambda req: "B")
        client.app.add_middleware(Outer)
        assert client.get("/async").text == "B"
        assert after == ["A"]

    def test_request_state_is_default_source(self):
        from starlette.middleware.base import BaseHTTPMiddleware

        class Auth(BaseHTTPMiddleware):     # stands in for a real auth layer
            async def dispatch(self, request, call_next):
                request.state.tenant_id = "A"
                return await call_next(request)

        client = _starlette_client()
        client.app.add_middleware(Auth)     # added last, so it runs first
        assert client.get("/async").text == "A"


# ============================================================================
# Flask
# ============================================================================

flask = pytest.importorskip("flask", reason="flask not installed")


def _flask_client(before=None, **kwargs):
    app = flask.Flask(__name__)
    app.secret_key = "test-only"
    if before:
        app.before_request(before)          # registered first, so it runs first

    @app.route("/")
    def view():
        return str(get_tenant())

    flask_hooks(app, **kwargs)
    return app.test_client()


class TestFlask:

    def test_header_and_query_ignored_by_default(self):
        client = _flask_client()
        assert client.get("/?tenant_id=B", headers={HEADER: "B"}).text == "None"

    def test_header_used_when_trusted(self):
        client = _flask_client(trust_tenant_header=True)
        assert client.get("/", headers={HEADER: "B"}).text == "B"

    def test_g_is_default_source(self):
        def auth():
            flask.g.tenant_id = "A"

        assert _flask_client(before=auth).get("/").text == "A"

    def test_source_wins_over_trusted_header(self):
        client = _flask_client(tenant_id_source=lambda: "A", trust_tenant_header=True)
        assert client.get("/", headers={HEADER: "B"}).text == "A"

    def test_anonymous_request_hides_ambient_tenant(self):
        assert _flask_client(before=lambda: set_tenant("A")).get("/").text == "None"

    def test_invalid_header_value_is_ignored(self):
        client = _flask_client(trust_tenant_header=True)   # werkzeug refuses "\n" in headers
        assert client.get("/", headers={HEADER: "A\\B"}).text == "None"

    def test_query_string_never_trusted(self):
        client = _flask_client(trust_tenant_header=True)
        assert client.get("/?tenant_id=B").text == "None"

    def test_session_is_default_source(self):
        def login():
            flask.session["tenant_id"] = "A"

        assert _flask_client(before=login).get("/").text == "A"

    def test_outer_tenant_restored_after_request(self):
        app = flask.Flask(__name__)
        after = []
        app.before_request(lambda: set_tenant("A"))
        app.teardown_request(lambda exc: after.append(get_tenant()))  # registered first, runs last
        app.route("/")(lambda: str(get_tenant()))
        flask_hooks(app, tenant_id_source=lambda: "B")
        assert app.test_client().get("/").text == "B"
        assert after == ["A"]
