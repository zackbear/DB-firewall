"""
Django middleware under ASGI and WSGI, with a real Django test client.

- The middleware is sync- and async-capable, so Django runs it natively in
  either mode (no sync/async adaptation).
- Sync and async views, and sync and async streaming bodies, all run as the
  request's tenant, even though the body is read after the middleware returns.
- Concurrent async requests never see each other's tenant; the caller's
  context is untouched.
"""

import asyncio
import os
import sys

import pytest

django = pytest.importorskip("django")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
from django.conf import settings  # noqa: E402

if not settings.configured:
    settings.configure(
        DEBUG=True, SECRET_KEY="test", ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__,
        MIDDLEWARE=[f"{__name__}.TenantMiddleware"], INSTALLED_APPS=[],
        DEFAULT_CHARSET="utf-8")
    django.setup()

from asgiref.sync import iscoroutinefunction  # noqa: E402
from django.http import HttpResponse, StreamingHttpResponse  # noqa: E402
from django.test import AsyncClient, Client  # noqa: E402
from django.urls import path  # noqa: E402

from db_firewall import django_middleware_class, get_tenant, set_tenant  # noqa: E402

TenantMiddleware = django_middleware_class(
    tenant_id_source=lambda request: request.headers.get("X-Test-Tenant"))


def sync_view(request):
    return HttpResponse(str(get_tenant()))


async def async_view(request):
    await asyncio.sleep(0)
    return HttpResponse(str(get_tenant()))


def sync_stream(request):
    return StreamingHttpResponse(f"{get_tenant()}," for _ in range(3))


async def async_stream(request):
    async def body():
        for _ in range(3):
            await asyncio.sleep(0.01)          # let other requests interleave
            yield f"{get_tenant()},"
    return StreamingHttpResponse(body())


urlpatterns = [path("sync", sync_view), path("async", async_view),
               path("sync-stream", sync_stream), path("async-stream", async_stream)]


def _body(response):
    if getattr(response, "streaming", False):
        return b"".join(response.streaming_content).decode()
    return response.content.decode()


async def _abody(response):
    if getattr(response, "streaming", False):
        if response.is_async:
            return "".join([c.decode() async for c in response.streaming_content])
        return b"".join(response.streaming_content).decode()
    return response.content.decode()


def test_middleware_is_sync_and_async_capable():
    assert TenantMiddleware.sync_capable and TenantMiddleware.async_capable

    async def get_response(request):
        return HttpResponse()
    assert iscoroutinefunction(TenantMiddleware(get_response))
    assert not iscoroutinefunction(TenantMiddleware(lambda request: HttpResponse()))


@pytest.mark.parametrize("url,expected", [
    ("/sync", "A"), ("/async", "A"), ("/sync-stream", "A,A,A,"), ("/async-stream", "A,A,A,")])
def test_asgi(url, expected):
    async def run():
        response = await AsyncClient().get(url, headers={"X-Test-Tenant": "A"})
        return await _abody(response)
    assert asyncio.run(run()) == expected


@pytest.mark.parametrize("url,expected", [("/sync", "A"), ("/sync-stream", "A,A,A,")])
def test_wsgi(url, expected):
    assert _body(Client().get(url, headers={"X-Test-Tenant": "A"})) == expected


def test_asgi_without_tenant_is_none():
    async def run():
        return await _abody(await AsyncClient().get("/async-stream"))
    assert asyncio.run(run()) == "None,None,None,"


def test_concurrent_async_streams_keep_own_tenant():
    async def one(tenant):
        response = await AsyncClient().get("/async-stream", headers={"X-Test-Tenant": tenant})
        return await _abody(response)

    async def run():
        set_tenant("Z")                         # ambient tenant that must not leak in or out
        results = await asyncio.gather(*(one(t) for t in "ABCD"))
        return results, get_tenant()
    results, after = asyncio.run(run())
    assert results == [f"{t},{t},{t}," for t in "ABCD"]
    assert after == "Z"


def test_async_stream_wrapper_runs_in_request_context():
    """Unit level: the body is read after the middleware returned, in another task."""
    from db_firewall.web import _AsyncScopedStream

    async def body():
        for _ in range(2):
            yield get_tenant()

    async def run():
        set_tenant("Z")
        stream = _AsyncScopedStream("A", body())
        got = [x async for x in stream]
        await stream.aclose()
        return got, get_tenant()
    assert asyncio.run(run()) == (["A", "A"], "Z")


def test_async_stream_aclose_closes_generator():
    from db_firewall.web import _AsyncScopedStream
    closed = []

    async def body():
        try:
            yield get_tenant()
            yield get_tenant()
        finally:
            closed.append(get_tenant())

    async def run():
        stream = _AsyncScopedStream("A", body())
        assert await stream.__anext__() == "A"
        await stream.aclose()                   # closed early, as on a client disconnect
    asyncio.run(run())
    assert closed == ["A"]                      # cleanup ran as the request's tenant


def test_asgi_runs_middleware_without_adaptation(caplog):
    import logging
    caplog.set_level(logging.DEBUG, logger="django.request")

    async def run():
        return await _abody(await AsyncClient().get("/async", headers={"X-Test-Tenant": "A"}))
    assert asyncio.run(run()) == "A"
    assert "adapted for middleware" not in caplog.text


def test_async_stream_before_311_still_sees_tenant(monkeypatch):
    from types import SimpleNamespace
    from db_firewall import web
    monkeypatch.setattr(web, "sys", SimpleNamespace(version_info=(3, 10)))

    async def body():
        yield get_tenant()

    async def run():
        return [x async for x in web._AsyncScopedStream("A", body())]
    assert asyncio.run(run()) == ["A"]


def test_async_source_under_asgi():
    async def source(request):
        await asyncio.sleep(0)
        return "S"
    mw = django_middleware_class(tenant_id_source=source)

    async def get_response(request):
        return HttpResponse(str(get_tenant()))

    async def run():
        from django.test import AsyncRequestFactory
        return (await mw(get_response)(AsyncRequestFactory().get("/"))).content.decode()
    assert asyncio.run(run()) == "S"


def test_async_tenant_cleared_when_view_raises():
    mw = django_middleware_class(tenant_id_source=lambda r: "A")

    async def get_response(request):
        assert get_tenant() == "A"
        raise RuntimeError("view failed")

    async def run():
        from django.test import AsyncRequestFactory
        set_tenant("Z")
        with pytest.raises(RuntimeError):
            await mw(get_response)(AsyncRequestFactory().get("/"))
        return get_tenant()
    assert asyncio.run(run()) == "Z"
