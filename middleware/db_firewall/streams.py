"""DB Firewall: streaming bodies read as the request's tenant (sync and async)."""

import asyncio
import contextvars
import sys
import weakref
from typing import Optional

from .context import _TENANT_VAR


class _ScopedStream:
    """Iterate a streaming body as the request's tenant, inside a private copy
    of the context. A WSGI server reads the body after the middleware has
    returned. The caller's context is never changed, so a body read late, read
    in pieces, finalized by the garbage collector, or interleaved with another
    stream cannot set a tenant in some other request."""

    def __init__(self, tenant: Optional[str], content):
        self._ctx = contextvars.copy_context()
        self._ctx.run(_TENANT_VAR.set, tenant)
        self._it = iter(content)

    def __iter__(self):
        return self

    def __next__(self):
        return self._ctx.run(next, self._it)

    def close(self):                    # Django calls this when the response closes
        close = getattr(self._it, "close", None)
        if close is not None:
            self._ctx.run(close)


_PUMPS = set()      # running body tasks; a task only weakly referenced could be collected


async def _pump(it, requests: "asyncio.Queue", replies: "asyncio.Queue"):
    """Drive an async body one item per request, in this task's context.
    Cancel the task to close the body: its cleanup then runs here, as the
    request's tenant, not in whatever code happens to be running."""
    try:
        while True:
            await requests.get()
            try:
                item = await it.__anext__()
            except StopAsyncIteration:
                replies.put_nowait(("stop", None))
                return
            except Exception as e:      # the body failed: hand the error to the reader
                replies.put_nowait(("error", e))
                return
            replies.put_nowait(("item", item))
    except asyncio.CancelledError:
        replies.put_nowait(("stop", None))      # wake a reader that is still waiting
        raise
    finally:
        aclose = getattr(it, "aclose", None)
        if aclose is not None:
            await aclose()


class _AsyncScopedStream:
    """The async twin of _ScopedStream, for StreamingHttpResponse bodies that
    are async iterators (ASGI). The whole body runs in ONE task whose context
    holds the request's tenant, so every step, timeouts held across steps and
    the body's cleanup see that tenant. The caller's context never changes.
    close() (Django calls it after the response or a client disconnect) and
    garbage collection cancel the task, which closes the body in that task."""

    def __init__(self, tenant: Optional[str], content):
        self._ctx = contextvars.copy_context()
        self._ctx.run(_TENANT_VAR.set, tenant)
        self._it = content.__aiter__()
        self._task = None
        self._closed = False

    def __aiter__(self):
        return self

    def _start(self):
        self._requests, self._replies = asyncio.Queue(), asyncio.Queue()
        coro = _pump(self._it, self._requests, self._replies)
        loop = asyncio.get_running_loop()
        if sys.version_info >= (3, 11):
            self._task = loop.create_task(coro, context=self._ctx)
        else:   # the task runs in a copy of self._ctx: same tenant
            self._task = self._ctx.run(loop.create_task, coro)
        _PUMPS.add(self._task)
        self._task.add_done_callback(_PUMPS.discard)
        weakref.finalize(self, self._task.cancel)

    async def __anext__(self):
        if self._closed:
            raise StopAsyncIteration
        if self._task is None:
            self._start()
        self._requests.put_nowait(None)
        kind, value = await self._replies.get()
        if kind == "item":
            return value
        self._closed = True
        if kind == "error":
            raise value
        raise StopAsyncIteration

    def close(self):
        self._closed = True
        if self._task is not None:
            self._task.cancel()

    async def aclose(self):
        self.close()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass


def _scope_streaming(response, tenant):
    """Wrap a streaming body (sync or async) so it is read as the request's tenant."""
    content = getattr(response, "streaming_content", None)
    if not getattr(response, "streaming", False) or content is None:
        return response
    if hasattr(content, "__aiter__"):
        # Wrap the raw body, not Django's make_bytes generator (which refers to
        # the response and would keep it alive in a cycle). Django re-applies
        # make_bytes to what we yield.
        raw = getattr(response, "_iterator", None)
        response.streaming_content = _AsyncScopedStream(
            tenant, raw if hasattr(raw, "__aiter__") else content)
    else:
        response.streaming_content = _ScopedStream(tenant, content)
    return response
