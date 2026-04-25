"""Real-time event streaming routes (Phase-68 split from ``routers/events.py``).

The Phase-8 events module covered both halves of the surface —
paginated DB queries and the live transports. They share *no*
helpers: the read endpoints use ``_events_filter_sql_args`` to
build SQL, while the live transports rely on the singleton
``event_bus`` (see event_bus.py) to push events into per-subscriber
queues with their own server-side filter dict.

Phase 68 splits the live transports out so the (cheap) history
endpoints don't sit in the same diff as the long-lived
SSE/WebSocket plumbing — the latter has subtler concerns (proxy
buffering, keepalive, cookie-vs-header auth, EventSource retry
hint) that benefit from being read in isolation.

Routes
------
  GET /events/stream    — Server-Sent Events stream of live events
                          + recent backlog replay; cookie or
                          Authorization or query-token auth.
  WS  /events/ws        — JSON WebSocket mirror of the same stream
                          (same filters, same backlog, ping frames
                          instead of SSE keepalive comments).

Late binding
------------
Captured at module load time (after ``app.py`` runs):

  * require_principal — direct call from
    ``_principal_from_sse_headers_or_query`` (we synthesize an
    ``Authorization: Bearer <jwt>`` from cookie/query so the
    standard FastAPI dependency works for SSE/WS too);
  * event_bus — singleton (same identity as the one app.py uses
    when broadcasting via emit_event).

We do NOT take ``Depends(require_principal)`` here for SSE/WS
because EventSource cannot send custom headers and WebSocket
``ws.accept()`` happens before FastAPI dependency resolution; we
authenticate manually inside the handler instead. See the
``_principal_from_sse_headers_or_query`` docstring for the
preference order.
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue as _stdqueue
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import StreamingResponse

import app as _app
from config import (
    EVENT_SSE_KEEPALIVE_SECONDS,
    EVENT_SSE_RETRY_MS,
    EVENT_WS_ENABLED,
    JWT_COOKIE_NAME,
    JWT_USE_HTTPONLY_COOKIE,
    SSE_ALLOW_QUERY_TOKEN,
)
from security import Principal, assert_min_role
from tz_display import iso_timestamp_to_malaysia

require_principal = _app.require_principal
event_bus = _app.event_bus


logger = logging.getLogger("croc-api.routers.events_stream")
router = APIRouter(tags=["events"])


# ──────────────────────────────────────────────────── SSE / WS plumbing ────

def _sse_format(ev: dict[str, Any]) -> str:
    """Serialize one event as an SSE frame."""
    ev_out = {
        "id": ev.get("id"),
        "ts": ev.get("ts"),
        "ts_epoch_ms": ev.get("ts_epoch_ms"),
        "level": ev.get("level"),
        "category": ev.get("category"),
        "event_type": ev.get("event_type"),
        "actor": ev.get("actor"),
        "target": ev.get("target"),
        "owner_admin": ev.get("owner_admin"),
        "device_id": ev.get("device_id"),
        "summary": ev.get("summary"),
        "detail": ev.get("detail") or {},
    }
    return f"id: {ev.get('id') or ''}\nevent: {ev.get('event_type') or 'event'}\ndata: {json.dumps(ev_out, ensure_ascii=False)}\n\n"


def _principal_from_sse_headers_or_query(
    authorization: Optional[str],
    token: Optional[str],
    cookie_token: Optional[str],
) -> Principal:
    """Prefer Authorization; optional legacy ?token= when SSE_ALLOW_QUERY_TOKEN; else HttpOnly cookie."""
    auth_header = authorization
    if not auth_header and SSE_ALLOW_QUERY_TOKEN and token:
        auth_header = f"Bearer {token}"
    if not auth_header and JWT_USE_HTTPONLY_COOKIE and cookie_token:
        auth_header = f"Bearer {str(cookie_token).strip()}"
    if not auth_header:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return require_principal(authorization=auth_header)


# ─────────────────────────────────────────────────────────── SSE stream ────

@router.get("/events/stream")
def events_stream(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(
        default=None,
        description="Legacy only when SSE_ALLOW_QUERY_TOKEN=1. Prefer Authorization header or session cookie.",
    ),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    backlog: int = Query(default=100, ge=0, le=500),
) -> StreamingResponse:
    ck = request.cookies.get(JWT_COOKIE_NAME) if JWT_USE_HTTPONLY_COOKIE else None
    qtok = token if SSE_ALLOW_QUERY_TOKEN else None
    principal = _principal_from_sse_headers_or_query(authorization, qtok, ck)
    assert_min_role(principal, "user")

    filters: dict[str, Any] = {
        "min_level": min_level,
        "category": category,
        "device_id": device_id,
        "q": q,
    }
    filters = {k: v for k, v in filters.items() if v}

    sub = event_bus.subscribe(principal, filters)

    def generator():
        # Initial hello frame — tells the UI which role is connected and
        # flushes any proxy buffering.
        _hello_now = datetime.now(timezone.utc)
        _hello_ts = _hello_now.isoformat()
        hello = {
            "event_type": "stream.hello",
            "level": "info",
            "category": "system",
            "ts": _hello_ts,
            "ts_malaysia": iso_timestamp_to_malaysia(_hello_ts),
            "ts_epoch_ms": int(_hello_now.timestamp() * 1000),
            "summary": f"connected as {principal.role}",
            "actor": "system",
            "detail": {"role": principal.role, "filters": filters},
            "id": 0,
        }
        yield _sse_format(hello)
        # Hint browser EventSource backoff after dropped connections (proxies / sleep).
        yield f"retry: {max(500, EVENT_SSE_RETRY_MS)}\n\n"
        # Replay recent backlog so the dashboard isn't empty on first load.
        if backlog:
            for ev in event_bus.backlog(principal, filters, backlog):
                yield _sse_format(ev)
        last_keepalive = time.time()
        # NOTE: we rely on Starlette closing the generator when the client
        # disconnects (the write yield will raise and our `finally` fires).
        while True:
            try:
                ev = sub.q.get(timeout=1.0)
                yield _sse_format(ev)
            except _stdqueue.Empty:
                pass
            now = time.time()
            if now - last_keepalive >= EVENT_SSE_KEEPALIVE_SECONDS:
                last_keepalive = now
                yield f": keepalive {int(now)} dropped={sub.dropped}\n\n"
                # Data-bearing frame — some proxies buffer until they see `data:` lines.
                ping = json.dumps({"ts": int(now * 1000), "dropped": sub.dropped})
                yield f"event: ping\ndata: {ping}\n\n"

    def close():
        event_bus.unsubscribe(sub)

    headers = {
        "Cache-Control": "no-cache, no-store, no-transform, max-age=0",
        "Pragma": "no-cache",
        "CDN-Cache-Control": "no-store",
        "X-Accel-Buffering": "no",  # Nginx: disable proxy buffering (requires proxy_request_buffering off)
        "Connection": "keep-alive",
    }
    # Wrap generator so we unsubscribe on client disconnect.
    def wrapped():
        try:
            for chunk in generator():
                yield chunk
        finally:
            close()

    return StreamingResponse(
        wrapped(),
        media_type="text/event-stream; charset=utf-8",
        headers=headers,
    )


# ────────────────────────────────────────────────────────── WebSocket ────

@router.websocket("/events/ws")
async def events_ws(websocket: WebSocket) -> None:
    """JSON WebSocket mirror of /events/stream (Phase 2). Cookie JWT auth; same filters as query params."""
    if not EVENT_WS_ENABLED:
        # Complete the HTTP Upgrade so the client leaves CONNECTING; then close with policy.
        await websocket.accept()
        await websocket.close(code=1008, reason="ws disabled")
        return
    await websocket.accept()
    qp = websocket.query_params
    qtok = qp.get("token") if SSE_ALLOW_QUERY_TOKEN else None
    backlog = min(500, max(0, int(qp.get("backlog") or 100)))
    filters: dict[str, Any] = {
        "min_level": qp.get("min_level"),
        "category": qp.get("category"),
        "device_id": qp.get("device_id"),
        "q": qp.get("q"),
    }
    filters = {k: v for k, v in filters.items() if v}
    ck = websocket.cookies.get(JWT_COOKIE_NAME) if JWT_USE_HTTPONLY_COOKIE else None
    auth_header = websocket.headers.get("authorization") or None
    try:
        principal = _principal_from_sse_headers_or_query(auth_header, qtok, ck)
        assert_min_role(principal, "user")
    except HTTPException:
        await websocket.close(code=1008, reason="auth failed")
        return

    sub = event_bus.subscribe(principal, filters)
    try:
        _hello_now = datetime.now(timezone.utc)
        _hello_ts = _hello_now.isoformat()
        hello = {
            "type": "hello",
            "event_type": "stream.hello",
            "level": "info",
            "category": "system",
            "ts": _hello_ts,
            "ts_malaysia": iso_timestamp_to_malaysia(_hello_ts),
            "ts_epoch_ms": int(_hello_now.timestamp() * 1000),
            "summary": f"connected as {principal.role}",
            "actor": "system",
            "detail": {"role": principal.role, "filters": filters},
            "id": 0,
        }
        await websocket.send_text(json.dumps(hello, default=str))
        if backlog:
            for ev in event_bus.backlog(principal, filters, backlog):
                await websocket.send_text(json.dumps({"type": "event", "ev": ev}, default=str))
        last_keepalive = time.time()
        while True:
            try:
                ev = await asyncio.to_thread(lambda: sub.q.get(timeout=1.0))
                await websocket.send_text(json.dumps({"type": "event", "ev": ev}, default=str))
            except _stdqueue.Empty:
                pass
            now = time.time()
            if now - last_keepalive >= EVENT_SSE_KEEPALIVE_SECONDS:
                last_keepalive = now
                await websocket.send_text(
                    json.dumps({"type": "ping", "ts": int(now * 1000), "dropped": sub.dropped}, default=str)
                )
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("events_ws failed")
    finally:
        event_bus.unsubscribe(sub)


__all__ = ("router",)
