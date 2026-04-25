"""Event center routes (Phase-8 modularization extract from ``app.py``).

Six endpoints around the unified event log — paginated browsing, CSV
export, per-device aggregations, taxonomy lookup, and two real-time
transports (SSE + WebSocket):

  * ``GET  /events``                — paginated history (DB-backed).
  * ``GET  /events/export.csv``     — UTF-8 CSV snapshot.
  * ``GET  /events/stats/by-device``— per-device counts over a window.
  * ``GET  /events/categories``     — level + category enums (UI dropdowns).
  * ``GET  /events/stream``         — Server-Sent Events stream.
  * ``WS   /events/ws``             — JSON WebSocket mirror of the stream.

Tenant isolation rules:
  * superadmin → every event in the system
  * admin      → events where ``owner_admin = self`` OR ``actor/target = self``
  * user       → events in their manager_admin's tenant that mention them
                 or are warn+

Late-bound dependencies on ``app.py``
-------------------------------------
This module captures the following from the ``app`` module *at import
time* (after ``app.py`` has executed past the relevant definitions):

  * ``require_principal``   (function — used in Depends())
  * ``_VALID_LEVELS``       (tuple — used in /events/categories and
                              /events min_level filter clamp)
  * ``_VALID_CATEGORIES``   (tuple — used in /events/categories)
  * ``event_bus``           (singleton — SSE + WS subscriber registry)
  * ``get_manager_admin``   (function — tenant scope resolution)

We deliberately reference the function objects directly in
``Depends(require_principal)`` rather than wrapping them in a lambda;
the lambda would strip FastAPI's parameter injection (Cookie / Header /
Request) and silently break auth. See routers/factory.py for the same
trap documented at length.

The event_bus is a singleton, so there is no shadowing concern: the
binding here and the binding in ``app.py`` are the same Python object.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import queue as _stdqueue
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
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
from db import db_lock, get_conn
from security import Principal, assert_min_role
from tz_display import iso_timestamp_to_malaysia

# Resolved once at import time; see module docstring.
require_principal = _app.require_principal
_VALID_LEVELS = _app._VALID_LEVELS
_VALID_CATEGORIES = _app._VALID_CATEGORIES
event_bus = _app.event_bus
get_manager_admin = _app.get_manager_admin

logger = logging.getLogger("croc-api.routers.events")

router = APIRouter(tags=["events"])


# ────────────────────────────────────────────────────────────── tenant scope ──

def _event_scope_sql(principal: Principal) -> tuple[str, list[Any]]:
    """Return WHERE fragment + args for the events table based on role."""
    if principal.role == "superadmin":
        return "", []
    if principal.role == "admin":
        frag = (
            " AND (owner_admin = ? OR actor = ? OR target = ?) "
            " AND actor NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin') "
        )
        return frag, [principal.username, principal.username, principal.username]
    my_admin = get_manager_admin(principal.username) or ""
    if not my_admin:
        return " AND 1=0 ", []
    frag = (
        " AND (owner_admin = ? AND (actor = ? OR target = ? OR level IN ('warn','error','critical'))) "
        " AND actor NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin') "
    )
    return frag, [my_admin, principal.username, principal.username]


def _events_filter_sql_args(
    principal: Principal,
    *,
    min_level: Optional[str],
    category: Optional[str],
    device_id: Optional[str],
    q: Optional[str],
    since_id: int,
    ts_epoch_min: Optional[int] = None,
) -> tuple[str, list[Any]]:
    """Shared WHERE clause + bind values for `/events*` queries."""
    sql = "WHERE 1=1"
    args: list[Any] = []
    scope_frag, scope_args = _event_scope_sql(principal)
    sql += scope_frag
    args.extend(scope_args)
    if min_level:
        try:
            idx = _VALID_LEVELS.index(min_level)
            allowed = _VALID_LEVELS[idx:]
            ph = ",".join(["?"] * len(allowed))
            sql += f" AND level IN ({ph}) "
            args.extend(allowed)
        except ValueError:
            pass
    if category:
        sql += " AND category = ? "
        args.append(category)
    if device_id:
        sql += " AND device_id = ? "
        args.append(device_id)
    if q:
        sql += " AND (event_type LIKE ? OR summary LIKE ? OR actor LIKE ? OR target LIKE ? OR device_id LIKE ?) "
        like = f"%{q}%"
        args.extend([like, like, like, like, like])
    if since_id > 0:
        sql += " AND id > ? "
        args.append(since_id)
    if ts_epoch_min is not None:
        sql += " AND ts_epoch_ms >= ? "
        args.append(int(ts_epoch_min))
    return sql, args


# ──────────────────────────────────────────────────────────────── paginated ──

@router.get("/events")
def list_events(
    principal: Principal = Depends(require_principal),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    since_id: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    """Paginated read-only access to the events table."""
    wf, wa = _events_filter_sql_args(
        principal,
        min_level=min_level,
        category=category,
        device_id=device_id,
        q=q,
        since_id=since_id,
    )
    sql = (
        "SELECT id, ts, ts_epoch_ms, level, category, event_type, actor, target, owner_admin, device_id, summary, detail_json, ref_table, ref_id "
        f"FROM events {wf} ORDER BY id DESC LIMIT ? "
    )
    args = list(wa)
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        raw = r.pop("detail_json", None)
        try:
            r["detail"] = json.loads(raw) if raw else {}
        except Exception:
            r["detail"] = {"_raw": raw}
        r["ts_malaysia"] = iso_timestamp_to_malaysia(str(r.get("ts") or ""))
    return {"items": rows, "count": len(rows)}


# ────────────────────────────────────────────────────────────────── csv ────

@router.get("/events/export.csv")
def export_events_csv(
    principal: Principal = Depends(require_principal),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    limit: int = Query(default=5000, ge=1, le=20000),
) -> StreamingResponse:
    """Download a UTF-8 CSV snapshot (same visibility rules as GET /events)."""
    wf, wa = _events_filter_sql_args(
        principal,
        min_level=min_level,
        category=category,
        device_id=device_id,
        q=q,
        since_id=0,
    )
    sql = (
        "SELECT id, ts, level, category, event_type, actor, target, owner_admin, device_id, summary, detail_json "
        f"FROM events {wf} ORDER BY id DESC LIMIT ? "
    )
    args = list(wa)
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = list(cur.fetchall())
        conn.close()

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            ["id", "ts", "ts_malaysia", "level", "category", "event_type", "actor", "target", "owner_admin", "device_id", "summary", "detail_json"],
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for r in rows:
            w.writerow(
                [
                    r["id"],
                    r["ts"],
                    iso_timestamp_to_malaysia(str(r["ts"] or "")),
                    r["level"],
                    r["category"],
                    r["event_type"],
                    r["actor"] or "",
                    r["target"] or "",
                    r["owner_admin"] or "",
                    r["device_id"] or "",
                    r["summary"] or "",
                    (r["detail_json"] or "").replace("\r\n", " ").replace("\n", " "),
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    headers = {"Content-Disposition": 'attachment; filename="croc_sentinel_events.csv"'}
    return StreamingResponse(gen(), media_type="text/csv; charset=utf-8", headers=headers)


# ──────────────────────────────────────────────────────────────── stats ────

@router.get("/events/stats/by-device")
def events_stats_by_device(
    principal: Principal = Depends(require_principal),
    hours: int = Query(default=168, ge=1, le=24 * 365),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    """Aggregate event counts per device_id over the last `hours` hours."""
    ts_min = int(time.time() * 1000) - hours * 3600 * 1000
    wf, wa = _events_filter_sql_args(
        principal,
        min_level=None,
        category=None,
        device_id=None,
        q=None,
        since_id=0,
        ts_epoch_min=ts_min,
    )
    sql = (
        f"SELECT device_id, COUNT(*) AS cnt FROM events {wf} "
        "AND IFNULL(device_id,'') != '' "
        "GROUP BY device_id ORDER BY cnt DESC LIMIT ? "
    )
    args = list(wa)
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [{"device_id": r["device_id"], "count": int(r["cnt"])} for r in cur.fetchall()]
        conn.close()
    return {"hours": hours, "items": rows}


# ────────────────────────────────────────────────────────── categories ────

@router.get("/events/categories")
def event_categories(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {"levels": list(_VALID_LEVELS), "categories": list(_VALID_CATEGORIES)}


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
