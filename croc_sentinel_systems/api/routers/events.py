"""Event center read-only routes (Phase-8, trimmed in Phase-68).

The original Phase-8 module covered both halves of the event surface:
DB-backed history queries and the live SSE/WebSocket transports.
Phase 68 split the live transports into ``routers/events_stream.py``
because they share *no* helpers — the read endpoints filter via
SQL through ``_events_filter_sql_args``, while the streamers filter
via per-subscriber dicts handed to the singleton ``event_bus``.

This file now hosts the four read-only endpoints:

  * ``GET /events``                — paginated history (DB-backed).
  * ``GET /events/export.csv``     — UTF-8 CSV snapshot.
  * ``GET /events/stats/by-device``— per-device counts over a window.
  * ``GET /events/categories``     — level + category enums (UI dropdowns).

Tenant isolation rules (unchanged, still in ``_event_scope_sql``):
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
  * ``get_manager_admin``   (function — tenant scope resolution)

We deliberately reference the function objects directly in
``Depends(require_principal)`` rather than wrapping them in a lambda;
the lambda would strip FastAPI's parameter injection (Cookie / Header /
Request) and silently break auth. See routers/factory.py for the same
trap documented at length.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

import app as _app
from db import db_lock, get_conn
from security import Principal, assert_min_role
from tz_display import iso_timestamp_to_malaysia

require_principal = _app.require_principal
_VALID_LEVELS = _app._VALID_LEVELS
_VALID_CATEGORIES = _app._VALID_CATEGORIES
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


__all__ = (
    "router",
    "_event_scope_sql",
    "_events_filter_sql_args",
)
