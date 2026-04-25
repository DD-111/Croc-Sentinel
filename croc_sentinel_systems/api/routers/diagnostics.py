"""Diagnostics router (Phase-32 modularization).

Three operator/LB-facing health and inspection endpoints, all of which
return server-side state rather than performing operator actions:

  GET  /health                 (no-auth liveness for LBs / curl)
  GET  /admin/presence-probes  (admin+ scoped probe-history view)
  GET  /diag/db-ping           (admin+ SQLite latency probe)

Three /health-only helpers ride along with the route since they're
unused outside this module:

  _health_notify_summary_public   (SMTP+TG liveness w/o secrets)
  _health_db_probe                (cheap SELECT 1 probe)
  _health_subscriber_summary      (SSE/WS subscriber peek)

Late-binding strategy
---------------------
The mqtt_* + api_ready_event + api_bootstrap_error globals are mutated
by their respective worker threads inside app.py, so they're read off
``_app`` *at call time* inside ``/health`` to avoid freezing a stale
snapshot. Everything else is early-bound (helpers, security primitives,
config constants).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from notifier import notifier
import app as _app
from config import EVENT_MAX_SUBSCRIBERS, HEALTH_PUBLIC_DETAIL
from db import db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal
event_bus = _app.event_bus


logger = logging.getLogger("croc-api.routers.diagnostics")

router = APIRouter(tags=["diagnostics"])


# ---- /health-only helpers --------------------------------------------------

def _health_notify_summary_public() -> tuple[dict[str, Any], dict[str, Any]]:
    """Mail/TG liveness without secrets (for HEALTH_PUBLIC_DETAIL=0). Keeps dashboard pills honest."""
    smtp = {"configured": notifier.enabled(), "worker_running": notifier.worker_alive()}
    tg: dict[str, Any] = {"enabled": False, "worker_running": False, "last_error": ""}
    try:
        from telegram_notify import telegram_status

        full = dict(telegram_status())
        tg = {
            "enabled": bool(full.get("enabled")),
            "worker_running": bool(full.get("worker_running")),
            "last_error": str(full.get("last_error") or "")[:240],
        }
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "last_error": str(exc)[:240]}
    return smtp, tg


def _health_db_probe(timeout_s: float = 1.5) -> dict[str, Any]:
    """Fast DB liveness probe: run `SELECT 1` with a tight budget.
    Returns {ok, latency_ms, error?}. Never raises.
    """
    t0 = time.monotonic()
    out: dict[str, Any] = {"ok": False, "latency_ms": 0}
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            out["ok"] = True
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as exc:
        out["error"] = str(exc)[:240]
    latency_ms = int((time.monotonic() - t0) * 1000)
    out["latency_ms"] = latency_ms
    out["slow"] = latency_ms > int(timeout_s * 1000)
    return out


def _health_subscriber_summary() -> dict[str, Any]:
    try:
        with event_bus._lock:  # noqa: SLF001 — intentional peek
            n = len(event_bus._subs)  # noqa: SLF001
            dropped = sum(int(getattr(s, "dropped", 0)) for s in event_bus._subs.values())  # noqa: SLF001
        return {"count": n, "cap": int(EVENT_MAX_SUBSCRIBERS), "dropped_total": dropped}
    except Exception:
        return {"count": 0, "cap": int(EVENT_MAX_SUBSCRIBERS), "dropped_total": 0}


# ---- Routes ----------------------------------------------------------------

@router.get("/health")
def health() -> dict[str, Any]:
    """Liveness for load balancers / `curl` — intentionally **no** auth so Uptime
    Kuma, Docker healthchecks, and reverse proxies can probe without a token."""
    ready = _app.api_ready_event.is_set() and not _app.api_bootstrap_error
    db_probe = _health_db_probe()
    # Flip `ok` to False when DB is actually stalled — this is the load-balancer
    # signal that says "pull this worker out of rotation".
    db_ok = bool(db_probe.get("ok"))
    subs = _health_subscriber_summary()
    if not HEALTH_PUBLIC_DETAIL:
        smtp, tg = _health_notify_summary_public()
        # MQTT + mail/TG worker truth; FCM/token hints still only when HEALTH_PUBLIC_DETAIL=1.
        body = {
            "ok": bool(ready and db_ok),
            "ready": ready,
            "starting": not _app.api_ready_event.is_set(),
            "db": db_probe,
            "sse_subscribers": subs,
            "mqtt_connected": _app.mqtt_connected,
            "mqtt_ingest_queue_depth": _app.mqtt_ingest_queue.qsize(),
            "mqtt_ingest_dropped": _app.mqtt_ingest_dropped,
            "mqtt_last_connect_at": _app.mqtt_last_connect_at,
            "mqtt_last_disconnect_at": _app.mqtt_last_disconnect_at,
            "mqtt_last_disconnect_reason": _app.mqtt_last_disconnect_reason,
            "smtp": smtp,
            "telegram": tg,
            "ts": int(time.time()),
        }
        if _app.api_bootstrap_error:
            body["bootstrap_error"] = _app.api_bootstrap_error
        return body
    tg: dict[str, Any] = {}
    try:
        from telegram_notify import telegram_status

        tg = dict(telegram_status())
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "error": str(exc)}
    fcm: dict[str, Any] = {}
    try:
        from fcm_notify import fcm_status

        fcm = dict(fcm_status())
    except Exception as exc:
        fcm = {"enabled": False, "error": str(exc), "queue_size": 0, "worker_running": False}
    body = {
        "ok": bool(ready and db_ok),
        "ready": ready,
        "starting": not _app.api_ready_event.is_set(),
        "db": db_probe,
        "sse_subscribers": subs,
        "mqtt_connected": _app.mqtt_connected,
        "mqtt_ingest_queue_depth": _app.mqtt_ingest_queue.qsize(),
        "mqtt_ingest_dropped": _app.mqtt_ingest_dropped,
        "mqtt_last_connect_at": _app.mqtt_last_connect_at,
        "mqtt_last_disconnect_at": _app.mqtt_last_disconnect_at,
        "mqtt_last_disconnect_reason": _app.mqtt_last_disconnect_reason,
        "smtp": {
            "configured": notifier.enabled(),
            "worker_running": notifier.worker_alive(),
        },
        "telegram": tg,
        "fcm": fcm,
        "ts": int(time.time()),
    }
    if _app.api_bootstrap_error:
        body["bootstrap_error"] = _app.api_bootstrap_error
    return body


@router.get("/admin/presence-probes")
def list_presence_probes(
    principal: Principal = Depends(require_principal),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    sql = (
        "SELECT id, device_id, owner_admin, probe_ts, idle_seconds, outcome, detail "
        "FROM presence_probes WHERE 1=1 "
    )
    args: list[Any] = []
    if device_id:
        sql += "AND device_id = ? "
        args.append(device_id)
    if principal.role == "admin":
        sql += "AND (owner_admin = ? OR owner_admin IS NULL) "
        args.append(principal.username)
    sql += "ORDER BY probe_ts DESC LIMIT ?"
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.get("/diag/db-ping")
def diag_db_ping(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Cheap SQLite latency probe — use when the UI feels slow (admin+)."""
    assert_min_role(principal, "admin")
    t0 = time.perf_counter()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
    return {"ok": True, "db_ms": round((time.perf_counter() - t0) * 1000, 3), "pid": os.getpid()}


__all__ = [
    "router",
    "health",
    "list_presence_probes",
    "diag_db_ping",
    "_health_notify_summary_public",
    "_health_db_probe",
    "_health_subscriber_summary",
]
