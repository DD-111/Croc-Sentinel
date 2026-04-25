"""Dashboard / device-messages read router (Phase-31 modularization).

Two sibling read-only endpoints that aggregate state for the operator
SPA. They live together because they share auth/zone shape and both
exclusively read from `device_state` / `messages` tables:

  GET /dashboard/overview          (tenant-scoped fleet summary card)
  GET /devices/{device_id}/messages (paginated raw MQTT-style log)

Late-binding strategy
---------------------
Almost everything is early-bound at import time (helpers were defined
< line ~4300 in app.py before Phase-31). The one exception is the
``mqtt_connected`` boolean, which is mutated by the MQTT thread inside
app.py and therefore must be read off the app module at call time —
binding it as a value here would freeze it to whatever it was when this
module loaded.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel  # noqa: F401  (kept for contract/import parity)

from notifier import notifier
import app as _app
from db import cache_get, cache_put, db_lock, db_read_lock, get_conn
from security import (
    Principal,
    assert_min_role,
    assert_zone_for_device,
)

require_principal = _app.require_principal
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state
get_manager_admin = _app.get_manager_admin
_parse_iso = _app._parse_iso
_effective_online_for_presence = _app._effective_online_for_presence
assert_device_view_access = _app.assert_device_view_access
OFFLINE_THRESHOLD_SECONDS = _app.OFFLINE_THRESHOLD_SECONDS


logger = logging.getLogger("croc-api.routers.dashboard_read")

router = APIRouter(tags=["dashboard-read"])


@router.get("/dashboard/overview")
def dashboard_overview(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "overview" if (principal.is_superadmin() or principal.has_all_zones()) else f"overview:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    args = tuple(za + osa)
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) AS c FROM device_state WHERE 1=1 {zs} {osf}", args)
        total = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM device_state
            WHERE last_status_json IS NOT NULL {zs} {osf}
            """,
            args,
        )
        with_status = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT fw, chip_target, board_profile, net_type, COUNT(*) AS c
            FROM device_state
            WHERE 1=1 {zs} {osf}
            GROUP BY fw, chip_target, board_profile, net_type
            ORDER BY c DESC
            """,
            args,
        )
        grouped = [dict(r) for r in cur.fetchall()]
        cur.execute(
            f"""
            SELECT device_id, updated_at, last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state
            WHERE 1=1 {zs} {osf}
            """,
            args,
        )
        presence_rows = cur.fetchall()
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM alarms
            WHERE created_at >= datetime('now', '-24 hours')
              AND (? = '' OR owner_admin = ?)
            """,
            ("" if principal.is_superadmin() else "x",
             "" if principal.is_superadmin() else (
                 principal.username if principal.role == "admin"
                 else get_manager_admin(principal.username)
             )),
        )
        alarms_24h = int(cur.fetchone()["c"])
        conn.close()
    now_s = time.time()
    presence = {
        "online": 0,
        "offline_total": 0,
        "reason_power_low": 0,
        "reason_network_lost": 0,
        "reason_signal_weak": 0,
        "reason_unknown": 0,
    }
    tx_bps_total = 0.0
    rx_bps_total = 0.0
    for r in presence_rows:
        raw = r["last_status_json"] or ""
        try:
            s = json.loads(raw) if raw else {}
        except Exception:
            s = {}
        raw_hb = r["last_heartbeat_json"] or ""
        try:
            hb = json.loads(raw_hb) if raw_hb else {}
        except Exception:
            hb = {}
        raw_ack = r["last_ack_json"] or ""
        try:
            ack = json.loads(raw_ack) if raw_ack else {}
        except Exception:
            ack = {}
        raw_ev = r["last_event_json"] or ""
        try:
            ev = json.loads(raw_ev) if raw_ev else {}
        except Exception:
            ev = {}
        updated = _parse_iso(str(r["updated_at"] or ""))
        fresh = (now_s - updated) < OFFLINE_THRESHOLD_SECONDS
        is_online = _effective_online_for_presence(s, hb, ack, ev) and fresh
        if is_online:
            presence["online"] += 1
            try:
                tx_bps_total += float(s.get("tx_bps") or 0)
                rx_bps_total += float(s.get("rx_bps") or 0)
            except (TypeError, ValueError):
                pass
        else:
            presence["offline_total"] += 1
            reason = str(s.get("disconnect_reason") or "")
            if reason == "power_low":
                presence["reason_power_low"] += 1
            elif reason == "network_lost" or (now_s - updated) >= OFFLINE_THRESHOLD_SECONDS:
                presence["reason_network_lost"] += 1
            elif reason == "signal_weak":
                presence["reason_signal_weak"] += 1
            else:
                presence["reason_unknown"] += 1
    out = {
        "total_devices": total,
        "devices_with_status": with_status,
        "groups": grouped,
        "mqtt_connected": _app.mqtt_connected,
        "presence": presence,
        "throughput": {
            "tx_bps_total": round(tx_bps_total, 1),
            "rx_bps_total": round(rx_bps_total, 1),
        },
        "alarms_24h": alarms_24h,
        "notifier": notifier.status() if principal.is_adminish() else {"enabled": notifier.enabled()},
        "ts": int(time.time()),
    }
    cache_put(cache_key, out)
    return out


@router.get("/devices/{device_id}/messages")
def get_device_messages(
    device_id: str,
    channel: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")

    query = """
        SELECT id, topic, channel, device_id, payload_json, ts_device, ts_received
        FROM messages
        WHERE device_id = ?
    """
    args: list[Any] = [device_id]
    if channel:
        query += " AND channel = ?"
        args.append(channel)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    for r in rows:
        r["payload"] = json.loads(r.pop("payload_json"))
    return {"items": rows}


__all__ = [
    "router",
    "dashboard_overview",
    "get_device_messages",
]
