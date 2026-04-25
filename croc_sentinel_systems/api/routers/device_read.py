"""Device-read router (Phase-28 modularization).

Four read-only GET endpoints that the dashboard relies on for its main
device list, the per-device detail panel, the OTA "newer firmware
available" hints, and the sibling fan-out preview used when authoring
group cards.

Routes
------
  GET /devices
  GET /devices/firmware-hints
  GET /devices/{device_id}
  GET /devices/{device_id}/siblings-preview

Late-binding strategy
---------------------
Most helpers live < line ~4400 in app.py and are bound at module-import
time:

  require_principal, zone_sql_suffix, owner_scope_clause_for_device_state,
  get_manager_admin, _device_access_flags, _redact_notification_group_for_principal,
  assert_device_view_access, _lookup_owner_admin, _principal_tenant_owns_device,
  _tenant_siblings, _device_is_online_parsed, _device_presence_ages,
  _device_is_online_sql_row, _row_json_val, _net_health_from_status,
  _status_preview_from_device_row, _get_ota_firmware_catalog,
  _firmware_update_hint_for_current_in_catalog

``_cmd_queue_pending_counts`` is defined AFTER the router-include call
(at line ~5100) so it's wrapped via a small call-time forwarder so the
router module itself can be imported eagerly without an
``AttributeError``.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

import app as _app
from config import ALARM_FANOUT_MAX_TARGETS
from db import cache_get, cache_put, db_read_lock, get_conn
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state
get_manager_admin = _app.get_manager_admin
_device_access_flags = _app._device_access_flags
_redact_notification_group_for_principal = _app._redact_notification_group_for_principal
assert_device_view_access = _app.assert_device_view_access
_lookup_owner_admin = _app._lookup_owner_admin
_principal_tenant_owns_device = _app._principal_tenant_owns_device
_tenant_siblings = _app._tenant_siblings
_device_is_online_parsed = _app._device_is_online_parsed
_device_presence_ages = _app._device_presence_ages
_device_is_online_sql_row = _app._device_is_online_sql_row
_row_json_val = _app._row_json_val
_net_health_from_status = _app._net_health_from_status
_status_preview_from_device_row = _app._status_preview_from_device_row
_get_ota_firmware_catalog = _app._get_ota_firmware_catalog
_firmware_update_hint_for_current_in_catalog = _app._firmware_update_hint_for_current_in_catalog


# ``_cmd_queue_pending_counts`` is defined later in app.py (~line 5100)
# than the include_router call site (~4400), so we wrap the lookup in a
# call-time forwarder. Identity drift here is acceptable: nothing else
# imports it through this router module.
def _cmd_queue_pending_counts(*args: Any, **kwargs: Any) -> dict[str, int]:
    return _app._cmd_queue_pending_counts(*args, **kwargs)


logger = logging.getLogger("croc-api.routers.device_read")

router = APIRouter(tags=["device-read"])


@router.get("/devices")
def list_devices(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "devices:list" if (principal.is_superadmin() or principal.has_all_zones()) else f"devices:list:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, d.fw, d.chip_target, d.board_profile, d.net_type, d.zone, d.provisioned,
                   o.owner_admin,
                   IFNULL(display_label, '') AS display_label,
                   IFNULL(notification_group, '') AS notification_group, updated_at,
                   last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE 1=1 {zs} {osf}
            ORDER BY d.updated_at DESC
            """,
            tuple(za + osa),
        )
        now_s = int(time.time())
        rows_out: list[dict[str, Any]] = []
        for r in cur.fetchall():
            d = dict(r)
            d["is_online"] = _device_is_online_sql_row(d, now_s)
            d["status_preview"] = _status_preview_from_device_row(d)
            d["net_health"] = _net_health_from_status(d.get("last_status_json"))
            d.update(
                _device_presence_ages(
                    _row_json_val(d.get("last_status_json")),
                    _row_json_val(d.get("last_heartbeat_json")),
                    _row_json_val(d.get("last_ack_json")),
                    _row_json_val(d.get("last_event_json")),
                    str(d.get("updated_at") or ""),
                    now_s,
                )
            )
            owner_admin = str(d.get("owner_admin") or "")
            d.pop("last_status_json", None)
            d.pop("last_heartbeat_json", None)
            d.pop("last_ack_json", None)
            d.pop("last_event_json", None)
            _redact_notification_group_for_principal(principal, owner_admin, d)
            if principal.role != "superadmin":
                viewer_admin = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or "")
                is_shared = bool(owner_admin) and bool(viewer_admin) and owner_admin != viewer_admin
                d["is_shared"] = bool(is_shared)
                if is_shared:
                    d["shared_by"] = owner_admin
                d.pop("owner_admin", None)
            rows_out.append(d)
        conn.close()
    # Bulk-join pending command counts so the dashboard can render a
    # "X pending" chip next to devices that have queued MQTT commands.
    try:
        ids = [str(r.get("device_id") or "") for r in rows_out if r.get("device_id")]
        counts = _cmd_queue_pending_counts(ids) if ids else {}
        for r in rows_out:
            r["pending_cmds"] = int(counts.get(str(r.get("device_id") or ""), 0))
    except Exception as exc:
        logger.debug("devices list: pending_cmds join failed: %s", exc)
    out = {"items": rows_out}
    cache_put(cache_key, out)
    return out


@router.get("/devices/firmware-hints")
def list_devices_firmware_hints(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Per-device "newer .bin on disk" hint for the signed-in scope (no superadmin OTA UI required)."""
    assert_min_role(principal, "user")
    catalog = _get_ota_firmware_catalog()
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, d.fw
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE 1=1 {zs} {osf}
            """,
            tuple(za + osa),
        )
        rows = [dict(x) for x in cur.fetchall()]
        conn.close()
    hints: dict[str, Any] = {}
    for r in rows:
        did = str(r.get("device_id") or "")
        if not did:
            continue
        cur_fw = str(r.get("fw") or "")
        h = _firmware_update_hint_for_current_in_catalog(cur_fw, catalog)
        if h:
            hints[did] = h
    return {"hints": hints, "ts": int(time.time())}


@router.get("/devices/{device_id}")
def get_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM device_state WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        cur.execute(
            """
            SELECT o.owner_admin, o.assigned_by, o.assigned_at, IFNULL(u.email, '') AS owner_email
            FROM device_ownership o
            LEFT JOIN dashboard_users u ON u.username = o.owner_admin
            WHERE o.device_id = ?
            """,
            (device_id,),
        )
        ow = cur.fetchone()
        conn.close()
    assert_zone_for_device(principal, str(row["zone"]) if row["zone"] is not None else "")
    can_view, can_operate = _device_access_flags(principal, device_id)

    out = dict(row)
    for key in ("last_status_json", "last_heartbeat_json", "last_ack_json", "last_event_json"):
        if out.get(key):
            out[key] = json.loads(out[key])
    now_s = int(time.time())
    out["is_online"] = _device_is_online_parsed(
        out.get("last_status_json") or {},
        out.get("last_heartbeat_json") or {},
        out.get("last_ack_json") or {},
        out.get("last_event_json") or {},
        str(out.get("updated_at") or ""),
        now_s,
    )
    out.update(
        _device_presence_ages(
            out.get("last_status_json") or {},
            out.get("last_heartbeat_json") or {},
            out.get("last_ack_json") or {},
            out.get("last_event_json") or {},
            str(out.get("updated_at") or ""),
            now_s,
        )
    )
    # Firmware net_health (Wi-Fi/MQTT reconnect counters, longest offline
    # gaps, last disconnect reason code). Surfaced here so the device detail
    # page can render a "connectivity stability" card. Empty {} on older fw.
    out["net_health"] = _net_health_from_status(out.get("last_status_json") or {})
    # Pending server-side commands waiting for delivery (MQTT replay or HTTP
    # backup pull). Exposed for the device page's "X pending" chip.
    try:
        out["pending_cmds"] = int(_cmd_queue_pending_counts([device_id]).get(device_id, 0))
    except Exception:
        out["pending_cmds"] = 0
    owner_admin = str(ow["owner_admin"]) if ow and ow["owner_admin"] is not None else ""
    out["owner_admin"] = owner_admin
    out["owner_email"] = str(ow["owner_email"]) if ow and ow["owner_email"] is not None else ""
    if principal.role == "superadmin":
        out["registered_by"] = str(ow["assigned_by"]) if ow else ""
        out["registered_at"] = str(ow["assigned_at"]) if ow else ""
    else:
        viewer_admin = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or "")
        is_shared = bool(owner_admin) and bool(viewer_admin) and owner_admin != viewer_admin
        out["is_shared"] = bool(is_shared)
        if is_shared:
            out["shared_by"] = owner_admin
    _redact_notification_group_for_principal(principal, owner_admin, out)
    out["can_view"] = bool(can_view)
    out["can_operate"] = bool(can_operate)
    cat = _get_ota_firmware_catalog()
    out["firmware_hint"] = _firmware_update_hint_for_current_in_catalog(str(out.get("fw") or ""), cat)
    return out


@router.get("/devices/{device_id}/siblings-preview")
def preview_device_siblings(
    device_id: str,
    include_source: bool = Query(default=False),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Debug helper: resolve current sibling fan-out targets for a device."""
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(zone,''), IFNULL(notification_group,'') FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    zone = str(row[0] or "").strip()
    group_key = str(row[1] or "").strip()
    assert_zone_for_device(principal, zone)
    owner_admin = _lookup_owner_admin(device_id)
    if not _principal_tenant_owns_device(principal, owner_admin):
        raise HTTPException(
            status_code=403,
            detail="sibling preview is available to the owning tenant only",
        )
    targets, eligible_total = _tenant_siblings(
        owner_admin,
        device_id,
        source_zone=zone,
        source_group=group_key,
        include_source=bool(include_source),
    )
    out: dict[str, Any] = {
        "ok": True,
        "device_id": device_id,
        "zone": zone,
        "notification_group": group_key,
        "fanout_enabled": bool(group_key),
        "target_count": len(targets),
        "eligible_total": eligible_total,
        "fanout_capped": eligible_total > len(targets),
        "fanout_max": ALARM_FANOUT_MAX_TARGETS,
        "targets": [{"device_id": did, "zone": z} for did, z in targets],
    }
    if principal.role == "superadmin":
        out["owner_admin"] = owner_admin or ""
    return out


__all__ = [
    "router",
    "list_devices",
    "list_devices_firmware_hints",
    "get_device",
    "preview_device_siblings",
]
