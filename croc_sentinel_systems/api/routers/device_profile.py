"""Device-profile router (Phase-27 modularization).

Three mutation endpoints on a device's profile fields (display_label,
notification_group, zone override) — plus a bulk variant for production
operations. All routes share a single internal helper
(:func:`_apply_device_profile_update`) so the per-device PATCH and the
legacy display-label PATCH stay in lock-step.

Routes
------
  PATCH /devices/{device_id}/profile
  PATCH /devices/{device_id}/display-label   (legacy, label-only)
  POST  /devices/bulk/profile

Schemas moved with the routes
-----------------------------
  DeviceDisplayLabelBody, DeviceProfileBody, DeviceBulkProfileBody

Late-binding strategy
---------------------
Every helper used here is defined < line ~4500 in app.py, so they are
all early-bound (identity preserved at module-import time):

  require_principal, emit_event, assert_device_owner,
  _lookup_owner_admin, _principal_tenant_owns_device,
  _extract_zone_from_device_state_row
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from db import cache_invalidate, db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
emit_event = _app.emit_event
assert_device_owner = _app.assert_device_owner
_lookup_owner_admin = _app._lookup_owner_admin
_principal_tenant_owns_device = _app._principal_tenant_owns_device
_extract_zone_from_device_state_row = _app._extract_zone_from_device_state_row


logger = logging.getLogger("croc-api.routers.device_profile")

router = APIRouter(tags=["device-profile"])


# ---- Schemas ---------------------------------------------------------------

class DeviceDisplayLabelBody(BaseModel):
    display_label: str = Field(default="", max_length=80)


class DeviceProfileBody(BaseModel):
    display_label: Optional[str] = Field(default=None, max_length=80)
    notification_group: Optional[str] = Field(default=None, max_length=80)


class DeviceBulkProfileBody(BaseModel):
    device_ids: list[str] = Field(default_factory=list, min_length=1, max_length=500)
    set_notification_group: bool = False
    notification_group: Optional[str] = Field(default=None, max_length=80)
    set_zone_override: bool = False
    zone_override: Optional[str] = Field(default=None, max_length=31)
    clear_zone_override: bool = False


# ---- Helper ---------------------------------------------------------------

def _apply_device_profile_update(
    device_id: str,
    principal: Principal,
    body: DeviceProfileBody,
) -> dict[str, Any]:
    if body.display_label is None and body.notification_group is None:
        raise HTTPException(
            status_code=400,
            detail="provide at least one of display_label, notification_group",
        )
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row_owner = _lookup_owner_admin(device_id) or ""
    if body.notification_group is not None and not _principal_tenant_owns_device(principal, row_owner):
        raise HTTPException(
            status_code=403,
            detail="only the owning tenant may change notification_group; shared access is device-scoped",
        )
    sets: list[str] = []
    args: list[Any] = []
    if body.display_label is not None:
        sets.append("display_label = ?")
        args.append(body.display_label.strip())
    if body.notification_group is not None:
        sets.append("notification_group = ?")
        args.append(body.notification_group.strip())
    # Do not touch device_state.updated_at here: it is used for MQTT freshness
    # (overview presence, dashboard isOnline). Profile edits are not device traffic.
    args.append(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT zone, display_label, notification_group FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        zr = cur.fetchone()
        if not zr:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
        old_label = (str(zr["display_label"]).strip() if zr["display_label"] is not None else "")
        old_group = (str(zr["notification_group"]).strip() if zr["notification_group"] is not None else "")
        cur.execute(
            f"UPDATE device_state SET {', '.join(sets)} WHERE device_id = ?",
            tuple(args),
        )
        conn.commit()
        conn.close()
    new_label = (body.display_label.strip() if body.display_label is not None else old_label)
    new_group = (body.notification_group.strip() if body.notification_group is not None else old_group)
    group_changed = body.notification_group is not None and new_group != old_group
    label_changed = body.display_label is not None and new_label != old_label
    cache_invalidate("devices")
    cache_invalidate("overview")
    emit_event(
        level="info",
        category="device",
        event_type="device.profile",
        summary=f"device profile updated {device_id}",
        actor=principal.username,
        target=device_id,
        device_id=device_id,
        detail={
            "display_label": new_label,
            "notification_group": new_group,
            "previous_display_label": old_label,
            "previous_notification_group": old_group,
            "display_label_changed": label_changed,
            "notification_group_changed": group_changed,
        },
    )
    out: dict[str, Any] = {"ok": True, "device_id": device_id}
    if body.display_label is not None:
        out["display_label"] = new_label
    if body.notification_group is not None:
        out["notification_group"] = new_group
    return out


# ---- Routes ----------------------------------------------------------------

@router.patch("/devices/{device_id}/profile")
def patch_device_profile(
    device_id: str,
    body: DeviceProfileBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _apply_device_profile_update(device_id, principal, body)


@router.patch("/devices/{device_id}/display-label")
def patch_device_display_label(
    device_id: str,
    body: DeviceDisplayLabelBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Legacy: only updates display_label."""
    return _apply_device_profile_update(
        device_id,
        principal,
        DeviceProfileBody(display_label=body.display_label, notification_group=None),
    )


@router.post("/devices/bulk/profile")
def bulk_patch_device_profile(
    body: DeviceBulkProfileBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Bulk profile update for production operations (group + zone override)."""
    assert_min_role(principal, "user")
    ids = []
    seen = set()
    for raw in body.device_ids:
        did = str(raw or "").strip()
        if not did or did in seen:
            continue
        seen.add(did)
        ids.append(did)
    if not ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    if len(ids) > 500:
        raise HTTPException(status_code=400, detail="too many device_ids (max 500)")
    if not body.set_notification_group and not body.set_zone_override and not body.clear_zone_override:
        raise HTTPException(status_code=400, detail="no bulk operation selected")
    if body.set_zone_override and body.clear_zone_override:
        raise HTTPException(status_code=400, detail="set_zone_override and clear_zone_override are mutually exclusive")
    for did in ids:
        assert_device_owner(principal, did)
        if body.set_notification_group:
            o = _lookup_owner_admin(did) or ""
            if not _principal_tenant_owns_device(principal, o):
                raise HTTPException(
                    status_code=403,
                    detail=f"notification_group bulk-set denied for shared device {did} (owner-tenant only)",
                )
    notif_group = (str(body.notification_group or "").strip() if body.set_notification_group else None)
    zone_override = (str(body.zone_override or "").strip() if body.set_zone_override else None)
    if body.set_zone_override and not zone_override:
        raise HTTPException(status_code=400, detail="zone_override cannot be empty when set_zone_override=true")
    changed_group = 0
    changed_zone = 0
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for did in ids:
            if body.set_notification_group:
                cur.execute(
                    "UPDATE device_state SET notification_group = ? WHERE device_id = ?",
                    (notif_group, did),
                )
                changed_group += int(cur.rowcount or 0)
            if body.set_zone_override:
                cur.execute(
                    """
                    INSERT INTO device_zone_overrides (device_id, zone, updated_by, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                      zone = excluded.zone,
                      updated_by = excluded.updated_by,
                      updated_at = excluded.updated_at
                    """,
                    (did, zone_override, principal.username, now),
                )
                cur.execute("UPDATE device_state SET zone = ? WHERE device_id = ?", (zone_override, did))
                changed_zone += int(cur.rowcount or 0)
            if body.clear_zone_override:
                cur.execute("DELETE FROM device_zone_overrides WHERE device_id = ?", (did,))
                cur.execute(
                    """
                    SELECT last_status_json, last_heartbeat_json, last_ack_json, last_event_json
                    FROM device_state WHERE device_id = ?
                    """,
                    (did,),
                )
                zrow = cur.fetchone()
                zone_from_payload = _extract_zone_from_device_state_row(zrow)
                cur.execute("UPDATE device_state SET zone = ? WHERE device_id = ?", (zone_from_payload, did))
                changed_zone += int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    emit_event(
        level="info",
        category="device",
        event_type="device.bulk_profile",
        summary=f"bulk profile update {len(ids)} device(s)",
        actor=principal.username,
        target="devices",
        detail={
            "count": len(ids),
            "set_notification_group": bool(body.set_notification_group),
            "notification_group": notif_group if body.set_notification_group else None,
            "set_zone_override": bool(body.set_zone_override),
            "zone_override": zone_override if body.set_zone_override else None,
            "clear_zone_override": bool(body.clear_zone_override),
            "changed_group_rows": changed_group,
            "changed_zone_rows": changed_zone,
        },
    )
    return {
        "ok": True,
        "count": len(ids),
        "changed_group_rows": changed_group,
        "changed_zone_rows": changed_zone,
        "set_notification_group": bool(body.set_notification_group),
        "set_zone_override": bool(body.set_zone_override),
        "clear_zone_override": bool(body.clear_zone_override),
    }


__all__ = [
    "router",
    "DeviceDisplayLabelBody",
    "DeviceProfileBody",
    "DeviceBulkProfileBody",
    "_apply_device_profile_update",
    "patch_device_profile",
    "patch_device_display_label",
    "bulk_patch_device_profile",
]
