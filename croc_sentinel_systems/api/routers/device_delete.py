"""Device-delete / factory-unregister router (Phase-26 modularization).

Two POST endpoints + a shared implementation helper. Both endpoints
unbind a device from its tenant; ``factory-unregister`` additionally
rolls the row in ``factory_devices`` back to ``unclaimed`` (a
superadmin-or-owner-admin operation) while ``delete-reset`` is
available to any tenant user with ``can_send_command``.

Routes
------
  POST /devices/{device_id}/delete-reset
  POST /devices/{device_id}/factory-unregister

Schema moved with the routes
----------------------------
  DeviceDeleteRequest

Late-binding strategy
---------------------
* Early-bound (identity-preserved) — defined long before the
  ``app.include_router`` call at line ~3920 in app.py:

    require_principal, require_capability, assert_device_owner,
    _try_mqtt_unclaim_reset

  ``_try_mqtt_unclaim_reset`` keeps living in app.py because it leans
  on a half-dozen MQTT plumbing globals (``publish_command``,
  ``_wait_cmd_ack``, ``TOPIC_ROOT``, ``CMD_PROTO``, …) that are
  cleaner to leave at the original site for now.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
assert_device_owner = _app.assert_device_owner
_try_mqtt_unclaim_reset = _app._try_mqtt_unclaim_reset


logger = logging.getLogger("croc-api.routers.device_delete")

router = APIRouter(tags=["device-delete"])


# ---- Schema ----------------------------------------------------------------

class DeviceDeleteRequest(BaseModel):
    confirm_text: str = Field(min_length=3, max_length=128)


# ---- Helper ---------------------------------------------------------------

def _device_delete_reset_impl(
    device_id: str,
    principal: Principal,
    req: DeviceDeleteRequest,
    *,
    super_unclaim: bool,
) -> dict[str, Any]:
    if str(req.confirm_text or "").strip().upper() != str(device_id or "").strip().upper():
        raise HTTPException(status_code=400, detail="confirm_text must exactly match device_id")
    require_capability(principal, "can_send_command")
    if super_unclaim:
        # Factory rollback: admin+ only (not subordinate "user" accounts).
        assert_min_role(principal, "admin")
        if not principal.is_superadmin():
            assert_device_owner(principal, device_id)
    else:
        assert_min_role(principal, "user")
        assert_device_owner(principal, device_id)
    nvs_purge_sent, nvs_purge_acked = _try_mqtt_unclaim_reset(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        p = cur.fetchone()
        mac_nocolon = str(p["mac_nocolon"]) if p and p["mac_nocolon"] else ""
        cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        del_cred = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
        del_owner = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
        del_acl = int(cur.rowcount or 0)
        cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
        del_revoked = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
        del_state = int(cur.rowcount or 0)
        cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
        del_sched = int(cur.rowcount or 0)
        # Keep factory registry aligned whenever this serial/MAC is known (same as
        # "factory-unregister" — also applies to normal tenant unbind so ops lists
        # and identify flows stay consistent after unlink).
        if mac_nocolon:
            cur.execute(
                "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE mac_nocolon = ?",
                (utc_now_iso(), mac_nocolon),
            )
        else:
            cur.execute(
                "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE serial = ?",
                (utc_now_iso(), device_id),
            )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    action = "device.factory_unclaim" if super_unclaim else "device.delete_reset"
    audit_event(
        principal.username,
        action,
        device_id,
        {
            "mac_nocolon": mac_nocolon or "",
            "nvs_purge_mqtt": nvs_purge_sent,
            "nvs_purge_ack": nvs_purge_acked,
            "deleted_credentials": del_cred,
            "deleted_owner": del_owner,
            "deleted_acl": del_acl,
            "deleted_revoked": del_revoked,
            "deleted_state": del_state,
            "deleted_scheduled": del_sched,
            "factory_unclaimed": super_unclaim,
        },
    )
    return {
        "ok": True,
        "device_id": device_id,
        "mode": "factory_unclaim" if super_unclaim else "delete_reset",
        "factory_unclaimed": super_unclaim,
        "nvs_purge_sent": nvs_purge_sent,
        "nvs_purge_acked": nvs_purge_acked,
        "nvs_purge_note": "sent=true means command reached broker; acked=true means device confirmed unclaim_reset before DB unlink.",
    }


# ---- Routes ----------------------------------------------------------------

@router.post("/devices/{device_id}/delete-reset")
def device_delete_reset(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Tenant user (operate) / admin / superadmin: unlink device + best-effort unclaim_reset."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=False)


@router.post("/devices/{device_id}/factory-unregister")
def device_factory_unregister(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Rollback to unregistered while keeping factory serial: superadmin (any device) or owning admin."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=True)


__all__ = [
    "router",
    "DeviceDeleteRequest",
    "_device_delete_reset_impl",
    "device_delete_reset",
    "device_factory_unregister",
]
