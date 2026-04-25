"""Device-revoke router (Phase-23 modularization).

Three small admin endpoints that flip a device into / out of the
"revoked" state — i.e. mark it untrusted by inserting (or removing) a
row in ``revoked_devices``. Admins also need ``can_send_command``
capability; superadmins see every tenant.

Routes
------
  GET  /devices/revoked
  POST /devices/{device_id}/revoke
  POST /devices/{device_id}/unrevoke

Schema moved with the routes
----------------------------
  DeviceRevokeRequest

Late-binding strategy
---------------------
Every helper used here is defined < line ~3000 in app.py, so they're
all early-bound (identity-preserved):

  require_principal, require_capability, assert_device_owner
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
assert_device_owner = _app.assert_device_owner


logger = logging.getLogger("croc-api.routers.device_revoke")

router = APIRouter(tags=["device-revoke"])


# ---- Schema ----------------------------------------------------------------

class DeviceRevokeRequest(BaseModel):
    reason: str = Field(default="manual revoke", min_length=3, max_length=200)


# ---- Routes ----------------------------------------------------------------

@router.get("/devices/revoked")
def list_revoked_devices(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("SELECT device_id, reason, revoked_by, revoked_at FROM revoked_devices ORDER BY revoked_at DESC")
        else:
            cur.execute(
                """
                SELECT r.device_id, r.reason, r.revoked_by, r.revoked_at
                FROM revoked_devices r
                JOIN device_ownership o ON r.device_id = o.device_id
                WHERE o.owner_admin = ?
                ORDER BY r.revoked_at DESC
                """,
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.post("/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    req: DeviceRevokeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO revoked_devices (device_id, reason, revoked_by, revoked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                reason = excluded.reason,
                revoked_by = excluded.revoked_by,
                revoked_at = excluded.revoked_at
            """,
            (device_id, req.reason, principal.username, utc_now_iso()),
        )
        cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
        deleted_acl_rows = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(
        principal.username,
        "device.revoke",
        device_id,
        {"reason": req.reason, "deleted_device_acl_rows": deleted_acl_rows},
    )
    return {"ok": True, "device_id": device_id}


@router.post("/devices/{device_id}/unrevoke")
def unrevoke_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "device.unrevoke", device_id, {})
    return {"ok": True, "device_id": device_id}
