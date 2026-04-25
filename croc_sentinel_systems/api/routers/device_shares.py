"""Device sharing / ACL admin routes (Phase-16 modularization extract from ``app.py``).

A "share" is a row in ``device_acl`` granting another user
view/operate access to a device they don't own. Four endpoints:

  GET    /admin/devices/{device_id}/shares                — per-device grants
  GET    /admin/shares                                    — fleet-wide grants (with filters)
  POST   /admin/devices/{device_id}/share                 — grant or update share
  DELETE /admin/devices/{device_id}/share/{grantee}       — revoke share

Tenant model
------------
- admin: requires ``can_manage_users`` capability AND must own the
  device (``assert_device_owner``); for the global ``/admin/shares``
  feed, results are scoped to devices owned by this admin and
  grantees that the admin manages.
- superadmin: sees and edits everything.

Helpers and schemas (moved with routes)
---------------------------------------
  Pydantic body: ``DeviceShareRequest``

The helpers ``assert_device_owner`` and ``require_capability`` stay in
``app.py`` and are late-bound here.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
assert_device_owner = _app.assert_device_owner

logger = logging.getLogger("croc-api.routers.device_shares")

router = APIRouter(tags=["device-shares"])


class DeviceShareRequest(BaseModel):
    grantee_username: str = Field(min_length=2, max_length=64)
    can_view: bool = True
    can_operate: bool = False


@router.get("/admin/devices/{device_id}/shares")
def list_device_shares(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
        assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT a.device_id, a.grantee_username, u.role AS grantee_role,
                       a.can_view, a.can_operate, a.granted_by, a.granted_at, a.revoked_at
                FROM device_acl a
                LEFT JOIN dashboard_users u ON u.username = a.grantee_username
                WHERE a.device_id = ?
                ORDER BY a.revoked_at IS NOT NULL ASC, a.granted_at DESC
                """,
                (device_id,),
            )
        else:
            cur.execute(
                """
                SELECT a.device_id, a.grantee_username, u.role AS grantee_role,
                       a.can_view, a.can_operate, a.granted_by, a.granted_at, a.revoked_at
                FROM device_acl a
                LEFT JOIN dashboard_users u ON u.username = a.grantee_username
                WHERE a.device_id = ?
                  AND u.role = 'user'
                  AND IFNULL(u.manager_admin,'') = ?
                ORDER BY a.revoked_at IS NOT NULL ASC, a.granted_at DESC
                """,
                (device_id, principal.username),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.get("/admin/shares")
def list_all_shares(
    principal: Principal = Depends(require_principal),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=128),
    grantee_username: Optional[str] = Query(default=None, min_length=2, max_length=64),
    include_revoked: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=2000),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    clauses = ["1=1"]
    args: list[Any] = []
    if device_id:
        clauses.append("a.device_id = ?")
        args.append(device_id.strip())
    if grantee_username:
        clauses.append("a.grantee_username = ?")
        args.append(grantee_username.strip())
    if not include_revoked:
        clauses.append("a.revoked_at IS NULL")
    if principal.role == "admin":
        clauses.append("IFNULL(o.owner_admin,'') = ?")
        args.append(principal.username)
        clauses.append("u.role = 'user'")
        clauses.append("IFNULL(u.manager_admin,'') = ?")
        args.append(principal.username)
    where = " AND ".join(clauses)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT a.device_id, a.grantee_username, u.role AS grantee_role,
                   a.can_view, a.can_operate, a.granted_by, a.granted_at, a.revoked_at,
                   o.owner_admin
            FROM device_acl a
            LEFT JOIN dashboard_users u ON u.username = a.grantee_username
            LEFT JOIN device_ownership o ON o.device_id = a.device_id
            WHERE {where}
            ORDER BY a.revoked_at IS NOT NULL ASC, a.granted_at DESC
            LIMIT ?
            """,
            tuple(args + [limit]),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows, "count": len(rows)}


@router.post("/admin/devices/{device_id}/share")
def share_device(
    device_id: str,
    req: DeviceShareRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
        assert_device_owner(principal, device_id)
    grantee = req.grantee_username.strip()
    if not grantee:
        raise HTTPException(status_code=400, detail="grantee_username required")
    if not req.can_view and not req.can_operate:
        raise HTTPException(status_code=400, detail="at least one permission is required")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM device_state WHERE device_id = ?", (device_id,))
        if not cur.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        cur.execute("SELECT role, status, manager_admin FROM dashboard_users WHERE username = ?", (grantee,))
        ur = cur.fetchone()
        if not ur:
            conn.close()
            raise HTTPException(status_code=404, detail="grantee not found")
        role = str(ur["role"] or "")
        status = str(ur["status"] or "active")
        if principal.role == "superadmin":
            if role not in ("admin", "user"):
                conn.close()
                raise HTTPException(status_code=400, detail="only admin/user can be shared")
        else:
            # Admin can only share to own managed users.
            if role != "user":
                conn.close()
                raise HTTPException(status_code=400, detail="admin can only share to user")
            if str(ur["manager_admin"] or "") != principal.username:
                conn.close()
                raise HTTPException(status_code=403, detail="target user is not under this admin")
        if status not in ("active", ""):
            conn.close()
            raise HTTPException(status_code=400, detail=f"grantee is not active: {status}")
        now = utc_now_iso()
        cur.execute(
            """
            INSERT INTO device_acl (
                device_id, grantee_username, can_view, can_operate, granted_by, granted_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(device_id, grantee_username) DO UPDATE SET
                can_view = excluded.can_view,
                can_operate = excluded.can_operate,
                granted_by = excluded.granted_by,
                granted_at = excluded.granted_at,
                revoked_at = NULL
            """,
            (device_id, grantee, 1 if req.can_view else 0, 1 if req.can_operate else 0, principal.username, now),
        )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(
        principal.username,
        "device.share.grant",
        device_id,
        {"grantee_username": grantee, "can_view": bool(req.can_view), "can_operate": bool(req.can_operate)},
    )
    return {
        "ok": True,
        "device_id": device_id,
        "grantee_username": grantee,
        "can_view": bool(req.can_view),
        "can_operate": bool(req.can_operate),
    }


@router.delete("/admin/devices/{device_id}/share/{grantee_username}")
def unshare_device(
    device_id: str,
    grantee_username: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
        assert_device_owner(principal, device_id)
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT role, manager_admin FROM dashboard_users WHERE username = ?", (grantee_username,))
            ur = cur.fetchone()
            conn.close()
        if not ur or str(ur["role"] or "") != "user" or str(ur["manager_admin"] or "") != principal.username:
            raise HTTPException(status_code=403, detail="cannot revoke share for this grantee")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE device_acl
            SET revoked_at = ?
            WHERE device_id = ? AND grantee_username = ? AND revoked_at IS NULL
            """,
            (utc_now_iso(), device_id, grantee_username),
        )
        changed = cur.rowcount
        conn.commit()
        conn.close()
    if changed == 0:
        raise HTTPException(status_code=404, detail="active share not found")
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "device.share.revoke", device_id, {"grantee_username": grantee_username})
    return {"ok": True, "device_id": device_id, "grantee_username": grantee_username}
