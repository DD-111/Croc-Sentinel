"""Admin tenant management routes (Phase-69 split from ``routers/auth_users.py``).

The Phase-21 module covered both halves of the admin/user CRUD
surface — superadmin-only admin tenant management and admin-managed
user CRUD. Phase 69 splits the superadmin half (admin tenant
listing + close-tenant) into this dedicated module so that
fleet-management code (managing other admins) is reviewed
separately from the day-to-day user CRUD that admins themselves run.

Routes
------
  GET  /auth/admins                           — list admin/superadmin
                                                usernames (for the
                                                manager_admin picker
                                                during user creation).
  POST /auth/admins/{username}/close          — superadmin: close an
                                                admin tenant (unclaim
                                                or transfer devices,
                                                then delete the admin
                                                row + per-tenant data).

Schemas owned here
------------------
  AdminTenantCloseRequest

Late binding (call-time wrapper)
--------------------------------
``_close_admin_tenant_cur`` is *defined later* in app.py — past the
``include_router`` for this module, since it shares helpers with
non-router code paths (factory device unclaim, etc.). We use a
call-time wrapper so we don't AttributeError on ``import app``.

``require_principal`` is captured at import time (defined early in
app.py, available before this module's import).
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal


def _close_admin_tenant_cur(*args: Any, **kwargs: Any) -> Any:
    return _app._close_admin_tenant_cur(*args, **kwargs)


logger = logging.getLogger("croc-api.routers.auth_admins")
router = APIRouter(tags=["auth-admins"])


# ---- Schemas ---------------------------------------------------------------

class AdminTenantCloseRequest(BaseModel):
    """Superadmin closes another admin tenant; optional device transfer instead of unclaim."""

    confirm_text: str = Field(min_length=8, max_length=64)
    transfer_devices_to: Optional[str] = Field(default=None, max_length=64)


# ---- Routes ----------------------------------------------------------------

@router.get("/auth/admins")
def auth_list_admins(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """For superadmin only. Returns admins usable as manager_admin."""
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username FROM dashboard_users WHERE role IN ('admin','superadmin') ORDER BY username ASC"
        )
        rows = [str(r["username"]) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.post("/auth/admins/{username}/close")
def auth_close_admin_tenant(
    username: str,
    body: AdminTenantCloseRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Superadmin: close an admin tenant — unclaim devices (or transfer to another admin) and delete the admin."""
    assert_min_role(principal, "superadmin")
    if body.confirm_text.strip() != "CLOSE TENANT":
        raise HTTPException(status_code=400, detail="confirm_text must be exactly: CLOSE TENANT")
    target = username.strip()
    if secrets.compare_digest(target, principal.username):
        raise HTTPException(status_code=400, detail="use Account page to close your own tenant if you are an admin")
    transfer_to = (body.transfer_devices_to or "").strip() or None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        summary = _close_admin_tenant_cur(cur, target, transfer_to, principal.username)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "auth.admin.tenant.close", target, summary)
    return {"ok": True, **summary}


__all__ = (
    "router",
    "AdminTenantCloseRequest",
)
