"""Admin-managed user CRUD routes (Phase-21, trimmed in Phase-69 / 80).

Surface evolution:
  Phase 21 — original module: 7 routes (~479 lines). Covered both
              admin-tenant CRUD (superadmin) and per-tenant user CRUD.
  Phase 69 — extracted ``GET /auth/admins`` and
              ``POST /auth/admins/{username}/close`` into
              ``routers/auth_admins.py`` (admin-tenant management).
  Phase 80 — extracted policy GET/PUT into
              ``routers/auth_user_policy.py`` (capability-flag
              management) so this file is now identity-lifecycle
              only.

Routes (still here)
-------------------
  GET    /auth/users                — list users in tenant.
  POST   /auth/users                — create user (sends activation
                                      OTPs to email + optional SMS).
  DELETE /auth/users/{username}     — remove user (incl. auxiliary
                                      rows: device_shares,
                                      role_policies, etc.).

Schemas owned here
------------------
  UserCreateRequest

The policy schema (``UserPolicyUpdateRequest``) lives next door in
``routers/auth_user_policy.py``. Both routers share the
``"auth-users"`` OpenAPI tag so they group together in the docs.

Late-binding strategy
---------------------
Cross-feature helpers come from ``app.py``:

  early-bound (defined before this module's import):
    require_principal, require_capability,
    _looks_like_email, _normalize_phone, _issue_verification

  call-time wrapper (defined later in app.py):
    _delete_user_auxiliary_cur — needed by the DELETE route's
    fan-out cleanup. Wrapped with a thin ``def`` so the lookup
    happens at call time, after app.py has finished defining it.

Cross-router note
-----------------
``DELETE /auth/users/{username}`` rejects role=admin with the message
"use POST /auth/admins/{username}/close to remove an admin tenant" —
that close endpoint now lives in ``routers/auth_admins.py``. The
rejection text and behaviour are unchanged.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import REQUIRE_PHONE_VERIFICATION
from db import cache_invalidate, db_lock, get_conn
from helpers import default_policy_for_role, utc_now_iso
from security import (
    Principal,
    assert_min_role,
    hash_password,
    zones_from_json,
)

require_principal = _app.require_principal
require_capability = _app.require_capability
_looks_like_email = _app._looks_like_email
_normalize_phone = _app._normalize_phone
_issue_verification = _app._issue_verification


def _delete_user_auxiliary_cur(*args: Any, **kwargs: Any) -> Any:
    return _app._delete_user_auxiliary_cur(*args, **kwargs)


logger = logging.getLogger("croc-api.routers.auth_users")
router = APIRouter(tags=["auth-users"])


# ---- Schemas ---------------------------------------------------------------

class UserCreateRequest(BaseModel):
    # NOTE: superadmin is NEVER creatable through the API. It is seeded once
    # from BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD on first boot and that's it.
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(pattern="^(admin|user)$")
    zones: list[str] = Field(default_factory=lambda: ["*"])
    manager_admin: Optional[str] = Field(default=None, min_length=2, max_length=64)
    tenant: Optional[str] = Field(default=None, min_length=1, max_length=64)
    email: Optional[str] = Field(default=None, min_length=3, max_length=254)
    phone: Optional[str] = Field(default=None, min_length=4, max_length=32)


# Phase-80 split: ``UserPolicyUpdateRequest`` and the policy GET/PUT
# routes moved to ``routers/auth_user_policy.py``. Both routers share
# the ``"auth-users"`` tag so they group together in the OpenAPI docs.


# ---- Routes ----------------------------------------------------------------

@router.get("/auth/users")
def auth_list_users(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                "SELECT username, role, allowed_zones_json, manager_admin, tenant, created_at FROM dashboard_users ORDER BY username ASC"
            )
        else:
            cur.execute(
                """
                SELECT username, role, allowed_zones_json, manager_admin, tenant, created_at
                FROM dashboard_users
                WHERE role = 'user' AND manager_admin = ?
                ORDER BY username ASC
                """,
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        r["zones"] = zones_from_json(str(r.pop("allowed_zones_json")))
    return {"items": rows}


@router.post("/auth/users")
def auth_create_user(req: UserCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    # Hard guard: nobody can make a superadmin via the API even by forging role.
    if req.role == "superadmin":
        raise HTTPException(status_code=403, detail="superadmin is not creatable via API")
    if principal.role == "admin" and req.role != "user":
        raise HTTPException(status_code=403, detail="admin can only create user role")
    # admin-created users MUST have an email so the activation code can be sent.
    # (phone is optional; see REQUIRE_PHONE_VERIFICATION env flag)
    if not req.email:
        raise HTTPException(status_code=400, detail="email is required")
    email_norm = req.email.strip().lower()
    if not _looks_like_email(email_norm):
        raise HTTPException(status_code=400, detail="email format invalid")
    phone_norm = _normalize_phone(req.phone) if req.phone else None
    if REQUIRE_PHONE_VERIFICATION and not phone_norm:
        raise HTTPException(status_code=400, detail="phone is required")
    now = utc_now_iso()
    zones_json = json.dumps(req.zones, ensure_ascii=True)
    manager_admin = req.manager_admin or (principal.username if principal.role == "admin" else "")
    if req.role == "admin":
        manager_admin = ""
    if req.role == "user" and not manager_admin:
        raise HTTPException(status_code=400, detail="manager_admin is required when creating a user role")
    if req.role == "user":
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT role FROM dashboard_users WHERE username = ?",
                (manager_admin,),
            )
            mrow = cur.fetchone()
            conn.close()
        if not mrow or str(mrow["role"]) not in ("admin", "superadmin"):
            raise HTTPException(status_code=400, detail="manager_admin must be an existing admin/superadmin")
    tenant = req.tenant or (principal.username if principal.role == "admin" else (manager_admin or req.username))
    initial_status = "pending"  # activation code will flip to 'active'
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO dashboard_users (
                    username, password_hash, role, allowed_zones_json,
                    manager_admin, tenant, email, phone, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.username,
                    hash_password(req.password),
                    req.role,
                    zones_json,
                    manager_admin,
                    tenant,
                    email_norm,
                    phone_norm,
                    initial_status,
                    now,
                ),
            )
            pol = default_policy_for_role(req.role)
            cur.execute(
                """
                INSERT INTO role_policies (username, can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                  can_alert=excluded.can_alert,
                  can_send_command=excluded.can_send_command,
                  can_claim_device=excluded.can_claim_device,
                  can_manage_users=excluded.can_manage_users,
                  can_backup_restore=excluded.can_backup_restore,
                  updated_at=excluded.updated_at
                """,
                (
                    req.username,
                    pol["can_alert"],
                    pol["can_send_command"],
                    pol["can_claim_device"],
                    pol["can_manage_users"],
                    pol["can_backup_restore"],
                    now,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="username exists")
        conn.close()
    cache_invalidate("devices")
    audit_event(principal.username, "user.create", req.username, {
        "role": req.role, "zones": req.zones, "email": email_norm, "phone": bool(phone_norm),
    })
    # Send activation OTPs. We don't fail user creation if SMTP is down — the
    # admin can click "re-send code" from the dashboard.
    activation_msg = ""
    try:
        _issue_verification(req.username, "email", email_norm, purpose="activate")
        activation_msg = "Email verification code sent."
    except Exception as exc:
        logger.warning("email OTP issue failed for %s: %s", req.username, exc)
        activation_msg = f"Email code not sent: {exc}"
    if phone_norm:
        try:
            _issue_verification(req.username, "phone", phone_norm, purpose="activate")
            activation_msg += " SMS code sent."
        except Exception as exc:
            logger.warning("phone OTP issue failed for %s: %s", req.username, exc)
    return {
        "ok": True,
        "username": req.username,
        "status": initial_status,
        "message": activation_msg,
    }


@router.delete("/auth/users/{username}")
def auth_delete_user(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    if secrets.compare_digest(username, principal.username):
        raise HTTPException(status_code=400, detail="cannot delete self")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "admin":
            cur.execute("SELECT role, manager_admin FROM dashboard_users WHERE username = ?", (username,))
            row = cur.fetchone()
            if not row:
                conn.close()
                raise HTTPException(status_code=404, detail="user not found")
            if str(row["role"]) != "user" or str(row["manager_admin"] or "") != principal.username:
                conn.close()
                raise HTTPException(status_code=403, detail="cannot delete this user")
        else:
            cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (username,))
            row = cur.fetchone()
            if not row:
                conn.close()
                raise HTTPException(status_code=404, detail="user not found")
            if str(row["role"] or "") == "admin":
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail="use POST /auth/admins/{username}/close to remove an admin tenant",
                )
        cur.execute("SELECT username FROM dashboard_users WHERE username = ?", (username,))
        exists = cur.fetchone()
        if not exists:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        _delete_user_auxiliary_cur(cur, username)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "user.delete", username, {})
    return {"ok": True}


__all__ = (
    "router",
    "UserCreateRequest",
)
