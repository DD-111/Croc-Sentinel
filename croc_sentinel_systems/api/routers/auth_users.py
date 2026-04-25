"""Admin/user CRUD routes (Phase-21 modularization).

Seven endpoints owned by admins (and superadmins) that manage other
accounts in the tenant — listing, creating, deleting, fetching/saving
the per-user policy, plus the superadmin-only "close another admin
tenant" hatch.

Routes
------
  GET  /auth/admins
  POST /auth/admins/{username}/close
  GET  /auth/users
  POST /auth/users
  DELETE /auth/users/{username}
  GET  /auth/users/{username}/policy
  PUT  /auth/users/{username}/policy

Schemas moved with the routes
-----------------------------
  AdminTenantCloseRequest, UserCreateRequest, UserPolicyUpdateRequest

Late-binding strategy
---------------------
Cross-feature helpers come from app.py:

  early-bound (defined < line ~3500 in app.py):
    require_principal, require_capability,
    _looks_like_email, _normalize_phone, _issue_verification

  call-time wrappers (defined > line ~4300 in app.py):
    _delete_user_auxiliary_cur, _close_admin_tenant_cur
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


def _close_admin_tenant_cur(*args: Any, **kwargs: Any) -> Any:
    return _app._close_admin_tenant_cur(*args, **kwargs)


logger = logging.getLogger("croc-api.routers.auth_users")

router = APIRouter(tags=["auth-users"])


# ---- Schemas ---------------------------------------------------------------

class AdminTenantCloseRequest(BaseModel):
    """Superadmin closes another admin tenant; optional device transfer instead of unclaim."""

    confirm_text: str = Field(min_length=8, max_length=64)
    transfer_devices_to: Optional[str] = Field(default=None, max_length=64)


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


class UserPolicyUpdateRequest(BaseModel):
    can_alert: Optional[bool] = None
    can_send_command: Optional[bool] = None
    can_claim_device: Optional[bool] = None
    can_manage_users: Optional[bool] = None
    can_backup_restore: Optional[bool] = None
    tg_view_logs: Optional[bool] = None
    tg_view_devices: Optional[bool] = None
    tg_siren_on: Optional[bool] = None
    tg_siren_off: Optional[bool] = None
    tg_test_single: Optional[bool] = None
    tg_test_bulk: Optional[bool] = None


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


@router.get("/auth/users/{username}/policy")
def auth_get_user_policy(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, role, manager_admin FROM dashboard_users WHERE username = ?", (username,))
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if principal.role == "admin" and (str(u["role"]) != "user" or str(u["manager_admin"] or "") != principal.username):
            conn.close()
            raise HTTPException(status_code=403, detail="not your managed user")
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk,
                   updated_at
            FROM role_policies WHERE username = ?
            """,
            (username,),
        )
        p = cur.fetchone()
        conn.close()
    if not p:
        out = default_policy_for_role(str(u["role"]))
        out["updated_at"] = ""
        return out
    return dict(p)


@router.put("/auth/users/{username}/policy")
def auth_set_user_policy(
    username: str,
    req: UserPolicyUpdateRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, role, manager_admin FROM dashboard_users WHERE username = ?", (username,))
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if str(u["role"]) != "user":
            conn.close()
            raise HTTPException(status_code=400, detail="policy endpoint is for user role")
        if principal.role == "admin" and str(u["manager_admin"] or "") != principal.username:
            conn.close()
            raise HTTPException(status_code=403, detail="not your managed user")
        base = default_policy_for_role("user")
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk
            FROM role_policies WHERE username = ?
            """,
            (username,),
        )
        curp = cur.fetchone()
        if curp:
            for k in base.keys():
                base[k] = int(curp[k])
        updates = {
            "can_alert": req.can_alert,
            "can_send_command": req.can_send_command,
            "can_claim_device": req.can_claim_device,
            "can_manage_users": req.can_manage_users,
            "can_backup_restore": req.can_backup_restore,
            "tg_view_logs": req.tg_view_logs,
            "tg_view_devices": req.tg_view_devices,
            "tg_siren_on": req.tg_siren_on,
            "tg_siren_off": req.tg_siren_off,
            "tg_test_single": req.tg_test_single,
            "tg_test_bulk": req.tg_test_bulk,
        }
        for k, v in updates.items():
            if v is not None:
                base[k] = 1 if v else 0
        # guardrail: regular users never get backup/manage_users
        base["can_backup_restore"] = 0
        base["can_manage_users"] = 0
        cur.execute(
            """
            INSERT INTO role_policies (
                username, can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                can_alert=excluded.can_alert,
                can_send_command=excluded.can_send_command,
                can_claim_device=excluded.can_claim_device,
                can_manage_users=excluded.can_manage_users,
                can_backup_restore=excluded.can_backup_restore,
                tg_view_logs=excluded.tg_view_logs,
                tg_view_devices=excluded.tg_view_devices,
                tg_siren_on=excluded.tg_siren_on,
                tg_siren_off=excluded.tg_siren_off,
                tg_test_single=excluded.tg_test_single,
                tg_test_bulk=excluded.tg_test_bulk,
                updated_at=excluded.updated_at
            """,
            (
                username,
                base["can_alert"],
                base["can_send_command"],
                base["can_claim_device"],
                base["can_manage_users"],
                base["can_backup_restore"],
                base["tg_view_logs"],
                base["tg_view_devices"],
                base["tg_siren_on"],
                base["tg_siren_off"],
                base["tg_test_single"],
                base["tg_test_bulk"],
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "user.policy.update", username, base)
    return {"ok": True, "username": username, "policy": base}
