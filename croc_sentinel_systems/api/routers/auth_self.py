"""Self-service account routes (Phase-20 modularization).

Ten endpoints scoped to "the signed-in user" — i.e. ``/auth/me/*`` —
plus the small bag of schemas + helpers that go with them.

Routes
------
  GET    /auth/me                       (profile snapshot)
  POST   /auth/me/fcm-token             (register/refresh push token)
  DELETE /auth/me/fcm-token             (delete one push token, body)
  POST   /auth/me/fcm-token/delete      (POST mirror for proxies that strip DELETE bodies)
  GET    /auth/me/notification-prefs    (alarm push style)
  PATCH  /auth/me/notification-prefs    (alarm push style)
  PATCH  /auth/me/profile               (avatar URL)
  PATCH  /auth/me/password              (self password change)
  DELETE /auth/me                       (self-service delete)
  POST   /auth/me/delete                (POST mirror for proxies that strip DELETE bodies)

Schemas / helpers moved with the routes
---------------------------------------
  SelfPasswordChangeRequest, SelfDeleteRequest,
  FcmTokenRegisterRequest, FcmTokenDeleteRequest,
  NotificationPrefsPatchRequest, MeProfilePatchRequest,
  _validate_avatar_url, _auth_me_delete_impl

Late-binding strategy
---------------------
Cross-feature helpers come from app.py:

  early-bound (defined < line ~3000 in app.py):
    require_principal, _normalize_delete_confirm,
    get_manager_admin, get_effective_policy

  call-time wrappers (defined > line ~4500 in app.py):
    _delete_user_auxiliary_cur, _close_admin_tenant_cur
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from email_templates import render_password_changed_email
from helpers import utc_now_iso
from notifier import notifier
from security import Principal, assert_min_role, hash_password, verify_password
from tz_display import malaysia_now_iso

require_principal = _app.require_principal
_normalize_delete_confirm = _app._normalize_delete_confirm
get_manager_admin = _app.get_manager_admin
get_effective_policy = _app.get_effective_policy


def _delete_user_auxiliary_cur(*args: Any, **kwargs: Any) -> Any:
    return _app._delete_user_auxiliary_cur(*args, **kwargs)


def _close_admin_tenant_cur(*args: Any, **kwargs: Any) -> Any:
    return _app._close_admin_tenant_cur(*args, **kwargs)


logger = logging.getLogger("croc-api.routers.auth_self")

router = APIRouter(tags=["auth-self"])


# ---- Schemas ---------------------------------------------------------------

class SelfPasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    new_password_confirm: str = Field(min_length=8, max_length=128)


class SelfDeleteRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    confirm_text: str = Field(min_length=3, max_length=32)
    # Admin only: must be true — unclaims all owned devices (factory unclaimed) and deletes subordinate users.
    acknowledge_admin_tenant_closure: bool = Field(default=False)


class FcmTokenRegisterRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)
    platform: str = Field(default="", max_length=32)


class FcmTokenDeleteRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class NotificationPrefsPatchRequest(BaseModel):
    """Mobile alarm presentation: fullscreen (high-urgency) vs heads_up (standard notification)."""

    alarm_push_style: str = Field(pattern="^(fullscreen|heads_up)$")


class MeProfilePatchRequest(BaseModel):
    """User-editable console profile (sidebar avatar, etc.)."""

    avatar_url: str = Field(default="", max_length=800)


# ---- Module helpers --------------------------------------------------------

def _validate_avatar_url(raw: str) -> str:
    """Empty clears. Otherwise require https: URL suitable for <img src>."""
    s = (raw or "").strip()
    if not s:
        return ""
    if len(s) > 800:
        raise HTTPException(status_code=400, detail="avatar_url too long")
    u = urlparse(s)
    if u.scheme != "https":
        raise HTTPException(status_code=400, detail="avatar_url must be https or empty")
    if not (u.netloc and str(u.netloc).strip()):
        raise HTTPException(status_code=400, detail="avatar_url has no host")
    if u.username is not None or u.password is not None:
        raise HTTPException(status_code=400, detail="avatar_url must not contain credentials")
    return s


def _auth_me_delete_impl(body: SelfDeleteRequest, principal: Principal) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if _normalize_delete_confirm(body.confirm_text) != "DELETE":
        raise HTTPException(status_code=400, detail="confirm_text must be exactly: DELETE")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT password_hash, role FROM dashboard_users WHERE username = ?", (principal.username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if not verify_password(body.password, str(row["password_hash"])):
            conn.close()
            raise HTTPException(status_code=401, detail="password invalid")
        role = str(row["role"] or "")
        if role == "superadmin":
            conn.close()
            raise HTTPException(status_code=400, detail="superadmin account cannot be deleted via self-service")
        if role == "admin":
            if not body.acknowledge_admin_tenant_closure:
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail="admin tenant closure requires acknowledge_admin_tenant_closure=true "
                    "(all owned devices unclaimed to factory; subordinate users removed; email released)",
                )
            summary = _close_admin_tenant_cur(cur, principal.username, None, principal.username)
            conn.commit()
            conn.close()
            cache_invalidate("devices")
            cache_invalidate("overview")
            audit_event(principal.username, "auth.account.delete.admin_tenant", principal.username, summary)
            return {"ok": True, **summary}
        _delete_user_auxiliary_cur(cur, principal.username)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "auth.account.delete.self", principal.username, {})
    return {"ok": True}


# ---- Routes ----------------------------------------------------------------

@router.get("/auth/me")
def auth_me(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    alarm_push_style = "fullscreen"
    avatar_url = ""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(alarm_push_style,'fullscreen') AS s, IFNULL(avatar_url,'') AS a FROM dashboard_users WHERE username = ?",
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if row:
        alarm_push_style = str(row["s"] or "fullscreen").strip() or "fullscreen"
        avatar_url = str(row["a"] or "").strip()
    return {
        "username": principal.username,
        "role": principal.role,
        "zones": principal.zones,
        "policy": get_effective_policy(principal),
        "manager_admin": get_manager_admin(principal.username) if principal.role == "user" else "",
        "alarm_push_style": alarm_push_style,
        "avatar_url": avatar_url,
    }


@router.post("/auth/me/fcm-token")
def auth_me_fcm_token_register(
    body: FcmTokenRegisterRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Register or refresh one FCM device token for the signed-in user."""
    assert_min_role(principal, "user")
    tok = body.token.strip()
    plat = (body.platform or "").strip().lower()[:32]
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_fcm_tokens (username, token, platform, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(username, token) DO UPDATE SET
              platform = excluded.platform,
              updated_at = excluded.updated_at
            """,
            (principal.username, tok, plat, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "auth.fcm_token.upsert", principal.username, {"platform": plat})
    return {"ok": True}


@router.delete("/auth/me/fcm-token")
def auth_me_fcm_token_delete(
    body: FcmTokenDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    tok = body.token.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM user_fcm_tokens WHERE username = ? AND token = ?", (principal.username, tok))
        n = cur.rowcount
        conn.commit()
        conn.close()
    audit_event(principal.username, "auth.fcm_token.delete", principal.username, {"removed": int(n or 0)})
    return {"ok": True, "removed": int(n or 0)}


@router.post("/auth/me/fcm-token/delete")
def auth_me_fcm_token_delete_post(
    body: FcmTokenDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Same as DELETE /auth/me/fcm-token when reverse proxies drop DELETE bodies."""
    return auth_me_fcm_token_delete(body, principal)


@router.get("/auth/me/notification-prefs")
def auth_me_notification_prefs_get(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(alarm_push_style,'fullscreen') AS s FROM dashboard_users WHERE username = ?",
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"alarm_push_style": str(row["s"] or "fullscreen")}


@router.patch("/auth/me/notification-prefs")
def auth_me_notification_prefs_patch(
    body: NotificationPrefsPatchRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE dashboard_users SET alarm_push_style = ? WHERE username = ?",
            (body.alarm_push_style, principal.username),
        )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "auth.notification_prefs.patch",
        principal.username,
        {"alarm_push_style": body.alarm_push_style},
    )
    return {"ok": True, "alarm_push_style": body.alarm_push_style}


@router.patch("/auth/me/profile")
def auth_me_profile_patch(
    body: MeProfilePatchRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    val = _validate_avatar_url(body.avatar_url)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE dashboard_users SET avatar_url = ? WHERE username = ?", (val or None, principal.username))
        if cur.rowcount == 0:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "auth.profile.patch",
        principal.username,
        {"avatar_set": bool(val)},
    )
    return {"ok": True, "avatar_url": val}


@router.patch("/auth/me/password")
def auth_me_change_password(
    body: SelfPasswordChangeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if body.new_password != body.new_password_confirm:
        raise HTTPException(status_code=400, detail="new password confirmation does not match")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="new password must be different")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, role, email FROM dashboard_users WHERE username = ?",
            (principal.username,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if not verify_password(body.current_password, str(row["password_hash"])):
            conn.close()
            raise HTTPException(status_code=401, detail="current password invalid")
        rk = row.keys()
        notify_email = str(row["email"] or "").strip() if "email" in rk else ""
        cur.execute(
            "UPDATE dashboard_users SET password_hash = ? WHERE username = ?",
            (hash_password(body.new_password), principal.username),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "auth.password.change", principal.username, {})
    if notify_email and notifier.enabled():
        try:
            ps, pt, ph = render_password_changed_email(username=principal.username, iso_ts=malaysia_now_iso())
            notifier.send_sync([notify_email], ps, pt, ph)
        except Exception:
            logger.warning("password-changed email failed for %s", principal.username, exc_info=True)
    return {"ok": True}


@router.delete("/auth/me")
def auth_me_delete(
    body: SelfDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Self-service account deletion. Prefer POST /auth/me/delete behind proxies that strip DELETE bodies."""
    return _auth_me_delete_impl(body, principal)


@router.post("/auth/me/delete")
def auth_me_delete_post(
    body: SelfDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Same as DELETE /auth/me — JSON body is reliably forwarded by nginx/CDN stacks."""
    return _auth_me_delete_impl(body, principal)
