"""Self-service identity / account routes (Phase-20, trimmed Phase-83).

Surface evolution:
  Phase 20 — original module: 10 routes (~432 lines). Owned every
              ``/auth/me/*`` endpoint, including FCM tokens and
              notification prefs.
  Phase 83 — extracted FCM tokens + notification prefs (5 routes,
              3 schemas) into ``routers/auth_self_devices.py``,
              leaving identity/account here.

Routes (still here)
-------------------
  GET    /auth/me              — profile snapshot.
  PATCH  /auth/me/profile      — avatar URL.
  PATCH  /auth/me/password     — self password change (with
                                 password-changed email notification).
  DELETE /auth/me              — self-service deletion.
  POST   /auth/me/delete       — POST mirror for proxies that strip
                                 DELETE bodies.

Schemas owned here
------------------
  SelfPasswordChangeRequest, SelfDeleteRequest, MeProfilePatchRequest

The mobile/preference schemas (``FcmTokenRegisterRequest``,
``FcmTokenDeleteRequest``, ``NotificationPrefsPatchRequest``) live in
``routers/auth_self_devices.py``. Both routers share the
``"auth-self"`` OpenAPI tag so the docs group them together.

Helpers owned here
------------------
  _validate_avatar_url       — https-only URL gate for avatar PATCH.
  _auth_me_delete_impl       — shared body for DELETE/POST delete.
                               Calls ``_close_admin_tenant_cur`` for
                               admin tenants (cascades to all owned
                               devices + subordinate users) or
                               ``_delete_user_auxiliary_cur`` for
                               regular users (purges sidecar rows).

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


# Phase-83 split: ``FcmTokenRegisterRequest``, ``FcmTokenDeleteRequest``,
# and ``NotificationPrefsPatchRequest`` moved to
# ``routers/auth_self_devices.py`` along with their 5 routes
# (FCM token register/delete/delete-POST + notification-prefs GET/PATCH).
# Both routers share the ``auth-self`` tag.


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


# Phase-83 split: the 3 FCM-token routes (POST register, DELETE, POST
# delete-mirror) and the 2 notification-prefs routes (GET, PATCH) live
# in routers/auth_self_devices.py. Both routers share the auth-self tag
# so the OpenAPI doc groups them together for end users.


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
