"""Self-service mobile device + notification preference routes
(Phase-83 split from ``routers/auth_self.py``).

The Phase-20 ``routers/auth_self.py`` extract bundled two distinct
review surfaces under ``/auth/me/*``:

  * **Identity / account** (5 routes, ~280 lines): ``GET /auth/me``,
    ``PATCH /auth/me/profile`` (avatar), ``PATCH /auth/me/password``
    (self password change with email notification), and the two
    self-deletion endpoints (``DELETE /auth/me`` + the
    proxy-friendly ``POST /auth/me/delete`` mirror). These touch
    password hashing, ``email`` notification dispatch, and the
    cascading ``_close_admin_tenant_cur`` /
    ``_delete_user_auxiliary_cur`` purges.
  * **Mobile preferences** (5 routes, ~125 lines): FCM device-token
    register / delete / delete-POST-mirror, plus the
    fullscreen-vs-heads-up alarm prefs read + patch. These are
    preference plumbing — no password verify, no email send,
    no cascading delete.

Phase 83 splits the mobile preferences here. Both surfaces still
share the ``"auth-self"`` OpenAPI tag so the docs group them
together for end users.

Routes
------
  POST   /auth/me/fcm-token             — register/refresh FCM token.
  DELETE /auth/me/fcm-token             — delete one FCM token (body).
  POST   /auth/me/fcm-token/delete      — POST mirror for proxies that
                                          strip DELETE bodies.
  GET    /auth/me/notification-prefs    — read alarm push style.
  PATCH  /auth/me/notification-prefs    — update alarm push style.

Schemas owned here
------------------
  FcmTokenRegisterRequest
  FcmTokenDeleteRequest
  NotificationPrefsPatchRequest

Why proxy-friendly POST mirror
------------------------------
Some reverse-proxy and CDN configurations strip request bodies
from ``DELETE`` requests (or at least from non-RFC-7231 verbs).
The mobile app needs to delete a single FCM token by value, which
requires a body. The ``POST /auth/me/fcm-token/delete`` mirror
delegates to the canonical ``DELETE`` handler so we only have one
implementation site, but two reachable surfaces.

Late binding
------------
``require_principal`` is captured at module load from ``app``
(matches every other router). No other ``app.py`` helpers are
needed — the routes are pure DB upserts/deletes plus ``audit_event``.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal


logger = logging.getLogger("croc-api.routers.auth_self_devices")
router = APIRouter(tags=["auth-self"])


# ---- Schemas ---------------------------------------------------------------


class FcmTokenRegisterRequest(BaseModel):
    """Mobile registers/refreshes its FCM token after install or token rotation.

    The token is opaque to the server — we never decode it; we just
    persist it and use it as a target for ``fcm_notify``. The
    ``platform`` field is informational only (reserved for future
    per-platform routing). 32 chars is the published lower bound
    for FCM device tokens; 512 is conservative upper bound.
    """

    token: str = Field(min_length=32, max_length=512)
    platform: str = Field(default="", max_length=32)


class FcmTokenDeleteRequest(BaseModel):
    """Body for token deletion — body required to identify which token."""

    token: str = Field(min_length=32, max_length=512)


class NotificationPrefsPatchRequest(BaseModel):
    """Mobile alarm presentation: fullscreen (high-urgency) vs heads_up
    (standard notification).

    ``fullscreen`` triggers a full-screen Android intent so the user sees
    the alarm even with the phone locked / screen off; ``heads_up`` is the
    quieter banner. The choice is per-user.
    """

    alarm_push_style: str = Field(pattern="^(fullscreen|heads_up)$")


# ---- FCM token routes ------------------------------------------------------


@router.post("/auth/me/fcm-token")
def auth_me_fcm_token_register(
    body: FcmTokenRegisterRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Register or refresh one FCM device token for the signed-in user.

    ``ON CONFLICT(username, token) DO UPDATE`` — re-registering the
    same token just bumps ``platform`` + ``updated_at`` (so token
    refresh from the mobile app keeps the row but updates the audit
    timestamp). One user can hold multiple tokens (multi-device).
    """
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
    audit_event(
        principal.username,
        "auth.fcm_token.upsert",
        principal.username,
        {"platform": plat},
    )
    return {"ok": True}


@router.delete("/auth/me/fcm-token")
def auth_me_fcm_token_delete(
    body: FcmTokenDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Delete one FCM token belonging to the signed-in user.

    Returns ``removed: N`` so the mobile app can confirm the token
    was actually present (0 means the token wasn't registered for
    this user — usually a sign of a stale local-cache state).
    """
    assert_min_role(principal, "user")
    tok = body.token.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM user_fcm_tokens WHERE username = ? AND token = ?",
            (principal.username, tok),
        )
        n = cur.rowcount
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "auth.fcm_token.delete",
        principal.username,
        {"removed": int(n or 0)},
    )
    return {"ok": True, "removed": int(n or 0)}


@router.post("/auth/me/fcm-token/delete")
def auth_me_fcm_token_delete_post(
    body: FcmTokenDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """POST mirror for proxies that strip ``DELETE`` request bodies.

    Same handler as the canonical ``DELETE /auth/me/fcm-token`` route —
    do **not** inline a copy of the body, or both endpoints will
    diverge over time.
    """
    return auth_me_fcm_token_delete(body, principal)


# ---- Notification prefs ----------------------------------------------------


@router.get("/auth/me/notification-prefs")
def auth_me_notification_prefs_get(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Read the user's alarm push style.

    Defaults to ``fullscreen`` when the column is NULL/empty —
    matches the historical behavior so a freshly-bootstrapped
    account sees high-urgency alarms even if the prefs row was
    never explicitly written.
    """
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT IFNULL(alarm_push_style,'fullscreen') AS s
            FROM dashboard_users WHERE username = ?
            """,
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
    """Update the user's alarm push style.

    The pattern guard on the schema (``^(fullscreen|heads_up)$``)
    is the single source of truth — we don't re-validate here so
    adding a new style only requires one change.
    """
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


__all__ = (
    "router",
    "FcmTokenRegisterRequest",
    "FcmTokenDeleteRequest",
    "NotificationPrefsPatchRequest",
)
