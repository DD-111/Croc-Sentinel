"""Auth signup + activation routes (Phase-64, trimmed Phase-82).

Surface evolution:
  Phase 64 — split from ``routers/auth_recovery.py``: this module
              owned 7 routes (signup OTP flow + admin approval queue).
  Phase 82 — split the 3 superadmin approval routes
              (``/auth/signup/pending``,
              ``/auth/signup/approve/{username}``,
              ``/auth/signup/reject/{username}``) into
              ``routers/auth_signup_approval.py`` so the public OTP
              surface and the superadmin approval surface have
              independent reviewer groups.

Routes (all unauthenticated public OTP flow)
--------------------------------------------
  POST  /auth/signup/start    — public admin self-signup → OTP.
  POST  /auth/signup/verify   — verify the signup OTP →
                                ``awaiting_approval`` or ``active``.
  POST  /auth/activate        — admin-created user activates self
                                via OTP from admin-trigger.
  POST  /auth/code/resend     — re-send a pending OTP to a user.

The 3 approval routes (``/auth/signup/pending`` /
``/auth/signup/approve/{username}`` /
``/auth/signup/reject/{username}``) live in
``routers/auth_signup_approval.py`` (Phase 82). They share the
``"auth-signup"`` OpenAPI tag so the OpenAPI doc still groups
them together for human readers.

Late binding
------------
Validation/rate-limit helpers (``_USERNAME_RE``, ``_looks_like_email``,
``_check_signup_rate``, ``_issue_verification`` etc.) live in
``app.py`` / ``auth_helpers.py`` and are late-bound here via
``import app as _app`` so the import order between this module and
``auth_helpers.py`` does not matter. ``emit_event`` /
``get_manager_admin`` / ``_client_ip`` are likewise resolved at call
time off ``app``.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    ADMIN_SIGNUP_REQUIRE_APPROVAL,
    ALLOW_PUBLIC_ADMIN_SIGNUP,
    OTP_TTL_SECONDS,
    REQUIRE_EMAIL_VERIFICATION,
    REQUIRE_PHONE_VERIFICATION,
)
from db import db_lock, get_conn
from helpers import default_policy_for_role, utc_now_iso
from security import hash_password


# ----- Late-bound helpers (resolved at call time off ``app``) -------------
def _emit_event(*args: Any, **kwargs: Any) -> Any:
    return _app.emit_event(*args, **kwargs)


def _get_manager_admin(username: str) -> str:
    return _app.get_manager_admin(username)


def _client_ip(request: Request) -> str:
    return _app._client_ip(request)


def _looks_like_email(value: str) -> bool:
    return _app._looks_like_email(value)


def _normalize_phone(value: Optional[str]) -> str:
    return _app._normalize_phone(value)


def _check_signup_rate(ip: str, email_norm: str) -> None:
    _app._check_signup_rate(ip, email_norm)


def _record_signup_attempt(ip: str, email_norm: str) -> None:
    _app._record_signup_attempt(ip, email_norm)


def _issue_verification(
    username: str,
    channel: str,
    target: str,
    purpose: str = "activate",
    *,
    explicit_code: Optional[str] = None,
) -> int:
    return _app._issue_verification(username, channel, target, purpose, explicit_code=explicit_code)


def _consume_verification(username: str, channel: str, purpose: str, code: str) -> bool:
    return _app._consume_verification(username, channel, purpose, code)


def _username_re_match(username: str) -> Any:
    return _app._USERNAME_RE.match(username)


logger = logging.getLogger("croc-api.routers.auth_signup")
router = APIRouter(tags=["auth-signup"])


# ===========================================================================
# Pydantic request schemas
# ===========================================================================

class SignupStartRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: str = Field(min_length=3, max_length=254)
    phone: Optional[str] = Field(default=None, min_length=4, max_length=32)


class VerifyCodeRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    email_code: Optional[str] = Field(default=None, min_length=4, max_length=12)
    phone_code: Optional[str] = Field(default=None, min_length=4, max_length=12)


class ResendCodeRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    channel: str = Field(pattern="^(email|phone)$")
    purpose: str = Field(default="activate", pattern="^(signup|activate|reset)$")


# ===========================================================================
# Signup / activation / approval routes
# ===========================================================================

@router.post("/auth/signup/start")
def auth_signup_start(body: SignupStartRequest, request: Request) -> dict[str, Any]:
    """Public admin self-signup (role=admin only, never superadmin).

    Creates a `dashboard_users` row in status='pending' and emails an OTP.
    The account becomes usable only after /auth/signup/verify succeeds AND,
    when ADMIN_SIGNUP_REQUIRE_APPROVAL=1, a superadmin approves after OTP.
    """
    if not ALLOW_PUBLIC_ADMIN_SIGNUP:
        raise HTTPException(status_code=403, detail="public signup disabled")
    ip = _client_ip(request)
    username = body.username.strip()
    if not _username_re_match(username):
        raise HTTPException(status_code=400, detail="username must be 2–64 chars of [A-Za-z0-9_.-]")
    email_norm = body.email.strip().lower()
    if not _looks_like_email(email_norm):
        raise HTTPException(status_code=400, detail="email format invalid")
    phone_norm = _normalize_phone(body.phone)
    if REQUIRE_PHONE_VERIFICATION and not phone_norm:
        raise HTTPException(status_code=400, detail="phone is required")
    _check_signup_rate(ip, email_norm)
    _record_signup_attempt(ip, email_norm)
    initial_status = "pending"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, status FROM dashboard_users WHERE username = ?", (username,))
        existing = cur.fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=409, detail="username not available")
        cur.execute("SELECT username FROM dashboard_users WHERE LOWER(email) = ?", (email_norm,))
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=409, detail="email already registered")
        try:
            cur.execute(
                """INSERT INTO dashboard_users (
                       username, password_hash, role, allowed_zones_json,
                       manager_admin, tenant, email, phone, status, created_at
                   ) VALUES (?, ?, 'admin', '["*"]', '', ?, ?, ?, ?, ?)""",
                (
                    username,
                    hash_password(body.password),
                    username,
                    email_norm,
                    phone_norm,
                    initial_status,
                    utc_now_iso(),
                ),
            )
            pol = default_policy_for_role("admin")
            cur.execute(
                """INSERT OR IGNORE INTO role_policies
                   (username, can_alert, can_send_command, can_claim_device,
                    can_manage_users, can_backup_restore, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    username,
                    pol["can_alert"], pol["can_send_command"], pol["can_claim_device"],
                    pol["can_manage_users"], pol["can_backup_restore"], utc_now_iso(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="username not available")
        conn.close()
    try:
        _issue_verification(username, "email", email_norm, purpose="signup")
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("signup email OTP failed for %s: %s", username, exc)
        raise HTTPException(status_code=502, detail=f"failed to send email verification: {exc}")
    if phone_norm and REQUIRE_PHONE_VERIFICATION:
        try:
            _issue_verification(username, "phone", phone_norm, purpose="signup")
        except Exception as exc:
            logger.warning("signup phone OTP failed for %s: %s", username, exc)
            raise HTTPException(status_code=502, detail=f"failed to send SMS verification: {exc}")
    audit_event(username, "signup.start", username, {"email": email_norm, "phone": bool(phone_norm), "ip": ip})
    return {
        "ok": True,
        "username": username,
        "email_otp_sent": True,
        "phone_otp_sent": bool(phone_norm and REQUIRE_PHONE_VERIFICATION),
        "ttl_seconds": OTP_TTL_SECONDS,
        "requires_approval": ADMIN_SIGNUP_REQUIRE_APPROVAL,
    }


@router.post("/auth/signup/verify")
def auth_signup_verify(body: VerifyCodeRequest) -> dict[str, Any]:
    username = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, status, email, phone, email_verified_at, phone_verified_at "
            "FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        conn.close()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    if u["role"] != "admin":
        raise HTTPException(status_code=400, detail="wrong verification route for this user")
    if str(u["status"]) in ("active", "disabled"):
        return {"ok": True, "already_verified": True, "status": str(u["status"])}
    if REQUIRE_EMAIL_VERIFICATION:
        if not body.email_code:
            raise HTTPException(status_code=400, detail="email_code required")
        if not _consume_verification(username, "email", "signup", body.email_code):
            raise HTTPException(status_code=401, detail="invalid or expired email code")
    if REQUIRE_PHONE_VERIFICATION and u["phone"]:
        if not body.phone_code:
            raise HTTPException(status_code=400, detail="phone_code required")
        if not _consume_verification(username, "phone", "signup", body.phone_code):
            raise HTTPException(status_code=401, detail="invalid or expired phone code")
    next_status = "awaiting_approval" if ADMIN_SIGNUP_REQUIRE_APPROVAL else "active"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """UPDATE dashboard_users
               SET email_verified_at = ?,
                   phone_verified_at = CASE WHEN phone IS NOT NULL AND phone <> '' AND ? <> '' THEN ? ELSE phone_verified_at END,
                   status = ?
               WHERE username = ?""",
            (
                utc_now_iso(),
                (body.phone_code or ""),
                utc_now_iso(),
                next_status,
                username,
            ),
        )
        conn.commit()
        conn.close()
    audit_event(username, "signup.verify", username, {"next_status": next_status})
    return {"ok": True, "status": next_status, "requires_approval": ADMIN_SIGNUP_REQUIRE_APPROVAL}


@router.post("/auth/activate")
def auth_activate_user(body: VerifyCodeRequest) -> dict[str, Any]:
    """Admin-created users activate themselves with the OTP the admin triggered."""
    username = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, status, email, phone FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        conn.close()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    if str(u["status"]) == "active":
        return {"ok": True, "already_active": True}
    if REQUIRE_EMAIL_VERIFICATION:
        if not body.email_code:
            raise HTTPException(status_code=400, detail="email_code required")
        if not _consume_verification(username, "email", "activate", body.email_code):
            raise HTTPException(status_code=401, detail="invalid or expired email code")
    if REQUIRE_PHONE_VERIFICATION and u["phone"]:
        if not body.phone_code:
            raise HTTPException(status_code=400, detail="phone_code required")
        if not _consume_verification(username, "phone", "activate", body.phone_code):
            raise HTTPException(status_code=401, detail="invalid or expired phone code")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """UPDATE dashboard_users
               SET email_verified_at = ?, status = 'active'
               WHERE username = ?""",
            (utc_now_iso(), username),
        )
        conn.commit()
        conn.close()
    audit_event(username, "account.activate", username, {})
    return {"ok": True, "status": "active"}


@router.post("/auth/code/resend")
def auth_code_resend(body: ResendCodeRequest) -> dict[str, Any]:
    username = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT role, status, email, phone FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        conn.close()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    if str(u["status"]) == "active" and body.purpose != "reset":
        return {"ok": True, "already_active": True}
    target = str(u["email"] or "") if body.channel == "email" else str(u["phone"] or "")
    if not target:
        raise HTTPException(status_code=400, detail=f"{body.channel} not on file")
    try:
        _issue_verification(username, body.channel, target, purpose=body.purpose)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("resend verification failed for %s %s: %s", username, body.channel, exc)
        raise HTTPException(status_code=502, detail=f"failed to send code: {exc}") from exc
    return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS}


# Phase-82 split: the 3 superadmin approval routes
# (/auth/signup/pending, /auth/signup/approve/{username},
# /auth/signup/reject/{username}) live in
# routers/auth_signup_approval.py. Both routers share the
# "auth-signup" tag so the OpenAPI doc groups them together.


__all__ = (
    "router",
    "SignupStartRequest",
    "VerifyCodeRequest",
    "ResendCodeRequest",
)
