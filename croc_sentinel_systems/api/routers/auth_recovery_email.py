"""Email-OTP password recovery routes (Phase-72 split from ``routers/auth_recovery.py``).

The Phase-17 module bundled two distinct password-reset flows:

  * **Email-OTP flow** (this file) — newer, lighter: send a 10-char
    SHA-derived code to the registered email, user pastes it back
    along with a new password.  Requires nothing more than a
    working SMTP/notifier — no key material to manage.
  * **Offline RSA blob flow** (kept in ``auth_recovery.py``) — the
    legacy / "high-assurance" path: server generates an
    AES-GCM-wrapped recovery blob whose AES key is RSA-encrypted
    against a configured public key.  The operator has to take
    that blob to an offline holder of the matching private key,
    decrypt it, and paste the inner JSON back into
    ``/auth/forgot/complete``.

The two flows have very different operational footprints (one
needs a mailer, the other needs an out-of-band cryptographic
ceremony) and should be reviewed independently.

Routes (all unauthenticated)
----------------------------
  GET   /auth/forgot/email/enabled
  POST  /auth/forgot/email/check
  POST  /auth/forgot/email/start
  POST  /auth/forgot/email/complete

Schemas
-------
  ForgotEmailStartRequest, ForgotEmailCompleteRequest

Cross-module dependency
-----------------------
This module imports ``_check_forgot_ip_rate`` from
``routers.auth_recovery`` because both flows share the same
``forgot_password_attempts`` table (and the rate-limit budget is
counted across both flows — a determined attacker shouldn't be
able to alternate between flows to bypass the rate limit).

Late binding
------------
Validation/rate-limit helpers live in ``auth_helpers.py`` /
``app.py`` and are late-bound here via ``import app as _app``.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import OTP_RESEND_COOLDOWN_SECONDS, OTP_TTL_SECONDS
from db import db_lock, get_conn
from notifier import notifier
from routers.auth_recovery import _check_forgot_ip_rate
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


def _consume_verification(username: str, channel: str, purpose: str, code: str) -> bool:
    return _app._consume_verification(username, channel, purpose, code)


def _verification_resend_wait_seconds(username: str, channel: str, purpose: str) -> int:
    return _app._verification_resend_wait_seconds(username, channel, purpose)


def _generate_sha_code() -> str:
    return _app._generate_sha_code()


def _issue_verification(
    username: str,
    channel: str,
    target: str,
    purpose: str = "activate",
    *,
    explicit_code: Optional[str] = None,
) -> int:
    return _app._issue_verification(username, channel, target, purpose, explicit_code=explicit_code)


def _clear_login_failures(username: str) -> None:
    _app._clear_login_failures(username)


def _clear_login_ip_state(ip: str) -> None:
    _app._clear_login_ip_state(ip)


logger = logging.getLogger("croc-api.routers.auth_recovery_email")
router = APIRouter(tags=["auth-recovery-email"])


# ---- Schemas ---------------------------------------------------------------

class ForgotEmailStartRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)


class ForgotEmailCompleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    sha_code: str = Field(min_length=6, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


# ---- Routes ----------------------------------------------------------------

@router.get("/auth/forgot/email/enabled")
def auth_forgot_email_enabled() -> dict[str, Any]:
    return {"enabled": bool(notifier.enabled())}


@router.post("/auth/forgot/email/check")
def auth_forgot_email_check(body: ForgotEmailStartRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    _check_forgot_ip_rate(ip)
    username = body.username.strip()
    email = body.email.strip().lower()
    if not _looks_like_email(email):
        raise HTTPException(status_code=400, detail="email format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT status, email FROM dashboard_users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return {"ok": True, "matched": False, "can_send": False, "resend_after_seconds": 0}
    if str(row["status"] or "active") == "disabled":
        return {"ok": True, "matched": False, "can_send": False, "resend_after_seconds": 0}
    reg_email = str(row["email"] or "").strip().lower()
    matched = bool(reg_email) and reg_email == email
    if not matched:
        return {"ok": True, "matched": False, "can_send": False, "resend_after_seconds": 0}
    wait = _verification_resend_wait_seconds(username, "email", "reset")
    return {"ok": True, "matched": True, "can_send": wait <= 0, "resend_after_seconds": wait}


@router.post("/auth/forgot/email/start")
def auth_forgot_email_start(body: ForgotEmailStartRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    _check_forgot_ip_rate(ip)
    username = body.username.strip()
    email = body.email.strip().lower()
    if not _looks_like_email(email):
        raise HTTPException(status_code=400, detail="email format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, status, email FROM dashboard_users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}
    if str(row["status"] or "active") == "disabled":
        return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}
    reg_email = str(row["email"] or "").strip().lower()
    if not reg_email or reg_email != email:
        return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}
    if not notifier.enabled():
        raise HTTPException(status_code=503, detail="email sender is not configured")
    sha_code = _generate_sha_code()
    try:
        ttl = _issue_verification(username, "email", email, "reset", explicit_code=sha_code)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("password reset email send failed for %s: %s", username, exc)
        raise HTTPException(
            status_code=502,
            detail=f"failed to send recovery email: {exc}",
        ) from exc
    _emit_event(
        level="info",
        category="auth",
        event_type="auth.password_reset.email_code.started",
        summary=f"password reset sha code sent for {username}",
        actor=f"ip:{ip}",
        target=username,
        owner_admin=username if str(row["role"] or "") == "admin" else _get_manager_admin(username),
        detail={"email": email},
    )
    return {"ok": True, "ttl_seconds": ttl, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}


@router.post("/auth/forgot/email/complete")
def auth_forgot_email_complete(body: ForgotEmailCompleteRequest, request: Request) -> dict[str, Any]:
    if body.password != body.password_confirm:
        raise HTTPException(status_code=400, detail="passwords do not match")
    username = body.username.strip()
    email = body.email.strip().lower()
    if not _looks_like_email(email):
        raise HTTPException(status_code=400, detail="email format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT status, role, email FROM dashboard_users WHERE username = ?", (username,))
        urow = cur.fetchone()
        conn.close()
    if not urow:
        raise HTTPException(status_code=404, detail="user not found")
    if str(urow["status"] or "active") == "disabled":
        raise HTTPException(status_code=403, detail="account disabled")
    if str(urow["email"] or "").strip().lower() != email:
        raise HTTPException(status_code=400, detail="email does not match registered email")
    ok = _consume_verification(username, "email", "reset", body.sha_code.strip())
    if not ok:
        raise HTTPException(status_code=400, detail="invalid or expired sha code")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE dashboard_users SET password_hash = ? WHERE username = ?",
            (hash_password(body.password), username),
        )
        conn.commit()
        conn.close()
    _clear_login_failures(username)
    ip = _client_ip(request)
    _clear_login_ip_state(ip)
    audit_event(username, "auth.password_reset.email_code.ok", "", {"ip": ip, "email": email})
    _emit_event(
        level="warn",
        category="auth",
        event_type="auth.password_reset.email_code.completed",
        summary=f"password reset via email code for {username}",
        actor=username,
        target=username,
        owner_admin=username if str(urow["role"] or "") == "admin" else _get_manager_admin(username),
        detail={"ip": ip, "email": email},
    )
    return {"ok": True}


__all__ = (
    "router",
    "ForgotEmailStartRequest",
    "ForgotEmailCompleteRequest",
)
