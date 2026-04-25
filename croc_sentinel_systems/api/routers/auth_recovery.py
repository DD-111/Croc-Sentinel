"""Auth signup + password-recovery routes (Phase-17 modularization).

Carved out of ``app.py`` so the gnarly OTP / RSA-blob recovery flows
live next to their schemas and crypto helpers instead of being
sandwiched between the JWT-issuing core and the user-management
admin endpoints.

Routes (all unauthenticated except the two superadmin approval calls)
---------------------------------------------------------------------
  POST  /auth/signup/start
  POST  /auth/signup/verify
  POST  /auth/activate
  POST  /auth/code/resend
  GET   /auth/signup/pending             [superadmin]
  POST  /auth/signup/approve/{username}  [superadmin]
  POST  /auth/signup/reject/{username}   [superadmin]
  GET   /auth/forgot/enabled
  GET   /auth/forgot/email/enabled
  POST  /auth/forgot/email/check
  POST  /auth/forgot/email/start
  POST  /auth/forgot/email/complete
  POST  /auth/forgot/start
  POST  /auth/forgot/complete

Helpers and schemas (moved with routes)
---------------------------------------
- 7 Pydantic schemas (3 signup + 4 forgot)
- ``_password_recovery_load_public`` + 3 RSA helpers
- ``_check_forgot_ip_rate``, ``_prune_password_reset_tokens``

The recovery prune helper is re-exported back into ``app.py`` so the
scheduler thread (which still lives in app.py) can call it without
caring about the move.

Late binding
------------
Validation/rate-limit helpers (``_USERNAME_RE``, ``_looks_like_email``,
``_check_signup_rate``, ``_issue_verification`` etc.) all stay in
``app.py`` for now and are late-bound here. ``emit_event`` and
``get_manager_admin`` are also late-bound to avoid pulling the entire
app module at import time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    ADMIN_SIGNUP_REQUIRE_APPROVAL,
    ALLOW_PUBLIC_ADMIN_SIGNUP,
    FORGOT_PASSWORD_IP_MAX,
    FORGOT_PASSWORD_IP_WINDOW_SECONDS,
    FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
    OTP_RESEND_COOLDOWN_SECONDS,
    OTP_TTL_SECONDS,
    PASSWORD_RECOVERY_BLOB_MAGIC,
    PASSWORD_RECOVERY_BLOB_VERSION,
    PASSWORD_RECOVERY_PLAINTEXT_PAD,
    PASSWORD_RECOVERY_PUBLIC_KEY_PATH,
    PASSWORD_RECOVERY_PUBLIC_KEY_PEM,
    REQUIRE_EMAIL_VERIFICATION,
    REQUIRE_PHONE_VERIFICATION,
)
from db import db_lock, get_conn
from helpers import default_policy_for_role, utc_now_iso
from notifier import notifier
from security import Principal, assert_min_role, hash_password

require_principal = _app.require_principal


# ----- late-bound, captured lazily so the order of definition in app.py
# does not matter. Each call goes through ``_app.<name>``. ------------------
def _emit_event(*args: Any, **kwargs: Any) -> Any:
    return _app.emit_event(*args, **kwargs)


def _get_manager_admin(username: str) -> str:
    return _app.get_manager_admin(username)


def _client_ip(request: Request) -> str:
    return _app._client_ip(request)


def _looks_like_email(s: str) -> bool:
    return _app._looks_like_email(s)


def _normalize_phone(s: Optional[str]) -> Optional[str]:
    return _app._normalize_phone(s)


def _check_signup_rate(ip: str, email: str) -> None:
    _app._check_signup_rate(ip, email)


def _record_signup_attempt(ip: str, email: str) -> None:
    _app._record_signup_attempt(ip, email)


def _issue_verification(*args: Any, **kwargs: Any) -> Any:
    return _app._issue_verification(*args, **kwargs)


def _consume_verification(username: str, channel: str, purpose: str, code: str) -> bool:
    return _app._consume_verification(username, channel, purpose, code)


def _verification_resend_wait_seconds(username: str, channel: str, purpose: str) -> int:
    return _app._verification_resend_wait_seconds(username, channel, purpose)


def _generate_sha_code() -> str:
    return _app._generate_sha_code()


def _clear_login_failures(username: str) -> None:
    _app._clear_login_failures(username)


def _clear_login_ip_state(ip: str) -> None:
    _app._clear_login_ip_state(ip)


# Late-bind the username regex by attribute access so app.py can rebuild it.
def _username_re_match(username: str) -> Any:
    return _app._USERNAME_RE.match(username)


# sqlite3 IntegrityError is referenced inline; import lazily-style for safety.
import sqlite3  # noqa: E402

logger = logging.getLogger("croc-api.routers.auth_recovery")

router = APIRouter(tags=["auth-recovery"])


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


class ForgotStartRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class ForgotEmailStartRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)


class ForgotEmailCompleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    sha_code: str = Field(min_length=6, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


class ForgotCompleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    recovery_plain: str = Field(min_length=8, max_length=4096)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


# ===========================================================================
# Offline RSA password recovery (cipher / IP rate / prune)
# ===========================================================================

_pwrec_pubkey_lock = threading.Lock()
_pwrec_pubkey_cache: Any = None  # None=unset, False=missing, else RSAPublicKey


def _password_recovery_load_public() -> Optional[Any]:
    """Lazy-load PEM from PASSWORD_RECOVERY_PUBLIC_KEY_PEM or *_PATH."""
    global _pwrec_pubkey_cache
    with _pwrec_pubkey_lock:
        if _pwrec_pubkey_cache is not None:
            if _pwrec_pubkey_cache is False:
                return None
            return _pwrec_pubkey_cache
        pem = (PASSWORD_RECOVERY_PUBLIC_KEY_PEM or "").replace("\\n", "\n").strip()
        if not pem and PASSWORD_RECOVERY_PUBLIC_KEY_PATH:
            try:
                from pathlib import Path

                pem = Path(PASSWORD_RECOVERY_PUBLIC_KEY_PATH).expanduser().read_text(encoding="utf-8").strip()
            except Exception as exc:
                logger.warning("PASSWORD_RECOVERY_PUBLIC_KEY_PATH read failed: %s", exc)
                pem = ""
        if not pem:
            _pwrec_pubkey_cache = False
            return None
        try:
            key = serialization.load_pem_public_key(pem.encode("utf-8"))
            if not isinstance(key, rsa.RSAPublicKey):
                logger.warning("password recovery: PEM must be an RSA public key")
                _pwrec_pubkey_cache = False
                return None
            if key.key_size < 2048:
                logger.warning("password recovery: RSA key must be >= 2048 bits")
                _pwrec_pubkey_cache = False
                return None
            _pwrec_pubkey_cache = key
            return key
        except Exception as exc:
            logger.warning("password recovery: invalid PEM: %s", exc)
            _pwrec_pubkey_cache = False
            return None


def _password_recovery_blob_byte_len(pub: rsa.RSAPublicKey) -> int:
    rsa_len = pub.key_size // 8
    return len(PASSWORD_RECOVERY_BLOB_MAGIC) + 1 + rsa_len + 12 + (PASSWORD_RECOVERY_PLAINTEXT_PAD + 16)


def _encrypt_password_recovery_payload(pub: rsa.RSAPublicKey, inner: dict[str, Any]) -> bytes:
    pad = int(PASSWORD_RECOVERY_PLAINTEXT_PAD)
    pt = json.dumps(inner, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(pt) > pad:
        raise ValueError("inner JSON exceeds PASSWORD_RECOVERY_PLAINTEXT_PAD")
    pt = pt + (b"\x00" * (pad - len(pt)))
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(iv, pt, None)
    rsa_cipher = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(rsa_cipher) != pub.key_size // 8:
        raise ValueError("RSA ciphertext length mismatch")
    return PASSWORD_RECOVERY_BLOB_MAGIC + bytes([PASSWORD_RECOVERY_BLOB_VERSION]) + rsa_cipher + iv + ct


def _fake_password_recovery_hex(pub: rsa.RSAPublicKey) -> str:
    return secrets.token_bytes(_password_recovery_blob_byte_len(pub)).hex()


def _check_forgot_ip_rate(ip: str) -> None:
    now = int(time.time())
    cut = now - FORGOT_PASSWORD_IP_WINDOW_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM forgot_password_attempts WHERE ts_epoch < ?", (cut,))
        cur.execute(
            "SELECT COUNT(*) AS c FROM forgot_password_attempts WHERE ip = ? AND ts_epoch >= ?",
            (ip, cut),
        )
        c = int(cur.fetchone()["c"])
        if c >= FORGOT_PASSWORD_IP_MAX:
            conn.commit()
            conn.close()
            raise HTTPException(
                status_code=429,
                detail=f"too many recovery attempts from this IP — try again in {FORGOT_PASSWORD_IP_WINDOW_SECONDS}s",
            )
        cur.execute("INSERT INTO forgot_password_attempts (ip, ts_epoch) VALUES (?, ?)", (ip, now))
        conn.commit()
        conn.close()


def _prune_password_reset_tokens() -> None:
    """Drop expired rows (used or unused) older than 7 days past expiry."""
    now = int(time.time())
    cut = now - 7 * 86400
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM password_reset_tokens WHERE expires_at_ts < ?", (cut,))
        conn.commit()
        conn.close()


# ===========================================================================
# Signup / activation / approval routes
# ===========================================================================

@router.post("/auth/signup/start")
def auth_signup_start(body: SignupStartRequest, request: Request) -> dict[str, Any]:
    """Public admin self-signup (role=admin only, never superadmin).

    Creates a `dashboard_users` row in status='pending' and emails an OTP.
    The account becomes usable only after /auth/signup/verify succeeds AND,
    When ADMIN_SIGNUP_REQUIRE_APPROVAL=1, a superadmin must approve after OTP.
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


@router.get("/auth/signup/pending")
def auth_signup_pending(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin queue: admins who passed OTP but await approval."""
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT username, email, phone, created_at, email_verified_at
               FROM dashboard_users
               WHERE role = 'admin' AND status = 'awaiting_approval'
               ORDER BY created_at ASC"""
        )
        items = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": items}


@router.post("/auth/signup/approve/{username}")
def auth_signup_approve(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE dashboard_users SET status='active' WHERE username = ? AND role='admin' AND status='awaiting_approval'",
            (username,),
        )
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="no pending admin with that username")
    audit_event(principal.username, "signup.approve", username, {})
    return {"ok": True, "username": username}


@router.post("/auth/signup/reject/{username}")
def auth_signup_reject(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM dashboard_users WHERE username = ? AND role='admin' AND status='awaiting_approval'",
            (username,),
        )
        n = cur.rowcount
        cur.execute("DELETE FROM role_policies WHERE username = ?", (username,))
        cur.execute("DELETE FROM verifications WHERE username = ?", (username,))
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="no pending admin with that username")
    audit_event(principal.username, "signup.reject", username, {})
    return {"ok": True}


# ===========================================================================
# Forgot-password (email-OTP path) and offline RSA blob path
# ===========================================================================

@router.get("/auth/forgot/enabled")
def auth_forgot_enabled() -> dict[str, Any]:
    return {"enabled": bool(_password_recovery_load_public())}


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


@router.post("/auth/forgot/start")
def auth_forgot_start(body: ForgotStartRequest, request: Request) -> dict[str, Any]:
    """Return a hex-encoded blob. Only blobs tied to a real account can be
    completed; invalid usernames still receive a same-length random blob."""
    ip = _client_ip(request)
    pub = _password_recovery_load_public()
    if not pub:
        raise HTTPException(
            status_code=503,
            detail="password recovery is not configured (missing PASSWORD_RECOVERY_PUBLIC_KEY_*)",
        )
    _check_forgot_ip_rate(ip)
    un = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, status, role FROM dashboard_users WHERE username = ?", (un,))
        row = cur.fetchone()
        conn.close()
    blob_hex = _fake_password_recovery_hex(pub)
    if not row:
        return {
            "ok": True,
            "recovery_blob_hex": blob_hex,
            "ttl_seconds": FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
            "blob_byte_len": _password_recovery_blob_byte_len(pub),
        }
    status = str(row["status"] or "active")
    if status == "disabled":
        return {
            "ok": True,
            "recovery_blob_hex": blob_hex,
            "ttl_seconds": FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
            "blob_byte_len": _password_recovery_blob_byte_len(pub),
        }
    secret = os.urandom(32)
    secret_hash = hashlib.sha256(secret).hexdigest()
    jti = str(uuid.uuid4())
    exp_ts = int(time.time()) + FORGOT_PASSWORD_TOKEN_TTL_SECONDS
    inner = {
        "jti": jti,
        "u": un,
        "s": base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="),
        "e": exp_ts,
    }
    try:
        raw = _encrypt_password_recovery_payload(pub, inner)
    except Exception as exc:
        logger.error("password recovery encrypt failed: %s", exc)
        raise HTTPException(status_code=500, detail="could not build recovery blob") from exc
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO password_reset_tokens (jti, username, secret_hash, created_at, expires_at_ts, used, request_ip)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (jti, un, secret_hash, now_iso, exp_ts, ip),
        )
        conn.commit()
        conn.close()
    _emit_event(
        level="info",
        category="auth",
        event_type="auth.password_reset.started",
        summary=f"recovery blob issued for {un}",
        actor=f"ip:{ip}",
        target=un,
        owner_admin=un if str(row["role"]) == "admin" else _get_manager_admin(un),
        detail={"jti": jti},
    )
    return {
        "ok": True,
        "recovery_blob_hex": raw.hex(),
        "ttl_seconds": FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
        "blob_byte_len": len(raw),
    }


@router.post("/auth/forgot/complete")
def auth_forgot_complete(body: ForgotCompleteRequest, request: Request) -> dict[str, Any]:
    if body.password != body.password_confirm:
        raise HTTPException(status_code=400, detail="passwords do not match")
    pub = _password_recovery_load_public()
    if not pub:
        raise HTTPException(status_code=503, detail="password recovery is not configured")
    un = body.username.strip()
    try:
        data = json.loads(body.recovery_plain.strip())
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="recovery_plain must be valid JSON — paste the entire single-line output from decrypt_recovery_blob.py",
        ) from exc
    jti = str(data.get("jti") or "")
    u = str(data.get("u") or "")
    s_b64 = str(data.get("s") or "")
    exp = int(data.get("e") or 0)
    if not jti or not u or not s_b64:
        raise HTTPException(status_code=400, detail="recovery JSON missing jti / u / s")
    if u != un:
        raise HTTPException(status_code=400, detail="username does not match recovery token (u field)")
    if int(time.time()) > exp:
        raise HTTPException(status_code=400, detail="recovery token expired")
    pad = "=" * ((4 - len(s_b64) % 4) % 4)
    try:
        secret = base64.urlsafe_b64decode((s_b64 + pad).encode("ascii"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid secret field in recovery JSON") from exc
    if len(secret) != 32:
        raise HTTPException(status_code=400, detail="invalid secret length")
    digest = hashlib.sha256(secret).hexdigest()
    ip = _client_ip(request)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM password_reset_tokens WHERE jti = ? AND username = ? AND used = 0",
            (jti, un),
        )
        tok = cur.fetchone()
        if not tok or not secrets.compare_digest(str(tok["secret_hash"]), digest):
            conn.close()
            audit_event(f"ip:{ip}", "auth.password_reset.fail", un, {"reason": "bad token"})
            raise HTTPException(status_code=400, detail="invalid or already-used recovery token")
        if int(time.time()) > int(tok["expires_at_ts"]):
            conn.close()
            raise HTTPException(status_code=400, detail="recovery token expired")
        cur.execute("SELECT status, role FROM dashboard_users WHERE username = ?", (un,))
        urow = cur.fetchone()
        if not urow:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        st = str(urow["status"] or "active")
        role = str(urow["role"] or "")
        if st == "disabled":
            conn.close()
            raise HTTPException(status_code=403, detail="account disabled")
        new_hash = hash_password(body.password)
        cur.execute(
            "UPDATE dashboard_users SET password_hash = ? WHERE username = ?",
            (new_hash, un),
        )
        cur.execute(
            "UPDATE password_reset_tokens SET used = 1, used_at = ? WHERE jti = ?",
            (utc_now_iso(), jti),
        )
        conn.commit()
        conn.close()
    _clear_login_failures(un)
    _clear_login_ip_state(ip)
    audit_event(un, "auth.password_reset.ok", "", {"ip": ip})
    _emit_event(
        level="warn",
        category="auth",
        event_type="auth.password_reset.completed",
        summary=f"password reset for {un}",
        actor=un,
        target=un,
        owner_admin=un if role == "admin" else _get_manager_admin(un),
        detail={"ip": ip},
    )
    return {"ok": True}
