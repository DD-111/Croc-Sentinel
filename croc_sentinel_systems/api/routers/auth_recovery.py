"""Auth password-recovery routes
(Phase-17, trimmed Phase-64 → Phase-72 → Phase-84).

Surface evolution:
  Phase 17 — original module: signup + password recovery.
  Phase 64 — split the signup half into ``routers/auth_signup.py``.
  Phase 72 — split the email-OTP recovery flow into
              ``routers/auth_recovery_email.py``; this file kept
              the offline-RSA-blob flow plus the 6 helpers shared
              with the email module.
  Phase 84 — extract the 6 stateless helpers (4 RSA-blob crypto
              + per-IP rate-limit + token sweeper) into
              ``routers/auth_recovery_helpers.py`` and re-export
              them here for backward compatibility.

This module is now a pure routes module: 2 schemas + 3 routes +
the late-binding wrappers it needs to call into ``app``.

Routes (all unauthenticated)
----------------------------
  GET   /auth/forgot/enabled
  POST  /auth/forgot/start
  POST  /auth/forgot/complete

Schemas
-------
  ForgotStartRequest, ForgotCompleteRequest

Helpers re-exported (single source of truth in
``routers/auth_recovery_helpers.py``)
---------------------------------------------------
- ``_password_recovery_load_public``,
  ``_password_recovery_blob_byte_len``,
  ``_encrypt_password_recovery_payload``,
  ``_fake_password_recovery_hex`` — RSA-blob cipher.
- ``_check_forgot_ip_rate`` — also imported by
  ``routers.auth_recovery_email`` (both flows share the same
  per-IP budget).
- ``_prune_password_reset_tokens`` — bound onto
  ``_app._prune_password_reset_tokens`` by
  ``routes_registry.register_routers`` so the scheduler thread
  can call it without depending on this module's full import surface.

Late binding
------------
``emit_event`` / ``get_manager_admin`` / ``_client_ip`` /
``_clear_login_failures`` / ``_clear_login_ip_state`` are
late-bound at call time off ``app``. Validation/rate-limit helpers
that the email flow needed (``_looks_like_email``,
``_issue_verification``, ``_consume_verification``,
``_verification_resend_wait_seconds``, ``_generate_sha_code``)
were moved to the email module — this module no longer imports
those.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import uuid
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import FORGOT_PASSWORD_TOKEN_TTL_SECONDS
from db import db_lock, get_conn
from helpers import utc_now_iso
from routers.auth_recovery_helpers import (
    _check_forgot_ip_rate,
    _encrypt_password_recovery_payload,
    _fake_password_recovery_hex,
    _password_recovery_blob_byte_len,
    _password_recovery_load_public,
    _prune_password_reset_tokens,
)
from security import hash_password


# ----- Late-bound helpers (resolved at call time off ``app``) -------------
def _emit_event(*args: Any, **kwargs: Any) -> Any:
    return _app.emit_event(*args, **kwargs)


def _get_manager_admin(username: str) -> str:
    return _app.get_manager_admin(username)


def _client_ip(request: Request) -> str:
    return _app._client_ip(request)


def _clear_login_failures(username: str) -> None:
    _app._clear_login_failures(username)


def _clear_login_ip_state(ip: str) -> None:
    _app._clear_login_ip_state(ip)


logger = logging.getLogger("croc-api.routers.auth_recovery")
router = APIRouter(tags=["auth-recovery"])


# ===========================================================================
# Pydantic request schemas
# ===========================================================================

class ForgotStartRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class ForgotCompleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    recovery_plain: str = Field(min_length=8, max_length=4096)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


# ===========================================================================
# Offline RSA password recovery (cipher / IP rate / prune) — Phase-84
# ===========================================================================
#
# The 6 helpers (4 RSA-blob crypto + per-IP rate-limit + token sweeper)
# live in ``routers/auth_recovery_helpers.py``. They were imported at
# the top of this file and are also exported via this module's
# ``__all__`` for backward compatibility:
#
#   * ``routers.auth_recovery_email`` historically imports
#     ``_check_forgot_ip_rate`` from ``routers.auth_recovery``.
#   * ``routes_registry.register_routers`` historically imports
#     ``_prune_password_reset_tokens`` from ``routers.auth_recovery``
#     and pins it onto ``_app._prune_password_reset_tokens``.
#
# Either consumer can switch to importing directly from
# ``routers.auth_recovery_helpers`` — the re-export here is purely a
# transition convenience.


# ===========================================================================
# Forgot-password (offline RSA blob path)
# ===========================================================================

@router.get("/auth/forgot/enabled")
def auth_forgot_enabled() -> dict[str, Any]:
    return {"enabled": bool(_password_recovery_load_public())}


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


__all__ = (
    "router",
    "ForgotStartRequest",
    "ForgotCompleteRequest",
    "_password_recovery_load_public",
    "_password_recovery_blob_byte_len",
    "_encrypt_password_recovery_payload",
    "_fake_password_recovery_hex",
    "_check_forgot_ip_rate",
    "_prune_password_reset_tokens",
)
