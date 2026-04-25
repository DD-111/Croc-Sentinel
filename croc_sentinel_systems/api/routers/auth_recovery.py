"""Auth password-recovery routes (Phase-17, trimmed Phase-64 + Phase-72).

Originally this module covered both signup and password recovery.
Phase 64 split the signup half into ``routers/auth_signup.py``.
Phase 72 split the email-OTP password recovery flow into
``routers/auth_recovery_email.py`` so this file now hosts only
the offline-RSA-blob recovery flow plus the helpers shared
between the two flows.

Routes (all unauthenticated)
----------------------------
  GET   /auth/forgot/enabled
  POST  /auth/forgot/start
  POST  /auth/forgot/complete

Schemas
-------
  ForgotStartRequest, ForgotCompleteRequest

Helpers owned here
------------------
- 4 RSA-blob helpers
  (``_password_recovery_load_public``,
   ``_password_recovery_blob_byte_len``,
   ``_encrypt_password_recovery_payload``,
   ``_fake_password_recovery_hex``)
- ``_check_forgot_ip_rate``      — re-exported and reused by
  ``routers.auth_recovery_email`` so both flows count toward the
  same per-IP rate-limit budget.
- ``_prune_password_reset_tokens`` — re-exported back into
  ``app.py`` (``routes_registry.register_routers`` binds it onto
  ``_app._prune_password_reset_tokens``) so the scheduler thread
  can call it without depending on this module's full import surface.

Late binding
------------
``emit_event`` / ``get_manager_admin`` / ``_client_ip`` /
``_clear_login_failures`` / ``_clear_login_ip_state`` are
late-bound at call time off ``app``. Validation/rate-limit helpers
that the email flow needed (``_looks_like_email``, ``_issue_verification``,
``_consume_verification``, ``_verification_resend_wait_seconds``,
``_generate_sha_code``) were moved to the email module — this
module no longer imports those.
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
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    FORGOT_PASSWORD_IP_MAX,
    FORGOT_PASSWORD_IP_WINDOW_SECONDS,
    FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
    PASSWORD_RECOVERY_BLOB_MAGIC,
    PASSWORD_RECOVERY_BLOB_VERSION,
    PASSWORD_RECOVERY_PLAINTEXT_PAD,
    PASSWORD_RECOVERY_PUBLIC_KEY_PATH,
    PASSWORD_RECOVERY_PUBLIC_KEY_PEM,
)
from db import db_lock, get_conn
from helpers import utc_now_iso
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
