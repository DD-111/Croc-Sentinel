"""Signup / OTP / verification scaffolding (Phase-71 split from ``auth_helpers.py``).

The Phase-34 ``auth_helpers.py`` kernel bundled three concerns:

  1. Per-IP login lockout (rate-limit failed login attempts).
  2. Signup / OTP / verification (delivery + check codes for
     activation, password recovery, and email/phone change).
  3. ``require_principal`` (FastAPI dependency that decodes the JWT).

Concern (2) is the largest of the three (~250 lines) and has its
own dependency cluster: ``email_templates.render_otp_email``,
``notifier``, ``SMS_PROVIDER`` config knobs, the
``signup_attempts``/``verifications`` SQLite tables. None of those
are needed by login-lockout or by ``require_principal``, so
isolating them into this module makes the auth surface easier to
reason about — login-lockout review no longer needs to know how
SMS is wired up.

Public API
----------
Format normalisers
    _looks_like_email(s)            -> bool
    _normalize_phone(s)             -> Optional[str]
    _EMAIL_RE                       (regex, exposed for callers)
    _USERNAME_RE                    (regex, exposed for callers)
    _PHONE_RE                       (regex, exposed for callers)

OTP primitives
    _hash_otp(code)                 -> str
    _generate_otp()                 -> str  (6-digit numeric, CSPRNG)
    _generate_sha_code()            -> str  (10-char SHA-derived reset code)

Signup rate limit
    _check_signup_rate(ip, email)   -> None  (raises 429)
    _record_signup_attempt(ip, email) -> None

Delivery
    _send_email_otp(to, code, purpose)    -> None
    _send_sms_otp(phone, code, purpose)   -> None

Verification lifecycle
    _issue_verification(...)              -> int  (TTL seconds)
    _verification_resend_wait_seconds(...) -> int
    _consume_verification(...)            -> bool

Backward compatibility
----------------------
``auth_helpers.py`` re-exports all of these names through its
``__all__``, and ``app.py`` continues to re-export from
``auth_helpers``, so existing late-bound callers
(``import app as _app``; ``_app._issue_verification(...)``)
continue to work without changes.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import time
from datetime import datetime
from typing import Optional

from fastapi import HTTPException

from config import (
    JWT_SECRET,
    OTP_RESEND_COOLDOWN_SECONDS,
    OTP_TTL_SECONDS,
    SIGNUP_RATE_MAX,
    SIGNUP_RATE_WINDOW_SECONDS,
    SMS_PROVIDER,
)
from db import db_lock, get_conn
from email_templates import render_otp_email
from helpers import utc_now_iso
from notifier import notifier


logger = logging.getLogger("croc-api.auth_otp")


# ---- Format normalisers ----------------------------------------------------

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,64}$")
# Loose phone normalizer: keep + and digits only. Callers still have to pick a
# country prefix for SMS delivery; we don't do E.164 validation because the
# SMS provider will reject anything unusable.
_PHONE_RE = re.compile(r"[^\d+]")


def _looks_like_email(s: str) -> bool:
    return bool(_EMAIL_RE.match(s or ""))


def _normalize_phone(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    cleaned = _PHONE_RE.sub("", s.strip())
    return cleaned if 4 <= len(cleaned) <= 32 else None


# ---- OTP primitives --------------------------------------------------------

def _hash_otp(code: str) -> str:
    """One-way hash so we never store plaintext OTPs at rest."""
    return hashlib.sha256((code + "|" + (JWT_SECRET or "jwt-unset")).encode("utf-8")).hexdigest()


def _generate_otp() -> str:
    """6-digit numeric OTP, CSPRNG backed."""
    n = secrets.randbelow(1_000_000)
    return f"{n:06d}"


def _generate_sha_code() -> str:
    """10-char SHA-like reset code for email delivery."""
    seed = f"{time.time_ns()}|{secrets.token_hex(16)}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10].upper()


# ---- Signup rate limit -----------------------------------------------------

def _check_signup_rate(ip: str, email: str) -> None:
    cutoff = int(time.time()) - SIGNUP_RATE_WINDOW_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM signup_attempts WHERE ts_epoch < ?", (cutoff,))
        cur.execute(
            "SELECT COUNT(*) AS c FROM signup_attempts WHERE ip = ? AND ts_epoch >= ?",
            (ip, cutoff),
        )
        ip_c = int(cur.fetchone()["c"])
        cur.execute(
            "SELECT COUNT(*) AS c FROM signup_attempts WHERE email = ? AND ts_epoch >= ?",
            (email, cutoff),
        )
        email_c = int(cur.fetchone()["c"])
        conn.commit()
        conn.close()
    if ip_c >= SIGNUP_RATE_MAX or email_c >= SIGNUP_RATE_MAX:
        raise HTTPException(status_code=429, detail="too many signup attempts — slow down")


def _record_signup_attempt(ip: str, email: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO signup_attempts (ip, email, ts_epoch) VALUES (?, ?, ?)",
            (ip, email, int(time.time())),
        )
        conn.commit()
        conn.close()


# ---- Delivery --------------------------------------------------------------

def _send_email_otp(to: str, code: str, purpose: str) -> None:
    """Registration / activation / reset OTP — distinct HTML themes + no-reply footer."""
    subject_prefix = (os.getenv("SMTP_SUBJECT_PREFIX", "[Sentinel]") or "[Sentinel]").strip()
    ttl_min = max(1, int(OTP_TTL_SECONDS // 60))
    subject, body, body_html = render_otp_email(
        purpose=purpose,
        code=code,
        ttl_min=ttl_min,
        subject_prefix=subject_prefix,
    )
    notifier.send_sync([to], subject, body, body_html)


def _send_sms_otp(phone: str, code: str, purpose: str) -> None:
    if SMS_PROVIDER in ("", "none"):
        # In email-only mode we silently skip — callers already checked
        # REQUIRE_PHONE_VERIFICATION, so this branch is only reached when the
        # admin provided a phone but no provider is installed.
        logger.info("sms provider not configured; skipping %s otp for %s", purpose, phone)
        return
    raise NotImplementedError(
        f"SMS_PROVIDER={SMS_PROVIDER} is not implemented in this build; "
        f"wire up notifier_sms.py or keep SMS_PROVIDER=none"
    )


# ---- Verification lifecycle ------------------------------------------------

def _issue_verification(
    username: str,
    channel: str,
    target: str,
    purpose: str,
    *,
    explicit_code: Optional[str] = None,
) -> int:
    """Create and deliver a fresh OTP. Returns remaining TTL in seconds."""
    if channel not in ("email", "phone"):
        raise ValueError("channel must be email|phone")
    code = explicit_code or _generate_otp()
    code_hash = _hash_otp(code)
    expires_at = int(time.time()) + OTP_TTL_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        # Cooldown: prevent hammering the mailer.
        cur.execute(
            """SELECT created_at FROM verifications
               WHERE username = ? AND channel = ? AND purpose = ? AND used = 0
               ORDER BY id DESC LIMIT 1""",
            (username, channel, purpose),
        )
        last = cur.fetchone()
        if last:
            try:
                last_ts = int(datetime.fromisoformat(str(last["created_at"])).timestamp())
            except Exception:
                last_ts = 0
            if int(time.time()) - last_ts < OTP_RESEND_COOLDOWN_SECONDS:
                conn.close()
                wait = OTP_RESEND_COOLDOWN_SECONDS - (int(time.time()) - last_ts)
                raise HTTPException(
                    status_code=429,
                    detail=f"Resend cooldown: wait {max(1, wait)}s before requesting another code",
                )
        # Invalidate previous pending codes for this (user, channel, purpose).
        cur.execute(
            "UPDATE verifications SET used = 1 WHERE username = ? AND channel = ? AND purpose = ? AND used = 0",
            (username, channel, purpose),
        )
        cur.execute(
            """INSERT INTO verifications
               (username, channel, target, purpose, code_hash, expires_at_ts, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (username, channel, target, purpose, code_hash, expires_at, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    if channel == "email":
        _send_email_otp(target, code, purpose)
    else:
        _send_sms_otp(target, code, purpose)
    return OTP_TTL_SECONDS


def _verification_resend_wait_seconds(username: str, channel: str, purpose: str) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT created_at FROM verifications
               WHERE username = ? AND channel = ? AND purpose = ? AND used = 0
               ORDER BY id DESC LIMIT 1""",
            (username, channel, purpose),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return 0
    try:
        last_ts = int(datetime.fromisoformat(str(row["created_at"])).timestamp())
    except Exception:
        return 0
    delta = int(time.time()) - last_ts
    if delta >= OTP_RESEND_COOLDOWN_SECONDS:
        return 0
    return max(1, OTP_RESEND_COOLDOWN_SECONDS - delta)


def _consume_verification(username: str, channel: str, purpose: str, code: str) -> bool:
    """Check code; mark used if it matches. Return True/False."""
    code_hash = _hash_otp(code or "")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, code_hash, attempts, expires_at_ts, used FROM verifications
               WHERE username = ? AND channel = ? AND purpose = ?
               ORDER BY id DESC LIMIT 1""",
            (username, channel, purpose),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return False
        if int(row["used"]) == 1:
            conn.close()
            return False
        if int(time.time()) > int(row["expires_at_ts"]):
            conn.close()
            return False
        if int(row["attempts"]) >= 5:
            conn.close()
            return False
        if not secrets.compare_digest(str(row["code_hash"]), code_hash):
            cur.execute("UPDATE verifications SET attempts = attempts + 1 WHERE id = ?", (int(row["id"]),))
            conn.commit()
            conn.close()
            return False
        cur.execute("UPDATE verifications SET used = 1 WHERE id = ?", (int(row["id"]),))
        conn.commit()
        conn.close()
    return True


__all__ = [
    "_EMAIL_RE",
    "_USERNAME_RE",
    "_PHONE_RE",
    "_looks_like_email",
    "_normalize_phone",
    "_hash_otp",
    "_generate_otp",
    "_generate_sha_code",
    "_check_signup_rate",
    "_record_signup_attempt",
    "_send_email_otp",
    "_send_sms_otp",
    "_issue_verification",
    "_verification_resend_wait_seconds",
    "_consume_verification",
]
