"""Auth & signup-flow helper kernel (Phase-34 modularization).

The 17 small helpers extracted here are the bottom layer of the
authentication system: per-IP login lockout state, OTP/SMS/email
verification scaffolding, and signup rate limiting. They were the only
things still keeping app.py tied to plumbing concerns that nothing else
in the project actually needs to stay co-located with FastAPI/MQTT
boot code.

Public API
----------
Login lockout
    _check_login_ip_lockout(ip, username) → None
    _record_login_failure_ip(ip)         → None
    _record_login_failure(ip, username)  → None
    _clear_login_ip_state(ip)            → None
    _clear_login_failures(username)      → None

Signup / OTP
    _looks_like_email(s)                       → bool
    _normalize_phone(s)                        → Optional[str]
    _hash_otp(code)                            → str
    _generate_otp()                            → str   (6-digit numeric, CSPRNG)
    _generate_sha_code()                       → str   (10-char SHA-derived reset code)
    _check_signup_rate(ip, email)              → None  (raises 429)
    _record_signup_attempt(ip, email)          → None
    _send_email_otp(to, code, purpose)         → None
    _send_sms_otp(phone, code, purpose)        → None
    _issue_verification(...)                   → int   (TTL seconds)
    _verification_resend_wait_seconds(...)     → int
    _consume_verification(...)                 → bool

Late binding
------------
Only ``emit_event`` is late-bound from ``app`` because the event bus is
constructed during app startup and the module would otherwise pin a
no-op stub at import time. Everything else (config constants, the
notifier singleton, render_otp_email) is bound at import.
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
    LOGIN_LOCK_TIER0_FAILS,
    LOGIN_LOCK_TIER0_SECONDS,
    LOGIN_LOCK_TIER1_FAILS,
    LOGIN_LOCK_TIER1_SECONDS,
    LOGIN_LOCK_TIER2_FAILS,
    LOGIN_LOCK_TIER2_SECONDS,
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


logger = logging.getLogger("croc-api.auth_helpers")


def _emit_event(*args, **kwargs):
    """Late-bound emit_event — defer lookup until call time so the event
    bus is fully constructed. Avoids module-import cycles with app."""
    import app as _app  # local import — re-evaluated only on first call
    return _app.emit_event(*args, **kwargs)


# ────────────────────────────────────────────────────────────────────
#  Login lockout (per-IP) — three escalating tiers
# ────────────────────────────────────────────────────────────────────

def _check_login_ip_lockout(ip: str, username: str) -> None:
    """Raise 429 if this client IP is in an active post-failure lock window."""
    now = int(time.time())
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT fail_count, phase, lock_until FROM login_ip_state WHERE ip = ?", (ip,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return
    lock_until = int(row["lock_until"] or 0)
    if lock_until <= now:
        return
    remaining = max(1, lock_until - now)
    phase = int(row["phase"] or 0)
    fail_count = int(row["fail_count"] or 0)
    _emit_event(
        level="error",
        category="auth",
        event_type="auth.login.rate_limited",
        summary=f"login locked {username}@{ip}",
        actor=f"ip:{ip}",
        target=username,
        detail={
            "remaining_s": remaining,
            "phase": phase,
            "fail_count": fail_count,
        },
    )
    raise HTTPException(
        status_code=429,
        detail=f"too many login attempts — try again in {remaining}s",
        headers={"Retry-After": str(remaining)},
    )


def _record_login_failure_ip(ip: str) -> None:
    """Increment per-IP failure count; at threshold apply timed lock and advance phase."""
    now = int(time.time())
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT fail_count, phase, lock_until FROM login_ip_state WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if row:
            fail_count = int(row["fail_count"] or 0)
            phase = int(row["phase"] or 0)
        else:
            fail_count, phase = 0, 0
        fail_count += 1
        if phase == 0:
            th = LOGIN_LOCK_TIER0_FAILS
        elif phase == 1:
            th = LOGIN_LOCK_TIER1_FAILS
        else:
            th = LOGIN_LOCK_TIER2_FAILS
        new_fail = fail_count
        new_phase = phase
        new_lock = 0
        if new_fail >= th:
            if phase == 0:
                new_lock = now + LOGIN_LOCK_TIER0_SECONDS
                new_phase = 1
            elif phase == 1:
                new_lock = now + LOGIN_LOCK_TIER1_SECONDS
                new_phase = 2
            else:
                new_lock = now + LOGIN_LOCK_TIER2_SECONDS
                new_phase = 2
            new_fail = 0
        cur.execute(
            """
            INSERT INTO login_ip_state (ip, fail_count, phase, lock_until)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              fail_count = excluded.fail_count,
              phase = excluded.phase,
              lock_until = excluded.lock_until
            """,
            (ip, new_fail, new_phase, new_lock),
        )
        conn.commit()
        conn.close()


def _record_login_failure(ip: str, username: str) -> None:
    """Keep append-only failure log + update per-IP lockout state."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO login_failures (ip, username, ts_epoch) VALUES (?, ?, ?)",
            (ip, username, int(time.time())),
        )
        conn.commit()
        conn.close()
    _record_login_failure_ip(ip)


def _clear_login_ip_state(ip: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM login_ip_state WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()


def _clear_login_failures(username: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM login_failures WHERE username = ?", (username,))
        conn.commit()
        conn.close()


# ────────────────────────────────────────────────────────────────────
#  Signup / activation helpers
# ────────────────────────────────────────────────────────────────────

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
    "_check_login_ip_lockout",
    "_record_login_failure_ip",
    "_record_login_failure",
    "_clear_login_ip_state",
    "_clear_login_failures",
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
    "_EMAIL_RE",
    "_USERNAME_RE",
    "_PHONE_RE",
]
