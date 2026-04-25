"""Auth kernel: per-IP login lockout + ``require_principal`` (Phase-34, trimmed P71).

The Phase-34 modularization extracted 17 small helpers from app.py.
Phase 71 splits the OTP / signup-verification half into
``auth_otp.py`` so this module focuses on the two runtime auth
concerns that every request hits:

  1. Per-IP login lockout state (``login_ip_state``,
     ``login_failures`` tables) — three escalating tier penalty
     for repeated bad-password attempts.
  2. ``require_principal`` — FastAPI dependency that decodes the
     JWT (or falls back to legacy bearer when enabled) and returns
     a Principal.

Public API
----------
Login lockout
    _check_login_ip_lockout(ip, username) -> None
    _record_login_failure_ip(ip)          -> None
    _record_login_failure(ip, username)   -> None
    _clear_login_ip_state(ip)             -> None
    _clear_login_failures(username)       -> None

Principal
    require_principal(authorization=Header, sentinel_jwt_cookie=Cookie) -> Principal

Re-exported from auth_otp.py for backward compatibility
-------------------------------------------------------
All OTP/signup helpers are surfaced here through ``__all__`` so
``from auth_helpers import _issue_verification`` (and the bulk
re-export in app.py) keeps working with no caller changes:

    _looks_like_email, _normalize_phone, _hash_otp, _generate_otp,
    _generate_sha_code, _check_signup_rate, _record_signup_attempt,
    _send_email_otp, _send_sms_otp, _issue_verification,
    _verification_resend_wait_seconds, _consume_verification,
    _EMAIL_RE, _USERNAME_RE, _PHONE_RE.

Late binding
------------
``_emit_event`` is late-bound from ``app`` because the event bus
is constructed during app startup; the lockout helpers fire
``auth.login.rate_limited`` events when a client trips the lock.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Optional

from fastapi import Cookie, Header, HTTPException

from auth_otp import (  # noqa: F401  (re-exports for legacy callers)
    _EMAIL_RE,
    _PHONE_RE,
    _USERNAME_RE,
    _check_signup_rate,
    _consume_verification,
    _generate_otp,
    _generate_sha_code,
    _hash_otp,
    _issue_verification,
    _looks_like_email,
    _normalize_phone,
    _record_signup_attempt,
    _send_email_otp,
    _send_sms_otp,
    _verification_resend_wait_seconds,
)
from config import (
    API_TOKEN,
    JWT_COOKIE_NAME,
    JWT_USE_HTTPONLY_COOKIE,
    LEGACY_API_TOKEN_ENABLED,
    LOGIN_LOCK_TIER0_FAILS,
    LOGIN_LOCK_TIER0_SECONDS,
    LOGIN_LOCK_TIER1_FAILS,
    LOGIN_LOCK_TIER1_SECONDS,
    LOGIN_LOCK_TIER2_FAILS,
    LOGIN_LOCK_TIER2_SECONDS,
)
from db import db_lock, get_conn
from security import Principal, decode_jwt


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
#  Principal dependency  (Phase-60 extraction from app.py)
# ────────────────────────────────────────────────────────────────────


def require_principal(
    authorization: Optional[str] = Header(default=None),
    sentinel_jwt_cookie: Optional[str] = Cookie(default=None, alias=JWT_COOKIE_NAME),
) -> Principal:
    """FastAPI dependency: resolve the calling principal from JWT or legacy bearer.

    Accepts an ``Authorization: Bearer <jwt>`` header or, when
    ``JWT_USE_HTTPONLY_COOKIE`` is set, the ``sentinel_jwt`` HttpOnly cookie.
    Optional escape hatch: if ``LEGACY_API_TOKEN_ENABLED=1`` and the bearer
    constant-time matches ``API_TOKEN``, returns a synthetic
    superadmin principal (``api-legacy``). Otherwise hands the token off
    to :func:`security.decode_jwt`.

    Raises 401 when no token is present.
    """
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    elif JWT_USE_HTTPONLY_COOKIE and sentinel_jwt_cookie:
        token = str(sentinel_jwt_cookie).strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    if LEGACY_API_TOKEN_ENABLED and API_TOKEN:
        try:
            if secrets.compare_digest(token, API_TOKEN):
                return Principal(username="api-legacy", role="superadmin", zones=["*"])
        except (TypeError, ValueError):
            pass
    return decode_jwt(token)


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
    "require_principal",
]
