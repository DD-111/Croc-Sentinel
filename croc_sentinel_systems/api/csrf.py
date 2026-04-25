"""CSRF + readiness middleware helpers (Phase-53 extraction from ``app.py``).

This module owns the **non-decorator** pieces of the CSRF and
readiness middleware chains. The two ``@app.middleware("http")``
decorators stay in ``app.py`` (they have to — FastAPI can only
register middleware on the live ``FastAPI`` instance, and the
registration order is load-bearing) but the actual logic now lives
here so the cookie/exempt/readiness rules are easy to read in one
place.

Public API
----------
* :func:`_issue_csrf_token`  — generate a fresh url-safe random token.
* :func:`_set_csrf_cookie`   — write the double-submit cookie onto a
  ``Response`` (returns the token so the caller can echo it into a
  JSON body).
* :func:`_clear_csrf_cookie` — remove the cookie on logout.
* :data:`_CSRF_EXEMPT_PREFIXES` — tuple of path prefixes that browsers
  may POST to without an X-CSRF-Token header (login/signup, ingest,
  telegram webhook, mounted SPA, etc.).
* :func:`_csrf_path_exempt`   — ``True`` when a request path falls
  inside one of those prefixes (or is a docs/openapi route).
* :func:`_readiness_public_paths` — ``True`` for paths the readiness
  guard must never 503 (health probe, mounted SPA, telegram webhook,
  legacy redirects).
* :func:`_csrf_guard_impl`     — async middleware body. Bypasses
  GET/HEAD/OPTIONS, exempt paths, ``Authorization: Bearer`` callers,
  and unauthenticated requests. Otherwise enforces the
  ``cookie == header`` double-submit using ``secrets.compare_digest``.
* :func:`_readiness_guard_impl` — async middleware body. Returns 503
  JSON for non-public paths until the deferred bootstrap finishes;
  surfaces ``api_bootstrap_error`` when set.

Wiring
------
* ``api_ready_event`` and ``api_bootstrap_error`` are mutable globals
  on ``app.py``, so the readiness guard reads them at call time via
  ``import app as _app`` (``_app.api_ready_event.is_set()`` /
  ``_app.api_bootstrap_error``). That avoids a load-order trap where
  the readiness state would otherwise be captured at module import.
* ``app.py`` re-exports every helper here under its old name and
  keeps both ``@app.middleware("http")`` decorators as thin shims
  that delegate to the ``_impl`` callables, preserving the existing
  middleware registration order (csrf -> readiness -> slow-log).
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Awaitable, Callable, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from config import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRF_PROTECTION,
    CSRF_TOKEN_TTL_S,
    DASHBOARD_PATH,
    JWT_COOKIE_NAME,
    JWT_COOKIE_SAMESITE,
    JWT_COOKIE_SECURE,
)

import app as _app

__all__ = (
    "_issue_csrf_token",
    "_set_csrf_cookie",
    "_clear_csrf_cookie",
    "_CSRF_EXEMPT_PREFIXES",
    "_csrf_path_exempt",
    "_readiness_public_paths",
    "_csrf_guard_impl",
    "_readiness_guard_impl",
)

logger = logging.getLogger(__name__)


def _issue_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _set_csrf_cookie(response: Response, token: Optional[str] = None) -> str:
    tok = (token or "").strip() or _issue_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=tok,
        max_age=int(CSRF_TOKEN_TTL_S),
        path="/",
        httponly=False,  # JS must be able to read this one.
        secure=bool(JWT_COOKIE_SECURE),
        samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
    )
    return tok


def _clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        path="/",
        secure=bool(JWT_COOKIE_SECURE),
        httponly=False,
        samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
    )


# Paths that cookie-authenticated browsers are allowed to POST/PUT/PATCH/DELETE
# without a CSRF token. Auth endpoints issue the token so they can't require
# it pre-login; device-side paths run over MQTT or per-device HMAC so the
# cookie flow doesn't apply.
#
# Names here MUST mirror the paths the SPA actually calls (see
# api/dashboard/src/console.raw.js). The previous ``/auth/register``,
# ``/auth/forgot-password``, ``/auth/account-activate``,
# ``/auth/resend-activation`` entries never matched; today the SPA hits
# ``/auth/signup/...``, ``/auth/forgot/...``, ``/auth/activate``,
# ``/auth/code/resend`` instead.
_CSRF_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/auth/login",
    "/auth/logout",
    "/auth/signup/",       # signup/start, signup/verify, signup/approve, ...
    "/auth/forgot/",       # forgot/email/start, forgot/start, ...
    "/auth/activate",      # account activation (mirror SPA route)
    "/auth/code/resend",   # OTP resend used by signup + activate
    "/ingest/",            # device ingest; device-signed, no browser cookies
    "/integrations/telegram/webhook",
    "/health",
    "/dashboard/",         # legacy SPA shell mount (pre-/console)
    "/ui/",                # legacy static UI mount
)


def _csrf_path_exempt(path: str) -> bool:
    p = str(path or "")
    if p in ("/", "/favicon.ico", "/openapi.json", "/redoc", "/docs"):
        return True
    for pref in _CSRF_EXEMPT_PREFIXES:
        if p == pref.rstrip("/") or p.startswith(pref):
            return True
    # Let the mounted /console SPA serve its static files freely.
    if p == DASHBOARD_PATH or p.startswith(DASHBOARD_PATH + "/"):
        return True
    return False


def _readiness_public_paths(path: str) -> bool:
    """Paths that must never be blocked by startup / bootstrap-failure guard (SPA shell + probes)."""
    if path == "/health" or path == "/" or path.startswith("/docs") or path in (
        "/openapi.json",
        "/redoc",
        "/favicon.ico",
    ):
        return True
    # Telegram pushes updates during boot; handler returns 503 until DB ready so Telegram retries.
    if path == "/integrations/telegram/webhook":
        return True
    # Mounted dashboard (StaticFiles at DASHBOARD_PATH) — was missing and caused 503 on entire UI.
    base = DASHBOARD_PATH
    if path == base or path.startswith(base + "/"):
        return True
    # Legacy redirects into the console
    if path.startswith("/ui"):
        return True
    if path == "/dashboard" or path.startswith("/dashboard/"):
        return True
    return False


CallNext = Callable[[Request], Awaitable[Any]]


async def _csrf_guard_impl(request: Request, call_next: CallNext):
    """Enforce double-submit CSRF token for cookie-authenticated writes."""
    if not CSRF_PROTECTION:
        return await call_next(request)
    method = str(request.method or "GET").upper()
    if method in ("GET", "HEAD", "OPTIONS"):
        return await call_next(request)
    path = request.url.path
    if _csrf_path_exempt(path):
        return await call_next(request)
    # If the caller is using Authorization: Bearer, CSRF is n/a (token is not
    # ambient-authed via the browser). Browser-based attacks can't set this
    # header cross-origin.
    auth_hdr = str(request.headers.get("authorization") or "")
    if auth_hdr.lower().startswith("bearer "):
        return await call_next(request)
    # Only enforce when the request actually carries our session cookie —
    # otherwise the request will fail auth anyway and CSRF is moot.
    jwt_ck = request.cookies.get(JWT_COOKIE_NAME)
    if not jwt_ck:
        return await call_next(request)
    sent = str(request.headers.get(CSRF_HEADER_NAME) or "").strip()
    expected = str(request.cookies.get(CSRF_COOKIE_NAME) or "").strip()
    if not sent or not expected or not secrets.compare_digest(sent, expected):
        return JSONResponse(
            status_code=403,
            content={"detail": "csrf token missing or invalid", "code": "csrf_invalid"},
        )
    return await call_next(request)


async def _readiness_guard_impl(request: Request, call_next: CallNext):
    """503 JSON API routes until deferred bootstrap finishes; never block static dashboard."""
    path = request.url.path
    if _readiness_public_paths(path):
        return await call_next(request)
    if not _app.api_ready_event.is_set():
        return JSONResponse(
            status_code=503,
            content={"detail": "service starting", "ready": False},
        )
    if _app.api_bootstrap_error:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "bootstrap failed",
                "ready": False,
                "error": _app.api_bootstrap_error,
            },
        )
    return await call_next(request)
