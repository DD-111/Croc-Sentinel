"""Lightweight HTTP middleware bodies (Phase-58 extraction from ``app.py``).

Two middleware that don't fit ``csrf.py`` (which is scoped to the
CSRF + readiness pair):

* ``_security_headers_impl``     — baseline hardening headers
  (X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy and a CSP that allows Google Fonts used by
  ``index.html``). Implemented as set-default so individual route
  handlers can still override.
* ``_slow_request_log_impl``     — gated by the
  ``SLOW_REQUEST_LOG_MS`` env knob; logs a one-line warning per
  request that takes longer than the threshold. ``<= 0`` disables.

Like ``csrf.py``, the ``@app.middleware("http")`` decorators stay in
``app.py`` because FastAPI registers middleware on the live
``FastAPI`` instance and the registration order is load-bearing
(security -> csrf -> readiness -> slow-log). The decorators in
``app.py`` now delegate to these ``_impl`` callables; that keeps the
behaviour byte-identical while letting the actual logic move out.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Awaitable, Callable

from fastapi import Request

from config import SLOW_REQUEST_LOG_MS

__all__ = (
    "_security_headers_impl",
    "_slow_request_log_impl",
)

logger = logging.getLogger(__name__)


CallNext = Callable[[Request], Awaitable[Any]]


async def _security_headers_impl(request: Request, call_next: CallNext):
    """Baseline hardening for dashboard + API responses (CSP allows Google Fonts used by index.html)."""
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'",
    )
    return resp


async def _slow_request_log_impl(request: Request, call_next: CallNext):
    if SLOW_REQUEST_LOG_MS <= 0:
        return await call_next(request)
    t0 = time.perf_counter()
    resp = await call_next(request)
    dt_ms = (time.perf_counter() - t0) * 1000
    if dt_ms >= float(SLOW_REQUEST_LOG_MS):
        logger.warning("slow HTTP %s %s %.0fms", request.method, request.url.path, dt_ms)
    return resp
