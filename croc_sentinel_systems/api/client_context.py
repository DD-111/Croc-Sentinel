"""Client-context helpers (Phase-50 extraction from ``app.py``).

This module owns six small helpers that the auth / device-command
routes use to enrich every audit log row with "who is hitting me
right now":

* :func:`_telegram_enabled_safe` — defensive
  ``telegram_status()["enabled"]`` probe; returns False on any
  import / config error so the readiness probe never crashes when
  Telegram isn't configured.
* :func:`_fcm_enabled_safe` — same pattern for
  ``fcm_status()["enabled"]``.
* :func:`_fcm_delete_stale_registration_token` — drop a row from
  ``user_fcm_tokens`` when FCM HTTP v1 returns ``404`` /
  ``UNREGISTERED`` for a token (called by the FCM worker when
  Google says the token is dead).
* :func:`_client_ip` — read ``X-Forwarded-For`` first (taking the
  left-most hop), fall back to ``request.client.host``, then
  ``"?"``. Used by login lockout, password-reset rate limit and
  audit context.
* :func:`_ip_geo_text` — best-effort 30-min-cached
  ``"city, region, country"`` lookup via ``ip-api.com``. Returns
  ``""`` for private/local/unknown IPs so the audit row stays
  clean. Cache key is the raw IP string; entries expire after
  1800s.
* :func:`_client_context` — the public aggregator: ``{ ip,
  platform, device_type, client_kind, ua, geo, mac_hint }`` for
  the audit log. Detects iOS / Android / Windows / macOS / Linux
  from User-Agent, classifies mobile / tablet / desktop, and
  flags the request as ``"app"`` (native / WebView) vs ``"web"``
  by sniffing the UA for okhttp / dalvik / cfnetwork / flutter /
  reactnative. Accepts an optional ``X-Client-Mac`` /
  ``X-Device-Mac`` from upstream proxies because browsers cannot
  expose endpoint MACs reliably.

Wiring
------
* No FastAPI router; consumed via ``_app._client_context(...)``
  / ``_app._client_ip(...)`` shims in routers/auth_core.py,
  routers/auth_recovery.py, routers/device_commands.py, and
  routers/device_control.py — those keep working unchanged
  because ``app.py`` re-exports all six symbols, preserving
  identity.
* Pulls ``Request`` from FastAPI directly, ``db_lock`` /
  ``get_conn`` from :mod:`db`, and stdlib ``time`` / ``json`` /
  ``urllib.request``. The Telegram and FCM modules are imported
  *lazily* inside the ``_safe`` probes so this module is safe to
  import even when those packages aren't configured.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from typing import Any

from fastapi import Request

from db import db_lock, get_conn

__all__ = (
    "_telegram_enabled_safe",
    "_fcm_enabled_safe",
    "_fcm_delete_stale_registration_token",
    "_client_ip",
    "_ip_geo_text",
    "_client_context",
)

logger = logging.getLogger(__name__)


def _telegram_enabled_safe() -> bool:
    try:
        from telegram_notify import telegram_status

        return bool(telegram_status().get("enabled"))
    except Exception:
        return False


def _fcm_enabled_safe() -> bool:
    try:
        from fcm_notify import fcm_status

        return bool(fcm_status().get("enabled"))
    except Exception:
        return False


def _fcm_delete_stale_registration_token(token: str) -> None:
    """Remove invalid FCM tokens reported by HTTP v1 (404 / unregistered)."""
    tok = (token or "").strip()
    if not tok or len(tok) < 32:
        return
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("DELETE FROM user_fcm_tokens WHERE token = ?", (tok,))
            n = int(cur.rowcount or 0)
            conn.commit()
            conn.close()
        if n:
            logger.info("fcm removed stale registration token (rows=%s)", n)
    except Exception as exc:
        logger.warning("fcm stale token delete failed: %s", exc)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "?"


_ip_geo_cache: dict[str, tuple[float, str]] = {}


def _ip_geo_text(ip: str) -> str:
    """Best-effort geo text for a public IP. Returns '' when unavailable."""
    ip = str(ip or "").strip()
    if not ip or ip in ("?", "127.0.0.1", "::1"):
        return ""
    now = time.time()
    ent = _ip_geo_cache.get(ip)
    if ent and (now - ent[0]) < 1800:
        return ent[1]
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,query",
            headers={"User-Agent": "CrocSentinel-Geo/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        j = json.loads(raw)
        if str(j.get("status")) == "success":
            city = str(j.get("city") or "").strip()
            region = str(j.get("regionName") or "").strip()
            country = str(j.get("country") or "").strip()
            txt = ", ".join([x for x in (city, region, country) if x]) or ""
            _ip_geo_cache[ip] = (now, txt)
            return txt
    except Exception:
        pass
    _ip_geo_cache[ip] = (now, "")
    return ""


def _client_context(request: Request) -> dict[str, str]:
    """Best-effort client context for auth logs (IP + UA-derived platform).

    Browser and HTTP clients do not expose endpoint MAC reliably; if an upstream
    proxy/device gateway sets one, we accept it via x-client-mac/x-device-mac.
    """
    ip = _client_ip(request)
    ua = str(request.headers.get("user-agent") or "").strip()
    ua_l = ua.lower()
    if "iphone" in ua_l or "ipad" in ua_l or "ios" in ua_l:
        platform = "iPhone/iOS"
    elif "android" in ua_l:
        platform = "Android"
    elif "windows" in ua_l:
        platform = "Windows"
    elif "mac os" in ua_l or "macintosh" in ua_l:
        platform = "macOS"
    elif "linux" in ua_l:
        platform = "Linux"
    else:
        platform = "Unknown"
    if "mobile" in ua_l:
        device_type = "mobile"
    elif "tablet" in ua_l or "ipad" in ua_l:
        device_type = "tablet"
    else:
        device_type = "desktop"
    mac_hint = str(request.headers.get("x-client-mac") or request.headers.get("x-device-mac") or "").strip()
    client_kind = "app" if any(x in ua_l for x in ("okhttp", "dalvik", "cfnetwork", "flutter", "reactnative")) else "web"
    geo = _ip_geo_text(ip)
    out = {
        "ip": ip,
        "platform": platform,
        "device_type": device_type,
        "client_kind": client_kind,
        "ua": ua[:220],
    }
    if geo:
        out["geo"] = geo
    if mac_hint:
        out["mac_hint"] = mac_hint[:64]
    return out
