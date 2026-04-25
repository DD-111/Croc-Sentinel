"""FCM HTTP-v1 OAuth2 service-account authentication (Phase-76 split
from ``fcm_notify.py``).

The previous ``fcm_notify.py`` mixed three concerns inside
``_FcmQueue``:

  1. Service-account JSON loading + project-id resolution
     (file IO, env precedence, fingerprint-based caching).
  2. Google OAuth2 access-token minting via the JWT-bearer flow
     (``urn:ietf:params:oauth:grant-type:jwt-bearer``) — RS256 JWT
     assertion + POST to ``oauth2.googleapis.com/token``.
  3. Queue / worker / FCM v1 ``messages:send`` HTTP delivery.

Phase 76 isolates concerns #1 + #2 here so ``fcm_notify.py`` can
focus on the queue + worker + transport plumbing. Everything in
this module is **pure** (no module-level state, no thread locks,
no singletons). The queue class in ``fcm_notify`` keeps its lock
around the cached access token; this module just gives it the
helpers to populate it.

Public API
----------
  ``TOKEN_URL``               — Google OAuth2 token endpoint.
  ``FCM_SCOPE``               — Required OAuth scope for FCM v1.
  ``load_service_account``    — read + validate a service-account JSON file.
  ``mint_jwt_assertion``      — build the RS256 JWT bearer assertion.
  ``exchange_assertion_for_access_token`` — POST assertion → access token.

The queue class composes these as: ``load_service_account`` once
per (path, mtime, project_id) fingerprint; then on every refresh
it calls ``mint_jwt_assertion`` followed by
``exchange_assertion_for_access_token`` and stores ``(token, expires)``
under its own lock.

The 60-second pre-expiry cushion that the queue applies to its
cached access token lives in ``fcm_notify`` because that's where
the cache lives. ``expires_in`` returned here is the raw value
from Google's ``/token`` response.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("croc-fcm.oauth")

TOKEN_URL = "https://oauth2.googleapis.com/token"
FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"


def _strip_bom(s: str) -> str:
    """Strip UTF-8 BOM and stray quotes from env values.

    Same shape as the helper in ``telegram_notify_format`` but kept
    local so each module is self-contained — there's no shared
    "string utils" module to absorb both, and a one-line copy
    isn't worth a new dependency edge.
    """
    s = (s or "").strip()
    if s.startswith("\ufeff"):
        s = s[1:].strip()
    return s.strip().strip('"').strip("'")


def load_service_account(
    path_env: str = "FCM_SERVICE_ACCOUNT_JSON",
    project_id_env: str = "FCM_PROJECT_ID",
) -> tuple[
    Optional[dict[str, Any]],
    str,
    Optional[tuple[str, float, str]],
    str,
]:
    """Read + validate the service-account JSON pointed to by env.

    Reads ``$path_env`` for the JSON file path and ``$project_id_env``
    for an optional override of the project id (the JSON's
    ``project_id`` is used when the env var is empty).

    Returns a 4-tuple:
      * sa          — parsed JSON dict, or ``None`` on any failure.
      * project_id  — resolved project id (env > JSON), or ``""``.
      * fingerprint — ``(path, mtime, project_id)`` for cache key, or
                      ``None`` when no SA was loaded.
      * detail      — human-readable status / error string suitable
                      for surfacing in ``/admin/fcm/status``.

    The SA JSON must contain ``private_key`` and ``client_email``
    or we treat it as unloaded. Caller decides whether to clear
    cached access tokens (typically: yes, if fingerprint changed).
    """
    path = _strip_bom(os.getenv(path_env, "") or "")
    proj_env = _strip_bom(os.getenv(project_id_env, "") or "")
    if not path:
        return None, "", None, f"{path_env} empty"
    if not os.path.isfile(path):
        return None, "", None, f"{path_env} not a file: {path}"
    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        return None, "", None, f"FCM JSON stat failed: {exc}"
    try:
        with open(path, "r", encoding="utf-8") as f:
            sa = json.load(f)
    except Exception as exc:
        return None, "", None, f"FCM JSON read failed: {exc}"
    if not isinstance(sa, dict) or not sa.get("private_key") or not sa.get("client_email"):
        return None, "", None, "FCM JSON missing private_key or client_email"
    pid = proj_env or str(sa.get("project_id") or "").strip()
    if not pid:
        return None, "", None, f"{project_id_env} empty and JSON has no project_id"
    fp = (path, float(mtime), pid)
    return sa, pid, fp, f"loaded project_id={pid}"


def mint_jwt_assertion(sa: dict[str, Any]) -> str:
    """Mint an RS256 JWT-bearer assertion suitable for Google's /token.

    Google requires ``iss`` and ``sub`` set to the service account's
    ``client_email``, ``aud`` set to the token URL, ``scope`` set
    to the FCM messaging scope, and ``iat``/``exp`` within ~1h.
    We use a 3500-second window (under Google's 1h cap with a
    100-second buffer).

    Raises whatever ``serialization.load_pem_private_key`` /
    ``jwt.encode`` raise on bad keys; the caller turns that into a
    user-visible last_error string.
    """
    pem = str(sa["private_key"])
    private_key = serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None,
        backend=default_backend(),
    )
    iat = int(time.time())
    kid = sa.get("private_key_id")
    headers: dict[str, str] = {}
    if kid:
        headers["kid"] = str(kid)
    assertion = jwt.encode(
        {
            "iss": sa["client_email"],
            "sub": sa["client_email"],
            "aud": TOKEN_URL,
            "iat": iat,
            "exp": iat + 3500,
            "scope": FCM_SCOPE,
        },
        private_key,
        algorithm="RS256",
        headers=headers or None,
    )
    if isinstance(assertion, bytes):
        assertion = assertion.decode("ascii")
    return assertion


def exchange_assertion_for_access_token(
    assertion: str,
    *,
    ssl_ctx: Optional[ssl.SSLContext] = None,
    timeout: float = 20.0,
) -> tuple[bool, str, float]:
    """POST the JWT assertion to Google's /token endpoint.

    On success returns ``(True, access_token, expires_in_seconds)``.
    On failure returns ``(False, error_detail, 0.0)``. The caller
    must apply its own pre-expiry buffer to ``expires_in`` before
    deciding when to refresh — this function returns the raw
    ``expires_in`` from the response body so any cushion policy
    is centralized in one place (the queue class).
    """
    body = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        tok_json = json.loads(raw)
        access_token = str(tok_json.get("access_token") or "")
        if not access_token:
            return False, raw[:300] or "no access_token in response", 0.0
        expires_in = float(tok_json.get("expires_in") or 3600)
        return True, access_token, expires_in
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")[:400]
        return False, f"token HTTP {exc.code}: {err}", 0.0
    except Exception as exc:
        return False, f"token: {exc}", 0.0


__all__ = [
    "TOKEN_URL",
    "FCM_SCOPE",
    "load_service_account",
    "mint_jwt_assertion",
    "exchange_assertion_for_access_token",
]
