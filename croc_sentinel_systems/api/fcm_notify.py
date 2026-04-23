"""
Optional Firebase Cloud Messaging (HTTP v1) fan-out for mobile clients.

Uses the service-account JWT → OAuth2 access token flow (PyJWT + cryptography;
no extra google-* packages).

Env (all optional — when unset, worker is idle and enqueue is a no-op):
  FCM_PROJECT_ID              — Firebase / GCP project id (or taken from JSON "project_id")
  FCM_SERVICE_ACCOUNT_JSON     — Absolute path to the service account JSON key file

The API process calls enqueue_alarm_payloads() from emit_event; the worker
thread batches sends to FCM without blocking request handlers.

Invalid / unregistered device tokens: optional handler (registered from app.py)
removes stale rows from user_fcm_tokens so the next alarm does not retry forever.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("croc-fcm")

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"

# FCM `data` map: keep well under 4 KiB total; values must be strings.
_MAX_DATA_KEY_LEN = 64
_MAX_DATA_VAL_LEN = 1024
_MAX_DATA_KEYS = 48

_invalid_token_handler: Optional[Callable[[str], None]] = None


def set_invalid_token_handler(fn: Optional[Callable[[str], None]]) -> None:
    """Called from API bootstrap with a function that deletes one FCM token from SQLite."""
    global _invalid_token_handler
    _invalid_token_handler = fn


def _strip_bom(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("\ufeff"):
        s = s[1:].strip()
    return s.strip().strip('"').strip("'")


def _sanitize_fcm_data(raw: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, (k0, v0) in enumerate(raw.items()):
        if i >= _MAX_DATA_KEYS:
            break
        k = str(k0 or "")[:_MAX_DATA_KEY_LEN].strip()
        if not k or k == "token":
            continue
        v = str(v0 if v0 is not None else "")[:_MAX_DATA_VAL_LEN]
        out[k] = v
    return out


def _fcm_error_suggests_bad_token(code: int, body: str) -> bool:
    if code == 404:
        return True
    low = body.lower()
    if "not a valid fcm registration token" in low:
        return True
    if "unregistered" in low and "registration" in low:
        return True
    if "requested entity was not found" in low:
        return True
    try:
        j = json.loads(body)
        err = j.get("error") or {}
        status = str(err.get("status") or "").upper()
        if status in ("NOT_FOUND", "UNREGISTERED"):
            return True
        msg = str(err.get("message") or "").lower()
        if "not a valid fcm registration token" in msg:
            return True
    except Exception:
        pass
    return False


def _notify_invalid_token(token: str) -> None:
    h = _invalid_token_handler
    if not h or not token or len(token) < 32:
        return
    try:
        h(token)
    except Exception as exc:
        logger.warning("fcm invalid-token handler failed: %s", exc)


class _FcmQueue:
    def __init__(self) -> None:
        self._q: "queue.Queue[dict[str, str]]" = queue.Queue(maxsize=500)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None
        self._last_error = ""
        self._sa: Optional[dict[str, Any]] = None
        self._project_id = ""
        self._access_token = ""
        self._access_expires_ts = 0.0
        self._lock = threading.Lock()
        # Fingerprint of loaded service account file — avoids clearing OAuth on every poll.
        self._cfg_fp: Optional[tuple[str, float, str]] = None  # (path, mtime, resolved_project_id)

    def _ssl(self) -> Optional[ssl.SSLContext]:
        if self._ssl_ctx is None:
            try:
                self._ssl_ctx = ssl.create_default_context()
            except Exception as exc:
                logger.warning("fcm SSL context init failed: %s", exc)
                self._ssl_ctx = None
        return self._ssl_ctx

    def _clear_credentials(self) -> None:
        self._sa = None
        self._project_id = ""
        self._access_token = ""
        self._access_expires_ts = 0.0
        self._cfg_fp = None

    def reload_config(self) -> tuple[bool, str]:
        """Load or refresh service account JSON. Returns (ok, detail).

        Does **not** invalidate cached OAuth access tokens when the same file
        (path + mtime + project id) is already loaded — critical for throughput.
        """
        path = _strip_bom(os.getenv("FCM_SERVICE_ACCOUNT_JSON", "") or "")
        proj_env = _strip_bom(os.getenv("FCM_PROJECT_ID", "") or "")
        if not path:
            with self._lock:
                self._clear_credentials()
            return False, "FCM_SERVICE_ACCOUNT_JSON empty"
        if not os.path.isfile(path):
            with self._lock:
                self._clear_credentials()
            return False, f"FCM_SERVICE_ACCOUNT_JSON not a file: {path}"
        try:
            mtime = os.path.getmtime(path)
        except OSError as exc:
            with self._lock:
                self._clear_credentials()
            return False, f"FCM JSON stat failed: {exc}"
        try:
            with open(path, "r", encoding="utf-8") as f:
                sa = json.load(f)
        except Exception as exc:
            with self._lock:
                self._clear_credentials()
            return False, f"FCM JSON read failed: {exc}"
        if not isinstance(sa, dict) or not sa.get("private_key") or not sa.get("client_email"):
            with self._lock:
                self._clear_credentials()
            return False, "FCM JSON missing private_key or client_email"
        pid = proj_env or str(sa.get("project_id") or "").strip()
        if not pid:
            with self._lock:
                self._clear_credentials()
            return False, "FCM_PROJECT_ID empty and JSON has no project_id"

        new_fp = (path, float(mtime), pid)
        with self._lock:
            if self._sa is not None and self._cfg_fp == new_fp:
                return True, "ok"
            # New or changed credentials — must drop OAuth cache.
            self._sa = sa
            self._project_id = pid
            self._access_token = ""
            self._access_expires_ts = 0.0
            self._cfg_fp = new_fp
        return True, f"loaded project_id={pid}"

    def enabled(self) -> bool:
        with self._lock:
            return bool(self._sa and self._project_id)

    def status(self) -> dict[str, Any]:
        ok, detail = self.reload_config()
        with self._lock:
            wr = bool(self._worker and self._worker.is_alive())
            return {
                "enabled": bool(self._sa and self._project_id),
                "project_id": self._project_id or "",
                "detail": detail if not ok else "ok",
                "last_error": self._last_error,
                "queue_size": self._q.qsize(),
                "worker_running": wr,
            }

    def start(self) -> None:
        self.reload_config()
        if self._worker is not None:
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="fcm-notify", daemon=True)
        self._worker.start()
        logger.info("FCM worker started enabled=%s", self.enabled())

    def stop(self) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=2.0)
            self._worker = None

    def enqueue_alarm_payloads(self, items: list[dict[str, str]]) -> None:
        """Each item must include key \"token\" plus string FCM data fields."""
        self.reload_config()
        if not self.enabled() or not items:
            return
        dropped = 0
        for it in items:
            tok = str(it.get("token") or "").strip()
            if not tok:
                continue
            try:
                self._q.put_nowait(dict(it))
            except queue.Full:
                dropped += 1
                with self._lock:
                    self._last_error = "FCM queue full"
                logger.warning("fcm queue full, dropped %s alarm push(es)", dropped + 1)
                break

    def _access_token_refresh(self) -> tuple[bool, str]:
        with self._lock:
            sa = self._sa
            if not sa:
                return False, "no service account"
            now = time.time()
            if self._access_token and now < self._access_expires_ts - 60:
                return True, self._access_token
        try:
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
                    "aud": _TOKEN_URL,
                    "iat": iat,
                    "exp": iat + 3500,
                    "scope": _FCM_SCOPE,
                },
                private_key,
                algorithm="RS256",
                headers=headers or None,
            )
            if isinstance(assertion, bytes):
                assertion = assertion.decode("ascii")
        except Exception as exc:
            with self._lock:
                self._last_error = f"jwt: {exc}"
            return False, str(exc)

        body = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            _TOKEN_URL,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=self._ssl()) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            tok_json = json.loads(raw)
            at = str(tok_json.get("access_token") or "")
            if not at:
                with self._lock:
                    self._last_error = raw[:300]
                return False, "no access_token in response"
            exp = float(tok_json.get("expires_in") or 3600)
            with self._lock:
                self._access_token = at
                self._access_expires_ts = time.time() + max(120.0, exp)
            return True, at
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")[:400]
            with self._lock:
                self._last_error = f"token HTTP {exc.code}: {err}"
            return False, self._last_error
        except Exception as exc:
            with self._lock:
                self._last_error = f"token: {exc}"
            return False, str(exc)

    def _send_one(self, project_id: str, access_token: str, item: dict[str, str]) -> tuple[bool, str]:
        tok = str(item.get("token") or "").strip()
        if not tok:
            return False, "empty token"
        data = _sanitize_fcm_data({k: str(v) for k, v in item.items() if k != "token" and v is not None})
        msg: dict[str, Any] = {
            "message": {
                "token": tok,
                "data": data,
                "android": {"priority": "HIGH"},
                "apns": {
                    "headers": {"apns-priority": "10"},
                    "payload": {"aps": {"content-available": 1}},
                },
            }
        }
        url = f"https://fcm.googleapis.com/v1/projects/{urllib.parse.quote(project_id)}/messages:send"
        body = json.dumps(msg, ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=self._ssl()) as resp:
                resp.read().decode("utf-8", errors="replace")
            return True, "ok"
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")[:1200]
            if _fcm_error_suggests_bad_token(exc.code, err):
                _notify_invalid_token(tok)
            with self._lock:
                self._last_error = f"FCM HTTP {exc.code}: {err[:500]}"
            return False, self._last_error
        except Exception as exc:
            with self._lock:
                self._last_error = f"FCM send: {exc}"
            return False, str(exc)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.35)
            except queue.Empty:
                continue
            self.reload_config()
            if not self.enabled():
                continue
            ok_t, tok_or_err = self._access_token_refresh()
            if not ok_t:
                logger.warning("fcm token refresh failed: %s", tok_or_err)
                continue
            access_token = tok_or_err
            with self._lock:
                pid = self._project_id
            ok, detail = self._send_one(pid, access_token, item)
            if not ok:
                logger.warning("fcm send failed: %s", detail)
            time.sleep(0.05)


_fcm = _FcmQueue()


def start_fcm_worker() -> None:
    _fcm.start()


def stop_fcm_worker() -> None:
    _fcm.stop()


def fcm_status() -> dict[str, Any]:
    return dict(_fcm.status())


def enqueue_alarm_payloads(items: list[dict[str, str]]) -> None:
    _fcm.enqueue_alarm_payloads(items)
