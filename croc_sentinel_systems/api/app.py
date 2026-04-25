import collections
import csv
import io
import json
import logging
import os
import queue as _stdqueue
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from contextlib import asynccontextmanager
import asyncio
import base64
import hashlib
import hmac
import re
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security import (
    JWT_EXPIRE_S,
    Principal,
    assert_min_role,
    assert_zone_for_device,
    decode_jwt,
    decrypt_blob,
    encrypt_blob,
    hash_password,
    issue_jwt,
    verify_password,
    zones_from_json,
)
from notifier import notifier, render_alarm_email, render_remote_siren_email
from email_templates import (
    render_otp_email,
    render_password_changed_email,
    render_smtp_test_email,
    render_welcome_email,
)
from tz_display import iso_timestamp_to_malaysia, malaysia_now_iso
from db import (
    CACHE_TTL_SECONDS,
    DB_PATH,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_CONNECT_TIMEOUT_S,
    _DbLockContext,
    _SqliteRWLock,
    _db_rw,
    api_cache,
    cache_get,
    cache_invalidate,
    cache_lock,
    cache_put,
    db_lock,
    db_read_lock,
    db_write_lock,
    ensure_column,
    get_conn,
    init_db_pragmas,
)

# Env-derived configuration (Phase-2 modularization). ``from config import *``
# re-binds every previously module-level constant under its original name so
# every call site below is unchanged. Kept as a star-import on purpose:
# config.py defines ``__all__`` to gate exposure, and listing 100+ names here
# would just be noise that drifts from config.py.
from config import *  # noqa: E402,F401,F403  (re-export for app.py call sites)

# Stable re-export surface for any third party that already does
# ``from app import ...`` — these names round-trip through db.py / config.py
# but their identity is unchanged.
__all_db_reexports__ = (
    "CACHE_TTL_SECONDS",
    "DB_PATH",
    "SQLITE_BUSY_TIMEOUT_MS",
    "SQLITE_CONNECT_TIMEOUT_S",
    "_DbLockContext",
    "_SqliteRWLock",
    "_db_rw",
    "api_cache",
    "cache_get",
    "cache_invalidate",
    "cache_lock",
    "cache_put",
    "db_lock",
    "db_read_lock",
    "db_write_lock",
    "ensure_column",
    "get_conn",
    "init_db_pragmas",
)


# Pure leaf helpers (Phase-4 modularization). ``utc_now_iso``,
# ``_sibling_group_norm``, ``default_policy_for_role`` now live in
# ``helpers.py`` — re-imported here so existing call sites keep working
# and ``from app import utc_now_iso`` (used by tests / migrations) is
# still legal.
from helpers import (  # noqa: E402,F401  (re-export for legacy callers)
    _sibling_group_norm,
    default_policy_for_role,
    utc_now_iso,
)


def _normalize_delete_confirm(raw: str) -> str:
    """Strip invisible chars / odd spacing so pasted confirmation still matches DELETE."""
    s = raw or ""
    s = re.sub(r"[\u200b-\u200d\ufeff]", "", s)
    return re.sub(r"\s+", " ", s).strip().upper()


def _legacy_unowned_device_scope(principal: "Principal") -> bool:
    """Whether unowned device_state rows appear in non-superadmin device queries."""
    if principal.is_superadmin():
        return False
    return bool(ALLOW_LEGACY_UNOWNED) and not TENANT_STRICT


# DB locks (`_SqliteRWLock`, `_DbLockContext`, `_db_rw`, `db_lock`,
# `db_read_lock`, `db_write_lock`) live in ``db.py`` — see import below.
mqtt_client: Optional[mqtt.Client] = None
mqtt_connected = False
mqtt_ingest_queue: _stdqueue.Queue[Optional[dict[str, Any]]] = _stdqueue.Queue(maxsize=MQTT_INGEST_QUEUE_MAX)
mqtt_worker_stop = threading.Event()
mqtt_worker_thread: Optional[threading.Thread] = None
mqtt_ingest_dropped = 0
mqtt_last_connect_at = ""
mqtt_last_disconnect_at = ""
mqtt_last_disconnect_reason = ""
alarm_event_dedup_lock = threading.Lock()
alarm_event_dedup_seen: dict[str, float] = {}
auto_reconcile_lock = threading.Lock()
auto_reconcile_queue: collections.deque[tuple[str, str]] = collections.deque()
auto_reconcile_last_seen: dict[str, float] = {}
# Deferred bootstrap: ASGI binds immediately; heavy IO runs on api-bootstrap thread.
api_ready_event = threading.Event()
api_bootstrap_error: Optional[str] = None
_bootstrap_thread: Optional[threading.Thread] = None
scheduler_stop = threading.Event()
scheduler_thread: Optional[threading.Thread] = None

log_dir = os.path.dirname(LOG_FILE_PATH)
if log_dir:
    os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("croc-api")


def _parse_chat_ids(raw: str) -> set[str]:
    out: set[str] = set()
    for part in re.split(r"[\s,;]+", (raw or "").strip()):
        p = part.strip().strip('"').strip("'")
        if p:
            out.add(p)
    return out


TELEGRAM_COMMAND_CHAT_IDS = _parse_chat_ids(TELEGRAM_COMMAND_CHAT_IDS_RAW)


def contains_insecure_marker(value: str) -> bool:
    markers = ["CHANGE_ME", "YOUR_", "your.vps.domain", "bootstrap_user", "bootstrap_pass", "mqtt_pass", "mqtt_user"]
    return any(m in value for m in markers)


def is_hex_16(value: str) -> bool:
    if len(value) != 16:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def validate_production_env() -> None:
    errors: list[str] = []
    if LEGACY_API_TOKEN_ENABLED and (
        not API_TOKEN or len(API_TOKEN) < 20 or contains_insecure_marker(API_TOKEN)
    ):
        errors.append("API_TOKEN is weak or default (LEGACY_API_TOKEN_ENABLED=1)")
    if not CMD_AUTH_KEY or not is_hex_16(CMD_AUTH_KEY):
        errors.append("CMD_AUTH_KEY must be 16 hex chars")
    if not BOOTSTRAP_BIND_KEY or len(BOOTSTRAP_BIND_KEY) < 16 or contains_insecure_marker(BOOTSTRAP_BIND_KEY):
        errors.append("BOOTSTRAP_BIND_KEY is default")
    if len(MQTT_USERNAME) < 4 or len(MQTT_PASSWORD) < 12:
        errors.append("MQTT credentials too weak")
    if contains_insecure_marker(MQTT_USERNAME) or contains_insecure_marker(MQTT_PASSWORD):
        errors.append("MQTT credentials are default/insecure")
    if contains_insecure_marker(MQTT_HOST):
        errors.append("MQTT_HOST is placeholder")
    if MAX_BULK_TARGETS < 1 or MAX_BULK_TARGETS > 5000:
        errors.append("MAX_BULK_TARGETS out of allowed range")
    if MESSAGE_RETENTION_DAYS < 1:
        errors.append("MESSAGE_RETENTION_DAYS must be >= 1")
    if ENFORCE_DEVICE_CHALLENGE and DEVICE_CHALLENGE_TTL_SECONDS < 30:
        errors.append("DEVICE_CHALLENGE_TTL_SECONDS must be >= 30 when ENFORCE_DEVICE_CHALLENGE=1")
    if ENFORCE_DEVICE_CHALLENGE and (not QR_SIGN_SECRET or len(QR_SIGN_SECRET) < 24):
        errors.append("QR_SIGN_SECRET must be set (>=24 chars) when ENFORCE_DEVICE_CHALLENGE=1")
    if BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD:
        if not JWT_SECRET or len(JWT_SECRET) < 32:
            errors.append("JWT_SECRET must be set (>=32 chars) when BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD is used")
    if errors:
        msg = "Invalid production environment: " + "; ".join(errors)
        if STRICT_STARTUP_ENV_CHECK:
            raise RuntimeError(msg)
        logger.warning("%s (startup allowed because STRICT_STARTUP_ENV_CHECK=0)", msg)


# cache_get / cache_put / cache_invalidate moved to db.py (re-exported below).
# get_conn / init_db_pragmas / ensure_column moved to db.py (re-exported below).
# init_db() (~700 lines of CREATE TABLE / CREATE INDEX / ensure_column) lives
# in schema.py; we import it lazily here so any caller that already does
# ``from app import init_db`` keeps working without a code change.
from schema import init_db  # noqa: E402,F401  (re-export for legacy callers)


def zone_sql_suffix(principal: Principal, column: str = "zone") -> tuple[str, list[Any]]:
    """Extra WHERE fragment for zone-scoped roles."""
    if principal.is_superadmin() or principal.has_all_zones():
        return "", []
    placeholders = ",".join(["?"] * len(principal.zones))
    frag = (
        f" AND ({column} IN ({placeholders}) OR IFNULL({column},'') IN ('all','')) "
    )
    return frag, list(principal.zones)


# ═══════════════════════════════════════════════
#  Event center — global real-time log bus
#
#  Two sinks for every emitted event:
#    (a) SQLite row in `events` (durable, indexed by time + owner_admin
#        + category + level + device_id)
#    (b) broadcast to every subscribed SSE queue
#
#  Memory budget: each subscriber holds up to EVENT_SUB_QUEUE_SIZE events,
#  the ring buffer holds EVENT_RING_SIZE, events are ≤ ~500 B JSON.
#  Default 2000 + 128 × 500 ≈ 33 MB worst-case — well within the 8 GB VPS.
# ═══════════════════════════════════════════════

_VALID_LEVELS = ("debug", "info", "warn", "error", "critical")
_VALID_CATEGORIES = ("auth", "alarm", "ota", "presence", "provision", "device", "system", "audit")


class _EventBus:
    def __init__(self, ring_size: int = 2000) -> None:
        self._lock = threading.Lock()
        self._ring: collections.deque[dict[str, Any]] = collections.deque(maxlen=ring_size)
        self._subs: dict[int, _EventSub] = {}
        self._next_sub_id = 1

    def subscribe(self, principal: "Principal", filters: dict[str, Any]) -> "_EventSub":
        with self._lock:
            if len(self._subs) >= EVENT_MAX_SUBSCRIBERS:
                raise HTTPException(status_code=503, detail="event subscribers at capacity")
            sid = self._next_sub_id
            self._next_sub_id += 1
            sub = _EventSub(sid, principal, filters)
            self._subs[sid] = sub
            return sub

    def unsubscribe(self, sub: "_EventSub") -> None:
        with self._lock:
            self._subs.pop(sub.id, None)

    def backlog(self, principal: "Principal", filters: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        """Return recent ring-buffer events the principal is allowed to see."""
        with self._lock:
            items = list(self._ring)
        out: list[dict[str, Any]] = []
        for ev in reversed(items):
            if not _event_visible(principal, ev):
                continue
            if not _event_matches_filters(ev, filters):
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return list(reversed(out))

    def _fanout_locked(self, ev: dict[str, Any]) -> None:
        for sub in list(self._subs.values()):
            if not _event_visible(sub.principal, ev):
                continue
            if not _event_matches_filters(ev, sub.filters):
                continue
            try:
                sub.q.put_nowait(ev)
            except _stdqueue.Full:
                try:
                    sub.q.get_nowait()
                    sub.q.put_nowait(ev)
                    sub.dropped += 1
                except Exception:
                    sub.dropped += 1

    def publish(self, ev: dict[str, Any]) -> None:
        with self._lock:
            self._ring.append(ev)
            self._fanout_locked(ev)

    def publish_from_peer(self, ev: dict[str, Any]) -> None:
        """Fan-in from another API worker (Redis). Same ring + local subscribers; no DB insert."""
        with self._lock:
            self._ring.append(ev)
            self._fanout_locked(ev)


class _EventSub:
    def __init__(self, sid: int, principal: "Principal", filters: dict[str, Any]) -> None:
        self.id = sid
        self.principal = principal
        self.filters = filters
        self.q: _stdqueue.Queue[dict[str, Any]] = _stdqueue.Queue(maxsize=EVENT_SUB_QUEUE_SIZE)
        self.dropped = 0
        self.created_at = time.time()


def _event_visible(principal: "Principal", ev: dict[str, Any]) -> bool:
    """Tenant isolation: superadmin sees everything; admin sees events where
    owner_admin == self OR actor == self; user sees only events in its
    manager_admin's tenant (and that involve it)."""
    if principal.role == "superadmin":
        return True
    owner = str(ev.get("owner_admin") or "")
    actor = str(ev.get("actor") or "")
    target = str(ev.get("target") or "")
    if _is_superadmin_username(actor):
        return False
    if principal.role == "admin":
        if owner == principal.username:
            return True
        if actor == principal.username or target == principal.username:
            return True
        # system-global events (owner_admin='') are hidden from admins by
        # default to avoid spamming every tenant with cross-cutting noise.
        return False
    # user
    if str(ev.get("category") or "") == "auth":
        return False
    my_admin = get_manager_admin(principal.username) or ""
    if my_admin and owner == my_admin and (actor == principal.username or target == principal.username or str(ev.get("level")) in ("warn", "error", "critical")):
        return True
    return False


def _event_matches_filters(ev: dict[str, Any], filters: dict[str, Any]) -> bool:
    lvl = filters.get("level")
    if lvl and ev.get("level") != lvl:
        # Allow "at least X" too if it was passed in {'min_level': ...}.
        pass
    min_lvl = filters.get("min_level")
    if min_lvl:
        try:
            if _VALID_LEVELS.index(str(ev.get("level") or "info")) < _VALID_LEVELS.index(str(min_lvl)):
                return False
        except ValueError:
            pass
    cat = filters.get("category")
    if cat and ev.get("category") != cat:
        return False
    device_id = filters.get("device_id")
    if device_id and ev.get("device_id") != device_id:
        return False
    q = filters.get("q")
    if q:
        q_lc = str(q).lower()
        blob = " ".join(str(ev.get(k) or "") for k in ("event_type", "actor", "target", "summary", "device_id")).lower()
        if q_lc not in blob:
            return False
    return True


event_bus = _EventBus(ring_size=EVENT_RING_SIZE)

# --- Multi-instance event bus (optional Redis Pub/Sub) ---
BUS_INSTANCE_ID = str(uuid.uuid4())
REDIS_URL = (os.getenv("REDIS_URL") or "").strip()
EVENT_BUS_REDIS_CHANNEL = (os.getenv("EVENT_BUS_REDIS_CHANNEL") or "sentinel:event_bus").strip() or "sentinel:event_bus"
# EVENT_WS_ENABLED moved to config.py and re-imported via `from config import *` above.
SLOW_REQUEST_LOG_MS = int(os.getenv("SLOW_REQUEST_LOG_MS", "0"))
_redis_sync_client: Optional[Any] = None
_redis_bridge_stop = threading.Event()
_redis_listener_thread: Optional[threading.Thread] = None

_superadmin_cache: set[str] = set()
_superadmin_cache_ts = 0.0

# Cached list of Telegram chat_ids bound to a superadmin dashboard user. Used
# to fan EVERY event out to superadmin Telegram (filters on env chats still
# apply normally — see telegram_notify.maybe_enqueue). Cached briefly so we
# don't hit sqlite once per event on a hot emit_event path.
_superadmin_tg_chats_cache: list[str] = []
_superadmin_tg_chats_ts: float = 0.0
_superadmin_tg_chats_ttl_s: float = 20.0


def _is_superadmin_username(username: str) -> bool:
    u = str(username or "").strip()
    if not u:
        return False
    global _superadmin_cache_ts, _superadmin_cache
    now = time.time()
    if (now - _superadmin_cache_ts) > 20.0:
        if not _db_rw.try_acquire_read():
            # Avoid lock inversion on hot paths; conservative fallback still hides default superadmin names.
            return u.lower().startswith("superadmin")
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT username FROM dashboard_users WHERE role = 'superadmin'")
            _superadmin_cache = {str(r["username"]) for r in cur.fetchall() if r["username"]}
            conn.close()
        finally:
            _db_rw.release_read()
        _superadmin_cache_ts = now
    return u in _superadmin_cache


def _superadmin_telegram_chat_ids() -> list[str]:
    """All enabled Telegram chat_ids bound to a superadmin dashboard user.

    Returns an empty list on any DB/config error; callers treat it as
    "no extras" which is safe. Result is cached for ~20s to avoid hitting
    sqlite on every emit_event.
    """
    global _superadmin_tg_chats_cache, _superadmin_tg_chats_ts
    now = time.time()
    if _superadmin_tg_chats_cache and (now - _superadmin_tg_chats_ts) < _superadmin_tg_chats_ttl_s:
        return list(_superadmin_tg_chats_cache)
    # Best-effort non-blocking lock to avoid starving the emit_event hot path.
    if not _db_rw.try_acquire_read():
        return list(_superadmin_tg_chats_cache)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT b.chat_id
            FROM telegram_chat_bindings b
            JOIN dashboard_users u ON u.username = b.username
            WHERE b.enabled = 1 AND u.role = 'superadmin'
            """
        )
        chats = [str(r["chat_id"]) for r in cur.fetchall() if r["chat_id"]]
        conn.close()
    except Exception as exc:
        logger.warning("superadmin telegram chat lookup failed: %s", exc)
        chats = list(_superadmin_tg_chats_cache)
    finally:
        _db_rw.release_read()
    _superadmin_tg_chats_cache = chats
    _superadmin_tg_chats_ts = now
    return list(chats)


def _invalidate_superadmin_telegram_chats_cache() -> None:
    """Reset the cached superadmin->chat mapping so the next emit_event
    picks up a fresh bind/unbind/toggle immediately instead of after TTL."""
    global _superadmin_tg_chats_cache, _superadmin_tg_chats_ts
    _superadmin_tg_chats_cache = []
    _superadmin_tg_chats_ts = 0.0


def _insert_event_row(ev: dict[str, Any]) -> int:
    """Append to the events table. Returns row id (0 on failure)."""
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO events
                    (ts, ts_epoch_ms, level, category, event_type, actor, target, owner_admin, device_id, summary, detail_json, ref_table, ref_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev["ts"], ev["ts_epoch_ms"], ev["level"], ev["category"], ev["event_type"],
                    ev.get("actor"), ev.get("target"), ev.get("owner_admin"), ev.get("device_id"),
                    ev.get("summary") or "", json.dumps(ev.get("detail") or {}, ensure_ascii=True),
                    ev.get("ref_table"), ev.get("ref_id"),
                ),
            )
            rid = int(cur.lastrowid or 0)
            conn.commit()
            conn.close()
        return rid
    except Exception as exc:
        logger.warning("event insert failed: %s (%s)", exc, ev.get("event_type"))
        return 0


def emit_event(
    *,
    level: str,
    category: str,
    event_type: str,
    summary: str = "",
    actor: Optional[str] = None,
    target: Optional[str] = None,
    owner_admin: Optional[str] = None,
    device_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    ref_table: Optional[str] = None,
    ref_id: Optional[int] = None,
) -> None:
    """Write one event to the DB AND broadcast it to every subscribed SSE.

    This is the single shared entry-point used by audit / alarm / ota /
    presence / provision / device / system / auth paths.
    """
    if level not in _VALID_LEVELS:
        level = "info"
    if category not in _VALID_CATEGORIES:
        category = "system"
    now = datetime.now(timezone.utc)
    ts_iso = now.isoformat()
    ts_ms = int(now.timestamp() * 1000)
    sum_line = summary or event_type
    did = (device_id or "").strip()
    if did:
        pfx = _notify_subject_prefix(did)
        if pfx and not str(sum_line).startswith(pfx):
            sum_line = f"{pfx}{sum_line}"
    ev: dict[str, Any] = {
        "ts": ts_iso,
        "ts_epoch_ms": ts_ms,
        "ts_malaysia": iso_timestamp_to_malaysia(ts_iso),
        "level": level,
        "category": category,
        "event_type": event_type,
        "actor": actor or "",
        "target": target or "",
        "owner_admin": owner_admin or "",
        "device_id": device_id or "",
        "summary": sum_line,
        "detail": detail or {},
        "ref_table": ref_table,
        "ref_id": ref_id,
    }
    ev["_actor_superadmin"] = _is_superadmin_username(str(ev.get("actor") or ""))
    rid = _insert_event_row(ev)
    ev["id"] = rid
    event_bus.publish(ev)
    _redis_event_forward(ev)
    try:
        from telegram_notify import maybe_notify_telegram

        # Superadmin bindings get the firehose; env TELEGRAM_CHAT_IDS stays
        # filtered as before (signal hygiene for operators).
        try:
            sa_chats = _superadmin_telegram_chat_ids()
        except Exception:
            sa_chats = []
        maybe_notify_telegram(ev, extra_chat_ids=sa_chats)
    except Exception as exc:
        # Avoid silent failures when Telegram module/env is misconfigured (default log level INFO).
        logger.warning("telegram_notify skipped: %s", exc)
    try:
        _maybe_dispatch_fcm_for_ev(ev)
    except Exception as exc:
        logger.warning("fcm_notify skipped: %s", exc)


def _redis_event_forward(ev: dict[str, Any]) -> None:
    if _redis_sync_client is None:
        return
    try:
        out = dict(ev)
        out["_bus_origin"] = BUS_INSTANCE_ID
        _redis_sync_client.publish(EVENT_BUS_REDIS_CHANNEL, json.dumps(out, default=str))
    except Exception as exc:
        logger.warning("redis event forward failed: %s", exc)


def _redis_listener_main() -> None:
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("redis package not installed; pip install redis")
        return
    try:
        r2 = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r2.pubsub()
        pubsub.subscribe(EVENT_BUS_REDIS_CHANNEL)
        while not _redis_bridge_stop.is_set():
            msg = pubsub.get_message(timeout=1.0)
            if not msg or msg.get("type") != "message":
                continue
            raw = msg.get("data")
            if not raw or not isinstance(raw, str):
                continue
            try:
                data = json.loads(raw)
            except Exception:
                logger.warning("redis event bus bad json")
                continue
            origin = str(data.pop("_bus_origin", "") or "")
            if origin == BUS_INSTANCE_ID:
                continue
            try:
                event_bus.publish_from_peer(data)
            except Exception:
                logger.exception("event_bus.publish_from_peer failed")
        try:
            pubsub.close()
        except Exception:
            pass
        try:
            r2.close()
        except Exception:
            pass
    except Exception:
        logger.exception("redis event bus listener exited")


def _start_event_redis_bridge() -> None:
    global _redis_sync_client, _redis_listener_thread
    if not REDIS_URL:
        logger.info("REDIS_URL unset — event bus is single-process memory only")
        return
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("REDIS_URL set but redis package missing; install redis or unset REDIS_URL")
        return
    try:
        _redis_sync_client = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_sync_client.ping()
    except Exception as exc:
        logger.error("redis connect failed (event bus): %s", exc)
        _redis_sync_client = None
        return
    _redis_bridge_stop.clear()
    _redis_listener_thread = threading.Thread(target=_redis_listener_main, name="redis-event-bus", daemon=True)
    _redis_listener_thread.start()
    logger.info(
        "event bus redis bridge ok channel=%s instance=%s",
        EVENT_BUS_REDIS_CHANNEL,
        BUS_INSTANCE_ID[:8],
    )


def _stop_event_redis_bridge() -> None:
    global _redis_sync_client, _redis_listener_thread
    _redis_bridge_stop.set()
    if _redis_listener_thread is not None:
        _redis_listener_thread.join(timeout=4.0)
        _redis_listener_thread = None
    if _redis_sync_client is not None:
        try:
            _redis_sync_client.close()
        except Exception:
            pass
        _redis_sync_client = None


def _alarm_severity_bucket(level: str) -> str:
    lv = (level or "").lower()
    if lv == "critical":
        return "HIGH"
    if lv in ("error", "warn"):
        return "MEDIUM"
    return "LOW"


def _sound_hint_from_severity(sev: str) -> str:
    if sev == "HIGH":
        return "siren"
    if sev == "MEDIUM":
        return "beep"
    return "tone"


def _trigger_method_from_ev(ev: dict[str, Any]) -> str:
    actor = str(ev.get("actor") or "")
    if actor.startswith("device:"):
        return "MQTT"
    if actor.startswith("telegram:"):
        return "Telegram"
    return "API"


def _maybe_dispatch_fcm_for_ev(ev: dict[str, Any]) -> None:
    """Tenant-owner FCM: ALARM lane for admin/user; SYSTEM (no siren) if owner row is superadmin."""
    if str(ev.get("category") or "") != "alarm":
        return
    owner = str(ev.get("owner_admin") or "").strip()
    if not owner:
        return
    device_id = str(ev.get("device_id") or "").strip()
    grp, label = ("", "")
    if device_id:
        grp, label = _device_notify_labels(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT role, IFNULL(alarm_push_style,'fullscreen') AS alarm_push_style, IFNULL(tenant,'') AS tenant "
            "FROM dashboard_users WHERE username = ?",
            (owner,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return
        role = str(row["role"] or "")
        alarm_push_style = str(row["alarm_push_style"] or "fullscreen").strip() or "fullscreen"
        system_name = str(row["tenant"] or "").strip() or owner
        cur.execute(
            "SELECT token, platform FROM user_fcm_tokens WHERE username = ? ORDER BY updated_at DESC",
            (owner,),
        )
        tok_rows = cur.fetchall()
        conn.close()
    if not tok_rows:
        return
    sev = _alarm_severity_bucket(str(ev.get("level") or "warn"))
    sound_hint = _sound_hint_from_severity(sev)
    detail = ev.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}
    triggered_by = str(
        detail.get("trigger_kind") or detail.get("client_kind") or ev.get("event_type") or "",
    ).strip()
    push_kind = "SYSTEM" if role == "superadmin" else "ALARM"
    if push_kind == "SYSTEM":
        sound_hint = "none"
        alarm_push_style = "heads_up"
    method = _trigger_method_from_ev(ev)
    lat = str(detail.get("lat") or detail.get("latitude") or "")
    lng = str(detail.get("lng") or detail.get("longitude") or "")
    loc = f"{lat},{lng}" if lat and lng else ""
    ui_mode = "heads_up" if (push_kind == "SYSTEM" or alarm_push_style == "heads_up") else "fullscreen"
    base: dict[str, str] = {
        "push_kind": push_kind,
        "severity": sev,
        "sound_hint": sound_hint,
        "alarm_ui_mode": ui_mode,
        "event_id": str(int(ev.get("id") or 0)),
        "event_type": str(ev.get("event_type") or ""),
        "ts": str(ev.get("ts_malaysia") or iso_timestamp_to_malaysia(str(ev.get("ts") or "")))[:500],
        "alarm_title": "ALARM",
        "device_id": device_id,
        "device_name": (label or device_id)[:200],
        "system_name": system_name[:200],
        "group": grp[:120],
        "triggered_by": (triggered_by or "unknown")[:120],
        "trigger_method": method[:32],
        "summary": str(ev.get("summary") or "")[:500],
        "location": loc[:120],
    }
    from fcm_notify import enqueue_alarm_payloads

    out: list[dict[str, str]] = []
    for tr in tok_rows:
        tok = str(tr["token"] or "").strip()
        if not tok:
            continue
        rowd = dict(base)
        rowd["token"] = tok
        rowd["platform"] = str(tr["platform"] or "")[:32]
        out.append(rowd)
    if out:
        enqueue_alarm_payloads(out)


# Audit log helpers (Phase-6 modularization). ``audit_event`` and the
# ``_HIGH_RISK_AUDIT_PREFIXES`` taxonomy now live in ``audit.py`` and are
# re-exported here so existing callers (``from app import audit_event``,
# of which there are dozens) keep working unchanged. The audit module
# does ``import app`` at its top and reaches ``emit_event`` /
# ``_VALID_CATEGORIES`` at call time, so the cycle resolves cleanly.
from audit import (  # noqa: E402,F401  (re-export for legacy callers)
    _HIGH_RISK_AUDIT_PREFIXES,
    _audit_action_is_high_risk,
    audit_event,
)


# Device-side identity gates (Phase-5 modularization). Both the revoke
# check and the EC/RSA + QR signature verifiers now live in
# ``device_security.py`` — re-imported here so legacy callers
# (``from app import is_device_revoked``) keep working unchanged.
from device_security import (  # noqa: E402,F401  (re-export for legacy callers)
    ensure_not_revoked,
    is_device_revoked,
    verify_device_signature,
    verify_qr_signature,
)


def get_manager_admin(username: str) -> str:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT manager_admin FROM dashboard_users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return ""
    return str(row["manager_admin"] or "")


def principal_for_username(username: str) -> Principal:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT username, role, allowed_zones_json, status
            FROM dashboard_users
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="telegram binding user not found")
    status = str(row["status"] or "active")
    if status not in ("active", ""):
        raise HTTPException(status_code=403, detail=f"user not active: {status}")
    role = str(row["role"] or "user")
    zones = zones_from_json(str(row["allowed_zones_json"] or "[]"))
    return Principal(username=str(row["username"]), role=role, zones=zones)


def get_effective_policy(principal: Principal) -> dict[str, int]:
    base = default_policy_for_role(principal.role)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk
            FROM role_policies WHERE username = ?
            """,
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return base
    out = dict(base)
    for k in out.keys():
        out[k] = int(row[k]) if k in row.keys() else out[k]
    return out


def require_capability(principal: Principal, capability: str) -> None:
    if principal.role == "superadmin":
        return
    pol = get_effective_policy(principal)
    if int(pol.get(capability, 0)) != 1:
        raise HTTPException(status_code=403, detail=f"capability denied: {capability}")


def _device_access_flags(principal: Principal, device_id: str) -> tuple[bool, bool]:
    """Return (can_view, can_operate) with strict tenant ownership isolation."""
    if principal.role == "superadmin":
        return True, True
    manager = get_manager_admin(principal.username) if principal.role == "user" else ""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        own = cur.fetchone()
        conn.close()
    owner = str(own["owner_admin"]) if own and own["owner_admin"] is not None else ""
    if principal.role == "admin":
        owner_view = bool(owner) and owner == principal.username
        if not owner and _legacy_unowned_device_scope(principal):
            owner_view = True
        owner_operate = bool(owner) and owner == principal.username
        # Strict isolation mode: admin cannot view/operate cross-tenant shared devices.
        return owner_view, owner_operate
    owner_view = bool(owner) and bool(manager) and owner == manager
    if not owner and _legacy_unowned_device_scope(principal) and bool(manager):
        owner_view = True
    owner_operate = bool(owner) and bool(manager) and owner == manager
    # Tenant user follows manager tenant only; shared ACL does not cross tenant boundary.
    return owner_view, owner_operate


def _principal_tenant_owns_device(principal: Principal, owner_admin: Optional[str]) -> bool:
    """True if principal is the registered owning tenant — not an ACL grantee on someone else's device."""
    if principal.role == "superadmin":
        return True
    o = str(owner_admin or "").strip()
    if not o:
        return _legacy_unowned_device_scope(principal)
    if principal.role == "admin":
        return o == principal.username
    mgr = get_manager_admin(principal.username) or ""
    return bool(mgr) and o == mgr


def _redact_notification_group_for_principal(
    principal: Principal, owner_admin: Optional[str], payload: dict[str, Any]
) -> None:
    """Hide owner's notification_group in JSON for ACL grantees (device-only sharing)."""
    if _principal_tenant_owns_device(principal, owner_admin):
        return
    payload["notification_group"] = ""


def assert_device_view_access(principal: Principal, device_id: str) -> None:
    can_view, _ = _device_access_flags(principal, device_id)
    if not can_view:
        raise HTTPException(status_code=403, detail="device not in your scope")


def assert_device_siren_access(principal: Principal, device_id: str) -> None:
    """Remote siren ON/OFF: same visibility as dashboard device view + role ``can_alert`` (checked on route)."""
    assert_device_view_access(principal, device_id)


def assert_device_operate_access(principal: Principal, device_id: str) -> None:
    _, can_operate = _device_access_flags(principal, device_id)
    if not can_operate:
        raise HTTPException(status_code=403, detail="device operation denied")


def assert_device_owner(principal: Principal, device_id: str) -> None:
    # Backward-compatible alias used by existing routes.
    assert_device_operate_access(principal, device_id)


def assert_device_command_actor(
    principal: Principal, device_id: str, *, check_revoked: bool = True
) -> None:
    """Publish-style device commands: at least user, policy capability, operate ACL, optional revoke."""
    assert_min_role(principal, "user")
    require_capability(principal, "can_send_command")
    if check_revoked:
        ensure_not_revoked(device_id)
    assert_device_operate_access(principal, device_id)


def owner_sql_suffix(principal: Principal, alias: str = "d") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    col = f"{alias}.owner_admin"
    leg = _legacy_unowned_device_scope(principal)
    if principal.role == "admin":
        return f" AND ({col} = ? {'OR '+col+' IS NULL' if leg else ''}) ", [principal.username]
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    return f" AND ({col} = ? {'OR '+col+' IS NULL' if leg else ''}) ", [manager]


def owner_scope_clause_for_device_state(principal: Principal, device_alias: str = "device_state") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    if principal.role == "admin":
        if _legacy_unowned_device_scope(principal):
            return (
                f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
                f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
                [principal.username],
            )
        return (
            f" AND (EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) ",
            [principal.username],
        )
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    if _legacy_unowned_device_scope(principal):
        return (
            f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
            f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
            [manager],
        )
    return (
        f" AND (EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) ",
        [manager],
    )


def parse_topic(topic: str) -> tuple[Optional[str], Optional[str]]:
    parts = topic.split("/")
    if len(parts) != 3:
        return None, None
    if parts[0] != TOPIC_ROOT:
        return None, None
    return parts[1], parts[2]


def upsert_pending_claim(payload: dict[str, Any]) -> None:
    mac_nocolon = str(payload.get("mac_nocolon", "")).upper()
    claim_nonce = str(payload.get("claim_nonce", ""))
    if len(mac_nocolon) != 12 or len(claim_nonce) != 16:
        return
    # Production mode: the device must be listed in factory_devices. This is
    # the mechanism that makes the serial number "unguessable": an attacker
    # who types a random serial on the dashboard will 404 because there is no
    # matching factory row AND because the real devices are the only ones that
    # ever get into pending_claims via the bootstrap MQTT credential.
    serial = str(payload.get("serial", "")).strip().upper()
    if ENFORCE_FACTORY_REGISTRATION:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT serial, mac_nocolon, status FROM factory_devices "
                "WHERE mac_nocolon = ? OR serial = ? LIMIT 1",
                (mac_nocolon, serial),
            )
            fdev = cur.fetchone()
            conn.close()
        if not fdev:
            logger.warning(
                "pending_claims rejected: MAC %s serial %s not in factory_devices (ENFORCE_FACTORY_REGISTRATION=1)",
                mac_nocolon, serial or "-",
            )
            return
        if str(fdev["status"] or "unclaimed") == "blocked":
            logger.warning("pending_claims rejected: serial %s is blocked", serial or fdev["serial"])
            return

    mac = str(payload.get("mac", ""))
    qr_code = str(payload.get("qr_code", ""))
    fw = str(payload.get("fw", ""))
    proposed_device_id = str(payload.get("device_id", ""))
    now = utc_now_iso()

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pending_claims (
                mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, payload_json, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_nocolon) DO UPDATE SET
                mac = excluded.mac,
                qr_code = excluded.qr_code,
                fw = excluded.fw,
                claim_nonce = excluded.claim_nonce,
                proposed_device_id = excluded.proposed_device_id,
                payload_json = excluded.payload_json,
                last_seen_at = excluded.last_seen_at
            """,
            (
                mac_nocolon,
                mac,
                qr_code,
                fw,
                claim_nonce,
                proposed_device_id,
                json.dumps(payload, ensure_ascii=True),
                now,
            ),
        )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")


def upsert_device_state(device_id: str, channel: str, payload: dict[str, Any]) -> Optional[str]:
    """Persist the latest MQTT frame for ``device_id`` and return the
    previous ``updated_at`` value (ISO string) so callers can detect
    offline→online transitions. Returns ``None`` for brand-new devices.
    """
    now = utc_now_iso()
    fw = str(payload.get("fw", ""))
    chip_target = str(payload.get("chip_target", ""))
    board_profile = str(payload.get("board_profile", ""))
    net_type = str(payload.get("net_type", ""))
    provisioned = payload.get("provisioned")
    if isinstance(provisioned, bool):
        provisioned_val = 1 if provisioned else 0
    else:
        provisioned_val = None
    zone = str(payload.get("zone", ""))
    payload_str = json.dumps(payload, ensure_ascii=True)

    prev_updated_at: Optional[str] = None

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_zone_overrides WHERE device_id = ?", (device_id,))
        zov = cur.fetchone()
        if zov and zov["zone"] is not None:
            zone = str(zov["zone"])
        cur.execute("SELECT device_id, updated_at FROM device_state WHERE device_id = ?", (device_id,))
        existing_row = cur.fetchone()
        exists = existing_row is not None
        if exists:
            prev_updated_at = str(existing_row["updated_at"] or "") or None

        if not exists:
            cur.execute(
                """
                INSERT INTO device_state (
                    device_id, fw, chip_target, board_profile, net_type, zone, provisioned, last_status_json, last_heartbeat_json,
                    last_ack_json, last_event_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)
                """,
                (device_id, fw, chip_target, board_profile, net_type, zone, provisioned_val, now),
            )

        update_fields = ["updated_at = ?"]
        update_args: list[Any] = [now]

        if fw:
            update_fields.append("fw = ?")
            update_args.append(fw)
        if chip_target:
            update_fields.append("chip_target = ?")
            update_args.append(chip_target)
        if board_profile:
            update_fields.append("board_profile = ?")
            update_args.append(board_profile)
        if net_type:
            update_fields.append("net_type = ?")
            update_args.append(net_type)
        if zone:
            update_fields.append("zone = ?")
            update_args.append(zone)
        if provisioned_val is not None:
            update_fields.append("provisioned = ?")
            update_args.append(provisioned_val)

        if channel == "status":
            update_fields.append("last_status_json = ?")
            update_args.append(payload_str)
        elif channel == "heartbeat":
            update_fields.append("last_heartbeat_json = ?")
            update_args.append(payload_str)
        elif channel == "ack":
            update_fields.append("last_ack_json = ?")
            update_args.append(payload_str)
        elif channel == "event":
            update_fields.append("last_event_json = ?")
            update_args.append(payload_str)

        update_args.append(device_id)
        cur.execute(
            f"UPDATE device_state SET {', '.join(update_fields)} WHERE device_id = ?",
            tuple(update_args),
        )
        conn.commit()
        conn.close()

    return prev_updated_at


def _extract_zone_from_device_state_row(row: Any) -> str:
    """Best-effort fallback zone from latest stored MQTT payloads."""
    if not row:
        return "all"
    for k in ("last_status_json", "last_heartbeat_json", "last_ack_json", "last_event_json"):
        raw = row[k] if k in row.keys() else None
        if not raw:
            continue
        try:
            obj = json.loads(str(raw))
        except Exception:
            continue
        z = str(obj.get("zone") or "").strip()
        if z:
            return z
    return "all"


def insert_message(topic: str, channel: str, device_id: Optional[str], payload: dict[str, Any]) -> None:
    ts_device = payload.get("ts")
    if not isinstance(ts_device, int):
        ts_device = None

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO messages (topic, channel, device_id, payload_json, ts_device, ts_received)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                topic,
                channel,
                device_id,
                json.dumps(payload, ensure_ascii=True),
                ts_device,
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()


def on_connect(client: mqtt.Client, _userdata: Any, _flags: Any, rc: int, _properties: Any = None) -> None:
    global mqtt_connected, mqtt_last_connect_at, mqtt_last_disconnect_reason
    mqtt_connected = rc == 0
    if rc == 0:
        mqtt_last_connect_at = utc_now_iso()
        mqtt_last_disconnect_reason = ""
        logger.info("MQTT connected")
        client.subscribe(TOPIC_HEARTBEAT, qos=1)
        client.subscribe(TOPIC_STATUS, qos=1)
        client.subscribe(TOPIC_EVENT, qos=1)
        client.subscribe(TOPIC_ACK, qos=1)
        client.subscribe(TOPIC_BOOTSTRAP_REGISTER, qos=1)
    else:
        logger.error("MQTT connect failed rc=%s", rc)


def on_disconnect(_client: mqtt.Client, _userdata: Any, _disconnect_flags: Any, _reason_code: Any, _properties: Any = None) -> None:
    global mqtt_connected, mqtt_last_disconnect_at, mqtt_last_disconnect_reason
    mqtt_connected = False
    mqtt_last_disconnect_at = utc_now_iso()
    mqtt_last_disconnect_reason = str(_reason_code or "")
    logger.warning("MQTT disconnected reason=%s", mqtt_last_disconnect_reason)


def _alarm_event_is_duplicate(device_id: str, payload: dict[str, Any]) -> bool:
    """Best-effort dedup for repeated `alarm.trigger` payloads in a short window."""
    win = max(0, int(ALARM_EVENT_DEDUP_WINDOW_SEC))
    if win <= 0:
        return False
    nonce = str(payload.get("nonce") or "").strip()
    ts_raw = str(payload.get("ts") or "").strip()
    trig = str(payload.get("trigger_kind") or "").strip()
    zone = str(payload.get("source_zone") or "").strip()
    # Prefer nonce when present; fall back to ts+kind+zone signature.
    sig = nonce or f"ts={ts_raw}|kind={trig}|zone={zone}"
    key = f"{device_id}|{sig}"
    now = time.time()
    cutoff = now - win
    with alarm_event_dedup_lock:
        stale = [k for k, exp in alarm_event_dedup_seen.items() if exp < cutoff]
        for k in stale:
            alarm_event_dedup_seen.pop(k, None)
        last = alarm_event_dedup_seen.get(key)
        if last and (now - last) <= win:
            return True
        alarm_event_dedup_seen[key] = now
    return False


def _is_ack_key_mismatch(payload: dict[str, Any]) -> bool:
    """Detect device-side command auth mismatch from ACK payload."""
    if bool(payload.get("ok", True)):
        return False
    detail = str(payload.get("detail") or "").strip().lower()
    if not detail:
        return False
    return detail in ("bad key", "device cmd_key unset", "key not 16 hex", "missing key")


def _enqueue_auto_reconcile(device_id: str, reason: str) -> None:
    if not AUTO_RECONCILE_ENABLED:
        return
    did = str(device_id or "").strip().upper()
    if not did:
        return
    now = time.time()
    with auto_reconcile_lock:
        last = auto_reconcile_last_seen.get(did, 0.0)
        if (now - last) < max(1, AUTO_RECONCILE_COOLDOWN_SEC):
            return
        auto_reconcile_last_seen[did] = now
        auto_reconcile_queue.append((did, str(reason or "auto")))


def _run_auto_reconcile_once(device_id: str, reason: str) -> bool:
    """Re-dispatch bootstrap assign with a fresh cmd_key for mismatched devices."""
    if not AUTO_RECONCILE_ENABLED:
        return False
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT pc.device_id, pc.mac_nocolon, IFNULL(pc.zone,'all') AS zone, IFNULL(pc.qr_code,'') AS qr_code
            FROM provisioned_credentials pc
            WHERE UPPER(pc.device_id)=UPPER(?)
            LIMIT 1
            """,
            (device_id,),
        )
        prov = cur.fetchone()
        if not prov:
            conn.close()
            return False
        did = str(prov["device_id"])
        mac = str(prov["mac_nocolon"] or "").upper()
        zone = str(prov["zone"] or "all").strip() or "all"
        qr = str(prov["qr_code"] or "")
        cur.execute(
            """
            SELECT claim_nonce, IFNULL(proposed_device_id,'') AS proposed_device_id
            FROM pending_claims
            WHERE mac_nocolon = ?
            LIMIT 1
            """,
            (mac,),
        )
        pending = cur.fetchone()
        if not pending:
            conn.close()
            emit_event(
                level="warn",
                category="provision",
                event_type="provision.auto_reconcile.skipped",
                summary=f"auto-reconcile skipped for {did} (no pending_claim)",
                actor="system",
                target=did,
                device_id=did,
                detail={"reason": reason, "mac_nocolon": mac},
            )
            return False
        claim_nonce = str(pending["claim_nonce"] or "").strip()
        if len(claim_nonce) != 16:
            conn.close()
            return False
        mqtt_u, mqtt_p, cmd_key = generate_device_credentials(did)
        cur.execute(
            """
            UPDATE provisioned_credentials
            SET mqtt_username=?, mqtt_password=?, cmd_key=?, zone=?, qr_code=?, claimed_at=?
            WHERE device_id=?
            """,
            (mqtt_u, mqtt_p, cmd_key, zone, qr, utc_now_iso(), did),
        )
        # Auto-rebind: keep pending proposed ID aligned to active provisioned device_id.
        cur.execute(
            "UPDATE pending_claims SET proposed_device_id = ? WHERE mac_nocolon = ?",
            (did, mac),
        )
        conn.commit()
        conn.close()
    publish_bootstrap_claim(
        mac_nocolon=mac,
        claim_nonce=claim_nonce,
        device_id=did,
        zone=zone,
        qr_code=qr if qr else f"CROC-{mac}",
        mqtt_username=mqtt_u,
        mqtt_password=mqtt_p,
        cmd_key=cmd_key,
    )
    audit_event("system", "provision.auto_reconcile", did, {"reason": reason, "mac_nocolon": mac})
    emit_event(
        level="warn",
        category="provision",
        event_type="provision.auto_reconcile.dispatched",
        summary=f"auto-reconcile assign dispatched for {did}",
        actor="system",
        target=did,
        device_id=did,
        detail={"reason": reason, "mac_nocolon": mac},
    )
    return True


def _auto_reconcile_tick() -> None:
    if not AUTO_RECONCILE_ENABLED:
        return
    batch: list[tuple[str, str]] = []
    with auto_reconcile_lock:
        for _ in range(min(AUTO_RECONCILE_MAX_PER_TICK, len(auto_reconcile_queue))):
            batch.append(auto_reconcile_queue.popleft())
    for did, why in batch:
        try:
            _run_auto_reconcile_once(did, why)
        except Exception as exc:
            logger.warning("auto_reconcile failed for %s: %s", did, exc)


def _prune_stale_pending_claims() -> None:
    """Remove old pending_claim rows and keep proposed_device_id aligned by MAC."""
    if PENDING_CLAIM_STALE_SECONDS <= 0:
        return
    cutoff = datetime.fromtimestamp(time.time() - PENDING_CLAIM_STALE_SECONDS, tz=timezone.utc).isoformat()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        # Rebind pending proposed_device_id to known provisioned device_id by MAC.
        cur.execute(
            """
            UPDATE pending_claims
            SET proposed_device_id = (
                SELECT pc.device_id FROM provisioned_credentials pc
                WHERE pc.mac_nocolon = pending_claims.mac_nocolon LIMIT 1
            )
            WHERE EXISTS (
                SELECT 1 FROM provisioned_credentials pc
                WHERE pc.mac_nocolon = pending_claims.mac_nocolon
            )
            """
        )
        # Clear stale rows that no longer refreshed by bootstrap.register.
        cur.execute("DELETE FROM pending_claims WHERE last_seen_at < ?", (cutoff,))
        deleted = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    if deleted:
        logger.info("pending_claims: pruned %d stale row(s)", deleted)


def _lookup_owner_admin(device_id: str) -> Optional[str]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    if row and row["owner_admin"]:
        return str(row["owner_admin"])
    return None


def _tenant_siblings(
    owner_admin: Optional[str],
    source_id: str,
    *,
    source_zone: str = "",
    source_group: str = "",
    include_source: bool = False,
) -> tuple[list[tuple[str, str]], int]:
    """Devices that receive group fan-out commands ("siblings") for this source_id.

    Selection: same ``owner_admin``, not revoked, optional matching ``source_zone``
    (unless zone is ``all``/``*``), and **normalized match** on ``notification_group``
    (NFC, collapse whitespace, case-fold) so minor string drift does not break linkage.

    Non-siblings (other tenants, empty group, revoked) are never targeted.

    ``include_source``: when False (default), the originating ``source_id`` is omitted.

    If the source group's normalized key is empty, there are **no** siblings.

    Returns ``(targets, eligible_total)``: ``targets`` is capped at
    ``ALARM_FANOUT_MAX_TARGETS``, sorted by ``device_id`` for stable ordering;
    ``eligible_total`` is how many devices matched before the cap.
    """
    zone_filter = source_zone.strip()
    norm_source = _sibling_group_norm(source_group)
    if not norm_source:
        return [], 0
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if owner_admin:
            sql = """
                SELECT d.device_id, d.zone, IFNULL(d.notification_group,'') AS notification_group
                FROM device_state d
                JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.owner_admin = ? AND r.device_id IS NULL
                  AND TRIM(IFNULL(d.notification_group,'')) != ''
            """
            args: list[Any] = [owner_admin]
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            cur.execute(sql, args)
        else:
            sql = """
                SELECT d.device_id, d.zone, IFNULL(d.notification_group,'') AS notification_group
                FROM device_state d
                LEFT JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.device_id IS NULL AND r.device_id IS NULL
                  AND TRIM(IFNULL(d.notification_group,'')) != ''
            """
            args: list[Any] = []
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            cur.execute(sql, args)
        rows = cur.fetchall()
        conn.close()
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for r in rows:
        if _sibling_group_norm(str(r["notification_group"] or "")) != norm_source:
            continue
        did = str(r["device_id"])
        if did == source_id and not include_source:
            continue
        if did in seen:
            continue
        seen.add(did)
        candidates.append((did, str(r["zone"] or "")))
    candidates.sort(key=lambda t: t[0])
    eligible_total = len(candidates)
    out = candidates[:ALARM_FANOUT_MAX_TARGETS]
    return out, eligible_total


def _recipients_for_admin(owner_admin: Optional[str]) -> list[str]:
    if not owner_admin:
        return []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT email FROM admin_alert_recipients WHERE owner_admin = ? AND enabled = 1",
            (owner_admin,),
        )
        rows = cur.fetchall()
        conn.close()
    return [str(r["email"]) for r in rows if r["email"]]


def _insert_alarm(source_id: str, owner_admin: Optional[str], zone: str,
                  triggered_by: str, payload: dict[str, Any]) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alarms
                (source_id, owner_admin, zone, triggered_by, ts_device, nonce, sig,
                 fanout_count, email_sent, email_detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?)
            """,
            (
                source_id,
                owner_admin,
                zone,
                triggered_by,
                int(payload.get("ts") or 0) or None,
                str(payload.get("nonce") or "") or None,
                str(payload.get("sig") or "") or None,
                utc_now_iso(),
            ),
        )
        alarm_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    return alarm_id


def _update_alarm(alarm_id: int, fanout_count: int, email_sent: bool, email_detail: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE alarms SET fanout_count = ?, email_sent = ?, email_detail = ? WHERE id = ?
            """,
            (fanout_count, 1 if email_sent else 0, email_detail[:400], alarm_id),
        )
        conn.commit()
        conn.close()


def _log_signal_trigger(
    kind: str,
    device_id: str,
    zone: str,
    actor_username: str,
    owner_admin: Optional[str],
    duration_ms: Optional[int] = None,
    target_count: int = 1,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO signal_triggers (
                created_at, kind, device_id, owner_admin, zone, actor_username,
                duration_ms, target_count, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                kind,
                device_id,
                owner_admin,
                zone,
                actor_username,
                duration_ms,
                target_count,
                json.dumps(detail or {}, ensure_ascii=True),
            ),
        )
        conn.commit()
        conn.close()


def _device_notify_labels(device_id: str) -> tuple[str, str]:
    """Returns (notification_group, display_label) from device_state; may be empty."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(notification_group,''), IFNULL(display_label,'') "
            "FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return "", ""
    return str(row[0] or "").strip(), str(row[1] or "").strip()


def _trigger_policy_defaults() -> dict[str, Any]:
    return {
        "panic_local_siren": True,
        # MQTT fan-out of panic_button to same-group siblings (independent of remote loud link).
        "panic_link_enabled": True,
        "panic_fanout_duration_ms": int(DEFAULT_PANIC_FANOUT_MS),
        "remote_silent_link_enabled": True,
        "remote_loud_link_enabled": True,
        "remote_loud_duration_ms": int(ALARM_FANOUT_DURATION_MS),
        "fanout_exclude_self": True,
    }


def _trigger_policy_for(owner_admin: Optional[str], scope_group: str) -> dict[str, Any]:
    base = _trigger_policy_defaults()
    if not owner_admin:
        return base
    # Match-path normalization: siblings are resolved via _sibling_group_norm
    # (case-fold + NFC + whitespace), so the policy lookup MUST use the same
    # normalization — otherwise "Warehouse" and "warehouse" branch into
    # different policies for what is the same sibling set.
    group_key = _sibling_group_norm(scope_group)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT panic_local_siren, remote_silent_link_enabled, remote_loud_link_enabled,
                   remote_loud_duration_ms, fanout_exclude_self,
                   panic_link_enabled, panic_fanout_duration_ms
            FROM trigger_policies
            WHERE owner_admin = ? AND scope_group = ?
            """,
            (owner_admin, group_key),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return base
    base["panic_local_siren"] = bool(row["panic_local_siren"])
    base["remote_silent_link_enabled"] = bool(row["remote_silent_link_enabled"])
    base["remote_loud_link_enabled"] = bool(row["remote_loud_link_enabled"])
    base["remote_loud_duration_ms"] = int(row["remote_loud_duration_ms"] or ALARM_FANOUT_DURATION_MS)
    base["fanout_exclude_self"] = bool(row["fanout_exclude_self"])
    base["panic_link_enabled"] = bool(row["panic_link_enabled"])
    base["panic_fanout_duration_ms"] = int(row["panic_fanout_duration_ms"] or DEFAULT_PANIC_FANOUT_MS)
    return base


def _notify_subject_prefix(device_id: str) -> str:
    """Prefix for emails / Telegram: '[Group] DisplayName · ' or fallback to device_id."""
    grp, name = _device_notify_labels(device_id)
    parts: list[str] = []
    if grp:
        parts.append(f"[{grp}]")
    if name:
        parts.append(name)
    if parts:
        return " ".join(parts) + " · "
    return f"{device_id} · "


def _remote_siren_notify_email(
    *,
    action: str,
    device_id: str,
    zone: str,
    actor: str,
    owner_admin: Optional[str],
    duration_ms: Optional[int],
) -> None:
    recipients = _recipients_for_admin(owner_admin) if owner_admin else []
    grp, disp = _device_notify_labels(device_id)
    if not recipients or not notifier.enabled():
        return
    subject, text, html = render_remote_siren_email(
        action=action,
        device_id=device_id,
        display_label=disp,
        notification_group=grp,
        zone=zone,
        actor=actor,
        duration_ms=duration_ms,
    )
    notifier.enqueue(recipients, subject, text, html)


# ═══════════════════════════════════════════════
#  Presence probes (12h idle → server-initiated ping)
# ═══════════════════════════════════════════════

def _insert_presence_probe(device_id: str, owner_admin: Optional[str], idle_seconds: int, outcome: str, detail: str) -> int:
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO presence_probes (device_id, owner_admin, probe_ts, idle_seconds, outcome, detail, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (device_id, owner_admin, now_iso, idle_seconds, outcome, detail, now_iso),
        )
        pid = int(cur.lastrowid or 0)
        conn.commit()
        conn.close()
    return pid


def _mark_presence_probe_acked(device_id: str) -> None:
    """Flip the most recent 'sent' probe for this device to 'acked'."""
    flipped_id = 0
    owner = None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, owner_admin FROM presence_probes
            WHERE device_id = ? AND outcome = 'sent'
            ORDER BY id DESC LIMIT 1
            """,
            (device_id,),
        )
        row = cur.fetchone()
        if row:
            flipped_id = int(row["id"])
            owner = str(row["owner_admin"] or "") or None
            cur.execute(
                "UPDATE presence_probes SET outcome='acked', updated_at=? WHERE id=?",
                (utc_now_iso(), flipped_id),
            )
            conn.commit()
        conn.close()
    if flipped_id:
        emit_event(
            level="info",
            category="presence",
            event_type="presence.probe.acked",
            summary=f"{device_id} came back",
            actor=f"device:{device_id}",
            owner_admin=owner,
            device_id=device_id,
            detail={"probe_id": flipped_id},
        )


def _find_stale_devices(idle_seconds: int, cooldown_seconds: int, limit: int = 100) -> list[tuple[str, Optional[str], int]]:
    """Return [(device_id, owner_admin, idle_seconds_actual), ...] for devices
    whose last message is older than idle_seconds, excluding devices we already
    probed within cooldown_seconds.
    """
    now_ts = int(time.time())
    idle_cutoff_iso = datetime.fromtimestamp(now_ts - idle_seconds, tz=timezone.utc).isoformat()
    cooldown_cutoff_iso = datetime.fromtimestamp(now_ts - cooldown_seconds, tz=timezone.utc).isoformat()

    results: list[tuple[str, Optional[str], int]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.device_id, d.updated_at,
                   (SELECT o.owner_admin FROM device_ownership o WHERE o.device_id = d.device_id) AS owner_admin,
                   (SELECT MAX(p.probe_ts) FROM presence_probes p WHERE p.device_id = d.device_id) AS last_probe_ts
            FROM device_state d
            WHERE d.updated_at IS NOT NULL AND d.updated_at < ?
            ORDER BY d.updated_at ASC
            LIMIT ?
            """,
            (idle_cutoff_iso, limit),
        )
        rows = cur.fetchall()
        conn.close()
    for r in rows:
        last_probe = str(r["last_probe_ts"] or "")
        if last_probe and last_probe > cooldown_cutoff_iso:
            continue
        updated = _parse_iso(str(r["updated_at"] or ""))
        idle_actual = int(time.time() - (updated.timestamp() if updated else 0))
        results.append((str(r["device_id"]), (str(r["owner_admin"]) if r["owner_admin"] else None), idle_actual))
    return results


def _send_presence_probe(device_id: str, owner_admin: Optional[str], idle_seconds: int) -> None:
    """Publish a `ping` command and log the probe."""
    try:
        publish_command(
            topic=f"{TOPIC_ROOT}/{device_id}/cmd",
            cmd="ping",
            params={},
            target_id=device_id,
            proto=CMD_PROTO,
            cmd_key=get_cmd_key_for_device(device_id),
        )
        _insert_presence_probe(device_id, owner_admin, idle_seconds, "sent", f"idle>{PRESENCE_PROBE_IDLE_SECONDS}s")
        emit_event(
            level="warn",
            category="presence",
            event_type="presence.probe.sent",
            summary=f"{device_id} silent {idle_seconds}s → ping",
            actor="system",
            target=device_id,
            owner_admin=owner_admin,
            device_id=device_id,
            detail={"idle_seconds": idle_seconds},
        )
    except Exception as exc:
        logger.warning("presence probe publish failed dev=%s err=%s", device_id, exc)
        _insert_presence_probe(device_id, owner_admin, idle_seconds, "skipped", f"publish_err:{exc}")


def _events_retention_tick() -> None:
    """Delete old rows from the `events` table according to the level-based
    retention windows. Runs every EVENT_RETENTION_SCAN_SECONDS."""
    retention_map = {
        "debug": EVENT_RETAIN_DAYS_DEBUG,
        "info": EVENT_RETAIN_DAYS_INFO,
        "warn": EVENT_RETAIN_DAYS_WARN,
        "error": EVENT_RETAIN_DAYS_ERROR,
        "critical": EVENT_RETAIN_DAYS_CRITICAL,
    }
    now_ms = int(time.time() * 1000)
    try:
        total_deleted = 0
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            for level, days in retention_map.items():
                if days <= 0:
                    continue
                cutoff = now_ms - (days * 86400 * 1000)
                cur.execute("DELETE FROM events WHERE level = ? AND ts_epoch_ms < ?", (level, cutoff))
                total_deleted += cur.rowcount or 0
            if EVENT_RETAIN_DAYS_MAX > 0:
                hard_cut = now_ms - (EVENT_RETAIN_DAYS_MAX * 86400 * 1000)
                cur.execute("DELETE FROM events WHERE ts_epoch_ms < ?", (hard_cut,))
                total_deleted += cur.rowcount or 0
            conn.commit()
            conn.close()
        if total_deleted:
            logger.info("events retention: pruned %d rows", total_deleted)
    except Exception as exc:
        logger.warning("events retention failed: %s", exc)


def _presence_probe_tick() -> None:
    """One pass of the stale-device scanner. Called from scheduler_loop."""
    try:
        stale = _find_stale_devices(PRESENCE_PROBE_IDLE_SECONDS, PRESENCE_PROBE_COOLDOWN_SECONDS, limit=200)
    except Exception as exc:
        logger.warning("presence probe scan failed: %s", exc)
        return
    for device_id, owner_admin, idle_seconds in stale:
        _send_presence_probe(device_id, owner_admin, idle_seconds)


def _expire_presence_probes_waiting_ack() -> None:
    """Mark long-running ``sent`` probes as ``timeout`` so they do not appear stuck."""
    if PRESENCE_PROBE_ACK_TIMEOUT_SEC <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=PRESENCE_PROBE_ACK_TIMEOUT_SEC)
    cutoff_iso = cutoff.isoformat()
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE presence_probes
            SET outcome='timeout', updated_at=?, detail=COALESCE(detail, '') || ' | ack_timeout'
            WHERE outcome='sent' AND probe_ts < ?
            """,
            (now_iso, cutoff_iso),
        )
        n = cur.rowcount or 0
        conn.commit()
        conn.close()
    if n:
        logger.info("presence_probes: marked %d sent row(s) as timeout (>%ss)", n, PRESENCE_PROBE_ACK_TIMEOUT_SEC)


def _fail_stale_scheduled_commands(now_ts: int) -> None:
    """Pending jobs whose execute_at is far in the past should not hang forever."""
    if SCHEDULED_CMD_STALE_PENDING_SEC <= 0:
        return
    boundary = int(now_ts) - SCHEDULED_CMD_STALE_PENDING_SEC
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE scheduled_commands
            SET status='failed', executed_at=?
            WHERE status='pending' AND execute_at_ts < ?
            """,
            (now_iso, boundary),
        )
        n = cur.rowcount or 0
        conn.commit()
        conn.close()
    if n:
        logger.warning(
            "scheduled_commands: marked %d stale pending row(s) failed (execute_at >%ss ago)",
            n,
            SCHEDULED_CMD_STALE_PENDING_SEC,
        )


# ═══════════════════════════════════════════════
#  OTA campaigns (superadmin -> admin accept -> per-device rollout)
# ═══════════════════════════════════════════════

def _append_ota_token_to_url(url: str) -> str:
    """Append ?token=OTA_TOKEN when set — nginx OTA template requires it (SECURITY.md)."""
    tok = (OTA_TOKEN or "").strip()
    if not tok:
        return url
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    if q.get("token"):
        return url
    q["token"] = tok
    new_query = urlencode(q)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _effective_ota_verify_base() -> str:
    """Prefer OTA_VERIFY_BASE_URL so the API can reach ota-nginx inside Docker."""
    return (OTA_VERIFY_BASE_URL or OTA_PUBLIC_BASE_URL).rstrip("/")


def _service_check_url_for_firmware(fname: str) -> str:
    """URL the API uses for HTTP checks (may be internal Docker base)."""
    base = _effective_ota_verify_base()
    return _append_ota_token_to_url(f"{base}/fw/{fname}")


def _public_firmware_url(fname: str) -> str:
    """Canonical URL stored in campaigns / shown to devices (no token in DB; ESP adds token)."""
    return f"{OTA_PUBLIC_BASE_URL}/fw/{fname}"


def _http_probe_ota(url: str) -> tuple[bool, str]:
    """HEAD first (with optional Range GET fallback). URL should already include token if required."""
    if not url.startswith(("http://", "https://")):
        return False, "scheme_not_http"

    def _read_response(resp: Any) -> tuple[int, str]:
        code = int(getattr(resp, "status", getattr(resp, "code", 200)))
        length = resp.headers.get("content-length", "") if hasattr(resp, "headers") else ""
        return code, length or "?"

    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code, length = _read_response(resp)
            if 200 <= code < 400:
                return True, f"HEAD http_{code} size={length}"
            return False, f"HEAD http_{code}"
    except urllib.error.HTTPError as exc:
        if int(exc.code) == 405:
            pass  # fall through to GET range
        else:
            return False, f"HEAD http_{exc.code}:{exc.reason}"
    except Exception as exc:
        return False, f"HEAD_err:{exc.__class__.__name__}:{exc}"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Range", "bytes=0-0")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code, length = _read_response(resp)
            if code in (200, 206) or (200 <= code < 400):
                return True, f"GET_range http_{code} size={length}"
            return False, f"GET_range http_{code}"
    except urllib.error.HTTPError as exc:
        return False, f"GET http_{exc.code}:{exc.reason}"
    except Exception as exc:
        return False, f"GET_err:{exc.__class__.__name__}:{exc}"


def _verify_ota_url(url: str) -> tuple[bool, str]:
    """Verify the firmware URL responds (HEAD or byte-range GET). Appends OTA_TOKEN for nginx."""
    return _http_probe_ota(_append_ota_token_to_url(url))


def _verify_firmware_file_on_service(fname: str) -> tuple[bool, str, str]:
    """Check reachability via OTA_VERIFY_BASE_URL or public base; returns (ok, detail, checked_url_masked)."""
    safe = os.path.basename(fname.strip())
    u = _service_check_url_for_firmware(safe)
    ok, detail = _http_probe_ota(u)
    masked = u
    tok = (OTA_TOKEN or "").strip()
    if tok:
        masked = u.replace(tok, "***")
    return ok, detail, masked


def _ota_campaign_targets_for_admin(admin_username: str, fw_version: str, target_url: str) -> list[dict[str, Any]]:
    """Return the list of device rows that belong to `admin_username` along
    with their current fw/url so we can roll them back if needed."""
    rows: list[dict[str, Any]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.device_id, d.fw, d.last_status_json
            FROM device_state d
            JOIN device_ownership o ON o.device_id = d.device_id
            WHERE o.owner_admin = ?
            """,
            (admin_username,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    out: list[dict[str, Any]] = []
    for r in rows:
        prev_fw = str(r.get("fw") or "")
        prev_url = ""
        raw_status = r.get("last_status_json") or ""
        if raw_status:
            try:
                js = json.loads(str(raw_status))
                prev_url = str(js.get("ota_source_url") or "")
            except Exception:
                pass
        out.append({"device_id": str(r["device_id"]), "prev_fw": prev_fw, "prev_url": prev_url})
    return out


def _dispatch_ota_to_device(campaign_id: str, device_id: str, target_fw: str, target_url: str) -> None:
    publish_command(
        topic=f"{TOPIC_ROOT}/{device_id}/cmd",
        cmd="ota",
        params={"url": target_url, "fw": target_fw, "campaign_id": campaign_id},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=get_cmd_key_for_device(device_id),
        dedupe_key=f"ota:{device_id}:{campaign_id or target_fw or target_url}",
        dedupe_ttl_s=60.0,
    )


def _start_ota_rollout_for_admin(campaign_id: str, admin_username: str) -> tuple[int, list[str]]:
    """Dispatch the OTA command to every device owned by admin_username.
    Returns (dispatched_count, failures)."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT fw_version, url FROM ota_campaigns WHERE id = ?", (campaign_id,),
        )
        camp = cur.fetchone()
        if not camp:
            conn.close()
            return 0, ["campaign_not_found"]
        target_fw = str(camp["fw_version"])
        target_url = str(camp["url"])

        cur.execute(
            "SELECT device_id, target_fw, target_url FROM ota_device_runs WHERE campaign_id = ? AND admin_username = ?",
            (campaign_id, admin_username),
        )
        device_rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    dispatched = 0
    failures: list[str] = []
    for r in device_rows:
        did = str(r["device_id"])
        try:
            _dispatch_ota_to_device(campaign_id, did, target_fw, target_url)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='dispatched', started_at=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (utc_now_iso(), utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
            dispatched += 1
        except Exception as exc:
            failures.append(f"{did}:{exc}")
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='failed', error=?, finished_at=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (str(exc)[:240], utc_now_iso(), utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
    return dispatched, failures


def _rollback_admin_devices(campaign_id: str, admin_username: str, reason: str) -> int:
    """Send OTA with the previously-known url/fw to every device that had
    already flipped to success for this campaign under this admin."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_id, prev_fw, prev_url
            FROM ota_device_runs
            WHERE campaign_id = ? AND admin_username = ? AND state = 'success'
            """,
            (campaign_id, admin_username),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    rolled = 0
    for r in rows:
        did = str(r["device_id"])
        prev_url = str(r.get("prev_url") or "")
        prev_fw = str(r.get("prev_fw") or "")
        if not prev_url:
            continue
        try:
            _dispatch_ota_to_device(f"{campaign_id}#rollback", did, prev_fw or "rollback", prev_url)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='rolled_back', error=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (reason[:240], utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
            rolled += 1
        except Exception:
            pass

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'rolled_back', ?, ?)
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='rolled_back', decided_at=excluded.decided_at, detail=excluded.detail
            """,
            (campaign_id, admin_username, utc_now_iso(), reason[:240]),
        )
        conn.commit()
        conn.close()

    try:
        audit_event("system", "ota.rollback", target=admin_username, detail={"campaign_id": campaign_id, "reason": reason, "rolled": rolled})
    except Exception:
        pass
    return rolled


def _handle_ota_result_safe(device_id: str, payload: dict[str, Any]) -> None:
    try:
        _handle_ota_result(device_id, payload)
    except Exception as exc:
        logger.exception("ota result handling failed for %s: %s", device_id, exc)


def _handle_ota_result(device_id: str, payload: dict[str, Any]) -> None:
    campaign_id = str(payload.get("campaign_id") or "").strip()
    if not campaign_id or campaign_id.endswith("#rollback"):
        return
    ok = bool(payload.get("ok"))
    detail = str(payload.get("detail") or "")[:240]
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE ota_device_runs
            SET state = ?, error = ?, finished_at = ?, updated_at = ?
            WHERE campaign_id = ? AND device_id = ?
            """,
            ("success" if ok else "failed", "" if ok else detail, now_iso, now_iso, campaign_id, device_id),
        )
        # Find admin for rollback logic.
        cur.execute(
            "SELECT admin_username FROM ota_device_runs WHERE campaign_id = ? AND device_id = ?",
            (campaign_id, device_id),
        )
        row = cur.fetchone()
        admin_username = str(row["admin_username"]) if row else ""

        # Aggregate campaign state.
        cur.execute(
            "SELECT state, COUNT(*) AS c FROM ota_device_runs WHERE campaign_id = ? GROUP BY state",
            (campaign_id,),
        )
        agg = {str(r["state"]): int(r["c"]) for r in cur.fetchall()}
        conn.commit()
        conn.close()

    emit_event(
        level="info" if ok else "error",
        category="ota",
        event_type="ota.device.result",
        summary=f"{device_id} ota {'ok' if ok else 'FAILED'} [{campaign_id}]",
        actor=f"device:{device_id}",
        target=admin_username or None,
        owner_admin=admin_username or None,
        device_id=device_id,
        detail={"campaign_id": campaign_id, "ok": ok, "detail": detail},
    )

    if not ok and OTA_AUTO_ROLLBACK_ON_FAILURE and admin_username:
        _rollback_admin_devices(campaign_id, admin_username, reason=f"device {device_id} failed: {detail}")

    # Update top-level campaign state for the dashboard.
    total = sum(agg.values())
    if total:
        failed = agg.get("failed", 0)
        success = agg.get("success", 0)
        pending = agg.get("pending", 0) + agg.get("dispatched", 0)
        rolled = agg.get("rolled_back", 0)
        if pending == 0 and failed == 0 and rolled == 0 and success == total:
            new_state = "success"
        elif pending == 0 and rolled > 0:
            new_state = "rolled_back"
        elif pending == 0 and failed > 0:
            new_state = "partial" if success > 0 else "failed"
        else:
            new_state = "running"
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE ota_campaigns SET state=?, updated_at=? WHERE id=?",
                (new_state, utc_now_iso(), campaign_id),
            )
            conn.commit()
            conn.close()


def _fan_out_alarm(device_id: str, payload: dict[str, Any]) -> None:
    """Called from the MQTT thread when an `alarm.trigger` event arrives.

    Steps:
      1. Resolve ``owner_admin`` and this device's ``notification_group`` / zone (sibling scope).
      2. Apply policy: remote silent vs loud vs panic use different linkage toggles.
      3. Build target list: **siblings only** for ``remote_loud_button``,
         ``remote_silent_button`` and ``remote_pause_button`` (never MQTT the transmitting unit).
         For ``panic_button``,
         MQTT **siblings** only; the pressing unit relies on firmware local siren.
      4. Publish per-target ``siren_on`` / ``siren_off`` / ``alarm_signal``, insert alarm row,
         queue email.
    """
    if _alarm_event_is_duplicate(device_id, payload):
        emit_event(
            level="debug",
            category="alarm",
            event_type="alarm.trigger.duplicate",
            summary=f"duplicate alarm.trigger ignored for {device_id}",
            actor=f"device:{device_id}",
            device_id=device_id,
            detail={
                "nonce": str(payload.get("nonce") or ""),
                "ts": payload.get("ts"),
                "dedup_window_sec": ALARM_EVENT_DEDUP_WINDOW_SEC,
            },
        )
        return

    source_zone = str(payload.get("source_zone") or "all")
    local_trigger = bool(payload.get("local_trigger"))
    triggered_by = str(payload.get("trigger_kind") or ("remote_button" if local_trigger else "network"))
    owner_admin = _lookup_owner_admin(device_id)
    source_group, _source_label = _device_notify_labels(device_id)
    policy = _trigger_policy_for(owner_admin, source_group)

    alarm_id = _insert_alarm(device_id, owner_admin, source_zone, triggered_by, payload)
    emit_event(
        level="warn",
        category="alarm",
        event_type="alarm.trigger",
        summary=f"alarm from {device_id} ({triggered_by})",
        actor=f"device:{device_id}",
        target=owner_admin or "",
        owner_admin=owner_admin,
        device_id=device_id,
        detail={"alarm_id": alarm_id, "zone": source_zone, "trigger_kind": triggered_by},
        ref_table="alarms",
        ref_id=alarm_id,
    )

    should_fanout = triggered_by in (
        "remote_button",
        "remote_loud_button",
        "remote_silent_button",
        "remote_pause_button",
        "network",
        "group_link",
        "panic_button",
    )
    if triggered_by == "remote_silent_button" and not bool(policy.get("remote_silent_link_enabled", True)):
        should_fanout = False
    # Remote "loud" pathways only (not panic — panic has its own toggle).
    if triggered_by in ("remote_button", "remote_loud_button", "remote_pause_button", "network", "group_link") and not bool(
        policy.get("remote_loud_link_enabled", True)
    ):
        should_fanout = False
    if triggered_by == "panic_button" and not bool(policy.get("panic_link_enabled", True)):
        should_fanout = False

    # Who receives MQTT commands: siblings in the same tenant + notification_group (+ zone).
    # Remote #1 silent / #2 loud: never command the originating device.
    # Panic: MQTT to siblings only; originator sounds via firmware TRIGGER_SELF_SIREN.
    include_source = not bool(policy.get("fanout_exclude_self", True))
    if triggered_by in ("remote_button", "remote_loud_button", "remote_silent_button", "remote_pause_button", "panic_button"):
        include_source = False

    targets, eligible_total = (
        _tenant_siblings(
            owner_admin,
            device_id,
            source_zone=source_zone,
            source_group=source_group,
            include_source=include_source,
        )
        if should_fanout
        else ([], 0)
    )
    fanout_capped = bool(should_fanout and eligible_total > len(targets))
    sent = 0
    failures: list[str] = []
    loud_ms = int(policy.get("remote_loud_duration_ms", ALARM_FANOUT_DURATION_MS))
    panic_ms = int(policy.get("panic_fanout_duration_ms", DEFAULT_PANIC_FANOUT_MS))
    default_cmd_key = str(CMD_AUTH_KEY or "").strip().upper()
    cmd_key_map = get_cmd_keys_for_devices([did for did, _ in targets]) if targets else {}

    def _fanout_publish_one(did: str, ckey: str) -> None:
        if triggered_by == "remote_silent_button":
            cmd, params = "alarm_signal", {"kind": "silent"}
        elif triggered_by == "remote_pause_button":
            cmd, params = "siren_off", {}
        else:
            dur_ms = panic_ms if triggered_by == "panic_button" else loud_ms
            cmd, params = "siren_on", {"duration_ms": dur_ms}
        # wait_publish=False: fan-out runs in a thread pool; we don't want each
        # target to block waiting for paho drain, otherwise a 50-device group can
        # stall the MQTT ingest thread for tens of seconds and back up the queue.
        publish_command(
            topic=f"{TOPIC_ROOT}/{did}/cmd",
            cmd=cmd,
            params=params,
            target_id=did,
            proto=CMD_PROTO,
            cmd_key=ckey,
            wait_publish=False,
        )

    if should_fanout and targets:
        sent_lock = threading.Lock()
        fail_lock = threading.Lock()

        # Bounded concurrency: on a 200-device group we do not want 200 threads.
        pool = min(max(4, FANOUT_WORKER_POOL_SIZE), max(1, len(targets)))
        sem = threading.BoundedSemaphore(pool)

        def _worker(did: str) -> None:
            nonlocal sent
            ck = cmd_key_map.get(did.strip().upper(), default_cmd_key)
            with sem:
                try:
                    _fanout_publish_one(did, ck)
                    with sent_lock:
                        sent += 1
                except Exception as exc:
                    with fail_lock:
                        failures.append(f"{did}:{exc}")

        workers = [
            threading.Thread(target=_worker, args=(did,), name=f"fanout-{did}", daemon=True)
            for did, _z in targets
        ]
        for t in workers:
            t.start()
        # Cap wall-clock on the ingest thread: even in a 100-device group, we should
        # return in ~1.5s. QoS 1 retries remain paho's responsibility.
        deadline = time.time() + float(FANOUT_WALL_CLOCK_MAX_S)
        for t in workers:
            left = max(0.05, deadline - time.time())
            t.join(timeout=left)
        if failures:
            retry_ids = [x.split(":", 1)[0] for x in failures if ":" in x and x.split(":", 1)[0]]
            if retry_ids:
                time.sleep(0.3)
                failures.clear()
                retry_threads = [
                    threading.Thread(target=_worker, args=(did,), name=f"fanout-retry-{did}", daemon=True)
                    for did in retry_ids
                ]
                for t in retry_threads:
                    t.start()
                retry_deadline = time.time() + float(FANOUT_WALL_CLOCK_MAX_S)
                for t in retry_threads:
                    left = max(0.05, retry_deadline - time.time())
                    t.join(timeout=left)

    email_sent = False
    email_detail = ""
    try:
        recipients = _recipients_for_admin(owner_admin)
        if recipients and notifier.enabled():
            g, n = _device_notify_labels(device_id)
            subject, text, html = render_alarm_email({
                "source_id": device_id,
                "zone": source_zone,
                "triggered_by": triggered_by,
                "created_at": utc_now_iso(),
                "fanout_count": sent,
                "notification_group": g,
                "display_label": n,
                "notify_prefix": _notify_subject_prefix(device_id),
            })
            email_sent = notifier.enqueue(recipients, subject, text, html)
            email_detail = f"queued={email_sent} to={len(recipients)}"
        elif recipients:
            email_detail = "smtp_disabled"
        else:
            email_detail = "no_recipients"
    except Exception as exc:
        email_detail = f"queue_err:{exc}"

    _update_alarm(alarm_id, sent, email_sent, email_detail)

    try:
        audit_event(
            f"device:{device_id}",
            "alarm.fanout",
            target=owner_admin or "(unowned)",
            detail={
                "alarm_id": alarm_id,
                "triggered_by": triggered_by,
                "fanout_count": sent,
                "target_total": len(targets),
                "eligible_total": eligible_total,
                "fanout_capped": fanout_capped,
                "fanout_max": ALARM_FANOUT_MAX_TARGETS,
                "failures": failures[:5],
                "email": email_detail,
            },
        )
    except Exception:
        pass


def _dispatch_mqtt_payload(topic: str, payload: dict[str, Any]) -> None:
    """All MQTT business logic: runs on the mqtt-ingest worker thread only."""
    if topic == TOPIC_BOOTSTRAP_REGISTER:
        upsert_pending_claim(payload)
        insert_message(topic, "bootstrap_register", str(payload.get("device_id", "")), payload)
        did_try = str(payload.get("device_id", ""))
        emit_event(
            level="info",
            category="provision",
            event_type="provision.bootstrap_register",
            summary=f"{did_try} bootstrap register",
            actor=f"device:{did_try}",
            device_id=did_try,
            detail={"serial": payload.get("serial"), "mac": payload.get("mac"), "qr_code": payload.get("qr_code")},
        )
        return

    device_id, channel = parse_topic(topic)
    if not channel:
        return

    insert_message(topic, channel, device_id, payload)
    prev_updated_at: Optional[str] = None
    if device_id:
        prev_updated_at = upsert_device_state(device_id, channel, payload)

    # Offline→online replay: if the device was silent for longer than
    # CMD_QUEUE_REPLAY_GAP_S and we have unacked queue entries, push them
    # again over MQTT. Runs inline on the ingest worker because it is a
    # cheap SELECT + a few publishes; truly heavy cases are debounced.
    if device_id and channel in ("heartbeat", "status") and prev_updated_at:
        try:
            _maybe_replay_queue_on_reconnect(device_id, prev_updated_at)
        except Exception:
            logger.debug("cmd_queue replay failed for %s", device_id, exc_info=True)

    # Flow EVERY device channel into the unified event stream (at debug
    # level so subscribers can opt in). This gives the superadmin a true
    # firehose while staying out of the tenant admin's default view.
    if device_id and channel in ("heartbeat", "status", "ack", "event"):
        try:
            owner = _lookup_owner_admin(device_id) if "lookup_owner" not in payload else None
        except Exception:
            owner = None
        ev_level = "debug"
        ev_type = f"device.{channel}"
        ev_sum = f"{device_id} {channel}"
        # Elevate important ones.
        if channel == "event":
            p_type = str(payload.get("type") or "")
            if p_type:
                ev_type = f"device.event.{p_type}"
                ev_sum = f"{device_id} event {p_type}"
                if p_type.startswith("alarm."):
                    ev_level = "warn"
        elif channel == "ack":
            if str(payload.get("type") or "") == "ota.result":
                ev_level = "warn" if not bool(payload.get("ok")) else "info"
                ev_type = "device.ota.result"
                ev_sum = f"{device_id} ota {'ok' if payload.get('ok') else 'FAIL'}"
        emit_event(
            level=ev_level,
            category="device",
            event_type=ev_type,
            summary=ev_sum,
            actor=f"device:{device_id}",
            owner_admin=owner,
            device_id=device_id,
            detail={"topic": topic, **{k: v for k, v in payload.items() if k in ("type", "ok", "detail", "campaign_id", "rssi", "vbat", "net_type", "fw", "throughput_rx_bps", "throughput_tx_bps")}},
        )

    if channel == "event" and device_id and str(payload.get("type") or "") == "alarm.trigger":
        # Dispatch fan-out to a worker thread so the MQTT ingest queue keeps draining.
        t = threading.Thread(
            target=_fan_out_alarm_safe,
            name=f"alarm-fanout-{device_id}",
            args=(device_id, payload),
            daemon=True,
        )
        t.start()

    if channel == "ack" and device_id and str(payload.get("type") or "") == "ota.result":
        t = threading.Thread(
            target=_handle_ota_result_safe,
            name=f"ota-result-{device_id}",
            args=(device_id, payload),
            daemon=True,
        )
        t.start()

    if channel == "ack" and device_id and _is_ack_key_mismatch(payload):
        _enqueue_auto_reconcile(device_id, "ack_key_mismatch")

    # Settle the persistent cmd_queue entry for this cmd_id regardless of
    # which channel actually delivered the command (MQTT primary vs HTTP
    # pull fallback). Missing cmd_id is fine — older payloads or raw
    # publishes never hit the queue.
    if channel == "ack" and device_id:
        cid = str(payload.get("cmd_id") or "").strip()
        if cid:
            ok = bool(payload.get("ok", True))
            detail = str(payload.get("detail") or payload.get("error") or "")
            try:
                _cmd_queue_mark_acked(cid, ok=ok, detail=detail)
            except Exception:
                logger.debug("cmd_queue ack settle failed dev=%s cid=%s", device_id, cid, exc_info=True)

    if channel in ("heartbeat", "status", "ack", "event") and device_id:
        try:
            _mark_presence_probe_acked(device_id)
        except Exception:
            logger.debug("presence probe ack update failed for %s", device_id, exc_info=True)


def _mqtt_ingest_worker() -> None:
    """Drain mqtt_ingest_queue: JSON parse + _dispatch_mqtt_payload (DB, emit_event, side threads)."""
    while True:
        try:
            item = mqtt_ingest_queue.get(timeout=0.3)
        except _stdqueue.Empty:
            if mqtt_worker_stop.is_set():
                break
            continue
        if not item:
            continue
        topic = str(item.get("topic") or "")
        raw = item.get("payload")
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                continue
        except Exception:
            continue
        try:
            _dispatch_mqtt_payload(topic, payload)
        except Exception as exc:
            logger.exception("mqtt ingest worker failed topic=%s: %s", topic, exc)


def on_message(_client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
    """Paho callback: enqueue only — never DB, JSON business logic, or emit_event here."""
    global mqtt_ingest_dropped
    try:
        raw = msg.payload.decode("utf-8", errors="replace")
    except Exception:
        return
    try:
        mqtt_ingest_queue.put_nowait({"topic": msg.topic, "payload": raw, "ts": time.time()})
    except _stdqueue.Full:
        mqtt_ingest_dropped += 1
        if mqtt_ingest_dropped == 1 or mqtt_ingest_dropped % 250 == 0:
            logger.warning(
                "mqtt ingest queue full (max=%s); dropped=%s last_topic=%r",
                MQTT_INGEST_QUEUE_MAX,
                mqtt_ingest_dropped,
                getattr(msg, "topic", ""),
            )


def _fan_out_alarm_safe(device_id: str, payload: dict[str, Any]) -> None:
    try:
        _fan_out_alarm(device_id, payload)
    except Exception as exc:
        logger.exception("alarm fan-out failed for %s: %s", device_id, exc)


def start_mqtt_loop() -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if MQTT_USE_TLS:
        if not MQTT_CLIENT_CA or not os.path.isfile(MQTT_CLIENT_CA):
            logging.getLogger(__name__).error(
                "MQTT_USE_TLS=1 but CA file missing at MQTT_CLIENT_CA=%r "
                "(mount host certs/ca.crt into the api container; see docker-compose.yml).",
                MQTT_CLIENT_CA,
            )
        else:
            ctx = ssl.create_default_context(cafile=MQTT_CLIENT_CA)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if not MQTT_TLS_VERIFY_HOSTNAME:
                ctx.check_hostname = False
            client.tls_set_context(ctx)
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=60)
    client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
    client.loop_start()
    return client


def stop_mqtt_loop(client: mqtt.Client) -> None:
    try:
        client.loop_stop()
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def require_principal(
    authorization: Optional[str] = Header(default=None),
    sentinel_jwt_cookie: Optional[str] = Cookie(default=None, alias=JWT_COOKIE_NAME),
) -> Principal:
    """
    JWT: Authorization Bearer, or HttpOnly cookie (when JWT_USE_HTTPONLY_COOKIE).
    Optional legacy API_TOKEN superadmin bearer when LEGACY_API_TOKEN_ENABLED=1.
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


class CommandRequest(BaseModel):
    cmd: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    target_id: Optional[str] = None
    proto: int = Field(default=CMD_PROTO, ge=1, le=16)


class BroadcastCommandRequest(BaseModel):
    cmd: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    target_id: str = Field(default="all")
    proto: int = Field(default=CMD_PROTO, ge=1, le=16)


class ClaimDeviceRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=3, max_length=23)
    zone: str = Field(default="all", min_length=1, max_length=31)
    qr_code: Optional[str] = Field(default=None, max_length=47)

# (ScheduleRebootRequest moved to routers/device_control.py — see the
# corresponding `from routers.device_control import ...` block below.)

class BulkAlertRequest(BaseModel):
    action: str = Field(pattern="^(on|off)$")
    duration_ms: int = Field(default=int(DEFAULT_REMOTE_FANOUT_MS), ge=500, le=300000)
    device_ids: list[str] = Field(default_factory=list)

# (4 schemas + _WIFI_DEFERRED_CMDS moved to routers/device_provision.py — see
# the corresponding `from routers.device_provision import ...` block below.)

class DeviceChallengeRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=8, max_length=40)
    public_key_pem: str = Field(min_length=64, max_length=4096)
    attestation: Optional[dict[str, Any]] = None


class DeviceChallengeVerifyRequest(BaseModel):
    challenge_id: int = Field(ge=1)
    signature_b64: str = Field(min_length=32, max_length=1024)


class DeviceRevokeRequest(BaseModel):
    reason: str = Field(default="manual revoke", min_length=3, max_length=200)


class DeviceDeleteRequest(BaseModel):
    confirm_text: str = Field(min_length=3, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)

# (6 self-service schemas + _validate_avatar_url moved to routers/auth_self.py — see
# the corresponding `from routers.auth_self import ...` block below.)

# (3 user-CRUD schemas moved to routers/auth_users.py — see the corresponding
# `from routers.auth_users import ...` block below.)

def _blocking_api_bootstrap_inner() -> None:
    """Runs on thread api-bootstrap: DB init, notifier, MQTT ingest, scheduler."""
    global mqtt_client, scheduler_thread, mqtt_worker_thread, mqtt_ingest_dropped
    validate_production_env()
    init_db()
    try:
        _ota_enforce_max_stored_bins()
    except Exception:
        logger.exception("OTA firmware retention prune at startup failed")
    notifier.start()
    try:
        from telegram_notify import start_telegram_worker

        start_telegram_worker()
    except Exception:
        logger.exception("Telegram worker failed to start (check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS)")
    try:
        from fcm_notify import set_invalid_token_handler, start_fcm_worker

        start_fcm_worker()
        set_invalid_token_handler(_fcm_delete_stale_registration_token)
    except Exception:
        logger.exception("FCM worker failed to start (check FCM_SERVICE_ACCOUNT_JSON / FCM_PROJECT_ID)")
    mqtt_worker_stop.clear()
    mqtt_ingest_dropped = 0
    mqtt_worker_thread = threading.Thread(target=_mqtt_ingest_worker, name="mqtt-ingest", daemon=True)
    mqtt_worker_thread.start()
    mqtt_client = start_mqtt_loop()
    scheduler_stop.clear()
    scheduler_thread = threading.Thread(target=scheduler_loop, name="cmd-scheduler", daemon=True)
    scheduler_thread.start()
    _start_event_redis_bridge()
    logger.info(
        "API started mqtt_host=%s mqtt_port=%s mqtt_tls=%s "
        "mqtt_tls_verify_hostname=%s db=%s notifier_enabled=%s telegram=%s fcm=%s",
        MQTT_HOST,
        MQTT_PORT,
        MQTT_USE_TLS,
        MQTT_TLS_VERIFY_HOSTNAME,
        DB_PATH,
        notifier.enabled(),
        _telegram_enabled_safe(),
        _fcm_enabled_safe(),
    )


def _shutdown_api() -> None:
    global mqtt_client, scheduler_thread, mqtt_worker_thread
    _stop_event_redis_bridge()
    scheduler_stop.set()
    if scheduler_thread is not None:
        scheduler_thread.join(timeout=2.0)
        scheduler_thread = None
    if mqtt_client is not None:
        stop_mqtt_loop(mqtt_client)
        mqtt_client = None
    mqtt_worker_stop.set()
    if mqtt_worker_thread is not None:
        mqtt_worker_thread.join(timeout=10.0)
        mqtt_worker_thread = None
    try:
        from telegram_notify import stop_telegram_worker

        stop_telegram_worker()
    except Exception:
        pass
    try:
        from fcm_notify import stop_fcm_worker

        stop_fcm_worker()
    except Exception:
        pass
    notifier.stop()


@asynccontextmanager
async def _app_lifespan(app: FastAPI):
    """Bind HTTP immediately; heavy sync startup runs on api-bootstrap thread."""
    global _bootstrap_thread, api_bootstrap_error
    api_ready_event.clear()
    api_bootstrap_error = None

    def _run_bootstrap() -> None:
        global api_bootstrap_error
        try:
            _blocking_api_bootstrap_inner()
        except BaseException as exc:
            api_bootstrap_error = repr(exc)
            logger.exception("API bootstrap failed")
        finally:
            api_ready_event.set()

    _bootstrap_thread = threading.Thread(target=_run_bootstrap, name="api-bootstrap", daemon=True)
    _bootstrap_thread.start()
    yield
    if _bootstrap_thread is not None and _bootstrap_thread.is_alive():
        _bootstrap_thread.join(timeout=2.0)
    _shutdown_api()


app = FastAPI(title="Croc Sentinel API", version="1.1.0", lifespan=_app_lifespan)
app.add_middleware(GZipMiddleware, minimum_size=700)


@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
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


# ----------------------------------------------------------------- CSRF guard
# Double-submit token (cookie + header). Written to the client alongside the
# JWT cookie at login; every state-changing request must echo the value via
# the CSRF_HEADER_NAME header. Because the cookie is NOT HttpOnly, first-party
# JS can read it; a cross-origin attacker can't — that's the security property.

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
# without a CSRF token. Auth endpoints issue the token so they can't require it
# pre-login; device-side paths run over MQTT or per-device HMAC so the cookie
# flow doesn't apply.
#
# Names here MUST mirror the paths the SPA actually calls (see
# api/dashboard/src/console.raw.js). The previous `/auth/register`,
# `/auth/forgot-password`, `/auth/account-activate`, `/auth/resend-activation`
# entries never matched; today the SPA hits `/auth/signup/...`,
# `/auth/forgot/...`, `/auth/activate`, `/auth/code/resend` instead.
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


@app.middleware("http")
async def _csrf_guard(request: Request, call_next):
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

_dash_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")
if os.path.isdir(_dash_dir):
    app.mount(DASHBOARD_PATH, StaticFiles(directory=_dash_dir, html=True), name="dashboard")


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


@app.middleware("http")
async def _readiness_guard(request: Request, call_next):
    """503 JSON API routes until deferred bootstrap finishes; never block static dashboard."""
    path = request.url.path
    if _readiness_public_paths(path):
        return await call_next(request)
    if not api_ready_event.is_set():
        return JSONResponse(
            status_code=503,
            content={"detail": "service starting", "ready": False},
        )
    if api_bootstrap_error:
        return JSONResponse(
            status_code=503,
            content={"detail": "bootstrap failed", "ready": False, "error": api_bootstrap_error},
        )
    return await call_next(request)


@app.middleware("http")
async def _slow_request_log_middleware(request: Request, call_next):
    if SLOW_REQUEST_LOG_MS <= 0:
        return await call_next(request)
    t0 = time.perf_counter()
    resp = await call_next(request)
    dt_ms = (time.perf_counter() - t0) * 1000
    if dt_ms >= float(SLOW_REQUEST_LOG_MS):
        logger.warning("slow HTTP %s %s %.0fms", request.method, request.url.path, dt_ms)
    return resp


@app.get("/", include_in_schema=False)
def _root_redirect() -> RedirectResponse:
    return RedirectResponse(url=DASHBOARD_PATH + "/", status_code=302)


@app.get("/ui", include_in_schema=False)
@app.get("/ui/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
def _legacy_ui_redirect() -> RedirectResponse:
    return RedirectResponse(url=DASHBOARD_PATH + "/", status_code=301)


@app.get("/ui/{path:path}", include_in_schema=False)
def _legacy_ui_deep_redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=f"{DASHBOARD_PATH}/{path}", status_code=301)


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
    emit_event(
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

# (3 signup/verify schemas moved to routers/auth_recovery.py — see the
# corresponding `from routers.auth_recovery import ...` block below.)



# =====================================================================
#  Auth signup + password recovery (offline RSA blob + email-OTP path)
# =====================================================================

# Phase-17 modularization: 14 routes + 7 schemas + 6 password-recovery
# helpers now live in routers/auth_recovery.py. The scheduler loop in
# this file calls _prune_password_reset_tokens via the re-export below.
from routers.auth_recovery import (  # noqa: E402,F401
    router as _auth_recovery_router,
    _prune_password_reset_tokens,
)

app.include_router(_auth_recovery_router)

@app.post("/auth/login")
def auth_login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    ctx = _client_context(request)
    ip = ctx["ip"]
    _check_login_ip_lockout(ip, body.username)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM dashboard_users WHERE username = ?", (body.username,))
        row = cur.fetchone()
        conn.close()
    if not row or not verify_password(body.password, str(row["password_hash"])):
        _record_login_failure(ip, body.username)
        fail_detail = dict(ctx)
        fail_detail["owner_admin"] = ""
        fail_detail["login_user"] = body.username
        audit_event(f"ip:{ip}", "auth.login.fail", body.username, fail_detail)
        raise HTTPException(status_code=401, detail="invalid credentials")
    # Status gate: pending / awaiting_approval / disabled cannot log in.
    status = str(row["status"] if "status" in row.keys() else "active") or "active"
    role = str(row["role"])
    owner_admin = str(row["username"]) if role == "admin" else str(row["manager_admin"] or "")
    if status == "disabled":
        dis_detail = dict(ctx)
        dis_detail["owner_admin"] = owner_admin
        dis_detail["login_user"] = str(row["username"])
        audit_event(f"ip:{ip}", "auth.login.disabled", str(row["username"]), dis_detail)
        raise HTTPException(status_code=403, detail="account disabled")
    if status == "pending":
        raise HTTPException(status_code=403, detail="account not activated yet — please enter the verification code sent to your email")
    if status == "awaiting_approval":
        raise HTTPException(status_code=403, detail="account awaiting superadmin approval")
    _clear_login_failures(body.username)
    _clear_login_ip_state(ip)
    zones = zones_from_json(str(row["allowed_zones_json"]))
    token = issue_jwt(str(row["username"]), str(row["role"]), zones)
    csrf_tok = ""
    if JWT_USE_HTTPONLY_COOKIE:
        response.set_cookie(
            key=JWT_COOKIE_NAME,
            value=token,
            max_age=int(JWT_EXPIRE_S),
            path="/",
            httponly=True,
            secure=bool(JWT_COOKIE_SECURE),
            samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
        )
        # Paired CSRF token — required on every cookie-authenticated write.
        csrf_tok = _set_csrf_cookie(response)
    ok_detail = dict(ctx)
    ok_detail["owner_admin"] = owner_admin
    ok_detail["login_user"] = str(row["username"])
    audit_event(str(row["username"]), "auth.login.ok", str(row["username"]), ok_detail)
    # One-time welcome email after first successful login. Runs in a background
    # thread so a slow SMTP server never stalls the login response (was seen as
    # "sometimes login freezes").
    try:
        email_u = str(row["email"] or "").strip()
        rk = row.keys()
        wel_sent = int(row["welcome_email_sent"] or 0) if "welcome_email_sent" in rk else 0
        if notifier.enabled() and email_u and wel_sent == 0:
            uname_snap = str(row["username"])
            role_snap = str(row["role"])

            def _send_welcome_async() -> None:
                try:
                    ws, wt, wh = render_welcome_email(username=uname_snap, role=role_snap)
                    # Prefer the async enqueue if available (non-blocking + retried).
                    if hasattr(notifier, "enqueue"):
                        try:
                            notifier.enqueue([email_u], ws, wt, wh)
                        except Exception:
                            notifier.send_sync([email_u], ws, wt, wh)
                    else:
                        notifier.send_sync([email_u], ws, wt, wh)
                    with db_lock:
                        c2 = get_conn()
                        cu2 = c2.cursor()
                        cu2.execute(
                            "UPDATE dashboard_users SET welcome_email_sent = 1 WHERE username = ?",
                            (uname_snap,),
                        )
                        c2.commit()
                        c2.close()
                except Exception:
                    logger.warning("welcome email skipped or failed for %s", uname_snap, exc_info=True)

            threading.Thread(target=_send_welcome_async, name=f"welcome-mail-{uname_snap}", daemon=True).start()
    except Exception:
        logger.warning("welcome email scheduling failed for %s", body.username, exc_info=True)
    out: dict[str, Any] = {"token_type": "bearer", "role": row["role"], "zones": zones}
    if JWT_RETURN_BODY_TOKEN or not JWT_USE_HTTPONLY_COOKIE:
        out["access_token"] = token
    if csrf_tok:
        # Also echo the CSRF token in the JSON body so SPA clients that ignore
        # document.cookie (for whatever reason) can still bootstrap the header.
        out["csrf_token"] = csrf_tok
    return out


@app.get("/auth/csrf")
def auth_csrf(
    response: Response,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """
    Refresh / read the paired CSRF token for the signed-in session.

    The SPA calls this on boot (or whenever it notices the header is rejected)
    to re-sync its double-submit token without forcing a logout-login cycle.
    """
    tok = _set_csrf_cookie(response)
    return {"csrf_token": tok, "header": CSRF_HEADER_NAME}


@app.post("/auth/logout")
def auth_logout(response: Response) -> dict[str, Any]:
    """Clear HttpOnly session cookie (no auth required)."""
    response.delete_cookie(
        JWT_COOKIE_NAME,
        path="/",
        secure=bool(JWT_COOKIE_SECURE),
        httponly=True,
        samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
    )
    _clear_csrf_cookie(response)
    return {"ok": True}


# =====================================================================
#  Device-side HTTP fallback (boot-sync, OTA report, command pull/ack)
# =====================================================================

# Phase-15 modularization: the four /device/* endpoints called by the
# ESP32 firmware (NOT the dashboard) — they authenticate via
# device_id+mac_nocolon+cmd_key, not JWT — plus their four request
# schemas (DeviceBootSyncRequest, DeviceOtaReportRequest,
# DeviceCommandsPendingRequest, DeviceCommandAckRequest) and the
# three device-only auth helpers (_norm_mac_nocolon12,
# _provision_row_for_device_mac, _auth_device_http) now live in
# routers/device_http.py.
from routers.device_http import router as _device_http_router  # noqa: E402

app.include_router(_device_http_router)


# =====================================================================
#  Self-service account routes  (/auth/me/*)
# =====================================================================

# Phase-20 modularization: 10 routes + _auth_me_delete_impl +
# 6 schemas + _validate_avatar_url now live in routers/auth_self.py.
from routers.auth_self import (  # noqa: E402,F401  (re-export for legacy callers)
    FcmTokenDeleteRequest,
    FcmTokenRegisterRequest,
    MeProfilePatchRequest,
    NotificationPrefsPatchRequest,
    SelfDeleteRequest,
    SelfPasswordChangeRequest,
    _validate_avatar_url,
)
from routers.auth_self import router as _auth_self_router  # noqa: E402

app.include_router(_auth_self_router)


# =====================================================================
#  Admin/user CRUD  (/auth/admins, /auth/users)
# =====================================================================

# Phase-21 modularization: 7 routes + 3 schemas now live in routers/auth_users.py.
from routers.auth_users import (  # noqa: E402,F401  (re-export for legacy callers)
    AdminTenantCloseRequest,
    UserCreateRequest,
    UserPolicyUpdateRequest,
)
from routers.auth_users import router as _auth_users_router  # noqa: E402

app.include_router(_auth_users_router)

@app.get("/admin/backup/export")
def admin_backup_export(
    principal: Principal = Depends(require_principal),
    x_backup_key: str = Header(..., alias="X-Backup-Encryption-Key"),
) -> Response:
    assert_min_role(principal, "superadmin")
    if not os.path.isfile(DB_PATH):
        raise HTTPException(status_code=404, detail="database file not found")
    with open(DB_PATH, "rb") as f:
        raw = f.read()
    if len(raw) < 16 or raw[:15] != b"SQLite format 3":
        raise HTTPException(status_code=500, detail="database file invalid")
    enc = encrypt_blob(raw, x_backup_key)
    return Response(
        content=enc,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="sentinel-backup.enc"'},
    )


@app.post("/admin/backup/import")
async def admin_backup_import(
    principal: Principal = Depends(require_principal),
    x_backup_key: str = Header(..., alias="X-Backup-Encryption-Key"),
    file: UploadFile = File(...),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    body = await file.read()
    plain = decrypt_blob(body, x_backup_key)
    if len(plain) < 16 or plain[:15] != b"SQLite format 3":
        raise HTTPException(status_code=400, detail="decrypted payload is not sqlite")
    out_path = DB_PATH + ".restored"
    with open(out_path, "wb") as f:
        f.write(plain)
    return {
        "ok": True,
        "written_path": out_path,
        "hint": "Stop the API container, replace the live DB file with this path, then start again (see docs).",
    }


@app.post("/provision/challenge/request")
def provision_challenge_request(
    req: DeviceChallengeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    device_id = req.device_id.strip().upper()
    mac_nocolon = req.mac_nocolon.strip().upper()
    if not re.fullmatch(DEVICE_ID_REGEX, device_id):
        raise HTTPException(status_code=400, detail="device_id format rejected by policy")
    nonce = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + DEVICE_CHALLENGE_TTL_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_identities (device_id, mac_nocolon, public_key_pem, attestation_json, registered_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                mac_nocolon = excluded.mac_nocolon,
                public_key_pem = excluded.public_key_pem,
                attestation_json = excluded.attestation_json,
                registered_at = excluded.registered_at
            """,
            (
                device_id,
                mac_nocolon,
                req.public_key_pem,
                json.dumps(req.attestation or {}, ensure_ascii=True),
                utc_now_iso(),
            ),
        )
        cur.execute(
            """
            INSERT INTO provision_challenges (mac_nocolon, device_id, nonce, expires_at_ts, verified_at, used)
            VALUES (?, ?, ?, ?, NULL, 0)
            """,
            (mac_nocolon, device_id, nonce, expires_at),
        )
        challenge_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    audit_event(principal.username, "challenge.request", device_id, {"challenge_id": challenge_id})
    return {"challenge_id": challenge_id, "nonce": nonce, "expires_at_ts": expires_at}


@app.post("/provision/challenge/verify")
def provision_challenge_verify(
    req: DeviceChallengeVerifyRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.id, c.device_id, c.nonce, c.expires_at_ts, c.used, i.public_key_pem
            FROM provision_challenges c
            JOIN device_identities i ON c.device_id = i.device_id
            WHERE c.id = ?
            """,
            (req.challenge_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="challenge not found")
        if int(row["used"]) == 1:
            conn.close()
            raise HTTPException(status_code=409, detail="challenge already used")
        if int(time.time()) > int(row["expires_at_ts"]):
            conn.close()
            raise HTTPException(status_code=410, detail="challenge expired")
        ok = verify_device_signature(str(row["public_key_pem"]), str(row["nonce"]), req.signature_b64)
        if not ok:
            conn.close()
            raise HTTPException(status_code=401, detail="device signature verification failed")
        cur.execute(
            "UPDATE provision_challenges SET verified_at = ? WHERE id = ?",
            (utc_now_iso(), req.challenge_id),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "challenge.verify", str(row["device_id"]), {"challenge_id": req.challenge_id})
    return {"ok": True, "device_id": row["device_id"], "challenge_id": req.challenge_id}


@app.get("/devices/revoked")
def list_revoked_devices(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("SELECT device_id, reason, revoked_by, revoked_at FROM revoked_devices ORDER BY revoked_at DESC")
        else:
            cur.execute(
                """
                SELECT r.device_id, r.reason, r.revoked_by, r.revoked_at
                FROM revoked_devices r
                JOIN device_ownership o ON r.device_id = o.device_id
                WHERE o.owner_admin = ?
                ORDER BY r.revoked_at DESC
                """,
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.post("/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    req: DeviceRevokeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO revoked_devices (device_id, reason, revoked_by, revoked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                reason = excluded.reason,
                revoked_by = excluded.revoked_by,
                revoked_at = excluded.revoked_at
            """,
            (device_id, req.reason, principal.username, utc_now_iso()),
        )
        cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
        deleted_acl_rows = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(
        principal.username,
        "device.revoke",
        device_id,
        {"reason": req.reason, "deleted_device_acl_rows": deleted_acl_rows},
    )
    return {"ok": True, "device_id": device_id}


@app.post("/devices/{device_id}/unrevoke")
def unrevoke_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "device.unrevoke", device_id, {})
    return {"ok": True, "device_id": device_id}


def _delete_user_auxiliary_cur(cur: Any, username: str) -> None:
    """Remove dashboard user row and attached rows (not device ownership)."""
    cur.execute("DELETE FROM role_policies WHERE username = ?", (username,))
    cur.execute("DELETE FROM verifications WHERE username = ?", (username,))
    cur.execute("DELETE FROM device_acl WHERE grantee_username = ?", (username,))
    cur.execute("DELETE FROM telegram_chat_bindings WHERE username = ?", (username,))
    cur.execute("DELETE FROM telegram_link_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM user_fcm_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM password_reset_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))
    # If the deleted user was a superadmin, the cached chat list is stale;
    # same for the username->role cache.
    _invalidate_superadmin_telegram_chats_cache()


def _apply_device_factory_unclaim_cur(cur: Any, device_id: str) -> None:
    """Same data effect as factory-unregister: unclaim in DB + factory_devices status (caller holds lock)."""
    cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (device_id,))
    p = cur.fetchone()
    mac_nocolon = str(p["mac_nocolon"]) if p and p["mac_nocolon"] else ""
    cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
    if mac_nocolon:
        cur.execute(
            "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE mac_nocolon = ?",
            (utc_now_iso(), mac_nocolon),
        )
    else:
        cur.execute(
            "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE serial = ?",
            (utc_now_iso(), device_id),
        )


def _close_admin_tenant_cur(
    cur: Any,
    admin_username: str,
    transfer_devices_to: Optional[str],
    actor_username: str,
) -> dict[str, Any]:
    """
    admin_username: role must be 'admin'. Transfers or unclaims all owned devices, deletes
    subordinate users, then deletes the admin row. Does not commit.
    """
    cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (admin_username,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    role = str(row["role"] or "")
    if role == "superadmin":
        raise HTTPException(status_code=400, detail="cannot close a superadmin account with this action")
    if role != "admin":
        raise HTTPException(status_code=400, detail="target is not an admin tenant")
    summary: dict[str, Any] = {
        "admin": admin_username,
        "devices_unclaimed": 0,
        "devices_transferred": 0,
        "subordinate_users_deleted": 0,
    }
    transfer_to = (transfer_devices_to or "").strip() or None
    if transfer_to:
        cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (transfer_to,))
        trow = cur.fetchone()
        if not trow or str(trow["role"] or "") not in ("admin", "superadmin"):
            raise HTTPException(status_code=400, detail="transfer_devices_to must be an existing admin or superadmin")
        if secrets.compare_digest(transfer_to, admin_username):
            raise HTTPException(status_code=400, detail="cannot transfer to the same admin")
        cur.execute("SELECT device_id FROM device_ownership WHERE owner_admin = ?", (admin_username,))
        transfer_ids = [str(r["device_id"]) for r in cur.fetchall() if r and r["device_id"]]
        cur.execute(
            """
            UPDATE device_ownership
            SET owner_admin = ?, assigned_by = ?, assigned_at = ?
            WHERE owner_admin = ?
            """,
            (transfer_to, actor_username, utc_now_iso(), admin_username),
        )
        summary["devices_transferred"] = int(cur.rowcount or 0)
        if transfer_ids:
            ph = ",".join("?" * len(transfer_ids))
            cur.execute(
                f"UPDATE device_state SET display_label = '', notification_group = '' WHERE device_id IN ({ph})",
                transfer_ids,
            )
    else:
        cur.execute("SELECT device_id FROM device_ownership WHERE owner_admin = ?", (admin_username,))
        for r in cur.fetchall():
            did = str(r["device_id"] or "")
            if not did:
                continue
            _apply_device_factory_unclaim_cur(cur, did)
            summary["devices_unclaimed"] += 1
    cur.execute(
        "SELECT username FROM dashboard_users WHERE manager_admin = ? AND role = 'user'",
        (admin_username,),
    )
    for r in cur.fetchall():
        su = str(r["username"] or "")
        if su:
            _delete_user_auxiliary_cur(cur, su)
            summary["subordinate_users_deleted"] += 1
    _delete_user_auxiliary_cur(cur, admin_username)
    return summary


def _wait_cmd_ack(device_id: str, cmd: str, timeout_s: float = 2.5, cmd_id: Optional[str] = None) -> bool:
    deadline = time.time() + max(0.2, float(timeout_s))
    cid = (cmd_id or "").strip()
    while time.time() < deadline:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT IFNULL(last_ack_json,'') AS last_ack_json FROM device_state WHERE device_id = ?", (device_id,))
            row = cur.fetchone()
            conn.close()
        try:
            ack = json.loads(str((row["last_ack_json"] if row else "") or ""))
        except Exception:
            ack = {}
        if str(ack.get("cmd") or "") != cmd or not bool(ack.get("ok")):
            time.sleep(0.12)
            continue
        if cid and str(ack.get("cmd_id") or "") != cid:
            time.sleep(0.12)
            continue
        return True
    return False


def _try_mqtt_unclaim_reset(device_id: str) -> tuple[bool, bool]:
    """Best-effort dispatch + short ack wait for unclaim_reset before DB unlink.

    Returns (sent, acked). Fails fast (no blocking) when the broker is down or
    the device is offline — the HTTP request must not hang for a dead device.
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 1 AS ok,
                   IFNULL((SELECT updated_at FROM device_state WHERE device_id = pc.device_id),'') AS updated_at
            FROM provisioned_credentials pc
            WHERE pc.device_id = ?
            """,
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return False, False
    last_seen = str(row["updated_at"] or "")
    # If the device hasn't been seen recently, skip the ACK wait entirely.
    # The command is still published (broker queues for QoS 1), but the HTTP caller
    # won't block waiting for an ACK that's never coming.
    online_hint = False
    try:
        last_ts = _parse_iso(last_seen)
        if last_ts > 0:
            online_hint = (time.time() - last_ts) < max(60, int(OFFLINE_THRESHOLD_SECONDS))
    except Exception:
        online_hint = False
    try:
        # No dedupe: a prior attempt may have deleted server-side creds while
        # the device never got MQTT; retries must publish a fresh frame. Firmware
        # treats unclaim_reset idempotently.
        cmd_id = publish_command(
            f"{TOPIC_ROOT}/{device_id}/cmd",
            "unclaim_reset",
            {},
            device_id,
            CMD_PROTO,
            get_cmd_key_for_device(device_id),
        )
    except HTTPException as exc:
        # 503 = broker disconnected → no MQTT, don't wait.
        logger.warning("unclaim_reset MQTT not delivered for %s: %s", device_id, getattr(exc, "detail", exc))
        return False, False
    except Exception as exc:
        logger.warning("unclaim_reset MQTT error for %s: %s", device_id, exc)
        return False, False
    if not online_hint:
        return True, False
    return True, _wait_cmd_ack(device_id, "unclaim_reset", timeout_s=2.2, cmd_id=cmd_id)


def _device_delete_reset_impl(
    device_id: str,
    principal: Principal,
    req: DeviceDeleteRequest,
    *,
    super_unclaim: bool,
) -> dict[str, Any]:
    if str(req.confirm_text or "").strip().upper() != str(device_id or "").strip().upper():
        raise HTTPException(status_code=400, detail="confirm_text must exactly match device_id")
    require_capability(principal, "can_send_command")
    if super_unclaim:
        # Factory rollback: admin+ only (not subordinate "user" accounts).
        assert_min_role(principal, "admin")
        if not principal.is_superadmin():
            assert_device_owner(principal, device_id)
    else:
        assert_min_role(principal, "user")
        assert_device_owner(principal, device_id)
    nvs_purge_sent, nvs_purge_acked = _try_mqtt_unclaim_reset(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        p = cur.fetchone()
        mac_nocolon = str(p["mac_nocolon"]) if p and p["mac_nocolon"] else ""
        cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        del_cred = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
        del_owner = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
        del_acl = int(cur.rowcount or 0)
        cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
        del_revoked = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
        del_state = int(cur.rowcount or 0)
        cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
        del_sched = int(cur.rowcount or 0)
        # Keep factory registry aligned whenever this serial/MAC is known (same as
        # "factory-unregister" — also applies to normal tenant unbind so ops lists
        # and identify flows stay consistent after unlink).
        if mac_nocolon:
            cur.execute(
                "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE mac_nocolon = ?",
                (utc_now_iso(), mac_nocolon),
            )
        else:
            cur.execute(
                "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE serial = ?",
                (utc_now_iso(), device_id),
            )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    action = "device.factory_unclaim" if super_unclaim else "device.delete_reset"
    audit_event(
        principal.username,
        action,
        device_id,
        {
            "mac_nocolon": mac_nocolon or "",
            "nvs_purge_mqtt": nvs_purge_sent,
            "nvs_purge_ack": nvs_purge_acked,
            "deleted_credentials": del_cred,
            "deleted_owner": del_owner,
            "deleted_acl": del_acl,
            "deleted_revoked": del_revoked,
            "deleted_state": del_state,
            "deleted_scheduled": del_sched,
            "factory_unclaimed": super_unclaim,
        },
    )
    return {
        "ok": True,
        "device_id": device_id,
        "mode": "factory_unclaim" if super_unclaim else "delete_reset",
        "factory_unclaimed": super_unclaim,
        "nvs_purge_sent": nvs_purge_sent,
        "nvs_purge_acked": nvs_purge_acked,
        "nvs_purge_note": "sent=true means command reached broker; acked=true means device confirmed unclaim_reset before DB unlink.",
    }


@app.post("/devices/{device_id}/delete-reset")
def device_delete_reset(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Tenant user (operate) / admin / superadmin: unlink device + best-effort unclaim_reset."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=False)


@app.post("/devices/{device_id}/factory-unregister")
def device_factory_unregister(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Rollback to unregistered while keeping factory serial: superadmin (any device) or owning admin."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=True)


def _health_notify_summary_public() -> tuple[dict[str, Any], dict[str, Any]]:
    """Mail/TG liveness without secrets (for HEALTH_PUBLIC_DETAIL=0). Keeps dashboard pills honest."""
    smtp = {"configured": notifier.enabled(), "worker_running": notifier.worker_alive()}
    tg: dict[str, Any] = {"enabled": False, "worker_running": False, "last_error": ""}
    try:
        from telegram_notify import telegram_status

        full = dict(telegram_status())
        tg = {
            "enabled": bool(full.get("enabled")),
            "worker_running": bool(full.get("worker_running")),
            "last_error": str(full.get("last_error") or "")[:240],
        }
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "last_error": str(exc)[:240]}
    return smtp, tg


def _health_db_probe(timeout_s: float = 1.5) -> dict[str, Any]:
    """Fast DB liveness probe: run `SELECT 1` with a tight budget.
    Returns {ok, latency_ms, error?}. Never raises.
    """
    t0 = time.monotonic()
    out: dict[str, Any] = {"ok": False, "latency_ms": 0}
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            out["ok"] = True
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as exc:
        out["error"] = str(exc)[:240]
    latency_ms = int((time.monotonic() - t0) * 1000)
    out["latency_ms"] = latency_ms
    out["slow"] = latency_ms > int(timeout_s * 1000)
    return out


def _health_subscriber_summary() -> dict[str, Any]:
    try:
        with event_bus._lock:  # noqa: SLF001 — intentional peek
            n = len(event_bus._subs)  # noqa: SLF001
            dropped = sum(int(getattr(s, "dropped", 0)) for s in event_bus._subs.values())  # noqa: SLF001
        return {"count": n, "cap": int(EVENT_MAX_SUBSCRIBERS), "dropped_total": dropped}
    except Exception:
        return {"count": 0, "cap": int(EVENT_MAX_SUBSCRIBERS), "dropped_total": 0}


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness for load balancers / `curl` — intentionally **no** auth so Uptime
    Kuma, Docker healthchecks, and reverse proxies can probe without a token."""
    ready = api_ready_event.is_set() and not api_bootstrap_error
    db_probe = _health_db_probe()
    # Flip `ok` to False when DB is actually stalled — this is the load-balancer
    # signal that says "pull this worker out of rotation".
    db_ok = bool(db_probe.get("ok"))
    subs = _health_subscriber_summary()
    if not HEALTH_PUBLIC_DETAIL:
        smtp, tg = _health_notify_summary_public()
        # MQTT + mail/TG worker truth; FCM/token hints still only when HEALTH_PUBLIC_DETAIL=1.
        body = {
            "ok": bool(ready and db_ok),
            "ready": ready,
            "starting": not api_ready_event.is_set(),
            "db": db_probe,
            "sse_subscribers": subs,
            "mqtt_connected": mqtt_connected,
            "mqtt_ingest_queue_depth": mqtt_ingest_queue.qsize(),
            "mqtt_ingest_dropped": mqtt_ingest_dropped,
            "mqtt_last_connect_at": mqtt_last_connect_at,
            "mqtt_last_disconnect_at": mqtt_last_disconnect_at,
            "mqtt_last_disconnect_reason": mqtt_last_disconnect_reason,
            "smtp": smtp,
            "telegram": tg,
            "ts": int(time.time()),
        }
        if api_bootstrap_error:
            body["bootstrap_error"] = api_bootstrap_error
        return body
    tg: dict[str, Any] = {}
    try:
        from telegram_notify import telegram_status

        tg = dict(telegram_status())
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "error": str(exc)}
    fcm: dict[str, Any] = {}
    try:
        from fcm_notify import fcm_status

        fcm = dict(fcm_status())
    except Exception as exc:
        fcm = {"enabled": False, "error": str(exc), "queue_size": 0, "worker_running": False}
    body = {
        "ok": bool(ready and db_ok),
        "ready": ready,
        "starting": not api_ready_event.is_set(),
        "db": db_probe,
        "sse_subscribers": subs,
        "mqtt_connected": mqtt_connected,
        "mqtt_ingest_queue_depth": mqtt_ingest_queue.qsize(),
        "mqtt_ingest_dropped": mqtt_ingest_dropped,
        "mqtt_last_connect_at": mqtt_last_connect_at,
        "mqtt_last_disconnect_at": mqtt_last_disconnect_at,
        "mqtt_last_disconnect_reason": mqtt_last_disconnect_reason,
        "smtp": {
            "configured": notifier.enabled(),
            "worker_running": notifier.worker_alive(),
        },
        "telegram": tg,
        "fcm": fcm,
        "ts": int(time.time()),
    }
    if api_bootstrap_error:
        body["bootstrap_error"] = api_bootstrap_error
    return body


OFFLINE_THRESHOLD_SECONDS = int(os.getenv("OFFLINE_THRESHOLD_SECONDS", "90"))


def _parse_iso(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _payload_ts(d: dict[str, Any]) -> int:
    """Device JSON `ts` field (epoch seconds or millis fallback before NTP)."""
    t = d.get("ts")
    if isinstance(t, int):
        return t
    if isinstance(t, float):
        return int(t)
    return 0


def _effective_online_for_presence(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
) -> bool:
    """
    True when the device is up on MQTT, even if last /status snapshot is stale.

    Retained LWT (online=false) can remain in last_status_json while newer
    heartbeat, ack, or event traffic (same row `updated_at`) proves the device is back.
    """
    ts_s = _payload_ts(last_status)
    ts_hb = _payload_ts(last_heartbeat)
    ts_a = _payload_ts(last_ack)
    ts_e = _payload_ts(last_event)
    if ts_a > ts_s or ts_e > ts_s:
        return True
    if ts_hb > ts_s:
        return bool(last_heartbeat.get("online"))
    if ts_s == 0 and ts_hb == 0 and ts_a == 0 and ts_e == 0:
        return False
    return bool(last_status.get("online"))


def _device_is_online_parsed(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
    updated_at_iso: str,
    now_s: int,
) -> bool:
    """Same rule as dashboard overview presence: payload truth + row freshness."""
    updated = _parse_iso(str(updated_at_iso or ""))
    fresh = (now_s - updated) < OFFLINE_THRESHOLD_SECONDS
    return _effective_online_for_presence(last_status, last_heartbeat, last_ack, last_event) and fresh


def _device_presence_ages(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
    updated_at_iso: str,
    now_s: int,
) -> dict[str, int]:
    """
    Returns granular age-in-seconds fields for UI/health display.

    Anything we can't compute comes back as -1 (render as "--" in the UI) so
    the frontend never has to invent placeholder values.

    - `last_heartbeat_age_s`: seconds since the device last sent /heartbeat
      (HYBRID mode keepalive or an event heartbeat). -1 before first hb.
    - `last_signal_age_s`: seconds since ANY channel (status/heartbeat/ack/
      event) touched the row — this is the same clock the presence logic
      compares against OFFLINE_THRESHOLD_SECONDS.
    - `last_updated_age_s`: seconds since the DB row's updated_at column.
    """
    def _age(ts: int) -> int:
        if ts <= 0:
            return -1
        return max(0, int(now_s) - int(ts))

    hb_age = _age(_payload_ts(last_heartbeat))
    signal_ts = max(
        _payload_ts(last_status) or 0,
        _payload_ts(last_heartbeat) or 0,
        _payload_ts(last_ack) or 0,
        _payload_ts(last_event) or 0,
    )
    updated = _parse_iso(str(updated_at_iso or ""))
    return {
        "last_heartbeat_age_s": hb_age,
        "last_signal_age_s": _age(signal_ts),
        "last_updated_age_s": _age(int(updated) if updated > 0 else 0),
    }


def _device_is_online_sql_row(row: dict[str, Any], now_s: int) -> bool:
    def _pj(col: str) -> dict[str, Any]:
        raw = row.get(col)
        if not raw:
            return {}
        try:
            return json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            return {}

    return _device_is_online_parsed(
        _pj("last_status_json"),
        _pj("last_heartbeat_json"),
        _pj("last_ack_json"),
        _pj("last_event_json"),
        str(row.get("updated_at") or ""),
        now_s,
    )


def _row_json_val(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        j = json.loads(raw) if isinstance(raw, str) else dict(raw)
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _net_health_from_status(last_status: Any) -> dict[str, Any]:
    """Extract the firmware's net_health ledger block.

    Accepts either a parsed status dict (from `get_device`) or a raw
    ``last_status_json`` column value (from the list query).

    Returns ``{}`` for firmware that doesn't emit it — older builds only
    publish the flat rssi/online fields.

    Fields (all integers, monotonic since the device's last boot):
        wifi_reconnects       — successful Wi-Fi rejoins since boot
        mqtt_reconnects       — successful MQTT reconnects since boot
        mqtt_last_down_code   — PubSubClient state() at last drop (-4..5)
        mqtt_last_conn_code   — PubSubClient state() at last connect fail
        mqtt_longest_gap_ms   — longest continuous MQTT offline span
        wifi_longest_gap_ms   — longest continuous Wi-Fi offline span
        roam_attempts         — signal-driven AP switches
        mqtt_fail_streak      — consecutive connect failures right now
    """
    if isinstance(last_status, dict):
        st = last_status
    else:
        st = _row_json_val(last_status)
    raw = st.get("net_health") if isinstance(st, dict) else None
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key in (
        "wifi_reconnects",
        "mqtt_reconnects",
        "mqtt_last_down_code",
        "mqtt_last_conn_code",
        "mqtt_longest_gap_ms",
        "wifi_longest_gap_ms",
        "roam_attempts",
        "mqtt_fail_streak",
    ):
        if key in raw:
            try:
                out[key] = int(raw[key])
            except (TypeError, ValueError):
                pass
    return out


def _status_preview_from_device_row(d: dict[str, Any]) -> dict[str, Any]:
    """Compact live hints for the device list (one round-trip, no N+1)."""
    st = _row_json_val(d.get("last_status_json"))
    hb = _row_json_val(d.get("last_heartbeat_json"))
    rssi: int | None = None
    _w = st.get("wifi")
    wifi = _w if isinstance(_w, dict) else {}
    for cand in (st.get("rssi"), wifi.get("rssi") if isinstance(wifi, dict) else None, hb.get("rssi")):
        if cand is None:
            continue
        try:
            r = int(cand)
        except (TypeError, ValueError):
            continue
        if r != -127:
            rssi = r
            break
    vbat: float | None
    vbat = None
    if st.get("vbat") is not None:
        try:
            vb = float(st["vbat"])
            if vb >= 0:
                vbat = round(vb, 2)
        except (TypeError, ValueError):
            vbat = None
    parts: list[str] = []
    if rssi is not None:
        parts.append(f"RSSI {rssi} dBm")
    if vbat is not None:
        parts.append(f"{vbat:.2f} V")
    hb_on = bool(hb.get("online")) if "online" in hb else None
    if hb_on is True and not parts:
        parts.append("heartbeat")
    if hb_on is False and not parts:
        parts.append("heartbeat lost")
    line = " · ".join(parts) if parts else "—"
    return {"line": line, "rssi": rssi, "vbat": vbat}


def _parse_fw_version_tuple(s: str) -> tuple[int, ...] | None:
    t = (s or "").strip()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:\D|$)", t)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m2 = re.search(r"(\d+)\.(\d+)(?:\D|$)", t)
    if m2:
        return (int(m2.group(1)), int(m2.group(2)), 0)
    return None


def _fw_version_gt(newer: str, current: str) -> bool:
    a, b = (newer or "").strip(), (current or "").strip()
    if not a:
        return False
    if not b:
        return bool(a)
    ta, tb = _parse_fw_version_tuple(a), _parse_fw_version_tuple(b)
    if ta and tb:
        return ta > tb
    return a > b


def _version_str_from_ota_bin_name(name: str) -> str:
    base = os.path.basename(name)
    m = re.match(r"^croc-(.+)-[a-f0-9]{8}\.bin$", base, re.I)
    if m:
        return m.group(1).replace("_", ".")
    m2 = re.search(r"(\d+\.\d+\.\d+)", base)
    if m2:
        return m2.group(1)
    m3 = re.search(r"(\d+\.\d+)(?:\D|$)", base)
    if m3:
        return m3.group(1) + ".0"
    if base.lower().endswith(".bin"):
        return base[:-4] or base
    return base


def _read_ota_stored_version_sidecar(bin_path: str) -> str:
    """Canonical version string from OTA upload (`<name>.version`, one line). Not derived from the filename."""
    b = (bin_path or "").strip()
    if not b or ".." in b:
        return ""
    p = b + ".version"
    if not os.path.isfile(p):
        return ""
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            line = f.readline()
        v = (line or "").strip()
        return v[:80] if v else ""
    except OSError:
        return ""


def _version_str_for_ota_bin_file(bin_path: str, name: str) -> str:
    v = _read_ota_stored_version_sidecar(bin_path).strip()
    if v:
        return v
    return str(_version_str_from_ota_bin_name(name) or "").strip()


def _read_ota_release_notes_for_stem(stem: str) -> str:
    if not stem or ".." in stem or "/" in stem or "\\" in stem:
        return ""
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    for ext in (".txt", ".md", ".notes"):
        p = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, stem + ext))
        if not p.startswith(base_dir + os.sep) or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                return f.read(8000)
        except OSError:
            continue
    return ""


_OTA_CATALOG_TTL = 45.0
_OTA_CATALOG_CACHE: tuple[float, list[dict[str, Any]]] | None = None


def _invalidate_ota_firmware_catalog_cache() -> None:
    global _OTA_CATALOG_CACHE
    _OTA_CATALOG_CACHE = None


def _get_ota_firmware_catalog() -> list[dict[str, Any]]:
    global _OTA_CATALOG_CACHE
    now = time.time()
    if _OTA_CATALOG_CACHE and (now - _OTA_CATALOG_CACHE[0]) < _OTA_CATALOG_TTL:
        return _OTA_CATALOG_CACHE[1]
    items: list[dict[str, Any]] = []
    base = OTA_FIRMWARE_DIR
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            if not str(name).endswith(".bin"):
                continue
            p = os.path.join(base, name)
            if not os.path.isfile(p):
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            vs = _version_str_for_ota_bin_file(p, name).strip()
            if not vs:
                continue
            items.append(
                {
                    "name": name,
                    "version_str": vs,
                    "version_tuple": _parse_fw_version_tuple(vs),
                    "mtime": int(st.st_mtime),
                },
            )
    _OTA_CATALOG_CACHE = (now, items)
    return items


def _catalog_entry_beats(a: dict[str, Any], b: dict[str, Any] | None) -> bool:
    """True if `a` is a strictly better upgrade candidate than `b` (newer version, or same version + newer mtime)."""
    if b is None:
        return True
    va, vb = str(a.get("version_str") or "").strip(), str(b.get("version_str") or "").strip()
    if not va:
        return False
    if _fw_version_gt(va, vb):
        return True
    if va == vb and int(a.get("mtime", 0)) > int(b.get("mtime", 0)):
        return True
    return False


def _best_catalog_entry_newer_than_fw(current_fw: str, catalog: list[dict[str, Any]]) -> dict[str, Any] | None:
    cur = (current_fw or "").strip()
    if not cur or not catalog:
        return None
    best: dict[str, Any] | None = None
    for ent in catalog:
        v = str(ent.get("version_str") or "").strip()
        if not v or not _fw_version_gt(v, cur):
            continue
        if _catalog_entry_beats(ent, best):
            best = ent
    return best


def _firmware_hint_dict_from_entry(best: dict[str, Any]) -> dict[str, Any]:
    name = str(best["name"])
    stem = name[:-4] if name.lower().endswith(".bin") else name
    notes = _read_ota_release_notes_for_stem(stem)
    dl = ""
    if OTA_PUBLIC_BASE_URL:
        dl = f"{OTA_PUBLIC_BASE_URL}/fw/{name}"
    return {
        "update_available": True,
        "to_version": str(best["version_str"]),
        "to_file": name,
        "release_notes": notes,
        "download_url": dl or None,
    }


def _firmware_update_hint_for_current_in_catalog(
    current_fw: str, catalog: list[dict[str, Any]]
) -> dict[str, Any] | None:
    best = _best_catalog_entry_newer_than_fw(current_fw, catalog)
    if not best:
        return None
    cur = (current_fw or "").strip().lower()
    tgt = str(best.get("version_str") or "").strip().lower()
    if cur and tgt and cur == tgt:
        return None
    return _firmware_hint_dict_from_entry(best)


@app.get("/dashboard/overview")
def dashboard_overview(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "overview" if (principal.is_superadmin() or principal.has_all_zones()) else f"overview:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    args = tuple(za + osa)
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) AS c FROM device_state WHERE 1=1 {zs} {osf}", args)
        total = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM device_state
            WHERE last_status_json IS NOT NULL {zs} {osf}
            """,
            args,
        )
        with_status = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT fw, chip_target, board_profile, net_type, COUNT(*) AS c
            FROM device_state
            WHERE 1=1 {zs} {osf}
            GROUP BY fw, chip_target, board_profile, net_type
            ORDER BY c DESC
            """,
            args,
        )
        grouped = [dict(r) for r in cur.fetchall()]
        cur.execute(
            f"""
            SELECT device_id, updated_at, last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state
            WHERE 1=1 {zs} {osf}
            """,
            args,
        )
        presence_rows = cur.fetchall()
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM alarms
            WHERE created_at >= datetime('now', '-24 hours')
              AND (? = '' OR owner_admin = ?)
            """,
            ("" if principal.is_superadmin() else "x",
             "" if principal.is_superadmin() else (
                 principal.username if principal.role == "admin"
                 else get_manager_admin(principal.username)
             )),
        )
        alarms_24h = int(cur.fetchone()["c"])
        conn.close()
    now_s = time.time()
    presence = {
        "online": 0,
        "offline_total": 0,
        "reason_power_low": 0,
        "reason_network_lost": 0,
        "reason_signal_weak": 0,
        "reason_unknown": 0,
    }
    tx_bps_total = 0.0
    rx_bps_total = 0.0
    for r in presence_rows:
        raw = r["last_status_json"] or ""
        try:
            s = json.loads(raw) if raw else {}
        except Exception:
            s = {}
        raw_hb = r["last_heartbeat_json"] or ""
        try:
            hb = json.loads(raw_hb) if raw_hb else {}
        except Exception:
            hb = {}
        raw_ack = r["last_ack_json"] or ""
        try:
            ack = json.loads(raw_ack) if raw_ack else {}
        except Exception:
            ack = {}
        raw_ev = r["last_event_json"] or ""
        try:
            ev = json.loads(raw_ev) if raw_ev else {}
        except Exception:
            ev = {}
        updated = _parse_iso(str(r["updated_at"] or ""))
        fresh = (now_s - updated) < OFFLINE_THRESHOLD_SECONDS
        is_online = _effective_online_for_presence(s, hb, ack, ev) and fresh
        if is_online:
            presence["online"] += 1
            try:
                tx_bps_total += float(s.get("tx_bps") or 0)
                rx_bps_total += float(s.get("rx_bps") or 0)
            except (TypeError, ValueError):
                pass
        else:
            presence["offline_total"] += 1
            reason = str(s.get("disconnect_reason") or "")
            if reason == "power_low":
                presence["reason_power_low"] += 1
            elif reason == "network_lost" or (now_s - updated) >= OFFLINE_THRESHOLD_SECONDS:
                presence["reason_network_lost"] += 1
            elif reason == "signal_weak":
                presence["reason_signal_weak"] += 1
            else:
                presence["reason_unknown"] += 1
    out = {
        "total_devices": total,
        "devices_with_status": with_status,
        "groups": grouped,
        "mqtt_connected": mqtt_connected,
        "presence": presence,
        "throughput": {
            "tx_bps_total": round(tx_bps_total, 1),
            "rx_bps_total": round(rx_bps_total, 1),
        },
        "alarms_24h": alarms_24h,
        "notifier": notifier.status() if principal.is_adminish() else {"enabled": notifier.enabled()},
        "ts": int(time.time()),
    }
    cache_put(cache_key, out)
    return out


@app.get("/devices")
def list_devices(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "devices:list" if (principal.is_superadmin() or principal.has_all_zones()) else f"devices:list:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, d.fw, d.chip_target, d.board_profile, d.net_type, d.zone, d.provisioned,
                   o.owner_admin,
                   IFNULL(display_label, '') AS display_label,
                   IFNULL(notification_group, '') AS notification_group, updated_at,
                   last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE 1=1 {zs} {osf}
            ORDER BY d.updated_at DESC
            """,
            tuple(za + osa),
        )
        now_s = int(time.time())
        rows_out: list[dict[str, Any]] = []
        for r in cur.fetchall():
            d = dict(r)
            d["is_online"] = _device_is_online_sql_row(d, now_s)
            d["status_preview"] = _status_preview_from_device_row(d)
            d["net_health"] = _net_health_from_status(d.get("last_status_json"))
            d.update(
                _device_presence_ages(
                    _row_json_val(d.get("last_status_json")),
                    _row_json_val(d.get("last_heartbeat_json")),
                    _row_json_val(d.get("last_ack_json")),
                    _row_json_val(d.get("last_event_json")),
                    str(d.get("updated_at") or ""),
                    now_s,
                )
            )
            owner_admin = str(d.get("owner_admin") or "")
            d.pop("last_status_json", None)
            d.pop("last_heartbeat_json", None)
            d.pop("last_ack_json", None)
            d.pop("last_event_json", None)
            _redact_notification_group_for_principal(principal, owner_admin, d)
            if principal.role != "superadmin":
                viewer_admin = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or "")
                is_shared = bool(owner_admin) and bool(viewer_admin) and owner_admin != viewer_admin
                d["is_shared"] = bool(is_shared)
                if is_shared:
                    d["shared_by"] = owner_admin
                d.pop("owner_admin", None)
            rows_out.append(d)
        conn.close()
    # Bulk-join pending command counts so the dashboard can render a
    # "X pending" chip next to devices that have queued MQTT commands.
    try:
        ids = [str(r.get("device_id") or "") for r in rows_out if r.get("device_id")]
        counts = _cmd_queue_pending_counts(ids) if ids else {}
        for r in rows_out:
            r["pending_cmds"] = int(counts.get(str(r.get("device_id") or ""), 0))
    except Exception as exc:
        logger.debug("devices list: pending_cmds join failed: %s", exc)
    out = {"items": rows_out}
    cache_put(cache_key, out)
    return out


@app.get("/devices/firmware-hints")
def list_devices_firmware_hints(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Per-device “newer .bin on disk” hint for the signed-in scope (no superadmin OTA UI required)."""
    assert_min_role(principal, "user")
    catalog = _get_ota_firmware_catalog()
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, d.fw
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE 1=1 {zs} {osf}
            """,
            tuple(za + osa),
        )
        rows = [dict(x) for x in cur.fetchall()]
        conn.close()
    hints: dict[str, Any] = {}
    for r in rows:
        did = str(r.get("device_id") or "")
        if not did:
            continue
        cur_fw = str(r.get("fw") or "")
        h = _firmware_update_hint_for_current_in_catalog(cur_fw, catalog)
        if h:
            hints[did] = h
    return {"hints": hints, "ts": int(time.time())}


@app.get("/devices/{device_id}")
def get_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM device_state WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        cur.execute(
            """
            SELECT o.owner_admin, o.assigned_by, o.assigned_at, IFNULL(u.email, '') AS owner_email
            FROM device_ownership o
            LEFT JOIN dashboard_users u ON u.username = o.owner_admin
            WHERE o.device_id = ?
            """,
            (device_id,),
        )
        ow = cur.fetchone()
        conn.close()
    assert_zone_for_device(principal, str(row["zone"]) if row["zone"] is not None else "")
    can_view, can_operate = _device_access_flags(principal, device_id)

    out = dict(row)
    for key in ("last_status_json", "last_heartbeat_json", "last_ack_json", "last_event_json"):
        if out.get(key):
            out[key] = json.loads(out[key])
    now_s = int(time.time())
    out["is_online"] = _device_is_online_parsed(
        out.get("last_status_json") or {},
        out.get("last_heartbeat_json") or {},
        out.get("last_ack_json") or {},
        out.get("last_event_json") or {},
        str(out.get("updated_at") or ""),
        now_s,
    )
    out.update(
        _device_presence_ages(
            out.get("last_status_json") or {},
            out.get("last_heartbeat_json") or {},
            out.get("last_ack_json") or {},
            out.get("last_event_json") or {},
            str(out.get("updated_at") or ""),
            now_s,
        )
    )
    # Firmware net_health (Wi-Fi/MQTT reconnect counters, longest offline
    # gaps, last disconnect reason code). Surfaced here so the device detail
    # page can render a "connectivity stability" card. Empty {} on older fw.
    out["net_health"] = _net_health_from_status(out.get("last_status_json") or {})
    # Pending server-side commands waiting for delivery (MQTT replay or HTTP
    # backup pull). Exposed for the device page's "X pending" chip.
    try:
        out["pending_cmds"] = int(_cmd_queue_pending_counts([device_id]).get(device_id, 0))
    except Exception:
        out["pending_cmds"] = 0
    owner_admin = str(ow["owner_admin"]) if ow and ow["owner_admin"] is not None else ""
    out["owner_admin"] = owner_admin
    out["owner_email"] = str(ow["owner_email"]) if ow and ow["owner_email"] is not None else ""
    if principal.role == "superadmin":
        out["registered_by"] = str(ow["assigned_by"]) if ow else ""
        out["registered_at"] = str(ow["assigned_at"]) if ow else ""
    else:
        viewer_admin = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or "")
        is_shared = bool(owner_admin) and bool(viewer_admin) and owner_admin != viewer_admin
        out["is_shared"] = bool(is_shared)
        if is_shared:
            out["shared_by"] = owner_admin
    _redact_notification_group_for_principal(principal, owner_admin, out)
    out["can_view"] = bool(can_view)
    out["can_operate"] = bool(can_operate)
    cat = _get_ota_firmware_catalog()
    out["firmware_hint"] = _firmware_update_hint_for_current_in_catalog(str(out.get("fw") or ""), cat)
    return out


@app.get("/devices/{device_id}/siblings-preview")
def preview_device_siblings(
    device_id: str,
    include_source: bool = Query(default=False),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Debug helper: resolve current sibling fan-out targets for a device."""
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(zone,''), IFNULL(notification_group,'') FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    zone = str(row[0] or "").strip()
    group_key = str(row[1] or "").strip()
    assert_zone_for_device(principal, zone)
    owner_admin = _lookup_owner_admin(device_id)
    if not _principal_tenant_owns_device(principal, owner_admin):
        raise HTTPException(
            status_code=403,
            detail="sibling preview is available to the owning tenant only",
        )
    targets, eligible_total = _tenant_siblings(
        owner_admin,
        device_id,
        source_zone=zone,
        source_group=group_key,
        include_source=bool(include_source),
    )
    out: dict[str, Any] = {
        "ok": True,
        "device_id": device_id,
        "zone": zone,
        "notification_group": group_key,
        "fanout_enabled": bool(group_key),
        "target_count": len(targets),
        "eligible_total": eligible_total,
        "fanout_capped": eligible_total > len(targets),
        "fanout_max": ALARM_FANOUT_MAX_TARGETS,
        "targets": [{"device_id": did, "zone": z} for did, z in targets],
    }
    if principal.role == "superadmin":
        out["owner_admin"] = owner_admin or ""
    return out


class DeviceDisplayLabelBody(BaseModel):
    display_label: str = Field(default="", max_length=80)


class DeviceProfileBody(BaseModel):
    display_label: Optional[str] = Field(default=None, max_length=80)
    notification_group: Optional[str] = Field(default=None, max_length=80)


class DeviceBulkProfileBody(BaseModel):
    device_ids: list[str] = Field(default_factory=list, min_length=1, max_length=500)
    set_notification_group: bool = False
    notification_group: Optional[str] = Field(default=None, max_length=80)
    set_zone_override: bool = False
    zone_override: Optional[str] = Field(default=None, max_length=31)
    clear_zone_override: bool = False

# (GroupCardSettingsBody moved to routers/group_cards.py — see the
# corresponding `from routers.group_cards import ...` block below.)

# (DeviceShareRequest moved to routers/device_shares.py — see the
# corresponding `from routers.device_shares import ...` block below.)

# =====================================================================
#  Group cards (siren fan-out by notification_group)
# =====================================================================

# Phase-14 modularization: the eleven group-card routes (six canonical
# plus five /api/* mirrors), the GroupCardSettingsBody schema, and the
# four group-card helpers (_delete_group_card_impl, _group_owner_scope,
# _group_settings_defaults, _group_devices_with_owner) now live in
# routers/group_cards.py. That module late-binds the cross-feature
# helpers (_principal_tenant_owns_device, _lookup_owner_admin,
# _log_signal_trigger, _device_access_flags, publish_command, …) from
# `app` so we don't duplicate them here.
from routers.group_cards import router as _group_cards_router  # noqa: E402

app.include_router(_group_cards_router)

def _apply_device_profile_update(
    device_id: str,
    principal: Principal,
    body: DeviceProfileBody,
) -> dict[str, Any]:
    if body.display_label is None and body.notification_group is None:
        raise HTTPException(
            status_code=400,
            detail="provide at least one of display_label, notification_group",
        )
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row_owner = _lookup_owner_admin(device_id) or ""
    if body.notification_group is not None and not _principal_tenant_owns_device(principal, row_owner):
        raise HTTPException(
            status_code=403,
            detail="only the owning tenant may change notification_group; shared access is device-scoped",
        )
    sets: list[str] = []
    args: list[Any] = []
    if body.display_label is not None:
        sets.append("display_label = ?")
        args.append(body.display_label.strip())
    if body.notification_group is not None:
        sets.append("notification_group = ?")
        args.append(body.notification_group.strip())
    # Do not touch device_state.updated_at here: it is used for MQTT freshness
    # (overview presence, dashboard isOnline). Profile edits are not device traffic.
    args.append(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT zone, display_label, notification_group FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        zr = cur.fetchone()
        if not zr:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
        old_label = (str(zr["display_label"]).strip() if zr["display_label"] is not None else "")
        old_group = (str(zr["notification_group"]).strip() if zr["notification_group"] is not None else "")
        cur.execute(
            f"UPDATE device_state SET {', '.join(sets)} WHERE device_id = ?",
            tuple(args),
        )
        conn.commit()
        conn.close()
    new_label = (body.display_label.strip() if body.display_label is not None else old_label)
    new_group = (body.notification_group.strip() if body.notification_group is not None else old_group)
    group_changed = body.notification_group is not None and new_group != old_group
    label_changed = body.display_label is not None and new_label != old_label
    cache_invalidate("devices")
    cache_invalidate("overview")
    emit_event(
        level="info",
        category="device",
        event_type="device.profile",
        summary=f"device profile updated {device_id}",
        actor=principal.username,
        target=device_id,
        device_id=device_id,
        detail={
            "display_label": new_label,
            "notification_group": new_group,
            "previous_display_label": old_label,
            "previous_notification_group": old_group,
            "display_label_changed": label_changed,
            "notification_group_changed": group_changed,
        },
    )
    out: dict[str, Any] = {"ok": True, "device_id": device_id}
    if body.display_label is not None:
        out["display_label"] = new_label
    if body.notification_group is not None:
        out["notification_group"] = new_group
    return out


@app.patch("/devices/{device_id}/profile")
def patch_device_profile(
    device_id: str,
    body: DeviceProfileBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _apply_device_profile_update(device_id, principal, body)


@app.patch("/devices/{device_id}/display-label")
def patch_device_display_label(
    device_id: str,
    body: DeviceDisplayLabelBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Legacy: only updates display_label."""
    return _apply_device_profile_update(
        device_id,
        principal,
        DeviceProfileBody(display_label=body.display_label, notification_group=None),
    )


@app.post("/devices/bulk/profile")
def bulk_patch_device_profile(
    body: DeviceBulkProfileBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Bulk profile update for production operations (group + zone override)."""
    assert_min_role(principal, "user")
    ids = []
    seen = set()
    for raw in body.device_ids:
        did = str(raw or "").strip()
        if not did or did in seen:
            continue
        seen.add(did)
        ids.append(did)
    if not ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    if len(ids) > 500:
        raise HTTPException(status_code=400, detail="too many device_ids (max 500)")
    if not body.set_notification_group and not body.set_zone_override and not body.clear_zone_override:
        raise HTTPException(status_code=400, detail="no bulk operation selected")
    if body.set_zone_override and body.clear_zone_override:
        raise HTTPException(status_code=400, detail="set_zone_override and clear_zone_override are mutually exclusive")
    for did in ids:
        assert_device_owner(principal, did)
        if body.set_notification_group:
            o = _lookup_owner_admin(did) or ""
            if not _principal_tenant_owns_device(principal, o):
                raise HTTPException(
                    status_code=403,
                    detail=f"notification_group bulk-set denied for shared device {did} (owner-tenant only)",
                )
    notif_group = (str(body.notification_group or "").strip() if body.set_notification_group else None)
    zone_override = (str(body.zone_override or "").strip() if body.set_zone_override else None)
    if body.set_zone_override and not zone_override:
        raise HTTPException(status_code=400, detail="zone_override cannot be empty when set_zone_override=true")
    changed_group = 0
    changed_zone = 0
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for did in ids:
            if body.set_notification_group:
                cur.execute(
                    "UPDATE device_state SET notification_group = ? WHERE device_id = ?",
                    (notif_group, did),
                )
                changed_group += int(cur.rowcount or 0)
            if body.set_zone_override:
                cur.execute(
                    """
                    INSERT INTO device_zone_overrides (device_id, zone, updated_by, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                      zone = excluded.zone,
                      updated_by = excluded.updated_by,
                      updated_at = excluded.updated_at
                    """,
                    (did, zone_override, principal.username, now),
                )
                cur.execute("UPDATE device_state SET zone = ? WHERE device_id = ?", (zone_override, did))
                changed_zone += int(cur.rowcount or 0)
            if body.clear_zone_override:
                cur.execute("DELETE FROM device_zone_overrides WHERE device_id = ?", (did,))
                cur.execute(
                    """
                    SELECT last_status_json, last_heartbeat_json, last_ack_json, last_event_json
                    FROM device_state WHERE device_id = ?
                    """,
                    (did,),
                )
                zrow = cur.fetchone()
                zone_from_payload = _extract_zone_from_device_state_row(zrow)
                cur.execute("UPDATE device_state SET zone = ? WHERE device_id = ?", (zone_from_payload, did))
                changed_zone += int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    emit_event(
        level="info",
        category="device",
        event_type="device.bulk_profile",
        summary=f"bulk profile update {len(ids)} device(s)",
        actor=principal.username,
        target="devices",
        detail={
            "count": len(ids),
            "set_notification_group": bool(body.set_notification_group),
            "notification_group": notif_group if body.set_notification_group else None,
            "set_zone_override": bool(body.set_zone_override),
            "zone_override": zone_override if body.set_zone_override else None,
            "clear_zone_override": bool(body.clear_zone_override),
            "changed_group_rows": changed_group,
            "changed_zone_rows": changed_zone,
        },
    )
    return {
        "ok": True,
        "count": len(ids),
        "changed_group_rows": changed_group,
        "changed_zone_rows": changed_zone,
        "set_notification_group": bool(body.set_notification_group),
        "set_zone_override": bool(body.set_zone_override),
        "clear_zone_override": bool(body.clear_zone_override),
    }


# =====================================================================
#  Device sharing / ACL admin
# =====================================================================

# Phase-16 modularization: the four /admin/(devices/{id}/)?share(s)?/*
# routes plus the DeviceShareRequest schema now live in
# routers/device_shares.py. Late-binds assert_device_owner +
# require_capability + require_principal from `app`.
from routers.device_shares import router as _device_shares_router  # noqa: E402

app.include_router(_device_shares_router)

@app.get("/devices/{device_id}/messages")
def get_device_messages(
    device_id: str,
    channel: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")

    query = """
        SELECT id, topic, channel, device_id, payload_json, ts_device, ts_received
        FROM messages
        WHERE device_id = ?
    """
    args: list[Any] = [device_id]
    if channel:
        query += " AND channel = ?"
        args.append(channel)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    for r in rows:
        r["payload"] = json.loads(r.pop("payload_json"))
    return {"items": rows}


def generate_device_credentials(device_id: str) -> tuple[str, str, str]:
    if (not ENFORCE_PER_DEVICE_CREDS) and PROVISION_USE_SHARED_MQTT_CREDS and MQTT_USERNAME:
        mqtt_username = MQTT_USERNAME
        mqtt_password = MQTT_PASSWORD
    else:
        suffix = device_id.replace("-", "").lower()[:12]
        mqtt_username = f"dev_{suffix}"
        mqtt_password = secrets.token_urlsafe(24)
    cmd_key = secrets.token_hex(8).upper()
    return mqtt_username, mqtt_password, cmd_key


def get_cmd_key_for_device(device_id: str) -> str:
    """Resolve signing key for MQTT /cmd. Match credentials case-insensitively — claim may
    have stored mixed-case device_id while the console route uses uppercase (or vice versa);
    falling back to CMD_AUTH_KEY then breaks every Danger-zone /commands publish."""
    raw = str(device_id or "").strip()
    if not raw:
        return str(CMD_AUTH_KEY or "").strip().upper()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT cmd_key FROM provisioned_credentials WHERE UPPER(device_id) = UPPER(?) LIMIT 1",
            (raw,),
        )
        row = cur.fetchone()
        conn.close()
    if row and row["cmd_key"]:
        return str(row["cmd_key"]).strip().upper()
    return str(CMD_AUTH_KEY or "").strip().upper()


def get_cmd_keys_for_devices(device_ids: list[str]) -> dict[str, str]:
    """Batch-resolve MQTT /cmd signing keys. Keys are ``UPPER(device_id)`` → cmd_key."""
    ids = sorted({str(x or "").strip().upper() for x in device_ids if str(x or "").strip()})
    if not ids:
        return {}
    out: dict[str, str] = {}
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        ph = ",".join(["?"] * len(ids))
        cur.execute(
            f"SELECT UPPER(device_id) AS u, cmd_key FROM provisioned_credentials WHERE UPPER(device_id) IN ({ph})",
            tuple(ids),
        )
        for r in cur.fetchall():
            ck = str(r["cmd_key"] or "").strip().upper()
            if ck:
                out[str(r["u"])] = ck
        conn.close()
    return out


def publish_bootstrap_claim(
    mac_nocolon: str,
    claim_nonce: str,
    device_id: str,
    zone: str,
    qr_code: str,
    mqtt_username: str,
    mqtt_password: str,
    cmd_key: str,
) -> None:
    global mqtt_client
    if mqtt_client is None:
        raise HTTPException(status_code=500, detail="mqtt client not ready")

    topic = f"{TOPIC_ROOT}/bootstrap/assign/{mac_nocolon}"
    payload = {
        "type": "bootstrap.assign",
        "bind_key": BOOTSTRAP_BIND_KEY,
        "mac_nocolon": mac_nocolon,
        "claim_nonce": claim_nonce,
        "device_id": device_id,
        "zone": zone,
        "qr_code": qr_code,
        "mqtt_username": mqtt_username,
        "mqtt_password": mqtt_password,
        "cmd_key": cmd_key,
        "ts": int(time.time()),
    }
    info = mqtt_client.publish(topic, json.dumps(payload, ensure_ascii=True), qos=1)
    info.wait_for_publish(timeout=3.0)
    if not info.is_published():
        raise HTTPException(status_code=502, detail="bootstrap publish failed")


MQTT_PUBLISH_WAIT_MS = max(0, min(5000, int(os.getenv("MQTT_PUBLISH_WAIT_MS", "800"))))
# TTL (seconds) for the idempotency cache. Must be long enough to eat a double-click
# or a rushed retry (UI, proxy, accidental re-post), short enough to not hide a
# genuinely re-issued operator action minutes later.
PUBLISH_DEDUPE_TTL_S = max(5, min(120, int(os.getenv("PUBLISH_DEDUPE_TTL_S", "30"))))

# In-memory idempotency cache: { dedupe_key -> (cmd_id, expire_epoch_s) }.
# Process-local only (ok: multi-worker deployments should use sticky sessions
# for the admin dashboard; background fan-out has its own wall-clock cap).
_publish_dedupe_cache: dict[str, tuple[str, float]] = {}
_publish_dedupe_lock = threading.Lock()


def _publish_dedupe_get(key: str) -> Optional[str]:
    if not key:
        return None
    now = time.time()
    with _publish_dedupe_lock:
        # Opportunistic prune so the cache can't grow unbounded under a flood.
        if len(_publish_dedupe_cache) > 2048:
            expired = [k for k, (_cid, exp) in _publish_dedupe_cache.items() if exp <= now]
            for k in expired:
                _publish_dedupe_cache.pop(k, None)
        entry = _publish_dedupe_cache.get(key)
        if not entry:
            return None
        cid, exp = entry
        if exp <= now:
            _publish_dedupe_cache.pop(key, None)
            return None
        return cid


def _publish_dedupe_set(key: str, cmd_id: str, ttl_s: float) -> None:
    if not key or not cmd_id:
        return
    with _publish_dedupe_lock:
        _publish_dedupe_cache[key] = (cmd_id, time.time() + max(1.0, ttl_s))


# ─────────────────────────────────────────────────────────────────────────
# cmd_queue helpers
# MQTT is ALWAYS the primary delivery channel. These functions persist a
# ledger row per published command so that:
#   * Offline devices can pick up unacked commands via an HTTP GET pull
#     (see /device-http/*/commands/pending). Firmware uses this only when
#     MQTT has been disconnected past COMMAND_HTTP_FALLBACK_ARM_MS seconds —
#     it does not compete with MQTT for live connections.
#   * The ACK flow can mark rows acked regardless of which channel delivered
#     or which channel the ACK came back on.
#   * Sibling fan-out can be replayed to a device that came online after
#     the fan-out happened (see group offline replay).
# TTL default is 24h so a device that was offline overnight still gets its
# commands on reconnect, but ancient commands don't pile up.
# ─────────────────────────────────────────────────────────────────────────
CMD_QUEUE_TTL_S = int(os.getenv("CROC_CMD_QUEUE_TTL_S", "86400"))
# Commands we never persist (would balloon the table without offline semantics):
#   presence probes — transient per-device keepalive only
#   debug / dev-only — no offline retry value
_CMD_QUEUE_SKIP_VERBS = {"presence_probe"}


def _cmd_queue_enqueue(
    *,
    cmd_id: str,
    device_id: str,
    cmd: str,
    params: dict[str, Any],
    target_id: str,
    proto: int,
    cmd_key: str,
    delivered_via: str,
    delivered_at: Optional[str],
) -> None:
    """Insert a row into cmd_queue right after a publish. Best-effort: any
    DB error is logged and swallowed so a hiccup in the queue never blocks
    the MQTT publish that already succeeded."""
    if cmd in _CMD_QUEUE_SKIP_VERBS:
        return
    if not device_id:
        return
    now = utc_now_iso()
    try:
        expires_at = (
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=CMD_QUEUE_TTL_S)
        ).isoformat(timespec="seconds")
    except Exception:
        expires_at = None
    try:
        payload = json.dumps(params or {}, ensure_ascii=True)
    except Exception:
        payload = "{}"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT OR REPLACE INTO cmd_queue (
                    cmd_id, device_id, cmd, params_json, target_id, proto, cmd_key,
                    created_at, expires_at, delivered_via, delivered_at, acked_at, ack_ok, ack_detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    cmd_id, device_id, cmd, payload, target_id, int(proto or 0), cmd_key or "",
                    now, expires_at, delivered_via, delivered_at,
                ),
            )
            conn.commit()
        except Exception as exc:
            logger.warning("cmd_queue enqueue failed cmd=%s device=%s err=%s", cmd, device_id, exc)
        finally:
            conn.close()


def _cmd_queue_mark_acked(cmd_id: str, *, ok: bool, detail: str = "") -> bool:
    """Clear the pending row for ``cmd_id`` on ACK arrival (from ANY channel).
    Returns True if a row was actually updated. No-op and False if cmd_id
    wasn't in the queue (older/expired cmd, or from a sender that bypassed
    the queue — e.g. legacy code paths that publish raw)."""
    if not cmd_id:
        return False
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "UPDATE cmd_queue SET acked_at = ?, ack_ok = ?, ack_detail = ? "
                "WHERE cmd_id = ? AND acked_at IS NULL",
                (now, 1 if ok else 0, str(detail or "")[:200], cmd_id),
            )
            updated = cur.rowcount
            conn.commit()
            return bool(updated)
        except Exception as exc:
            logger.warning("cmd_queue ack update failed cmd_id=%s err=%s", cmd_id, exc)
            return False
        finally:
            conn.close()


def _cmd_queue_pending_for_device(device_id: str, limit: int = 32) -> list[dict[str, Any]]:
    """Return un-acked, un-expired commands for ``device_id`` (oldest first).
    This is what the HTTP backup pull endpoint returns. Rows with
    ``expires_at < now`` are silently filtered — the cleanup pass handles
    their removal on a slower cadence."""
    if not device_id:
        return []
    now = utc_now_iso()
    out: list[dict[str, Any]] = []
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT cmd_id, device_id, cmd, params_json, target_id, proto, cmd_key,
                       created_at, delivered_via, delivered_at
                FROM cmd_queue
                WHERE device_id = ?
                  AND acked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (device_id, now, int(limit)),
            )
            for r in cur.fetchall():
                try:
                    params = json.loads(r["params_json"] or "{}")
                except Exception:
                    params = {}
                out.append({
                    "cmd_id": r["cmd_id"],
                    "device_id": r["device_id"],
                    "cmd": r["cmd"],
                    "params": params,
                    "target_id": r["target_id"] or "",
                    "proto": int(r["proto"] or 0),
                    "cmd_key": r["cmd_key"] or "",
                    "created_at": r["created_at"],
                    "delivered_via": r["delivered_via"] or "",
                    "delivered_at": r["delivered_at"] or "",
                })
        except Exception as exc:
            logger.warning("cmd_queue pending scan failed device=%s err=%s", device_id, exc)
        finally:
            conn.close()
    return out


def _cmd_queue_pending_counts(device_ids: list[str] | None = None) -> dict[str, int]:
    """Return ``{device_id: pending_count}`` for the supplied ids (or all
    devices with at least one unacked entry when ``device_ids`` is None).

    Used by the dashboard devices list to surface a "X pending" chip next to
    devices that have queued MQTT commands waiting for delivery/ack. The
    query is O(N) over the un-acked slice of ``cmd_queue``, which is small
    in steady state (most entries get acked within a few seconds)."""
    now = utc_now_iso()
    out: dict[str, int] = {}
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        try:
            if device_ids:
                # SQLite has a default compiled-in 999-parameter cap; chunk so we
                # stay safely below it on large fleets.
                chunk = 500
                for i in range(0, len(device_ids), chunk):
                    batch = device_ids[i:i + chunk]
                    placeholders = ",".join(["?"] * len(batch))
                    cur.execute(
                        f"""
                        SELECT device_id, COUNT(*) AS n
                        FROM cmd_queue
                        WHERE acked_at IS NULL
                          AND (expires_at IS NULL OR expires_at > ?)
                          AND device_id IN ({placeholders})
                        GROUP BY device_id
                        """,
                        (now, *batch),
                    )
                    for r in cur.fetchall():
                        out[r["device_id"]] = int(r["n"])
            else:
                cur.execute(
                    """
                    SELECT device_id, COUNT(*) AS n
                    FROM cmd_queue
                    WHERE acked_at IS NULL
                      AND (expires_at IS NULL OR expires_at > ?)
                    GROUP BY device_id
                    """,
                    (now,),
                )
                for r in cur.fetchall():
                    out[r["device_id"]] = int(r["n"])
        except Exception as exc:
            logger.warning("cmd_queue pending counts failed: %s", exc)
        finally:
            conn.close()
    return out


# Gap past which a device is treated as "came back from offline" — a
# fresh heartbeat after this much silence triggers a replay of its
# unacked cmd_queue entries. Tuned to cover a typical Wi-Fi drop
# (30–60s) without firing on every ordinary heartbeat skew.
CMD_QUEUE_REPLAY_GAP_S = int(os.getenv("CROC_CMD_QUEUE_REPLAY_GAP_S", "60"))
# Per-device debounce so a noisy flap-up does not trigger replay on every
# status frame. ``device_id -> epoch_s`` of last replay.
_cmd_queue_replay_last: dict[str, float] = {}
_cmd_queue_replay_lock = threading.Lock()


def _maybe_replay_queue_on_reconnect(device_id: str, prev_updated_at: Optional[str]) -> None:
    """Called when a fresh heartbeat/status lands. If the device was
    silent for longer than CMD_QUEUE_REPLAY_GAP_S, re-publish any
    unacked cmd_queue entries over MQTT so a sibling that was offline
    during fan-out actually receives the broadcast."""
    if not device_id or not prev_updated_at:
        return
    try:
        prev = _parse_iso(prev_updated_at)
    except Exception:
        return
    if not prev:
        return
    gap_s = (datetime.datetime.now(datetime.UTC) - prev).total_seconds()
    if gap_s < float(CMD_QUEUE_REPLAY_GAP_S):
        return
    now_epoch = time.time()
    with _cmd_queue_replay_lock:
        last = _cmd_queue_replay_last.get(device_id, 0.0)
        if now_epoch - last < 15.0:
            return
        _cmd_queue_replay_last[device_id] = now_epoch
    pending = _cmd_queue_pending_for_device(device_id, limit=16)
    if not pending:
        return
    logger.info(
        "cmd_queue replay: device=%s gap=%.1fs pending=%d",
        device_id, gap_s, len(pending),
    )
    for entry in pending:
        try:
            publish_command(
                topic=f"{TOPIC_ROOT}/{device_id}/cmd",
                cmd=str(entry["cmd"]),
                params=entry.get("params") or {},
                target_id=str(entry.get("target_id") or device_id),
                proto=int(entry.get("proto") or CMD_PROTO),
                cmd_key=str(entry.get("cmd_key") or ""),
                wait_publish=False,
                persist=False,
            )
        except Exception as exc:
            logger.warning(
                "cmd_queue replay publish failed device=%s cmd_id=%s err=%s",
                device_id, entry.get("cmd_id"), exc,
            )


def _cmd_queue_cleanup_expired(max_rows: int = 500) -> int:
    """Periodic purge of expired + stale acked rows. Called from the
    scheduled_commands worker tick so we don't add another thread."""
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            # Drop expired-and-unacked first (true queue items).
            cur.execute(
                "DELETE FROM cmd_queue WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            # Drop acked rows older than the TTL — at some point the ledger
            # stops being useful and just bloats the table.
            cur.execute(
                "DELETE FROM cmd_queue WHERE acked_at IS NOT NULL AND created_at < ?",
                ((
                    datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=CMD_QUEUE_TTL_S)
                ).isoformat(timespec="seconds"),),
            )
            deleted = cur.rowcount
            conn.commit()
            return int(deleted or 0)
        except Exception as exc:
            logger.warning("cmd_queue cleanup failed: %s", exc)
            return 0
        finally:
            conn.close()


def publish_command(
    topic: str,
    cmd: str,
    params: dict[str, Any],
    target_id: str,
    proto: int,
    cmd_key: str,
    *,
    wait_publish: bool = True,
    dedupe_key: Optional[str] = None,
    dedupe_ttl_s: Optional[float] = None,
    persist: bool = True,
) -> str:
    """Publish a /cmd frame. Returns generated ``cmd_id`` (so callers can wait on ACK by id).

    Does **not** block for retries. If the broker is disconnected, raises 503 immediately
    instead of stalling the caller (fan-out and HTTP handlers must stay responsive).
    When ``wait_publish=True`` (default), briefly waits for paho to drain (``MQTT_PUBLISH_WAIT_MS``)
    so QoS 1 can start delivery; callers that do fan-out in a worker pool can pass False.

    ``dedupe_key`` makes the publish idempotent over a short TTL: if the same key is
    re-used within the TTL, the previously generated ``cmd_id`` is returned and
    **no new MQTT message is published** (e.g. double-clicks on OTA/reboot).
    ``unclaim_reset`` is sent **without** dedupe so a repeated unlink can publish
    a fresh frame; firmware handles it idempotently.
    """
    global mqtt_client
    if dedupe_key:
        cached = _publish_dedupe_get(dedupe_key)
        if cached:
            logger.info("publish_command dedupe hit: %s -> %s", dedupe_key, cached)
            return cached
    if mqtt_client is None:
        raise HTTPException(status_code=503, detail="mqtt client not ready")
    if not mqtt_connected:
        raise HTTPException(status_code=503, detail="mqtt broker disconnected")
    cmd_id = str(uuid.uuid4())
    payload = {
        "proto": proto,
        "key": cmd_key,
        "target_id": target_id,
        "cmd": cmd,
        "params": params,
        "cmd_id": cmd_id,
    }
    body = json.dumps(payload, ensure_ascii=True)
    try:
        info = mqtt_client.publish(topic, body, qos=1)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"mqtt publish error: {exc}")
    if getattr(info, "rc", 0) not in (0, None):
        raise HTTPException(status_code=502, detail=f"mqtt publish rc={info.rc}")
    publish_delivered_at: Optional[str] = None
    if wait_publish and MQTT_PUBLISH_WAIT_MS > 0:
        try:
            info.wait_for_publish(timeout=max(0.05, MQTT_PUBLISH_WAIT_MS / 1000.0))
            publish_delivered_at = utc_now_iso()
        except Exception:
            pass
    if dedupe_key:
        _publish_dedupe_set(dedupe_key, cmd_id, float(dedupe_ttl_s or PUBLISH_DEDUPE_TTL_S))
    # Ledger-only (does not gate success). target_id is the device the
    # cmd_key binds to, which equals device_id for single-target commands;
    # topic parsing keeps it honest for future indirect paths.
    if persist:
        dev_id_from_topic = ""
        try:
            # Topic shape: <TOPIC_ROOT>/<device_id>/cmd → device_id is the
            # second-to-last segment. Cheap and robust against topic churn.
            parts = topic.split("/")
            if len(parts) >= 2 and parts[-1] == "cmd":
                dev_id_from_topic = parts[-2]
        except Exception:
            dev_id_from_topic = ""
        _cmd_queue_enqueue(
            cmd_id=cmd_id,
            device_id=dev_id_from_topic or target_id,
            cmd=cmd,
            params=params or {},
            target_id=target_id,
            proto=proto,
            cmd_key=cmd_key or "",
            delivered_via="mqtt",
            delivered_at=publish_delivered_at,
        )
    return cmd_id


def enqueue_scheduled_command(device_id: str, cmd: str, params: dict[str, Any], target_id: str, proto: int, execute_at_ts: int) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scheduled_commands (
                device_id, cmd, params_json, target_id, proto, execute_at_ts, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                device_id,
                cmd,
                json.dumps(params, ensure_ascii=True),
                target_id,
                proto,
                execute_at_ts,
                utc_now_iso(),
            ),
        )
        job_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    return job_id


def resolve_target_devices(device_ids: list[str], principal: Optional[Principal] = None) -> list[str]:
    unique = sorted(set([d for d in device_ids if d]))
    zs, za = zone_sql_suffix(principal) if principal else ("", [])
    osf, osa = ("", [])
    if principal and not principal.is_superadmin():
        if principal.role == "admin":
            osf = " AND o.owner_admin = ? "
            osa = [principal.username]
        else:
            manager = get_manager_admin(principal.username)
            if not manager:
                osf = " AND 1=0 "
                osa = []
            else:
                osf = " AND o.owner_admin = ? "
                osa = [manager]
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if unique:
            placeholders = ",".join(["?"] * len(unique))
            cur.execute(
                f"""
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN revoked_devices r ON d.device_id = r.device_id
                LEFT JOIN device_ownership o ON d.device_id = o.device_id
                WHERE d.device_id IN ({placeholders}){zs} {osf} AND r.device_id IS NULL
                """,
                tuple(unique) + tuple(za) + tuple(osa),
            )
        else:
            cur.execute(
                f"""
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN revoked_devices r ON d.device_id = r.device_id
                LEFT JOIN device_ownership o ON d.device_id = o.device_id
                WHERE 1=1 {zs} {osf} AND r.device_id IS NULL
                """,
                tuple(za) + tuple(osa),
            )
        rows = cur.fetchall()
        conn.close()
    out: list[str] = []
    for r in rows:
        did = str(r["device_id"])
        z = str(r["zone"]) if r["zone"] is not None else ""
        if principal is None or principal.is_superadmin() or principal.has_all_zones() or principal.zone_ok(z):
            out.append(did)
    if len(out) > MAX_BULK_TARGETS:
        raise HTTPException(status_code=413, detail=f"target set too large (> {MAX_BULK_TARGETS})")
    return out


def scheduler_loop() -> None:
    next_cleanup_at = time.time() + 60
    next_probe_at = time.time() + 30  # kick probe worker ~30s after boot
    next_events_retention_at = time.time() + 300  # first retention pass ~5 min after boot
    next_pwd_prune_at = time.time() + 900
    next_pending_claim_prune_at = time.time() + 120
    while not scheduler_stop.is_set():
        now_ts = int(time.time())
        jobs: list[sqlite3.Row] = []
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, device_id, cmd, params_json, target_id, proto
                FROM scheduled_commands
                WHERE status = 'pending' AND execute_at_ts <= ?
                ORDER BY id ASC
                LIMIT 50
                """,
                (now_ts,),
            )
            jobs = cur.fetchall()
            conn.close()

        for job in jobs:
            jid = int(job["id"])
            try:
                topic = f"{TOPIC_ROOT}/{job['device_id']}/cmd"
                publish_command(
                    topic=topic,
                    cmd=str(job["cmd"]),
                    params=json.loads(str(job["params_json"])),
                    target_id=str(job["target_id"]),
                    proto=int(job["proto"]),
                    cmd_key=get_cmd_key_for_device(str(job["device_id"])),
                )
                with db_lock:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scheduled_commands SET status='done', executed_at=? WHERE id=?",
                        (utc_now_iso(), jid),
                    )
                    conn.commit()
                    conn.close()
            except Exception as exc:
                logger.exception("scheduled command failed id=%s err=%s", jid, exc)
                with db_lock:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scheduled_commands SET status='failed', executed_at=? WHERE id=?",
                        (utc_now_iso(), jid),
                    )
                    conn.commit()
                    conn.close()

        try:
            _fail_stale_scheduled_commands(now_ts)
        except Exception as exc:
            logger.warning("stale scheduled_commands cleanup failed: %s", exc)
        try:
            _expire_presence_probes_waiting_ack()
        except Exception as exc:
            logger.warning("presence probe ack expiry failed: %s", exc)
        try:
            _auto_reconcile_tick()
        except Exception as exc:
            logger.warning("auto reconcile tick failed: %s", exc)
        try:
            _cmd_queue_cleanup_expired()
        except Exception as exc:
            logger.warning("cmd_queue cleanup tick failed: %s", exc)

        now = time.time()
        if now >= next_cleanup_at:
            cutoff = datetime.fromtimestamp(now - (MESSAGE_RETENTION_DAYS * 86400), tz=timezone.utc).isoformat()
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("DELETE FROM messages WHERE ts_received < ?", (cutoff,))
                cur.execute(
                    """
                    DELETE FROM scheduled_commands
                    WHERE status IN ('done','failed') AND executed_at IS NOT NULL AND executed_at < ?
                    """,
                    (cutoff,),
                )
                conn.commit()
                conn.close()
            next_cleanup_at = now + 3600

        if now >= next_probe_at:
            try:
                _presence_probe_tick()
            except Exception as exc:
                logger.warning("presence probe tick failed: %s", exc)
            next_probe_at = now + max(30, PRESENCE_PROBE_SCAN_SECONDS)

        if now >= next_events_retention_at:
            try:
                _events_retention_tick()
            except Exception as exc:
                logger.warning("events retention tick failed: %s", exc)
            next_events_retention_at = now + max(300, EVENT_RETENTION_SCAN_SECONDS)

        if now >= next_pwd_prune_at:
            try:
                _prune_password_reset_tokens()
            except Exception as exc:
                logger.warning("password reset token prune failed: %s", exc)
            next_pwd_prune_at = now + 21600  # every 6h

        if now >= next_pending_claim_prune_at:
            try:
                _prune_stale_pending_claims()
            except Exception as exc:
                logger.warning("pending_claim prune failed: %s", exc)
            next_pending_claim_prune_at = now + 900

        scheduler_stop.wait(SCHEDULER_POLL_SECONDS)


@app.get("/provision/pending")
def list_pending_claims(
    principal: Principal = Depends(require_principal),
    q: Optional[str] = Query(default=None, max_length=64, description="Filter by MAC (no colon) or QR substring"),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role != "superadmin":
        raise HTTPException(status_code=403, detail="pending claim list is superadmin-only")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if q and q.strip():
            like = f"%{q.strip()}%"
            like_mac = f"%{q.strip().upper().replace(':', '').replace('-', '')}%"
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                WHERE (mac_nocolon LIKE ? OR UPPER(mac) LIKE ? OR IFNULL(qr_code,'') LIKE ?)
                  AND NOT EXISTS (
                    SELECT 1 FROM provisioned_credentials pc
                    WHERE pc.device_id = pending_claims.proposed_device_id
                  )
                ORDER BY last_seen_at DESC
                """,
                (like_mac, like, like),
            )
        else:
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                WHERE NOT EXISTS (
                  SELECT 1 FROM provisioned_credentials pc
                  WHERE pc.device_id = pending_claims.proposed_device_id
                )
                ORDER BY last_seen_at DESC
                """
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.post("/provision/claim")
def claim_device(req: ClaimDeviceRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    mac_nocolon = req.mac_nocolon.upper()
    if len(mac_nocolon) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    if not re.fullmatch(DEVICE_ID_REGEX, req.device_id.strip().upper()):
        raise HTTPException(status_code=400, detail="device_id format rejected by policy")
    if not BOOTSTRAP_BIND_KEY:
        raise HTTPException(status_code=500, detail="server BOOTSTRAP_BIND_KEY not configured")
    did_norm = req.device_id.strip().upper()
    ensure_not_revoked(did_norm)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM pending_claims WHERE mac_nocolon = ?", (mac_nocolon,))
        pending = cur.fetchone()
        if not pending:
            conn.close()
            raise HTTPException(status_code=404, detail="pending device not found")
        cur.execute(
            "SELECT mac_nocolon FROM provisioned_credentials WHERE UPPER(device_id) = UPPER(?) LIMIT 1",
            (did_norm,),
        )
        exist_id = cur.fetchone()
        if exist_id:
            conn.close()
            raise HTTPException(status_code=409, detail="device_id already registered")
        cur.execute(
            "SELECT device_id FROM provisioned_credentials WHERE mac_nocolon = ?",
            (mac_nocolon,),
        )
        existing = cur.fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=409, detail="device already claimed")

        claim_nonce = str(pending["claim_nonce"])
        qr_code = req.qr_code if req.qr_code else (str(pending["qr_code"] or "") or f"CROC-{mac_nocolon}")
        if req.qr_code:
            if not re.fullmatch(QR_CODE_REGEX, req.qr_code):
                conn.close()
                raise HTTPException(status_code=400, detail="qr_code format rejected by policy")
            if QR_SIGN_SECRET and not verify_qr_signature(req.qr_code):
                conn.close()
                raise HTTPException(status_code=401, detail="qr_code signature invalid")
        if ENFORCE_DEVICE_CHALLENGE:
            cur.execute(
                """
                SELECT id, verified_at, used
                FROM provision_challenges
                WHERE mac_nocolon = ? AND device_id = ? AND expires_at_ts >= ?
                ORDER BY id DESC LIMIT 1
                """,
                (mac_nocolon, did_norm, int(time.time())),
            )
            ch = cur.fetchone()
            if not ch or not ch["verified_at"] or int(ch["used"]) == 1:
                conn.close()
                raise HTTPException(status_code=412, detail="verified device challenge required before claim")
        mqtt_username, mqtt_password, cmd_key = generate_device_credentials(did_norm)

        cur.execute(
            """
            INSERT INTO provisioned_credentials (
                device_id, mac_nocolon, mqtt_username, mqtt_password, cmd_key, zone, qr_code, claimed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                mac_nocolon = excluded.mac_nocolon,
                mqtt_username = excluded.mqtt_username,
                mqtt_password = excluded.mqtt_password,
                cmd_key = excluded.cmd_key,
                zone = excluded.zone,
                qr_code = excluded.qr_code,
                claimed_at = excluded.claimed_at
            """,
            (
                did_norm,
                mac_nocolon,
                mqtt_username,
                mqtt_password,
                cmd_key,
                req.zone,
                qr_code,
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()
    owner_admin = principal.username
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_ownership (device_id, owner_admin, assigned_by, assigned_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
              owner_admin = excluded.owner_admin,
              assigned_by = excluded.assigned_by,
              assigned_at = excluded.assigned_at
            """,
            (did_norm, owner_admin, principal.username, utc_now_iso()),
        )
        # Stale device_state from a previous tenant/owner: clear profile fields on (re)claim
        cur.execute(
            "UPDATE device_state SET display_label = '', notification_group = '' WHERE device_id = ?",
            (did_norm,),
        )
        conn.commit()
        conn.close()
        cache_invalidate("devices")
        cache_invalidate("overview")
    if ENFORCE_DEVICE_CHALLENGE:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE provision_challenges SET used = 1
                WHERE mac_nocolon = ? AND device_id = ? AND verified_at IS NOT NULL AND used = 0
                """,
                (mac_nocolon, did_norm),
            )
            conn.commit()
            conn.close()

    publish_bootstrap_claim(
        mac_nocolon=mac_nocolon,
        claim_nonce=claim_nonce,
        device_id=did_norm,
        zone=req.zone,
        qr_code=qr_code,
        mqtt_username=mqtt_username,
        mqtt_password=mqtt_password,
        cmd_key=cmd_key,
    )

    resp = {
        "ok": True,
        "device_id": did_norm,
        "mac_nocolon": mac_nocolon,
        "mqtt_username": mqtt_username if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "mqtt_password": mqtt_password if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "cmd_key": cmd_key if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
    }
    audit_event(
        principal.username,
        "provision.claim",
        did_norm,
        {
            "mac_nocolon": mac_nocolon,
            "zone": req.zone,
            "owner_admin": owner_admin,
            "device_id": did_norm,
            "role": principal.role,
        },
    )
    return resp


# Phase-9 modularization: /audit, /logs/messages, /logs/file moved to
# routers/audit_logs.py. The router is imported and wired in here so it
# sits at the same point in the route table as the original @app
# decorators did.
from routers.audit_logs import router as _audit_logs_router  # noqa: E402

app.include_router(_audit_logs_router)


@app.post("/devices/{device_id}/commands")
def send_device_command(
    device_id: str,
    req: CommandRequest,
    request: Request,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    target = req.target_id or device_id
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    publish_command(topic, req.cmd, req.params, target, req.proto, get_cmd_key_for_device(device_id))
    ctx = _client_context(request)
    emit_event(
        level="info",
        category="device",
        event_type="device.command.send",
        summary=f"command {req.cmd} to {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=_lookup_owner_admin(device_id) or "",
        device_id=device_id,
        detail={
            "cmd": req.cmd,
            "target_id": target,
            "trigger_kind": ctx.get("client_kind", "web"),
            "ip": ctx.get("ip", ""),
            "platform": ctx.get("platform", ""),
            "device_type": ctx.get("device_type", ""),
            "mac_hint": ctx.get("mac_hint", ""),
            "geo": ctx.get("geo", ""),
        },
    )
    return {"ok": True, "topic": topic, "target_id": target}


# =====================================================================
#  Trigger policy + Wi-Fi provisioning task
# =====================================================================

# Phase-19 modularization: 4 routes + _load_device_row_for_task +
# 4 schemas now live in routers/device_provision.py.
from routers.device_provision import router as _device_provision_router  # noqa: E402

app.include_router(_device_provision_router)

# =====================================================================
#  Device control: alert on/off + self-test + schedule-reboot
# =====================================================================

# Phase-18 modularization: 5 single-device control routes + the
# ScheduleRebootRequest schema now live in routers/device_control.py.
from routers.device_control import router as _device_control_router  # noqa: E402

app.include_router(_device_control_router)

@app.post("/alerts")
def bulk_alert(req: BulkAlertRequest, request: Request, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    targets = resolve_target_devices(req.device_ids, principal)
    if not targets:
        return {"ok": True, "sent_count": 0, "device_ids": []}

    sent = 0
    for did in targets:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        if req.action == "on":
            publish_command(
                topic=topic,
                cmd="siren_on",
                params={"duration_ms": req.duration_ms},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
        else:
            publish_command(
                topic=topic,
                cmd="siren_off",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
        sent += 1

    if sent > 0:
        own = _lookup_owner_admin(targets[0])
        owner_admins: list[str] = []
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            ph = ",".join(["?"] * len(targets))
            cur.execute(
                f"SELECT DISTINCT IFNULL(owner_admin,'') AS owner_admin FROM device_ownership WHERE device_id IN ({ph})",
                tuple(targets),
            )
            owner_admins = [str(r["owner_admin"]) for r in cur.fetchall() if r["owner_admin"]]
            conn.close()
        ctx = _client_context(request)
        _log_signal_trigger(
            f"bulk_siren_{req.action}",
            "*",
            "",
            principal.username,
            own,
            duration_ms=req.duration_ms if req.action == "on" else None,
            target_count=sent,
            detail={"device_ids": targets, "owner_admins": owner_admins[:16], **ctx},
        )
        if notifier.enabled() and own:
            rec = _recipients_for_admin(own)
            if rec:
                subj = f"[Croc Sentinel] Bulk siren {req.action} ×{sent} by {principal.username}"
                body = "Targets:\n" + "\n".join(targets[:120])
                notifier.enqueue(rec, subj, body, None)
        emit_event(
            level="warn" if req.action == "on" else "info",
            category="alarm",
            event_type=f"bulk.siren_{req.action}",
            summary=f"Bulk siren {req.action} {sent} device(s) by {principal.username}",
            actor=principal.username,
            target=",".join(targets[:8]),
            owner_admin=own or "",
            detail={
                "count": sent,
                "device_ids": targets[:64],
                "owner_admins": owner_admins[:16],
                "trigger_kind": ctx.get("client_kind", "web"),
                "ip": ctx.get("ip", ""),
                "platform": ctx.get("platform", ""),
                "device_type": ctx.get("device_type", ""),
                "mac_hint": ctx.get("mac_hint", ""),
                "geo": ctx.get("geo", ""),
            },
        )

    return {
        "ok": True,
        "action": req.action,
        "sent_count": sent,
        "device_ids": targets,
    }

# (3 more device control routes moved with phase-18 — see include above.)

@app.post("/commands/broadcast")
def send_broadcast_command(req: BroadcastCommandRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id FROM device_state
            WHERE 1=1 {zs} {osf}
              AND device_id NOT IN (SELECT device_id FROM revoked_devices)
            """,
            tuple(za + osa),
        )
        device_ids = [r["device_id"] for r in cur.fetchall()]
        conn.close()

    if len(device_ids) > MAX_BULK_TARGETS:
        raise HTTPException(status_code=413, detail=f"target set too large (> {MAX_BULK_TARGETS})")

    for did in device_ids:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        publish_command(topic, req.cmd, req.params, req.target_id, req.proto, get_cmd_key_for_device(did))

    audit_event(principal.username, "command.broadcast", req.target_id, {
        "cmd": req.cmd,
        "sent_count": len(device_ids),
    })
    return {"ok": True, "target_id": req.target_id, "sent_count": len(device_ids)}


# =====================================================================
#  Alarms (server-side fan-out history)
# =====================================================================
# Phase-10 modularization: the three alarms / activity-feed routes
# (/alarms, /alarms/summary, /activity/signals) plus the ACL helper
# `_alarm_scope_for` now live in routers/alarms.py.
from routers.alarms import router as _alarms_router  # noqa: E402

app.include_router(_alarms_router)


# =====================================================================
#  Email recipients (per-tenant) & SMTP/Telegram/FCM admin status & test
# =====================================================================
# Phase-11 modularization: ten admin notification-channel routes plus
# their request schemas now live in routers/notifications_admin.py.
# (Drive-by: removed dead `_admin_scope_for` helper that was defined
# here but never called anywhere.)
from routers.notifications_admin import router as _notif_admin_router  # noqa: E402

app.include_router(_notif_admin_router)


# Phase-12 modularization: the six Telegram link/bind/webhook routes
# plus all telegram-only helpers (chat reply, bind, capability gating,
# target parsing, recent-devices/recent-logs replies, command publish,
# text command parser) and the two request schemas now live in
# routers/telegram.py. The status/test/webhook-info routes were
# already moved out in Phase 11 (see routers/notifications_admin.py).
from routers.telegram import router as _telegram_router  # noqa: E402

app.include_router(_telegram_router)


# =====================================================================
#  OTA — firmware listing & tenant-scoped broadcast
# =====================================================================

# Phase-13 modularization: every /ota/* route, the three Pydantic request
# schemas (OtaBroadcastRequest, OtaCampaignCreateRequest,
# OtaCampaignFromStoredRequest), and eight OTA-only helpers
# (_sha256_sidecar_only, _sha256_for, _list_all_admin_usernames,
# _insert_ota_campaign, _safe_ota_stored_filename,
# _ota_bin_path_for_stored_name, _require_ota_upload_password,
# _ota_store_uploaded_bin) now live in routers/ota.py. The retention
# helpers (_ota_delete_artifacts_for_stored_basename, _ota_in_use_basenames,
# _ota_enforce_max_stored_bins) stay in this file because non-OTA code
# paths still call them; routers/ota.py late-binds via _app.
from routers.ota import router as _ota_router  # noqa: E402

app.include_router(_ota_router)



def _ota_delete_artifacts_for_stored_basename(basename: str) -> None:
    """Delete .bin, .bin.sha256, .bin.version, and sidecar release notes (stem + .txt/.md/.notes)."""
    if not str(basename).endswith(".bin") or ".." in basename or "/" in basename or "\\" in basename:
        return
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    path = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, basename))
    if not path.startswith(base_dir + os.sep) or not path.lower().endswith(".bin"):
        return
    stem_name = path[:-4]  # full path without ".bin" suffix; basename for sidecars
    base_name = os.path.basename(stem_name)
    to_try: list[str] = [path, path + ".sha256", path + ".version"]
    for ext in (".txt", ".md", ".notes"):
        to_try.append(os.path.join(OTA_FIRMWARE_DIR, base_name + ext))
    for p in to_try:
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass


def _ota_in_use_basenames() -> set[str]:
    """Set of .bin basenames currently referenced by a non-terminal OTA campaign.
    We refuse to prune these so devices mid-download don't 404 on the artifact.
    """
    out: set[str] = set()
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT url FROM ota_campaigns
                WHERE state NOT IN ('success', 'failed', 'cancelled', 'rolled_back')
                """
            )
            rows = cur.fetchall() or []
            conn.close()
    except Exception as exc:
        logger.warning("in-use OTA campaign lookup failed: %s", exc)
        return out
    for r in rows:
        url = str((r["url"] if r else "") or "")
        if not url:
            continue
        try:
            tail = url.rsplit("/", 1)[-1]
            # Strip query string.
            if "?" in tail:
                tail = tail.split("?", 1)[0]
            if tail.lower().endswith(".bin"):
                out.add(tail)
        except Exception:
            continue
    return out


def _ota_enforce_max_stored_bins() -> None:
    """Keep at most OTA_MAX_FIRMWARE_BINS .bin files; remove oldest by mtime first, with artifacts.

    Never prunes a .bin that's currently referenced by an active OTA campaign — doing
    so would cause in-flight devices to fail the download and fall back to rollback.
    If the number of in-use bins alone already exceeds the limit, we keep them all and
    warn so the operator can raise ``OTA_MAX_FIRMWARE_BINS``.
    """
    base = os.path.realpath(OTA_FIRMWARE_DIR)
    if not os.path.isdir(base):
        return
    in_use = _ota_in_use_basenames()
    items: list[tuple[int, str, str]] = []  # mtime, name, relpath join path
    for name in os.listdir(OTA_FIRMWARE_DIR):
        if not str(name).lower().endswith(".bin"):
            continue
        p = os.path.join(OTA_FIRMWARE_DIR, name)
        if not os.path.isfile(p):
            continue
        try:
            rp = os.path.realpath(p)
        except OSError:
            continue
        if not str(rp).startswith(base + os.sep):
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        items.append((int(st.st_mtime), str(name), p))
    # Oldest mtime first; break ties by name for stable order
    items.sort(key=lambda t: (t[0], t[1]))
    # Remove oldest until count ≤ max — but skip any in-use .bin.
    idx = 0
    kept_protected = 0
    while len(items) > OTA_MAX_FIRMWARE_BINS and idx < len(items):
        _m, name, _p = items[idx]
        if name in in_use:
            kept_protected += 1
            idx += 1
            continue
        items.pop(idx)
        _ota_delete_artifacts_for_stored_basename(name)
    if len(items) > OTA_MAX_FIRMWARE_BINS and kept_protected > 0:
        logger.warning(
            "OTA retention: %d artifact(s) kept above limit=%d because they are in-use by active campaigns",
            kept_protected, OTA_MAX_FIRMWARE_BINS,
        )
    _invalidate_ota_firmware_catalog_cache()


# =====================================================================
#  Presence probes (admin-facing read-only view of the 12h ping log)
# =====================================================================

@app.get("/admin/presence-probes")
def list_presence_probes(
    principal: Principal = Depends(require_principal),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    sql = (
        "SELECT id, device_id, owner_admin, probe_ts, idle_seconds, outcome, detail "
        "FROM presence_probes WHERE 1=1 "
    )
    args: list[Any] = []
    if device_id:
        sql += "AND device_id = ? "
        args.append(device_id)
    if principal.role == "admin":
        sql += "AND (owner_admin = ? OR owner_admin IS NULL) "
        args.append(principal.username)
    sql += "ORDER BY probe_ts DESC LIMIT ?"
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


# =====================================================================
#  Event center — historical query + live SSE stream
#
#  Phase-8 modularization: the six event-center routes (paginated /events,
#  CSV export, by-device stats, taxonomy, SSE stream, WS mirror) plus the
#  tenant-scope SQL helpers (_event_scope_sql, _events_filter_sql_args)
#  and the SSE auth helper now live in routers/events.py. The router is
#  imported and wired in here so it sits at the same point in the route
#  table as the original @app decorators did.
#
#  Tenant isolation rules (kept here for readers grepping app.py):
#    * superadmin  → every event in the system
#    * admin       → events where owner_admin = self OR actor/target = self
#    * user        → events in their manager_admin's tenant that mention them
#                    or are warn+
# =====================================================================
from routers.events import router as _events_router  # noqa: E402

app.include_router(_events_router)


@app.get("/diag/db-ping")
def diag_db_ping(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Cheap SQLite latency probe — use when the UI feels slow (admin+)."""
    assert_min_role(principal, "admin")
    t0 = time.perf_counter()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
    return {"ok": True, "db_ms": round((time.perf_counter() - t0) * 1000, 3), "pid": os.getpid()}


# =====================================================================
#  Factory device registry & /provision/identify (the "unguessable" story)
# =====================================================================

# Serial format: SN-<16 uppercase base32 chars>. 80 bits of CSPRNG entropy.
# The factory side generates these, never the device. Device only uses
# (serial, mac_nocolon) tuples that were uploaded to /factory/devices.
# Used here by /provision/identify; the parallel "FACTORY_QR_RE" used to
# live alongside it but was dead code, so it now lives on as the inline
# regex inside provision_identify().
FACTORY_SERIAL_RE = re.compile(r"^SN-[A-Z2-7]{16}$")


# Phase-7 modularization: the four /factory/* routes (register / ping /
# list / block) plus their request models and the X-Factory-Token auth
# helper now live in routers/factory.py. The router is imported and
# wired in here so it sits at the same point in the route table as the
# original @app decorators did.
from routers.factory import router as _factory_router  # noqa: E402

app.include_router(_factory_router)


class IdentifyRequest(BaseModel):
    serial: Optional[str] = Field(default=None, max_length=64)
    qr_code: Optional[str] = Field(default=None, max_length=512)


@app.post("/provision/identify")
def provision_identify(
    body: IdentifyRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Answer "what state is this device in right now?" for the claim UI.

    The operator either scans the factory QR sticker or types the serial. We
    return one of:

      - unknown_serial       -> the serial is not in our factory registry
      - blocked              -> factory revoked this serial (RMA etc.)
      - already_registered   -> device is claimed
      - offline              -> device is in factory registry but has never
                                published bootstrap.register, i.e. it was
                                never online. Operator must power it up and
                                connect it to the network first.
      - ready                -> factory-registered, has bootstrap row, not
                                yet claimed. Caller can POST /provision/claim
                                with the returned mac_nocolon.
    """
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    serial = (body.serial or "").strip().upper()
    qr = (body.qr_code or "").strip()
    if qr:
        # QR can optionally be HMAC-signed; the claim step verifies the sig.
        # For identify we only need to pluck the serial out of the QR string.
        m = re.match(r"^CROC\|(SN-[A-Z2-7]{16})\|", qr)
        if m:
            serial = m.group(1)
    if not serial:
        raise HTTPException(status_code=400, detail="serial or qr_code is required")
    if not FACTORY_SERIAL_RE.match(serial):
        raise HTTPException(status_code=400, detail="serial format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT serial, mac_nocolon, qr_code, status FROM factory_devices WHERE serial = ?",
            (serial,),
        )
        fdev = cur.fetchone()
        conn.close()
    if not fdev:
        return {"status": "unknown_serial", "serial": serial,
                "message": "该序列号不在出厂清单，请确认扫描的是正品贴纸或联系管理员"}
    if str(fdev["status"] or "unclaimed") == "blocked":
        return {"status": "blocked", "serial": serial,
                "message": "该设备已被出厂侧禁用（RMA / 质量问题）"}
    # Already registered?
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT device_id, mac_nocolon, claimed_at FROM provisioned_credentials WHERE device_id = ?",
            (serial,),
        )
        prov = cur.fetchone()
        owner = None
        if prov:
            cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (serial,))
            ow = cur.fetchone()
            owner = str(ow["owner_admin"]) if ow else None
        conn.close()
    if prov:
        you = owner and (owner == principal.username or (
            principal.role == "user" and owner == get_manager_admin(principal.username)
        ))
        resp: dict[str, Any] = {
            "status": "already_registered",
            "serial": serial,
            "device_id": str(prov["device_id"]),
            "mac_nocolon": str(prov["mac_nocolon"]),
            "claimed_at": str(prov["claimed_at"]),
            "message": "设备已被登记，无法再次注册",
        }
        if principal.role == "superadmin":
            resp["owner_admin"] = owner
            resp["by_you"] = bool(you)
        return resp
    # Does it appear in pending_claims? That only happens after the device
    # comes online and publishes bootstrap.register on MQTT.
    mac_for_lookup = str(fdev["mac_nocolon"] or "").upper()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        pend = None
        if mac_for_lookup:
            cur.execute(
                "SELECT mac_nocolon, last_seen_at, fw FROM pending_claims WHERE mac_nocolon = ?",
                (mac_for_lookup,),
            )
            pend = cur.fetchone()
        # Factory CSV may still carry a placeholder MAC while bootstrap.register
        # upserts pending_claims with the real MAC — list_pending shows the row
        # but MAC-only identify would wrongly return offline without this fallback.
        if pend is None:
            cur.execute(
                "SELECT mac_nocolon, last_seen_at, fw FROM pending_claims "
                "WHERE UPPER(IFNULL(proposed_device_id,'')) = ? ORDER BY last_seen_at DESC LIMIT 1",
                (serial,),
            )
            pend = cur.fetchone()
        conn.close()
    if not pend:
        return {
            "status": "offline",
            "serial": serial,
            "mac_hint": mac_for_lookup,
            "message": "设备未联网。请先通电、连上 WiFi/网线，看到状态灯稳定后再扫码激活。",
        }
    return {
        "status": "ready",
        "serial": serial,
        "mac_nocolon": str(pend["mac_nocolon"]),
        "fw": str(pend["fw"] or ""),
        "last_seen_at": str(pend["last_seen_at"]),
        "message": "设备在线且尚未登记，可点击确认注册",
    }
