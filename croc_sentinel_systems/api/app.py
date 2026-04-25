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


# _legacy_unowned_device_scope moved to authz.py (Phase 49) along with
# the rest of the per-tenant scope/ACL helpers; re-exported below from
# `from authz import ...` once the security module is in place.


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
# Phase-38: alarm-event dedup + auto-reconcile in-process state moved
# to auto_reconcile.py (see re-export block lower in this file). The
# names stay accessible as ``app.alarm_event_dedup_seen`` etc. for any
# legacy late-binder.
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
# Phase-52 modularization: BUS_INSTANCE_ID, REDIS_URL,
# EVENT_BUS_REDIS_CHANNEL, the listener-thread state, and the four
# bridge functions (_redis_event_forward / _redis_listener_main /
# _start_event_redis_bridge / _stop_event_redis_bridge) all moved to
# redis_bridge.py. They are re-exported below alongside the bridge
# helpers so the in-module call sites (emit_event() ->
# _redis_event_forward, lifespan startup -> _start_event_redis_bridge,
# lifespan shutdown -> _stop_event_redis_bridge) keep working.
# EVENT_WS_ENABLED moved to config.py and re-imported via `from config import *` above.
SLOW_REQUEST_LOG_MS = int(os.getenv("SLOW_REQUEST_LOG_MS", "0"))
from redis_bridge import (  # noqa: E402,F401  (re-exports for legacy callers)
    BUS_INSTANCE_ID,
    EVENT_BUS_REDIS_CHANNEL,
    REDIS_URL,
    _redis_bridge_stop,
    _redis_event_forward,
    _redis_listener_main,
    _redis_listener_thread,
    _redis_sync_client,
    _start_event_redis_bridge,
    _stop_event_redis_bridge,
)

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


# _redis_event_forward, _redis_listener_main, _start_event_redis_bridge
# and _stop_event_redis_bridge moved to redis_bridge.py (Phase 52);
# see the re-export block at the top of this file for details.


# FCM alarm-dispatch helpers (Phase-46 modularization). The four
# helpers below — ``_alarm_severity_bucket``, ``_sound_hint_from_severity``,
# ``_trigger_method_from_ev`` and ``_maybe_dispatch_fcm_for_ev`` —
# now live in ``fcm_dispatch.py`` and are re-exported here so the
# single in-process caller (``emit_event`` above) and any direct
# ``from app import _maybe_dispatch_fcm_for_ev`` imports keep
# working unchanged. The new module pulls
# ``_device_notify_labels`` straight from ``trigger_policy`` and
# ``enqueue_alarm_payloads`` straight from ``fcm_notify``, so it
# has no late-bound ``_app.*`` shims.
from fcm_dispatch import (
    _alarm_severity_bucket,
    _maybe_dispatch_fcm_for_ev,
    _sound_hint_from_severity,
    _trigger_method_from_ev,
)


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


# Authorization & per-tenant scope helpers (Phase-49 modularization).
# The 14 ACL/scope helpers below — get_manager_admin,
# principal_for_username, get_effective_policy, require_capability,
# _device_access_flags, _principal_tenant_owns_device,
# _redact_notification_group_for_principal,
# assert_device_view_access / siren_access / operate_access /
# device_owner / device_command_actor, owner_sql_suffix and
# owner_scope_clause_for_device_state — plus
# _legacy_unowned_device_scope now live in authz.py and are
# re-exported here so every router's `_app.assert_device_view_access`
# / `_app.owner_sql_suffix` / `_app.principal_for_username` shim
# (and the in-module call sites in @app.* handlers) keep finding the
# same callables. authz.py imports Principal / assert_min_role /
# default_policy_for_role / zones_from_json straight from `security`,
# `ensure_not_revoked` from `device_security`, and the
# ALLOW_LEGACY_UNOWNED / TENANT_STRICT flags from `config` — no
# late binding, fully import-acyclic.
from authz import (
    _device_access_flags,
    _legacy_unowned_device_scope,
    _principal_tenant_owns_device,
    _redact_notification_group_for_principal,
    assert_device_command_actor,
    assert_device_operate_access,
    assert_device_owner,
    assert_device_siren_access,
    assert_device_view_access,
    get_effective_policy,
    get_manager_admin,
    owner_scope_clause_for_device_state,
    owner_sql_suffix,
    principal_for_username,
    require_capability,
)


def parse_topic(topic: str) -> tuple[Optional[str], Optional[str]]:
    parts = topic.split("/")
    if len(parts) != 3:
        return None, None
    if parts[0] != TOPIC_ROOT:
        return None, None
    return parts[1], parts[2]


# Phase-37 modularization: device-state SQLite writers live in
# device_state.py — pure SQLite + helpers, no event bus / notifier /
# publish dependency. Re-exported here so the in-module call sites in
# ``_dispatch_mqtt_payload`` (lines ~2492–2513) and the late-bind shim
# in routers/device_profile.py (`_app._extract_zone_from_device_state_row`)
# keep finding the same callable identities.
from device_state import (  # noqa: E402,F401  (re-exports for legacy callers)
    _extract_zone_from_device_state_row,
    insert_message,
    upsert_device_state,
    upsert_pending_claim,
)


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


# Phase-38 modularization: alarm-event dedup, auto-reconcile worker,
# and the pending-claim janitor live in auto_reconcile.py. The 6
# helpers are pure SQLite + late-bound ``app.emit_event`` /
# ``app.generate_device_credentials`` / ``app.publish_bootstrap_claim``.
# Re-exported so the in-module call sites
# (``_dispatch_mqtt_payload`` for dedup + ack-key-mismatch, the
# scheduler loop for tick + prune) keep finding the same callables.
from auto_reconcile import (  # noqa: E402,F401  (re-exports for legacy callers)
    _alarm_event_is_duplicate,
    _auto_reconcile_tick,
    _enqueue_auto_reconcile,
    _is_ack_key_mismatch,
    _prune_stale_pending_claims,
    _run_auto_reconcile_once,
    alarm_event_dedup_lock,
    alarm_event_dedup_seen,
    auto_reconcile_last_seen,
    auto_reconcile_lock,
    auto_reconcile_queue,
)


# Phase-41 modularization: 5 alarm-DB helpers (owner-admin lookup,
# tenant-sibling resolver, recipient roster, alarm row writers) live in
# alarm_db.py — pure SQLite + helpers + config. Re-exported here so the
# in-module call sites (``_fan_out_alarm`` for all 5, ``_remote_siren_notify_email``
# for ``_recipients_for_admin``, ``_dispatch_mqtt_payload`` for
# ``_lookup_owner_admin``) keep using the bare names, and so the routers
# that late-bind via ``_app._lookup_owner_admin`` /
# ``_app._tenant_siblings`` / ``_app._recipients_for_admin``
# (device_control, device_commands, device_http, device_profile,
# device_read, group_cards) keep resolving to the same callables.
from alarm_db import (  # noqa: E402,F401  (re-exports for legacy callers)
    _insert_alarm,
    _lookup_owner_admin,
    _recipients_for_admin,
    _tenant_siblings,
    _update_alarm,
)


# Phase-45 modularization: 6 trigger-policy + signal-logging helpers
# (audit row writer, device label reader, in-code policy defaults,
# tenant-overridden policy reader with normalized group key, email
# subject prefix renderer, remote-siren email queuer) live in
# trigger_policy.py — pure SQLite + helpers + config + alarm_db +
# notifier. Re-exported here so the in-module call sites (
# ``emit_event`` for ``_notify_subject_prefix``,
# ``_maybe_dispatch_fcm_for_ev`` for ``_device_notify_labels``) and
# the routers' late-bind shims (``_app._log_signal_trigger`` in
# device_commands / device_control / group_cards;
# ``_app._trigger_policy_for`` in device_provision;
# ``_app._remote_siren_notify_email`` in device_control;
# ``_app._device_notify_labels`` / ``_app._notify_subject_prefix`` in
# alarm_fanout) keep finding the same callables.
from trigger_policy import (  # noqa: E402,F401  (re-exports for legacy callers)
    _device_notify_labels,
    _log_signal_trigger,
    _notify_subject_prefix,
    _remote_siren_notify_email,
    _trigger_policy_defaults,
    _trigger_policy_for,
)


# Phase-43 modularization: presence-probe subsystem (8 helpers across
# 3 concerns: probe insert/ack/expire, stale-device scan + ping
# publish, plus two scheduler-driven housekeeping passes for events
# retention and stale ``scheduled_commands``) lives in
# presence_probes.py — pure SQLite + helpers + config + stdlib datetime.
# The MQTT/event-bus dependencies (``publish_command``,
# ``get_cmd_key_for_device``, ``emit_event``, ``_parse_iso``) are
# late-bound via ``import app as _app`` at call time so import is
# acyclic. Re-exported here so the in-module call sites
# (``_dispatch_mqtt_payload`` for ``_mark_presence_probe_acked``,
# ``scheduler_loop`` for ``_fail_stale_scheduled_commands`` /
# ``_expire_presence_probes_waiting_ack`` / ``_presence_probe_tick``
# / ``_events_retention_tick``) keep using the bare names.
from presence_probes import (  # noqa: E402,F401  (re-exports for legacy callers)
    _events_retention_tick,
    _expire_presence_probes_waiting_ack,
    _fail_stale_scheduled_commands,
    _find_stale_devices,
    _insert_presence_probe,
    _mark_presence_probe_acked,
    _presence_probe_tick,
    _send_presence_probe,
)


# ═══════════════════════════════════════════════
#  OTA campaigns (superadmin -> admin accept -> per-device rollout)
# ═══════════════════════════════════════════════

# Phase-40 modularization: 10 OTA URL/file utilities (URL shaping +
# reachability probes + disk retention) live in ota_files.py — pure
# stdlib + config + db + ota_catalog cache invalidator. Re-exported
# here so routers/ota.py's late-bind shims (`_app._public_firmware_url`,
# `_app._effective_ota_verify_base`, `_app._verify_firmware_file_on_service`,
# `_app._verify_ota_url`, `_app._ota_enforce_max_stored_bins`) keep
# resolving, and so the in-module call site (`_blocking_api_bootstrap_inner`
# at startup, the `/ota/upload` retention pass) keeps using the bare names.
from ota_files import (  # noqa: E402,F401  (re-exports for legacy callers)
    _append_ota_token_to_url,
    _effective_ota_verify_base,
    _http_probe_ota,
    _public_firmware_url,
    _service_check_url_for_firmware,
    _verify_firmware_file_on_service,
    _verify_ota_url,
)


# Phase-39 modularization: OTA campaign rollout / rollback / result
# handling lives in ota_rollout.py. The 6 helpers late-bind
# ``app.publish_command``, ``app.get_cmd_key_for_device``, and
# ``app.emit_event`` so the cyclic ``ota_rollout -> app -> ota_rollout``
# dependency doesn't wedge import. Re-exported here so
# ``_dispatch_mqtt_payload``'s OTA-result branch (via
# ``_handle_ota_result_safe`` Thread target) and the three router
# late-bind shims (routers/ota.py for rollout/rollback,
# routers/device_http.py for result-safe) keep finding the same callables.
from ota_rollout import (  # noqa: E402,F401  (re-exports for legacy callers)
    _dispatch_ota_to_device,
    _handle_ota_result,
    _handle_ota_result_safe,
    _ota_campaign_targets_for_admin,
    _rollback_admin_devices,
    _start_ota_rollout_for_admin,
)


# Phase-42 modularization: ``_fan_out_alarm`` (the alarm trigger
# pipeline: dedup → policy → MQTT fan-out → email queue → audit) and
# its exception-swallowing wrapper ``_fan_out_alarm_safe`` live in
# alarm_fanout.py. They depend on symbols defined further down in
# this file (``publish_command``, ``get_cmd_keys_for_devices``,
# ``emit_event``) plus three helpers that still live here
# (``_device_notify_labels``, ``_trigger_policy_for``,
# ``_notify_subject_prefix``); ``alarm_fanout.py`` resolves those at
# call time via ``import app as _app`` so its module import is acyclic.
# Re-exported here so ``_dispatch_mqtt_payload``'s threading.Thread
# target keeps using the bare name ``_fan_out_alarm_safe``.
from alarm_fanout import (  # noqa: E402,F401  (re-exports for legacy callers)
    _fan_out_alarm,
    _fan_out_alarm_safe,
)


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


# (CommandRequest, BroadcastCommandRequest, BulkAlertRequest moved to
# routers/device_commands.py — see the corresponding
# `from routers.device_commands import ...` re-export below.)

# (ClaimDeviceRequest schema moved to routers/provision_lifecycle.py — see
# the corresponding `from routers.provision_lifecycle import ClaimDeviceRequest`
# re-export below.)

# (ScheduleRebootRequest moved to routers/device_control.py — see the
# corresponding `from routers.device_control import ...` block below.)

# (4 schemas + _WIFI_DEFERRED_CMDS moved to routers/device_provision.py — see
# the corresponding `from routers.device_provision import ...` block below.)

# (DeviceChallengeRequest + DeviceChallengeVerifyRequest moved to
# routers/provision_challenge.py — see the corresponding `from
# routers.provision_challenge import ...` re-export below.)

# (DeviceRevokeRequest schema moved to routers/device_revoke.py — see the
# corresponding `from routers.device_revoke import DeviceRevokeRequest` re-export below.)

# (DeviceDeleteRequest schema moved to routers/device_delete.py — see the
# corresponding `from routers.device_delete import DeviceDeleteRequest` re-export below.)

# (LoginRequest schema moved to routers/auth_core.py — see the corresponding
# `from routers.auth_core import LoginRequest` re-export below.)

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


# Phase-33 modularization: the six tiny SPA-mount redirect routes
# (/, /ui[/], /dashboard[/], /ui/{path:path}) now live in
# routers/ui_mounts.py. Pure redirect-to-mount shape — no auth,
# no DB, no shared state.
from routers.ui_mounts import router as _ui_mounts_router  # noqa: E402

app.include_router(_ui_mounts_router)


# Client-context helpers (Phase-50 modularization). The 6 helpers
# below — _telegram_enabled_safe, _fcm_enabled_safe,
# _fcm_delete_stale_registration_token, _client_ip, _ip_geo_text and
# _client_context — now live in client_context.py and are
# re-exported here so every router's `_app._client_context(...)` /
# `_app._client_ip(...)` shim and the in-module call sites keep
# finding the same callables. client_context.py is fully self-contained
# (lazy imports for telegram_notify / fcm_notify when probed, direct
# imports for db / fastapi / stdlib), no late binding on app.py.
from client_context import (
    _client_context,
    _client_ip,
    _fcm_delete_stale_registration_token,
    _fcm_enabled_safe,
    _ip_geo_text,
    _telegram_enabled_safe,
)


# Phase-34 modularization: 17 small auth/lockout/OTP helpers + the
# 3 module-level regex constants now live in auth_helpers.py.
# Re-exported here so legacy callers continue to read these names off
# the `app` module (auth_core, auth_recovery, auth_users — all still
# late-bind via `import app as _app`).
from auth_helpers import (  # noqa: E402,F401  (re-exports for legacy callers)
    _EMAIL_RE,
    _PHONE_RE,
    _USERNAME_RE,
    _check_login_ip_lockout,
    _check_signup_rate,
    _clear_login_failures,
    _clear_login_ip_state,
    _consume_verification,
    _generate_otp,
    _generate_sha_code,
    _hash_otp,
    _issue_verification,
    _looks_like_email,
    _normalize_phone,
    _record_login_failure,
    _record_login_failure_ip,
    _record_signup_attempt,
    _send_email_otp,
    _send_sms_otp,
    _verification_resend_wait_seconds,
)

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


# =====================================================================
#  Auth core  (login / csrf / logout)
# =====================================================================

# Phase-22 modularization: 3 routes + LoginRequest now live in routers/auth_core.py.
from routers.auth_core import LoginRequest  # noqa: E402,F401  (re-export for legacy callers)
from routers.auth_core import router as _auth_core_router  # noqa: E402

app.include_router(_auth_core_router)

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


# =====================================================================
#  Admin DB backup (encrypted export / import)
# =====================================================================

# Phase-25 modularization: 2 routes now live in routers/admin_backup.py.
from routers.admin_backup import router as _admin_backup_router  # noqa: E402

app.include_router(_admin_backup_router)

# =====================================================================
#  Provisioning challenge (sign nonce → verify)
# =====================================================================

# Phase-24 modularization: 2 routes + 2 schemas now live in routers/provision_challenge.py.
from routers.provision_challenge import (  # noqa: E402,F401  (re-export for legacy callers)
    DeviceChallengeRequest,
    DeviceChallengeVerifyRequest,
)
from routers.provision_challenge import router as _provision_challenge_router  # noqa: E402

app.include_router(_provision_challenge_router)

# =====================================================================
#  Device revoke / unrevoke
# =====================================================================

# Phase-23 modularization: 3 routes + DeviceRevokeRequest now live in routers/device_revoke.py.
from routers.device_revoke import DeviceRevokeRequest  # noqa: E402,F401  (re-export for legacy callers)
from routers.device_revoke import router as _device_revoke_router  # noqa: E402

app.include_router(_device_revoke_router)

# Tenant lifecycle + device-cleanup helpers (Phase-47 modularization).
# The five helpers below — _delete_user_auxiliary_cur,
# _apply_device_factory_unclaim_cur, _close_admin_tenant_cur,
# _wait_cmd_ack and _try_mqtt_unclaim_reset — now live in
# tenant_admin.py and are re-exported here so the existing call
# sites (the @app.* delete-user / close-admin handlers and the
# routers/auth_users.py + routers/auth_self.py + routers/device_delete.py
# late-binders) keep finding them on `app`. tenant_admin.py late-binds
# _invalidate_superadmin_telegram_chats_cache, publish_command,
# get_cmd_key_for_device, _parse_iso and OFFLINE_THRESHOLD_SECONDS
# off `app` at call time, so it can be imported safely even before
# those names are bound.
from tenant_admin import (
    _apply_device_factory_unclaim_cur,
    _close_admin_tenant_cur,
    _delete_user_auxiliary_cur,
    _try_mqtt_unclaim_reset,
    _wait_cmd_ack,
)


# Phase-26 modularization: the impl helper + 2 routes (delete-reset,
# factory-unregister) and the DeviceDeleteRequest schema now live in
# routers/device_delete.py. The router is wired in here so it sits at
# roughly the same point in the route table as the original @app
# decorators did, and so _try_mqtt_unclaim_reset (defined just above)
# is already bound by the time the router module is imported.
from routers.device_delete import DeviceDeleteRequest  # noqa: E402,F401  (re-export for legacy callers)
from routers.device_delete import _device_delete_reset_impl  # noqa: E402,F401  (re-export for legacy callers)
from routers.device_delete import router as _device_delete_router  # noqa: E402

app.include_router(_device_delete_router)


# Phase-32 modularization: /health (+ its three private helpers
# _health_notify_summary_public, _health_db_probe,
# _health_subscriber_summary) plus /admin/presence-probes and
# /diag/db-ping now live in routers/diagnostics.py. The router reads
# mqtt_* / api_ready_event / api_bootstrap_error off `app` at call time
# so the live worker-thread state stays the source of truth.
from routers.diagnostics import router as _diagnostics_router  # noqa: E402

app.include_router(_diagnostics_router)


OFFLINE_THRESHOLD_SECONDS = int(os.getenv("OFFLINE_THRESHOLD_SECONDS", "90"))


# Phase-44 modularization: 9 pure presence/parsing helpers (epoch
# parsers, the source-of-truth online rule that survives stale retained
# LWT, granular age fields the UI renders, JSON-column normalizer,
# net_health ledger extractor, and the compact "RSSI · 3.7 V" preview
# for the device list) live in device_presence.py — pure stdlib, with
# a single late-bound reference to ``app.OFFLINE_THRESHOLD_SECONDS``
# inside ``_device_is_online_parsed``. Re-exported here so the in-module
# call sites and the routers that late-bind via ``_app._parse_iso``,
# ``_app._device_is_online_parsed``, ``_app._device_presence_ages``,
# ``_app._device_is_online_sql_row``, ``_app._row_json_val``,
# ``_app._net_health_from_status``, ``_app._status_preview_from_device_row``
# all keep finding the same callables.
from device_presence import (  # noqa: E402,F401  (re-exports for legacy callers)
    _device_is_online_parsed,
    _device_is_online_sql_row,
    _device_presence_ages,
    _effective_online_for_presence,
    _net_health_from_status,
    _parse_iso,
    _payload_ts,
    _row_json_val,
    _status_preview_from_device_row,
)


# Phase-35 modularization: 12 OTA firmware-catalog helpers + the
# in-memory cache state now live in ota_catalog.py — they're pure
# parsing/IO with no DB or notifier dependency. Re-exported here so
# late-binders (routers/ota.py, routers/device_read.py, the OTA fan-out
# in this module) keep working without touching their imports.
from ota_catalog import (  # noqa: E402,F401  (re-exports for legacy callers)
    _best_catalog_entry_newer_than_fw,
    _catalog_entry_beats,
    _firmware_hint_dict_from_entry,
    _firmware_update_hint_for_current_in_catalog,
    _fw_version_gt,
    _get_ota_firmware_catalog,
    _invalidate_ota_firmware_catalog_cache,
    _parse_fw_version_tuple,
    _read_ota_release_notes_for_stem,
    _read_ota_stored_version_sidecar,
    _version_str_for_ota_bin_file,
    _version_str_from_ota_bin_name,
)


# (dashboard_overview moved to routers/dashboard_read.py — see the
# `app.include_router(_dashboard_read_router)` block alongside
# get_device_messages further below.)


# Phase-28 modularization: the four read-only device endpoints
# (GET /devices, /devices/firmware-hints, /devices/{id},
# /devices/{id}/siblings-preview) now live in routers/device_read.py.
# Most helpers are early-bound; _cmd_queue_pending_counts is wrapped
# call-time because it is defined later in app.py.
from routers.device_read import router as _device_read_router  # noqa: E402

app.include_router(_device_read_router)


# (DeviceDisplayLabelBody, DeviceProfileBody, DeviceBulkProfileBody schemas
# moved to routers/device_profile.py — see the corresponding
# `from routers.device_profile import ...` re-export below.)

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

# Phase-27 modularization: the three device-profile mutation routes
# (PATCH /devices/{id}/profile, PATCH /devices/{id}/display-label,
# POST /devices/bulk/profile), the shared `_apply_device_profile_update`
# helper, and the three Pydantic schemas now live in
# routers/device_profile.py. Late-binds emit_event,
# _principal_tenant_owns_device, _lookup_owner_admin,
# _extract_zone_from_device_state_row, assert_device_owner,
# require_principal from `app`.
from routers.device_profile import (  # noqa: E402,F401  (re-exports for legacy callers)
    DeviceBulkProfileBody,
    DeviceDisplayLabelBody,
    DeviceProfileBody,
    _apply_device_profile_update,
)
from routers.device_profile import router as _device_profile_router  # noqa: E402

app.include_router(_device_profile_router)


# =====================================================================
#  Device sharing / ACL admin
# =====================================================================

# Phase-16 modularization: the four /admin/(devices/{id}/)?share(s)?/*
# routes plus the DeviceShareRequest schema now live in
# routers/device_shares.py. Late-binds assert_device_owner +
# require_capability + require_principal from `app`.
from routers.device_shares import router as _device_shares_router  # noqa: E402

app.include_router(_device_shares_router)

# Phase-31 modularization: GET /dashboard/overview and
# GET /devices/{device_id}/messages now live in routers/dashboard_read.py
# (mqtt_connected is read off `app` at call time so the live MQTT-state
# global stays the source of truth).
from routers.dashboard_read import router as _dashboard_read_router  # noqa: E402

app.include_router(_dashboard_read_router)


# Per-device credentials + bootstrap publish (Phase-51 modularization).
# generate_device_credentials, get_cmd_key_for_device,
# get_cmd_keys_for_devices and publish_bootstrap_claim now live in
# cmd_keys.py; resolve_target_devices is re-exported from there
# below alongside scheduler_loop. Re-exported here so:
#   - `app.publish_bootstrap_claim is cmd_keys.publish_bootstrap_claim`
#     etc. (identity preserved for every router/_app shim);
#   - the in-module call sites in scheduler_loop / @app.* claim
#     handlers / fan-out workers keep finding these names on `app`.
# cmd_keys.py reads `app.mqtt_client` and `app.zone_sql_suffix` at
# call time so MQTT reconnects + the (still-in-app.py) zone helper
# stay live; everything else is direct imports from config / authz /
# security / db.
from cmd_keys import (
    generate_device_credentials,
    get_cmd_key_for_device,
    get_cmd_keys_for_devices,
    publish_bootstrap_claim,
)


# Phase-36 modularization: cmd_queue ledger lives in cmd_queue.py.
# The 5 helpers + replay state are pure SQLite + ``app.publish_command``
# (late-bound through ``import app as _app`` inside the replay function
# to avoid the ``publish_command -> _cmd_queue_enqueue -> ...`` cycle).
# Re-exported here so the 4 in-module call sites
# (``_dispatch_mqtt_payload`` ack handler, ``upsert_device_state`` replay
# trigger, ``publish_command`` ledger insert, ``scheduler_loop`` cleanup)
# and the 2 router late-bind shims (device_read.py / device_http.py)
# keep finding the same callable identities.
from cmd_queue import (  # noqa: E402,F401  (re-exports for legacy callers)
    CMD_QUEUE_REPLAY_GAP_S,
    CMD_QUEUE_TTL_S,
    _CMD_QUEUE_SKIP_VERBS,
    _cmd_queue_cleanup_expired,
    _cmd_queue_enqueue,
    _cmd_queue_mark_acked,
    _cmd_queue_pending_counts,
    _cmd_queue_pending_for_device,
    _cmd_queue_replay_last,
    _cmd_queue_replay_lock,
    _maybe_replay_queue_on_reconnect,
)


# Command-publish primitives (Phase-48 modularization). The MQTT
# /cmd publisher (publish_command), its idempotency cache state +
# helpers (_publish_dedupe_get/_set, MQTT_PUBLISH_WAIT_MS,
# PUBLISH_DEDUPE_TTL_S), and the SQLite-only deferred-command writer
# (enqueue_scheduled_command) now live in cmd_publish.py. They're
# re-exported here so:
#   - identity is preserved (`app.publish_command is
#     cmd_publish.publish_command`), keeping every router's
#     `_app.publish_command(...)` shim working unchanged;
#   - the in-module call sites (scheduler_loop, _dispatch_mqtt_payload,
#     fan-out workers, etc.) keep finding `publish_command` /
#     `_publish_dedupe_get` / `_publish_dedupe_set` on the module
#     namespace.
# cmd_publish.py reads `app.mqtt_client` and `app.mqtt_connected`
# at call time so MQTT reconnects (which reassign those globals on
# `app`) are picked up correctly.
from cmd_publish import (
    MQTT_PUBLISH_WAIT_MS,
    PUBLISH_DEDUPE_TTL_S,
    _publish_dedupe_cache,
    _publish_dedupe_get,
    _publish_dedupe_lock,
    _publish_dedupe_set,
    enqueue_scheduled_command,
    publish_command,
)


# resolve_target_devices moved to cmd_keys.py (Phase 51) — see the
# `from cmd_keys import ...` block above for the rest of that group.
from cmd_keys import resolve_target_devices  # noqa: E402,F401  (re-export)


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


# Phase-29 modularization: the three provision-lifecycle routes
# (/provision/pending, /provision/claim, /provision/identify) plus
# their two schemas (ClaimDeviceRequest, IdentifyRequest) and the
# FACTORY_SERIAL_RE regex now live in routers/provision_lifecycle.py.
# Late-binds get_manager_admin, generate_device_credentials,
# publish_bootstrap_claim, require_capability, require_principal from
# `app`.
from routers.provision_lifecycle import (  # noqa: E402,F401  (re-exports for legacy callers)
    ClaimDeviceRequest,
    FACTORY_SERIAL_RE,
    IdentifyRequest,
)
from routers.provision_lifecycle import router as _provision_lifecycle_router  # noqa: E402

app.include_router(_provision_lifecycle_router)


# Phase-9 modularization: /audit, /logs/messages, /logs/file moved to
# routers/audit_logs.py. The router is imported and wired in here so it
# sits at the same point in the route table as the original @app
# decorators did.
from routers.audit_logs import router as _audit_logs_router  # noqa: E402

app.include_router(_audit_logs_router)


# (send_device_command moved to routers/device_commands.py — see the
# `app.include_router(_device_commands_router)` block at the bottom of
# this section.)


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

# (bulk_alert + send_broadcast_command moved to routers/device_commands.py
# alongside send_device_command — single phase-30 router covers all three
# command-publishing endpoints.)
from routers.device_commands import (  # noqa: E402
    BroadcastCommandRequest,
    BulkAlertRequest,
    CommandRequest,
)
from routers.device_commands import router as _device_commands_router  # noqa: E402

app.include_router(_device_commands_router)

# (3 more device control routes moved with phase-18 — see include above.)


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



# Phase-40: disk-retention helpers (`_ota_delete_artifacts_for_stored_basename`,
# `_ota_in_use_basenames`, `_ota_enforce_max_stored_bins`) live in
# ota_files.py — see the re-export block above for the URL utilities.
# These three are also re-exported from ota_files because the bootstrap
# pass and routers/ota.py both call `_ota_enforce_max_stored_bins`.
from ota_files import (  # noqa: E402,F401  (re-exports for legacy callers)
    _ota_delete_artifacts_for_stored_basename,
    _ota_enforce_max_stored_bins,
    _ota_in_use_basenames,
)


# =====================================================================
#  Presence probes (admin-facing read-only view of the 12h ping log)
# =====================================================================

# (list_presence_probes moved to routers/diagnostics.py — see the
# `app.include_router(_diagnostics_router)` block above.)


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


# (diag_db_ping moved to routers/diagnostics.py — see the
# `app.include_router(_diagnostics_router)` block above.)


# =====================================================================
#  Factory device registry & /provision/identify (the "unguessable" story)
# =====================================================================

# (FACTORY_SERIAL_RE moved to routers/provision_lifecycle.py — re-exported
# above via the `from routers.provision_lifecycle import FACTORY_SERIAL_RE`
# block.)


# Phase-7 modularization: the four /factory/* routes (register / ping /
# list / block) plus their request models and the X-Factory-Token auth
# helper now live in routers/factory.py. The router is imported and
# wired in here so it sits at the same point in the route table as the
# original @app decorators did.
from routers.factory import router as _factory_router  # noqa: E402

app.include_router(_factory_router)


# (IdentifyRequest schema + /provision/identify route moved to
# routers/provision_lifecycle.py — re-exported above via the
# `from routers.provision_lifecycle import IdentifyRequest` block.)
