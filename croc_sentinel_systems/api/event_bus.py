"""In-process event bus + emit_event pipeline (Phase-55 extraction).

Carved out of ``app.py``. Owns:

* ``_VALID_LEVELS`` / ``_VALID_CATEGORIES``   — schema enums for emit.
* ``_EventBus``  / ``_EventSub``               — bounded ring + per-sub queue.
* ``event_bus``  singleton (sized via ``EVENT_RING_SIZE``).
* ``_event_visible``  — tenant-isolation predicate (superadmin sees
  all; admin sees own-tenant + actor/target/self; user sees only
  events involving them inside their manager's tenant).
* ``_event_matches_filters`` — level / min_level / category /
  device_id / free-text ``q`` filter used by SSE + WS subscribers
  and the recent-events backlog.
* ``_insert_event_row`` — append to the ``events`` table; returns
  row id (0 on failure).
* :func:`emit_event` — single shared entry-point used by every
  audit / alarm / ota / presence / provision / device / system /
  auth path. Inserts the row, publishes to local fan-out, mirrors
  to the Redis bridge, kicks Telegram (with the cached superadmin
  chat-id firehose) and FCM dispatch.

Wiring
------
* Ring + queue sizes are read from ``config`` (``EVENT_RING_SIZE``,
  ``EVENT_MAX_SUBSCRIBERS``, ``EVENT_SUB_QUEUE_SIZE``).
* Late-binds via ``import app as _app`` for two helpers that still
  live in ``app.py`` (the superadmin recogniser and the cached
  superadmin telegram chat list); both are call-time only so the
  load order is fine.
* Direct imports for the per-module helpers we already extracted:
  ``db.{db_lock,get_conn}``, ``tz_display.iso_timestamp_to_malaysia``,
  ``trigger_policy._notify_subject_prefix``,
  ``redis_bridge._redis_event_forward``,
  ``fcm_dispatch._maybe_dispatch_fcm_for_ev``,
  ``authz.get_manager_admin``, ``security.Principal``.
* ``app.py`` re-exports every public symbol back so existing
  ``from app import emit_event`` / ``from app import event_bus``
  call sites in routers and helpers keep working unchanged.
"""

from __future__ import annotations

import collections
import json
import logging
import queue as _stdqueue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException

from authz import get_manager_admin
from config import (
    EVENT_MAX_SUBSCRIBERS,
    EVENT_RING_SIZE,
    EVENT_SUB_QUEUE_SIZE,
)
from db import db_lock, get_conn
from fcm_dispatch import _maybe_dispatch_fcm_for_ev
from redis_bridge import _redis_event_forward
from security import Principal
from trigger_policy import _notify_subject_prefix
from tz_display import iso_timestamp_to_malaysia

import app as _app

__all__ = (
    "_VALID_LEVELS",
    "_VALID_CATEGORIES",
    "_EventBus",
    "_EventSub",
    "event_bus",
    "_event_visible",
    "_event_matches_filters",
    "_insert_event_row",
    "emit_event",
)

logger = logging.getLogger(__name__)


_VALID_LEVELS = ("debug", "info", "warn", "error", "critical")
_VALID_CATEGORIES = ("auth", "alarm", "ota", "presence", "provision", "device", "system", "audit")


class _EventBus:
    def __init__(self, ring_size: int = 2000) -> None:
        self._lock = threading.Lock()
        self._ring: collections.deque[dict[str, Any]] = collections.deque(maxlen=ring_size)
        self._subs: dict[int, "_EventSub"] = {}
        self._next_sub_id = 1

    def subscribe(self, principal: Principal, filters: dict[str, Any]) -> "_EventSub":
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

    def backlog(self, principal: Principal, filters: dict[str, Any], limit: int) -> list[dict[str, Any]]:
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
    def __init__(self, sid: int, principal: Principal, filters: dict[str, Any]) -> None:
        self.id = sid
        self.principal = principal
        self.filters = filters
        self.q: _stdqueue.Queue[dict[str, Any]] = _stdqueue.Queue(maxsize=EVENT_SUB_QUEUE_SIZE)
        self.dropped = 0
        self.created_at = time.time()


def _event_visible(principal: Principal, ev: dict[str, Any]) -> bool:
    """Tenant isolation: superadmin sees everything; admin sees events where
    owner_admin == self OR actor == self; user sees only events in its
    manager_admin's tenant (and that involve it)."""
    if principal.role == "superadmin":
        return True
    owner = str(ev.get("owner_admin") or "")
    actor = str(ev.get("actor") or "")
    target = str(ev.get("target") or "")
    if _app._is_superadmin_username(actor):
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
    if my_admin and owner == my_admin and (
        actor == principal.username
        or target == principal.username
        or str(ev.get("level")) in ("warn", "error", "critical")
    ):
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
        blob = " ".join(
            str(ev.get(k) or "") for k in ("event_type", "actor", "target", "summary", "device_id")
        ).lower()
        if q_lc not in blob:
            return False
    return True


event_bus = _EventBus(ring_size=EVENT_RING_SIZE)


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
    ev["_actor_superadmin"] = _app._is_superadmin_username(str(ev.get("actor") or ""))
    rid = _insert_event_row(ev)
    ev["id"] = rid
    event_bus.publish(ev)
    _redis_event_forward(ev)
    try:
        from telegram_notify import maybe_notify_telegram

        # Superadmin bindings get the firehose; env TELEGRAM_CHAT_IDS stays
        # filtered as before (signal hygiene for operators).
        try:
            sa_chats = _app._superadmin_telegram_chat_ids()
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
