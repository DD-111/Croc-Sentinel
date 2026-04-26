"""Tier-aware Telegram chat fan-out (Phase-69).

Replaces the superadmin-only firehose with a per-binding visibility
predicate that mirrors :func:`event_bus._event_visible`, so the
Telegram tier boundaries match SSE / WebSocket exactly:

  * ``superadmin`` — global firehose (every event, full detail).
  * ``admin``      — events where ``owner_admin == self``,
                     events where ``actor == self`` or
                     ``target == self``, plus events whose actor or
                     target is one of the admin's managed users (so
                     a profile change by ``user_bob`` pings
                     ``admin_alice`` even when ``owner_admin`` is
                     empty). Admins are isolated from each other.
  * ``user``       — events involving them (``actor`` or ``target``)
                     inside their ``manager_admin`` tenant, plus
                     warn/error/critical alarms in that tenant.
                     ``category == "auth"`` is muted (only the
                     superadmin tier should see raw auth telemetry
                     on Telegram).

Why a separate module?
----------------------
``event_bus.emit_event`` runs on every audit / alarm / ota / presence
/ provision / device / system / auth event, so the lookup must:
  * never block ``emit_event`` on a SQLite write lock — we use the
    non-blocking read-lock pattern from ``superadmin_cache.py`` and
    fall back to the previous snapshot on contention;
  * never raise — a Telegram lookup error must not lose the event;
  * cache aggressively (~20s) so a steady stream of events does not
    pound SQLite.

Cache invalidation
------------------
:func:`invalidate_telegram_recipient_directory` resets both the
recipient list and the admin→managed-users index so the next
``emit_event`` picks up bind / unbind / toggle / role-change
mutations immediately. The legacy
``_invalidate_superadmin_telegram_chats_cache`` hook in
``superadmin_cache.py`` bridges to this function, which means every
existing invalidation call site (``routers/telegram.py``,
``routers/telegram_webhook.py``) keeps working unchanged.

True-duplicate suppression (alarm.trigger twins, audit.alarm.fanout
echoes) is handled inside ``telegram_notify_format.is_duplicate_event``
and the dedupe-window map in ``telegram_notify._TelegramWorker``;
this module only decides *which* chat_ids should be considered.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from db import _db_rw, get_conn

__all__ = (
    "telegram_chat_ids_for_event",
    "invalidate_telegram_recipient_directory",
)

logger = logging.getLogger(__name__)


_RECIPIENT_TTL_S: float = 20.0

_recipient_cache: list[dict[str, Any]] = []
_managed_users_cache: dict[str, set[str]] = {}
_recipient_cache_ts: float = 0.0


def _refresh_directory() -> None:
    """Reload recipients + admin→managed-users index from SQLite.

    Best-effort: holds the read lock non-blockingly; on contention or
    DB error we keep the previous (possibly stale) snapshot so
    ``emit_event`` never sees an exception path.
    """
    global _recipient_cache, _managed_users_cache, _recipient_cache_ts
    if not _db_rw.try_acquire_read():
        return
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT b.chat_id,
                   b.username,
                   u.role,
                   COALESCE(u.manager_admin, '') AS manager_admin
            FROM telegram_chat_bindings b
            JOIN dashboard_users u ON u.username = b.username
            WHERE b.enabled = 1
            """
        )
        recipients = [
            {
                "chat_id": str(r["chat_id"]),
                "username": str(r["username"] or ""),
                "role": str(r["role"] or ""),
                "manager_admin": str(r["manager_admin"] or ""),
            }
            for r in cur.fetchall()
            if r["chat_id"]
        ]
        cur.execute(
            """
            SELECT username, COALESCE(manager_admin, '') AS manager_admin
            FROM dashboard_users
            WHERE role = 'user'
            """
        )
        managed: dict[str, set[str]] = {}
        for r in cur.fetchall():
            adm = str(r["manager_admin"] or "")
            uname = str(r["username"] or "")
            if adm and uname:
                managed.setdefault(adm, set()).add(uname)
        conn.close()
    except Exception as exc:
        logger.warning("telegram recipient directory refresh failed: %s", exc)
        _db_rw.release_read()
        return
    _db_rw.release_read()
    _recipient_cache = recipients
    _managed_users_cache = managed
    _recipient_cache_ts = time.time()


def _get_directory() -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    if (time.time() - _recipient_cache_ts) > _RECIPIENT_TTL_S:
        _refresh_directory()
    return _recipient_cache, _managed_users_cache


def invalidate_telegram_recipient_directory() -> None:
    """Force the next :func:`telegram_chat_ids_for_event` call to
    re-read SQLite. Cheap (just resets the timestamp); safe to call
    from any thread.
    """
    global _recipient_cache_ts
    _recipient_cache_ts = 0.0


def telegram_chat_ids_for_event(ev: dict[str, Any]) -> list[str]:
    """Final fan-out target list for one event, role-isolated.

    The returned list is order-stable and de-duplicated. Empty list
    means "no Telegram bindings should receive this event"; the
    caller (``event_bus.emit_event``) just passes that through to
    ``maybe_notify_telegram`` as ``extra_chat_ids``, so the env
    ``TELEGRAM_CHAT_IDS`` channel still receives whatever the
    ``min_rank`` filter lets through independently.
    """
    if not ev:
        return []

    actor = str(ev.get("actor") or "")
    target = str(ev.get("target") or "")
    owner = str(ev.get("owner_admin") or "")
    cat = str(ev.get("category") or "")
    level = str(ev.get("level") or "info")
    actor_is_sa = bool(ev.get("_actor_superadmin"))

    recipients, managed = _get_directory()
    if not recipients:
        return []

    out: list[str] = []
    for r in recipients:
        role = r["role"]
        u = r["username"]
        chat = r["chat_id"]
        if not chat or not u or not role:
            continue

        if role == "superadmin":
            out.append(chat)
            continue

        # Hide superadmin-initiated actions from admin/user tiers so a
        # cross-tenant SA touch (e.g. force-unbind, mass reset) does
        # not leak into a tenant Telegram feed.
        if actor_is_sa:
            continue

        if role == "admin":
            if owner and owner == u:
                out.append(chat)
                continue
            if actor == u or target == u:
                out.append(chat)
                continue
            mset = managed.get(u)
            if mset and (actor in mset or target in mset):
                out.append(chat)
                continue
            continue

        if role == "user":
            # Raw auth telemetry is firehose-only (login fail / lockout
            # / IP throttle): users see those in the dashboard, not
            # on Telegram.
            if cat == "auth":
                continue
            # "user sees self" — self-actor / self-target events are
            # delivered regardless of owner_admin context (so e.g. a
            # profile change with no device owner still pings the
            # user's own chat).
            if actor == u or target == u:
                out.append(chat)
                continue
            # Tenant-wide warn/error/critical events: user sees them
            # only when the event sits inside their manager's tenant.
            my_admin = r["manager_admin"]
            if not my_admin or owner != my_admin:
                continue
            if level in ("warn", "error", "critical"):
                out.append(chat)
            continue

    return list(dict.fromkeys(out))
