"""Superadmin recogniser + Telegram chat fan-out cache (Phase-57 extract).

Two short-lived in-memory caches with a single shared concern:
"is this username a superadmin?" + "what Telegram chat-ids should
we cc on every event?". Both feed the ``emit_event`` hot path so
they cache for ~20s to keep SQLite traffic off it.

Public API
----------
* :func:`_parse_chat_ids` — split a comma/space/semicolon-delimited
  env value into a tidy ``set[str]``. Used at module import to
  build :data:`TELEGRAM_COMMAND_CHAT_IDS` from the
  ``TELEGRAM_COMMAND_CHAT_IDS_RAW`` config var, plus by callers
  who want the same parser for ad-hoc lists.
* :data:`TELEGRAM_COMMAND_CHAT_IDS` — frozen-at-startup allow-list
  of chat-ids the Telegram command bot will accept; consumed by
  ``routers/telegram.py`` via the ``app.TELEGRAM_COMMAND_CHAT_IDS``
  re-export.
* :func:`_is_superadmin_username` — bool, reads
  ``dashboard_users WHERE role='superadmin'`` and caches the result
  for 20s. Falls back to a startswith("superadmin") prefix check
  if it can't grab a non-blocking read lock; that conservatively
  hides default superadmin names without ever blocking the hot path.
* :func:`_superadmin_telegram_chat_ids` — list of enabled chat_ids
  bound to a superadmin user; cached for ``_superadmin_tg_chats_ttl_s``
  (20s default). Best-effort: returns the previous cache verbatim
  on lock contention or DB error so emit_event never raises.
* :func:`_invalidate_superadmin_telegram_chats_cache` — reset the
  cache so the next emit_event picks up a fresh bind/unbind/toggle
  immediately instead of after the TTL.

Wiring
------
* Pure imports against ``config``, ``db`` (``get_conn`` plus the
  ``_db_rw`` SQLite read/write lock); ``import app as _app`` is NOT
  used here — this module sits below ``app.py`` so ``event_bus.py``
  can pull these helpers directly without going through the legacy
  re-export.
* ``app.py`` re-exports every public symbol so legacy ``_app.*``
  late-binders (``tenant_admin``, ``routers/telegram``,
  ``routers/superadmin``) keep working unchanged.
"""

from __future__ import annotations

import logging
import re
import time

from config import TELEGRAM_COMMAND_CHAT_IDS_RAW
from db import _db_rw, get_conn

__all__ = (
    "_parse_chat_ids",
    "TELEGRAM_COMMAND_CHAT_IDS",
    "_superadmin_cache",
    "_superadmin_cache_ts",
    "_superadmin_tg_chats_cache",
    "_superadmin_tg_chats_ts",
    "_superadmin_tg_chats_ttl_s",
    "_is_superadmin_username",
    "_superadmin_telegram_chat_ids",
    "_invalidate_superadmin_telegram_chats_cache",
)

logger = logging.getLogger(__name__)


def _parse_chat_ids(raw: str) -> set[str]:
    out: set[str] = set()
    for part in re.split(r"[\s,;]+", (raw or "").strip()):
        p = part.strip().strip('"').strip("'")
        if p:
            out.add(p)
    return out


TELEGRAM_COMMAND_CHAT_IDS: set[str] = _parse_chat_ids(TELEGRAM_COMMAND_CHAT_IDS_RAW)


_superadmin_cache: set[str] = set()
_superadmin_cache_ts: float = 0.0

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
    picks up a fresh bind/unbind/toggle immediately instead of after TTL.

    Phase-69: also busts the per-binding directory cache used by
    :mod:`telegram_visibility` so the tier-isolated fan-out (admin /
    user / superadmin) reflects the change on the very next event.
    Imported lazily to keep this module free of any compile-time
    dependency on ``telegram_visibility`` (preserves the import
    order: ``superadmin_cache`` < ``telegram_visibility`` <
    ``event_bus``).
    """
    global _superadmin_tg_chats_cache, _superadmin_tg_chats_ts
    _superadmin_tg_chats_cache = []
    _superadmin_tg_chats_ts = 0.0
    try:
        from telegram_visibility import invalidate_telegram_recipient_directory

        invalidate_telegram_recipient_directory()
    except Exception:
        pass
