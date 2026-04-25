"""Optional Telegram fan-out for ``emit_event`` (non-blocking queue).

This module owns the **transport** half of Telegram delivery:

  * The ``_TelegramQueue`` singleton (thread-safe queue, worker
    thread, lazy SSL context, env reload).
  * HTTP send via ``urllib.request`` (Bot API ``sendMessage``).
  * Public facade used by ``app.py`` and the dashboard
    diagnostic endpoints (``start_telegram_worker``, ``stop_…``,
    ``maybe_notify_telegram``, ``telegram_status``,
    ``send_telegram_text_now``, ``send_telegram_chat_text``,
    ``telegram_get_webhook_info``).

The **formatting** half — event → multi-line message body,
duplicate suppression, env-channel level/category gating, and
target-list resolution — lives in ``telegram_notify_format.py``
(Phase 75 split). ``maybe_enqueue`` here is a thin wrapper that
calls :func:`telegram_notify_format.format_event_for_chat`,
applies the time-windowed dedupe map, and pushes the resulting
``(text, targets)`` tuple onto the worker queue.

Env:
  TELEGRAM_BOT_TOKEN   — BotFather token; if empty, disabled.
  TELEGRAM_CHAT_IDS    — Comma-separated numeric chat ids.
  TELEGRAM_MIN_LEVEL   — debug | info | warn | error | critical (default: info)
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
import urllib.request
from typing import Any, Optional

from telegram_notify_format import (
    _LEVEL_RANK,
    _parse_chat_ids,
    _strip_bom,
    format_event_for_chat,
)

logger = logging.getLogger("croc-telegram")


class _TelegramQueue:
    def __init__(self) -> None:
        self._token = ""
        self._chats: list[str] = []
        self._min = "info"
        self._min_rank = 1
        # Each queue item is (text, extra_chat_ids). extra_chat_ids is unioned
        # with the env-wide TELEGRAM_CHAT_IDS at send time so superadmin
        # bindings from the DB can receive events the env list didn't cover.
        self._q: "queue.Queue[tuple[str, list[str]]]" = queue.Queue(maxsize=800)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._last_error: str = ""
        self._last_send_ok: bool = False
        # Lazy SSL context: some minimal/container images throw or lack CA data at import time.
        self._ssl_ctx: Optional[ssl.SSLContext] = None
        self._ssl_ctx_init_done = False
        self._recent_fingerprint_ts: dict[str, float] = {}
        self._dedupe_window_s = 35.0
        self.reload_from_env()

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        if self._ssl_ctx_init_done:
            return self._ssl_ctx
        self._ssl_ctx_init_done = True
        try:
            self._ssl_ctx = ssl.create_default_context()
        except Exception as exc:
            logger.warning("telegram SSL context init failed (will use platform default HTTPS): %s", exc)
            self._ssl_ctx = None
        return self._ssl_ctx

    def reload_from_env(self) -> None:
        """Re-read env (handles UTF-8 BOM / stray quotes from editors)."""
        self._token = _strip_bom(os.getenv("TELEGRAM_BOT_TOKEN", "") or "")
        self._chats = _parse_chat_ids(os.getenv("TELEGRAM_CHAT_IDS", "") or "")
        self._min = (os.getenv("TELEGRAM_MIN_LEVEL", "info").strip().lower() or "info")
        self._min_rank = _LEVEL_RANK.get(self._min, 1)

    def enabled(self) -> bool:
        return bool(self._token and self._chats)

    def start(self) -> None:
        self.reload_from_env()
        if not self.enabled() or self._worker is not None:
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="telegram-notify", daemon=True)
        self._worker.start()
        logger.info("Telegram notify worker started chats=%s min_level=%s", len(self._chats), self._min)

    def stop(self) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=2.0)
            self._worker = None

    def maybe_enqueue(
        self,
        ev: dict[str, Any],
        extra_chat_ids: Optional[list[str]] = None,
    ) -> None:
        """Filter, format and enqueue an event for the Telegram worker.

        Channel model:
          * ``env_chats``  — operator-configured ``TELEGRAM_CHAT_IDS``
            (signal-clean; level + category filters apply).
          * ``extras``     — per-event chat_ids (e.g. superadmin
            firehose bindings); bypass env filters.

        Both channels obey the true-duplicate filter
        (alarm.trigger twins + audit.alarm.fanout echoes — see
        :func:`telegram_notify_format.is_duplicate_event`).

        This method is intentionally thin: every formatting / filter
        decision is delegated to ``telegram_notify_format``. We keep
        the dedupe-window map here because that's stateful (per-
        instance, time-windowed) and best lives next to the queue.
        """
        self.reload_from_env()
        if not self._token:
            return
        env_chats = list(self._chats)
        plan = format_event_for_chat(
            ev,
            env_chats=env_chats,
            extras=extra_chat_ids or [],
            min_rank=self._min_rank,
        )
        if plan is None:
            return
        text, fingerprint, final_targets = plan
        now = time.time()
        prev = float(self._recent_fingerprint_ts.get(fingerprint, 0.0))
        if prev and (now - prev) < self._dedupe_window_s:
            return
        self._recent_fingerprint_ts[fingerprint] = now
        # Periodic map cleanup to avoid unbounded growth under steady load.
        if len(self._recent_fingerprint_ts) > 1200:
            cutoff = now - (self._dedupe_window_s * 4.0)
            self._recent_fingerprint_ts = {
                k: ts for k, ts in self._recent_fingerprint_ts.items() if ts >= cutoff
            }
        item = (text, final_targets)
        try:
            self._q.put_nowait(item)
        except queue.Full:
            # Drop the oldest item to make room — alerts are time-sensitive.
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(item)
            except queue.Full:
                pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self.reload_from_env()
                if not self._token:
                    self._last_error = "TELEGRAM_BOT_TOKEN empty after reload"
                    continue
                text, targets = item
                # Targets are already final/deduped/filtered at enqueue time.
                any_ok = False
                for chat in targets:
                    if self._send_one(chat, text):
                        any_ok = True
                self._last_send_ok = any_ok
                if not any_ok and targets:
                    logger.warning("telegram: message not delivered to any chat (see prior warnings)")
            except Exception:
                logger.exception("telegram worker iteration failed")

    def _send_one(self, chat_id: str, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:4090],
            "disable_web_page_preview": True,
        }
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "CrocSentinel-TelegramNotify/1.0",
            },
            method="POST",
        )
        try:
            ctx = self._get_ssl_context()
            kw: dict[str, Any] = {"timeout": 20}
            if ctx is not None:
                kw["context"] = ctx
            with urllib.request.urlopen(req, **kw) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if resp.status != 200:
                    self._last_error = f"HTTP {resp.status}"
                    logger.warning("telegram send HTTP %s", resp.status)
                    return False
                try:
                    j = json.loads(raw)
                except json.JSONDecodeError:
                    self._last_error = "non-json response"
                    logger.warning("telegram non-json: %s", raw[:200])
                    return False
                if not j.get("ok"):
                    desc = raw[:500]
                    self._last_error = desc
                    logger.warning("telegram api ok=false: %s", desc)
                    return False
                self._last_error = ""
                return True
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:400]
            self._last_error = f"HTTPError {exc.code}: {err_body}"
            logger.warning("telegram HTTPError %s: %s", exc.code, err_body)
            return False
        except Exception as exc:
            self._last_error = str(exc)
            logger.warning("telegram send failed: %s", exc)
            return False


_tg = _TelegramQueue()


def start_telegram_worker() -> None:
    _tg.start()


def stop_telegram_worker() -> None:
    _tg.stop()


def maybe_notify_telegram(ev: dict[str, Any], extra_chat_ids: Optional[list[str]] = None) -> None:
    _tg.maybe_enqueue(ev, extra_chat_ids=extra_chat_ids)


def telegram_status() -> dict[str, Any]:
    """Safe for GET /admin/telegram/status — must not raise (avoid opaque 500s)."""
    try:
        _tg.reload_from_env()
        wr = bool(_tg._worker is not None and _tg._worker.is_alive())
        tok = _tg._token
        hint = ""
        if len(tok) >= 12:
            hint = tok[:6] + "…" + tok[-4:]
        try:
            qsz = _tg._q.qsize()
        except Exception:
            qsz = -1
        return {
            "enabled": bool(_tg._token and _tg._chats),
            "chats": len(_tg._chats),
            "min_level": _tg._min,
            "queue_size": qsz,
            "worker_running": wr,
            "last_error": getattr(_tg, "_last_error", "") or "",
            "last_send_ok": bool(getattr(_tg, "_last_send_ok", False)),
            "token_hint": hint,
        }
    except Exception as exc:
        logger.exception("telegram_status failed")
        return {
            "enabled": False,
            "chats": 0,
            "min_level": "info",
            "queue_size": 0,
            "worker_running": False,
            "last_error": str(exc),
            "last_send_ok": False,
            "token_hint": "",
            "status_module_error": True,
        }


def send_telegram_text_now(text: str) -> tuple[bool, str]:
    """Blocking send to all configured chats (for /admin/telegram/test)."""
    _tg.reload_from_env()
    text = (text or "").strip() or "Croc Sentinel: test"
    if not _tg.enabled():
        return False, "Telegram disabled: set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS on the server only (not in git)."
    bad: list[str] = []
    for chat in _tg._chats:
        if not _tg._send_one(chat, text[:4090]):
            bad.append(str(chat))
    if bad:
        return False, f"failed for chat_id(s): {','.join(bad)} — check token, chat id, and bot started chat with you"
    return True, f"sent to {len(_tg._chats)} chat(s)"


def send_telegram_chat_text(chat_id: str, text: str) -> tuple[bool, str]:
    """Blocking send to one chat_id (for webhook command replies)."""
    _tg.reload_from_env()
    chat = (chat_id or "").strip()
    if not chat:
        return False, "empty chat_id"
    if not _tg._token:
        return False, "Telegram disabled: TELEGRAM_BOT_TOKEN empty"
    ok = _tg._send_one(chat, (text or "").strip()[:4090] or "ok")
    if not ok:
        return False, getattr(_tg, "_last_error", "") or "send failed"
    return True, "sent"


def telegram_get_webhook_info() -> tuple[bool, str, dict[str, Any]]:
    """Call Bot API getWebhookInfo (for dashboard diagnostics)."""
    _tg.reload_from_env()
    if not _tg._token:
        return False, "TELEGRAM_BOT_TOKEN empty", {}
    url = f"https://api.telegram.org/bot{_tg._token}/getWebhookInfo"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "CrocSentinel-TelegramNotify/1.0"},
    )
    try:
        ctx = _tg._get_ssl_context()
        kw: dict[str, Any] = {"timeout": 20}
        if ctx is not None:
            kw["context"] = ctx
        with urllib.request.urlopen(req, **kw) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            j = json.loads(raw)
        if not j.get("ok"):
            return False, str(j.get("description") or raw[:300]), {}
        return True, "", dict(j.get("result") or {})
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:400]
        return False, f"HTTPError {exc.code}: {err_body}", {}
    except Exception as exc:
        logger.warning("telegram getWebhookInfo failed: %s", exc)
        return False, str(exc), {}
