"""
Optional Telegram fan-out for emit_event (non-blocking queue).

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
import threading
import urllib.error
import urllib.request
from typing import Any, Optional

logger = logging.getLogger("croc-telegram")

_LEVEL_RANK = {"debug": 0, "info": 1, "warn": 2, "error": 3, "critical": 4}


class _TelegramQueue:
    def __init__(self) -> None:
        self._token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        raw = os.getenv("TELEGRAM_CHAT_IDS", "").strip()
        self._chats = [c.strip() for c in raw.split(",") if c.strip()]
        self._min = (os.getenv("TELEGRAM_MIN_LEVEL", "info").strip().lower() or "info")
        self._min_rank = _LEVEL_RANK.get(self._min, 1)
        self._q: "queue.Queue[str]" = queue.Queue(maxsize=800)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None

    def enabled(self) -> bool:
        return bool(self._token and self._chats)

    def start(self) -> None:
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

    def maybe_enqueue(self, ev: dict[str, Any]) -> None:
        if not self.enabled():
            return
        lvl = str(ev.get("level") or "info").lower()
        if _LEVEL_RANK.get(lvl, 1) < self._min_rank:
            return
        # Plain text (no HTML) — avoids Telegram parse errors from arbitrary JSON/symbols.
        line = (
            f"[{lvl.upper()}] {ev.get('category')}/{ev.get('event_type')}\n"
            f"{ev.get('summary') or ''}\n"
            f"actor={ev.get('actor') or '-'} target={ev.get('target') or '-'} "
            f"device={ev.get('device_id') or '-'}"
        )
        if ev.get("detail"):
            try:
                d = ev["detail"]
                if isinstance(d, dict) and d:
                    line += "\n" + json.dumps(d, ensure_ascii=True)[:900]
            except Exception:
                pass
        try:
            self._q.put_nowait(line)
        except queue.Full:
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(line)
            except queue.Full:
                pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                text = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            for chat in self._chats:
                self._send_one(chat, text)

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
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if resp.status != 200:
                    logger.warning("telegram send HTTP %s", resp.status)
                    return False
                try:
                    j = json.loads(raw)
                except json.JSONDecodeError:
                    logger.warning("telegram non-json: %s", raw[:200])
                    return False
                if not j.get("ok"):
                    logger.warning("telegram api ok=false: %s", raw[:400])
                    return False
                return True
        except urllib.error.HTTPError as exc:
            logger.warning("telegram HTTPError %s: %s", exc.code, exc.read()[:200])
            return False
        except Exception as exc:
            logger.warning("telegram send failed: %s", exc)
            return False


_tg = _TelegramQueue()


def start_telegram_worker() -> None:
    _tg.start()


def stop_telegram_worker() -> None:
    _tg.stop()


def maybe_notify_telegram(ev: dict[str, Any]) -> None:
    _tg.maybe_enqueue(ev)


def telegram_status() -> dict[str, Any]:
    wr = bool(_tg._worker is not None and _tg._worker.is_alive())
    return {
        "enabled": _tg.enabled(),
        "chats": len(_tg._chats),
        "min_level": _tg._min,
        "queue_size": _tg._q.qsize(),
        "worker_running": wr,
    }


def send_telegram_text_now(text: str) -> tuple[bool, str]:
    """Blocking send to all configured chats (for /admin/telegram/test)."""
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
