"""Telegram bot webhook (Phase-67 split from ``routers/telegram.py``,
trimmed Phase 78).

Owns the **transport** half of the Telegram integration:

  * Bot API webhook (``X-Telegram-Bot-Api-Secret-Token`` validation).
  * ``/start`` deep-link binding flow (deep link
    ``https://t.me/<bot>?start=bind_<token>`` → consume the
    one-shot ``telegram_link_tokens`` row → bind chat to user).
  * Chat-allowlist gate (``TELEGRAM_COMMAND_CHAT_IDS``).
  * Reply send (calls ``telegram_notify.send_telegram_chat_text``).
  * Principal lookup (``_bound_principal``).

The **command grammar** half (text parser → capability gates →
data readers → MQTT publisher) lives in
``routers/telegram_commands.py`` (Phase 78 split). The webhook
calls ``telegram_commands.handle_text(principal, text)`` and
ships the returned reply to the chat.

Routes
------
  POST /integrations/telegram/webhook   — Telegram Bot API webhook;
                                          handles /start, /whoami,
                                          and the natural-language
                                          command grammar.

Bind helper
-----------
``_telegram_bind_chat`` is imported from ``routers.telegram`` because
the webhook's ``/start bind_<token>`` path inserts a chat binding
inline — same shared helper POST /admin/telegram/bind-self uses,
so we have a single definition site.

Late binding
------------
Captured at module load time:

  Functions:
    principal_for_username — chat→Principal resolver in
    ``_telegram_bound_principal``; bound here so test rigs that
    stub it out on ``app`` propagate to the webhook.

  State (re-read via ``getattr(_app, …)`` on every webhook call
  because these flip after import time):
    api_ready_event, api_bootstrap_error, TELEGRAM_COMMAND_CHAT_IDS.

The command-grammar late-binds (emit_event, get_manager_admin,
get_effective_policy, _device_is_online_sql_row, require_capability,
resolve_target_devices, publish_command, get_cmd_key_for_device,
zone_sql_suffix, owner_scope_clause_for_device_state) moved with
the grammar to ``routers/telegram_commands.py``.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request

import app as _app
from config import TELEGRAM_COMMAND_SECRET
from db import db_lock, get_conn
from helpers import utc_now_iso
from routers.telegram import _telegram_bind_chat
from routers.telegram_commands import handle_text as _telegram_cmd_handle_text
from security import Principal

principal_for_username = _app.principal_for_username


logger = logging.getLogger("croc-api.routers.telegram_webhook")
router = APIRouter(tags=["telegram"])


# ─────────────────────────────────── helpers (webhook plumbing) ────


def _telegram_cmd_send_reply(chat_id: str, text: str) -> tuple[bool, str]:
    """Best-effort sendMessage for chat replies.

    The lazy import on ``telegram_notify`` lets the webhook keep
    working even if the notify module fails to load (the worker
    thread is optional; the bot can still receive webhooks).
    """
    try:
        from telegram_notify import send_telegram_chat_text
    except Exception as exc:
        return False, f"telegram module unavailable: {exc}"
    return send_telegram_chat_text(chat_id, text)


def _telegram_cmd_send_reply_logged(chat_id: str, text: str, context: str) -> None:
    """Send + log the failure mode for diagnostics.

    The ``context`` string lets logs carry which webhook branch
    produced the reply (``bind_ok`` / ``bind_bad_token`` /
    ``command_reply`` / etc.) so an operator scanning logs after a
    silent-bot incident can locate which path went sideways.
    """
    ok, detail = _telegram_cmd_send_reply(chat_id, text)
    if not ok:
        logger.warning(
            "telegram webhook: send failed (%s) chat_id=%s: %s",
            context, chat_id, detail,
        )


def _telegram_bound_principal(chat_id: str) -> Principal:
    """Resolve the chat_id to a Principal via ``telegram_chat_bindings``.

    Raises 403 when the chat isn't bound at all or the binding row's
    ``enabled`` flag is 0 (operator can soft-disable a chat without
    deleting the binding to revoke command access).
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, enabled FROM telegram_chat_bindings WHERE chat_id = ?",
            (chat_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=403, detail="chat is not bound")
    if int(row["enabled"] or 0) != 1:
        raise HTTPException(status_code=403, detail="chat binding disabled")
    return principal_for_username(str(row["username"]))


# ───────────────────────────────────────────────────────── webhook ────

@router.post("/integrations/telegram/webhook")
def telegram_webhook(
    request: Request,
    payload: dict[str, Any],
    x_telegram_bot_api_secret_token: Optional[str] = Header(default=None, alias="X-Telegram-Bot-Api-Secret-Token"),
) -> dict[str, Any]:
    # Re-read at call time: api_ready_event is module-level on app and may
    # transition; api_bootstrap_error is set after a failed bootstrap and we
    # don't want a stale snapshot from import time.
    if not _app.api_ready_event.is_set():
        raise HTTPException(status_code=503, detail="service starting")
    if getattr(_app, "api_bootstrap_error", None):
        raise HTTPException(status_code=503, detail="bootstrap failed")
    # Proxies sometimes preserve header casing differently; fall back to raw request.
    secret_hdr = (x_telegram_bot_api_secret_token or "").strip()
    if not secret_hdr:
        secret_hdr = (request.headers.get("x-telegram-bot-api-secret-token") or "").strip()
    if TELEGRAM_COMMAND_SECRET and secret_hdr != TELEGRAM_COMMAND_SECRET:
        logger.warning(
            "telegram webhook: rejected (TELEGRAM_COMMAND_SECRET mismatch or missing secret header). "
            "Set BotFather webhook secret_token to the same value as TELEGRAM_COMMAND_SECRET, "
            "or leave TELEGRAM_COMMAND_SECRET empty if not using a webhook secret."
        )
        return {"ok": True, "ignored": "bad_secret"}
    msg = payload.get("message") or payload.get("channel_post") or payload.get("edited_message") or {}
    if not isinstance(msg, dict):
        return {"ok": True, "ignored": "no_message"}
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "").strip()
    if not chat_id:
        return {"ok": True, "ignored": "no_chat_id"}
    text = str(msg.get("text") or "").strip()
    if not text:
        return {"ok": True, "ignored": "no_text"}

    # Allow everyone to discover chat_id and perform one-time deep-link bind.
    if text.strip().lower().startswith("/start") or text.strip().lower() in ("start", "/whoami", "whoami"):
        parts = text.strip().split(maxsplit=1)
        payload = parts[1].strip() if len(parts) > 1 else ""
        if payload.startswith("bind_"):
            token = payload[len("bind_"):].strip()
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT token, username, expires_at_ts, used_at
                    FROM telegram_link_tokens
                    WHERE token = ?
                    """,
                    (token,),
                )
                row = cur.fetchone()
                if not row:
                    conn.close()
                    _telegram_cmd_send_reply_logged(
                        chat_id, "Invalid link token. Generate a new one from dashboard.", "bind_bad_token"
                    )
                    return {"ok": True, "processed": True, "bound": False, "reason": "bad_token"}
                if row["used_at"]:
                    conn.close()
                    _telegram_cmd_send_reply_logged(chat_id, "This link token is already used.", "bind_used_token")
                    return {"ok": True, "processed": True, "bound": False, "reason": "used_token"}
                if int(row["expires_at_ts"]) < int(time.time()):
                    conn.close()
                    _telegram_cmd_send_reply_logged(
                        chat_id, "Link token expired. Generate a new one from dashboard.", "bind_expired"
                    )
                    return {"ok": True, "processed": True, "bound": False, "reason": "expired_token"}
                username = str(row["username"])
                cur.execute("UPDATE telegram_link_tokens SET used_at = ? WHERE token = ?", (utc_now_iso(), token))
                conn.commit()
                conn.close()
            _telegram_bind_chat(chat_id, username, True)
            _telegram_cmd_send_reply_logged(
                chat_id, f"Bound OK: {username}\nYou can now use bot commands.", "bind_ok"
            )
            return {"ok": True, "processed": True, "bound": True, "username": username}
        _telegram_cmd_send_reply_logged(
            chat_id,
            f"chat_id={chat_id}\nBind this in dashboard Telegram settings (or use a dashboard-generated bind link).",
            "start_chat_id",
        )
        return {"ok": True, "processed": True, "bound": False}

    # Command allowlist applies to command execution (not /start binding flow).
    # Re-read at call time: app may rebuild this allowlist on hot config reload.
    chat_id_allowlist = getattr(_app, "TELEGRAM_COMMAND_CHAT_IDS", set())
    if chat_id_allowlist and chat_id not in chat_id_allowlist:
        return {"ok": True, "ignored": "chat_not_allowed"}

    try:
        principal = _telegram_bound_principal(chat_id)
        reply = _telegram_cmd_handle_text(principal, text)
    except HTTPException as exc:
        reply = f"Denied: {exc.detail}"
    except Exception as exc:
        logger.exception("telegram command failed")
        reply = f"Error: {exc}"
    _telegram_cmd_send_reply_logged(chat_id, reply, "command_reply")
    return {"ok": True, "processed": True}


__all__ = ("router",)
