"""Telegram bot webhook + command grammar (Phase-67 split from ``routers/telegram.py``).

The original Phase-12 module covered both halves of the integration —
binding management (link-token, bind-self, list, unbind, enable) and
the natural-language command webhook. They have *very* different
review surfaces:

  * bindings are simple CRUD against ``telegram_chat_bindings``;
  * the webhook is a 100-line state machine that reads device data,
    publishes MQTT commands, parses ``/start <bind_token>`` deep
    links, and gates on a TELEGRAM_COMMAND_SECRET header.

Phase 67 splits the webhook + its 9 command helpers out so the
binding CRUD is independently reviewable without dragging the
command parser, capability gates, MQTT publisher, and recent-devices
SQL into the same diff.

Routes
------
  POST /integrations/telegram/webhook   — Telegram Bot API webhook;
                                          handles /start, /whoami,
                                          and the natural-language
                                          command grammar.

Bind helper
-----------
This module imports ``_telegram_bind_chat`` from ``routers.telegram``
because the webhook's ``/start bind_<token>`` path inserts a chat
binding inline (same shared helper that POST /admin/telegram/bind-self
uses, so we have one definition site).

Late binding
------------
Captured at module load time, after ``app.py`` has executed past
these defs:

  Functions:
    require_principal, emit_event, get_manager_admin,
    get_effective_policy, principal_for_username,
    _device_is_online_sql_row, require_capability,
    resolve_target_devices, publish_command,
    get_cmd_key_for_device, zone_sql_suffix,
    owner_scope_clause_for_device_state.

  State:
    api_ready_event, api_bootstrap_error,
    TELEGRAM_COMMAND_CHAT_IDS — re-read via ``getattr(_app, ...)``
    on each webhook call because they can change after import time
    (readiness flips on bootstrap, allowlist on hot config reload).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request

import app as _app
from config import (
    CMD_PROTO,
    DEFAULT_REMOTE_FANOUT_MS,
    TELEGRAM_COMMAND_MAX_DEVICES,
    TELEGRAM_COMMAND_MAX_LOG,
    TELEGRAM_COMMAND_SECRET,
    TOPIC_ROOT,
)
from db import db_lock, get_conn
from helpers import utc_now_iso
from routers.telegram import _telegram_bind_chat
from security import Principal

require_principal = _app.require_principal
emit_event = _app.emit_event
get_manager_admin = _app.get_manager_admin
get_effective_policy = _app.get_effective_policy
principal_for_username = _app.principal_for_username
_device_is_online_sql_row = _app._device_is_online_sql_row
require_capability = _app.require_capability
resolve_target_devices = _app.resolve_target_devices
publish_command = _app.publish_command
get_cmd_key_for_device = _app.get_cmd_key_for_device
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state


logger = logging.getLogger("croc-api.routers.telegram_webhook")
router = APIRouter(tags=["telegram"])


# ───────────────────────────────────── helpers (webhook + commands) ────

def _telegram_cmd_send_reply(chat_id: str, text: str) -> tuple[bool, str]:
    try:
        from telegram_notify import send_telegram_chat_text
    except Exception as exc:
        return False, f"telegram module unavailable: {exc}"
    return send_telegram_chat_text(chat_id, text)


def _telegram_cmd_send_reply_logged(chat_id: str, text: str, context: str) -> None:
    ok, detail = _telegram_cmd_send_reply(chat_id, text)
    if not ok:
        logger.warning("telegram webhook: send failed (%s) chat_id=%s: %s", context, chat_id, detail)


def _telegram_policy_allow(principal: Principal, capability: str) -> bool:
    if principal.role == "superadmin":
        return True
    pol = get_effective_policy(principal)
    return int(pol.get(capability, 0)) == 1


def _telegram_require(principal: Principal, capability: str) -> None:
    if not _telegram_policy_allow(principal, capability):
        raise HTTPException(status_code=403, detail=f"telegram capability denied: {capability}")


def _telegram_bound_principal(chat_id: str) -> Principal:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, enabled FROM telegram_chat_bindings WHERE chat_id = ?", (chat_id,))
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=403, detail="chat is not bound")
    if int(row["enabled"] or 0) != 1:
        raise HTTPException(status_code=403, detail="chat binding disabled")
    return principal_for_username(str(row["username"]))


def _telegram_parse_targets(token: str) -> list[str]:
    raw = (token or "").strip()
    if not raw:
        return []
    if raw.lower() == "all":
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _telegram_cmd_recent_devices(principal: Principal, limit: int) -> str:
    _telegram_require(principal, "tg_view_devices")
    n = max(1, min(limit, TELEGRAM_COMMAND_MAX_DEVICES))
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id, IFNULL(display_label, '') AS display_label, IFNULL(zone,'') AS zone,
                   IFNULL(fw,'') AS fw, updated_at, last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state
            WHERE 1=1 {zs} {osf}
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            tuple(za + osa + [n]),
        )
        rows = cur.fetchall()
        conn.close()
    now_s = int(time.time())
    lines = [f"Devices (latest {len(rows)}):"]
    for r in rows:
        d = dict(r)
        online = _device_is_online_sql_row(d, now_s)
        did = str(d.get("device_id") or "")
        label = str(d.get("display_label") or "")
        fw = str(d.get("fw") or "-")
        zone = str(d.get("zone") or "all")
        tag = "online" if online else "offline"
        lines.append(f"- {did} [{tag}] fw={fw} zone={zone}" + (f" label={label}" if label else ""))
    return "\n".join(lines)[:3900]


def _telegram_cmd_recent_logs(principal: Principal, limit: int) -> str:
    _telegram_require(principal, "tg_view_logs")
    n = max(1, min(limit, TELEGRAM_COMMAND_MAX_LOG))
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT ts, level, category, event_type, IFNULL(device_id,'') AS device_id, IFNULL(summary,'') AS summary
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (n,),
            )
        elif principal.role == "admin":
            cur.execute(
                """
                SELECT ts, level, category, event_type, IFNULL(device_id,'') AS device_id, IFNULL(summary,'') AS summary
                FROM events
                WHERE owner_admin = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (principal.username, n),
            )
        else:
            mgr = get_manager_admin(principal.username)
            cur.execute(
                """
                SELECT ts, level, category, event_type, IFNULL(device_id,'') AS device_id, IFNULL(summary,'') AS summary
                FROM events
                WHERE owner_admin = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (mgr or "__none__", n),
            )
        rows = cur.fetchall()
        conn.close()
    lines = [f"Logs (latest {len(rows)}):"]
    for r in rows:
        ts = str(r["ts"] or "")
        lvl = str(r["level"] or "info").upper()
        cat = str(r["category"] or "-")
        et = str(r["event_type"] or "-")
        did = str(r["device_id"] or "-")
        summary = str(r["summary"] or "")[:90]
        lines.append(f"- {ts} [{lvl}] {cat}/{et} dev={did} {summary}")
    return "\n".join(lines)[:3900]


def _telegram_cmd_publish(principal: Principal, cmd: str, params: dict[str, Any], ids: list[str], bulk_cap: str) -> tuple[int, int]:
    if cmd in ("siren_on", "siren_off"):
        require_capability(principal, "can_alert")
    else:
        require_capability(principal, "can_send_command")
    if ids:
        _telegram_require(principal, "tg_test_single" if cmd == "self_test" else ("tg_siren_on" if cmd == "siren_on" else "tg_siren_off"))
    else:
        _telegram_require(principal, bulk_cap)
    targets = resolve_target_devices(ids, principal=principal)
    sent = 0
    for did in targets:
        try:
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd=cmd,
                params=params,
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            sent += 1
        except Exception as exc:
            logger.warning("telegram cmd publish %s -> %s failed: %s", cmd, did, exc)
    return sent, len(targets)


def _telegram_cmd_handle_text(principal: Principal, text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return "Empty command. Try: help"
    if raw.startswith("/"):
        raw = raw[1:]
    raw = raw.split("@", 1)[0].strip()
    lower = raw.lower()

    if lower in ("start", "help", "h", "?"):
        return (
            "Commands:\n"
            "- devices [N]\n"
            "- log [N]\n"
            "- siren on <all|device|id1,id2> [duration_ms]\n"
            "- siren off <all|device|id1,id2>\n"
            "- test <device_id>\n"
            "- test all\n"
            "- test many <id1,id2,...>\n"
        )

    if lower.startswith("devices"):
        parts = lower.split()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        return _telegram_cmd_recent_devices(principal, n)

    if lower.startswith("log"):
        parts = lower.split()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        return _telegram_cmd_recent_logs(principal, n)

    if lower.startswith("siren on"):
        parts = raw.split()
        target_token = "all" if len(parts) < 3 else parts[2]
        duration_ms = DEFAULT_REMOTE_FANOUT_MS
        if len(parts) >= 4 and parts[3].isdigit():
            duration_ms = int(parts[3])
        duration_ms = max(500, min(duration_ms, 300000))
        ids = _telegram_parse_targets(target_token)
        cap = "tg_siren_on"
        sent, total = _telegram_cmd_publish(principal, "siren_on", {"duration_ms": duration_ms}, ids, cap)
        emit_event(
            level="warn",
            category="alarm",
            event_type="telegram.siren_on",
            summary=f"telegram siren_on sent={sent}/{total}",
            actor=f"telegram:{principal.username}",
            owner_admin=None if principal.role == "superadmin" else (principal.username if principal.role == "admin" else get_manager_admin(principal.username)),
            detail={"target": target_token, "duration_ms": duration_ms},
        )
        return f"siren_on done: sent={sent}/{total}, duration_ms={duration_ms}, target={target_token}"

    if lower.startswith("siren off"):
        parts = raw.split()
        target_token = "all" if len(parts) < 3 else parts[2]
        ids = _telegram_parse_targets(target_token)
        cap = "tg_siren_off"
        sent, total = _telegram_cmd_publish(principal, "siren_off", {}, ids, cap)
        emit_event(
            level="warn",
            category="alarm",
            event_type="telegram.siren_off",
            summary=f"telegram siren_off sent={sent}/{total}",
            actor=f"telegram:{principal.username}",
            owner_admin=None if principal.role == "superadmin" else (principal.username if principal.role == "admin" else get_manager_admin(principal.username)),
            detail={"target": target_token},
        )
        return f"siren_off done: sent={sent}/{total}, target={target_token}"

    if lower in ("test all", "device all test", "devices all test"):
        sent, total = _telegram_cmd_publish(principal, "self_test", {}, [], "tg_test_bulk")
        return f"self_test(all) done: sent={sent}/{total}"

    if lower.startswith("test many "):
        ids = _telegram_parse_targets(raw[10:])
        if not ids:
            return "No device ids provided."
        sent, total = _telegram_cmd_publish(principal, "self_test", {}, ids, "tg_test_bulk")
        return f"self_test(many) done: sent={sent}/{total}"

    if lower.startswith("test "):
        did = raw.split(maxsplit=1)[1].strip() if len(raw.split(maxsplit=1)) > 1 else ""
        if not did:
            return "Usage: test <device_id>"
        sent, total = _telegram_cmd_publish(principal, "self_test", {}, [did], "tg_test_single")
        return f"self_test(single) done: sent={sent}/{total}"

    return "Unknown command. Try: help"


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
