"""Telegram link/bind admin routes (Phase-12, trimmed in Phase-67).

The original Phase-12 module covered the entire Telegram surface
(6 routes, 9 helpers, 609 lines). Phase 67 split the
``/integrations/telegram/webhook`` route and its 9 command-grammar
helpers out into ``routers/telegram_webhook.py`` so this file now
hosts only the dashboard-facing CRUD half:

  * ``POST   /telegram/link-token``                       — issue one-time deep-link bind token (any user)
  * ``POST   /admin/telegram/bind-self``                  — bind a chat_id to self
  * ``GET    /admin/telegram/bindings``                   — list bindings (own / all)
  * ``DELETE /admin/telegram/bindings/{chat_id}``         — unbind
  * ``PATCH  /admin/telegram/bindings/{chat_id}/enabled`` — toggle without unbinding

The /admin/telegram/{status,test,webhook-info} *test/status* endpoints
already moved in Phase 11 (they live in routers/notifications_admin.py).
The webhook + command grammar moved in Phase 67 (routers/telegram_webhook.py).

Shared helper
-------------
``_telegram_bind_chat`` stays here because both halves need it:
  * POST /admin/telegram/bind-self → calls it directly;
  * the webhook /start bind_<token> flow → imports it from this
    module (single definition site for the chat-binding upsert).

Late-bound dependencies on ``app.py``
-------------------------------------
Captured at module load time (in import order, after app.py runs):

  Functions:
    require_principal
    _invalidate_superadmin_telegram_chats_cache

We deliberately reference the function objects directly in
``Depends(require_principal)`` — never wrap in a lambda, that strips
FastAPI's parameter injection. See routers/factory.py for a long
write-up of the trap.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    TELEGRAM_BOT_USERNAME,
    TELEGRAM_LINK_TOKEN_TTL_SECONDS,
)
from db import db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
_invalidate_superadmin_telegram_chats_cache = _app._invalidate_superadmin_telegram_chats_cache


logger = logging.getLogger("croc-api.routers.telegram")
router = APIRouter(tags=["telegram"])


# ───────────────────────────────────────────────────── request schemas ────

class TelegramBindRequest(BaseModel):
    chat_id: str = Field(min_length=1, max_length=64)
    enabled: bool = True


class TelegramLinkTokenRequest(BaseModel):
    enabled_on_bind: bool = True


# ───────────────────────────────────────────────── shared bind helper ────

def _telegram_bind_chat(chat_id: str, username: str, enabled: bool) -> None:
    """Upsert a Telegram chat binding.

    Used by:
      * POST /admin/telegram/bind-self in this module;
      * the webhook /start bind_<token> deep-link flow in
        ``routers/telegram_webhook.py`` (which imports this name).
    """
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO telegram_chat_bindings (chat_id, username, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                username=excluded.username,
                enabled=excluded.enabled,
                updated_at=excluded.updated_at
            """,
            (chat_id, username, 1 if enabled else 0, now, now),
        )
        conn.commit()
        conn.close()
    _invalidate_superadmin_telegram_chats_cache()


# ───────────────────────────────────────────────────────────── routes ────

@router.post("/telegram/link-token")
def telegram_link_token(
    req: TelegramLinkTokenRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    token = secrets.token_urlsafe(24)
    expires_at_ts = int(time.time()) + max(60, TELEGRAM_LINK_TOKEN_TTL_SECONDS)
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO telegram_link_tokens (token, username, expires_at_ts, used_at, created_at)
            VALUES (?, ?, ?, NULL, ?)
            """,
            (token, principal.username, expires_at_ts, now),
        )
        conn.commit()
        conn.close()
    payload = f"bind_{token}"
    deep_link = ""
    open_chat_url = ""
    if TELEGRAM_BOT_USERNAME:
        open_chat_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}"
        deep_link = f"https://t.me/{TELEGRAM_BOT_USERNAME}?start={payload}"
    return {
        "ok": True,
        "token": token,
        "bot_username": TELEGRAM_BOT_USERNAME,
        "open_chat_url": open_chat_url,
        "start_payload": payload,
        "deep_link": deep_link,
        "expires_at_ts": expires_at_ts,
        "enabled_on_bind": bool(req.enabled_on_bind),
    }


@router.post("/admin/telegram/bind-self")
def telegram_bind_self(req: TelegramBindRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    chat_id = req.chat_id.strip()
    _telegram_bind_chat(chat_id, principal.username, bool(req.enabled))
    audit_event(principal.username, "telegram.bind.self", chat_id, {"enabled": req.enabled})
    return {"ok": True, "chat_id": chat_id, "username": principal.username, "enabled": bool(req.enabled)}


@router.get("/admin/telegram/bindings")
def telegram_bindings(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("SELECT chat_id, username, enabled, created_at, updated_at FROM telegram_chat_bindings ORDER BY updated_at DESC")
        else:
            cur.execute(
                "SELECT chat_id, username, enabled, created_at, updated_at FROM telegram_chat_bindings WHERE username = ? ORDER BY updated_at DESC",
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.delete("/admin/telegram/bindings/{chat_id}")
def telegram_unbind(chat_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("DELETE FROM telegram_chat_bindings WHERE chat_id = ?", (chat_id,))
        else:
            cur.execute("DELETE FROM telegram_chat_bindings WHERE chat_id = ? AND username = ?", (chat_id, principal.username))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="binding not found")
    _invalidate_superadmin_telegram_chats_cache()
    audit_event(principal.username, "telegram.unbind", chat_id, {})
    return {"ok": True}


@router.patch("/admin/telegram/bindings/{chat_id}/enabled")
def telegram_binding_set_enabled(
    chat_id: str,
    enabled: bool = Query(...),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                "UPDATE telegram_chat_bindings SET enabled=?, updated_at=? WHERE chat_id=?",
                (1 if enabled else 0, utc_now_iso(), chat_id),
            )
        else:
            cur.execute(
                "UPDATE telegram_chat_bindings SET enabled=?, updated_at=? WHERE chat_id=? AND username=?",
                (1 if enabled else 0, utc_now_iso(), chat_id, principal.username),
            )
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="binding not found")
    _invalidate_superadmin_telegram_chats_cache()
    audit_event(principal.username, "telegram.bind.enabled", chat_id, {"enabled": bool(enabled)})
    return {"ok": True, "chat_id": chat_id, "enabled": bool(enabled)}


__all__ = (
    "router",
    "TelegramBindRequest",
    "TelegramLinkTokenRequest",
    "_telegram_bind_chat",
)
