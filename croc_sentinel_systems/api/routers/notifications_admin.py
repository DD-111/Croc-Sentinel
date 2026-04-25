"""Notification-channel admin routes (Phase-11 modularization extract from ``app.py``).

Ten admin endpoints covering the four outbound channels (email, SMTP,
Telegram, FCM):

  * ``GET    /admin/alert-recipients``        — list per-tenant recipients
  * ``POST   /admin/alert-recipients``        — add a recipient
  * ``PATCH  /admin/alert-recipients/{rid}``  — toggle / rename
  * ``DELETE /admin/alert-recipients/{rid}``  — remove
  * ``GET    /admin/smtp/status``             — notifier health
  * ``POST   /admin/smtp/test``               — send canary email
  * ``GET    /admin/telegram/status``         — Telegram worker health
  * ``GET    /admin/fcm/status``              — FCM worker health
  * ``POST   /admin/telegram/test``           — send canary Telegram msg
  * ``GET    /admin/telegram/webhook-info``   — Telegram getWebhookInfo

Drive-by: ``_admin_scope_for`` was defined alongside these routes in
``app.py`` but never called anywhere in the codebase. Dropped during
this extract.

Late-bound dependencies on ``app.py``: ``require_principal`` only.
The bcrypt-style trap with Depends(lambda: ...) is documented at length
in routers/factory.py — never wrap the function in a lambda or you
strip FastAPI's parameter injection.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import db_lock, get_conn
from email_templates import render_smtp_test_email
from helpers import utc_now_iso
from notifier import notifier
from security import Principal, assert_min_role
from tz_display import malaysia_now_iso

require_principal = _app.require_principal
get_manager_admin = _app.get_manager_admin

logger = logging.getLogger("croc-api.routers.notifications_admin")

router = APIRouter(tags=["notifications-admin"])


# ───────────────────────────────────────────────────── request schemas ────

class RecipientCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    label: Optional[str] = Field(default=None, max_length=80)
    enabled: bool = True


class RecipientUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    label: Optional[str] = Field(default=None, max_length=80)


class SmtpTestRequest(BaseModel):
    to: str = Field(min_length=3, max_length=120)
    subject: Optional[str] = Field(default=None, max_length=200)


class TelegramTestRequest(BaseModel):
    text: str = Field(default="Croc Sentinel Telegram test OK", max_length=3900)


# ──────────────────────────────────────────────────── alert recipients ────

@router.get("/admin/alert-recipients")
def list_recipients(
    for_admin: Optional[str] = Query(default=None),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if principal.role == "user":
        target = get_manager_admin(principal.username)
    elif principal.role == "admin":
        target = principal.username
    else:
        target = (for_admin or "").strip()
        if not target:
            return {"items": [], "scope": ""}
    if not target:
        return {"items": [], "scope": ""}
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, owner_admin, email, label, enabled, created_at
            FROM admin_alert_recipients
            WHERE owner_admin = ?
            ORDER BY id ASC
            """,
            (target,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows, "scope": target}


@router.post("/admin/alert-recipients")
def create_recipient(
    req: RecipientCreateRequest,
    for_admin: Optional[str] = Query(default=None),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "superadmin":
        target = (for_admin or "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="for_admin query param required for superadmin")
    else:
        target = principal.username
    if "@" not in req.email:
        raise HTTPException(status_code=400, detail="email is not valid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO admin_alert_recipients (owner_admin, email, label, enabled, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target, req.email.strip(), req.label or "", 1 if req.enabled else 0, utc_now_iso()),
            )
            new_id = int(cur.lastrowid)
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="email already registered for this admin")
        conn.close()
    audit_event(principal.username, "recipient.add", target, {"email": req.email})
    return {"ok": True, "id": new_id}


@router.patch("/admin/alert-recipients/{rid}")
def update_recipient(
    rid: int,
    req: RecipientUpdateRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM admin_alert_recipients WHERE id = ?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="recipient not found")
        owner = str(row["owner_admin"])
        if principal.role == "admin" and owner != principal.username:
            conn.close()
            raise HTTPException(status_code=403, detail="not yours")
        fields: list[str] = []
        args: list[Any] = []
        if req.enabled is not None:
            fields.append("enabled = ?")
            args.append(1 if req.enabled else 0)
        if req.label is not None:
            fields.append("label = ?")
            args.append(req.label)
        if not fields:
            conn.close()
            return {"ok": True, "noop": True}
        args.append(rid)
        cur.execute(f"UPDATE admin_alert_recipients SET {', '.join(fields)} WHERE id = ?", tuple(args))
        conn.commit()
        conn.close()
    audit_event(principal.username, "recipient.update", owner, {"id": rid})
    return {"ok": True}


@router.delete("/admin/alert-recipients/{rid}")
def delete_recipient(rid: int, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM admin_alert_recipients WHERE id = ?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="recipient not found")
        owner = str(row["owner_admin"])
        if principal.role == "admin" and owner != principal.username:
            conn.close()
            raise HTTPException(status_code=403, detail="not yours")
        cur.execute("DELETE FROM admin_alert_recipients WHERE id = ?", (rid,))
        conn.commit()
        conn.close()
    audit_event(principal.username, "recipient.delete", owner, {"id": rid})
    return {"ok": True}


# ──────────────────────────────────────────────────────────────── smtp ────

@router.get("/admin/smtp/status")
def smtp_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    return notifier.status()


@router.post("/admin/smtp/test")
def smtp_test(req: SmtpTestRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if "@" not in req.to:
        raise HTTPException(status_code=400, detail="invalid recipient")
    subject, text, html_body = render_smtp_test_email(
        actor_username=principal.username,
        iso_ts=malaysia_now_iso(),
        subject_override=req.subject,
    )
    try:
        notifier.send_sync([req.to], subject, text, html_body)
    except Exception as exc:
        audit_event(principal.username, "smtp.test.fail", req.to, {"error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Mail channel error: {exc}")
    audit_event(principal.username, "smtp.test.ok", req.to, {})
    return {"ok": True, "status": notifier.status()}


# ──────────────────────────────────────── telegram + fcm status/test ────

@router.get("/admin/telegram/status")
def telegram_admin_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import telegram_status

        return telegram_status()
    except Exception as exc:
        logging.getLogger(__name__).exception("telegram_admin_status import or call failed")
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


@router.get("/admin/fcm/status")
def fcm_admin_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    try:
        from fcm_notify import fcm_status

        return fcm_status()
    except Exception as exc:
        logging.getLogger(__name__).exception("fcm_admin_status import or call failed")
        return {
            "enabled": False,
            "project_id": "",
            "detail": str(exc),
            "last_error": str(exc),
            "queue_size": 0,
            "worker_running": False,
        }


@router.post("/admin/telegram/test")
def telegram_admin_test(
    req: TelegramTestRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import send_telegram_text_now, telegram_status
    except ModuleNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="telegram_notify module missing from deployment image (rebuild API with telegram_notify.py)",
        ) from exc

    ok, detail = send_telegram_text_now(req.text.strip())
    if not ok:
        audit_event(principal.username, "telegram.test.fail", "", {"error": detail})
        raise HTTPException(status_code=502, detail=detail)
    audit_event(principal.username, "telegram.test.ok", "", {"detail": detail})
    return {"ok": True, "detail": detail, "telegram": telegram_status()}


@router.get("/admin/telegram/webhook-info")
def telegram_admin_webhook_info(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Shows Telegram getWebhookInfo (URL, last_error, pending updates) for debugging /start no-reply."""
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import telegram_get_webhook_info
    except ModuleNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="telegram_notify module missing from deployment image",
        ) from exc
    ok, err, info = telegram_get_webhook_info()
    if not ok:
        raise HTTPException(status_code=502, detail=err)
    return {"ok": True, "webhook": info, "expected_path": "/integrations/telegram/webhook"}
