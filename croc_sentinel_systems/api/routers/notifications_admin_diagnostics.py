"""Notification-channel diagnostic routes
(Phase-85 split from ``routers/notifications_admin.py``).

The Phase-11 ``routers/notifications_admin.py`` extract bundled two
distinct admin surfaces under ``/admin/*``:

  * **Recipient CRUD** (4 routes): list/create/update/delete on the
    ``alert_recipients`` table. Multi-tenant scoped, requires write
    locks, mutates persisted state. Tested through normal admin
    workflows.
  * **Channel diagnostics** (6 routes): read-only health probes and
    canary sends for SMTP / Telegram / FCM. No database writes,
    no tenant scoping (channels are global config), only audit
    rows on canary sends. Used to debug deployment issues
    (token expired, SMTP relay down, Telegram webhook
    misconfigured, FCM service-account JSON not loaded).

Phase 85 splits the diagnostics out so the recipient CRUD module
isn't cluttered with channel-specific imports
(``telegram_notify`` / ``fcm_notify``) that aren't relevant to
its primary job.

Routes
------
  GET  /admin/smtp/status                — notifier health snapshot.
  POST /admin/smtp/test                  — send canary email.
  GET  /admin/telegram/status            — Telegram worker health.
  GET  /admin/fcm/status                 — FCM worker health.
  POST /admin/telegram/test              — send canary Telegram msg.
  GET  /admin/telegram/webhook-info      — getWebhookInfo for
                                          debugging /start no-reply.

Schemas owned here
------------------
  SmtpTestRequest, TelegramTestRequest

Why deferred imports of ``telegram_notify`` and ``fcm_notify``
-------------------------------------------------------------
Both modules optional-load OAuth / SMTP libraries at import time.
Importing them at module-load would (a) drag those deps into every
unit test that imports any router, and (b) fail noisily on a
deployment image that intentionally skipped the optional channels.
Doing the import inside each route lets us return a graceful 503
or fallback "disabled" status when the channel module is missing,
instead of crashing the whole API at import.

Late binding
------------
``require_principal`` is captured at module load from ``app``
(matches every other router). No other ``app.py`` helpers are
needed — these routes are pure delegations to the notifier /
telegram_notify / fcm_notify singletons.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from email_templates import render_smtp_test_email
from notifier import notifier
from security import Principal, assert_min_role
from tz_display import malaysia_now_iso

require_principal = _app.require_principal

logger = logging.getLogger("croc-api.routers.notifications_admin_diagnostics")
router = APIRouter(tags=["notifications-admin"])


# ─── Schemas ────────────────────────────────────────────────────────────────


class SmtpTestRequest(BaseModel):
    """Canary email body. Subject defaults to a server-rendered string
    so an admin who just wants to confirm the relay is alive doesn't
    have to type one."""

    to: str = Field(min_length=3, max_length=120)
    subject: Optional[str] = Field(default=None, max_length=200)


class TelegramTestRequest(BaseModel):
    """Canary Telegram message text. Capped at 3900 chars to fit the
    4096-byte Telegram message budget with our envelope."""

    text: str = Field(default="Croc Sentinel Telegram test OK", max_length=3900)


# ─── SMTP ───────────────────────────────────────────────────────────────────


@router.get("/admin/smtp/status")
def smtp_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Health snapshot from the notifier singleton.

    Returns whatever ``notifier.status()`` synthesizes — currently
    enabled flag, queue depth, last send result, and last error.
    Unauthenticated callers get 401 from ``require_principal``;
    non-admins get 403 from ``assert_min_role``.
    """
    assert_min_role(principal, "admin")
    return notifier.status()


@router.post("/admin/smtp/test")
def smtp_test(
    req: SmtpTestRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Send a canary email synchronously and surface the outcome.

    Synchronous (``send_sync``) is intentional — async dispatch via
    the notifier queue would defer the failure to a background
    worker, defeating the point of a "test" button. The route
    re-raises as ``502`` so the admin UI can show the actual SMTP
    relay error string.
    """
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


# ─── Telegram + FCM ─────────────────────────────────────────────────────────


@router.get("/admin/telegram/status")
def telegram_admin_status(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Telegram worker health.

    Imports inside the function so a deployment image that
    intentionally skipped Telegram doesn't fail at module-load —
    the route returns a "disabled" payload with the import error
    instead of crashing the whole API.
    """
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import telegram_status

        return telegram_status()
    except Exception as exc:
        logging.getLogger(__name__).exception(
            "telegram_admin_status import or call failed"
        )
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
def fcm_admin_status(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """FCM worker health.

    Same deferred-import pattern as ``telegram_admin_status`` —
    returns a fallback payload if the optional ``fcm_notify``
    module wasn't included in the deployment image.
    """
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
    """Send a canary Telegram message synchronously.

    Hard-fails with 503 if the ``telegram_notify`` module is missing
    (so the admin UI can distinguish "module missing" from
    "Telegram down"). Otherwise re-raises the send error as 502.
    """
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import send_telegram_text_now, telegram_status
    except ModuleNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "telegram_notify module missing from deployment image "
                "(rebuild API with telegram_notify.py)"
            ),
        ) from exc

    ok, detail = send_telegram_text_now(req.text.strip())
    if not ok:
        audit_event(principal.username, "telegram.test.fail", "", {"error": detail})
        raise HTTPException(status_code=502, detail=detail)
    audit_event(principal.username, "telegram.test.ok", "", {"detail": detail})
    return {"ok": True, "detail": detail, "telegram": telegram_status()}


@router.get("/admin/telegram/webhook-info")
def telegram_admin_webhook_info(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Surface Telegram ``getWebhookInfo`` (URL, last_error, pending)
    so admins can debug ``/start`` no-reply scenarios.

    The expected_path field is hard-coded so the UI can compare it
    against Telegram's reported webhook URL in one place.
    """
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
    return {
        "ok": True,
        "webhook": info,
        "expected_path": "/integrations/telegram/webhook",
    }


__all__ = (
    "router",
    "SmtpTestRequest",
    "TelegramTestRequest",
)
