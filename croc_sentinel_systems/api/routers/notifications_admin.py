"""Notification-recipient admin routes (Phase-11, trimmed Phase-85).

Surface evolution:
  Phase 11 — original module: 10 admin routes covering recipient
              CRUD + 4-channel diagnostics (SMTP/Telegram/FCM)
              under ``/admin/*``.
  Phase 85 — extracted the 6 channel-diagnostic routes (SMTP/
              Telegram/FCM status + test + webhook-info) and
              their 2 schemas into
              ``routers/notifications_admin_diagnostics.py``,
              leaving recipient CRUD here.

Routes (still here)
-------------------
  * ``GET    /admin/alert-recipients``       — list per-tenant recipients.
  * ``POST   /admin/alert-recipients``       — add a recipient.
  * ``PATCH  /admin/alert-recipients/{rid}`` — toggle / rename.
  * ``DELETE /admin/alert-recipients/{rid}`` — remove.

Schemas owned here
------------------
  RecipientCreateRequest, RecipientUpdateRequest

The 6 diagnostic routes (SMTP/Telegram/FCM status, test, and
webhook-info) and their 2 schemas (``SmtpTestRequest``,
``TelegramTestRequest``) live in
``routers/notifications_admin_diagnostics.py``. Both routers share
the ``"notifications-admin"`` OpenAPI tag so the docs group all 10
endpoints together for end users.

Drive-by: ``_admin_scope_for`` was defined alongside these routes in
``app.py`` but never called anywhere in the codebase. Dropped during
the original Phase-11 extract.

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
from helpers import utc_now_iso
from security import Principal, assert_min_role

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


# Phase-85 split: ``SmtpTestRequest`` and ``TelegramTestRequest`` moved
# to ``routers/notifications_admin_diagnostics.py`` along with the 6
# channel-diagnostic routes (SMTP / Telegram / FCM status + test +
# webhook-info). Both routers share the ``notifications-admin`` tag.


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


# Phase-85 split: the 6 channel-diagnostic routes (SMTP status + test,
# Telegram status + test + webhook-info, FCM status) live in
# ``routers/notifications_admin_diagnostics.py``. Both routers share
# the ``notifications-admin`` tag so the OpenAPI doc still groups all
# 10 endpoints together for end users.
