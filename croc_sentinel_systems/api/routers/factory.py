"""Factory provisioning routes (Phase-7 modularization extract from ``app.py``).

These four endpoints back the *manufacturing-time* device registration flow:

  * ``POST /factory/devices``                — bulk register (serial, mac, qr).
  * ``GET  /factory/ping``                   — auth probe for factory CI / scripts.
  * ``GET  /factory/devices``                — list factory rows (superadmin only).
  * ``POST /factory/devices/{serial}/block`` — RMA / block a serial.

Auth is intentionally non-standard for this prefix: the bulk-register and
ping endpoints accept *either* a superadmin JWT *or* a static
``X-Factory-Token`` header that matches ``FACTORY_API_TOKEN``. That way
the factory floor can run a token-only client without needing to mint a
superadmin password. See :func:`_require_factory_auth`.

The two read/admin endpoints (``GET /factory/devices`` and
``POST /factory/devices/{serial}/block``) require a real superadmin
principal and are wired through the standard ``Depends(require_principal)``
dependency.

Late-bound dependency on ``app.require_principal``
--------------------------------------------------
``require_principal`` lives in ``app.py`` because it touches the FastAPI
app context (cookies, JWT, audit-trail enrichment). To avoid an
``app → routers.factory → app`` import cycle at module-load time we
import the ``app`` *module* and resolve ``app.require_principal`` once at
this module's top — by the time the ``app.include_router(router)`` line
in ``app.py`` runs (after the ``app = FastAPI(...)`` instantiation), the
``require_principal`` definition (line ~2700 in app.py) has already been
evaluated, so the attribute lookup succeeds.

We deliberately reference the *function object*, not a wrapper. Wrapping
in ``Depends(lambda: app.require_principal())`` would strip FastAPI's
parameter injection (Cookie / Header / Request) and silently break auth.
"""

from __future__ import annotations

import re
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    CMD_PROTO,
    ENFORCE_FACTORY_REGISTRATION,
    FACTORY_API_TOKEN,
    FACTORY_VERIFY_QR_ON_REGISTER,
    QR_CODE_REGEX,
    QR_SIGN_SECRET,
)
from db import db_lock, get_conn
from device_security import verify_qr_signature
from helpers import utc_now_iso
from security import Principal, assert_min_role, decode_jwt

# Resolved once at import time; see module docstring for why this is safe.
require_principal = _app.require_principal

router = APIRouter(tags=["factory"])


class FactoryDeviceItem(BaseModel):
    serial: str = Field(pattern=r"^SN-[A-Z2-7]{16}$")
    mac_nocolon: Optional[str] = Field(default=None, min_length=12, max_length=12)
    qr_code: Optional[str] = Field(default=None, max_length=512)
    batch: Optional[str] = Field(default=None, max_length=64)
    note: Optional[str] = Field(default=None, max_length=256)


class FactoryBulkRequest(BaseModel):
    items: list[FactoryDeviceItem] = Field(min_length=1, max_length=2000)


def _require_factory_auth(request: Request) -> str:
    """Either superadmin JWT OR X-Factory-Token header matches FACTORY_API_TOKEN.

    We do the auth by hand here so that CI / factory scripts can use only the
    token and skip the JWT flow entirely.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            token = auth.split(" ", 1)[1].strip()
            # decode_jwt returns a Principal dataclass (not a dict). The earlier
            # `.get("role")` form silently raised AttributeError under
            # `except Exception: pass`, so the JWT path was effectively dead.
            principal = decode_jwt(token)
            if principal and str(getattr(principal, "role", "") or "") == "superadmin":
                return str(getattr(principal, "username", "") or "superadmin")
        except Exception:
            pass
    token = request.headers.get("x-factory-token", "")
    if FACTORY_API_TOKEN and token and secrets.compare_digest(token, FACTORY_API_TOKEN):
        return "factory-token"
    raise HTTPException(status_code=403, detail="factory auth required (superadmin JWT or X-Factory-Token)")


@router.post("/factory/devices")
def factory_register_bulk(body: FactoryBulkRequest, request: Request) -> dict[str, Any]:
    """Bulk-register (serial, mac, qr) tuples produced at manufacturing time.

    Authenticate as superadmin (JWT) **or** supply X-Factory-Token equal to
    FACTORY_API_TOKEN. Existing rows are updated in place.

    When ``QR_SIGN_SECRET`` is configured AND
    ``FACTORY_VERIFY_QR_ON_REGISTER=1`` (default), each item's ``qr_code`` is
    HMAC-verified BEFORE insertion. Any item whose signature is wrong is
    rejected up-front with the failing serial in the response — this catches
    forged or legacy unsigned QR payloads at upload time instead of letting
    them sit in ``factory_devices`` until a tenant tries to claim.
    """
    actor = _require_factory_auth(request)
    now = utc_now_iso()
    verify_qr = bool(QR_SIGN_SECRET) and FACTORY_VERIFY_QR_ON_REGISTER
    qr_re = re.compile(QR_CODE_REGEX)

    rejected: list[dict[str, str]] = []
    valid_items: list[FactoryDeviceItem] = []
    for it in body.items:
        mac = (it.mac_nocolon or "").upper() or None
        if mac and (len(mac) != 12 or not re.fullmatch(r"^[0-9A-F]{12}$", mac)):
            rejected.append({"serial": it.serial, "reason": "invalid mac"})
            continue
        if verify_qr:
            qr = (it.qr_code or "").strip()
            if not qr:
                rejected.append({"serial": it.serial, "reason": "qr_code missing"})
                continue
            if not qr_re.fullmatch(qr):
                rejected.append({"serial": it.serial, "reason": "qr_code policy"})
                continue
            if not verify_qr_signature(qr):
                rejected.append({"serial": it.serial, "reason": "qr_code signature"})
                continue
        valid_items.append(it)

    written = 0
    if valid_items:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            for it in valid_items:
                mac = (it.mac_nocolon or "").upper() or None
                cur.execute(
                    """INSERT INTO factory_devices (serial, mac_nocolon, qr_code, batch, status, note, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'unclaimed', ?, ?, ?)
                       ON CONFLICT(serial) DO UPDATE SET
                           mac_nocolon = COALESCE(excluded.mac_nocolon, factory_devices.mac_nocolon),
                           qr_code     = COALESCE(excluded.qr_code,     factory_devices.qr_code),
                           batch       = COALESCE(excluded.batch,       factory_devices.batch),
                           note        = COALESCE(excluded.note,        factory_devices.note),
                           updated_at  = excluded.updated_at""",
                    (it.serial, mac, it.qr_code, it.batch, it.note, now, now),
                )
                written += 1
            conn.commit()
            conn.close()

    audit_event(
        actor,
        "factory.register.bulk",
        f"count={written}",
        {
            "batch": body.items[0].batch if body.items else "",
            "rejected": len(rejected),
            "qr_verified": verify_qr,
        },
    )
    if rejected and not valid_items:
        # Whole batch rejected — surface as 400 so the UI/CLI fails loudly
        # instead of silently writing zero rows with a 200.
        raise HTTPException(
            status_code=400,
            detail={"ok": False, "written": 0, "rejected": rejected, "qr_verified": verify_qr},
        )
    return {
        "ok": True,
        "written": written,
        "rejected": rejected,
        "qr_verified": verify_qr,
    }


@router.get("/factory/ping")
def factory_ping(request: Request) -> dict[str, Any]:
    """Auth + environment probe for factory UIs / scripts.

    Returns the runtime knobs the UI needs to display "what server am I
    talking to?" — QR-sign requirement, factory-registration enforcement,
    cmd protocol version, and current server time. Lets the operator
    confirm they connected to the right deployment before generating a
    batch of serials.
    """
    actor = _require_factory_auth(request)
    return {
        "ok": True,
        "factory_auth": True,
        "actor": actor,
        "server_time": utc_now_iso(),
        "qr_sign_required": bool(QR_SIGN_SECRET),
        "qr_verify_on_register": bool(QR_SIGN_SECRET) and FACTORY_VERIFY_QR_ON_REGISTER,
        "enforce_factory_registration": bool(ENFORCE_FACTORY_REGISTRATION),
        "cmd_proto": int(CMD_PROTO),
        "qr_code_regex": QR_CODE_REGEX,
    }


@router.get("/factory/devices")
def factory_list(
    request: Request,
    status: Optional[str] = Query(default=None, pattern="^(unclaimed|claimed|blocked)$"),
    batch: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    sql = "SELECT serial, mac_nocolon, qr_code, batch, status, note, created_at, updated_at FROM factory_devices WHERE 1=1"
    args: list[Any] = []
    if status:
        sql += " AND status = ?"
        args.append(status)
    if batch:
        sql += " AND batch = ?"
        args.append(batch)
    sql += " ORDER BY created_at DESC LIMIT 1000"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        items = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": items}


@router.post("/factory/devices/{serial}/block")
def factory_block_device(
    serial: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE factory_devices SET status='blocked', updated_at=? WHERE serial=?", (utc_now_iso(), serial))
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="serial not found")
    audit_event(principal.username, "factory.block", serial, {})
    return {"ok": True}
