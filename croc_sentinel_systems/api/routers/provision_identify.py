"""Provision-identify router (Phase-70 split from ``routers/provision_lifecycle.py``).

The Phase-29 module bundled three operator-facing claim-flow endpoints
together. Phase 70 splits the read-only inspection step
(``POST /provision/identify``) into its own module so that the
write-side flow (pending list + claim) is reviewed separately from
the no-side-effect serial-state lookup.

The dashboard's "Activate device" wizard still walks operators
through identify -> pending -> claim in that order; the wizard only
imports them by URL, never by Python module name, so the split is
transparent to the UI.

Routes
------
  POST /provision/identify   (decide what state the serial is in)

Schemas owned here
------------------
  IdentifyRequest

Constants owned here
--------------------
  FACTORY_SERIAL_RE          (used only by /provision/identify)

Late-binding strategy
---------------------
``get_manager_admin`` is defined < line ~5300 in app.py, so it is
early-bound (identity preserved at module-import time):

  require_principal, require_capability, get_manager_admin
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from db import db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
get_manager_admin = _app.get_manager_admin


logger = logging.getLogger("croc-api.routers.provision_identify")

router = APIRouter(tags=["provision-identify"])


# Serial format: SN-<16 uppercase base32 chars>. 80 bits of CSPRNG entropy.
# The factory side generates these, never the device. Device only uses
# (serial, mac_nocolon) tuples that were uploaded to /factory/devices.
FACTORY_SERIAL_RE = re.compile(r"^SN-[A-Z2-7]{16}$")


# ---- Schemas ---------------------------------------------------------------

class IdentifyRequest(BaseModel):
    serial: Optional[str] = Field(default=None, max_length=23)
    qr_code: Optional[str] = Field(default=None, max_length=47)


# ---- Routes ----------------------------------------------------------------

@router.post("/provision/identify")
def provision_identify(
    body: IdentifyRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Answer "what state is this device in right now?" for the claim UI.

    The operator either scans the factory QR sticker or types the serial. We
    return one of:

      - unknown_serial       -> the serial is not in our factory registry
      - blocked              -> factory revoked this serial (RMA etc.)
      - already_registered   -> device is claimed
      - offline              -> device is in factory registry but has never
                                published bootstrap.register, i.e. it was
                                never online. Operator must power it up and
                                connect it to the network first.
      - ready                -> factory-registered, has bootstrap row, not
                                yet claimed. Caller can POST /provision/claim
                                with the returned mac_nocolon.
    """
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    serial = (body.serial or "").strip().upper()
    qr = (body.qr_code or "").strip()
    if qr:
        # QR can optionally be HMAC-signed; the claim step verifies the sig.
        # For identify we only need to pluck the serial out of the QR string.
        m = re.match(r"^CROC\|(SN-[A-Z2-7]{16})\|", qr)
        if m:
            serial = m.group(1)
    if not serial:
        raise HTTPException(status_code=400, detail="serial or qr_code is required")
    if not FACTORY_SERIAL_RE.match(serial):
        raise HTTPException(status_code=400, detail="serial format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT serial, mac_nocolon, qr_code, status FROM factory_devices WHERE serial = ?",
            (serial,),
        )
        fdev = cur.fetchone()
        conn.close()
    if not fdev:
        return {"status": "unknown_serial", "serial": serial,
                "message": "该序列号不在出厂清单，请确认扫描的是正品贴纸或联系管理员"}
    if str(fdev["status"] or "unclaimed") == "blocked":
        return {"status": "blocked", "serial": serial,
                "message": "该设备已被出厂侧禁用（RMA / 质量问题）"}
    # Already registered?
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT device_id, mac_nocolon, claimed_at FROM provisioned_credentials WHERE device_id = ?",
            (serial,),
        )
        prov = cur.fetchone()
        owner = None
        if prov:
            cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (serial,))
            ow = cur.fetchone()
            owner = str(ow["owner_admin"]) if ow else None
        conn.close()
    if prov:
        you = owner and (owner == principal.username or (
            principal.role == "user" and owner == get_manager_admin(principal.username)
        ))
        resp: dict[str, Any] = {
            "status": "already_registered",
            "serial": serial,
            "device_id": str(prov["device_id"]),
            "mac_nocolon": str(prov["mac_nocolon"]),
            "claimed_at": str(prov["claimed_at"]),
            "message": "设备已被登记，无法再次注册",
        }
        if principal.role == "superadmin":
            resp["owner_admin"] = owner
            resp["by_you"] = bool(you)
        return resp
    # Does it appear in pending_claims? That only happens after the device
    # comes online and publishes bootstrap.register on MQTT.
    mac_for_lookup = str(fdev["mac_nocolon"] or "").upper()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        pend = None
        if mac_for_lookup:
            cur.execute(
                "SELECT mac_nocolon, last_seen_at, fw FROM pending_claims WHERE mac_nocolon = ?",
                (mac_for_lookup,),
            )
            pend = cur.fetchone()
        # Factory CSV may still carry a placeholder MAC while bootstrap.register
        # upserts pending_claims with the real MAC — list_pending shows the row
        # but MAC-only identify would wrongly return offline without this fallback.
        if pend is None:
            cur.execute(
                "SELECT mac_nocolon, last_seen_at, fw FROM pending_claims "
                "WHERE UPPER(IFNULL(proposed_device_id,'')) = ? ORDER BY last_seen_at DESC LIMIT 1",
                (serial,),
            )
            pend = cur.fetchone()
        conn.close()
    if not pend:
        return {
            "status": "offline",
            "serial": serial,
            "mac_hint": mac_for_lookup,
            "message": "设备未联网。请先通电、连上 WiFi/网线，看到状态灯稳定后再扫码激活。",
        }
    return {
        "status": "ready",
        "serial": serial,
        "mac_nocolon": str(pend["mac_nocolon"]),
        "fw": str(pend["fw"] or ""),
        "last_seen_at": str(pend["last_seen_at"]),
        "message": "设备在线且尚未登记，可点击确认注册",
    }


__all__ = (
    "router",
    "IdentifyRequest",
    "FACTORY_SERIAL_RE",
    "provision_identify",
)
