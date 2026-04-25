"""Provision-lifecycle router (Phase-29 modularization).

The three operator-facing claim-flow endpoints. The dashboard's
"Activate device" wizard walks operators through identify → pending →
claim, in that order, so it makes sense to keep all three in a single
module:

  POST /provision/identify   (decide what state the serial is in)
  GET  /provision/pending    (list devices that have phoned home but
                              haven't been bound to a tenant yet)
  POST /provision/claim      (bind a pending device to a tenant)

Schemas moved with the routes
-----------------------------
  ClaimDeviceRequest, IdentifyRequest

Constants moved with the routes
-------------------------------
  FACTORY_SERIAL_RE  (used only by /provision/identify)

Late-binding strategy
---------------------
All helpers used here are defined < line ~5300 in app.py, so they're
all early-bound (identity preserved at module-import time):

  require_principal, require_capability, get_manager_admin,
  generate_device_credentials, publish_bootstrap_claim
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    BOOTSTRAP_BIND_KEY,
    CLAIM_RESPONSE_INCLUDE_SECRETS,
    DEVICE_ID_REGEX,
    ENFORCE_DEVICE_CHALLENGE,
    QR_CODE_REGEX,
    QR_SIGN_SECRET,
)
from db import cache_invalidate, db_lock, get_conn
from device_security import ensure_not_revoked, verify_qr_signature
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
get_manager_admin = _app.get_manager_admin
generate_device_credentials = _app.generate_device_credentials
publish_bootstrap_claim = _app.publish_bootstrap_claim


logger = logging.getLogger("croc-api.routers.provision_lifecycle")

router = APIRouter(tags=["provision-lifecycle"])


# Serial format: SN-<16 uppercase base32 chars>. 80 bits of CSPRNG entropy.
# The factory side generates these, never the device. Device only uses
# (serial, mac_nocolon) tuples that were uploaded to /factory/devices.
FACTORY_SERIAL_RE = re.compile(r"^SN-[A-Z2-7]{16}$")


# ---- Schemas ---------------------------------------------------------------

class ClaimDeviceRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=3, max_length=23)
    zone: str = Field(default="all", min_length=1, max_length=31)
    qr_code: Optional[str] = Field(default=None, max_length=47)


class IdentifyRequest(BaseModel):
    serial: Optional[str] = Field(default=None, max_length=64)
    qr_code: Optional[str] = Field(default=None, max_length=512)


# ---- Routes ----------------------------------------------------------------

@router.get("/provision/pending")
def list_pending_claims(
    principal: Principal = Depends(require_principal),
    q: Optional[str] = Query(default=None, max_length=64, description="Filter by MAC (no colon) or QR substring"),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role != "superadmin":
        raise HTTPException(status_code=403, detail="pending claim list is superadmin-only")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if q and q.strip():
            like = f"%{q.strip()}%"
            like_mac = f"%{q.strip().upper().replace(':', '').replace('-', '')}%"
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                WHERE (mac_nocolon LIKE ? OR UPPER(mac) LIKE ? OR IFNULL(qr_code,'') LIKE ?)
                  AND NOT EXISTS (
                    SELECT 1 FROM provisioned_credentials pc
                    WHERE pc.device_id = pending_claims.proposed_device_id
                  )
                ORDER BY last_seen_at DESC
                """,
                (like_mac, like, like),
            )
        else:
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                WHERE NOT EXISTS (
                  SELECT 1 FROM provisioned_credentials pc
                  WHERE pc.device_id = pending_claims.proposed_device_id
                )
                ORDER BY last_seen_at DESC
                """
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.post("/provision/claim")
def claim_device(req: ClaimDeviceRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    mac_nocolon = req.mac_nocolon.upper()
    if len(mac_nocolon) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    if not re.fullmatch(DEVICE_ID_REGEX, req.device_id.strip().upper()):
        raise HTTPException(status_code=400, detail="device_id format rejected by policy")
    if not BOOTSTRAP_BIND_KEY:
        raise HTTPException(status_code=500, detail="server BOOTSTRAP_BIND_KEY not configured")
    did_norm = req.device_id.strip().upper()
    ensure_not_revoked(did_norm)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM pending_claims WHERE mac_nocolon = ?", (mac_nocolon,))
        pending = cur.fetchone()
        if not pending:
            conn.close()
            raise HTTPException(status_code=404, detail="pending device not found")
        cur.execute(
            "SELECT mac_nocolon FROM provisioned_credentials WHERE UPPER(device_id) = UPPER(?) LIMIT 1",
            (did_norm,),
        )
        exist_id = cur.fetchone()
        if exist_id:
            conn.close()
            raise HTTPException(status_code=409, detail="device_id already registered")
        cur.execute(
            "SELECT device_id FROM provisioned_credentials WHERE mac_nocolon = ?",
            (mac_nocolon,),
        )
        existing = cur.fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=409, detail="device already claimed")

        claim_nonce = str(pending["claim_nonce"])
        qr_code = req.qr_code if req.qr_code else (str(pending["qr_code"] or "") or f"CROC-{mac_nocolon}")
        if req.qr_code:
            if not re.fullmatch(QR_CODE_REGEX, req.qr_code):
                conn.close()
                raise HTTPException(status_code=400, detail="qr_code format rejected by policy")
            if QR_SIGN_SECRET and not verify_qr_signature(req.qr_code):
                conn.close()
                raise HTTPException(status_code=401, detail="qr_code signature invalid")
        if ENFORCE_DEVICE_CHALLENGE:
            cur.execute(
                """
                SELECT id, verified_at, used
                FROM provision_challenges
                WHERE mac_nocolon = ? AND device_id = ? AND expires_at_ts >= ?
                ORDER BY id DESC LIMIT 1
                """,
                (mac_nocolon, did_norm, int(time.time())),
            )
            ch = cur.fetchone()
            if not ch or not ch["verified_at"] or int(ch["used"]) == 1:
                conn.close()
                raise HTTPException(status_code=412, detail="verified device challenge required before claim")
        mqtt_username, mqtt_password, cmd_key = generate_device_credentials(did_norm)

        cur.execute(
            """
            INSERT INTO provisioned_credentials (
                device_id, mac_nocolon, mqtt_username, mqtt_password, cmd_key, zone, qr_code, claimed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                mac_nocolon = excluded.mac_nocolon,
                mqtt_username = excluded.mqtt_username,
                mqtt_password = excluded.mqtt_password,
                cmd_key = excluded.cmd_key,
                zone = excluded.zone,
                qr_code = excluded.qr_code,
                claimed_at = excluded.claimed_at
            """,
            (
                did_norm,
                mac_nocolon,
                mqtt_username,
                mqtt_password,
                cmd_key,
                req.zone,
                qr_code,
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()
    owner_admin = principal.username
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_ownership (device_id, owner_admin, assigned_by, assigned_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
              owner_admin = excluded.owner_admin,
              assigned_by = excluded.assigned_by,
              assigned_at = excluded.assigned_at
            """,
            (did_norm, owner_admin, principal.username, utc_now_iso()),
        )
        # Stale device_state from a previous tenant/owner: clear profile fields on (re)claim
        cur.execute(
            "UPDATE device_state SET display_label = '', notification_group = '' WHERE device_id = ?",
            (did_norm,),
        )
        conn.commit()
        conn.close()
        cache_invalidate("devices")
        cache_invalidate("overview")
    if ENFORCE_DEVICE_CHALLENGE:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE provision_challenges SET used = 1
                WHERE mac_nocolon = ? AND device_id = ? AND verified_at IS NOT NULL AND used = 0
                """,
                (mac_nocolon, did_norm),
            )
            conn.commit()
            conn.close()

    publish_bootstrap_claim(
        mac_nocolon=mac_nocolon,
        claim_nonce=claim_nonce,
        device_id=did_norm,
        zone=req.zone,
        qr_code=qr_code,
        mqtt_username=mqtt_username,
        mqtt_password=mqtt_password,
        cmd_key=cmd_key,
    )

    resp = {
        "ok": True,
        "device_id": did_norm,
        "mac_nocolon": mac_nocolon,
        "mqtt_username": mqtt_username if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "mqtt_password": mqtt_password if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "cmd_key": cmd_key if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
    }
    audit_event(
        principal.username,
        "provision.claim",
        did_norm,
        {
            "mac_nocolon": mac_nocolon,
            "zone": req.zone,
            "owner_admin": owner_admin,
            "device_id": did_norm,
            "role": principal.role,
        },
    )
    return resp


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


__all__ = [
    "router",
    "ClaimDeviceRequest",
    "IdentifyRequest",
    "FACTORY_SERIAL_RE",
    "list_pending_claims",
    "claim_device",
    "provision_identify",
]
