"""Provision-lifecycle router (Phase-29 modularization, trimmed in Phase-70).

The Phase-29 module bundled three operator-facing claim-flow
endpoints together. Phase 70 splits the read-only inspection step
(``POST /provision/identify``) into ``routers/provision_identify.py``
so this module now hosts only the *write-side* claim flow:

  GET  /provision/pending    (list devices that have phoned home but
                              haven't been bound to a tenant yet)
  POST /provision/claim      (bind a pending device to a tenant)

Schemas owned here
------------------
  ClaimDeviceRequest

Late-binding strategy
---------------------
All helpers used here are defined < line ~5300 in app.py, so they're
all early-bound (identity preserved at module-import time):

  require_principal, require_capability, generate_device_credentials,
  publish_bootstrap_claim
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
generate_device_credentials = _app.generate_device_credentials
publish_bootstrap_claim = _app.publish_bootstrap_claim


logger = logging.getLogger("croc-api.routers.provision_lifecycle")

router = APIRouter(tags=["provision-lifecycle"])


# ---- Schemas ---------------------------------------------------------------

class ClaimDeviceRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=3, max_length=23)
    zone: str = Field(default="all", min_length=1, max_length=31)
    qr_code: Optional[str] = Field(default=None, max_length=47)


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
            INSERT INTO device_ownership (device_id, owner_admin, assigned_by, assigned_at, cmd_key_shadow)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
              owner_admin = excluded.owner_admin,
              assigned_by = excluded.assigned_by,
              assigned_at = excluded.assigned_at,
              cmd_key_shadow = excluded.cmd_key_shadow
            """,
            (did_norm, owner_admin, principal.username, utc_now_iso(), cmd_key),
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


__all__ = (
    "router",
    "ClaimDeviceRequest",
    "list_pending_claims",
    "claim_device",
)
