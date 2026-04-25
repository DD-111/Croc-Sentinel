"""Provisioning challenge router (Phase-24 modularization).

Two-step admin flow that mints a one-time nonce, has the device sign
it locally with its private key, then verifies the signature against
the public key the device sent in /provision/challenge/request. Used
by tooling to assert "I am holding this MAC + private key" before
binding the device to a tenant.

Routes
------
  POST /provision/challenge/request   (mint nonce → return challenge_id)
  POST /provision/challenge/verify    (validate signature → mark verified)

Schemas moved with the routes
-----------------------------
  DeviceChallengeRequest, DeviceChallengeVerifyRequest

Late-binding strategy
---------------------
Every helper used here is defined < line ~3000 in app.py, so they're
all early-bound (identity-preserved):

  require_principal, require_capability
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import DEVICE_CHALLENGE_TTL_SECONDS, DEVICE_ID_REGEX
from db import db_lock, get_conn
from device_security import verify_device_signature
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability


logger = logging.getLogger("croc-api.routers.provision_challenge")

router = APIRouter(tags=["provision-challenge"])


# ---- Schemas ---------------------------------------------------------------

class DeviceChallengeRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=8, max_length=40)
    public_key_pem: str = Field(min_length=64, max_length=4096)
    attestation: Optional[dict[str, Any]] = None


class DeviceChallengeVerifyRequest(BaseModel):
    challenge_id: int = Field(ge=1)
    signature_b64: str = Field(min_length=32, max_length=1024)


# ---- Routes ----------------------------------------------------------------

@router.post("/provision/challenge/request")
def provision_challenge_request(
    req: DeviceChallengeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    device_id = req.device_id.strip().upper()
    mac_nocolon = req.mac_nocolon.strip().upper()
    if not re.fullmatch(DEVICE_ID_REGEX, device_id):
        raise HTTPException(status_code=400, detail="device_id format rejected by policy")
    nonce = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + DEVICE_CHALLENGE_TTL_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_identities (device_id, mac_nocolon, public_key_pem, attestation_json, registered_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                mac_nocolon = excluded.mac_nocolon,
                public_key_pem = excluded.public_key_pem,
                attestation_json = excluded.attestation_json,
                registered_at = excluded.registered_at
            """,
            (
                device_id,
                mac_nocolon,
                req.public_key_pem,
                json.dumps(req.attestation or {}, ensure_ascii=True),
                utc_now_iso(),
            ),
        )
        cur.execute(
            """
            INSERT INTO provision_challenges (mac_nocolon, device_id, nonce, expires_at_ts, verified_at, used)
            VALUES (?, ?, ?, ?, NULL, 0)
            """,
            (mac_nocolon, device_id, nonce, expires_at),
        )
        challenge_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    audit_event(principal.username, "challenge.request", device_id, {"challenge_id": challenge_id})
    return {"challenge_id": challenge_id, "nonce": nonce, "expires_at_ts": expires_at}


@router.post("/provision/challenge/verify")
def provision_challenge_verify(
    req: DeviceChallengeVerifyRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.id, c.device_id, c.nonce, c.expires_at_ts, c.used, i.public_key_pem
            FROM provision_challenges c
            JOIN device_identities i ON c.device_id = i.device_id
            WHERE c.id = ?
            """,
            (req.challenge_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="challenge not found")
        if int(row["used"]) == 1:
            conn.close()
            raise HTTPException(status_code=409, detail="challenge already used")
        if int(time.time()) > int(row["expires_at_ts"]):
            conn.close()
            raise HTTPException(status_code=410, detail="challenge expired")
        ok = verify_device_signature(str(row["public_key_pem"]), str(row["nonce"]), req.signature_b64)
        if not ok:
            conn.close()
            raise HTTPException(status_code=401, detail="device signature verification failed")
        cur.execute(
            "UPDATE provision_challenges SET verified_at = ? WHERE id = ?",
            (utc_now_iso(), req.challenge_id),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "challenge.verify", str(row["device_id"]), {"challenge_id": req.challenge_id})
    return {"ok": True, "device_id": row["device_id"], "challenge_id": req.challenge_id}
