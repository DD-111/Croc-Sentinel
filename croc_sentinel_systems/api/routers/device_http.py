"""Device-side HTTP fallback endpoints (Phase-15 modularization extract from ``app.py``).

These four endpoints are called by the ESP32 firmware (NOT the
dashboard) when MQTT is unreachable or for one-shot post-boot recovery.
They authenticate purely via ``device_id + mac_nocolon + cmd_key`` —
JWT/CSRF/cookies don't apply, so this is the one router that does NOT
go through ``require_principal``.

  POST /device/boot-sync           — verify NVS cmd_key vs DB; return resync payload on mismatch
  POST /device/ota/report          — OTA outcome (HTTP twin of MQTT ``ota.result`` for post-OTA recovery)
  POST /device/commands/pending    — backup command-channel pull (oldest-first; idempotent per cmd_id)
  POST /device/commands/ack        — backup command-channel ACK (drains queue when MQTT never recovers)

Helpers (moved with the routes; only used here)
-----------------------------------------------
  _norm_mac_nocolon12, _provision_row_for_device_mac, _auth_device_http,
  DeviceBootSyncRequest, DeviceOtaReportRequest,
  DeviceCommandsPendingRequest, DeviceCommandAckRequest

Helpers that stay in ``app.py`` and are late-bound here
-------------------------------------------------------
  _lookup_owner_admin, emit_event, _handle_ota_result_safe,
  _cmd_queue_pending_for_device, _cmd_queue_mark_acked

The last two are defined *below* the include-router line in app.py
(they live next to the rest of the command queue plumbing), so we use
call-time wrappers instead of module-load attribute capture.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import CMD_PROTO
from db import db_lock, get_conn

# `is_hex_16` lives in app.py at top-level (line 191) — import-time bind is safe.
is_hex_16 = _app.is_hex_16
_lookup_owner_admin = _app._lookup_owner_admin
emit_event = _app.emit_event
_handle_ota_result_safe = _app._handle_ota_result_safe


# `_cmd_queue_pending_for_device` and `_cmd_queue_mark_acked` are defined
# *after* this router's `include_router(...)` line in app.py (they live
# in the device-command-queue helpers section). Use call-time wrappers.
def _cmd_queue_pending_for_device(device_id: str, limit: int = 32) -> list[dict[str, Any]]:
    return _app._cmd_queue_pending_for_device(device_id, limit=limit)


def _cmd_queue_mark_acked(cmd_id: str, *, ok: bool, detail: str = "") -> bool:
    return _app._cmd_queue_mark_acked(cmd_id, ok=ok, detail=detail)


logger = logging.getLogger("croc-api.routers.device_http")

router = APIRouter(tags=["device-http"])


# ─────────────────────────────────────── request schemas ────

class DeviceBootSyncRequest(BaseModel):
    device_id: str = Field(min_length=3, max_length=40)
    mac_nocolon: str = Field(min_length=12, max_length=24)
    cmd_key: str = Field(default="", max_length=32)
    fw: str = Field(default="", max_length=48)


class DeviceOtaReportRequest(BaseModel):
    device_id: str = Field(min_length=3, max_length=40)
    mac_nocolon: str = Field(min_length=12, max_length=24)
    cmd_key: str = Field(default="", max_length=32)
    ok: bool
    detail: str = Field(default="", max_length=480)
    campaign_id: str = Field(default="", max_length=120)
    target_fw: str = Field(default="", max_length=48)
    current_fw: str = Field(default="", max_length=48)


class DeviceCommandsPendingRequest(BaseModel):
    """Backup command-channel pull. The firmware only calls this when MQTT
    has been offline longer than its fallback arm window (≥120s) so we
    don't compete with the live MQTT path."""

    device_id: str = Field(min_length=3, max_length=40)
    mac_nocolon: str = Field(min_length=12, max_length=24)
    cmd_key: str = Field(min_length=16, max_length=32)
    limit: int = Field(default=8, ge=1, le=32)


class DeviceCommandAckRequest(BaseModel):
    """HTTP ACK for commands pulled from the backup channel."""

    device_id: str = Field(min_length=3, max_length=40)
    mac_nocolon: str = Field(min_length=12, max_length=24)
    cmd_key: str = Field(min_length=16, max_length=32)
    cmd_id: str = Field(min_length=8, max_length=64)
    ok: bool = True
    detail: str = Field(default="", max_length=240)


# ─────────────────────────────────────── helpers ────

def _norm_mac_nocolon12(raw: str) -> str:
    s = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    return s[:12].upper() if len(s) >= 12 else ""


def _provision_row_for_device_mac(device_id: str, mac12: str) -> Optional[sqlite3.Row]:
    """Return provisioned_credentials row when device_id and MAC both match (anti impersonation)."""
    if len(mac12) != 12:
        return None
    did = (device_id or "").strip()
    if not did:
        return None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_id, mac_nocolon, mqtt_username, mqtt_password, cmd_key, zone, qr_code
            FROM provisioned_credentials
            WHERE UPPER(device_id) = UPPER(?) AND UPPER(mac_nocolon) = UPPER(?)
            LIMIT 1
            """,
            (did, mac12),
        )
        row = cur.fetchone()
        conn.close()
    return row


def _auth_device_http(device_id: str, mac_nocolon: str, cmd_key: str) -> sqlite3.Row:
    """Shared device-HTTP authenticator. Matches MAC+device_id to a
    provisioned row and verifies the 16-hex cmd_key (same credential the
    firmware uses to sign MQTT /cmd payloads). Any mismatch is a 403 —
    we deliberately do not leak whether the device or the key was wrong."""
    mac = _norm_mac_nocolon12(mac_nocolon)
    if len(mac) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    row = _provision_row_for_device_mac(device_id, mac)
    if not row:
        raise HTTPException(status_code=404, detail="device not provisioned")
    db_key = str(row["cmd_key"] or "").strip().upper()
    rep = (cmd_key or "").strip().upper()
    if not rep or not is_hex_16(rep) or rep != db_key:
        raise HTTPException(status_code=403, detail="cmd_key mismatch")
    return row


def _reconcile_ownership_cmd_key_shadow(device_id: str, db_key: str) -> None:
    """Cross-table consistency check for cmd_key shadow.

    Source of truth for runtime auth remains ``provisioned_credentials.cmd_key``.
    ``device_ownership.cmd_key_shadow`` is a redundancy/consistency copy used
    for drift detection and recovery workflows.
    """
    did = str(device_id or "").strip()
    key = str(db_key or "").strip().upper()
    if not did or not is_hex_16(key):
        return
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(cmd_key_shadow,'') AS cmd_key_shadow "
            "FROM device_ownership WHERE device_id = ? LIMIT 1",
            (did,),
        )
        ow = cur.fetchone()
        if not ow:
            conn.close()
            return
        sh = str(ow["cmd_key_shadow"] or "").strip().upper()
        if sh == key:
            conn.close()
            return
        cur.execute(
            "UPDATE device_ownership SET cmd_key_shadow = ? WHERE device_id = ?",
            (key, did),
        )
        conn.commit()
        conn.close()
    logger.warning(
        "device_ownership cmd_key_shadow reconciled for %s (had=%s now=%s)",
        did,
        bool(sh),
        key[:4] + "..." + key[-4:],
    )


# ─────────────────────────────────────── routes ────

@router.post("/device/boot-sync")
def device_boot_sync(body: DeviceBootSyncRequest) -> dict[str, Any]:
    """Device HTTP: verify NVS cmd_key vs DB; return resync payload when mismatched (MAC+device_id bound)."""
    mac = _norm_mac_nocolon12(body.mac_nocolon)
    if len(mac) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    row = _provision_row_for_device_mac(body.device_id, mac)
    if not row:
        return {"status": "unprovisioned"}
    did = str(row["device_id"])
    db_key = str(row["cmd_key"] or "").strip().upper()
    # Keep ownership-side shadow in sync every time a known device checks in.
    _reconcile_ownership_cmd_key_shadow(did, db_key)
    rep = (body.cmd_key or "").strip().upper()
    if rep and is_hex_16(rep) and rep == db_key:
        return {"status": "ok"}
    owner = _lookup_owner_admin(did) or ""
    emit_event(
        level="warn",
        category="provision",
        event_type="device.boot_sync.resync",
        summary=f"boot-sync resync {did}",
        actor=f"device:{did}",
        target=did,
        owner_admin=owner or None,
        device_id=did,
        detail={"fw": (body.fw or "").strip(), "had_cmd_key": bool(rep)},
    )
    audit_event(
        f"device:{did}",
        "device.boot_sync.resync",
        did,
        {"mac_nocolon": mac, "fw": (body.fw or "").strip()},
    )
    return {
        "status": "resync",
        "cmd_key": db_key,
        "mqtt_username": str(row["mqtt_username"] or ""),
        "mqtt_password": str(row["mqtt_password"] or ""),
        "zone": str(row["zone"] or "all").strip() or "all",
        "qr_code": str(row["qr_code"] or ""),
    }


@router.post("/device/ota/report")
def device_ota_report(body: DeviceOtaReportRequest) -> dict[str, Any]:
    """Device HTTP: OTA outcome (duplicate path alongside MQTT ota.result for post-OTA recovery)."""
    mac = _norm_mac_nocolon12(body.mac_nocolon)
    if len(mac) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    row = _provision_row_for_device_mac(body.device_id, mac)
    if not row:
        raise HTTPException(status_code=404, detail="device not provisioned")
    did = str(row["device_id"])
    db_key = str(row["cmd_key"] or "").strip().upper()
    rep = (body.cmd_key or "").strip().upper()
    if rep and (not is_hex_16(rep) or rep != db_key):
        raise HTTPException(status_code=403, detail="cmd_key does not match server")
    owner = _lookup_owner_admin(did) or ""
    payload: dict[str, Any] = {
        "type": "ota.result",
        "ok": bool(body.ok),
        "detail": (body.detail or "")[:240],
        "campaign_id": (body.campaign_id or "").strip(),
        "target_fw": (body.target_fw or "").strip(),
        "current_fw": (body.current_fw or "").strip(),
    }
    cid = str(payload.get("campaign_id") or "")
    if cid and not cid.endswith("#rollback"):
        _handle_ota_result_safe(did, payload)
    else:
        emit_event(
            level="info" if body.ok else "warn",
            category="ota",
            event_type="ota.device.http_report",
            summary=f"{did} ota http report ok={body.ok}",
            actor=f"device:{did}",
            target=owner or None,
            owner_admin=owner or None,
            device_id=did,
            detail=payload,
        )
    return {"ok": True, "status": "recorded"}


@router.post("/device/commands/pending")
def device_commands_pending(body: DeviceCommandsPendingRequest) -> dict[str, Any]:
    """HTTP backup command pull. Returns unacked commands queued for the
    device. This is deliberately a POST (not GET) so cmd_key auth rides
    in the body, not in a querystring that could show up in access logs.

    Contract (so firmware and server stay in lockstep):
      * Server returns ``{"commands": [...]}`` — oldest first.
      * Each entry mirrors the MQTT ``/cmd`` JSON shape (``cmd``,
        ``cmd_id``, ``target_id``, ``proto``, ``params``, ``key``).
        The signing ``key`` is always the **live**
        ``get_cmd_key_for_device(device_id)`` at pull time — if the
        device's credentials rotated after the command was originally
        published, the ledger row may still carry an older snapshot, but
        the HTTP response must never resurrect a stale key or the device
        will reject the frame even though its NVS is already current.
      * The firmware handler must be idempotent per ``cmd_id`` because the
        same entry can be served again on the next pull until ACK'd.
      * The server does NOT mark anything delivered on pull. Delivery is
        confirmed only when the device POSTs /device/commands/ack — MQTT
        remains the source of truth for delivery semantics.
    """
    row = _auth_device_http(body.device_id, body.mac_nocolon, body.cmd_key)
    did = str(row["device_id"])
    rows = _cmd_queue_pending_for_device(did, limit=int(body.limit))
    # Shape mirrors the MQTT /cmd payload exactly so the firmware can
    # pass each entry straight to handleCmdFromBody() without any
    # transformation layer. ``key`` is the 16-hex cmd_key the device
    # would have seen on MQTT, enabling the same auth check offline.
    commands = []
    for r in rows:
        commands.append({
            "proto": int(r["proto"] or CMD_PROTO),
            "key": r["cmd_key"] or "",
            "cred_version": int(r.get("cred_version") or 1),
            "target_id": r["target_id"] or did,
            "cmd": r["cmd"],
            "params": r["params"] or {},
            "cmd_id": r["cmd_id"],
            "enqueued_at": r["created_at"],
        })
    return {"commands": commands, "count": len(commands)}


@router.post("/device/commands/ack")
def device_commands_ack(body: DeviceCommandAckRequest) -> dict[str, Any]:
    """HTTP ACK for backup-channel commands. The device should still
    publish its normal MQTT /ack when MQTT comes back; this endpoint
    exists so an unack'd queue entry can be drained purely over HTTP
    when the MQTT link never recovers."""
    row = _auth_device_http(body.device_id, body.mac_nocolon, body.cmd_key)
    did = str(row["device_id"])
    updated = _cmd_queue_mark_acked(body.cmd_id, ok=bool(body.ok), detail=body.detail or "")
    return {"ok": True, "settled": bool(updated), "device_id": did}


# ─────────────────────────────────── /api/* alias router ────
#
# Some shipped firmware builds (config.h DEVICE_SYNC_BOOT_PATH default,
# pre-Phase-69) hard-code the four device endpoints under an ``/api``
# prefix because a Traefik / nginx reverse-proxy was assumed to strip
# it before forwarding. Operators that point ``DEVICE_SYNC_API_BASE``
# straight at the API container (no ``/api → /`` rewrite at the proxy)
# would otherwise see ``HTTP 404`` on every boot-sync, which silently
# blocks the cmd_key self-heal path → MQTT cmd auth then fails with
# ``key mismatch`` until the device is re-claimed.
#
# Mounting the same handlers a second time under ``/api`` is the
# zero-flash, zero-downtime fix: both ``POST /device/boot-sync`` and
# ``POST /api/device/boot-sync`` resolve to the same function, so old
# and new firmware both work, and the cmd_key resync payload reaches
# every device on the next boot. The new prefix-less paths remain the
# canonical surface — keep new firmware aligned with config.h.example.
alias_router = APIRouter(prefix="/api", tags=["device-http-api-alias"])
alias_router.add_api_route("/device/boot-sync", device_boot_sync, methods=["POST"], name="device_boot_sync_api_alias")
alias_router.add_api_route("/device/ota/report", device_ota_report, methods=["POST"], name="device_ota_report_api_alias")
alias_router.add_api_route("/device/commands/pending", device_commands_pending, methods=["POST"], name="device_commands_pending_api_alias")
alias_router.add_api_route("/device/commands/ack", device_commands_ack, methods=["POST"], name="device_commands_ack_api_alias")
