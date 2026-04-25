"""Device-commands router (Phase-30 modularization).

Three "actually publish over MQTT now" endpoints, all of which sit at
the top of the operator's command hierarchy:

  POST /devices/{device_id}/commands   (per-device generic command)
  POST /alerts                         (bulk siren on/off across N devices)
  POST /commands/broadcast             (tenant-scoped or global broadcast)

Schemas moved with the routes
-----------------------------
  CommandRequest, BulkAlertRequest, BroadcastCommandRequest

Late-binding strategy
---------------------
Every helper used here is defined < line ~5300 in app.py, so they're
all early-bound (identity preserved at module-import time):

  require_principal, require_capability, assert_device_command_actor,
  zone_sql_suffix, owner_scope_clause_for_device_state,
  publish_command, get_cmd_key_for_device, _client_context,
  _lookup_owner_admin, emit_event, resolve_target_devices,
  _log_signal_trigger, _recipients_for_admin

``notifier`` is imported from the dedicated ``notifier`` module (same
singleton instance the rest of app.py uses).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from notifier import notifier
import app as _app
from audit import audit_event
from config import CMD_PROTO, DEFAULT_REMOTE_FANOUT_MS, MAX_BULK_TARGETS, TOPIC_ROOT
from db import db_lock, get_conn
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
require_capability = _app.require_capability
assert_device_command_actor = _app.assert_device_command_actor
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state
publish_command = _app.publish_command
get_cmd_key_for_device = _app.get_cmd_key_for_device
_client_context = _app._client_context
_lookup_owner_admin = _app._lookup_owner_admin
emit_event = _app.emit_event
resolve_target_devices = _app.resolve_target_devices
_log_signal_trigger = _app._log_signal_trigger
_recipients_for_admin = _app._recipients_for_admin


logger = logging.getLogger("croc-api.routers.device_commands")

router = APIRouter(tags=["device-commands"])


# ---- Schemas ---------------------------------------------------------------

class CommandRequest(BaseModel):
    cmd: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    target_id: Optional[str] = None
    proto: int = Field(default=CMD_PROTO, ge=1, le=16)


class BroadcastCommandRequest(BaseModel):
    cmd: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    target_id: str = Field(default="all")
    proto: int = Field(default=CMD_PROTO, ge=1, le=16)


class BulkAlertRequest(BaseModel):
    action: str = Field(pattern="^(on|off)$")
    duration_ms: int = Field(default=int(DEFAULT_REMOTE_FANOUT_MS), ge=500, le=300000)
    device_ids: list[str] = Field(default_factory=list)


# ---- Routes ----------------------------------------------------------------

@router.post("/devices/{device_id}/commands")
def send_device_command(
    device_id: str,
    req: CommandRequest,
    request: Request,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    target = req.target_id or device_id
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    publish_command(topic, req.cmd, req.params, target, req.proto, get_cmd_key_for_device(device_id))
    ctx = _client_context(request)
    emit_event(
        level="info",
        category="device",
        event_type="device.command.send",
        summary=f"command {req.cmd} to {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=_lookup_owner_admin(device_id) or "",
        device_id=device_id,
        detail={
            "cmd": req.cmd,
            "target_id": target,
            "trigger_kind": ctx.get("client_kind", "web"),
            "ip": ctx.get("ip", ""),
            "platform": ctx.get("platform", ""),
            "device_type": ctx.get("device_type", ""),
            "mac_hint": ctx.get("mac_hint", ""),
            "geo": ctx.get("geo", ""),
        },
    )
    return {"ok": True, "topic": topic, "target_id": target}


@router.post("/alerts")
def bulk_alert(req: BulkAlertRequest, request: Request, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    targets = resolve_target_devices(req.device_ids, principal)
    if not targets:
        return {"ok": True, "sent_count": 0, "device_ids": []}

    sent = 0
    for did in targets:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        if req.action == "on":
            publish_command(
                topic=topic,
                cmd="siren_on",
                params={"duration_ms": req.duration_ms},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
        else:
            publish_command(
                topic=topic,
                cmd="siren_off",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
        sent += 1

    if sent > 0:
        own = _lookup_owner_admin(targets[0])
        owner_admins: list[str] = []
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            ph = ",".join(["?"] * len(targets))
            cur.execute(
                f"SELECT DISTINCT IFNULL(owner_admin,'') AS owner_admin FROM device_ownership WHERE device_id IN ({ph})",
                tuple(targets),
            )
            owner_admins = [str(r["owner_admin"]) for r in cur.fetchall() if r["owner_admin"]]
            conn.close()
        ctx = _client_context(request)
        _log_signal_trigger(
            f"bulk_siren_{req.action}",
            "*",
            "",
            principal.username,
            own,
            duration_ms=req.duration_ms if req.action == "on" else None,
            target_count=sent,
            detail={"device_ids": targets, "owner_admins": owner_admins[:16], **ctx},
        )
        if notifier.enabled() and own:
            rec = _recipients_for_admin(own)
            if rec:
                subj = f"[Croc Sentinel] Bulk siren {req.action} ×{sent} by {principal.username}"
                body = "Targets:\n" + "\n".join(targets[:120])
                notifier.enqueue(rec, subj, body, None)
        emit_event(
            level="warn" if req.action == "on" else "info",
            category="alarm",
            event_type=f"bulk.siren_{req.action}",
            summary=f"Bulk siren {req.action} {sent} device(s) by {principal.username}",
            actor=principal.username,
            target=",".join(targets[:8]),
            owner_admin=own or "",
            detail={
                "count": sent,
                "device_ids": targets[:64],
                "owner_admins": owner_admins[:16],
                "trigger_kind": ctx.get("client_kind", "web"),
                "ip": ctx.get("ip", ""),
                "platform": ctx.get("platform", ""),
                "device_type": ctx.get("device_type", ""),
                "mac_hint": ctx.get("mac_hint", ""),
                "geo": ctx.get("geo", ""),
            },
        )

    return {
        "ok": True,
        "action": req.action,
        "sent_count": sent,
        "device_ids": targets,
    }


@router.post("/commands/broadcast")
def send_broadcast_command(req: BroadcastCommandRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id FROM device_state
            WHERE 1=1 {zs} {osf}
              AND device_id NOT IN (SELECT device_id FROM revoked_devices)
            """,
            tuple(za + osa),
        )
        device_ids = [r["device_id"] for r in cur.fetchall()]
        conn.close()

    if len(device_ids) > MAX_BULK_TARGETS:
        raise HTTPException(status_code=413, detail=f"target set too large (> {MAX_BULK_TARGETS})")

    for did in device_ids:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        publish_command(topic, req.cmd, req.params, req.target_id, req.proto, get_cmd_key_for_device(did))

    audit_event(principal.username, "command.broadcast", req.target_id, {
        "cmd": req.cmd,
        "sent_count": len(device_ids),
    })
    return {"ok": True, "target_id": req.target_id, "sent_count": len(device_ids)}


__all__ = [
    "router",
    "CommandRequest",
    "BroadcastCommandRequest",
    "BulkAlertRequest",
    "send_device_command",
    "bulk_alert",
    "send_broadcast_command",
]
