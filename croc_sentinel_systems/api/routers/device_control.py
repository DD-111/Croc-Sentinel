"""Device control routes (Phase-18 modularization extract from ``app.py``).

Five small operator-facing endpoints that fan out a single command to
exactly one device:

  POST /devices/{device_id}/alert/on
  POST /devices/{device_id}/alert/off
  POST /devices/{device_id}/self-test
  POST /devices/{device_id}/schedule-reboot
  GET  /devices/{device_id}/scheduled-jobs

Their bulk cousin (POST /alerts) and the unrelated /commands/broadcast
endpoint stay in app.py for now — they have a different surface area
and pull in many more helpers.

Schema
------
``ScheduleRebootRequest`` is exclusive to /schedule-reboot and moves
with it.

Late-binding strategy
---------------------
Every helper called by these routes (publish_command,
get_cmd_key_for_device, enqueue_scheduled_command,
assert_device_command_actor, _lookup_owner_admin,
_remote_siren_notify_email, _log_signal_trigger, _client_context,
ensure_not_revoked, emit_event) lives in app.py. We capture the ones
that are guaranteed to exist at module import (require_principal,
require_capability, assert_zone_for_device, assert_device_siren_access)
and call-time-wrap the rest.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import app as _app
from config import CMD_PROTO, DEFAULT_REMOTE_FANOUT_MS, TOPIC_ROOT
from db import db_lock, get_conn
from device_security import ensure_not_revoked
from security import Principal, assert_min_role, assert_zone_for_device

# Captured at import-time — guaranteed to exist before this router is ever
# included (defined < line ~3300 in app.py).
require_principal = _app.require_principal
require_capability = _app.require_capability
assert_device_siren_access = _app.assert_device_siren_access
assert_device_command_actor = _app.assert_device_command_actor
_lookup_owner_admin = _app._lookup_owner_admin
_client_context_app = _app._client_context
_log_signal_trigger = _app._log_signal_trigger
_remote_siren_notify_email = _app._remote_siren_notify_email
emit_event = _app.emit_event


# Defined later in app.py than typical router-include sites — wrap so the
# lookup happens at call-time, not module load.
def _publish_command(*args: Any, **kwargs: Any) -> Any:
    return _app.publish_command(*args, **kwargs)


def _get_cmd_key_for_device(device_id: str) -> Any:
    return _app.get_cmd_key_for_device(device_id)


def _enqueue_scheduled_command(*args: Any, **kwargs: Any) -> Any:
    return _app.enqueue_scheduled_command(*args, **kwargs)


def _client_context(request: Optional[Request]) -> dict[str, Any]:
    if request is None:
        return {}
    return _client_context_app(request)


logger = logging.getLogger("croc-api.routers.device_control")

router = APIRouter(tags=["device-control"])


class ScheduleRebootRequest(BaseModel):
    delay_s: Optional[int] = Field(default=None, ge=5, le=604800)
    at_ts: Optional[int] = Field(default=None, ge=0)


@router.post("/devices/{device_id}/alert/on")
def device_alert_on(
    device_id: str,
    duration_ms: int = Query(default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000),
    request: Request = None,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    ensure_not_revoked(device_id)
    assert_device_siren_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    _publish_command(
        topic=topic,
        cmd="siren_on",
        params={"duration_ms": duration_ms},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=_get_cmd_key_for_device(device_id),
    )
    z = str(zr["zone"] if zr["zone"] is not None else "")
    owner = _lookup_owner_admin(device_id)
    ctx = _client_context(request) if request else {}
    _log_signal_trigger(
        "remote_siren_on",
        device_id,
        z,
        principal.username,
        owner,
        duration_ms=duration_ms,
        target_count=1,
        detail=ctx,
    )
    _remote_siren_notify_email(
        action="ON",
        device_id=device_id,
        zone=z,
        actor=principal.username,
        owner_admin=owner,
        duration_ms=duration_ms,
    )
    emit_event(
        level="warn",
        category="alarm",
        event_type="remote.siren_on",
        summary=f"Remote siren ON {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=owner or "",
        device_id=device_id,
        detail={"duration_ms": duration_ms, "zone": z, **ctx},
    )
    return {"ok": True}


@router.post("/devices/{device_id}/alert/off")
def device_alert_off(device_id: str, request: Request, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    ensure_not_revoked(device_id)
    assert_device_siren_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    _publish_command(
        topic=topic,
        cmd="siren_off",
        params={},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=_get_cmd_key_for_device(device_id),
    )
    z = str(zr["zone"] if zr["zone"] is not None else "")
    owner = _lookup_owner_admin(device_id)
    _log_signal_trigger(
        "remote_siren_off",
        device_id,
        z,
        principal.username,
        owner,
        duration_ms=None,
        target_count=1,
        detail=_client_context(request),
    )
    _remote_siren_notify_email(
        action="OFF",
        device_id=device_id,
        zone=z,
        actor=principal.username,
        owner_admin=owner,
        duration_ms=None,
    )
    emit_event(
        level="info",
        category="alarm",
        event_type="remote.siren_off",
        summary=f"Remote siren OFF {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=owner or "",
        device_id=device_id,
        detail={"zone": z, **_client_context(request)},
    )
    return {"ok": True}


@router.post("/devices/{device_id}/self-test")
def device_self_test(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
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
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    _publish_command(
        topic=topic,
        cmd="self_test",
        params={},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=_get_cmd_key_for_device(device_id),
    )
    return {"ok": True}


@router.post("/devices/{device_id}/schedule-reboot")
def device_schedule_reboot(device_id: str, req: ScheduleRebootRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
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
    now_ts = int(time.time())
    execute_at = 0
    if req.delay_s is not None:
        execute_at = now_ts + req.delay_s
    elif req.at_ts is not None and req.at_ts > now_ts + 5:
        execute_at = req.at_ts
    else:
        raise HTTPException(status_code=400, detail="provide valid delay_s or at_ts")

    job_id = _enqueue_scheduled_command(
        device_id=device_id,
        cmd="reboot",
        params={},
        target_id=device_id,
        proto=CMD_PROTO,
        execute_at_ts=execute_at,
    )
    return {"ok": True, "job_id": job_id, "execute_at_ts": execute_at}


@router.get("/devices/{device_id}/scheduled-jobs")
def device_scheduled_jobs(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        if not zr:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
        conn.close()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, cmd, params_json, target_id, proto, execute_at_ts, status, created_at, executed_at
            FROM scheduled_commands
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT 200
            """,
            (device_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for row in rows:
        row["params"] = json.loads(row.pop("params_json"))
    return {"items": rows}
