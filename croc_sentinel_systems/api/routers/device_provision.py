"""Device provisioning + trigger-policy routes (Phase-19 modularization).

Four self-contained per-device endpoints that share one common helper
(``_load_device_row_for_task``) and a small grab-bag of schemas:

  GET  /devices/{device_id}/trigger-policy
  PUT  /devices/{device_id}/trigger-policy
  POST /devices/{device_id}/provision/wifi-task
  GET  /devices/{device_id}/provision/wifi-task/{task_id}

Schemas / constants moved with the routes
-----------------------------------------
  TriggerPolicyBody, WifiDeferredCmd, ProvisionWifiTaskRequest,
  _WIFI_DEFERRED_CMDS

Late-binding strategy
---------------------
The cross-feature helpers live in app.py and are captured here:

  early-bound (defined < line ~3300 in app.py):
    require_principal, assert_device_owner, assert_device_command_actor,
    _principal_tenant_owns_device, _trigger_policy_for, emit_event

  call-time wrappers (defined > line ~6000 in app.py):
    publish_command, get_cmd_key_for_device
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    CMD_PROTO,
    DEFAULT_PANIC_FANOUT_MS,
    DEFAULT_REMOTE_FANOUT_MS,
    TOPIC_ROOT,
)
from db import db_lock, get_conn
from helpers import _sibling_group_norm, utc_now_iso
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
assert_device_owner = _app.assert_device_owner
assert_device_command_actor = _app.assert_device_command_actor
_principal_tenant_owns_device = _app._principal_tenant_owns_device
_trigger_policy_for = _app._trigger_policy_for
emit_event = _app.emit_event


def _publish_command(*args: Any, **kwargs: Any) -> Any:
    return _app.publish_command(*args, **kwargs)


def _get_cmd_key_for_device(device_id: str) -> Any:
    return _app.get_cmd_key_for_device(device_id)


logger = logging.getLogger("croc-api.routers.device_provision")

router = APIRouter(tags=["device-provision"])


# ---- Schemas / constants ---------------------------------------------------

_WIFI_DEFERRED_CMDS = frozenset({"get_info", "ping", "self_test", "set_param"})


class WifiDeferredCmd(BaseModel):
    """Executed on-device after Wi-Fi credentials are saved + reboot, once MQTT reconnects (order preserved)."""

    cmd: str = Field(min_length=1, max_length=32)
    params: dict[str, Any] = Field(default_factory=dict)


class ProvisionWifiTaskRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=32)
    password: str = Field(default="", max_length=64)
    chain: list[WifiDeferredCmd] = Field(default_factory=list, max_length=4)


class TriggerPolicyBody(BaseModel):
    panic_local_siren: bool = True
    panic_link_enabled: bool = True
    panic_fanout_duration_ms: int = Field(default=DEFAULT_PANIC_FANOUT_MS, ge=500, le=600000)
    remote_silent_link_enabled: bool = True
    remote_loud_link_enabled: bool = True
    remote_loud_duration_ms: int = Field(default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000)
    fanout_exclude_self: bool = True


# ---- Module-private helper -------------------------------------------------

def _load_device_row_for_task(device_id: str) -> tuple[dict[str, Any], Optional[str]]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT zone, IFNULL(notification_group,'') AS notification_group, "
            "IFNULL(last_ack_json,'') AS last_ack_json "
            "FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        ow = cur.fetchone()
        owner = str(ow["owner_admin"]) if ow and ow["owner_admin"] else None
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    return dict(row), owner


# ---- Routes ----------------------------------------------------------------

@router.get("/devices/{device_id}/trigger-policy")
def get_device_trigger_policy(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    if not _principal_tenant_owns_device(principal, owner):
        raise HTTPException(
            status_code=403,
            detail="trigger policy is managed by the owning tenant only (device share does not include group policy)",
        )
    group_display = str(row.get("notification_group") or "")
    pol = _trigger_policy_for(owner, group_display)
    return {"ok": True, "device_id": device_id, "scope_group": group_display, "policy": pol}


@router.put("/devices/{device_id}/trigger-policy")
def save_device_trigger_policy(
    device_id: str,
    body: TriggerPolicyBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id, check_revoked=False)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    if not _principal_tenant_owns_device(principal, owner):
        raise HTTPException(
            status_code=403,
            detail="trigger policy is managed by the owning tenant only (device share does not include group policy)",
        )
    group_display = str(row.get("notification_group") or "")
    group_key = _sibling_group_norm(group_display)
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO trigger_policies (
                owner_admin, scope_group, panic_local_siren, remote_silent_link_enabled,
                remote_loud_link_enabled, remote_loud_duration_ms, fanout_exclude_self,
                panic_link_enabled, panic_fanout_duration_ms, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_admin, scope_group) DO UPDATE SET
                panic_local_siren=excluded.panic_local_siren,
                remote_silent_link_enabled=excluded.remote_silent_link_enabled,
                remote_loud_link_enabled=excluded.remote_loud_link_enabled,
                remote_loud_duration_ms=excluded.remote_loud_duration_ms,
                fanout_exclude_self=excluded.fanout_exclude_self,
                panic_link_enabled=excluded.panic_link_enabled,
                panic_fanout_duration_ms=excluded.panic_fanout_duration_ms,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (
                owner or "",
                group_key,
                1 if body.panic_local_siren else 0,
                1 if body.remote_silent_link_enabled else 0,
                1 if body.remote_loud_link_enabled else 0,
                int(body.remote_loud_duration_ms),
                1 if body.fanout_exclude_self else 0,
                1 if body.panic_link_enabled else 0,
                int(body.panic_fanout_duration_ms),
                principal.username,
                now,
            ),
        )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "trigger.policy.save",
        target=device_id,
        detail={"group": group_display, "group_key": group_key, "owner_admin": owner or ""},
    )
    return {"ok": True, "device_id": device_id, "scope_group": group_display, "scope_group_key": group_key}


@router.post("/devices/{device_id}/provision/wifi-task")
def start_wifi_provision_task(
    device_id: str,
    body: ProvisionWifiTaskRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    chain_out: list[dict[str, Any]] = []
    for it in body.chain:
        c = (it.cmd or "").strip()
        if c not in _WIFI_DEFERRED_CMDS:
            raise HTTPException(
                status_code=400,
                detail=f"chain cmd not allowed: {c!r} (allowed: {', '.join(sorted(_WIFI_DEFERRED_CMDS))})",
            )
        chain_out.append({"cmd": c, "params": dict(it.params or {})})
    now = utc_now_iso()
    task_id = secrets.token_hex(12)
    params: dict[str, Any] = {"ssid": body.ssid, "password": body.password}
    if chain_out:
        params["chain"] = chain_out
    _publish_command(
        topic=f"{TOPIC_ROOT}/{device_id}/cmd",
        cmd="wifi_config",
        params=params,
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=_get_cmd_key_for_device(device_id),
    )
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO provision_tasks (
                task_id, owner_admin, device_id, kind, status, progress, message,
                request_json, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                owner or "",
                device_id,
                "wifi_config",
                "running",
                35,
                "command sent, waiting ack",
                json.dumps({"ssid": body.ssid, "chain": chain_out}, ensure_ascii=False),
                principal.username,
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
    emit_event(
        level="info",
        category="provision",
        event_type="provision.wifi.task.start",
        summary=f"wifi task started for {device_id}",
        actor=principal.username,
        target=device_id,
        owner_admin=owner or "",
        device_id=device_id,
        detail={"task_id": task_id, "chain_len": len(chain_out)},
    )
    return {"ok": True, "task_id": task_id, "status": "running", "progress": 35}


@router.get("/devices/{device_id}/provision/wifi-task/{task_id}")
def get_wifi_provision_task(
    device_id: str,
    task_id: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT task_id, status, progress, message, created_at, updated_at, request_json
            FROM provision_tasks
            WHERE task_id = ? AND device_id = ?
            """,
            (task_id, device_id),
        )
        tr = cur.fetchone()
        if not tr:
            conn.close()
            raise HTTPException(status_code=404, detail="task not found")
        status = str(tr["status"])
        progress = int(tr["progress"] or 0)
        message = str(tr["message"] or "")
        if status == "running":
            ack_obj: dict[str, Any] = {}
            try:
                ack_raw = str(row.get("last_ack_json") or "")
                ack_obj = json.loads(ack_raw) if ack_raw else {}
            except Exception:
                ack_obj = {}
            if str(ack_obj.get("cmd") or "") == "wifi_config" and isinstance(ack_obj.get("ok"), bool):
                status = "success" if bool(ack_obj.get("ok")) else "failed"
                progress = 100
                message = str(ack_obj.get("detail") or ("wifi saved" if status == "success" else "wifi rejected"))
                cur.execute(
                    "UPDATE provision_tasks SET status=?, progress=?, message=?, updated_at=? WHERE task_id=?",
                    (status, progress, message, utc_now_iso(), task_id),
                )
                conn.commit()
            else:
                progress = max(progress, 60)
                message = "waiting device ack/reboot"
        req_obj: dict[str, Any] = {}
        try:
            req_obj = json.loads(str(tr["request_json"] or "{}"))
        except Exception:
            req_obj = {}
        conn.close()
    return {
        "ok": True,
        "task_id": task_id,
        "device_id": device_id,
        "owner_admin": owner or "",
        "status": status,
        "progress": progress,
        "message": message,
        "request": req_obj,
        "created_at": tr["created_at"],
        "updated_at": tr["updated_at"],
    }
