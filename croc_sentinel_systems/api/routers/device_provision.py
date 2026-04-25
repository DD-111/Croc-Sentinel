"""Device Wi-Fi provisioning routes (Phase-19, trimmed Phase-86).

Surface evolution:
  Phase 19 — original module: 4 per-device endpoints (2 trigger-policy
              GET/PUT + 2 Wi-Fi provisioning POST/GET-task) sharing a
              common ``_load_device_row_for_task`` helper.
  Phase 86 — extracted the 2 trigger-policy routes + ``TriggerPolicyBody``
              into ``routers/device_trigger_policy.py``, leaving the
              Wi-Fi provisioning machinery here.

Routes (still here)
-------------------
  POST /devices/{device_id}/provision/wifi-task           — start a
                                                            wifi_config
                                                            MQTT cmd
                                                            and a task
                                                            row.
  GET  /devices/{device_id}/provision/wifi-task/{task_id} — poll task
                                                            status,
                                                            promote
                                                            on ack.

Schemas / constants owned here
------------------------------
  WifiDeferredCmd, ProvisionWifiTaskRequest, _WIFI_DEFERRED_CMDS

The ``TriggerPolicyBody`` schema and the 2 trigger-policy routes
live in ``routers/device_trigger_policy.py``. Both routers share
the ``"device-provision"`` OpenAPI tag for end-user grouping.

Helper re-exported (single source of truth here)
------------------------------------------------
  _load_device_row_for_task — imported by
    ``routers/device_trigger_policy.py``. Resolves zone +
    notification_group + last_ack_json + owner_admin in one
    db_lock-scoped read; both surfaces need it.

Late-binding strategy
---------------------
The cross-feature helpers live in app.py and are captured here:

  early-bound (defined < line ~3300 in app.py):
    require_principal, assert_device_command_actor,
    _principal_tenant_owns_device, emit_event

  call-time wrappers (defined > line ~6000 in app.py):
    publish_command, get_cmd_key_for_device

Trigger-policy routes also need:
  early-bound: assert_device_owner, _trigger_policy_for
which they late-bind themselves in their own module.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from config import CMD_PROTO, TOPIC_ROOT
from db import db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
assert_device_owner = _app.assert_device_owner
assert_device_command_actor = _app.assert_device_command_actor
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


# Phase-86 split: ``TriggerPolicyBody`` moved to
# ``routers/device_trigger_policy.py`` along with the 2 trigger-policy
# routes (GET/PUT /devices/{device_id}/trigger-policy). Both routers
# share the ``device-provision`` OpenAPI tag.


# ---- Shared helper (re-exported by routers/device_trigger_policy.py) -------

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
#
# Phase-86 split: the 2 trigger-policy routes (GET/PUT
# /devices/{device_id}/trigger-policy) live in
# ``routers/device_trigger_policy.py`` along with ``TriggerPolicyBody``.
# Both routers share the ``device-provision`` tag so the OpenAPI doc
# still groups all 4 endpoints together for end users.


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
