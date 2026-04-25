"""Per-device trigger-policy routes
(Phase-86 split from ``routers/device_provision.py``).

The Phase-19 ``routers/device_provision.py`` extract bundled two
distinct per-device admin surfaces:

  * **Trigger policy** (2 routes): GET/PUT
    ``/devices/{device_id}/trigger-policy`` — reads/writes the
    server-side ``trigger_policies`` table that controls panic
    fan-out behaviour, remote silent/loud links, and panic
    durations for a tenant+group scope. No MQTT publish, no
    external state machine, just SQL plus the audit row.
  * **Wi-Fi provisioning** (2 routes): POST/GET
    ``/devices/{device_id}/provision/wifi-task[/{task_id}]`` —
    dispatches a ``wifi_config`` MQTT command, persists a row in
    ``provision_tasks``, and tracks the task's status via the
    device's ``last_ack_json``. Heavy MQTT + cmd-key bookkeeping.

Phase 86 splits the trigger-policy surface here so the
``device_provision`` module can stay focused on the more invasive
Wi-Fi provisioning machinery (MQTT publish, cmd-key resolution,
deferred command chains, ack polling). Both routers share the
``"device-provision"`` OpenAPI tag for end-user grouping.

Routes
------
  GET /devices/{device_id}/trigger-policy   — read effective policy
                                              for the device's
                                              tenant+group scope.
  PUT /devices/{device_id}/trigger-policy   — upsert
                                              ``trigger_policies``
                                              row keyed by
                                              ``(owner_admin,
                                              scope_group_key)``.

Schemas owned here
------------------
  TriggerPolicyBody — bool/int validation for the 7 policy fields,
                      defaults pulled from
                      ``DEFAULT_PANIC_FANOUT_MS`` /
                      ``DEFAULT_REMOTE_FANOUT_MS`` so an admin who
                      omits a field gets the same value the seeder
                      uses for unconfigured tenants.

Why share ``_load_device_row_for_task``
--------------------------------------
The helper resolves zone + group + ownership from a single
device-row read; both surfaces need it. We import it from
``routers/device_provision.py`` (the Phase-19 host module) rather
than duplicating to avoid drift if the schema columns change.

Authorization rules
-------------------
* GET requires ``user`` role + ``assert_device_owner`` (read-only
  share is enough).
* PUT requires the stricter ``assert_device_command_actor`` (write
  authority over the device) AND tenant ownership of the group —
  trigger policy is intentionally not delegated through device
  share, since it affects every sibling device in the group.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import DEFAULT_PANIC_FANOUT_MS, DEFAULT_REMOTE_FANOUT_MS
from db import db_lock, get_conn
from helpers import _sibling_group_norm, utc_now_iso
from routers.device_provision import _load_device_row_for_task
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
assert_device_owner = _app.assert_device_owner
assert_device_command_actor = _app.assert_device_command_actor
_principal_tenant_owns_device = _app._principal_tenant_owns_device
_trigger_policy_for = _app._trigger_policy_for


logger = logging.getLogger("croc-api.routers.device_trigger_policy")
router = APIRouter(tags=["device-provision"])


class TriggerPolicyBody(BaseModel):
    """Per-tenant+group trigger policy.

    Defaults match the seeded values in ``app.py``: panic = local
    siren ON + link ON, default panic fanout = ``DEFAULT_PANIC_FANOUT_MS``,
    remote silent + loud links ON, default remote loud = ``DEFAULT_REMOTE_FANOUT_MS``,
    self-exclude ON. ``ge`` / ``le`` are clamped to safe siren-time
    bounds so a typo can't unknowingly request a 1-hour siren.
    """

    panic_local_siren: bool = True
    panic_link_enabled: bool = True
    panic_fanout_duration_ms: int = Field(
        default=DEFAULT_PANIC_FANOUT_MS, ge=500, le=600000
    )
    remote_silent_link_enabled: bool = True
    remote_loud_link_enabled: bool = True
    remote_loud_duration_ms: int = Field(
        default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000
    )
    fanout_exclude_self: bool = True


@router.get("/devices/{device_id}/trigger-policy")
def get_device_trigger_policy(
    device_id: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Read the effective trigger policy for a device's tenant+group.

    Returns the seeded defaults if no row exists in
    ``trigger_policies`` for the (owner_admin, scope_group) pair —
    callers can rely on ``policy`` always being a complete dict.
    """
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    if not _principal_tenant_owns_device(principal, owner):
        raise HTTPException(
            status_code=403,
            detail=(
                "trigger policy is managed by the owning tenant only "
                "(device share does not include group policy)"
            ),
        )
    group_display = str(row.get("notification_group") or "")
    pol = _trigger_policy_for(owner, group_display)
    return {
        "ok": True,
        "device_id": device_id,
        "scope_group": group_display,
        "policy": pol,
    }


@router.put("/devices/{device_id}/trigger-policy")
def save_device_trigger_policy(
    device_id: str,
    body: TriggerPolicyBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Upsert the trigger policy row for the device's tenant+group.

    The unique key is ``(owner_admin, scope_group)`` — every device
    in the same tenant+group sees the same policy. ``scope_group``
    is normalized via ``_sibling_group_norm`` so cosmetic
    differences (case, whitespace) don't fragment the policy table.
    """
    assert_device_command_actor(principal, device_id, check_revoked=False)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    if not _principal_tenant_owns_device(principal, owner):
        raise HTTPException(
            status_code=403,
            detail=(
                "trigger policy is managed by the owning tenant only "
                "(device share does not include group policy)"
            ),
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
        detail={
            "group": group_display,
            "group_key": group_key,
            "owner_admin": owner or "",
        },
    )
    return {
        "ok": True,
        "device_id": device_id,
        "scope_group": group_display,
        "scope_group_key": group_key,
    }


__all__ = (
    "router",
    "TriggerPolicyBody",
)
