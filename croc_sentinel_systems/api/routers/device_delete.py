"""Device-delete / factory-unregister router (Phase-26 modularization).

Two POST endpoints + a shared implementation helper. Both endpoints
unbind a device from its tenant; ``factory-unregister`` additionally
rolls the row in ``factory_devices`` back to ``unclaimed`` (a
superadmin-or-owner-admin operation) while ``delete-reset`` is
available to any tenant user with ``can_send_command``.

Routes
------
  POST /devices/{device_id}/delete-reset
  POST /devices/{device_id}/factory-unregister

Schema moved with the routes
----------------------------
  DeviceDeleteRequest

Late-binding strategy
---------------------
* Early-bound (identity-preserved) — defined long before the
  ``app.include_router`` call at line ~3920 in app.py:

    require_principal, require_capability, assert_device_owner,
    _try_mqtt_unclaim_reset

  ``_try_mqtt_unclaim_reset`` keeps living in app.py because it leans
  on a half-dozen MQTT plumbing globals (``publish_command``,
  ``_wait_cmd_ack``, ``TOPIC_ROOT``, ``CMD_PROTO``, …) that are
  cleaner to leave at the original site for now.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from device_lifecycle import LIFECYCLE_UNBOUND, transition_device_lifecycle_cur
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
assert_device_owner = _app.assert_device_owner
_try_mqtt_unclaim_reset = _app._try_mqtt_unclaim_reset
_try_mqtt_unclaim_reset_with_snapshot = _app._try_mqtt_unclaim_reset_with_snapshot
_snapshot_unclaim_payload_for_device = _app._snapshot_unclaim_payload_for_device
_mqtt_unsubscribe_device_topics = _app._mqtt_unsubscribe_device_topics


logger = logging.getLogger("croc-api.routers.device_delete")

router = APIRouter(tags=["device-delete"])


# ---- Schema ----------------------------------------------------------------

class DeviceDeleteRequest(BaseModel):
    confirm_text: str = Field(min_length=3, max_length=128)


# ---- Helper ---------------------------------------------------------------

def _device_delete_reset_impl(
    device_id: str,
    principal: Principal,
    req: DeviceDeleteRequest,
    *,
    super_unclaim: bool,
) -> dict[str, Any]:
    if str(req.confirm_text or "").strip().upper() != str(device_id or "").strip().upper():
        raise HTTPException(status_code=400, detail="confirm_text must exactly match device_id")
    require_capability(principal, "can_send_command")
    if super_unclaim:
        # Factory rollback: admin+ only (not subordinate "user" accounts).
        assert_min_role(principal, "admin")
        if not principal.is_superadmin():
            assert_device_owner(principal, device_id)
    else:
        assert_min_role(principal, "user")
        assert_device_owner(principal, device_id)
    req_id = str(uuid.uuid4())
    mode = "factory_unclaim" if super_unclaim else "delete_reset"
    now = utc_now_iso()
    # Phase 0 (pre-DB): snapshot publish material BEFORE the DB transaction
    # wipes ``provisioned_credentials``. Without this, every post-commit
    # ``unclaim_reset`` publish would either hit a missing row or sign with
    # the fallback CMD_AUTH_KEY (which the device's NVS rejects), leaving
    # the device locked in "server_unbound" forever and the operator stuck
    # watching a "pending" toast.
    snapshot = _snapshot_unclaim_payload_for_device(device_id)
    snapshot_cmd_key = str(snapshot.get("cmd_key") or "")
    snapshot_last_seen = str(snapshot.get("last_seen") or "")
    mac_nocolon = str(snapshot.get("mac_nocolon") or "")
    del_cred = del_owner = del_acl = del_revoked = del_state = del_sched = 0
    # Phase 1 (DB atomic): requested -> server_unbound + ownership/data unlink + lifecycle bump.
    with db_lock:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO device_unbind_jobs (
                    request_id, device_id, requested_by, mode, state,
                    command_sent, command_acked, detail_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'requested', 0, 0, ?, ?, ?)
                """,
                (req_id, device_id, principal.username, mode, "{}", now, now),
            )
            cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
            del_cred = int(cur.rowcount or 0)
            cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
            del_owner = int(cur.rowcount or 0)
            cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
            del_acl = int(cur.rowcount or 0)
            cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
            del_revoked = int(cur.rowcount or 0)
            cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
            del_state = int(cur.rowcount or 0)
            cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
            del_sched = int(cur.rowcount or 0)
            if mac_nocolon:
                cur.execute(
                    "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE mac_nocolon = ?",
                    (utc_now_iso(), mac_nocolon),
                )
            else:
                cur.execute(
                    "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE serial = ?",
                    (utc_now_iso(), device_id),
                )
            lifecycle_version = transition_device_lifecycle_cur(
                cur,
                device_id,
                LIFECYCLE_UNBOUND,
                owner_admin="",
                bump_version=True,
            )
            cur.execute(
                """
                UPDATE device_unbind_jobs
                SET state='server_unbound',
                    detail_json=?,
                    updated_at=?
                WHERE request_id=?
                """,
                (
                    json.dumps(
                        {
                            "deleted_credentials": del_cred,
                            "deleted_owner": del_owner,
                            "deleted_acl": del_acl,
                            "deleted_revoked": del_revoked,
                            "deleted_state": del_state,
                            "deleted_scheduled": del_sched,
                            "factory_unclaimed": bool(super_unclaim),
                            "lifecycle_state": LIFECYCLE_UNBOUND,
                            "lifecycle_version": int(lifecycle_version),
                            # Persist publish material so post-commit dispatch
                            # AND the scheduler compensation tick can keep
                            # retrying ``unclaim_reset`` until the device ACKs.
                            "snapshot_cmd_key": snapshot_cmd_key,
                            "snapshot_mac_nocolon": mac_nocolon,
                            "snapshot_last_seen": snapshot_last_seen,
                        },
                        ensure_ascii=True,
                    ),
                    utc_now_iso(),
                    req_id,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            raise
        conn.close()
    # Phase 2 (post-commit): non-blocking dispatch using the snapshotted
    # cmd_key — we deleted the credentials row above, so the legacy
    # ``_try_mqtt_unclaim_reset`` (which re-queries the DB) cannot work here.
    if snapshot_cmd_key:
        nvs_purge_sent, nvs_purge_acked = _try_mqtt_unclaim_reset_with_snapshot(
            device_id,
            snapshot_cmd_key,
            last_seen=snapshot_last_seen,
            wait_for_ack=False,
        )
    else:
        # No credentials existed (unknown / already-wiped device). Mark the
        # job completed so the scheduler doesn't retry forever, and audit.
        nvs_purge_sent = False
        nvs_purge_acked = False
    if nvs_purge_acked:
        unbind_state = "completed"
    elif nvs_purge_sent:
        # Command reached broker but no ACK yet. Scheduler will retry the
        # snapshot publish until the device confirms or operator gives up.
        unbind_state = "device_reset_pending"
    elif not snapshot_cmd_key:
        # Nothing to publish (no creds existed); server unlink is the final
        # state. Mark completed so no compensation tick chases a ghost.
        unbind_state = "completed"
    else:
        # Snapshot existed but broker was down. Schedule retries via
        # ``device_reset_pending`` so the compensation tick replays the
        # snapshot publish when the broker comes back.
        unbind_state = "device_reset_pending"
    mqtt_unsubscribed = _mqtt_unsubscribe_device_topics(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT IFNULL(detail_json,'{}') AS detail_json FROM device_unbind_jobs WHERE request_id = ?", (req_id,))
        row = cur.fetchone()
        try:
            detail = json.loads(str(row["detail_json"] if row else "{}") or "{}")
        except Exception:
            detail = {}
        detail["mqtt_unsubscribed"] = bool(mqtt_unsubscribed)
        detail["post_commit_dispatched_at"] = utc_now_iso()
        detail["post_commit_publish_sent"] = bool(nvs_purge_sent)
        detail["post_commit_publish_acked"] = bool(nvs_purge_acked)
        cur.execute(
            """
            UPDATE device_unbind_jobs
            SET state=?,
                command_sent=?,
                command_acked=?,
                detail_json=?,
                updated_at=?
            WHERE request_id=?
            """,
            (
                unbind_state,
                1 if nvs_purge_sent else 0,
                1 if nvs_purge_acked else 0,
                json.dumps(detail, ensure_ascii=True),
                utc_now_iso(),
                req_id,
            ),
        )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    action = "device.factory_unclaim" if super_unclaim else "device.delete_reset"
    audit_event(
        principal.username,
        action,
        device_id,
        {
            "request_id": req_id,
            "unbind_state": unbind_state,
            "mac_nocolon": mac_nocolon or "",
            "nvs_purge_mqtt": nvs_purge_sent,
            "nvs_purge_ack": nvs_purge_acked,
            "mqtt_unsubscribed": mqtt_unsubscribed,
            "deleted_credentials": del_cred,
            "deleted_owner": del_owner,
            "deleted_acl": del_acl,
            "deleted_revoked": del_revoked,
            "deleted_state": del_state,
            "deleted_scheduled": del_sched,
            "factory_unclaimed": super_unclaim,
            "snapshot_present": bool(snapshot_cmd_key),
        },
    )
    return {
        "ok": True,
        "status": "queued",
        "device_id": device_id,
        "request_id": req_id,
        "mode": mode,
        "unbind_state": unbind_state,
        "factory_unclaimed": super_unclaim,
        "nvs_purge_sent": nvs_purge_sent,
        "nvs_purge_acked": nvs_purge_acked,
        "nvs_purge_note": (
            "sent=true means command reached broker; "
            "acked=true means device confirmed unclaim_reset. "
            "acked=false means server unlink is done but device reset is pending; "
            "scheduler will keep retrying the snapshot publish until the device acks."
        ),
    }


# ---- Routes ----------------------------------------------------------------

@router.post("/devices/{device_id}/delete-reset")
def device_delete_reset(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Tenant user (operate) / admin / superadmin: unlink device + best-effort unclaim_reset."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=False)


@router.post("/devices/{device_id}/factory-unregister")
def device_factory_unregister(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Rollback to unregistered while keeping factory serial: superadmin (any device) or owning admin."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=True)


__all__ = [
    "router",
    "DeviceDeleteRequest",
    "_device_delete_reset_impl",
    "device_delete_reset",
    "device_factory_unregister",
]
