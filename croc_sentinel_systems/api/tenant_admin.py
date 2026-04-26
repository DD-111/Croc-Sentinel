"""Tenant lifecycle + device cleanup helpers (Phase-47 extraction
from ``app.py``).

This module owns the five small helpers that live at the boundary
between "delete a user" and "wipe a device" — the SQLite-only
cleanup operations and the best-effort MQTT preflight that runs
before the DB unlink:

* :func:`_delete_user_auxiliary_cur` — drop role policies, OTPs,
  ACL grants, Telegram bindings/links, FCM tokens, password reset
  tokens and the ``dashboard_users`` row for one username. Does
  *not* touch ``device_ownership`` (that's the caller's call).
  Invalidates the superadmin Telegram chat-id cache because the
  deleted user might have been the cached superadmin.
* :func:`_apply_device_factory_unclaim_cur` — same data effect as
  the ``factory-unregister`` endpoint, but cursor-only: drop
  provisioned creds, ownership, ACL, revocation, device_state and
  scheduled_commands rows for one device, and flip
  ``factory_devices.status`` back to ``unclaimed`` (matched on
  ``mac_nocolon`` if known, else ``serial``).
* :func:`_close_admin_tenant_cur` — top-level "close this admin"
  flow: validate the role, optionally transfer all owned devices
  to another admin/superadmin (clearing display labels +
  notification groups so the new owner re-labels), or unclaim
  them; then delete every subordinate user under that admin and
  finally the admin row itself. Returns a summary dict for the
  audit log. Does not commit — caller controls the transaction.
* :func:`_wait_cmd_ack` — busy-poll ``device_state.last_ack_json``
  for up to ``timeout_s`` seconds waiting for an ACK matching
  ``cmd`` (and optionally a specific ``cmd_id``). Used by
  :func:`_try_mqtt_unclaim_reset` to give a freshly-published
  ``unclaim_reset`` a brief window to land before we tear down
  the credentials.
* :func:`_try_mqtt_unclaim_reset` — best-effort: publish
  ``unclaim_reset`` over MQTT and, *only* if the device has been
  seen recently (``last_ts within OFFLINE_THRESHOLD_SECONDS``),
  wait briefly for an ACK. Returns ``(sent, acked)``. Fails fast
  on broker outages so the HTTP caller never blocks waiting for
  an ACK that's never coming.

Wiring
------
* SQLite-only helpers pull ``HTTPException`` from FastAPI,
  ``db_lock``/``get_conn`` from :mod:`db`, ``utc_now_iso`` from
  :mod:`helpers`, ``secrets`` from stdlib.
* The Telegram cache invalidator
  (``_invalidate_superadmin_telegram_chats_cache``), the MQTT
  publisher (``publish_command``), the per-device cmd-key getter
  (``get_cmd_key_for_device``), the offline threshold
  (``OFFLINE_THRESHOLD_SECONDS``) and the epoch parser
  (``_parse_iso``) are read off ``app`` at *call time* via
  ``import app as _app`` — they're defined in ``app.py`` and
  ``app.py`` re-exports the helpers below, so the cycle resolves
  at runtime when the worker actually fires.
* MQTT topic root and command-frame protocol come from
  :mod:`config` directly.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Optional

from fastapi import HTTPException

import app as _app
from config import CMD_PROTO, TOPIC_ROOT
from db import db_lock, get_conn
from device_lifecycle import LIFECYCLE_ACTIVE, LIFECYCLE_UNBOUND, transition_device_lifecycle_cur
from helpers import utc_now_iso

__all__ = (
    "_delete_user_auxiliary_cur",
    "_apply_device_factory_unclaim_cur",
    "_close_admin_tenant_cur",
    "_wait_cmd_ack",
    "_try_mqtt_unclaim_reset",
    "_try_mqtt_unclaim_reset_with_snapshot",
    "_snapshot_unclaim_payload_for_device",
    "_mqtt_unsubscribe_device_topics",
)

logger = logging.getLogger(__name__)


def _delete_user_auxiliary_cur(cur: Any, username: str) -> None:
    """Remove dashboard user row and attached rows (not device ownership)."""
    cur.execute("DELETE FROM role_policies WHERE username = ?", (username,))
    cur.execute("DELETE FROM verifications WHERE username = ?", (username,))
    cur.execute("DELETE FROM device_acl WHERE grantee_username = ?", (username,))
    cur.execute("DELETE FROM telegram_chat_bindings WHERE username = ?", (username,))
    cur.execute("DELETE FROM telegram_link_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM user_fcm_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM password_reset_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))
    # If the deleted user was a superadmin, the cached chat list is stale;
    # same for the username->role cache.
    _app._invalidate_superadmin_telegram_chats_cache()


def _apply_device_factory_unclaim_cur(cur: Any, device_id: str) -> None:
    """Same data effect as factory-unregister: unclaim in DB + factory_devices status (caller holds lock)."""
    cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (device_id,))
    p = cur.fetchone()
    mac_nocolon = str(p["mac_nocolon"]) if p and p["mac_nocolon"] else ""
    cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
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
    transition_device_lifecycle_cur(
        cur,
        device_id,
        LIFECYCLE_UNBOUND,
        owner_admin="",
        bump_version=True,
    )


def _close_admin_tenant_cur(
    cur: Any,
    admin_username: str,
    transfer_devices_to: Optional[str],
    actor_username: str,
) -> dict[str, Any]:
    """
    admin_username: role must be 'admin'. Transfers or unclaims all owned devices, deletes
    subordinate users, then deletes the admin row. Does not commit.
    """
    cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (admin_username,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    role = str(row["role"] or "")
    if role == "superadmin":
        raise HTTPException(status_code=400, detail="cannot close a superadmin account with this action")
    if role != "admin":
        raise HTTPException(status_code=400, detail="target is not an admin tenant")
    summary: dict[str, Any] = {
        "admin": admin_username,
        "devices_unclaimed": 0,
        "devices_transferred": 0,
        "subordinate_users_deleted": 0,
    }
    transfer_to = (transfer_devices_to or "").strip() or None
    if transfer_to:
        cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (transfer_to,))
        trow = cur.fetchone()
        if not trow or str(trow["role"] or "") not in ("admin", "superadmin"):
            raise HTTPException(status_code=400, detail="transfer_devices_to must be an existing admin or superadmin")
        if secrets.compare_digest(transfer_to, admin_username):
            raise HTTPException(status_code=400, detail="cannot transfer to the same admin")
        cur.execute("SELECT device_id FROM device_ownership WHERE owner_admin = ?", (admin_username,))
        transfer_ids = [str(r["device_id"]) for r in cur.fetchall() if r and r["device_id"]]
        cur.execute(
            """
            UPDATE device_ownership
            SET owner_admin = ?, assigned_by = ?, assigned_at = ?
            WHERE owner_admin = ?
            """,
            (transfer_to, actor_username, utc_now_iso(), admin_username),
        )
        summary["devices_transferred"] = int(cur.rowcount or 0)
        if transfer_ids:
            ph = ",".join("?" * len(transfer_ids))
            cur.execute(
                f"UPDATE device_state SET display_label = '', notification_group = '' WHERE device_id IN ({ph})",
                transfer_ids,
            )
            for did in transfer_ids:
                transition_device_lifecycle_cur(
                    cur,
                    did,
                    LIFECYCLE_ACTIVE,
                    owner_admin=transfer_to,
                    bump_version=True,
                )
    else:
        cur.execute("SELECT device_id FROM device_ownership WHERE owner_admin = ?", (admin_username,))
        for r in cur.fetchall():
            did = str(r["device_id"] or "")
            if not did:
                continue
            _apply_device_factory_unclaim_cur(cur, did)
            summary["devices_unclaimed"] += 1
    cur.execute(
        "SELECT username FROM dashboard_users WHERE manager_admin = ? AND role = 'user'",
        (admin_username,),
    )
    for r in cur.fetchall():
        su = str(r["username"] or "")
        if su:
            _delete_user_auxiliary_cur(cur, su)
            summary["subordinate_users_deleted"] += 1
    _delete_user_auxiliary_cur(cur, admin_username)
    return summary


def _wait_cmd_ack(device_id: str, cmd: str, timeout_s: float = 2.5, cmd_id: Optional[str] = None) -> bool:
    deadline = time.time() + max(0.2, float(timeout_s))
    cid = (cmd_id or "").strip()
    while time.time() < deadline:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT IFNULL(last_ack_json,'') AS last_ack_json FROM device_state WHERE device_id = ?",
                (device_id,),
            )
            row = cur.fetchone()
            conn.close()
        try:
            ack = json.loads(str((row["last_ack_json"] if row else "") or ""))
        except Exception:
            ack = {}
        if str(ack.get("cmd") or "") != cmd or not bool(ack.get("ok")):
            time.sleep(0.12)
            continue
        if cid and str(ack.get("cmd_id") or "") != cid:
            time.sleep(0.12)
            continue
        return True
    return False


def _try_mqtt_unclaim_reset(device_id: str, *, wait_for_ack: bool = True) -> tuple[bool, bool]:
    """Best-effort dispatch + short ack wait for unclaim_reset before DB unlink.

    Returns (sent, acked). Fails fast (no blocking) when the broker is down or
    the device is offline — the HTTP request must not hang for a dead device.
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 1 AS ok,
                   IFNULL((SELECT updated_at FROM device_state WHERE device_id = pc.device_id),'') AS updated_at
            FROM provisioned_credentials pc
            WHERE pc.device_id = ?
            """,
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return False, False
    last_seen = str(row["updated_at"] or "")
    # If the device hasn't been seen recently, skip the ACK wait entirely.
    # The command is still published (broker queues for QoS 1), but the HTTP caller
    # won't block waiting for an ACK that's never coming.
    online_hint = False
    try:
        last_ts = _app._parse_iso(last_seen)
        if last_ts > 0:
            online_hint = (time.time() - last_ts) < max(60, int(_app.OFFLINE_THRESHOLD_SECONDS))
    except Exception:
        online_hint = False
    try:
        # No dedupe: a prior attempt may have deleted server-side creds while
        # the device never got MQTT; retries must publish a fresh frame. Firmware
        # treats unclaim_reset idempotently.
        cmd_id = _app.publish_command(
            f"{TOPIC_ROOT}/{device_id}/cmd",
            "unclaim_reset",
            {},
            device_id,
            CMD_PROTO,
            _app.get_cmd_key_for_device(device_id),
            cred_version=_app.get_cmd_cred_version_for_device(device_id),
        )
    except HTTPException as exc:
        # 503 = broker disconnected -> no MQTT, don't wait.
        logger.warning("unclaim_reset MQTT not delivered for %s: %s", device_id, getattr(exc, "detail", exc))
        return False, False
    except Exception as exc:
        logger.warning("unclaim_reset MQTT error for %s: %s", device_id, exc)
        return False, False
    if (not wait_for_ack) or (not online_hint):
        return True, False
    return True, _wait_cmd_ack(device_id, "unclaim_reset", timeout_s=2.2, cmd_id=cmd_id)


def _snapshot_unclaim_payload_for_device(device_id: str) -> dict[str, str]:
    """Snapshot the publish material (cmd_key + mac + last_seen + cred_version) BEFORE the
    delete-reset DB transaction wipes ``provisioned_credentials``.

    Why this exists: ``_try_mqtt_unclaim_reset`` and ``get_cmd_key_for_device``
    both query ``provisioned_credentials`` to resolve the per-device cmd_key.
    Once the unbind transaction commits the DELETE, every subsequent publish
    attempt either fails the row lookup or signs with the fallback
    ``CMD_AUTH_KEY`` (which the device's NVS rejects). Persisting the snapshot
    in the unbind-job ``detail_json`` lets both the immediate post-commit
    dispatch *and* the scheduler compensation tick re-publish ``unclaim_reset``
    with the right key until the device ACKs.
    """
    raw = str(device_id or "").strip()
    if not raw:
        return {"cmd_key": "", "mac_nocolon": "", "last_seen": "", "cred_version": "0"}
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT IFNULL(pc.cmd_key,'')      AS cmd_key,
                   IFNULL(pc.mac_nocolon,'')  AS mac_nocolon,
                   IFNULL(pc.cred_version,0)   AS cred_version,
                   IFNULL((SELECT updated_at FROM device_state
                           WHERE device_id = pc.device_id),'') AS last_seen
            FROM provisioned_credentials pc
            WHERE pc.device_id = ?
            """,
            (raw,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return {"cmd_key": "", "mac_nocolon": "", "last_seen": "", "cred_version": "0"}
    return {
        "cmd_key": str(row["cmd_key"] or "").strip().upper(),
        "mac_nocolon": str(row["mac_nocolon"] or "").strip(),
        "last_seen": str(row["last_seen"] or "").strip(),
        "cred_version": str(int(row["cred_version"] or 0)),
    }


def _try_mqtt_unclaim_reset_with_snapshot(
    device_id: str,
    cmd_key: str,
    *,
    cred_version: int = 0,
    last_seen: str = "",
    wait_for_ack: bool = False,
) -> tuple[bool, bool]:
    """Publish ``unclaim_reset`` using a previously snapshotted cmd_key.

    Used by:
      * the post-commit phase in ``_device_delete_reset_impl`` (credentials
        already deleted, so the original DB-driven helper would no-op);
      * the scheduler compensation tick (retries until ACK or operator-bound
        timeout, replaying the same snapshot from ``detail_json``).

    Returns ``(sent, acked)``. Fails fast on broker outages so HTTP/scheduler
    callers never hang. ``wait_for_ack=True`` only waits when ``last_seen``
    indicates the device has been seen recently (within
    ``OFFLINE_THRESHOLD_SECONDS``).
    """
    did = str(device_id or "").strip()
    key = str(cmd_key or "").strip().upper()
    if not did or not key:
        return False, False
    online_hint = False
    seen = (last_seen or "").strip()
    if seen:
        try:
            last_ts = _app._parse_iso(seen)
            if last_ts > 0:
                online_hint = (time.time() - last_ts) < max(60, int(_app.OFFLINE_THRESHOLD_SECONDS))
        except Exception:
            online_hint = False
    try:
        cmd_id = _app.publish_command(
            f"{TOPIC_ROOT}/{did}/cmd",
            "unclaim_reset",
            {},
            did,
            CMD_PROTO,
            key,
            cred_version=int(cred_version or 1),
        )
    except HTTPException as exc:
        logger.warning(
            "unclaim_reset MQTT (snapshot) not delivered for %s: %s",
            did,
            getattr(exc, "detail", exc),
        )
        return False, False
    except Exception as exc:
        logger.warning("unclaim_reset MQTT (snapshot) error for %s: %s", did, exc)
        return False, False
    if (not wait_for_ack) or (not online_hint):
        return True, False
    return True, _wait_cmd_ack(did, "unclaim_reset", timeout_s=2.2, cmd_id=cmd_id)


def _mqtt_unsubscribe_device_topics(device_id: str) -> bool:
    """Best-effort MQTT topic cleanup after unbind/reset."""
    did = str(device_id or "").strip()
    if not did:
        return False
    c = getattr(_app, "mqtt_client", None)
    if c is None:
        return False
    ok = False
    for topic in (f"{TOPIC_ROOT}/{did}/#", f"{TOPIC_ROOT}/{did}/cmd"):
        try:
            c.unsubscribe(topic)
            ok = True
        except Exception as exc:
            logger.debug("mqtt unsubscribe failed topic=%s err=%s", topic, exc)
    return ok
