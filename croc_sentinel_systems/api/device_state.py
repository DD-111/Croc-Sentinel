"""Device-state SQLite writers (Phase-37 modularization).

Four pure DB writers that the MQTT ingest path calls on every inbound
frame:

* ``upsert_pending_claim`` — record (or refresh) a bootstrap-register
  row in ``pending_claims`` so the dashboard's claim flow can find the
  device. Honours ``ENFORCE_FACTORY_REGISTRATION``: in production the
  device must already exist in ``factory_devices`` and not be marked
  ``blocked``.
* ``upsert_device_state`` — main heartbeat / status / event / ack
  writer. Returns the previous ``updated_at`` so callers can detect an
  offline→online transition (which is what triggers
  ``_maybe_replay_queue_on_reconnect`` and the OTA-hint refresh).
* ``insert_message`` — append-only ``messages`` table for the
  per-device timeline view.
* ``_extract_zone_from_device_state_row`` — best-effort fallback that
  digs the most-recently-published zone out of the four ``last_*_json``
  payload columns when the dedicated ``zone`` column is empty.

These functions are deliberately self-contained: they touch only
SQLite (``db.py``), ``config.ENFORCE_FACTORY_REGISTRATION``, and
``helpers.utc_now_iso``. No event bus, no notifier, no MQTT publish —
the live-broadcast side effects happen further up the stack in
``_dispatch_mqtt_payload``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Optional

from config import ENFORCE_FACTORY_REGISTRATION
from db import cache_invalidate, db_lock, get_conn
from helpers import utc_now_iso

logger = logging.getLogger("crocapi.device_state")

# --- Deprovisioned-resurrection guard --------------------------------------
# A device that has been ``unbind & reset``-ed has its row removed from
# ``device_state`` and ``provisioned_credentials``, AND a ``UNBOUND`` row in
# ``device_lifecycle``. If that device is still online with the old cmd_key
# in its NVS (because ``unclaim_reset`` did not reach it / has not been
# acked), every heartbeat / status / ack / event would silently
# ``upsert_device_state`` and re-create the row — making the device look
# "alive again" in the dashboard immediately after the operator deletes it.
#
# The guard: any caller (today only ``mqtt_pipeline._dispatch_mqtt_payload``)
# that goes through ``upsert_device_state`` will short-circuit when the
# lifecycle says ``UNBOUND`` AND there is no provisioned_credentials row.
# We additionally throttle a "reaffirm" warning log so the operator sees
# WHY the device keeps publishing — and so they can confirm whether the
# scheduler is still retrying the snapshot ``unclaim_reset`` publish.

_DEPROV_LOG_LOCK = threading.Lock()
_DEPROV_LAST_LOG_AT: dict[str, float] = {}
_DEPROV_LOG_COOLDOWN_S = 60.0


def _is_deprovisioned(cur, device_id: str) -> bool:
    """True iff lifecycle is UNBOUND and no provisioned_credentials row exists.

    Pure read; uses the caller's cursor (no transaction boundary change).
    """
    if not device_id:
        return False
    try:
        cur.execute(
            "SELECT lifecycle_state FROM device_lifecycle WHERE device_id = ? LIMIT 1",
            (device_id,),
        )
        row = cur.fetchone()
        state = str(row["lifecycle_state"] if row and row["lifecycle_state"] is not None else "").upper()
        if state != "UNBOUND":
            return False
        cur.execute("SELECT 1 FROM provisioned_credentials WHERE device_id = ? LIMIT 1", (device_id,))
        return cur.fetchone() is None
    except Exception:
        # If the lifecycle table or columns aren't ready (older DB), do
        # NOT block. The guard is best-effort and must never block legit
        # writers.
        return False


def _maybe_log_deprov_blocked(device_id: str, channel: str) -> None:
    """Throttled warning so operators can see WHY the device keeps publishing."""
    now = time.monotonic()
    with _DEPROV_LOG_LOCK:
        last = _DEPROV_LAST_LOG_AT.get(device_id, 0.0)
        if now - last < _DEPROV_LOG_COOLDOWN_S:
            return
        _DEPROV_LAST_LOG_AT[device_id] = now
    logger.warning(
        "device_state.upsert blocked: device_id=%s lifecycle=UNBOUND, no provisioned_credentials. "
        "Channel=%s. Device still has old cmd_key in NVS — scheduler will keep retrying unclaim_reset.",
        device_id, channel,
    )


def upsert_pending_claim(payload: dict[str, Any]) -> None:
    mac_nocolon = str(payload.get("mac_nocolon", "")).upper()
    claim_nonce = str(payload.get("claim_nonce", ""))
    if len(mac_nocolon) != 12 or len(claim_nonce) != 16:
        return
    # Production mode: the device must be listed in factory_devices. This is
    # the mechanism that makes the serial number "unguessable": an attacker
    # who types a random serial on the dashboard will 404 because there is no
    # matching factory row AND because the real devices are the only ones that
    # ever get into pending_claims via the bootstrap MQTT credential.
    serial = str(payload.get("serial", "")).strip().upper()
    if ENFORCE_FACTORY_REGISTRATION:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT serial, mac_nocolon, status FROM factory_devices "
                "WHERE mac_nocolon = ? OR serial = ? LIMIT 1",
                (mac_nocolon, serial),
            )
            fdev = cur.fetchone()
            conn.close()
        if not fdev:
            logger.warning(
                "pending_claims rejected: MAC %s serial %s not in factory_devices (ENFORCE_FACTORY_REGISTRATION=1)",
                mac_nocolon, serial or "-",
            )
            return
        if str(fdev["status"] or "unclaimed") == "blocked":
            logger.warning("pending_claims rejected: serial %s is blocked", serial or fdev["serial"])
            return

    mac = str(payload.get("mac", ""))
    qr_code = str(payload.get("qr_code", ""))
    fw = str(payload.get("fw", ""))
    proposed_device_id = str(payload.get("device_id", ""))
    now = utc_now_iso()

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pending_claims (
                mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, payload_json, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_nocolon) DO UPDATE SET
                mac = excluded.mac,
                qr_code = excluded.qr_code,
                fw = excluded.fw,
                claim_nonce = excluded.claim_nonce,
                proposed_device_id = excluded.proposed_device_id,
                payload_json = excluded.payload_json,
                last_seen_at = excluded.last_seen_at
            """,
            (
                mac_nocolon,
                mac,
                qr_code,
                fw,
                claim_nonce,
                proposed_device_id,
                json.dumps(payload, ensure_ascii=True),
                now,
            ),
        )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")


def upsert_device_state(device_id: str, channel: str, payload: dict[str, Any]) -> Optional[str]:
    """Persist the latest MQTT frame for ``device_id`` and return the
    previous ``updated_at`` value (ISO string) so callers can detect
    offline→online transitions. Returns ``None`` for brand-new devices.
    """
    now = utc_now_iso()
    fw = str(payload.get("fw", ""))
    chip_target = str(payload.get("chip_target", ""))
    board_profile = str(payload.get("board_profile", ""))
    net_type = str(payload.get("net_type", ""))
    provisioned = payload.get("provisioned")
    if isinstance(provisioned, bool):
        provisioned_val = 1 if provisioned else 0
    else:
        provisioned_val = None
    zone = str(payload.get("zone", ""))
    payload_str = json.dumps(payload, ensure_ascii=True)

    prev_updated_at: Optional[str] = None

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if _is_deprovisioned(cur, device_id):
            conn.close()
            _maybe_log_deprov_blocked(device_id, channel)
            return None
        cur.execute("SELECT zone FROM device_zone_overrides WHERE device_id = ?", (device_id,))
        zov = cur.fetchone()
        if zov and zov["zone"] is not None:
            zone = str(zov["zone"])
        cur.execute("SELECT device_id, updated_at FROM device_state WHERE device_id = ?", (device_id,))
        existing_row = cur.fetchone()
        exists = existing_row is not None
        if exists:
            prev_updated_at = str(existing_row["updated_at"] or "") or None

        if not exists:
            cur.execute(
                """
                INSERT INTO device_state (
                    device_id, fw, chip_target, board_profile, net_type, zone, provisioned, last_status_json, last_heartbeat_json,
                    last_ack_json, last_event_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)
                """,
                (device_id, fw, chip_target, board_profile, net_type, zone, provisioned_val, now),
            )

        update_fields = ["updated_at = ?"]
        update_args: list[Any] = [now]

        if fw:
            update_fields.append("fw = ?")
            update_args.append(fw)
        if chip_target:
            update_fields.append("chip_target = ?")
            update_args.append(chip_target)
        if board_profile:
            update_fields.append("board_profile = ?")
            update_args.append(board_profile)
        if net_type:
            update_fields.append("net_type = ?")
            update_args.append(net_type)
        if zone:
            update_fields.append("zone = ?")
            update_args.append(zone)
        if provisioned_val is not None:
            update_fields.append("provisioned = ?")
            update_args.append(provisioned_val)

        if channel == "status":
            update_fields.append("last_status_json = ?")
            update_args.append(payload_str)
        elif channel == "heartbeat":
            update_fields.append("last_heartbeat_json = ?")
            update_args.append(payload_str)
        elif channel == "ack":
            update_fields.append("last_ack_json = ?")
            update_args.append(payload_str)
        elif channel == "event":
            update_fields.append("last_event_json = ?")
            update_args.append(payload_str)

        update_args.append(device_id)
        cur.execute(
            f"UPDATE device_state SET {', '.join(update_fields)} WHERE device_id = ?",
            tuple(update_args),
        )
        conn.commit()
        conn.close()

    return prev_updated_at


def _extract_zone_from_device_state_row(row: Any) -> str:
    """Best-effort fallback zone from latest stored MQTT payloads."""
    if not row:
        return "all"
    for k in ("last_status_json", "last_heartbeat_json", "last_ack_json", "last_event_json"):
        raw = row[k] if k in row.keys() else None
        if not raw:
            continue
        try:
            obj = json.loads(str(raw))
        except Exception:
            continue
        z = str(obj.get("zone") or "").strip()
        if z:
            return z
    return "all"


def insert_message(topic: str, channel: str, device_id: Optional[str], payload: dict[str, Any]) -> None:
    ts_device = payload.get("ts")
    if not isinstance(ts_device, int):
        ts_device = None

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO messages (topic, channel, device_id, payload_json, ts_device, ts_received)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                topic,
                channel,
                device_id,
                json.dumps(payload, ensure_ascii=True),
                ts_device,
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()


__all__ = [
    "upsert_pending_claim",
    "upsert_device_state",
    "_extract_zone_from_device_state_row",
    "insert_message",
]
