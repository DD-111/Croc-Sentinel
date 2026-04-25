"""Auto-reconcile worker + small MQTT-classifier helpers (Phase-38).

Two cooperating concerns that share an in-process queue and a couple
of dedup tables:

* **Alarm-event dedup** (``_alarm_event_is_duplicate``): the firmware
  occasionally retransmits the same ``alarm.trigger`` payload (Wi-Fi
  retry, MQTT QoS 1 redelivery on flap-up). We collapse repeats inside
  a short window so the dashboard only shows one alarm card per
  physical event.

* **Auto-reconcile worker** (``_enqueue_auto_reconcile``,
  ``_run_auto_reconcile_once``, ``_auto_reconcile_tick``): when an ACK
  comes back saying the device's ``cmd_key`` is wrong (we shipped one
  set of credentials, the device is running with another), we requeue
  a fresh bootstrap-assign with new credentials and re-publish it on
  the bootstrap topic. ``_is_ack_key_mismatch`` is the classifier the
  ingest path calls to decide whether to enqueue.

* **Pending-claim janitor** (``_prune_stale_pending_claims``): drops
  rows that haven't refreshed their ``bootstrap.register`` heartbeat
  in ``PENDING_CLAIM_STALE_SECONDS`` and rebinds ``proposed_device_id``
  by MAC so the dashboard's claim flow doesn't show stale aliases.

Late-binding rules
------------------
``_run_auto_reconcile_once`` calls into three symbols defined in
``app.py``: ``emit_event``, ``generate_device_credentials``, and
``publish_bootstrap_claim``. We resolve them at call time via
``import app as _app`` so this module loads cleanly during
``app.py``'s own import (the cycle would otherwise wedge bootstrap).
"""

from __future__ import annotations

import collections
import datetime as _dt
import logging
import threading
import time
from typing import Any, Optional

from audit import audit_event
from config import (
    ALARM_EVENT_DEDUP_WINDOW_SEC,
    AUTO_RECONCILE_COOLDOWN_SEC,
    AUTO_RECONCILE_ENABLED,
    AUTO_RECONCILE_MAX_PER_TICK,
    PENDING_CLAIM_STALE_SECONDS,
)
from db import db_lock, get_conn
from helpers import utc_now_iso

logger = logging.getLogger("crocapi.auto_reconcile")


# ─────────────────────────────────────────────────────────────────────────
# In-process state
# ─────────────────────────────────────────────────────────────────────────

# Alarm-event dedup table. ``"<device_id>|<sig>" -> last_epoch_seen``.
# Pruned opportunistically inside ``_alarm_event_is_duplicate``.
alarm_event_dedup_lock = threading.Lock()
alarm_event_dedup_seen: dict[str, float] = {}

# Auto-reconcile work queue. ``(device_id, reason)`` tuples.
# ``auto_reconcile_last_seen`` is the per-device cooldown ledger so a
# device that's misbehaving in a tight loop only triggers one assign
# every ``AUTO_RECONCILE_COOLDOWN_SEC``.
auto_reconcile_lock = threading.Lock()
auto_reconcile_queue: collections.deque[tuple[str, str]] = collections.deque()
auto_reconcile_last_seen: dict[str, float] = {}


# ─────────────────────────────────────────────────────────────────────────
# Classifiers (pure)
# ─────────────────────────────────────────────────────────────────────────

def _alarm_event_is_duplicate(device_id: str, payload: dict[str, Any]) -> bool:
    """Best-effort dedup for repeated ``alarm.trigger`` payloads in a short window."""
    win = max(0, int(ALARM_EVENT_DEDUP_WINDOW_SEC))
    if win <= 0:
        return False
    nonce = str(payload.get("nonce") or "").strip()
    ts_raw = str(payload.get("ts") or "").strip()
    trig = str(payload.get("trigger_kind") or "").strip()
    zone = str(payload.get("source_zone") or "").strip()
    # Prefer nonce when present; fall back to ts+kind+zone signature.
    sig = nonce or f"ts={ts_raw}|kind={trig}|zone={zone}"
    key = f"{device_id}|{sig}"
    now = time.time()
    cutoff = now - win
    with alarm_event_dedup_lock:
        stale = [k for k, exp in alarm_event_dedup_seen.items() if exp < cutoff]
        for k in stale:
            alarm_event_dedup_seen.pop(k, None)
        last = alarm_event_dedup_seen.get(key)
        if last and (now - last) <= win:
            return True
        alarm_event_dedup_seen[key] = now
    return False


def _is_ack_key_mismatch(payload: dict[str, Any]) -> bool:
    """Detect device-side command auth mismatch from ACK payload."""
    if bool(payload.get("ok", True)):
        return False
    detail = str(payload.get("detail") or "").strip().lower()
    if not detail:
        return False
    return detail in ("bad key", "device cmd_key unset", "key not 16 hex", "missing key")


# ─────────────────────────────────────────────────────────────────────────
# Auto-reconcile worker
# ─────────────────────────────────────────────────────────────────────────

def _enqueue_auto_reconcile(device_id: str, reason: str) -> None:
    if not AUTO_RECONCILE_ENABLED:
        return
    did = str(device_id or "").strip().upper()
    if not did:
        return
    now = time.time()
    with auto_reconcile_lock:
        last = auto_reconcile_last_seen.get(did, 0.0)
        if (now - last) < max(1, AUTO_RECONCILE_COOLDOWN_SEC):
            return
        auto_reconcile_last_seen[did] = now
        auto_reconcile_queue.append((did, str(reason or "auto")))


def _run_auto_reconcile_once(device_id: str, reason: str) -> bool:
    """Re-dispatch bootstrap assign with a fresh cmd_key for mismatched devices."""
    if not AUTO_RECONCILE_ENABLED:
        return False
    import app as _app  # late: avoid cycle at import time
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT pc.device_id, pc.mac_nocolon, IFNULL(pc.zone,'all') AS zone, IFNULL(pc.qr_code,'') AS qr_code
            FROM provisioned_credentials pc
            WHERE UPPER(pc.device_id)=UPPER(?)
            LIMIT 1
            """,
            (device_id,),
        )
        prov = cur.fetchone()
        if not prov:
            conn.close()
            return False
        did = str(prov["device_id"])
        mac = str(prov["mac_nocolon"] or "").upper()
        zone = str(prov["zone"] or "all").strip() or "all"
        qr = str(prov["qr_code"] or "")
        cur.execute(
            """
            SELECT claim_nonce, IFNULL(proposed_device_id,'') AS proposed_device_id
            FROM pending_claims
            WHERE mac_nocolon = ?
            LIMIT 1
            """,
            (mac,),
        )
        pending = cur.fetchone()
        if not pending:
            conn.close()
            _app.emit_event(
                level="warn",
                category="provision",
                event_type="provision.auto_reconcile.skipped",
                summary=f"auto-reconcile skipped for {did} (no pending_claim)",
                actor="system",
                target=did,
                device_id=did,
                detail={"reason": reason, "mac_nocolon": mac},
            )
            return False
        claim_nonce = str(pending["claim_nonce"] or "").strip()
        if len(claim_nonce) != 16:
            conn.close()
            return False
        mqtt_u, mqtt_p, cmd_key = _app.generate_device_credentials(did)
        cur.execute(
            """
            UPDATE provisioned_credentials
            SET mqtt_username=?, mqtt_password=?, cmd_key=?, zone=?, qr_code=?, claimed_at=?
            WHERE device_id=?
            """,
            (mqtt_u, mqtt_p, cmd_key, zone, qr, utc_now_iso(), did),
        )
        # Auto-rebind: keep pending proposed ID aligned to active provisioned device_id.
        cur.execute(
            "UPDATE pending_claims SET proposed_device_id = ? WHERE mac_nocolon = ?",
            (did, mac),
        )
        conn.commit()
        conn.close()
    _app.publish_bootstrap_claim(
        mac_nocolon=mac,
        claim_nonce=claim_nonce,
        device_id=did,
        zone=zone,
        qr_code=qr if qr else f"CROC-{mac}",
        mqtt_username=mqtt_u,
        mqtt_password=mqtt_p,
        cmd_key=cmd_key,
    )
    audit_event("system", "provision.auto_reconcile", did, {"reason": reason, "mac_nocolon": mac})
    _app.emit_event(
        level="warn",
        category="provision",
        event_type="provision.auto_reconcile.dispatched",
        summary=f"auto-reconcile assign dispatched for {did}",
        actor="system",
        target=did,
        device_id=did,
        detail={"reason": reason, "mac_nocolon": mac},
    )
    return True


def _auto_reconcile_tick() -> None:
    if not AUTO_RECONCILE_ENABLED:
        return
    batch: list[tuple[str, str]] = []
    with auto_reconcile_lock:
        for _ in range(min(AUTO_RECONCILE_MAX_PER_TICK, len(auto_reconcile_queue))):
            batch.append(auto_reconcile_queue.popleft())
    for did, why in batch:
        try:
            _run_auto_reconcile_once(did, why)
        except Exception as exc:
            logger.warning("auto_reconcile failed for %s: %s", did, exc)


# ─────────────────────────────────────────────────────────────────────────
# Pending-claim janitor
# ─────────────────────────────────────────────────────────────────────────

def _prune_stale_pending_claims() -> None:
    """Remove old pending_claim rows and keep proposed_device_id aligned by MAC."""
    if PENDING_CLAIM_STALE_SECONDS <= 0:
        return
    cutoff = _dt.datetime.fromtimestamp(
        time.time() - PENDING_CLAIM_STALE_SECONDS, tz=_dt.timezone.utc
    ).isoformat()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        # Rebind pending proposed_device_id to known provisioned device_id by MAC.
        cur.execute(
            """
            UPDATE pending_claims
            SET proposed_device_id = (
                SELECT pc.device_id FROM provisioned_credentials pc
                WHERE pc.mac_nocolon = pending_claims.mac_nocolon LIMIT 1
            )
            WHERE EXISTS (
                SELECT 1 FROM provisioned_credentials pc
                WHERE pc.mac_nocolon = pending_claims.mac_nocolon
            )
            """
        )
        # Clear stale rows that no longer refreshed by bootstrap.register.
        cur.execute("DELETE FROM pending_claims WHERE last_seen_at < ?", (cutoff,))
        deleted = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    if deleted:
        logger.info("pending_claims: pruned %d stale row(s)", deleted)


__all__ = [
    "alarm_event_dedup_lock",
    "alarm_event_dedup_seen",
    "auto_reconcile_lock",
    "auto_reconcile_queue",
    "auto_reconcile_last_seen",
    "_alarm_event_is_duplicate",
    "_is_ack_key_mismatch",
    "_enqueue_auto_reconcile",
    "_run_auto_reconcile_once",
    "_auto_reconcile_tick",
    "_prune_stale_pending_claims",
]
