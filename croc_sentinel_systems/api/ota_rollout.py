"""OTA campaign rollout / rollback / result-handling (Phase-39).

Six helpers that drive a per-admin OTA campaign through its lifecycle:

* ``_ota_campaign_targets_for_admin`` — snapshot every device an admin
  owns (with its current ``fw`` + ``ota_source_url`` from the last
  status frame) so we can later roll those exact same versions back
  if the new build misbehaves.
* ``_dispatch_ota_to_device`` — publish a single ``cmd=ota`` frame to
  one device with a per-device dedupe key (60 s) so a click-storm or
  retry burst can't spam the firmware with duplicate jobs.
* ``_start_ota_rollout_for_admin`` — fan the ``cmd=ota`` out across
  every row in ``ota_device_runs`` for the campaign+admin, flipping
  each row to ``dispatched`` (or ``failed`` on publish error).
* ``_rollback_admin_devices`` — for every device that had already
  flipped to ``success`` for this campaign+admin, re-publish their
  saved ``prev_url`` / ``prev_fw`` so the fleet returns to the prior
  build. Idempotent through ``ota_decisions`` ON CONFLICT.
* ``_handle_ota_result_safe`` / ``_handle_ota_result`` — what we call
  when a device ACKs an OTA. Updates the per-device row, emits an
  ``ota.device.result`` event, optionally triggers auto-rollback (if
  ``OTA_AUTO_ROLLBACK_ON_FAILURE`` is on), and recomputes the
  top-level campaign state for the dashboard.

Late-binding rules
------------------
``publish_command``, ``get_cmd_key_for_device``, and ``emit_event``
all live in ``app.py``. We resolve them at call time via
``import app as _app`` so this module loads cleanly during ``app.py``'s
own import. ``audit_event`` is imported directly from ``audit.py``
(no cycle there).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from audit import audit_event
from config import (
    CMD_PROTO,
    OTA_AUTO_ROLLBACK_ON_FAILURE,
    TOPIC_ROOT,
)
from db import db_lock, get_conn
from helpers import utc_now_iso

logger = logging.getLogger("crocapi.ota_rollout")


# ─────────────────────────────────────────────────────────────────────────
# Snapshot
# ─────────────────────────────────────────────────────────────────────────

def _ota_campaign_targets_for_admin(
    admin_username: str, fw_version: str, target_url: str
) -> list[dict[str, Any]]:
    """Return the list of device rows that belong to ``admin_username``
    along with their current fw/url so we can roll them back if needed.
    """
    rows: list[dict[str, Any]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.device_id, d.fw, d.last_status_json
            FROM device_state d
            JOIN device_ownership o ON o.device_id = d.device_id
            WHERE o.owner_admin = ?
            """,
            (admin_username,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    out: list[dict[str, Any]] = []
    for r in rows:
        prev_fw = str(r.get("fw") or "")
        prev_url = ""
        raw_status = r.get("last_status_json") or ""
        if raw_status:
            try:
                js = json.loads(str(raw_status))
                prev_url = str(js.get("ota_source_url") or "")
            except Exception:
                pass
        out.append({"device_id": str(r["device_id"]), "prev_fw": prev_fw, "prev_url": prev_url})
    return out


# ─────────────────────────────────────────────────────────────────────────
# Per-device dispatch
# ─────────────────────────────────────────────────────────────────────────

def _dispatch_ota_to_device(
    campaign_id: str, device_id: str, target_fw: str, target_url: str
) -> None:
    import app as _app  # late: avoid cycle at import time
    _app.publish_command(
        topic=f"{TOPIC_ROOT}/{device_id}/cmd",
        cmd="ota",
        params={"url": target_url, "fw": target_fw, "campaign_id": campaign_id},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=_app.get_cmd_key_for_device(device_id),
        dedupe_key=f"ota:{device_id}:{campaign_id or target_fw or target_url}",
        dedupe_ttl_s=60.0,
    )


# ─────────────────────────────────────────────────────────────────────────
# Rollout / rollback
# ─────────────────────────────────────────────────────────────────────────

def _start_ota_rollout_for_admin(
    campaign_id: str, admin_username: str
) -> tuple[int, list[str]]:
    """Dispatch the OTA command to every device owned by admin_username.

    Returns ``(dispatched_count, failures)``.
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT fw_version, url FROM ota_campaigns WHERE id = ?", (campaign_id,),
        )
        camp = cur.fetchone()
        if not camp:
            conn.close()
            return 0, ["campaign_not_found"]
        target_fw = str(camp["fw_version"])
        target_url = str(camp["url"])

        cur.execute(
            "SELECT device_id, target_fw, target_url FROM ota_device_runs WHERE campaign_id = ? AND admin_username = ?",
            (campaign_id, admin_username),
        )
        device_rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    dispatched = 0
    failures: list[str] = []
    for r in device_rows:
        did = str(r["device_id"])
        try:
            _dispatch_ota_to_device(campaign_id, did, target_fw, target_url)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='dispatched', started_at=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (utc_now_iso(), utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
            dispatched += 1
        except Exception as exc:
            failures.append(f"{did}:{exc}")
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='failed', error=?, finished_at=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (str(exc)[:240], utc_now_iso(), utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
    return dispatched, failures


def _rollback_admin_devices(campaign_id: str, admin_username: str, reason: str) -> int:
    """Send OTA with the previously-known url/fw to every device that had
    already flipped to ``success`` for this campaign under this admin.
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_id, prev_fw, prev_url
            FROM ota_device_runs
            WHERE campaign_id = ? AND admin_username = ? AND state = 'success'
            """,
            (campaign_id, admin_username),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    rolled = 0
    for r in rows:
        did = str(r["device_id"])
        prev_url = str(r.get("prev_url") or "")
        prev_fw = str(r.get("prev_fw") or "")
        if not prev_url:
            continue
        try:
            _dispatch_ota_to_device(f"{campaign_id}#rollback", did, prev_fw or "rollback", prev_url)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='rolled_back', error=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (reason[:240], utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
            rolled += 1
        except Exception:
            pass

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'rolled_back', ?, ?)
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='rolled_back', decided_at=excluded.decided_at, detail=excluded.detail
            """,
            (campaign_id, admin_username, utc_now_iso(), reason[:240]),
        )
        conn.commit()
        conn.close()

    try:
        audit_event(
            "system",
            "ota.rollback",
            target=admin_username,
            detail={"campaign_id": campaign_id, "reason": reason, "rolled": rolled},
        )
    except Exception:
        pass
    return rolled


# ─────────────────────────────────────────────────────────────────────────
# Result handling (called from MQTT ack ingest)
# ─────────────────────────────────────────────────────────────────────────

def _handle_ota_result_safe(device_id: str, payload: dict[str, Any]) -> None:
    try:
        _handle_ota_result(device_id, payload)
    except Exception as exc:
        logger.exception("ota result handling failed for %s: %s", device_id, exc)


def _handle_ota_result(device_id: str, payload: dict[str, Any]) -> None:
    campaign_id = str(payload.get("campaign_id") or "").strip()
    if not campaign_id or campaign_id.endswith("#rollback"):
        return
    ok = bool(payload.get("ok"))
    detail = str(payload.get("detail") or "")[:240]
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE ota_device_runs
            SET state = ?, error = ?, finished_at = ?, updated_at = ?
            WHERE campaign_id = ? AND device_id = ?
            """,
            ("success" if ok else "failed", "" if ok else detail, now_iso, now_iso, campaign_id, device_id),
        )
        # Find admin for rollback logic.
        cur.execute(
            "SELECT admin_username FROM ota_device_runs WHERE campaign_id = ? AND device_id = ?",
            (campaign_id, device_id),
        )
        row = cur.fetchone()
        admin_username = str(row["admin_username"]) if row else ""

        # Aggregate campaign state.
        cur.execute(
            "SELECT state, COUNT(*) AS c FROM ota_device_runs WHERE campaign_id = ? GROUP BY state",
            (campaign_id,),
        )
        agg = {str(r["state"]): int(r["c"]) for r in cur.fetchall()}
        conn.commit()
        conn.close()

    import app as _app  # late: avoid cycle at import time
    _app.emit_event(
        level="info" if ok else "error",
        category="ota",
        event_type="ota.device.result",
        summary=f"{device_id} ota {'ok' if ok else 'FAILED'} [{campaign_id}]",
        actor=f"device:{device_id}",
        target=admin_username or None,
        owner_admin=admin_username or None,
        device_id=device_id,
        detail={"campaign_id": campaign_id, "ok": ok, "detail": detail},
    )

    if not ok and OTA_AUTO_ROLLBACK_ON_FAILURE and admin_username:
        _rollback_admin_devices(campaign_id, admin_username, reason=f"device {device_id} failed: {detail}")

    # Update top-level campaign state for the dashboard.
    total = sum(agg.values())
    if total:
        failed = agg.get("failed", 0)
        success = agg.get("success", 0)
        pending = agg.get("pending", 0) + agg.get("dispatched", 0)
        rolled = agg.get("rolled_back", 0)
        if pending == 0 and failed == 0 and rolled == 0 and success == total:
            new_state = "success"
        elif pending == 0 and rolled > 0:
            new_state = "rolled_back"
        elif pending == 0 and failed > 0:
            new_state = "partial" if success > 0 else "failed"
        else:
            new_state = "running"
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE ota_campaigns SET state=?, updated_at=? WHERE id=?",
                (new_state, utc_now_iso(), campaign_id),
            )
            conn.commit()
            conn.close()


__all__ = [
    "_ota_campaign_targets_for_admin",
    "_dispatch_ota_to_device",
    "_start_ota_rollout_for_admin",
    "_rollback_admin_devices",
    "_handle_ota_result_safe",
    "_handle_ota_result",
]
