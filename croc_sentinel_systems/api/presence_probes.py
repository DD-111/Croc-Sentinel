"""Presence-probe + retention helpers (Phase-43 extraction from ``app.py``).

This module owns the "is the device alive?" subsystem that runs on a
background thread:

* When a device has been silent longer than
  :data:`PRESENCE_PROBE_IDLE_SECONDS`, the scheduler thread asks us to
  send a ``ping`` command and remember we did so (so we don't spam the
  same idle device every tick).
* When the device's MQTT ack arrives, the ingest thread flips the most
  recent ``sent`` row to ``acked`` and emits a ``presence.probe.acked``
  event for the dashboard.
* If no ack ever arrives, ``_expire_presence_probes_waiting_ack``
  marks the row ``timeout`` so the dashboard doesn't show it as
  forever-pending.

The same scheduler also drives two cousin housekeeping passes that are
unrelated to presence but live in the same neighbourhood:

* :func:`_events_retention_tick` — level-based pruning of the ``events``
  table (debug rows expire fast, critical rows live for a year).
* :func:`_fail_stale_scheduled_commands` — flip ``status='pending'``
  scheduled jobs whose ``execute_at`` is far in the past to ``failed``.

Late-bind contract
------------------
``_send_presence_probe``, ``_mark_presence_probe_acked``, and
``_presence_probe_tick`` need three callables that are defined further
down in ``app.py`` — ``publish_command``, ``get_cmd_key_for_device``,
and ``emit_event`` — so they go through ``import app as _app`` at
call time. ``_find_stale_devices`` does the same for ``_parse_iso``.
This keeps ``presence_probes`` import-acyclic with respect to ``app``.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import (
    CMD_PROTO,
    EVENT_RETAIN_DAYS_CRITICAL,
    EVENT_RETAIN_DAYS_DEBUG,
    EVENT_RETAIN_DAYS_ERROR,
    EVENT_RETAIN_DAYS_INFO,
    EVENT_RETAIN_DAYS_MAX,
    EVENT_RETAIN_DAYS_WARN,
    PRESENCE_PROBE_ACK_TIMEOUT_SEC,
    PRESENCE_PROBE_COOLDOWN_SECONDS,
    PRESENCE_PROBE_IDLE_SECONDS,
    SCHEDULED_CMD_STALE_PENDING_SEC,
    TOPIC_ROOT,
)
from db import db_lock, get_conn
from helpers import utc_now_iso

__all__ = (
    "_insert_presence_probe",
    "_mark_presence_probe_acked",
    "_find_stale_devices",
    "_send_presence_probe",
    "_events_retention_tick",
    "_presence_probe_tick",
    "_expire_presence_probes_waiting_ack",
    "_fail_stale_scheduled_commands",
)

logger = logging.getLogger(__name__)


def _insert_presence_probe(
    device_id: str,
    owner_admin: Optional[str],
    idle_seconds: int,
    outcome: str,
    detail: str,
) -> int:
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO presence_probes (device_id, owner_admin, probe_ts, idle_seconds, outcome, detail, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (device_id, owner_admin, now_iso, idle_seconds, outcome, detail, now_iso),
        )
        pid = int(cur.lastrowid or 0)
        conn.commit()
        conn.close()
    return pid


def _mark_presence_probe_acked(device_id: str) -> None:
    """Flip the most recent 'sent' probe for this device to 'acked'."""
    import app as _app

    flipped_id = 0
    owner = None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, owner_admin FROM presence_probes
            WHERE device_id = ? AND outcome = 'sent'
            ORDER BY id DESC LIMIT 1
            """,
            (device_id,),
        )
        row = cur.fetchone()
        if row:
            flipped_id = int(row["id"])
            owner = str(row["owner_admin"] or "") or None
            cur.execute(
                "UPDATE presence_probes SET outcome='acked', updated_at=? WHERE id=?",
                (utc_now_iso(), flipped_id),
            )
            conn.commit()
        conn.close()
    if flipped_id:
        _app.emit_event(
            level="info",
            category="presence",
            event_type="presence.probe.acked",
            summary=f"{device_id} came back",
            actor=f"device:{device_id}",
            owner_admin=owner,
            device_id=device_id,
            detail={"probe_id": flipped_id},
        )


def _find_stale_devices(
    idle_seconds: int,
    cooldown_seconds: int,
    limit: int = 100,
) -> list[tuple[str, Optional[str], int]]:
    """Return [(device_id, owner_admin, idle_seconds_actual), ...] for devices
    whose last message is older than idle_seconds, excluding devices we already
    probed within cooldown_seconds.
    """
    import app as _app

    now_ts = int(time.time())
    idle_cutoff_iso = datetime.fromtimestamp(now_ts - idle_seconds, tz=timezone.utc).isoformat()
    cooldown_cutoff_iso = datetime.fromtimestamp(now_ts - cooldown_seconds, tz=timezone.utc).isoformat()

    results: list[tuple[str, Optional[str], int]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.device_id, d.updated_at,
                   (SELECT o.owner_admin FROM device_ownership o WHERE o.device_id = d.device_id) AS owner_admin,
                   (SELECT MAX(p.probe_ts) FROM presence_probes p WHERE p.device_id = d.device_id) AS last_probe_ts
            FROM device_state d
            WHERE d.updated_at IS NOT NULL AND d.updated_at < ?
            ORDER BY d.updated_at ASC
            LIMIT ?
            """,
            (idle_cutoff_iso, limit),
        )
        rows = cur.fetchall()
        conn.close()
    for r in rows:
        last_probe = str(r["last_probe_ts"] or "")
        if last_probe and last_probe > cooldown_cutoff_iso:
            continue
        updated = _app._parse_iso(str(r["updated_at"] or ""))
        idle_actual = int(time.time() - (updated.timestamp() if updated else 0))
        results.append((str(r["device_id"]), (str(r["owner_admin"]) if r["owner_admin"] else None), idle_actual))
    return results


def _send_presence_probe(device_id: str, owner_admin: Optional[str], idle_seconds: int) -> None:
    """Publish a `ping` command and log the probe."""
    import app as _app

    try:
        _app.publish_command(
            topic=f"{TOPIC_ROOT}/{device_id}/cmd",
            cmd="ping",
            params={},
            target_id=device_id,
            proto=CMD_PROTO,
            cmd_key=_app.get_cmd_key_for_device(device_id),
        )
        _insert_presence_probe(device_id, owner_admin, idle_seconds, "sent", f"idle>{PRESENCE_PROBE_IDLE_SECONDS}s")
        _app.emit_event(
            level="warn",
            category="presence",
            event_type="presence.probe.sent",
            summary=f"{device_id} silent {idle_seconds}s → ping",
            actor="system",
            target=device_id,
            owner_admin=owner_admin,
            device_id=device_id,
            detail={"idle_seconds": idle_seconds},
        )
    except Exception as exc:
        logger.warning("presence probe publish failed dev=%s err=%s", device_id, exc)
        _insert_presence_probe(device_id, owner_admin, idle_seconds, "skipped", f"publish_err:{exc}")


def _events_retention_tick() -> None:
    """Delete old rows from the `events` table according to the level-based
    retention windows. Runs every EVENT_RETENTION_SCAN_SECONDS."""
    retention_map = {
        "debug": EVENT_RETAIN_DAYS_DEBUG,
        "info": EVENT_RETAIN_DAYS_INFO,
        "warn": EVENT_RETAIN_DAYS_WARN,
        "error": EVENT_RETAIN_DAYS_ERROR,
        "critical": EVENT_RETAIN_DAYS_CRITICAL,
    }
    now_ms = int(time.time() * 1000)
    try:
        total_deleted = 0
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            for level, days in retention_map.items():
                if days <= 0:
                    continue
                cutoff = now_ms - (days * 86400 * 1000)
                cur.execute("DELETE FROM events WHERE level = ? AND ts_epoch_ms < ?", (level, cutoff))
                total_deleted += cur.rowcount or 0
            if EVENT_RETAIN_DAYS_MAX > 0:
                hard_cut = now_ms - (EVENT_RETAIN_DAYS_MAX * 86400 * 1000)
                cur.execute("DELETE FROM events WHERE ts_epoch_ms < ?", (hard_cut,))
                total_deleted += cur.rowcount or 0
            conn.commit()
            conn.close()
        if total_deleted:
            logger.info("events retention: pruned %d rows", total_deleted)
    except Exception as exc:
        logger.warning("events retention failed: %s", exc)


def _presence_probe_tick() -> None:
    """One pass of the stale-device scanner. Called from scheduler_loop."""
    try:
        stale = _find_stale_devices(PRESENCE_PROBE_IDLE_SECONDS, PRESENCE_PROBE_COOLDOWN_SECONDS, limit=200)
    except Exception as exc:
        logger.warning("presence probe scan failed: %s", exc)
        return
    for device_id, owner_admin, idle_seconds in stale:
        _send_presence_probe(device_id, owner_admin, idle_seconds)


def _expire_presence_probes_waiting_ack() -> None:
    """Mark long-running ``sent`` probes as ``timeout`` so they do not appear stuck."""
    if PRESENCE_PROBE_ACK_TIMEOUT_SEC <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=PRESENCE_PROBE_ACK_TIMEOUT_SEC)
    cutoff_iso = cutoff.isoformat()
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE presence_probes
            SET outcome='timeout', updated_at=?, detail=COALESCE(detail, '') || ' | ack_timeout'
            WHERE outcome='sent' AND probe_ts < ?
            """,
            (now_iso, cutoff_iso),
        )
        n = cur.rowcount or 0
        conn.commit()
        conn.close()
    if n:
        logger.info("presence_probes: marked %d sent row(s) as timeout (>%ss)", n, PRESENCE_PROBE_ACK_TIMEOUT_SEC)


def _fail_stale_scheduled_commands(now_ts: int) -> None:
    """Pending jobs whose execute_at is far in the past should not hang forever."""
    if SCHEDULED_CMD_STALE_PENDING_SEC <= 0:
        return
    boundary = int(now_ts) - SCHEDULED_CMD_STALE_PENDING_SEC
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE scheduled_commands
            SET status='failed', executed_at=?
            WHERE status='pending' AND execute_at_ts < ?
            """,
            (now_iso, boundary),
        )
        n = cur.rowcount or 0
        conn.commit()
        conn.close()
    if n:
        logger.warning(
            "scheduled_commands: marked %d stale pending row(s) failed (execute_at >%ss ago)",
            n,
            SCHEDULED_CMD_STALE_PENDING_SEC,
        )
