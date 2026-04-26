"""Command-scheduler loop + lifecycle (Phase-54 extraction from ``app.py``).

The scheduler is a single daemon thread that polls SQLite once per
``SCHEDULER_POLL_SECONDS`` and performs every periodic
housekeeping job for the API: dispatching due ``scheduled_commands``
rows over MQTT, failing stale jobs, expiring stuck presence probes,
running auto-reconcile, pruning expired cmd-queue entries, deleting
old messages, kicking presence probes, retaining/dropping old
events, pruning password-reset tokens, and pruning stale pending
device claims.

Public API
----------
* :data:`scheduler_stop` — ``threading.Event``. Cleared at start,
  set by :func:`stop_scheduler` to wake the loop and let it exit.
* :data:`scheduler_thread` — module-level ``Thread`` reference,
  ``None`` while stopped.
* :func:`scheduler_loop`   — the actual thread body. Imported back
  into ``app.py`` for legacy callers (and the contract tests that
  search for it on the module).
* :func:`start_scheduler`  — clear the stop event, spawn the daemon
  thread, return it.
* :func:`stop_scheduler`   — signal stop and join (2s timeout).

Wiring
------
* Every periodic helper this loop calls (e.g.
  ``_fail_stale_scheduled_commands``, ``_presence_probe_tick``,
  ``publish_command``) is reached via ``import app as _app`` at call
  time. They live in disparate modules (``presence_probes``,
  ``cmd_queue``, ``auto_reconcile``, ``cmd_publish``, ``cmd_keys``,
  ``routers.auth_recovery``) and ``app.py`` already re-exports each
  of them, so going through ``_app`` keeps this module
  import-acyclic with the wider codebase — and means we always pick
  up the *current* binding (e.g. monkey-patched in tests).
* ``app.py`` re-exports ``scheduler_stop`` / ``scheduler_thread`` /
  ``scheduler_loop`` and replaces the inline thread-management with
  thin :func:`start_scheduler` / :func:`stop_scheduler` calls in the
  lifespan startup / shutdown hooks.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import tempfile
import urllib.request
import os
import gzip
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import (
    EVENT_RETENTION_SCAN_SECONDS,
    MESSAGE_RETENTION_DAYS,
    PRESENCE_PROBE_SCAN_SECONDS,
    SCHEDULER_POLL_SECONDS,
    TOPIC_ROOT,
    DB_BACKUP_ENABLED,
    DB_BACKUP_INTERVAL_SECONDS,
    DB_BACKUP_TIMEOUT_SECONDS,
    DB_BACKUP_PRESIGNED_URL_TEMPLATE,
)
from db import DB_PATH, db_lock, get_conn
from helpers import utc_now_iso

import app as _app

__all__ = (
    "scheduler_stop",
    "scheduler_thread",
    "scheduler_loop",
    "start_scheduler",
    "stop_scheduler",
)

logger = logging.getLogger(__name__)


scheduler_stop = threading.Event()
scheduler_thread: Optional[threading.Thread] = None


def _upload_db_backup_once() -> None:
    """Create a consistent SQLite snapshot and upload it via PUT to object storage.

    Transport contract:
      * destination URL comes from DB_BACKUP_PRESIGNED_URL_TEMPLATE
      * if template contains ``{ts}``, it is replaced with UTC timestamp
      * payload is gzip-compressed SQLite bytes
    """
    if not DB_BACKUP_PRESIGNED_URL_TEMPLATE:
        return
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    url = DB_BACKUP_PRESIGNED_URL_TEMPLATE.replace("{ts}", ts)
    tmp_path = ""
    try:
        with db_lock:
            src = get_conn()
            fd, tmp_path = tempfile.mkstemp(prefix="sentinel-db-backup-", suffix=".sqlite")
            os.close(fd)
            dst = sqlite3.connect(tmp_path, timeout=5.0)
            # Online-consistent snapshot even while the API is writing.
            src.backup(dst)
            dst.close()
            src.close()
        with open(tmp_path, "rb") as f:
            raw = f.read()
        if len(raw) < 16 or raw[:15] != b"SQLite format 3":
            raise RuntimeError("snapshot is not a valid sqlite file")
        payload = gzip.compress(raw, compresslevel=6)
        req = urllib.request.Request(
            url=url,
            data=payload,
            method="PUT",
            headers={
                "Content-Type": "application/gzip",
                "X-Sentinel-Backup-Ts": ts,
                "X-Sentinel-Backup-Source": os.path.basename(DB_PATH),
            },
        )
        with urllib.request.urlopen(req, timeout=float(DB_BACKUP_TIMEOUT_SECONDS)) as resp:
            code = int(getattr(resp, "status", 0) or 0)
            if code < 200 or code >= 300:
                raise RuntimeError(f"backup upload failed: HTTP {code}")
        logger.info(
            "db backup uploaded ts=%s bytes_raw=%d bytes_gzip=%d",
            ts,
            len(raw),
            len(payload),
        )
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _db_backup_tick(now: float, next_backup_at: float) -> float:
    """Periodic wrapper that keeps scheduler_loop readable."""
    if not DB_BACKUP_ENABLED:
        return now + 3600
    if now < next_backup_at:
        return next_backup_at
    try:
        _upload_db_backup_once()
    except Exception as exc:
        logger.warning("db backup tick failed: %s", exc)
    return now + max(60, DB_BACKUP_INTERVAL_SECONDS)


_UNBIND_RESET_PENDING_TIMEOUT_DAYS = 7


def _unbind_reset_compensation_tick(limit: int = 10) -> None:
    """Retry device reset for server-unbound jobs waiting for device ACK.

    Production hardening (Phase 98):
      * Jobs older than ``_UNBIND_RESET_PENDING_TIMEOUT_DAYS`` collapse to
        ``completed`` with a ``timeout`` reason — server-side is already
        unbound, so leaving the job pending forever bloats the table and
        leaves UI badges stuck.
      * Legacy rows without ``snapshot_cmd_key`` cannot signal the device
        any more (``provisioned_credentials`` was already deleted by the
        unbind transaction), so they are also collapsed to ``completed``
        with reason ``no_snapshot``. The single ``_try_mqtt_unclaim_reset``
        fallback would always return ``(False, False)``.
      * Compensation publish runs with ``wait_for_ack=False``; the
        regular ``cmd_ack`` MQTT pipeline still flips ``command_acked``
        when the device finally checks in. Avoids tying up the scheduler
        thread waiting for offline devices.
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT request_id, device_id, created_at,
                   IFNULL(detail_json,'{}') AS detail_json
            FROM device_unbind_jobs
            WHERE state = 'device_reset_pending'
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        )
        rows = cur.fetchall()
        conn.close()
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=_UNBIND_RESET_PENDING_TIMEOUT_DAYS)
    for row in rows:
        req_id = str(row["request_id"])
        did = str(row["device_id"])
        raw_detail = str(row["detail_json"] or "{}")
        try:
            detail = json.loads(raw_detail) if raw_detail else {}
        except Exception:
            detail = {}
        created_raw = str(row["created_at"] or "").strip()
        created_dt = None
        if created_raw:
            try:
                created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
            except Exception:
                created_dt = None
        snapshot_key = str(detail.get("snapshot_cmd_key") or "").strip()
        snapshot_seen = str(detail.get("snapshot_last_seen") or "").strip()
        attempts = int(detail.get("reset_retry_attempts", 0) or 0) + 1

        # Hard stop for re-claimed devices: once a device is ACTIVE again and
        # has a live provisioned_credentials row, any historical unbind-reset
        # compensation becomes stale and must not keep publishing unclaim_reset.
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT dl.lifecycle_state AS lifecycle_state,
                       EXISTS (
                         SELECT 1 FROM provisioned_credentials pc
                         WHERE UPPER(pc.device_id) = UPPER(?)
                       ) AS has_prov
                FROM device_lifecycle dl
                WHERE UPPER(dl.device_id) = UPPER(?)
                LIMIT 1
                """,
                (did, did),
            )
            st_row = cur.fetchone()
            conn.close()
        lifecycle_state = str(st_row["lifecycle_state"] or "").upper() if st_row else ""
        has_prov = bool(int(st_row["has_prov"] or 0)) if st_row else False
        if lifecycle_state == "ACTIVE" and has_prov:
            detail["reset_retry_attempts"] = attempts
            detail["last_reset_retry_at"] = utc_now_iso()
            detail["completion_reason"] = "reclaimed"
            detail["completion_note"] = (
                "device is ACTIVE with provisioned credentials; "
                "stale unbind compensation cancelled"
            )
            _finalize_unbind_job(req_id, "completed", detail)
            logger.info(
                "unbind compensation cancelled req=%s dev=%s (already reclaimed)",
                req_id, did,
            )
            continue

        if created_dt is not None and created_dt < cutoff:
            detail["reset_retry_attempts"] = attempts
            detail["last_reset_retry_at"] = utc_now_iso()
            detail["completion_reason"] = "timeout"
            detail["completion_note"] = (
                f"server-unbound; device-side reset not acknowledged within "
                f"{_UNBIND_RESET_PENDING_TIMEOUT_DAYS} days"
            )
            _finalize_unbind_job(req_id, "completed", detail)
            logger.warning(
                "unbind job timed out req=%s dev=%s after %sd",
                req_id, did, _UNBIND_RESET_PENDING_TIMEOUT_DAYS,
            )
            continue

        if not snapshot_key:
            detail["reset_retry_attempts"] = attempts
            detail["last_reset_retry_at"] = utc_now_iso()
            detail["completion_reason"] = "no_snapshot"
            detail["completion_note"] = (
                "legacy job without snapshot_cmd_key; provisioned_credentials "
                "already deleted, device-side reset cannot be signed"
            )
            _finalize_unbind_job(req_id, "completed", detail)
            logger.warning(
                "unbind job collapsed (no snapshot) req=%s dev=%s",
                req_id, did,
            )
            continue

        sent = False
        acked = False
        try:
            sent, acked = _app._try_mqtt_unclaim_reset_with_snapshot(
                did,
                snapshot_key,
                last_seen=snapshot_seen,
                wait_for_ack=False,
            )
        except Exception as exc:
            logger.warning(
                "unbind compensation dispatch failed req=%s dev=%s err=%s",
                req_id, did, exc,
            )
        detail["reset_retry_attempts"] = attempts
        detail["last_reset_retry_at"] = utc_now_iso()
        detail["last_reset_retry_sent"] = bool(sent)
        detail["last_reset_retry_acked"] = bool(acked)
        new_state = "completed" if acked else "device_reset_pending"
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE device_unbind_jobs
                SET state = ?,
                    command_sent = CASE WHEN ? THEN 1 ELSE command_sent END,
                    command_acked = CASE WHEN ? THEN 1 ELSE command_acked END,
                    detail_json = ?,
                    updated_at = ?
                WHERE request_id = ?
                """,
                (
                    new_state,
                    1 if sent else 0,
                    1 if acked else 0,
                    json.dumps(detail, ensure_ascii=True),
                    utc_now_iso(),
                    req_id,
                ),
            )
            conn.commit()
            conn.close()


def _finalize_unbind_job(req_id: str, new_state: str, detail: dict) -> None:
    """Idempotent terminal-state update for ``device_unbind_jobs``."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE device_unbind_jobs
            SET state = ?, detail_json = ?, updated_at = ?
            WHERE request_id = ?
            """,
            (
                new_state,
                json.dumps(detail, ensure_ascii=True),
                utc_now_iso(),
                req_id,
            ),
        )
        conn.commit()
        conn.close()


def scheduler_loop() -> None:
    next_cleanup_at = time.time() + 60
    next_probe_at = time.time() + 30  # kick probe worker ~30s after boot
    next_events_retention_at = time.time() + 300  # first retention pass ~5 min after boot
    next_pwd_prune_at = time.time() + 900
    next_pending_claim_prune_at = time.time() + 120
    next_db_backup_at = time.time() + 90
    next_unbind_reset_retry_at = time.time() + 30
    while not scheduler_stop.is_set():
        now_ts = int(time.time())
        jobs: list[sqlite3.Row] = []
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, device_id, cmd, params_json, target_id, proto
                FROM scheduled_commands
                WHERE status = 'pending' AND execute_at_ts <= ?
                ORDER BY id ASC
                LIMIT 50
                """,
                (now_ts,),
            )
            jobs = cur.fetchall()
            conn.close()

        for job in jobs:
            jid = int(job["id"])
            try:
                topic = f"{TOPIC_ROOT}/{job['device_id']}/cmd"
                _app.publish_command(
                    topic=topic,
                    cmd=str(job["cmd"]),
                    params=json.loads(str(job["params_json"])),
                    target_id=str(job["target_id"]),
                    proto=int(job["proto"]),
                    cmd_key=_app.get_cmd_key_for_device(str(job["device_id"])),
                )
                with db_lock:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scheduled_commands SET status='done', executed_at=? WHERE id=?",
                        (utc_now_iso(), jid),
                    )
                    conn.commit()
                    conn.close()
            except Exception as exc:
                logger.exception("scheduled command failed id=%s err=%s", jid, exc)
                with db_lock:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scheduled_commands SET status='failed', executed_at=? WHERE id=?",
                        (utc_now_iso(), jid),
                    )
                    conn.commit()
                    conn.close()

        try:
            _app._fail_stale_scheduled_commands(now_ts)
        except Exception as exc:
            logger.warning("stale scheduled_commands cleanup failed: %s", exc)
        try:
            _app._expire_presence_probes_waiting_ack()
        except Exception as exc:
            logger.warning("presence probe ack expiry failed: %s", exc)
        try:
            _app._auto_reconcile_tick()
        except Exception as exc:
            logger.warning("auto reconcile tick failed: %s", exc)
        try:
            _app._cmd_queue_cleanup_expired()
        except Exception as exc:
            logger.warning("cmd_queue cleanup tick failed: %s", exc)

        now = time.time()
        if now >= next_cleanup_at:
            cutoff = datetime.fromtimestamp(now - (MESSAGE_RETENTION_DAYS * 86400), tz=timezone.utc).isoformat()
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("DELETE FROM messages WHERE ts_received < ?", (cutoff,))
                cur.execute(
                    """
                    DELETE FROM scheduled_commands
                    WHERE status IN ('done','failed') AND executed_at IS NOT NULL AND executed_at < ?
                    """,
                    (cutoff,),
                )
                conn.commit()
                conn.close()
            next_cleanup_at = now + 3600

        if now >= next_probe_at:
            try:
                _app._presence_probe_tick()
            except Exception as exc:
                logger.warning("presence probe tick failed: %s", exc)
            next_probe_at = now + max(30, PRESENCE_PROBE_SCAN_SECONDS)

        if now >= next_events_retention_at:
            try:
                _app._events_retention_tick()
            except Exception as exc:
                logger.warning("events retention tick failed: %s", exc)
            next_events_retention_at = now + max(300, EVENT_RETENTION_SCAN_SECONDS)

        if now >= next_pwd_prune_at:
            try:
                _app._prune_password_reset_tokens()
            except Exception as exc:
                logger.warning("password reset token prune failed: %s", exc)
            next_pwd_prune_at = now + 21600  # every 6h

        if now >= next_pending_claim_prune_at:
            try:
                _app._prune_stale_pending_claims()
            except Exception as exc:
                logger.warning("pending_claim prune failed: %s", exc)
            next_pending_claim_prune_at = now + 900

        if now >= next_unbind_reset_retry_at:
            try:
                _unbind_reset_compensation_tick(limit=10)
            except Exception as exc:
                logger.warning("unbind reset compensation tick failed: %s", exc)
            next_unbind_reset_retry_at = now + 30

        next_db_backup_at = _db_backup_tick(now, next_db_backup_at)

        scheduler_stop.wait(SCHEDULER_POLL_SECONDS)


def start_scheduler() -> threading.Thread:
    """Spawn the scheduler thread and return it."""
    global scheduler_thread
    scheduler_stop.clear()
    scheduler_thread = threading.Thread(
        target=scheduler_loop, name="cmd-scheduler", daemon=True
    )
    scheduler_thread.start()
    return scheduler_thread


def stop_scheduler() -> None:
    """Signal stop and join the scheduler thread (2s timeout)."""
    global scheduler_thread
    scheduler_stop.set()
    if scheduler_thread is not None:
        scheduler_thread.join(timeout=2.0)
        scheduler_thread = None
