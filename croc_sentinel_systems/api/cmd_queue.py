"""Command-queue ledger (Phase-36 modularization).

Persistent ledger of every published MQTT command so that:

* Offline devices can pick up unacked commands via the HTTP backup pull
  (see ``/device-http/*/commands/pending``). Firmware uses this only when
  MQTT has been disconnected past ``COMMAND_HTTP_FALLBACK_ARM_MS`` seconds —
  it does not compete with MQTT for live connections.
* The ACK flow can mark rows acked regardless of which channel delivered
  or which channel the ACK came back on.
* Sibling fan-out can be replayed to a device that came online after the
  fan-out happened (group offline replay).

The module owns five helpers and one piece of in-process state
(``_cmd_queue_replay_last`` + its lock) used to debounce per-device
replays. MQTT publishing itself stays in ``app.publish_command`` — we
only manage the persistent ledger here.

Late-binding
------------
``_maybe_replay_queue_on_reconnect`` re-publishes pending entries by
delegating to ``app.publish_command`` and reading ``app.TOPIC_ROOT``
at call time. The cyclic ``publish_command -> _cmd_queue_enqueue ->
... -> publish_command`` would otherwise wedge importation, so the
indirection is mandatory rather than stylistic.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import threading
import time
from typing import Any, Optional

from config import CMD_PROTO
from cmd_keys import get_cmd_key_for_device
from db import db_lock, db_read_lock, get_conn
from helpers import utc_now_iso

logger = logging.getLogger("crocapi.cmd_queue")


def _effective_cmd_key_for_delivery(device_id: str, stored_key: str, *, ctx: str) -> str:
    """Return the cmd_key that should sign a (re)delivered /cmd frame.

    Rows in ``cmd_queue`` snapshot the key at enqueue time.  After a
    boot-sync resync, reclaim, or manual credential rotation the live
    ``provisioned_credentials.cmd_key`` moves forward while pending
    rows still carry the old hex.  Replaying or HTTP-serving the stale
    value guarantees firmware ``verifyKey`` failures.

    Policy: always prefer :func:`get_cmd_key_for_device` at delivery
    time; log once per row when the ledger snapshot diverges so
    operators can correlate with rotation events.
    """
    did = str(device_id or "").strip()
    live = str(get_cmd_key_for_device(did) or "").strip().upper()
    snap = str(stored_key or "").strip().upper()
    if snap and live and snap != live:
        logger.warning(
            "cmd_queue %s: cmd_key drift for %s (ledger=%s…%s live=%s…%s) — using live key",
            ctx,
            did or "?",
            snap[:4],
            snap[-4:],
            live[:4],
            live[-4:],
        )
    if live:
        return live
    return snap


# ─────────────────────────────────────────────────────────────────────────
# Tunables
# TTL default is 24h: a device that's offline overnight still gets its
# commands on reconnect, but ancient commands don't pile up.
# ─────────────────────────────────────────────────────────────────────────
CMD_QUEUE_TTL_S = int(os.getenv("CROC_CMD_QUEUE_TTL_S", "86400"))

# Commands we never persist (would balloon the table without offline value):
#   presence probes — transient per-device keepalive only
#   debug / dev-only — no offline retry value
_CMD_QUEUE_SKIP_VERBS = {"presence_probe"}

# Gap past which a device is treated as "came back from offline" — a
# fresh heartbeat after this much silence triggers a replay of its
# unacked cmd_queue entries. Tuned to cover a typical Wi-Fi drop
# (30–60s) without firing on every ordinary heartbeat skew.
CMD_QUEUE_REPLAY_GAP_S = int(os.getenv("CROC_CMD_QUEUE_REPLAY_GAP_S", "60"))

# Per-device debounce so a noisy flap-up does not trigger replay on
# every status frame. ``device_id -> epoch_s`` of last replay.
_cmd_queue_replay_last: dict[str, float] = {}
_cmd_queue_replay_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────
# Inserts / updates
# ─────────────────────────────────────────────────────────────────────────

def _cmd_queue_enqueue(
    *,
    cmd_id: str,
    device_id: str,
    cmd: str,
    params: dict[str, Any],
    target_id: str,
    proto: int,
    cmd_key: str,
    delivered_via: str,
    delivered_at: Optional[str],
) -> None:
    """Insert a row into ``cmd_queue`` right after a publish.

    Best-effort: any DB error is logged and swallowed so a hiccup in the
    queue never blocks the MQTT publish that already succeeded.
    """
    if cmd in _CMD_QUEUE_SKIP_VERBS:
        return
    if not device_id:
        return
    now = utc_now_iso()
    try:
        expires_at = (
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=CMD_QUEUE_TTL_S)
        ).isoformat(timespec="seconds")
    except Exception:
        expires_at = None
    try:
        payload = json.dumps(params or {}, ensure_ascii=True)
    except Exception:
        payload = "{}"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT OR REPLACE INTO cmd_queue (
                    cmd_id, device_id, cmd, params_json, target_id, proto, cmd_key,
                    created_at, expires_at, delivered_via, delivered_at, acked_at, ack_ok, ack_detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    cmd_id, device_id, cmd, payload, target_id, int(proto or 0), cmd_key or "",
                    now, expires_at, delivered_via, delivered_at,
                ),
            )
            conn.commit()
        except Exception as exc:
            logger.warning("cmd_queue enqueue failed cmd=%s device=%s err=%s", cmd, device_id, exc)
        finally:
            conn.close()


def _cmd_queue_mark_acked(cmd_id: str, *, ok: bool, detail: str = "") -> bool:
    """Clear the pending row for ``cmd_id`` on ACK arrival (from ANY channel).

    Returns ``True`` if a row was actually updated. No-op and ``False`` if
    ``cmd_id`` wasn't in the queue (older/expired cmd, or from a sender
    that bypassed the queue — e.g. legacy code paths that publish raw).
    """
    if not cmd_id:
        return False
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "UPDATE cmd_queue SET acked_at = ?, ack_ok = ?, ack_detail = ? "
                "WHERE cmd_id = ? AND acked_at IS NULL",
                (now, 1 if ok else 0, str(detail or "")[:200], cmd_id),
            )
            updated = cur.rowcount
            conn.commit()
            return bool(updated)
        except Exception as exc:
            logger.warning("cmd_queue ack update failed cmd_id=%s err=%s", cmd_id, exc)
            return False
        finally:
            conn.close()


# ─────────────────────────────────────────────────────────────────────────
# Reads
# ─────────────────────────────────────────────────────────────────────────

def _cmd_queue_pending_for_device(device_id: str, limit: int = 32) -> list[dict[str, Any]]:
    """Un-acked, un-expired commands for ``device_id`` (oldest first).

    This is what the HTTP backup pull endpoint returns. Rows with
    ``expires_at < now`` are silently filtered — the cleanup pass
    handles their removal on a slower cadence.
    """
    if not device_id:
        return []
    now = utc_now_iso()
    out: list[dict[str, Any]] = []
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT cmd_id, device_id, cmd, params_json, target_id, proto, cmd_key,
                       created_at, delivered_via, delivered_at
                FROM cmd_queue
                WHERE device_id = ?
                  AND acked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (device_id, now, int(limit)),
            )
            for r in cur.fetchall():
                try:
                    params = json.loads(r["params_json"] or "{}")
                except Exception:
                    params = {}
                snap_key = r["cmd_key"] or ""
                out.append({
                    "cmd_id": r["cmd_id"],
                    "device_id": r["device_id"],
                    "cmd": r["cmd"],
                    "params": params,
                    "target_id": r["target_id"] or "",
                    "proto": int(r["proto"] or 0),
                    "cmd_key": _effective_cmd_key_for_delivery(
                        str(r["device_id"] or ""),
                        snap_key,
                        ctx=f"pending({r['cmd_id']})",
                    ),
                    "created_at": r["created_at"],
                    "delivered_via": r["delivered_via"] or "",
                    "delivered_at": r["delivered_at"] or "",
                })
        except Exception as exc:
            logger.warning("cmd_queue pending scan failed device=%s err=%s", device_id, exc)
        finally:
            conn.close()
    return out


def _cmd_queue_pending_counts(device_ids: list[str] | None = None) -> dict[str, int]:
    """Return ``{device_id: pending_count}`` for the supplied ids (or all
    devices with at least one unacked entry when ``device_ids`` is None).

    Used by the dashboard devices list to surface a "X pending" chip next
    to devices that have queued MQTT commands waiting for delivery/ack.
    The query is O(N) over the un-acked slice of ``cmd_queue``, which is
    small in steady state (most entries get acked within a few seconds).
    """
    now = utc_now_iso()
    out: dict[str, int] = {}
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        try:
            if device_ids:
                # SQLite has a default compiled-in 999-parameter cap; chunk so we
                # stay safely below it on large fleets.
                chunk = 500
                for i in range(0, len(device_ids), chunk):
                    batch = device_ids[i:i + chunk]
                    placeholders = ",".join(["?"] * len(batch))
                    cur.execute(
                        f"""
                        SELECT device_id, COUNT(*) AS n
                        FROM cmd_queue
                        WHERE acked_at IS NULL
                          AND (expires_at IS NULL OR expires_at > ?)
                          AND device_id IN ({placeholders})
                        GROUP BY device_id
                        """,
                        (now, *batch),
                    )
                    for r in cur.fetchall():
                        out[r["device_id"]] = int(r["n"])
            else:
                cur.execute(
                    """
                    SELECT device_id, COUNT(*) AS n
                    FROM cmd_queue
                    WHERE acked_at IS NULL
                      AND (expires_at IS NULL OR expires_at > ?)
                    GROUP BY device_id
                    """,
                    (now,),
                )
                for r in cur.fetchall():
                    out[r["device_id"]] = int(r["n"])
        except Exception as exc:
            logger.warning("cmd_queue pending counts failed: %s", exc)
        finally:
            conn.close()
    return out


# ─────────────────────────────────────────────────────────────────────────
# Replay on reconnect
# ─────────────────────────────────────────────────────────────────────────

def _maybe_replay_queue_on_reconnect(device_id: str, prev_updated_at: Optional[str]) -> None:
    """Called when a fresh heartbeat/status lands.

    If the device was silent for longer than ``CMD_QUEUE_REPLAY_GAP_S``,
    re-publish any unacked cmd_queue entries over MQTT so a sibling that
    was offline during fan-out actually receives the broadcast. The
    publish call is late-bound through ``app.py`` because
    ``publish_command`` lives there and itself calls back into this
    module to write the ledger row.
    """
    if not device_id or not prev_updated_at:
        return
    import app as _app  # late: avoid cycle at import time
    try:
        prev = _app._parse_iso(prev_updated_at)
    except Exception:
        return
    if not prev:
        return
    gap_s = (datetime.datetime.now(datetime.UTC) - prev).total_seconds()
    if gap_s < float(CMD_QUEUE_REPLAY_GAP_S):
        return
    now_epoch = time.time()
    with _cmd_queue_replay_lock:
        last = _cmd_queue_replay_last.get(device_id, 0.0)
        if now_epoch - last < 15.0:
            return
        _cmd_queue_replay_last[device_id] = now_epoch
    pending = _cmd_queue_pending_for_device(device_id, limit=16)
    if not pending:
        return
    logger.info(
        "cmd_queue replay: device=%s gap=%.1fs pending=%d",
        device_id, gap_s, len(pending),
    )
    topic_root = getattr(_app, "TOPIC_ROOT", "croc")
    for entry in pending:
        try:
            eff_key = _effective_cmd_key_for_delivery(
                device_id,
                str(entry.get("cmd_key") or ""),
                ctx=f"replay({entry.get('cmd_id')})",
            )
            _app.publish_command(
                topic=f"{topic_root}/{device_id}/cmd",
                cmd=str(entry["cmd"]),
                params=entry.get("params") or {},
                target_id=str(entry.get("target_id") or device_id),
                proto=int(entry.get("proto") or CMD_PROTO),
                cmd_key=eff_key,
                wait_publish=False,
                persist=False,
            )
        except Exception as exc:
            logger.warning(
                "cmd_queue replay publish failed device=%s cmd_id=%s err=%s",
                device_id, entry.get("cmd_id"), exc,
            )


# ─────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────

def _cmd_queue_cleanup_expired(max_rows: int = 500) -> int:
    """Periodic purge of expired + stale acked rows.

    Called from the ``scheduled_commands`` worker tick so we don't add
    another thread.
    """
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "DELETE FROM cmd_queue WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            cur.execute(
                "DELETE FROM cmd_queue WHERE acked_at IS NOT NULL AND created_at < ?",
                ((
                    datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=CMD_QUEUE_TTL_S)
                ).isoformat(timespec="seconds"),),
            )
            deleted = cur.rowcount
            conn.commit()
            return int(deleted or 0)
        except Exception as exc:
            logger.warning("cmd_queue cleanup failed: %s", exc)
            return 0
        finally:
            conn.close()


__all__ = [
    "CMD_QUEUE_TTL_S",
    "CMD_QUEUE_REPLAY_GAP_S",
    "_CMD_QUEUE_SKIP_VERBS",
    "_cmd_queue_replay_last",
    "_cmd_queue_replay_lock",
    "_cmd_queue_enqueue",
    "_cmd_queue_mark_acked",
    "_cmd_queue_pending_for_device",
    "_cmd_queue_pending_counts",
    "_maybe_replay_queue_on_reconnect",
    "_cmd_queue_cleanup_expired",
]
