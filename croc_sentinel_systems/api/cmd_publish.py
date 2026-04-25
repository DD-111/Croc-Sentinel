"""Command-publish primitives (Phase-48 extraction from ``app.py``).

This module owns the small set of helpers that turn an in-process
"please run X on device Y" intent into a real MQTT ``/cmd`` frame
or a row in ``scheduled_commands``:

* :data:`MQTT_PUBLISH_WAIT_MS` / :data:`PUBLISH_DEDUPE_TTL_S` — env-tuned
  caps for how long to wait for paho to drain after publish, and how
  long an idempotency entry stays "hot".
* :data:`_publish_dedupe_cache` / :data:`_publish_dedupe_lock` — the
  in-memory ``dedupe_key -> (cmd_id, expire_epoch_s)`` cache used to
  swallow accidental double-clicks on OTA / reboot / siren commands.
* :func:`_publish_dedupe_get` / :func:`_publish_dedupe_set` — TTL-aware
  read/write helpers for that cache. ``_get`` opportunistically prunes
  expired entries when the cache grows past 2048 entries so a flood
  of one-shot keys can't blow out memory.
* :func:`publish_command` — the single non-bootstrap MQTT publisher
  used by every dashboard handler, fan-out worker, scheduler tick,
  alarm pipeline, OTA rollout step, presence probe, and remote-siren
  call. Generates a fresh ``cmd_id``, refuses to block if the broker
  is down (``503`` instead of stalling the HTTP caller), waits up to
  ``MQTT_PUBLISH_WAIT_MS`` for QoS 1 to start delivery, optionally
  caches the ``cmd_id`` under ``dedupe_key``, and writes a row into
  the cmd-queue ledger so disconnect→reconnect can replay it.
* :func:`enqueue_scheduled_command` — the SQLite-only counterpart that
  records a deferred command into ``scheduled_commands`` (the
  ``scheduler_loop`` worker drains it and calls :func:`publish_command`
  when ``execute_at_ts`` arrives).

Wiring
------
* ``mqtt_client`` and ``mqtt_connected`` are *mutable globals* owned
  by ``app.py`` (the MQTT worker reassigns them when the connection
  flips). Both are read at call time via ``import app as _app`` so
  every publish sees the live state, never a stale snapshot.
* ``_cmd_queue_enqueue`` comes straight from :mod:`cmd_queue`; that
  module already late-binds ``_app.publish_command`` for its replay
  path, so the dependency is acyclic at import time even though both
  call into each other at runtime.
* No FastAPI router lives here — handlers reach this through
  ``app.publish_command`` (re-exported from :mod:`app`), preserving
  the existing ``_app.publish_command(...)`` shim pattern in every
  router.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Optional

from fastapi import HTTPException

import app as _app
from cmd_queue import _cmd_queue_enqueue
from helpers import utc_now_iso

__all__ = (
    "MQTT_PUBLISH_WAIT_MS",
    "PUBLISH_DEDUPE_TTL_S",
    "_publish_dedupe_cache",
    "_publish_dedupe_lock",
    "_publish_dedupe_get",
    "_publish_dedupe_set",
    "publish_command",
    "enqueue_scheduled_command",
)

logger = logging.getLogger(__name__)


MQTT_PUBLISH_WAIT_MS = max(0, min(5000, int(os.getenv("MQTT_PUBLISH_WAIT_MS", "800"))))
# TTL (seconds) for the idempotency cache. Must be long enough to eat a double-click
# or a rushed retry (UI, proxy, accidental re-post), short enough to not hide a
# genuinely re-issued operator action minutes later.
PUBLISH_DEDUPE_TTL_S = max(5, min(120, int(os.getenv("PUBLISH_DEDUPE_TTL_S", "30"))))

# In-memory idempotency cache: { dedupe_key -> (cmd_id, expire_epoch_s) }.
# Process-local only (ok: multi-worker deployments should use sticky sessions
# for the admin dashboard; background fan-out has its own wall-clock cap).
_publish_dedupe_cache: dict[str, tuple[str, float]] = {}
_publish_dedupe_lock = threading.Lock()


def _publish_dedupe_get(key: str) -> Optional[str]:
    if not key:
        return None
    now = time.time()
    with _publish_dedupe_lock:
        # Opportunistic prune so the cache can't grow unbounded under a flood.
        if len(_publish_dedupe_cache) > 2048:
            expired = [k for k, (_cid, exp) in _publish_dedupe_cache.items() if exp <= now]
            for k in expired:
                _publish_dedupe_cache.pop(k, None)
        entry = _publish_dedupe_cache.get(key)
        if not entry:
            return None
        cid, exp = entry
        if exp <= now:
            _publish_dedupe_cache.pop(key, None)
            return None
        return cid


def _publish_dedupe_set(key: str, cmd_id: str, ttl_s: float) -> None:
    if not key or not cmd_id:
        return
    with _publish_dedupe_lock:
        _publish_dedupe_cache[key] = (cmd_id, time.time() + max(1.0, ttl_s))


def publish_command(
    topic: str,
    cmd: str,
    params: dict[str, Any],
    target_id: str,
    proto: int,
    cmd_key: str,
    *,
    wait_publish: bool = True,
    dedupe_key: Optional[str] = None,
    dedupe_ttl_s: Optional[float] = None,
    persist: bool = True,
) -> str:
    """Publish a /cmd frame. Returns generated ``cmd_id`` (so callers can wait on ACK by id).

    Does **not** block for retries. If the broker is disconnected, raises 503 immediately
    instead of stalling the caller (fan-out and HTTP handlers must stay responsive).
    When ``wait_publish=True`` (default), briefly waits for paho to drain (``MQTT_PUBLISH_WAIT_MS``)
    so QoS 1 can start delivery; callers that do fan-out in a worker pool can pass False.

    ``dedupe_key`` makes the publish idempotent over a short TTL: if the same key is
    re-used within the TTL, the previously generated ``cmd_id`` is returned and
    **no new MQTT message is published** (e.g. double-clicks on OTA/reboot).
    ``unclaim_reset`` is sent **without** dedupe so a repeated unlink can publish
    a fresh frame; firmware handles it idempotently.
    """
    if dedupe_key:
        cached = _publish_dedupe_get(dedupe_key)
        if cached:
            logger.info("publish_command dedupe hit: %s -> %s", dedupe_key, cached)
            return cached
    mqtt_client = _app.mqtt_client
    if mqtt_client is None:
        raise HTTPException(status_code=503, detail="mqtt client not ready")
    if not _app.mqtt_connected:
        raise HTTPException(status_code=503, detail="mqtt broker disconnected")
    cmd_id = str(uuid.uuid4())
    payload = {
        "proto": proto,
        "key": cmd_key,
        "target_id": target_id,
        "cmd": cmd,
        "params": params,
        "cmd_id": cmd_id,
    }
    body = json.dumps(payload, ensure_ascii=True)
    try:
        info = mqtt_client.publish(topic, body, qos=1)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"mqtt publish error: {exc}")
    if getattr(info, "rc", 0) not in (0, None):
        raise HTTPException(status_code=502, detail=f"mqtt publish rc={info.rc}")
    publish_delivered_at: Optional[str] = None
    if wait_publish and MQTT_PUBLISH_WAIT_MS > 0:
        try:
            info.wait_for_publish(timeout=max(0.05, MQTT_PUBLISH_WAIT_MS / 1000.0))
            publish_delivered_at = utc_now_iso()
        except Exception:
            pass
    if dedupe_key:
        _publish_dedupe_set(dedupe_key, cmd_id, float(dedupe_ttl_s or PUBLISH_DEDUPE_TTL_S))
    # Ledger-only (does not gate success). target_id is the device the
    # cmd_key binds to, which equals device_id for single-target commands;
    # topic parsing keeps it honest for future indirect paths.
    if persist:
        dev_id_from_topic = ""
        try:
            # Topic shape: <TOPIC_ROOT>/<device_id>/cmd → device_id is the
            # second-to-last segment. Cheap and robust against topic churn.
            parts = topic.split("/")
            if len(parts) >= 2 and parts[-1] == "cmd":
                dev_id_from_topic = parts[-2]
        except Exception:
            dev_id_from_topic = ""
        _cmd_queue_enqueue(
            cmd_id=cmd_id,
            device_id=dev_id_from_topic or target_id,
            cmd=cmd,
            params=params or {},
            target_id=target_id,
            proto=proto,
            cmd_key=cmd_key or "",
            delivered_via="mqtt",
            delivered_at=publish_delivered_at,
        )
    return cmd_id


def enqueue_scheduled_command(
    device_id: str,
    cmd: str,
    params: dict[str, Any],
    target_id: str,
    proto: int,
    execute_at_ts: int,
) -> int:
    # Local SQLite import to avoid a circular dependency on app.py at module load.
    from db import db_lock, get_conn

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scheduled_commands (
                device_id, cmd, params_json, target_id, proto, execute_at_ts, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                device_id,
                cmd,
                json.dumps(params, ensure_ascii=True),
                target_id,
                proto,
                execute_at_ts,
                utc_now_iso(),
            ),
        )
        job_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    return job_id
