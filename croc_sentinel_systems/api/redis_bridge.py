"""Redis Pub/Sub event-bus bridge (Phase-52 extraction from
``app.py``).

This module owns the optional Redis Pub/Sub bridge that lets a
multi-process / multi-instance deployment share the in-memory event
bus. When ``REDIS_URL`` is unset the bridge stays dormant and the
event bus is single-process only (still works fine, just no fan-out
across uvicorn workers).

Public API
----------
* :data:`BUS_INSTANCE_ID` — random uuid generated once per process.
  Stamped into every outgoing event under ``_bus_origin`` so the
  listener loop can drop messages this same process just published.
* :data:`REDIS_URL` / :data:`EVENT_BUS_REDIS_CHANNEL` — env-derived
  configuration (``REDIS_URL`` empty by default; channel defaults
  to ``"sentinel:event_bus"``).
* :func:`_redis_event_forward` — mirror an event onto the Pub/Sub
  channel; no-op when ``_redis_sync_client`` is None (i.e. no
  REDIS_URL configured or initial connect failed). Called from
  ``app.emit_event`` after the local fan-out completes.
* :func:`_redis_listener_main` — the listener thread body. Calls
  ``event_bus.publish_from_peer(data)`` (resolved off ``app`` at call
  time) for every incoming message that wasn't published by us.
* :func:`_start_event_redis_bridge` — connect, ping, and start the
  listener thread. Logs a friendly message when REDIS_URL is unset
  or the redis package is missing instead of crashing the API.
* :func:`_stop_event_redis_bridge` — set the stop event, join the
  listener thread (4s timeout), close the sync client, and clear
  module-level state. Idempotent.

Wiring
------
* `event_bus` is reached via ``import app as _app`` at call time —
  ``app.py`` defines it after the heavy schema/router import block,
  but the listener thread starts much later (lifespan startup), so
  by the time ``publish_from_peer`` actually fires the symbol is
  bound.
* No FastAPI router lives here; consumed via the ``app.py``
  re-export (so the existing in-module call sites
  ``_redis_event_forward(ev)`` in ``emit_event`` and
  ``_start_event_redis_bridge()`` / ``_stop_event_redis_bridge()``
  in the lifespan hook keep working unchanged) and the
  ``audit.py`` doc-comment reference.
* Module-level state (``_redis_sync_client``,
  ``_redis_listener_thread``, ``_redis_bridge_stop``) lives here, so
  ``_start`` / ``_stop`` mutate the bridge's own globals — never
  ``app.py``'s — and ``_redis_event_forward`` reads them off the
  same module.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from typing import Any, Optional

import app as _app

__all__ = (
    "BUS_INSTANCE_ID",
    "REDIS_URL",
    "EVENT_BUS_REDIS_CHANNEL",
    "_redis_sync_client",
    "_redis_listener_thread",
    "_redis_bridge_stop",
    "_redis_event_forward",
    "_redis_listener_main",
    "_start_event_redis_bridge",
    "_stop_event_redis_bridge",
)

logger = logging.getLogger(__name__)


BUS_INSTANCE_ID = str(uuid.uuid4())
REDIS_URL = (os.getenv("REDIS_URL") or "").strip()
EVENT_BUS_REDIS_CHANNEL = (
    (os.getenv("EVENT_BUS_REDIS_CHANNEL") or "sentinel:event_bus").strip()
    or "sentinel:event_bus"
)

_redis_sync_client: Optional[Any] = None
_redis_bridge_stop = threading.Event()
_redis_listener_thread: Optional[threading.Thread] = None


def _redis_event_forward(ev: dict[str, Any]) -> None:
    if _redis_sync_client is None:
        return
    try:
        out = dict(ev)
        out["_bus_origin"] = BUS_INSTANCE_ID
        _redis_sync_client.publish(EVENT_BUS_REDIS_CHANNEL, json.dumps(out, default=str))
    except Exception as exc:
        logger.warning("redis event forward failed: %s", exc)


def _redis_listener_main() -> None:
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("redis package not installed; pip install redis")
        return
    try:
        r2 = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r2.pubsub()
        pubsub.subscribe(EVENT_BUS_REDIS_CHANNEL)
        while not _redis_bridge_stop.is_set():
            msg = pubsub.get_message(timeout=1.0)
            if not msg or msg.get("type") != "message":
                continue
            raw = msg.get("data")
            if not raw or not isinstance(raw, str):
                continue
            try:
                data = json.loads(raw)
            except Exception:
                logger.warning("redis event bus bad json")
                continue
            origin = str(data.pop("_bus_origin", "") or "")
            if origin == BUS_INSTANCE_ID:
                continue
            try:
                _app.event_bus.publish_from_peer(data)
            except Exception:
                logger.exception("event_bus.publish_from_peer failed")
        try:
            pubsub.close()
        except Exception:
            pass
        try:
            r2.close()
        except Exception:
            pass
    except Exception:
        logger.exception("redis event bus listener exited")


def _start_event_redis_bridge() -> None:
    global _redis_sync_client, _redis_listener_thread
    if not REDIS_URL:
        logger.info("REDIS_URL unset — event bus is single-process memory only")
        return
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("REDIS_URL set but redis package missing; install redis or unset REDIS_URL")
        return
    try:
        _redis_sync_client = redis_lib.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
            health_check_interval=30,
        )
        _redis_sync_client.ping()
    except Exception as exc:
        logger.error("redis connect failed (event bus): %s", exc)
        _redis_sync_client = None
        return
    _redis_bridge_stop.clear()
    _redis_listener_thread = threading.Thread(
        target=_redis_listener_main, name="redis-event-bus", daemon=True
    )
    _redis_listener_thread.start()
    logger.info(
        "event bus redis bridge ok channel=%s instance=%s",
        EVENT_BUS_REDIS_CHANNEL,
        BUS_INSTANCE_ID[:8],
    )


def _stop_event_redis_bridge() -> None:
    global _redis_sync_client, _redis_listener_thread
    _redis_bridge_stop.set()
    if _redis_listener_thread is not None:
        _redis_listener_thread.join(timeout=4.0)
        _redis_listener_thread = None
    if _redis_sync_client is not None:
        try:
            _redis_sync_client.close()
        except Exception:
            pass
        _redis_sync_client = None
