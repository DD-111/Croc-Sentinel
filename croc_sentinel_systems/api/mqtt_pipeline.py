"""MQTT ingest pipeline (Phase-56 extraction from ``app.py``).

Owns every Paho callback (``on_connect`` / ``on_disconnect`` /
``on_message``), the JSON parsing + dispatch worker that drains the
ingest queue (``_mqtt_ingest_worker``), the business-logic dispatcher
(``_dispatch_mqtt_payload``) and the tiny lifecycle helpers
(``start_mqtt_loop`` / ``stop_mqtt_loop``).

Why state lives on ``app.py``
-----------------------------
The mutable MQTT state — ``mqtt_client``, ``mqtt_connected``, the
``mqtt_ingest_queue``, the worker thread + stop event, the dropped
counter, plus the last connect/disconnect timestamps and reason —
is read all over the codebase via ``import app as _app`` (e.g.
``cmd_publish.py``, ``cmd_keys.py``, ``routers/dashboard_read.py``,
``routers/diagnostics.py``). Module-level variables in Python are
read live off ``module.__dict__``; rebinding them on a different
module would silently fork the source of truth. So this module
keeps the **logic** here while every callback continues to mutate
the canonical attributes through ``_app.<name> = <value>``. That's
the same pattern the rest of the post-Phase-30 modularization uses.

Public API
----------
* :func:`parse_topic`              — ``"<TOPIC_ROOT>/<device>/<chan>"`` -> ``(device, chan)``.
* :func:`on_connect`               — Paho callback; subscribes to
  every device topic on rc=0 and updates the connect timestamp.
* :func:`on_disconnect`            — flips ``mqtt_connected`` False
  and records the reason.
* :func:`on_message`               — non-blocking enqueue into
  ``mqtt_ingest_queue``. Drops messages and bumps the counter when
  the queue is saturated; logs every 250th drop.
* :func:`_dispatch_mqtt_payload`   — runs on the worker thread.
  Handles bootstrap-register, ``parse_topic`` decoding, message +
  device-state writes, offline->online cmd-queue replay, the
  unified event firehose into ``emit_event``, alarm fan-out
  thread-spawn, OTA result thread-spawn, ack-key-mismatch
  reconcile, persistent ``cmd_queue`` ack settle, and the
  presence-probe ack stamp.
* :func:`_mqtt_ingest_worker`      — drain the queue, JSON parse,
  call the dispatcher; never lets exceptions escape.
* :func:`start_mqtt_loop`          — TLS + auth + connect + loop_start.
* :func:`stop_mqtt_loop`           — loop_stop + disconnect (best-effort).
"""

from __future__ import annotations

import json
import logging
import os
import queue as _stdqueue
import ssl
import threading
import time
from typing import Any, Optional

import paho.mqtt.client as mqtt

from alarm_db import _lookup_owner_admin
from alarm_fanout import _fan_out_alarm_safe
from auto_reconcile import (
    _enqueue_auto_reconcile,
    _is_ack_key_mismatch,
    _reissue_existing_assign_for_mac,
)
from cmd_queue import _cmd_queue_mark_acked, _maybe_replay_queue_on_reconnect
from config import (
    MQTT_CLIENT_CA,
    MQTT_HOST,
    MQTT_INGEST_QUEUE_MAX,
    MQTT_KEEPALIVE,
    MQTT_PASSWORD,
    MQTT_PORT,
    MQTT_TLS_VERIFY_HOSTNAME,
    MQTT_USE_TLS,
    MQTT_USERNAME,
    TOPIC_ACK,
    TOPIC_BOOTSTRAP_REGISTER,
    TOPIC_EVENT,
    TOPIC_HEARTBEAT,
    TOPIC_ROOT,
    TOPIC_STATUS,
)
from device_state import insert_message, upsert_device_state, upsert_pending_claim
from event_bus import emit_event
from helpers import utc_now_iso
from ota_rollout import _handle_ota_result_safe
from presence_probes import _mark_presence_probe_acked

import app as _app

__all__ = (
    "parse_topic",
    "on_connect",
    "on_disconnect",
    "on_message",
    "_dispatch_mqtt_payload",
    "_mqtt_ingest_worker",
    "start_mqtt_loop",
    "stop_mqtt_loop",
)

logger = logging.getLogger(__name__)


def parse_topic(topic: str) -> tuple[Optional[str], Optional[str]]:
    parts = topic.split("/")
    if len(parts) != 3:
        return None, None
    if parts[0] != TOPIC_ROOT:
        return None, None
    return parts[1], parts[2]


def on_connect(client: mqtt.Client, _userdata: Any, _flags: Any, rc: int, _properties: Any = None) -> None:
    _app.mqtt_connected = rc == 0
    if rc == 0:
        _app.mqtt_last_connect_at = utc_now_iso()
        _app.mqtt_last_disconnect_reason = ""
        logger.info("MQTT connected")
        client.subscribe(TOPIC_HEARTBEAT, qos=1)
        client.subscribe(TOPIC_STATUS, qos=1)
        client.subscribe(TOPIC_EVENT, qos=1)
        client.subscribe(TOPIC_ACK, qos=1)
        client.subscribe(TOPIC_BOOTSTRAP_REGISTER, qos=1)
    else:
        logger.error("MQTT connect failed rc=%s", rc)


def on_disconnect(_client: mqtt.Client, _userdata: Any, _disconnect_flags: Any, _reason_code: Any, _properties: Any = None) -> None:
    _app.mqtt_connected = False
    _app.mqtt_last_disconnect_at = utc_now_iso()
    _app.mqtt_last_disconnect_reason = str(_reason_code or "")
    logger.warning("MQTT disconnected reason=%s", _app.mqtt_last_disconnect_reason)


def _dispatch_mqtt_payload(topic: str, payload: dict[str, Any]) -> None:
    """All MQTT business logic: runs on the mqtt-ingest worker thread only."""
    if topic == TOPIC_BOOTSTRAP_REGISTER:
        upsert_pending_claim(payload)
        insert_message(topic, "bootstrap_register", str(payload.get("device_id", "")), payload)
        did_try = str(payload.get("device_id", ""))
        emit_event(
            level="info",
            category="provision",
            event_type="provision.bootstrap_register",
            summary=f"{did_try} bootstrap register",
            actor=f"device:{did_try}",
            device_id=did_try,
            detail={"serial": payload.get("serial"), "mac": payload.get("mac"), "qr_code": payload.get("qr_code")},
        )
        # Phase 89 self-heal: if this MAC is already provisioned (server has
        # an existing cmd_key) but the device is still publishing
        # bootstrap.register, the device's NVS got cleared (re-flash, NVS
        # commit failure, etc.). Re-publish the existing bootstrap.assign
        # with the device's *current* claim_nonce so the firmware accepts
        # it and writes the existing cmd_key to NVS — no operator action
        # needed. Cooldown is enforced inside the helper.
        try:
            _reissue_existing_assign_for_mac(
                str(payload.get("mac_nocolon", "")),
                str(payload.get("claim_nonce", "")),
            )
        except Exception:
            logger.debug("bootstrap.register self-heal failed", exc_info=True)
        return

    device_id, channel = parse_topic(topic)
    if not channel:
        return

    insert_message(topic, channel, device_id, payload)
    prev_updated_at: Optional[str] = None
    if device_id:
        prev_updated_at = upsert_device_state(device_id, channel, payload)

    # Offline->online replay: if the device was silent for longer than
    # CMD_QUEUE_REPLAY_GAP_S and we have unacked queue entries, push them
    # again over MQTT. Runs inline on the ingest worker because it is a
    # cheap SELECT + a few publishes; truly heavy cases are debounced.
    if device_id and channel in ("heartbeat", "status") and prev_updated_at:
        try:
            _maybe_replay_queue_on_reconnect(device_id, prev_updated_at)
        except Exception:
            logger.debug("cmd_queue replay failed for %s", device_id, exc_info=True)

    # Flow EVERY device channel into the unified event stream (at debug
    # level so subscribers can opt in). This gives the superadmin a true
    # firehose while staying out of the tenant admin's default view.
    if device_id and channel in ("heartbeat", "status", "ack", "event"):
        try:
            owner = _lookup_owner_admin(device_id) if "lookup_owner" not in payload else None
        except Exception:
            owner = None
        ev_level = "debug"
        ev_type = f"device.{channel}"
        ev_sum = f"{device_id} {channel}"
        if channel == "event":
            p_type = str(payload.get("type") or "")
            if p_type:
                ev_type = f"device.event.{p_type}"
                ev_sum = f"{device_id} event {p_type}"
                if p_type.startswith("alarm."):
                    ev_level = "warn"
        elif channel == "ack":
            if str(payload.get("type") or "") == "ota.result":
                ev_level = "warn" if not bool(payload.get("ok")) else "info"
                ev_type = "device.ota.result"
                ev_sum = f"{device_id} ota {'ok' if payload.get('ok') else 'FAIL'}"
        emit_event(
            level=ev_level,
            category="device",
            event_type=ev_type,
            summary=ev_sum,
            actor=f"device:{device_id}",
            owner_admin=owner,
            device_id=device_id,
            detail={"topic": topic, **{k: v for k, v in payload.items() if k in ("type", "ok", "detail", "campaign_id", "rssi", "vbat", "net_type", "fw", "throughput_rx_bps", "throughput_tx_bps")}},
        )

    if channel == "event" and device_id and str(payload.get("type") or "") == "alarm.trigger":
        # Dispatch fan-out to a worker thread so the MQTT ingest queue keeps draining.
        t = threading.Thread(
            target=_fan_out_alarm_safe,
            name=f"alarm-fanout-{device_id}",
            args=(device_id, payload),
            daemon=True,
        )
        t.start()

    if channel == "ack" and device_id and str(payload.get("type") or "") == "ota.result":
        t = threading.Thread(
            target=_handle_ota_result_safe,
            name=f"ota-result-{device_id}",
            args=(device_id, payload),
            daemon=True,
        )
        t.start()

    if channel == "ack" and device_id and _is_ack_key_mismatch(payload):
        _enqueue_auto_reconcile(device_id, "ack_key_mismatch")

    # Settle the persistent cmd_queue entry for this cmd_id regardless of
    # which channel actually delivered the command (MQTT primary vs HTTP
    # pull fallback). Missing cmd_id is fine — older payloads or raw
    # publishes never hit the queue.
    if channel == "ack" and device_id:
        cid = str(payload.get("cmd_id") or "").strip()
        if cid:
            ok = bool(payload.get("ok", True))
            detail = str(payload.get("detail") or payload.get("error") or "")
            try:
                _cmd_queue_mark_acked(cid, ok=ok, detail=detail)
            except Exception:
                logger.debug("cmd_queue ack settle failed dev=%s cid=%s", device_id, cid, exc_info=True)

    if channel in ("heartbeat", "status", "ack", "event") and device_id:
        try:
            _mark_presence_probe_acked(device_id)
        except Exception:
            logger.debug("presence probe ack update failed for %s", device_id, exc_info=True)


def _mqtt_ingest_worker() -> None:
    """Drain mqtt_ingest_queue: JSON parse + _dispatch_mqtt_payload (DB, emit_event, side threads)."""
    while True:
        try:
            item = _app.mqtt_ingest_queue.get(timeout=0.3)
        except _stdqueue.Empty:
            if _app.mqtt_worker_stop.is_set():
                break
            continue
        if not item:
            continue
        topic = str(item.get("topic") or "")
        raw = item.get("payload")
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                continue
        except Exception:
            continue
        try:
            _dispatch_mqtt_payload(topic, payload)
        except Exception as exc:
            logger.exception("mqtt ingest worker failed topic=%s: %s", topic, exc)


def on_message(_client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
    """Paho callback: enqueue only — never DB, JSON business logic, or emit_event here."""
    try:
        raw = msg.payload.decode("utf-8", errors="replace")
    except Exception:
        return
    try:
        _app.mqtt_ingest_queue.put_nowait({"topic": msg.topic, "payload": raw, "ts": time.time()})
    except _stdqueue.Full:
        _app.mqtt_ingest_dropped += 1
        if _app.mqtt_ingest_dropped == 1 or _app.mqtt_ingest_dropped % 250 == 0:
            logger.warning(
                "mqtt ingest queue full (max=%s); dropped=%s last_topic=%r",
                MQTT_INGEST_QUEUE_MAX,
                _app.mqtt_ingest_dropped,
                getattr(msg, "topic", ""),
            )


def start_mqtt_loop() -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if MQTT_USE_TLS:
        if not MQTT_CLIENT_CA or not os.path.isfile(MQTT_CLIENT_CA):
            logging.getLogger(__name__).error(
                "MQTT_USE_TLS=1 but CA file missing at MQTT_CLIENT_CA=%r "
                "(mount host certs/ca.crt into the api container; see docker-compose.yml).",
                MQTT_CLIENT_CA,
            )
        else:
            ctx = ssl.create_default_context(cafile=MQTT_CLIENT_CA)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if not MQTT_TLS_VERIFY_HOSTNAME:
                ctx.check_hostname = False
            client.tls_set_context(ctx)
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=60)
    client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
    client.loop_start()
    return client


def stop_mqtt_loop(client: mqtt.Client) -> None:
    try:
        client.loop_stop()
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
