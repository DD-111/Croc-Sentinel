"""Alarm fan-out orchestrator (Phase-42 extraction from ``app.py``).

This module owns the alarm trigger pipeline that runs when an
``alarm.trigger`` MQTT event arrives:

  1. dedup check (auto_reconcile)
  2. resolve owner_admin + notification group + zone
  3. apply trigger_policy toggles (silent / loud / panic)
  4. fan out a per-target ``siren_on`` / ``siren_off`` /
     ``alarm_signal`` MQTT command to same-tenant siblings, with
     bounded concurrency, wall-clock cap, and a single retry pass
  5. queue an email to the tenant's alert recipients (if any)
  6. write the alarm row + audit log

The implementation is mostly side effects (MQTT publish, email queue,
event bus, audit log) so it depends on a number of symbols defined
*later* in ``app.py`` (``publish_command``, ``get_cmd_keys_for_devices``,
``emit_event``) and on three small lookups that still live in
``app.py`` (``_device_notify_labels``, ``_trigger_policy_for``,
``_notify_subject_prefix``). Those are accessed via ``import app as
_app`` at call time so this module can import without triggering the
cyclic import path.

Public API
----------
* :func:`_fan_out_alarm` — the orchestrator, called from a worker
  thread spawned by ``_dispatch_mqtt_payload``.
* :func:`_fan_out_alarm_safe` — exception-swallowing wrapper, used as
  the ``threading.Thread`` target.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from alarm_db import (
    _insert_alarm,
    _lookup_owner_admin,
    _recipients_for_admin,
    _tenant_siblings,
    _update_alarm,
)
from audit import audit_event
from auto_reconcile import _alarm_event_is_duplicate
from config import (
    ALARM_EVENT_DEDUP_WINDOW_SEC,
    ALARM_FANOUT_DURATION_MS,
    ALARM_FANOUT_MAX_TARGETS,
    CMD_AUTH_KEY,
    CMD_PROTO,
    DEFAULT_PANIC_FANOUT_MS,
    FANOUT_WALL_CLOCK_MAX_S,
    FANOUT_WORKER_POOL_SIZE,
    TOPIC_ROOT,
)
from helpers import utc_now_iso
from notifier import notifier, render_alarm_email

__all__ = (
    "_fan_out_alarm",
    "_fan_out_alarm_safe",
)

logger = logging.getLogger(__name__)


def _fan_out_alarm(device_id: str, payload: dict[str, Any]) -> None:
    """Called from the MQTT thread when an `alarm.trigger` event arrives.

    Steps:
      1. Resolve ``owner_admin`` and this device's ``notification_group`` / zone (sibling scope).
      2. Apply policy: remote silent vs loud vs panic use different linkage toggles.
      3. Build target list: **siblings only** for ``remote_loud_button``,
         ``remote_silent_button`` and ``remote_pause_button`` (never MQTT the transmitting unit).
         For ``panic_button``,
         MQTT **siblings** only; the pressing unit relies on firmware local siren.
      4. Publish per-target ``siren_on`` / ``siren_off`` / ``alarm_signal``, insert alarm row,
         queue email.
    """
    # Late-bind app symbols at call time so module import order doesn't
    # matter — these are defined further down in ``app.py`` (or rely on
    # other helpers that still live there).
    import app as _app

    if _alarm_event_is_duplicate(device_id, payload):
        _app.emit_event(
            level="debug",
            category="alarm",
            event_type="alarm.trigger.duplicate",
            summary=f"duplicate alarm.trigger ignored for {device_id}",
            actor=f"device:{device_id}",
            device_id=device_id,
            detail={
                "nonce": str(payload.get("nonce") or ""),
                "ts": payload.get("ts"),
                "dedup_window_sec": ALARM_EVENT_DEDUP_WINDOW_SEC,
            },
        )
        return

    source_zone = str(payload.get("source_zone") or "all")
    local_trigger = bool(payload.get("local_trigger"))
    triggered_by = str(payload.get("trigger_kind") or ("remote_button" if local_trigger else "network"))
    owner_admin = _lookup_owner_admin(device_id)
    source_group, _source_label = _app._device_notify_labels(device_id)
    policy = _app._trigger_policy_for(owner_admin, source_group)

    alarm_id = _insert_alarm(device_id, owner_admin, source_zone, triggered_by, payload)
    _app.emit_event(
        level="warn",
        category="alarm",
        event_type="alarm.trigger",
        summary=f"alarm from {device_id} ({triggered_by})",
        actor=f"device:{device_id}",
        target=owner_admin or "",
        owner_admin=owner_admin,
        device_id=device_id,
        detail={"alarm_id": alarm_id, "zone": source_zone, "trigger_kind": triggered_by},
        ref_table="alarms",
        ref_id=alarm_id,
    )

    should_fanout = triggered_by in (
        "remote_button",
        "remote_loud_button",
        "remote_silent_button",
        "remote_pause_button",
        "network",
        "group_link",
        "panic_button",
    )
    if triggered_by == "remote_silent_button" and not bool(policy.get("remote_silent_link_enabled", True)):
        should_fanout = False
    # Remote "loud" pathways only (not panic — panic has its own toggle).
    if triggered_by in ("remote_button", "remote_loud_button", "remote_pause_button", "network", "group_link") and not bool(
        policy.get("remote_loud_link_enabled", True)
    ):
        should_fanout = False
    if triggered_by == "panic_button" and not bool(policy.get("panic_link_enabled", True)):
        should_fanout = False

    # Who receives MQTT commands: siblings in the same tenant + notification_group (+ zone).
    # Remote #1 silent / #2 loud: never command the originating device.
    # Panic: MQTT to siblings only; originator sounds via firmware TRIGGER_SELF_SIREN.
    include_source = not bool(policy.get("fanout_exclude_self", True))
    if triggered_by in ("remote_button", "remote_loud_button", "remote_silent_button", "remote_pause_button", "panic_button"):
        include_source = False

    targets, eligible_total = (
        _tenant_siblings(
            owner_admin,
            device_id,
            source_zone=source_zone,
            source_group=source_group,
            include_source=include_source,
        )
        if should_fanout
        else ([], 0)
    )
    fanout_capped = bool(should_fanout and eligible_total > len(targets))
    sent = 0
    failures: list[str] = []
    loud_ms = int(policy.get("remote_loud_duration_ms", ALARM_FANOUT_DURATION_MS))
    panic_ms = int(policy.get("panic_fanout_duration_ms", DEFAULT_PANIC_FANOUT_MS))
    default_cmd_key = str(CMD_AUTH_KEY or "").strip().upper()
    cmd_key_map = _app.get_cmd_keys_for_devices([did for did, _ in targets]) if targets else {}

    def _fanout_publish_one(did: str, ckey: str) -> None:
        if triggered_by == "remote_silent_button":
            cmd, params = "alarm_signal", {"kind": "silent"}
        elif triggered_by == "remote_pause_button":
            cmd, params = "siren_off", {}
        else:
            dur_ms = panic_ms if triggered_by == "panic_button" else loud_ms
            cmd, params = "siren_on", {"duration_ms": dur_ms}
        # wait_publish=False: fan-out runs in a thread pool; we don't want each
        # target to block waiting for paho drain, otherwise a 50-device group can
        # stall the MQTT ingest thread for tens of seconds and back up the queue.
        _app.publish_command(
            topic=f"{TOPIC_ROOT}/{did}/cmd",
            cmd=cmd,
            params=params,
            target_id=did,
            proto=CMD_PROTO,
            cmd_key=ckey,
            wait_publish=False,
        )

    if should_fanout and targets:
        sent_lock = threading.Lock()
        fail_lock = threading.Lock()

        # Bounded concurrency: on a 200-device group we do not want 200 threads.
        pool = min(max(4, FANOUT_WORKER_POOL_SIZE), max(1, len(targets)))
        sem = threading.BoundedSemaphore(pool)

        def _worker(did: str) -> None:
            nonlocal sent
            ck = cmd_key_map.get(did.strip().upper(), default_cmd_key)
            with sem:
                try:
                    _fanout_publish_one(did, ck)
                    with sent_lock:
                        sent += 1
                except Exception as exc:
                    with fail_lock:
                        failures.append(f"{did}:{exc}")

        workers = [
            threading.Thread(target=_worker, args=(did,), name=f"fanout-{did}", daemon=True)
            for did, _z in targets
        ]
        for t in workers:
            t.start()
        # Cap wall-clock on the ingest thread: even in a 100-device group, we should
        # return in ~1.5s. QoS 1 retries remain paho's responsibility.
        deadline = time.time() + float(FANOUT_WALL_CLOCK_MAX_S)
        for t in workers:
            left = max(0.05, deadline - time.time())
            t.join(timeout=left)
        if failures:
            retry_ids = [x.split(":", 1)[0] for x in failures if ":" in x and x.split(":", 1)[0]]
            if retry_ids:
                time.sleep(0.3)
                failures.clear()
                retry_threads = [
                    threading.Thread(target=_worker, args=(did,), name=f"fanout-retry-{did}", daemon=True)
                    for did in retry_ids
                ]
                for t in retry_threads:
                    t.start()
                retry_deadline = time.time() + float(FANOUT_WALL_CLOCK_MAX_S)
                for t in retry_threads:
                    left = max(0.05, retry_deadline - time.time())
                    t.join(timeout=left)

    email_sent = False
    email_detail = ""
    try:
        recipients = _recipients_for_admin(owner_admin)
        if recipients and notifier.enabled():
            g, n = _app._device_notify_labels(device_id)
            subject, text, html = render_alarm_email({
                "source_id": device_id,
                "zone": source_zone,
                "triggered_by": triggered_by,
                "created_at": utc_now_iso(),
                "fanout_count": sent,
                "notification_group": g,
                "display_label": n,
                "notify_prefix": _app._notify_subject_prefix(device_id),
            })
            email_sent = notifier.enqueue(recipients, subject, text, html)
            email_detail = f"queued={email_sent} to={len(recipients)}"
        elif recipients:
            email_detail = "smtp_disabled"
        else:
            email_detail = "no_recipients"
    except Exception as exc:
        email_detail = f"queue_err:{exc}"

    _update_alarm(alarm_id, sent, email_sent, email_detail)

    try:
        audit_event(
            f"device:{device_id}",
            "alarm.fanout",
            target=owner_admin or "(unowned)",
            detail={
                "alarm_id": alarm_id,
                "triggered_by": triggered_by,
                "fanout_count": sent,
                "target_total": len(targets),
                "eligible_total": eligible_total,
                "fanout_capped": fanout_capped,
                "fanout_max": ALARM_FANOUT_MAX_TARGETS,
                "failures": failures[:5],
                "email": email_detail,
            },
        )
    except Exception:
        pass


def _fan_out_alarm_safe(device_id: str, payload: dict[str, Any]) -> None:
    try:
        _fan_out_alarm(device_id, payload)
    except Exception as exc:
        logger.exception("alarm fan-out failed for %s: %s", device_id, exc)
