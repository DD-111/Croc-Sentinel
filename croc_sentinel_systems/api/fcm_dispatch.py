"""FCM alarm-dispatch helpers (Phase-46 extraction from ``app.py``).

This module owns the four small helpers that turn an in-process
event row into a list of FCM alarm payloads enqueued via
``fcm_notify.enqueue_alarm_payloads``:

* :func:`_alarm_severity_bucket` — collapse the event's ``level``
  string ("critical", "error", "warn", "info", ...) into one of
  ``HIGH`` / ``MEDIUM`` / ``LOW`` for the device-side UI.
* :func:`_sound_hint_from_severity` — map that bucket to the
  ``siren`` / ``beep`` / ``tone`` sound hint sent in the FCM
  data payload.
* :func:`_trigger_method_from_ev` — look at ``ev["actor"]`` and
  return ``MQTT`` (``device:...``), ``Telegram`` (``telegram:...``)
  or ``API`` (default).
* :func:`_maybe_dispatch_fcm_for_ev` — the main entry point;
  filters out non-alarm events, looks up tenant + device labels,
  loads the owner's registered FCM tokens, builds one alarm
  payload per token, and enqueues them. Superadmin-owned alarms
  are demoted to a ``SYSTEM`` (heads-up, no sound) push so the
  superadmin's own dashboard never gets a fullscreen siren.

These were previously top-level functions in ``app.py`` and are
re-exported from there so existing callers (``emit_event`` →
``_maybe_dispatch_fcm_for_ev`` and any test that imports them
straight off ``app``) continue to work unchanged. There are no
late-bound ``_app.*`` references — this module pulls
``_device_notify_labels`` directly from :mod:`trigger_policy` and
``enqueue_alarm_payloads`` from :mod:`fcm_notify`.
"""

from __future__ import annotations

import logging
from typing import Any

from db import db_lock, get_conn
from fcm_notify import enqueue_alarm_payloads
from trigger_policy import _device_notify_labels
from tz_display import iso_timestamp_to_malaysia

__all__ = (
    "_alarm_severity_bucket",
    "_sound_hint_from_severity",
    "_trigger_method_from_ev",
    "_maybe_dispatch_fcm_for_ev",
)

logger = logging.getLogger(__name__)


def _alarm_severity_bucket(level: str) -> str:
    lv = (level or "").lower()
    if lv == "critical":
        return "HIGH"
    if lv in ("error", "warn"):
        return "MEDIUM"
    return "LOW"


def _sound_hint_from_severity(sev: str) -> str:
    if sev == "HIGH":
        return "siren"
    if sev == "MEDIUM":
        return "beep"
    return "tone"


def _trigger_method_from_ev(ev: dict[str, Any]) -> str:
    actor = str(ev.get("actor") or "")
    if actor.startswith("device:"):
        return "MQTT"
    if actor.startswith("telegram:"):
        return "Telegram"
    return "API"


def _maybe_dispatch_fcm_for_ev(ev: dict[str, Any]) -> None:
    """Tenant-owner FCM: ALARM lane for admin/user; SYSTEM (no siren) if owner row is superadmin."""
    if str(ev.get("category") or "") != "alarm":
        return
    owner = str(ev.get("owner_admin") or "").strip()
    if not owner:
        return
    device_id = str(ev.get("device_id") or "").strip()
    grp, label = ("", "")
    if device_id:
        grp, label = _device_notify_labels(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT role, IFNULL(alarm_push_style,'fullscreen') AS alarm_push_style, IFNULL(tenant,'') AS tenant "
            "FROM dashboard_users WHERE username = ?",
            (owner,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return
        role = str(row["role"] or "")
        alarm_push_style = str(row["alarm_push_style"] or "fullscreen").strip() or "fullscreen"
        system_name = str(row["tenant"] or "").strip() or owner
        cur.execute(
            "SELECT token, platform FROM user_fcm_tokens WHERE username = ? ORDER BY updated_at DESC",
            (owner,),
        )
        tok_rows = cur.fetchall()
        conn.close()
    if not tok_rows:
        return
    sev = _alarm_severity_bucket(str(ev.get("level") or "warn"))
    sound_hint = _sound_hint_from_severity(sev)
    detail = ev.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}
    triggered_by = str(
        detail.get("trigger_kind") or detail.get("client_kind") or ev.get("event_type") or "",
    ).strip()
    push_kind = "SYSTEM" if role == "superadmin" else "ALARM"
    if push_kind == "SYSTEM":
        sound_hint = "none"
        alarm_push_style = "heads_up"
    method = _trigger_method_from_ev(ev)
    lat = str(detail.get("lat") or detail.get("latitude") or "")
    lng = str(detail.get("lng") or detail.get("longitude") or "")
    loc = f"{lat},{lng}" if lat and lng else ""
    ui_mode = "heads_up" if (push_kind == "SYSTEM" or alarm_push_style == "heads_up") else "fullscreen"
    base: dict[str, str] = {
        "push_kind": push_kind,
        "severity": sev,
        "sound_hint": sound_hint,
        "alarm_ui_mode": ui_mode,
        "event_id": str(int(ev.get("id") or 0)),
        "event_type": str(ev.get("event_type") or ""),
        "ts": str(ev.get("ts_malaysia") or iso_timestamp_to_malaysia(str(ev.get("ts") or "")))[:500],
        "alarm_title": "ALARM",
        "device_id": device_id,
        "device_name": (label or device_id)[:200],
        "system_name": system_name[:200],
        "group": grp[:120],
        "triggered_by": (triggered_by or "unknown")[:120],
        "trigger_method": method[:32],
        "summary": str(ev.get("summary") or "")[:500],
        "location": loc[:120],
    }
    out: list[dict[str, str]] = []
    for tr in tok_rows:
        tok = str(tr["token"] or "").strip()
        if not tok:
            continue
        rowd = dict(base)
        rowd["token"] = tok
        rowd["platform"] = str(tr["platform"] or "")[:32]
        out.append(rowd)
    if out:
        enqueue_alarm_payloads(out)
