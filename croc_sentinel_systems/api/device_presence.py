"""Pure presence/parsing helpers for device telemetry rows
(Phase-44 extraction from ``app.py``).

This module owns the small pure-helper "kernel" that the dashboard,
status views, and presence-probe scanner all share for interpreting
device telemetry:

  * ``_parse_iso`` / ``_payload_ts`` — robust epoch parsers for the
    two timestamp shapes we get back (ISO-8601 strings on ``device_state``
    rows, integer ``ts`` fields inside the JSON payloads).
  * ``_effective_online_for_presence`` — the source-of-truth online
    rule that survives stale retained LWT (``status.online=false`` with
    a newer heartbeat / ack / event still in-row).
  * ``_device_is_online_parsed`` / ``_device_is_online_sql_row`` — the
    presence rule combined with the OFFLINE_THRESHOLD_SECONDS row
    freshness window. The ``_sql_row`` variant accepts the raw
    ``device_state`` columns straight from a SELECT.
  * ``_device_presence_ages`` — granular age fields the UI renders as
    "RSSI · 3m ago · row 2s ago" (with -1 sentinels meaning "we never
    received this", rendered as "--" client-side).
  * ``_row_json_val`` — defensive ``json.loads`` for nullable JSON
    columns, returns ``{}`` on garbage so callers can ``.get(...)``
    without try/except.
  * ``_net_health_from_status`` — extract the firmware net_health
    counters block (wifi_reconnects, mqtt_longest_gap_ms, etc.)
    that we expose on the diagnostic panel.
  * ``_status_preview_from_device_row`` — compact "RSSI · 3.7 V" line
    for the device-list cards (one round-trip, no N+1).

Everything in this module is pure: stdlib (``json``, ``datetime``)
plus a one-line reference to ``app.OFFLINE_THRESHOLD_SECONDS`` for
the row-freshness window. No SQLite, no MQTT, no event bus.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

__all__ = (
    "_parse_iso",
    "_payload_ts",
    "_effective_online_for_presence",
    "_device_is_online_parsed",
    "_device_presence_ages",
    "_device_is_online_sql_row",
    "_row_json_val",
    "_net_health_from_status",
    "_status_preview_from_device_row",
)


def _parse_iso(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _payload_ts(d: dict[str, Any]) -> int:
    """Device JSON `ts` field (epoch seconds or millis fallback before NTP)."""
    t = d.get("ts")
    if isinstance(t, int):
        return t
    if isinstance(t, float):
        return int(t)
    return 0


def _effective_online_for_presence(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
) -> bool:
    """
    True when the device is up on MQTT, even if last /status snapshot is stale.

    Retained LWT (online=false) can remain in last_status_json while newer
    heartbeat, ack, or event traffic (same row `updated_at`) proves the device is back.
    """
    ts_s = _payload_ts(last_status)
    ts_hb = _payload_ts(last_heartbeat)
    ts_a = _payload_ts(last_ack)
    ts_e = _payload_ts(last_event)
    if ts_a > ts_s or ts_e > ts_s:
        return True
    if ts_hb > ts_s:
        return bool(last_heartbeat.get("online"))
    if ts_s == 0 and ts_hb == 0 and ts_a == 0 and ts_e == 0:
        return False
    return bool(last_status.get("online"))


def _device_is_online_parsed(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
    updated_at_iso: str,
    now_s: int,
) -> bool:
    """Same rule as dashboard overview presence: payload truth + row freshness."""
    import app as _app

    updated = _parse_iso(str(updated_at_iso or ""))
    fresh = (now_s - updated) < _app.OFFLINE_THRESHOLD_SECONDS
    return _effective_online_for_presence(last_status, last_heartbeat, last_ack, last_event) and fresh


def _device_presence_ages(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
    updated_at_iso: str,
    now_s: int,
) -> dict[str, int]:
    """
    Returns granular age-in-seconds fields for UI/health display.

    Anything we can't compute comes back as -1 (render as "--" in the UI) so
    the frontend never has to invent placeholder values.

    - `last_heartbeat_age_s`: seconds since the device last sent /heartbeat
      (HYBRID mode keepalive or an event heartbeat). -1 before first hb.
    - `last_signal_age_s`: seconds since ANY channel (status/heartbeat/ack/
      event) touched the row — this is the same clock the presence logic
      compares against OFFLINE_THRESHOLD_SECONDS.
    - `last_updated_age_s`: seconds since the DB row's updated_at column.
    """
    def _age(ts: int) -> int:
        if ts <= 0:
            return -1
        return max(0, int(now_s) - int(ts))

    hb_age = _age(_payload_ts(last_heartbeat))
    signal_ts = max(
        _payload_ts(last_status) or 0,
        _payload_ts(last_heartbeat) or 0,
        _payload_ts(last_ack) or 0,
        _payload_ts(last_event) or 0,
    )
    updated = _parse_iso(str(updated_at_iso or ""))
    return {
        "last_heartbeat_age_s": hb_age,
        "last_signal_age_s": _age(signal_ts),
        "last_updated_age_s": _age(int(updated) if updated > 0 else 0),
    }


def _device_is_online_sql_row(row: dict[str, Any], now_s: int) -> bool:
    def _pj(col: str) -> dict[str, Any]:
        raw = row.get(col)
        if not raw:
            return {}
        try:
            return json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            return {}

    return _device_is_online_parsed(
        _pj("last_status_json"),
        _pj("last_heartbeat_json"),
        _pj("last_ack_json"),
        _pj("last_event_json"),
        str(row.get("updated_at") or ""),
        now_s,
    )


def _row_json_val(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        j = json.loads(raw) if isinstance(raw, str) else dict(raw)
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _net_health_from_status(last_status: Any) -> dict[str, Any]:
    """Extract the firmware's net_health ledger block.

    Accepts either a parsed status dict (from `get_device`) or a raw
    ``last_status_json`` column value (from the list query).

    Returns ``{}`` for firmware that doesn't emit it — older builds only
    publish the flat rssi/online fields.

    Fields (all integers, monotonic since the device's last boot):
        wifi_reconnects       — successful Wi-Fi rejoins since boot
        mqtt_reconnects       — successful MQTT reconnects since boot
        mqtt_last_down_code   — PubSubClient state() at last drop (-4..5)
        mqtt_last_conn_code   — PubSubClient state() at last connect fail
        mqtt_longest_gap_ms   — longest continuous MQTT offline span
        wifi_longest_gap_ms   — longest continuous Wi-Fi offline span
        roam_attempts         — signal-driven AP switches
        mqtt_fail_streak      — consecutive connect failures right now
    """
    if isinstance(last_status, dict):
        st = last_status
    else:
        st = _row_json_val(last_status)
    raw = st.get("net_health") if isinstance(st, dict) else None
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key in (
        "wifi_reconnects",
        "mqtt_reconnects",
        "mqtt_last_down_code",
        "mqtt_last_conn_code",
        "mqtt_longest_gap_ms",
        "wifi_longest_gap_ms",
        "roam_attempts",
        "mqtt_fail_streak",
    ):
        if key in raw:
            try:
                out[key] = int(raw[key])
            except (TypeError, ValueError):
                pass
    return out


def _status_preview_from_device_row(d: dict[str, Any]) -> dict[str, Any]:
    """Compact live hints for the device list (one round-trip, no N+1)."""
    st = _row_json_val(d.get("last_status_json"))
    hb = _row_json_val(d.get("last_heartbeat_json"))
    rssi: int | None = None
    _w = st.get("wifi")
    wifi = _w if isinstance(_w, dict) else {}
    for cand in (st.get("rssi"), wifi.get("rssi") if isinstance(wifi, dict) else None, hb.get("rssi")):
        if cand is None:
            continue
        try:
            r = int(cand)
        except (TypeError, ValueError):
            continue
        if r != -127:
            rssi = r
            break
    vbat: float | None
    vbat = None
    if st.get("vbat") is not None:
        try:
            vb = float(st["vbat"])
            if vb >= 0:
                vbat = round(vb, 2)
        except (TypeError, ValueError):
            vbat = None
    parts: list[str] = []
    if rssi is not None:
        parts.append(f"RSSI {rssi} dBm")
    if vbat is not None:
        parts.append(f"{vbat:.2f} V")
    hb_on = bool(hb.get("online")) if "online" in hb else None
    if hb_on is True and not parts:
        parts.append("heartbeat")
    if hb_on is False and not parts:
        parts.append("heartbeat lost")
    line = " · ".join(parts) if parts else "—"
    return {"line": line, "rssi": rssi, "vbat": vbat}
