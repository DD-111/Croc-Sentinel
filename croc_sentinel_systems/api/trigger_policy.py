"""Tenant trigger-policy + signal logging helpers
(Phase-45 extraction from ``app.py``).

This module owns six small helpers that resolve the per-tenant
trigger policy (silent / loud / panic toggles + fan-out durations),
read the device's notification labels, format email subject prefixes,
log a signal trigger row, and send the "remote siren on/off" admin
email.

Public API
----------
* :func:`_log_signal_trigger` — append an audit row to
  ``signal_triggers`` for a remote-siren / panic / test action.
* :func:`_device_notify_labels` — read ``(notification_group,
  display_label)`` straight off a ``device_state`` row (both may be
  empty).
* :func:`_trigger_policy_defaults` — the in-code defaults for a
  tenant that has never edited their policy: panic siren on, both
  link toggles on, durations from
  ``ALARM_FANOUT_DURATION_MS`` / ``DEFAULT_PANIC_FANOUT_MS``.
* :func:`_trigger_policy_for` — defaults overridden by the
  tenant's ``trigger_policies`` row for the matching ``scope_group``
  (normalized via ``_sibling_group_norm`` so "Warehouse" and
  "warehouse" resolve to the same policy).
* :func:`_notify_subject_prefix` — render
  "``[Group] Display Label · ``" from device labels, fall back to
  "``device_id · ``" so emails are never unprefixed.
* :func:`_remote_siren_notify_email` — queue the alarm-recipient
  email when a remote siren on/off action fires; opens
  ``notifier.enabled()`` first to skip work when SMTP is disabled.

These were previously top-level functions in ``app.py``. They are
re-exported from ``app.py`` so the routers' ``_app._log_signal_trigger``
/ ``_app._trigger_policy_for`` / ``_app._remote_siren_notify_email``
late-bind shims (and ``alarm_fanout.py``'s direct imports) keep
working.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from alarm_db import _recipients_for_admin
from config import ALARM_FANOUT_DURATION_MS, DEFAULT_PANIC_FANOUT_MS
from db import db_lock, get_conn
from helpers import _sibling_group_norm, utc_now_iso
from notifier import notifier, render_remote_siren_email

__all__ = (
    "_log_signal_trigger",
    "_device_notify_labels",
    "_trigger_policy_defaults",
    "_trigger_policy_for",
    "_notify_subject_prefix",
    "_remote_siren_notify_email",
)

logger = logging.getLogger(__name__)


def _log_signal_trigger(
    kind: str,
    device_id: str,
    zone: str,
    actor_username: str,
    owner_admin: Optional[str],
    duration_ms: Optional[int] = None,
    target_count: int = 1,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO signal_triggers (
                created_at, kind, device_id, owner_admin, zone, actor_username,
                duration_ms, target_count, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                kind,
                device_id,
                owner_admin,
                zone,
                actor_username,
                duration_ms,
                target_count,
                json.dumps(detail or {}, ensure_ascii=True),
            ),
        )
        conn.commit()
        conn.close()


def _device_notify_labels(device_id: str) -> tuple[str, str]:
    """Returns (notification_group, display_label) from device_state; may be empty."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(notification_group,''), IFNULL(display_label,'') "
            "FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return "", ""
    return str(row[0] or "").strip(), str(row[1] or "").strip()


def _trigger_policy_defaults() -> dict[str, Any]:
    return {
        "panic_local_siren": True,
        # MQTT fan-out of panic_button to same-group siblings (independent of remote loud link).
        "panic_link_enabled": True,
        "panic_fanout_duration_ms": int(DEFAULT_PANIC_FANOUT_MS),
        "remote_silent_link_enabled": True,
        "remote_loud_link_enabled": True,
        "remote_loud_duration_ms": int(ALARM_FANOUT_DURATION_MS),
        "fanout_exclude_self": True,
    }


def _trigger_policy_for(owner_admin: Optional[str], scope_group: str) -> dict[str, Any]:
    base = _trigger_policy_defaults()
    if not owner_admin:
        return base
    # Match-path normalization: siblings are resolved via _sibling_group_norm
    # (case-fold + NFC + whitespace), so the policy lookup MUST use the same
    # normalization — otherwise "Warehouse" and "warehouse" branch into
    # different policies for what is the same sibling set.
    group_key = _sibling_group_norm(scope_group)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT panic_local_siren, remote_silent_link_enabled, remote_loud_link_enabled,
                   remote_loud_duration_ms, fanout_exclude_self,
                   panic_link_enabled, panic_fanout_duration_ms
            FROM trigger_policies
            WHERE owner_admin = ? AND scope_group = ?
            """,
            (owner_admin, group_key),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return base
    base["panic_local_siren"] = bool(row["panic_local_siren"])
    base["remote_silent_link_enabled"] = bool(row["remote_silent_link_enabled"])
    base["remote_loud_link_enabled"] = bool(row["remote_loud_link_enabled"])
    base["remote_loud_duration_ms"] = int(row["remote_loud_duration_ms"] or ALARM_FANOUT_DURATION_MS)
    base["fanout_exclude_self"] = bool(row["fanout_exclude_self"])
    base["panic_link_enabled"] = bool(row["panic_link_enabled"])
    base["panic_fanout_duration_ms"] = int(row["panic_fanout_duration_ms"] or DEFAULT_PANIC_FANOUT_MS)
    return base


def _notify_subject_prefix(device_id: str) -> str:
    """Prefix for emails / Telegram: '[Group] DisplayName · ' or fallback to device_id."""
    grp, name = _device_notify_labels(device_id)
    parts: list[str] = []
    if grp:
        parts.append(f"[{grp}]")
    if name:
        parts.append(name)
    if parts:
        return " ".join(parts) + " · "
    return f"{device_id} · "


def _remote_siren_notify_email(
    *,
    action: str,
    device_id: str,
    zone: str,
    actor: str,
    owner_admin: Optional[str],
    duration_ms: Optional[int],
) -> None:
    recipients = _recipients_for_admin(owner_admin) if owner_admin else []
    grp, disp = _device_notify_labels(device_id)
    if not recipients or not notifier.enabled():
        return
    subject, text, html = render_remote_siren_email(
        action=action,
        device_id=device_id,
        display_label=disp,
        notification_group=grp,
        zone=zone,
        actor=actor,
        duration_ms=duration_ms,
    )
    notifier.enqueue(recipients, subject, text, html)
