"""Tenant-scoped alarm DB helpers (Phase-41 extraction from ``app.py``).

This module owns five small SQLite helpers that resolve "who hears this
alarm" and persist alarm rows. They are pure SQLite + ``helpers`` +
``config`` — no MQTT, no event bus, no notifier — so they import cleanly
without any cyclic dependency on ``app.py``.

Public API
----------
* :func:`_lookup_owner_admin` — return the ``owner_admin`` username for a
  device (``None`` if unowned).
* :func:`_tenant_siblings` — return same-tenant, same-notification-group
  devices that should receive a fan-out command, capped at
  ``ALARM_FANOUT_MAX_TARGETS``.
* :func:`_recipients_for_admin` — list enabled email recipients for a
  tenant admin's alarm notifications.
* :func:`_insert_alarm` — insert an ``alarms`` row and return the new id.
* :func:`_update_alarm` — patch ``fanout_count`` / ``email_sent`` /
  ``email_detail`` after fan-out completes.

These were previously top-level functions in ``app.py``. They are now
re-exported from ``app.py`` so the routers' ``_app._lookup_owner_admin``
late-bind shims (and the in-module ``_fan_out_alarm``) keep working.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from config import ALARM_FANOUT_MAX_TARGETS
from db import db_lock, get_conn
from helpers import _sibling_group_norm, utc_now_iso

__all__ = (
    "_lookup_owner_admin",
    "_tenant_siblings",
    "_recipients_for_admin",
    "_insert_alarm",
    "_update_alarm",
)

logger = logging.getLogger(__name__)


def _lookup_owner_admin(device_id: str) -> Optional[str]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    if row and row["owner_admin"]:
        return str(row["owner_admin"])
    return None


def _tenant_siblings(
    owner_admin: Optional[str],
    source_id: str,
    *,
    source_zone: str = "",
    source_group: str = "",
    include_source: bool = False,
) -> tuple[list[tuple[str, str]], int]:
    """Devices that receive group fan-out commands ("siblings") for this source_id.

    Selection: same ``owner_admin``, not revoked, optional matching ``source_zone``
    (unless zone is ``all``/``*``), and **normalized match** on ``notification_group``
    (NFC, collapse whitespace, case-fold) so minor string drift does not break linkage.

    Non-siblings (other tenants, empty group, revoked) are never targeted.

    ``include_source``: when False (default), the originating ``source_id`` is omitted.

    If the source group's normalized key is empty, there are **no** siblings.

    Returns ``(targets, eligible_total)``: ``targets`` is capped at
    ``ALARM_FANOUT_MAX_TARGETS``, sorted by ``device_id`` for stable ordering;
    ``eligible_total`` is how many devices matched before the cap.
    """
    zone_filter = source_zone.strip()
    norm_source = _sibling_group_norm(source_group)
    if not norm_source:
        return [], 0
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if owner_admin:
            sql = """
                SELECT d.device_id, d.zone, IFNULL(d.notification_group,'') AS notification_group
                FROM device_state d
                JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.owner_admin = ? AND r.device_id IS NULL
                  AND TRIM(IFNULL(d.notification_group,'')) != ''
            """
            args: list[Any] = [owner_admin]
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            cur.execute(sql, args)
        else:
            sql = """
                SELECT d.device_id, d.zone, IFNULL(d.notification_group,'') AS notification_group
                FROM device_state d
                LEFT JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.device_id IS NULL AND r.device_id IS NULL
                  AND TRIM(IFNULL(d.notification_group,'')) != ''
            """
            args = []
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            cur.execute(sql, args)
        rows = cur.fetchall()
        conn.close()
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for r in rows:
        if _sibling_group_norm(str(r["notification_group"] or "")) != norm_source:
            continue
        did = str(r["device_id"])
        if did == source_id and not include_source:
            continue
        if did in seen:
            continue
        seen.add(did)
        candidates.append((did, str(r["zone"] or "")))
    candidates.sort(key=lambda t: t[0])
    eligible_total = len(candidates)
    out = candidates[:ALARM_FANOUT_MAX_TARGETS]
    return out, eligible_total


def _recipients_for_admin(owner_admin: Optional[str]) -> list[str]:
    if not owner_admin:
        return []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT email FROM admin_alert_recipients WHERE owner_admin = ? AND enabled = 1",
            (owner_admin,),
        )
        rows = cur.fetchall()
        conn.close()
    return [str(r["email"]) for r in rows if r["email"]]


def _insert_alarm(
    source_id: str,
    owner_admin: Optional[str],
    zone: str,
    triggered_by: str,
    payload: dict[str, Any],
) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alarms
                (source_id, owner_admin, zone, triggered_by, ts_device, nonce, sig,
                 fanout_count, email_sent, email_detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?)
            """,
            (
                source_id,
                owner_admin,
                zone,
                triggered_by,
                int(payload.get("ts") or 0) or None,
                str(payload.get("nonce") or "") or None,
                str(payload.get("sig") or "") or None,
                utc_now_iso(),
            ),
        )
        alarm_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    return alarm_id


def _update_alarm(alarm_id: int, fanout_count: int, email_sent: bool, email_detail: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE alarms SET fanout_count = ?, email_sent = ?, email_detail = ? WHERE id = ?
            """,
            (fanout_count, 1 if email_sent else 0, email_detail[:400], alarm_id),
        )
        conn.commit()
        conn.close()
