"""Alarms + activity-feed routes (Phase-10 modularization extract from ``app.py``).

Three dashboard activity-center endpoints:

  * ``GET /alarms``           — server-side fan-out history of physical
                                device alarms.
  * ``GET /alarms/summary``   — count buckets (last_24h, last_7d) and
                                top noisy sources for the activity tile.
  * ``GET /activity/signals`` — unified feed merging ``alarms`` rows with
                                ``signal_triggers`` (dashboard / API
                                remote siren actions).

The ACL helper ``_alarm_scope_for`` (build the WHERE fragment that
restricts both tables to what the principal may see) lives here too —
nothing else uses it.

Late-bound dependencies on ``app.py``
-------------------------------------
Captured at module load time, after ``app.py`` is past these defs:

  * ``require_principal``                — Depends() target
  * ``_principal_tenant_owns_device``    — used to redact ``notification_group``
                                            for cross-tenant rows
  * ``_legacy_unowned_device_scope``     — legacy NULL-owner allow-list
  * ``get_manager_admin``                — non-admin tenant resolution

We deliberately reference the function objects directly in
``Depends(require_principal)`` rather than wrapping them in a lambda;
the lambda would strip FastAPI's parameter injection and silently
break auth. Same trap as routers/factory.py.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

import app as _app
from db import db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal
_principal_tenant_owns_device = _app._principal_tenant_owns_device
_legacy_unowned_device_scope = _app._legacy_unowned_device_scope
get_manager_admin = _app.get_manager_admin

logger = logging.getLogger("croc-api.routers.alarms")

router = APIRouter(tags=["alarms"])


# ──────────────────────────────────────────────────────── ACL helpers ────

def _alarm_scope_for(
    principal: Principal,
    *,
    device_id_sql: str = "alarms.source_id",
) -> tuple[str, list[Any]]:
    """SQL fragment restricting alarms/signal_triggers to what the principal may see.

    `device_id_sql` must be the device column in the current query (e.g. `alarms.source_id`, `a.source_id`, `s.device_id`)
    for ACL checks when a non-owner has a share.
    """
    if principal.is_superadmin():
        return "", []
    acl = (
        f"EXISTS (SELECT 1 FROM device_acl a2 "
        f"WHERE a2.device_id = {device_id_sql} AND a2.grantee_username = ? AND a2.revoked_at IS NULL "
        f"AND (a2.can_view=1 OR a2.can_operate=1))"
    )
    if principal.role == "admin":
        if _legacy_unowned_device_scope(principal):
            return (
                f" AND (owner_admin = ? OR owner_admin IS NULL OR ({acl})) ",
                [principal.username, principal.username],
            )
        return (
            f" AND (owner_admin = ? OR ({acl})) ",
            [principal.username, principal.username],
        )
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    if _legacy_unowned_device_scope(principal):
        return (
            f" AND (owner_admin = ? OR owner_admin IS NULL OR ({acl})) ",
            [manager, principal.username],
        )
    return (
        f" AND (owner_admin = ? OR ({acl})) ",
        [manager, principal.username],
    )


# ───────────────────────────────────────────────────────────── routes ────

@router.get("/alarms")
def list_alarms(
    limit: int = Query(default=100, ge=1, le=500),
    since_hours: int = Query(default=168, ge=1, le=720),
    source_id: Optional[str] = Query(default=None),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    scope_sql, scope_args = _alarm_scope_for(principal, device_id_sql="alarms.source_id")
    args: list[Any] = list(scope_args)
    where_extra = ""
    if source_id:
        where_extra += " AND source_id = ? "
        args.append(source_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT id, source_id, owner_admin, zone, triggered_by, ts_device,
                   fanout_count, email_sent, email_detail, created_at
            FROM alarms
            WHERE created_at >= datetime('now', ?)
            {scope_sql}
            {where_extra}
            ORDER BY id DESC
            LIMIT ?
            """,
            tuple([f"-{since_hours} hours"] + args + [limit]),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@router.get("/alarms/summary")
def alarms_summary(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    scope_sql, scope_args = _alarm_scope_for(principal, device_id_sql="alarms.source_id")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"SELECT COUNT(*) AS c FROM alarms WHERE created_at >= datetime('now','-24 hours') {scope_sql}",
            tuple(scope_args),
        )
        last24 = int(cur.fetchone()["c"])
        cur.execute(
            f"SELECT COUNT(*) AS c FROM alarms WHERE created_at >= datetime('now','-7 days') {scope_sql}",
            tuple(scope_args),
        )
        last7 = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT source_id, COUNT(*) AS c
            FROM alarms
            WHERE created_at >= datetime('now','-7 days') {scope_sql}
            GROUP BY source_id
            ORDER BY c DESC
            LIMIT 10
            """,
            tuple(scope_args),
        )
        top = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"last_24h": last24, "last_7d": last7, "top_sources_7d": top}


@router.get("/activity/signals")
def list_activity_signals(
    limit: int = Query(default=100, ge=1, le=500),
    since_hours: int = Query(default=168, ge=1, le=720),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Unified feed: physical device alarms + dashboard/API remote siren actions."""
    assert_min_role(principal, "user")
    al_base, scope_args = _alarm_scope_for(principal, device_id_sql="a.source_id")
    since_arg = f"-{since_hours} hours"
    al_scope = al_base.replace("owner_admin", "a.owner_admin")
    st_scope = (
        al_base.replace("owner_admin", "s.owner_admin")
        .replace("a.source_id", "s.device_id", 1)
    )
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT a.id, a.created_at, 'device_alarm' AS kind, a.source_id AS device_id, a.zone,
                   a.triggered_by AS actor, a.fanout_count, a.email_sent, a.email_detail,
                   NULL AS duration_ms, IFNULL(d.display_label, '') AS display_label,
                   IFNULL(d.notification_group, '') AS notification_group
            FROM alarms a
            LEFT JOIN device_state d ON d.device_id = a.source_id
            WHERE a.created_at >= datetime('now', ?) {al_scope}
            ORDER BY a.id DESC LIMIT ?
            """,
            tuple([since_arg] + list(scope_args) + [limit]),
        )
        alarm_rows = [dict(r) for r in cur.fetchall()]
        sig_actor_hide = ""
        if principal.role != "superadmin":
            sig_actor_hide = " AND s.actor_username NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin') "
        cur.execute(
            f"""
            SELECT s.id, s.created_at, s.kind, s.device_id, s.zone,
                   s.actor_username AS actor, s.target_count AS fanout_count,
                   0 AS email_sent, '' AS email_detail, s.duration_ms,
                   IFNULL(d.display_label, '') AS display_label,
                   IFNULL(d.notification_group, '') AS notification_group, s.detail_json
            FROM signal_triggers s
            LEFT JOIN device_state d ON d.device_id = s.device_id
            WHERE s.created_at >= datetime('now', ?) {st_scope} {sig_actor_hide}
            ORDER BY s.id DESC LIMIT ?
            """,
            tuple([since_arg] + list(scope_args) + [limit]),
        )
        sig_rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    all_dids = sorted(
        {str(r.get("device_id") or "").strip() for r in alarm_rows + sig_rows if r.get("device_id")}
    )
    owner_by_did: dict[str, str] = {}
    if all_dids:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            ph = ",".join(["?"] * len(all_dids))
            cur.execute(
                f"SELECT device_id, IFNULL(owner_admin,'') AS owner_admin FROM device_ownership WHERE device_id IN ({ph})",
                tuple(all_dids),
            )
            for owr in cur.fetchall():
                owner_by_did[str(owr["device_id"])] = str(owr["owner_admin"] or "")
            conn.close()

    merged: list[dict[str, Any]] = []
    for r in alarm_rows:
        did = str(r["device_id"] or "")
        ng = str(r.get("notification_group") or "")
        if did and not _principal_tenant_owns_device(principal, owner_by_did.get(did, "")):
            ng = ""
        merged.append(
            {
                "ts": r["created_at"],
                "kind": "device_alarm",
                "what": "alarm_fanout",
                "device_id": r["device_id"],
                "display_label": r["display_label"] or "",
                "notification_group": ng,
                "zone": r["zone"] or "",
                "who": r["actor"],
                "fanout_count": int(r["fanout_count"] or 0),
                "email_sent": bool(r["email_sent"]),
                "email_detail": r["email_detail"] or "",
                "duration_ms": r["duration_ms"],
                "_row": int(r["id"]),
            }
        )
    for r in sig_rows:
        did = str(r["device_id"] or "")
        ng = str(r.get("notification_group") or "")
        if did and not _principal_tenant_owns_device(principal, owner_by_did.get(did, "")):
            ng = ""
        merged.append(
            {
                "ts": r["created_at"],
                "kind": r["kind"],
                "what": r["kind"],
                "device_id": r["device_id"],
                "display_label": r["display_label"] or "",
                "notification_group": ng,
                "zone": r["zone"] or "",
                "who": r["actor"],
                "fanout_count": int(r["fanout_count"] or 0),
                "email_sent": bool(r["email_sent"]),
                "email_detail": r["email_detail"] or "",
                "duration_ms": r["duration_ms"],
                "detail_json": r.get("detail_json") or "",
                "_row": int(r["id"]),
            }
        )
    merged.sort(key=lambda x: (x["ts"] or "", x["_row"]), reverse=True)
    out_items = merged[:limit]
    for x in out_items:
        x.pop("_row", None)
    return {"items": out_items}
