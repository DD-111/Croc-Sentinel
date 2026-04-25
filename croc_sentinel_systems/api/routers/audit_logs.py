"""Audit + log feed routes (Phase-9 modularization extract from ``app.py``).

Three read-only history endpoints used by the dashboard's audit & logs
pages:

  * ``GET  /audit``           — admin/superadmin view of the audit_events
                                table, with role-based scope filtering.
  * ``GET  /logs/messages``   — MQTT-message log joined with device_state
                                for zone/ownership scoping.
  * ``GET  /logs/file``       — superadmin-only tail of the structured
                                ``LOG_FILE_PATH`` JSON-line file.

Late-bound dependencies on ``app.py``
-------------------------------------
This module captures the following from the ``app`` module *at import
time* (after ``app.py`` has executed past the relevant definitions):

  * ``require_principal``                  — function passed to Depends()
  * ``zone_sql_suffix``                    — function (zone scope SQL)
  * ``assert_device_view_access``          — function (per-device check)
  * ``owner_scope_clause_for_device_state``— function (owner scope SQL)

We deliberately reference the function objects directly in
``Depends(require_principal)`` rather than wrapping them in a lambda;
the lambda would strip FastAPI's parameter injection (Cookie / Header /
Request) and silently break auth. Same trap as routers/factory.py.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import app as _app
from config import LOG_FILE_PATH
from db import db_lock, get_conn
from security import Principal, assert_min_role, assert_zone_for_device

require_principal = _app.require_principal
zone_sql_suffix = _app.zone_sql_suffix
assert_device_view_access = _app.assert_device_view_access
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state

logger = logging.getLogger("croc-api.routers.audit_logs")

router = APIRouter(tags=["audit-logs"])


@router.get("/audit")
def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    actor: Optional[str] = Query(default=None, max_length=64),
    action: Optional[str] = Query(default=None, max_length=64),
    target: Optional[str] = Query(default=None, max_length=128),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    clauses: list[str] = ["1=1"]
    args: list[Any] = []
    if principal.role == "admin":
        # admin only sees:
        #   - own actions
        #   - actions on users they manage
        #   - actions on devices they own (or legacy unowned if allowed)
        owned_sub = (
            "SELECT username FROM dashboard_users WHERE manager_admin = ?"
        )
        clauses.append(
            "(actor = ? OR target IN (" + owned_sub + ") OR target IN "
            "(SELECT device_id FROM device_ownership WHERE owner_admin = ?))"
        )
        args.extend([principal.username, principal.username, principal.username])
        clauses.append("actor NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin')")
    if actor:
        clauses.append("actor = ?")
        args.append(actor)
    if action:
        clauses.append("action LIKE ?")
        args.append(f"{action}%")
    if target:
        clauses.append("target = ?")
        args.append(target)
    where = " AND ".join(clauses)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT id, actor, action, target, detail_json, created_at
            FROM audit_events
            WHERE {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            tuple(args + [limit]),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        try:
            r["detail"] = json.loads(r.pop("detail_json") or "{}")
        except Exception:
            r["detail"] = {}
    return {"items": rows}


@router.get("/logs/messages")
def get_logs_messages(
    channel: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if principal.role == "user" and not device_id:
        raise HTTPException(status_code=403, detail="device_id is required for this role")
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    query = """
        SELECT m.id, m.topic, m.channel, m.device_id, m.payload_json, m.ts_device, m.ts_received
        FROM messages m
        JOIN device_state d ON m.device_id = d.device_id
        WHERE 1=1
    """
    args: list[Any] = []
    query += zs
    args.extend(za)
    query += osf
    args.extend(osa)
    if channel:
        query += " AND m.channel = ?"
        args.append(channel)
    if device_id:
        assert_device_view_access(principal, device_id)
        query += " AND m.device_id = ?"
        args.append(device_id)
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
            zr = cur.fetchone()
            conn.close()
        if not zr:
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    query += " ORDER BY m.id DESC LIMIT ?"
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    for row in rows:
        row["payload"] = json.loads(row.pop("payload_json"))
    return {"items": rows}


@router.get("/logs/file")
def get_log_file_tail(
    tail: int = Query(default=200, ge=10, le=5000),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    if not os.path.exists(LOG_FILE_PATH):
        return {"lines": []}
    with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return {"lines": [ln.rstrip("\n") for ln in lines[-tail:]]}
