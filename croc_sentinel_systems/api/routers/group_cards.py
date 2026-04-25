"""Group-card read routes + shared helpers (Phase-14, trimmed P66 / P73 / P81).

A "group card" is the dashboard widget that fans out a single click to
every device sharing the same ``device_state.notification_group`` tag —
think floor-level / building-level grouping. The original Phase-14
extract carried 13 endpoints. The lifecycle is now split four ways:

  * ``routers.group_cards``         — capabilities + read routes +
                                      shared helpers + schema (this
                                      file).
  * ``routers.group_cards_save``    — PUT settings (Phase 81).
  * ``routers.group_cards_apply``   — siren fan-out (Phase 66).
  * ``routers.group_cards_delete``  — delete + impl helper (Phase 73).

Routes hosted here (all behind ``Depends(require_principal)``)
--------------------------------------------------------------
  Canonical:
    GET    /group-cards/capabilities          — feature discovery.
    GET    /group-cards/settings              — list owned/all.
    GET    /group-cards/{group_key}/settings  — single.

  /api/ mirrors (thin wrappers, same behavior):
    GET    /api/group-cards/settings
    GET    /api/group-cards/{group_key}/settings

The /api/ mirror routes exist so old proxies/firewalls that only allow
``/api/*`` can still reach the same logic. Keep them as thin wrappers —
do NOT inline a second copy of the body or you'll diverge.

Tenant model
------------
- ``admin``: scope is self; ``owner_admin`` query/body is rejected.
- ``user``: scope follows their managing admin (``get_manager_admin``).
- ``superadmin``: may slice by ``owner_admin`` to disambiguate the same
  group_key reused across tenants. When omitted and devices span
  multiple tenants, write/apply require an explicit slice (we 400).

Helpers and schemas (kept here, re-exported for sibling modules)
----------------------------------------------------------------
  Pydantic body: ``GroupCardSettingsBody``
  Helpers:       ``_group_owner_scope``,
                 ``_group_settings_defaults``,
                 ``_group_devices_with_owner``

These are imported by ``routers/group_cards_save.py`` (PUT settings)
and ``routers/group_cards_apply.py`` (apply fan-out) so all three
mutation paths agree on the same device slice and owner-scope
resolution. ``routers/group_cards_delete.py`` owns its own
``_delete_group_card_impl`` and doesn't need these.

``require_principal`` is also re-exported because ``group_cards_save``
imports it from this module — that way test rigs that patch
``app.require_principal`` propagate uniformly to every group-card
router.

The following stay in ``app.py`` because non-group code paths use them
(late-bound here):

  get_manager_admin, zone_sql_suffix, owner_scope_clause_for_device_state,
  require_principal
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import app as _app
from config import DEFAULT_REMOTE_FANOUT_MS
from db import db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal
get_manager_admin = _app.get_manager_admin
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state


logger = logging.getLogger("croc-api.routers.group_cards")

router = APIRouter(tags=["group-cards"])


# ─────────────────────────────────────────────── request schema ────

class GroupCardSettingsBody(BaseModel):
    trigger_mode: str = Field(default="continuous", pattern="^(continuous|delay)$")
    trigger_duration_ms: int = Field(default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000)
    delay_seconds: int = Field(default=0, ge=0, le=3600)
    reboot_self_check: bool = False
    # Superadmin only: which tenant's group_card_settings row / device slice to target.
    owner_admin: Optional[str] = Field(default=None, max_length=64)


# ─────────────────────────────────────────────── helpers ────

def _group_owner_scope(principal: Principal) -> str:
    if principal.role == "admin":
        return principal.username
    if principal.role == "user":
        return get_manager_admin(principal.username) or principal.username
    return principal.username


def _group_settings_defaults(group_key: str) -> dict[str, Any]:
    return {
        "group_key": group_key,
        "trigger_mode": "continuous",
        "trigger_duration_ms": int(DEFAULT_REMOTE_FANOUT_MS),
        "delay_seconds": 0,
        "reboot_self_check": False,
        "updated_by": "",
        "updated_at": "",
    }


def _group_devices_with_owner(
    group_key: str,
    principal: Principal,
    *,
    tenant_owner: Optional[str] = None,
) -> list[dict[str, str]]:
    g = (group_key or "").strip()
    if not g:
        return []
    tenant = (tenant_owner or "").strip()
    if principal.role != "superadmin" and tenant:
        raise HTTPException(status_code=400, detail="owner_admin filter is superadmin-only")
    slice_sql = ""
    slice_args: list[Any] = []
    if principal.role == "superadmin" and tenant:
        slice_sql = " AND IFNULL(o.owner_admin,'') = ? "
        slice_args.append(tenant)
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, IFNULL(o.owner_admin,'') AS owner_admin
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE IFNULL(d.notification_group,'') = ? {zs} {osf} {slice_sql}
            ORDER BY d.device_id ASC
            """,
            tuple([g] + za + osa + slice_args),
        )
        rows = [{"device_id": str(r["device_id"]), "owner_admin": str(r["owner_admin"] or "")} for r in cur.fetchall()]
        conn.close()
    return rows


@router.get("/group-cards/capabilities")
def group_cards_capabilities(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {
        "ok": True,
        "prefixes": ["/group-cards", "/api/group-cards"],
        "routes": {
            "settings_list": ["GET /group-cards/settings", "GET /api/group-cards/settings"],
            "settings_get": ["GET /group-cards/{group_key}/settings", "GET /api/group-cards/{group_key}/settings"],
            "settings_put": ["PUT /group-cards/{group_key}/settings", "PUT /api/group-cards/{group_key}/settings"],
            "apply": ["POST /group-cards/{group_key}/apply", "POST /api/group-cards/{group_key}/apply"],
            "delete_post": ["POST /group-cards/{group_key}/delete", "POST /api/group-cards/{group_key}/delete"],
            "delete_delete": ["DELETE /group-cards/{group_key}", "DELETE /api/group-cards/{group_key}"],
        },
    }


# ─────────────────────────────────────────── routes: settings list/get ────

@router.get("/group-cards/settings")
def list_group_card_settings(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    owner_scope = _group_owner_scope(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                       reboot_self_check, updated_by, updated_at
                FROM group_card_settings
                ORDER BY owner_admin ASC, group_key ASC
                """
            )
        else:
            cur.execute(
                """
                SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                       reboot_self_check, updated_by, updated_at
                FROM group_card_settings
                WHERE owner_admin = ?
                ORDER BY group_key ASC
                """,
                (owner_scope,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    out = []
    for r in rows:
        out.append(
            {
                "owner_admin": str(r.get("owner_admin") or ""),
                "group_key": str(r.get("group_key") or ""),
                "trigger_mode": str(r.get("trigger_mode") or "continuous"),
                "trigger_duration_ms": int(r.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS),
                "delay_seconds": int(r.get("delay_seconds") or 0),
                "reboot_self_check": bool(int(r.get("reboot_self_check") or 0)),
                "updated_by": str(r.get("updated_by") or ""),
                "updated_at": str(r.get("updated_at") or ""),
            }
        )
    return {"items": out}


@router.get("/api/group-cards/settings")
def list_group_card_settings_api(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    return list_group_card_settings(principal)


@router.get("/group-cards/{group_key}/settings")
def get_group_card_settings(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    tenant_q = (owner_admin or "").strip()
    if principal.role != "superadmin" and tenant_q:
        raise HTTPException(status_code=400, detail="owner_admin query is superadmin-only")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            if tenant_q:
                cur.execute(
                    """
                    SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                           reboot_self_check, updated_by, updated_at
                    FROM group_card_settings
                    WHERE owner_admin = ? AND group_key = ?
                    """,
                    (tenant_q, g),
                )
                row = cur.fetchone()
            else:
                cur.execute(
                    """
                    SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                           reboot_self_check, updated_by, updated_at
                    FROM group_card_settings
                    WHERE group_key = ?
                    """,
                    (g,),
                )
                matches = cur.fetchall()
                if not matches:
                    row = None
                elif len(matches) == 1:
                    row = matches[0]
                else:
                    conn.close()
                    raise HTTPException(
                        status_code=400,
                        detail="owner_admin query parameter required (multiple tenants use this group_key)",
                    )
        else:
            cur.execute(
                """
                SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                       reboot_self_check, updated_by, updated_at
                FROM group_card_settings
                WHERE owner_admin = ? AND group_key = ?
                """,
                (owner_scope, g),
            )
            row = cur.fetchone()
        conn.close()
    if not row:
        return _group_settings_defaults(g)
    r = dict(row)
    return {
        "owner_admin": str(r.get("owner_admin") or ""),
        "group_key": g,
        "trigger_mode": str(r.get("trigger_mode") or "continuous"),
        "trigger_duration_ms": int(r.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS),
        "delay_seconds": int(r.get("delay_seconds") or 0),
        "reboot_self_check": bool(int(r.get("reboot_self_check") or 0)),
        "updated_by": str(r.get("updated_by") or ""),
        "updated_at": str(r.get("updated_at") or ""),
    }


@router.get("/api/group-cards/{group_key}/settings")
def get_group_card_settings_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return get_group_card_settings(group_key, owner_admin=owner_admin, principal=principal)


# Phase-81 split: the PUT /group-cards/{group_key}/settings save route
# (and its /api/ mirror) lives in routers/group_cards_save.py. Both
# routes import the three ``_group_*`` helpers + ``GroupCardSettingsBody``
# from this module (re-exports below) so settings reads (here) and
# settings writes (next door) agree on owner-scope + device slice.
#
# The /group-cards/.../apply siren fan-out lives in
# routers/group_cards_apply.py — that route imports the three
# ``_group_*`` helpers below, so the settings rows persisted by
# group_cards_save and the device slice resolved here are exactly
# the same set the apply route reads.


__all__ = (
    "router",
    "GroupCardSettingsBody",
    # Helpers re-exported for routers/group_cards_save.py +
    # routers/group_cards_apply.py — single source of truth so the
    # read half (this module), save half, and apply half stay
    # perfectly aligned on owner-scope / device slice resolution.
    "_group_owner_scope",
    "_group_settings_defaults",
    "_group_devices_with_owner",
    # Re-exported so group_cards_save.py can capture the same
    # ``require_principal`` reference (so test patches on
    # ``app.require_principal`` propagate uniformly across all
    # group-card routers).
    "require_principal",
)
