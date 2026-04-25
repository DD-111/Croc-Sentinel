"""Group-card settings + delete + capabilities (Phase-14, trimmed in Phase-66).

A "group card" is the dashboard widget that fans out a single click to
every device sharing the same ``device_state.notification_group`` tag —
think floor-level / building-level grouping. The original Phase-14
extract carried 13 endpoints (the apply fan-out included). Phase 66
moved the 2 *apply* routes into ``routers/group_cards_apply.py`` so
this module now hosts the persistence half only:

  Canonical (no /api prefix):
    DELETE /group-cards/{group_key}
    POST   /group-cards/{group_key}/delete           — proxy-friendly alt
    GET    /group-cards/capabilities                 — feature discovery
    GET    /group-cards/settings                     — list owned/all
    GET    /group-cards/{group_key}/settings         — single
    PUT    /group-cards/{group_key}/settings         — upsert

  /api/ mirrors (delegate to the canonical handlers; same behavior):
    GET    /api/group-cards/settings
    GET    /api/group-cards/{group_key}/settings
    PUT    /api/group-cards/{group_key}/settings
    DELETE /api/group-cards/{group_key}
    POST   /api/group-cards/{group_key}/delete

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

Helpers and schemas (kept here, re-exported for group_cards_apply)
------------------------------------------------------------------
  Pydantic body: ``GroupCardSettingsBody``
  Helpers:       ``_delete_group_card_impl``, ``_group_owner_scope``,
                 ``_group_settings_defaults``, ``_group_devices_with_owner``

The three ``_group_*`` helpers (``_group_owner_scope``,
``_group_settings_defaults``, ``_group_devices_with_owner``) are
re-exported via ``__all__`` so ``routers/group_cards_apply.py`` can
import them — apply needs to read the same settings rows we write
and resolve the same device slice.

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
from audit import audit_event
from config import DEFAULT_REMOTE_FANOUT_MS
from db import cache_invalidate, db_lock, get_conn
from helpers import utc_now_iso
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


def _delete_group_card_impl(
    group_key: str,
    principal: Principal,
    *,
    tenant_owner: Optional[str] = None,
) -> dict[str, Any]:
    """Delete a group card by clearing notification_group on target devices.

    Security rule:
      - admin: can only delete groups fully owned by self (shared devices block deletion)
      - superadmin: can delete any group; pass `tenant_owner` to clear only that admin's slice
        (recommended when multiple tenants reuse the same group_key).
    """
    assert_min_role(principal, "admin")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
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
        rows = [dict(r) for r in cur.fetchall()]
        if not rows:
            conn.close()
            raise HTTPException(status_code=404, detail="group not found in your scope")
        if principal.role != "superadmin":
            for r in rows:
                owner = str(r.get("owner_admin") or "")
                if owner and owner != principal.username:
                    conn.close()
                    raise HTTPException(status_code=403, detail="shared group cannot be deleted")
                if not owner:
                    conn.close()
                    raise HTTPException(status_code=403, detail="unowned group cannot be deleted by admin")
        ids = [str(r["device_id"]) for r in rows if r.get("device_id")]
        ph = ",".join(["?"] * len(ids))
        cur.execute(
            f"UPDATE device_state SET notification_group = '' WHERE device_id IN ({ph})",
            tuple(ids),
        )
        changed = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            if tenant:
                cur.execute(
                    "DELETE FROM group_card_settings WHERE owner_admin = ? AND group_key = ?",
                    (tenant, g),
                )
            else:
                cur.execute("DELETE FROM group_card_settings WHERE group_key = ?", (g,))
        else:
            owner_scope = (
                principal.username
                if principal.role == "admin"
                else (get_manager_admin(principal.username) or principal.username)
            )
            cur.execute(
                "DELETE FROM group_card_settings WHERE owner_admin = ? AND group_key = ?",
                (owner_scope, g),
            )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "group.delete",
        g,
        {"device_count": len(ids), "changed": changed, "tenant_owner": tenant or None},
    )
    return {"ok": True, "group_key": g, "device_count": len(ids), "changed": changed}


# ─────────────────────────────────────────── routes: delete ────

@router.delete("/group-cards/{group_key}")
def delete_group_card(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


@router.post("/group-cards/{group_key}/delete")
def delete_group_card_post(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Proxy-friendly delete route for environments that block HTTP DELETE."""
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


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


# ─────────────────────────────────────────── routes: settings save ────

@router.put("/group-cards/{group_key}/settings")
def save_group_card_settings(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    tenant_body = (body.owner_admin or "").strip()
    if principal.role != "superadmin" and tenant_body:
        raise HTTPException(status_code=400, detail="owner_admin in body is superadmin-only")
    tenant_for_slice: Optional[str] = None
    if principal.role == "superadmin" and tenant_body:
        owner_scope = tenant_body
        tenant_for_slice = tenant_body
    rows = _group_devices_with_owner(g, principal, tenant_owner=tenant_for_slice)
    if principal.role == "superadmin" and not tenant_body:
        owners_set = {str(r.get("owner_admin") or "").strip() for r in rows}
        owners_set.discard("")
        if len(owners_set) > 1:
            raise HTTPException(
                status_code=400,
                detail="owner_admin required in body (multiple tenants share this group_key)",
            )
        if len(owners_set) == 1:
            owner_scope = next(iter(owners_set))
    # Allow saving even when no devices are tagged yet: otherwise UI 404s before any
    # `device_state.notification_group` is written (e.g. group name saved before members).
    # Sibling fan-out and apply still require devices with matching notification_group.
    # Shared groups are owner-managed: grantee cannot override owner strategy.
    if principal.role != "superadmin":
        for r in rows:
            o = str(r.get("owner_admin") or "")
            if o and o != owner_scope:
                raise HTTPException(status_code=403, detail="shared group settings are managed by owner")
    now = utc_now_iso()
    resolved_mode = "delay" if int(body.delay_seconds) > 0 else "continuous"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO group_card_settings (
                owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                reboot_self_check, updated_by, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_admin, group_key) DO UPDATE SET
                trigger_mode=excluded.trigger_mode,
                trigger_duration_ms=excluded.trigger_duration_ms,
                delay_seconds=excluded.delay_seconds,
                reboot_self_check=excluded.reboot_self_check,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (
                owner_scope,
                g,
                resolved_mode,
                int(body.trigger_duration_ms),
                int(body.delay_seconds),
                1 if body.reboot_self_check else 0,
                principal.username,
                now,
            ),
        )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "group.settings.save",
        g,
        {
            "trigger_mode": resolved_mode,
            "trigger_duration_ms": int(body.trigger_duration_ms),
            "delay_seconds": int(body.delay_seconds),
            "reboot_self_check": bool(body.reboot_self_check),
            "owner_admin": owner_scope,
        },
    )
    return {
        "ok": True,
        "owner_admin": owner_scope,
        "group_key": g,
        "trigger_mode": resolved_mode,
        "trigger_duration_ms": int(body.trigger_duration_ms),
        "delay_seconds": int(body.delay_seconds),
        "reboot_self_check": bool(body.reboot_self_check),
        "updated_by": principal.username,
        "updated_at": now,
        "device_count": len(rows),
    }


@router.put("/api/group-cards/{group_key}/settings")
def save_group_card_settings_api(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return save_group_card_settings(group_key, body, principal)


# Note: the /group-cards/.../apply siren fan-out lives in
# routers/group_cards_apply.py — that route imports the three
# `_group_*` helpers below, so the settings rows we persist here
# and the device slice we resolve here are exactly the same set
# the apply route reads. See ``__all__`` at the bottom for the
# re-exported helpers.


@router.delete("/api/group-cards/{group_key}")
def delete_group_card_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


@router.post("/api/group-cards/{group_key}/delete")
def delete_group_card_post_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


__all__ = (
    "router",
    "GroupCardSettingsBody",
    # Helpers re-exported for routers/group_cards_apply.py — single
    # source of truth so the settings half (this module) and the
    # apply half stay perfectly aligned on owner-scope / device
    # slice resolution.
    "_group_owner_scope",
    "_group_settings_defaults",
    "_group_devices_with_owner",
    "_delete_group_card_impl",
)
