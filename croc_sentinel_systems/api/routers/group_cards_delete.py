"""Group-card delete routes (Phase-73 split from ``routers/group_cards.py``).

The Phase-14 module bundled three concerns: settings CRUD, the
siren fan-out (``apply``), and tenant-scoped delete. Phase 66
already moved the apply fan-out into
``routers/group_cards_apply.py``. Phase 73 mirrors that for the
delete concern: the ``DELETE /group-cards/...`` routes plus their
93-line ``_delete_group_card_impl`` helper now live here.

Routes (all behind ``Depends(require_principal)``)
--------------------------------------------------
  DELETE /group-cards/{group_key}                — canonical
  POST   /group-cards/{group_key}/delete         — proxy-friendly alt
  DELETE /api/group-cards/{group_key}            — /api/ mirror
  POST   /api/group-cards/{group_key}/delete     — /api/ + proxy mirror

All four routes delegate to ``_delete_group_card_impl`` so the
behavior is identical and we don't carry four copies of the body.

Helpers owned here
------------------
  _delete_group_card_impl

The impl encapsulates the entire delete ceremony:

  * scope-check (admins can only delete groups they fully own;
    shared groups block deletion);
  * clear ``notification_group`` on every device in scope;
  * delete the matching ``group_card_settings`` row(s) — full
    sweep for superadmin, owner-scoped for admins, optional
    ``tenant_owner`` slice for superadmin disambiguation;
  * cache_invalidate + audit_event.

Late binding
------------
Captured at module load time, after ``app.py`` has executed past
these defs:

  Functions:
    require_principal, get_manager_admin, zone_sql_suffix,
    owner_scope_clause_for_device_state.

(All four are defined < line ~5300 in app.py — well before
``include_router`` for this module — so identity is preserved at
import time.)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import app as _app
from audit import audit_event
from db import cache_invalidate, db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal
get_manager_admin = _app.get_manager_admin
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state


logger = logging.getLogger("croc-api.routers.group_cards_delete")
router = APIRouter(tags=["group-cards"])


# ─────────────────────────────────────────────── helper ────

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
    "_delete_group_card_impl",
)
