"""Group-card admin routes (Phase-14 modularization extract from ``app.py``).

A "group card" is the dashboard widget that fans out a single click to
every device sharing the same ``device_state.notification_group`` tag —
think floor-level / building-level grouping. Eleven endpoints (six
canonical + five ``/api/`` mirrors that older clients still hit):

  Canonical (no /api prefix):
    DELETE /group-cards/{group_key}
    POST   /group-cards/{group_key}/delete           — proxy-friendly alt
    GET    /group-cards/capabilities                 — feature discovery
    GET    /group-cards/settings                     — list owned/all
    GET    /group-cards/{group_key}/settings         — single
    PUT    /group-cards/{group_key}/settings         — upsert
    POST   /group-cards/{group_key}/apply            — siren + optional self_test/reboot

  /api/ mirrors (delegate to the canonical handlers; same behavior):
    GET    /api/group-cards/settings
    GET    /api/group-cards/{group_key}/settings
    PUT    /api/group-cards/{group_key}/settings
    POST   /api/group-cards/{group_key}/apply
    DELETE /api/group-cards/{group_key}
    POST   /api/group-cards/{group_key}/delete

The mirror routes exist so old proxies/firewalls that only allow
``/api/*`` can still reach the same logic. Keep them as thin wrappers —
do NOT inline a second copy of the body or you'll diverge.

Tenant model
------------
- ``admin``: scope is self; ``owner_admin`` query/body is rejected.
- ``user``: scope follows their managing admin (``get_manager_admin``).
- ``superadmin``: may slice by ``owner_admin`` to disambiguate the same
  group_key reused across tenants. When omitted and devices span
  multiple tenants, write/apply require an explicit slice (we 400).

Helpers and schemas (moved with routes)
---------------------------------------
  Pydantic body: ``GroupCardSettingsBody``
  Helpers:       ``_delete_group_card_impl``, ``_group_owner_scope``,
                 ``_group_settings_defaults``, ``_group_devices_with_owner``

The following stay in ``app.py`` because non-group code paths use them
(late-bound here):

  get_manager_admin, zone_sql_suffix, owner_scope_clause_for_device_state,
  _principal_tenant_owns_device, _lookup_owner_admin, _log_signal_trigger,
  _device_access_flags, publish_command, get_cmd_key_for_device,
  require_capability, emit_event, require_principal
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import CMD_PROTO, DEFAULT_REMOTE_FANOUT_MS, TOPIC_ROOT
from db import cache_invalidate, db_lock, get_conn
from device_security import ensure_not_revoked
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
get_manager_admin = _app.get_manager_admin
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state
_principal_tenant_owns_device = _app._principal_tenant_owns_device
_lookup_owner_admin = _app._lookup_owner_admin
_log_signal_trigger = _app._log_signal_trigger
_device_access_flags = _app._device_access_flags
emit_event = _app.emit_event


# `publish_command` and `get_cmd_key_for_device` are *defined later* in
# app.py (the group-cards include sits above the device-command helpers
# section). Use call-time wrappers so we don't AttributeError on import.
def publish_command(*args: Any, **kwargs: Any) -> Any:
    return _app.publish_command(*args, **kwargs)


def get_cmd_key_for_device(device_id: str) -> str:
    return _app.get_cmd_key_for_device(device_id)

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


# ─────────────────────────────────────────── routes: apply (siren fan-out) ────

@router.post("/group-cards/{group_key}/apply")
def apply_group_card_settings(
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
    tenant_for_slice: Optional[str] = tenant_q or None
    rows = _group_devices_with_owner(g, principal, tenant_owner=tenant_for_slice)
    if principal.role == "superadmin" and not tenant_for_slice:
        owners_set = {str(r.get("owner_admin") or "").strip() for r in rows}
        owners_set.discard("")
        if len(owners_set) > 1:
            raise HTTPException(
                status_code=400,
                detail="owner_admin query required (multiple tenants share this group_key)",
            )
    rows = [r for r in rows if _principal_tenant_owns_device(principal, str(r.get("owner_admin") or ""))]
    targets = [str(r["device_id"]) for r in rows if r.get("device_id")]
    if not targets:
        raise HTTPException(
            status_code=404,
            detail="group has no devices owned by your tenant for this key (shared devices are excluded from group apply)",
        )

    # Settings ownership policy:
    # - own devices => use caller's owner_scope setting
    # - shared devices => follow real owner's setting (read-only for grantee)
    device_owner_map: dict[str, str] = {str(r["device_id"]): str(r.get("owner_admin") or "") for r in rows}
    owners_needed: set[str] = set()
    for did in targets:
        owner_real = str(device_owner_map.get(did) or "")
        owner_for_cfg = owner_real or owner_scope
        owners_needed.add(owner_for_cfg)
    settings_by_owner: dict[str, dict[str, Any]] = {}
    if owners_needed:
        ph = ",".join(["?"] * len(owners_needed))
        args = [g] + list(owners_needed)
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT owner_admin, trigger_mode, trigger_duration_ms, delay_seconds, reboot_self_check
                FROM group_card_settings
                WHERE group_key = ? AND owner_admin IN ({ph})
                """,
                tuple(args),
            )
            for r in cur.fetchall():
                settings_by_owner[str(r["owner_admin"])] = {
                    "trigger_mode": str(r["trigger_mode"] or "continuous"),
                    "trigger_duration_ms": int(r["trigger_duration_ms"] or DEFAULT_REMOTE_FANOUT_MS),
                    "delay_seconds": int(r["delay_seconds"] or 0),
                    "reboot_self_check": bool(int(r["reboot_self_check"] or 0)),
                }
            conn.close()

    siren_sent = 0
    siren_scheduled = 0
    reboot_jobs = 0
    self_tests = 0
    for did in targets:
        ensure_not_revoked(did)
        owner_real = str(device_owner_map.get(did) or "")
        owner_for_cfg = owner_real or owner_scope
        cfg = settings_by_owner.get(owner_for_cfg, _group_settings_defaults(g))
        dur_ms = int(cfg.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS)
        reboot_self_check = bool(cfg.get("reboot_self_check"))
        # Delay is config-only for UI visibility; execution is immediate.
        publish_command(
            topic=f"{TOPIC_ROOT}/{did}/cmd",
            cmd="siren_on",
            params={"duration_ms": dur_ms},
            target_id=did,
            proto=CMD_PROTO,
            cmd_key=get_cmd_key_for_device(did),
        )
        siren_sent += 1

        if reboot_self_check:
            require_capability(principal, "can_send_command")
            _, can_op = _device_access_flags(principal, did)
            if not can_op:
                continue
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="self_test",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            self_tests += 1
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="reboot",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            reboot_jobs += 1

    owner = _lookup_owner_admin(targets[0]) if targets else ""
    # Report the first owner's effective setting for compact response fields.
    first_owner = str(device_owner_map.get(targets[0]) or owner_scope) if targets else owner_scope
    first_cfg = settings_by_owner.get(first_owner, _group_settings_defaults(g))
    mode = "continuous"
    dur_ms = int(first_cfg.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS)
    delay_seconds = 0
    reboot_self_check = bool(first_cfg.get("reboot_self_check"))
    _log_signal_trigger(
        "group_card_apply",
        "*",
        "",
        principal.username,
        owner,
        duration_ms=dur_ms,
        target_count=len(targets),
        detail={
            "group_key": g,
            "trigger_mode": mode,
            "delay_seconds": delay_seconds,
            "reboot_self_check": reboot_self_check,
            "sent_now": siren_sent,
            "scheduled": siren_scheduled,
            "self_tests": self_tests,
            "reboot_jobs": reboot_jobs,
        },
    )
    emit_event(
        level="warn",
        category="alarm",
        event_type="group.trigger.apply",
        summary=f"group settings applied for {g} ({len(targets)} devices) by {principal.username}",
        actor=principal.username,
        target=g,
        owner_admin=owner or "",
        detail={
            "group_key": g,
            "mode": mode,
            "duration_ms": dur_ms,
            "delay_seconds": delay_seconds,
            "reboot_self_check": reboot_self_check,
            "owner_scope": owner_scope,
            "owners_count": len(owners_needed),
            "device_count": len(targets),
            "sent_now": siren_sent,
            "scheduled": siren_scheduled,
            "self_tests": self_tests,
            "reboot_jobs": reboot_jobs,
        },
    )
    return {
        "ok": True,
        "group_key": g,
        "device_count": len(targets),
        "mode": mode,
        "trigger_duration_ms": dur_ms,
        "delay_seconds": delay_seconds,
        "reboot_self_check": reboot_self_check,
        "sent_now": siren_sent,
        "scheduled": siren_scheduled,
        "self_tests": self_tests,
        "reboot_jobs": reboot_jobs,
    }


@router.post("/api/group-cards/{group_key}/apply")
def apply_group_card_settings_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return apply_group_card_settings(group_key, owner_admin=owner_admin, principal=principal)


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
