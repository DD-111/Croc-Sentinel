"""Group-card "apply" fan-out routes (Phase-66 split from ``routers/group_cards.py``).

The settings CRUD half of the group-card surface (delete,
capabilities, list/get/save settings) lives in
``routers/group_cards.py``. This module owns the **apply** route
— the one that actually fans the saved settings out to every
device in the group as ``siren_on`` (+ optional ``self_test`` /
``reboot``) MQTT commands.

Routes (both behind ``Depends(require_principal)``)
---------------------------------------------------
  POST /group-cards/{group_key}/apply        — siren fan-out (canonical)
  POST /api/group-cards/{group_key}/apply    — /api/ alias

Late binding
------------
* ``_group_owner_scope``, ``_group_devices_with_owner``,
  ``_group_settings_defaults`` are imported from
  ``routers.group_cards`` (single source of truth — the apply
  route reads the same group_card_settings rows the settings
  routes write).
* All other helpers (``publish_command``, ``get_cmd_key_for_device``,
  ``require_capability``, ``emit_event``, ``_principal_tenant_owns_device``,
  ``_lookup_owner_admin``, ``_log_signal_trigger``,
  ``_device_access_flags``) are late-bound off ``app`` because they
  are also used by non-group code paths in app.py.

Note on /api/ aliases
---------------------
The /api/ alias is a thin pass-through to the canonical handler.
Do NOT inline a second copy of the body — older proxies that only
allow ``/api/*`` rely on the alias hitting exactly the same logic.
See routers/group_cards.py for the long write-up.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import app as _app
from config import CMD_PROTO, DEFAULT_REMOTE_FANOUT_MS, TOPIC_ROOT
from db import db_lock, get_conn
from device_security import ensure_not_revoked
from routers.group_cards import (
    _group_devices_with_owner,
    _group_owner_scope,
    _group_settings_defaults,
)
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
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


logger = logging.getLogger("croc-api.routers.group_cards_apply")
router = APIRouter(tags=["group-cards"])


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


__all__ = ("router",)
