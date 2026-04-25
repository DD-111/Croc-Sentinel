"""Authorization & per-tenant scope helpers (Phase-49 extraction
from ``app.py``).

This module owns the layer that sits *on top of* the raw
``security.Principal`` (which only knows username/role/zones) and
turns it into per-device decisions and SQL scope clauses:

* :func:`_legacy_unowned_device_scope` — single source of truth for
  the "show admins their own pre-ownership-table devices" knob
  (``ALLOW_LEGACY_UNOWNED`` × not ``TENANT_STRICT``). Superadmins
  always see everything regardless.
* :func:`get_manager_admin` — read ``dashboard_users.manager_admin``
  for one user (used to resolve a ``role='user'`` principal back to
  the admin tenant they belong to).
* :func:`principal_for_username` — load a username straight off
  ``dashboard_users`` and turn it into a :class:`Principal`. Raises
  404 if missing, 403 if status is anything other than ``active``
  or empty. Used for Telegram webhook -> dashboard user mapping.
* :func:`get_effective_policy` — start from
  ``default_policy_for_role(role)`` and overlay any per-user
  ``role_policies`` row (``can_alert`` / ``can_send_command`` /
  ``can_claim_device`` / ``can_manage_users`` / ``can_backup_restore``
  + the six ``tg_*`` Telegram capabilities).
* :func:`require_capability` — gate a single capability on the
  effective policy; superadmins bypass.
* :func:`_device_access_flags` — the core ``(can_view, can_operate)``
  tuple for a principal × device. Superadmins always (True, True).
  Admins: must own the device (or it's an unowned legacy row in
  legacy mode). Users: must inherit ownership through their
  ``manager_admin``. Strict tenant isolation: cross-tenant ACL grants
  do NOT leak operate rights here (those go through device_acl
  separately).
* :func:`_principal_tenant_owns_device` — same idea but only the
  "is this MY tenant's device" half (no operate flag). Used to
  decide whether to leak ``notification_group`` to ACL grantees.
* :func:`_redact_notification_group_for_principal` — in-place mutator
  that blanks ``payload["notification_group"]`` when the principal
  is just an ACL grantee on someone else's device.
* :func:`assert_device_view_access` — raise 403 if ``can_view`` is
  False.
* :func:`assert_device_siren_access` — currently aliases view access
  (the actual ``can_alert`` capability is enforced on the route).
* :func:`assert_device_operate_access` — raise 403 if ``can_operate``
  is False.
* :func:`assert_device_owner` — backward-compatible alias for
  :func:`assert_device_operate_access`.
* :func:`assert_device_command_actor` — the full publish-style
  precondition: at least ``user`` role, has ``can_send_command``
  capability, optionally not revoked, and operate ACL.
* :func:`owner_sql_suffix` — generate ``" AND d.owner_admin = ? "``
  (or ``... OR IS NULL`` in legacy mode) for the device-state-style
  joined queries that already have a ``device_ownership`` join
  aliased to ``d``.
* :func:`owner_scope_clause_for_device_state` — generate the
  EXISTS-subquery variant for raw ``device_state`` queries that
  haven't joined ``device_ownership`` yet. Same legacy-unowned
  fallback rules.

Wiring
------
* Pulls config flags (``ALLOW_LEGACY_UNOWNED`` / ``TENANT_STRICT``)
  straight from :mod:`config` — these are env-fixed at startup,
  so importing once is correct.
* Pulls ``Principal`` / ``assert_min_role`` /
  ``default_policy_for_role`` / ``zones_from_json`` from
  :mod:`security` and ``ensure_not_revoked`` from
  :mod:`device_security` directly — no late binding needed because
  those modules are import-acyclic.
* Re-exported from ``app.py`` so the dozens of routers using
  ``_app.assert_device_view_access`` / ``_app.owner_sql_suffix`` /
  ``_app.principal_for_username`` etc. keep working with no
  identity drift.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import HTTPException

from config import ALLOW_LEGACY_UNOWNED, TENANT_STRICT
from db import db_lock, get_conn
from device_security import ensure_not_revoked
from helpers import default_policy_for_role
from security import (
    Principal,
    assert_min_role,
    zones_from_json,
)

__all__ = (
    "_legacy_unowned_device_scope",
    "get_manager_admin",
    "principal_for_username",
    "get_effective_policy",
    "require_capability",
    "_device_access_flags",
    "_principal_tenant_owns_device",
    "_redact_notification_group_for_principal",
    "assert_device_view_access",
    "assert_device_siren_access",
    "assert_device_operate_access",
    "assert_device_owner",
    "assert_device_command_actor",
    "owner_sql_suffix",
    "owner_scope_clause_for_device_state",
    "zone_sql_suffix",
)

logger = logging.getLogger(__name__)


def _legacy_unowned_device_scope(principal: Principal) -> bool:
    """Whether unowned device_state rows appear in non-superadmin device queries."""
    if principal.is_superadmin():
        return False
    return bool(ALLOW_LEGACY_UNOWNED) and not TENANT_STRICT


def zone_sql_suffix(principal: Principal, column: str = "zone") -> tuple[str, list[Any]]:
    """Extra WHERE fragment for zone-scoped roles."""
    if principal.is_superadmin() or principal.has_all_zones():
        return "", []
    placeholders = ",".join(["?"] * len(principal.zones))
    frag = (
        f" AND ({column} IN ({placeholders}) OR IFNULL({column},'') IN ('all','')) "
    )
    return frag, list(principal.zones)


def get_manager_admin(username: str) -> str:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT manager_admin FROM dashboard_users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return ""
    return str(row["manager_admin"] or "")


def principal_for_username(username: str) -> Principal:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT username, role, allowed_zones_json, status
            FROM dashboard_users
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="telegram binding user not found")
    status = str(row["status"] or "active")
    if status not in ("active", ""):
        raise HTTPException(status_code=403, detail=f"user not active: {status}")
    role = str(row["role"] or "user")
    zones = zones_from_json(str(row["allowed_zones_json"] or "[]"))
    return Principal(username=str(row["username"]), role=role, zones=zones)


def get_effective_policy(principal: Principal) -> dict[str, int]:
    base = default_policy_for_role(principal.role)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk
            FROM role_policies WHERE username = ?
            """,
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return base
    out = dict(base)
    for k in out.keys():
        out[k] = int(row[k]) if k in row.keys() else out[k]
    return out


def require_capability(principal: Principal, capability: str) -> None:
    if principal.role == "superadmin":
        return
    pol = get_effective_policy(principal)
    if int(pol.get(capability, 0)) != 1:
        raise HTTPException(status_code=403, detail=f"capability denied: {capability}")


def _device_access_flags(principal: Principal, device_id: str) -> tuple[bool, bool]:
    """Return (can_view, can_operate) with strict tenant ownership isolation."""
    if principal.role == "superadmin":
        return True, True
    manager = get_manager_admin(principal.username) if principal.role == "user" else ""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        own = cur.fetchone()
        conn.close()
    owner = str(own["owner_admin"]) if own and own["owner_admin"] is not None else ""
    if principal.role == "admin":
        owner_view = bool(owner) and owner == principal.username
        if not owner and _legacy_unowned_device_scope(principal):
            owner_view = True
        owner_operate = bool(owner) and owner == principal.username
        # Strict isolation mode: admin cannot view/operate cross-tenant shared devices.
        return owner_view, owner_operate
    owner_view = bool(owner) and bool(manager) and owner == manager
    if not owner and _legacy_unowned_device_scope(principal) and bool(manager):
        owner_view = True
    owner_operate = bool(owner) and bool(manager) and owner == manager
    # Tenant user follows manager tenant only; shared ACL does not cross tenant boundary.
    return owner_view, owner_operate


def _principal_tenant_owns_device(principal: Principal, owner_admin: Optional[str]) -> bool:
    """True if principal is the registered owning tenant — not an ACL grantee on someone else's device."""
    if principal.role == "superadmin":
        return True
    o = str(owner_admin or "").strip()
    if not o:
        return _legacy_unowned_device_scope(principal)
    if principal.role == "admin":
        return o == principal.username
    mgr = get_manager_admin(principal.username) or ""
    return bool(mgr) and o == mgr


def _redact_notification_group_for_principal(
    principal: Principal, owner_admin: Optional[str], payload: dict[str, Any]
) -> None:
    """Hide owner's notification_group in JSON for ACL grantees (device-only sharing)."""
    if _principal_tenant_owns_device(principal, owner_admin):
        return
    payload["notification_group"] = ""


def assert_device_view_access(principal: Principal, device_id: str) -> None:
    can_view, _ = _device_access_flags(principal, device_id)
    if not can_view:
        raise HTTPException(status_code=403, detail="device not in your scope")


def assert_device_siren_access(principal: Principal, device_id: str) -> None:
    """Remote siren ON/OFF: same visibility as dashboard device view + role ``can_alert`` (checked on route)."""
    assert_device_view_access(principal, device_id)


def assert_device_operate_access(principal: Principal, device_id: str) -> None:
    _, can_operate = _device_access_flags(principal, device_id)
    if not can_operate:
        raise HTTPException(status_code=403, detail="device operation denied")


def assert_device_owner(principal: Principal, device_id: str) -> None:
    # Backward-compatible alias used by existing routes.
    assert_device_operate_access(principal, device_id)


def assert_device_command_actor(
    principal: Principal, device_id: str, *, check_revoked: bool = True
) -> None:
    """Publish-style device commands: at least user, policy capability, operate ACL, optional revoke."""
    assert_min_role(principal, "user")
    require_capability(principal, "can_send_command")
    if check_revoked:
        ensure_not_revoked(device_id)
    assert_device_operate_access(principal, device_id)


def owner_sql_suffix(principal: Principal, alias: str = "d") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    col = f"{alias}.owner_admin"
    leg = _legacy_unowned_device_scope(principal)
    if principal.role == "admin":
        return f" AND ({col} = ? {'OR '+col+' IS NULL' if leg else ''}) ", [principal.username]
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    return f" AND ({col} = ? {'OR '+col+' IS NULL' if leg else ''}) ", [manager]


def owner_scope_clause_for_device_state(
    principal: Principal, device_alias: str = "device_state"
) -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    if principal.role == "admin":
        if _legacy_unowned_device_scope(principal):
            return (
                f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
                f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
                [principal.username],
            )
        return (
            f" AND (EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) ",
            [principal.username],
        )
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    if _legacy_unowned_device_scope(principal):
        return (
            f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
            f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
            [manager],
        )
    return (
        f" AND (EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) ",
        [manager],
    )
