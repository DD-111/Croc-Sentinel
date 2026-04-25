"""Group-card settings PUT (save) routes (Phase-81 split from
``routers/group_cards.py``).

The Phase-14 / Phase-66 / Phase-73 lineage already split the apply
fan-out and delete halves out of ``routers/group_cards.py``; what
remained was a 436-line module mixing reads (capabilities, list, get)
with writes (PUT settings). Phase 81 extracts the PUT writes here so
each lifecycle stage lives in its own module:

  read    → ``routers/group_cards.py``           (Phase 14, trimmed P81)
  write   → ``routers/group_cards_save.py``      (this file, Phase 81)
  apply   → ``routers/group_cards_apply.py``     (Phase 66)
  delete  → ``routers/group_cards_delete.py``    (Phase 73)

That mirrors the OTA campaign split (read / lifecycle) and the
auth_users / auth_user_policy split (identity / capabilities) — the
cross-cutting principle is "verbs that mutate live in their own
file".

Routes
------
  PUT  /group-cards/{group_key}/settings        — save settings.
  PUT  /api/group-cards/{group_key}/settings    — /api/ mirror
                                                  (delegates).

Tenant-scope rules (PUT only)
-----------------------------
* admin:      ``owner_admin`` in body is rejected (forced self-scope).
* user:       same — scope follows ``get_manager_admin``.
* superadmin: when omitted AND devices span multiple tenants,
              the request is rejected (400) — disambiguation must
              be explicit. When devices land in a single tenant we
              auto-pick that tenant for the scope.

Sharing rule
------------
Non-superadmin principals cannot save settings for a group whose
devices were granted to them via sharing — the owning admin keeps
authority over the group strategy. Detected by comparing each
device's ``device_ownership.owner_admin`` against the principal's
own scope; any mismatch ⇒ 403.

Empty-group allowance
---------------------
Saves are allowed even when zero devices are tagged with the group
yet. The dashboard creates the settings row first, then operators
tag devices. The apply / fan-out routes will continue to require
non-empty membership.

Late-binding strategy
---------------------
The three ``_group_*`` helpers live in ``routers.group_cards`` and
are imported here at module load time. ``routers.group_cards`` runs
before this module by way of ``routes_registry`` (group_cards →
group_cards_apply → group_cards_save → group_cards_delete), so
the import always resolves to a fully-defined helper.

``require_principal`` is captured from ``app`` at module load via
``routers.group_cards`` (we re-use the same captured function so
test rigs that patch ``app.require_principal`` propagate uniformly).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel  # noqa: F401  re-import for clarity

from audit import audit_event
from db import db_lock, get_conn
from helpers import utc_now_iso
from routers.group_cards import (
    GroupCardSettingsBody,
    _group_devices_with_owner,
    _group_owner_scope,
    require_principal,
)
from security import Principal, assert_min_role


logger = logging.getLogger("croc-api.routers.group_cards_save")
router = APIRouter(tags=["group-cards"])


# ─────────────────────────────────────────── routes: settings save ────


def _save_group_card_settings_impl(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal,
) -> dict[str, Any]:
    """Single-source implementation; both PUT routes delegate here.

    Order of operations:
      1. Trim & validate ``group_key``; reject empty.
      2. Reject non-superadmin attempts to override ``owner_admin``
         (the body field is superadmin-only).
      3. Resolve effective ``owner_scope``:
           * non-super: ``_group_owner_scope`` (self / managing-admin).
           * super + body.owner_admin: use that explicit slice.
           * super + no body.owner_admin: leave for the device-set
             auto-pick below.
      4. Fetch the device slice. For super-no-body, infer the unique
         owner from the slice (or 400 if the group spans multiple).
      5. Sharing guard: non-super principals cannot save when any
         device's ``device_ownership.owner_admin`` differs from
         their scope (rejecting "grantee tries to override owner
         strategy" silently).
      6. Resolve ``trigger_mode`` from delay_seconds (>0 ⇒ ``delay``,
         else ``continuous``) — single source of truth so the apply
         route's behavior is fully derived from the persisted row.
      7. UPSERT and emit audit event.

    Returns the canonical settings response shape (same fields as
    the GET handler) plus the resolved ``device_count``.
    """
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    tenant_body = (body.owner_admin or "").strip()
    if principal.role != "superadmin" and tenant_body:
        raise HTTPException(
            status_code=400, detail="owner_admin in body is superadmin-only"
        )
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
    # Allow saving even when no devices are tagged yet: otherwise UI 404s
    # before any ``device_state.notification_group`` is written (e.g. the
    # group name is saved before members). Sibling fan-out + apply still
    # require devices with matching notification_group.
    # Shared groups are owner-managed: grantee cannot override owner strategy.
    if principal.role != "superadmin":
        for r in rows:
            o = str(r.get("owner_admin") or "")
            if o and o != owner_scope:
                raise HTTPException(
                    status_code=403,
                    detail="shared group settings are managed by owner",
                )
    now = utc_now_iso()
    resolved_mode = "delay" if int(body.delay_seconds) > 0 else "continuous"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO group_card_settings (
                owner_admin, group_key, trigger_mode, trigger_duration_ms,
                delay_seconds, reboot_self_check, updated_by, updated_at
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


@router.put("/group-cards/{group_key}/settings")
def save_group_card_settings(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Canonical PUT — saves group-card settings for the group_key."""
    return _save_group_card_settings_impl(group_key, body, principal)


@router.put("/api/group-cards/{group_key}/settings")
def save_group_card_settings_api(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """``/api/`` mirror — delegates to the canonical handler.

    Kept as a thin wrapper so old proxies / firewalls that only allow
    ``/api/*`` keep working. Do **not** inline a copy of the body or
    you'll diverge from the canonical handler. (The same trap caught
    Phase 14 originally — the comment in ``routers/group_cards.py``'s
    docstring still applies.)
    """
    return _save_group_card_settings_impl(group_key, body, principal)


__all__ = ("router",)
