"""User-policy GET/PUT routes (Phase-80 split from ``routers/auth_users.py``).

The Phase-21 / Phase-69 ``routers/auth_users.py`` carried two
distinct concerns:

  * **CRUD half** (~200 lines): list / create / delete user, plus the
    ``UserCreateRequest`` schema. This is the lifecycle path —
    a user is born here, dies here.
  * **Policy half** (~125 lines): get + update the per-user
    capability policy row (``role_policies`` table), plus the
    ``UserPolicyUpdateRequest`` schema. This is the runtime path —
    operators flip ``tg_siren_on`` / ``can_send_command`` flags
    without touching identity at all.

Phase 80 splits the policy half here so:
  * ``routers/auth_users.py`` stays focused on identity lifecycle
    (list / create / delete) — and its hefty ``POST /auth/users``
    handler doesn't get conflated with policy edits in code review.
  * Both schemas can evolve independently. The policy schema
    grows every time we add a Telegram capability flag (currently
    11 fields); the create schema is stable.

Routes
------
  GET  /auth/users/{username}/policy   — fetch effective policy.
  PUT  /auth/users/{username}/policy   — update policy fields.

Schema
------
  UserPolicyUpdateRequest  — partial update; every field is
                             ``Optional[bool]`` so an admin can
                             flip exactly the bit they care about
                             without re-stating the rest. Unset
                             fields are preserved from the existing
                             ``role_policies`` row.

Authorization
-------------
Both routes require ``admin`` minimum role; ``admin`` (not superadmin)
additionally needs ``can_manage_users`` capability AND the target
user's ``manager_admin`` must be the principal (i.e. the admin can
only manage their own tenant's users — superadmin sees everyone).

Hard guardrails (PUT only)
--------------------------
* Target must be ``role='user'`` (admins use ``/auth/admins/...``).
* ``can_backup_restore`` and ``can_manage_users`` are forced to 0
  on every PUT regardless of the requested value — regular users
  never receive these high-trust capabilities through the policy
  endpoint.

Late-binding
------------
``require_principal`` and ``require_capability`` are captured at
module load time. They both exist on ``app.py`` before this router
is included, so direct attribute capture is safe (matches the
identity contract used in every other router).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import app as _app
from audit import audit_event
from db import db_lock, get_conn
from helpers import default_policy_for_role, utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability


logger = logging.getLogger("croc-api.routers.auth_user_policy")
router = APIRouter(tags=["auth-users"])


# ---- Schema ----------------------------------------------------------------


class UserPolicyUpdateRequest(BaseModel):
    """Partial update of the per-user capability flags (``role_policies`` row).

    Every field is ``Optional[bool]`` so the dashboard can PATCH-style
    update only the flags that changed. Unset fields keep the existing
    DB value (or fall back to ``default_policy_for_role('user')`` if
    the user has no row yet — first-time policy edits always start
    from the role default, never from zeros).
    """

    can_alert: Optional[bool] = None
    can_send_command: Optional[bool] = None
    can_claim_device: Optional[bool] = None
    can_manage_users: Optional[bool] = None
    can_backup_restore: Optional[bool] = None
    tg_view_logs: Optional[bool] = None
    tg_view_devices: Optional[bool] = None
    tg_siren_on: Optional[bool] = None
    tg_siren_off: Optional[bool] = None
    tg_test_single: Optional[bool] = None
    tg_test_bulk: Optional[bool] = None


# ---- Routes ----------------------------------------------------------------


@router.get("/auth/users/{username}/policy")
def auth_get_user_policy(
    username: str, principal: Principal = Depends(require_principal)
) -> dict[str, Any]:
    """Return the user's effective policy row.

    When no ``role_policies`` row exists yet (user was created before
    the table was populated, or the bootstrap row was deleted), we
    return ``default_policy_for_role(role)`` instead of 404 — that
    way the dashboard always has something to render.
    """
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, manager_admin FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if principal.role == "admin" and (
            str(u["role"]) != "user"
            or str(u["manager_admin"] or "") != principal.username
        ):
            conn.close()
            raise HTTPException(status_code=403, detail="not your managed user")
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device,
                   can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on,
                   tg_siren_off, tg_test_single, tg_test_bulk,
                   updated_at
            FROM role_policies WHERE username = ?
            """,
            (username,),
        )
        p = cur.fetchone()
        conn.close()
    if not p:
        out = default_policy_for_role(str(u["role"]))
        out["updated_at"] = ""
        return out
    return dict(p)


@router.put("/auth/users/{username}/policy")
def auth_set_user_policy(
    username: str,
    req: UserPolicyUpdateRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Update the user's policy row (partial — unset fields preserved).

    Order of operations:
      1. Authorize the principal (admin role + ``can_manage_users``).
      2. Verify the target exists and is a regular ``user`` (never
         an admin — admin policy is implicit).
      3. For admin principals, verify the target's ``manager_admin``
         matches the principal's username (tenant scoping).
      4. Load the *current* row into ``base`` (or default-for-role
         when no row exists yet — see Phase-80 docstring note above).
      5. Apply only the fields the request explicitly set
         (``v is not None``); leave the rest of ``base`` alone.
      6. **Force** ``can_backup_restore=0`` and ``can_manage_users=0``
         regardless of input — these are admin-only capabilities and
         must never leak to a regular user via this endpoint.
      7. UPSERT the row.
      8. Audit event.
    """
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, manager_admin FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if str(u["role"]) != "user":
            conn.close()
            raise HTTPException(
                status_code=400, detail="policy endpoint is for user role"
            )
        if (
            principal.role == "admin"
            and str(u["manager_admin"] or "") != principal.username
        ):
            conn.close()
            raise HTTPException(status_code=403, detail="not your managed user")
        base = default_policy_for_role("user")
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device,
                   can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on,
                   tg_siren_off, tg_test_single, tg_test_bulk
            FROM role_policies WHERE username = ?
            """,
            (username,),
        )
        curp = cur.fetchone()
        if curp:
            for k in base.keys():
                base[k] = int(curp[k])
        updates = {
            "can_alert": req.can_alert,
            "can_send_command": req.can_send_command,
            "can_claim_device": req.can_claim_device,
            "can_manage_users": req.can_manage_users,
            "can_backup_restore": req.can_backup_restore,
            "tg_view_logs": req.tg_view_logs,
            "tg_view_devices": req.tg_view_devices,
            "tg_siren_on": req.tg_siren_on,
            "tg_siren_off": req.tg_siren_off,
            "tg_test_single": req.tg_test_single,
            "tg_test_bulk": req.tg_test_bulk,
        }
        for k, v in updates.items():
            if v is not None:
                base[k] = 1 if v else 0
        base["can_backup_restore"] = 0
        base["can_manage_users"] = 0
        cur.execute(
            """
            INSERT INTO role_policies (
                username, can_alert, can_send_command, can_claim_device,
                can_manage_users, can_backup_restore,
                tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off,
                tg_test_single, tg_test_bulk, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                can_alert=excluded.can_alert,
                can_send_command=excluded.can_send_command,
                can_claim_device=excluded.can_claim_device,
                can_manage_users=excluded.can_manage_users,
                can_backup_restore=excluded.can_backup_restore,
                tg_view_logs=excluded.tg_view_logs,
                tg_view_devices=excluded.tg_view_devices,
                tg_siren_on=excluded.tg_siren_on,
                tg_siren_off=excluded.tg_siren_off,
                tg_test_single=excluded.tg_test_single,
                tg_test_bulk=excluded.tg_test_bulk,
                updated_at=excluded.updated_at
            """,
            (
                username,
                base["can_alert"],
                base["can_send_command"],
                base["can_claim_device"],
                base["can_manage_users"],
                base["can_backup_restore"],
                base["tg_view_logs"],
                base["tg_view_devices"],
                base["tg_siren_on"],
                base["tg_siren_off"],
                base["tg_test_single"],
                base["tg_test_bulk"],
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "user.policy.update", username, base)
    return {"ok": True, "username": username, "policy": base}


__all__ = (
    "router",
    "UserPolicyUpdateRequest",
)
