"""Superadmin approval queue for admin signups (Phase-82 split from
``routers/auth_signup.py``).

The Phase-64 ``routers/auth_signup.py`` extract bundled two
distinct authorization surfaces:

  * **public OTP flow** (4 routes, ~250 lines):
      ``/auth/signup/start``, ``/auth/signup/verify``,
      ``/auth/activate``, ``/auth/code/resend`` — all
      unauthenticated, all gated by IP + email rate limits and
      email/SMS OTP verification. Reviewed for OTP correctness,
      timing-safe comparisons, and rate-limit policy.
  * **superadmin approval** (3 routes, ~55 lines):
      ``/auth/signup/pending``, ``/auth/signup/approve/{username}``,
      ``/auth/signup/reject/{username}`` — all behind
      ``Depends(require_principal)`` + ``assert_min_role(superadmin)``.
      Reviewed for authorization correctness and audit-trail
      coverage.

Phase 82 splits the approval half here so the OTP file can be
reviewed without scrolling through the (tiny) approval queue, and
vice versa — the two surfaces have completely different reviewer
concerns.

Routes (all superadmin)
-----------------------
  GET   /auth/signup/pending             — list admins awaiting
                                           approval (status =
                                           ``awaiting_approval``).
  POST  /auth/signup/approve/{username}  — flip status to
                                           ``active`` after manual
                                           review.
  POST  /auth/signup/reject/{username}   — delete the row + its
                                           ``role_policies`` and
                                           ``verifications``
                                           sidecars.

Why approve and reject share a file
-----------------------------------
They are the two terminal states of the approval queue. The
"approve" path activates the user so they can log in; the "reject"
path purges all DB traces (rather than parking the row in a
``rejected`` status — that would just confuse the next signup
attempt with the same username, which we want to allow). Audit
events are emitted for both so a security review can replay the
queue.

Why we don't soft-delete on reject
----------------------------------
SQLite ``UNIQUE(username)`` would block re-signup with the same
username if we tombstoned. ``DELETE`` keeps the table normalized;
the audit log is the long-term record of who-rejected-whom.

Late binding
------------
``require_principal`` is captured at module load from ``app`` —
identical to every other router. ``audit_event`` is imported from
``audit``. No OTP / verification helpers are needed (those all
live in ``routers/auth_signup.py``).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

import app as _app
from audit import audit_event
from db import db_lock, get_conn
from security import Principal, assert_min_role

require_principal = _app.require_principal


logger = logging.getLogger("croc-api.routers.auth_signup_approval")
router = APIRouter(tags=["auth-signup"])


@router.get("/auth/signup/pending")
def auth_signup_pending(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Superadmin queue: admins who passed OTP but await approval.

    Sorted by ``created_at`` ASC so the oldest pending request is
    at the top — a queue, not a stack. ``email_verified_at`` is
    surfaced so the operator can confirm the OTP flow really
    completed before approving.
    """
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT username, email, phone, created_at, email_verified_at
            FROM dashboard_users
            WHERE role = 'admin' AND status = 'awaiting_approval'
            ORDER BY created_at ASC
            """
        )
        items = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": items}


@router.post("/auth/signup/approve/{username}")
def auth_signup_approve(
    username: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Flip a pending admin to ``active`` after manual review.

    The triple guard (``role='admin' AND status='awaiting_approval'``)
    on the UPDATE statement prevents accidental approval of users
    that are not actually in the queue (e.g. a typo'd username
    matching an existing active admin).

    ``rowcount == 0`` ⇒ 404 — the operator either typed the wrong
    username or the row was already approved/rejected by another
    superadmin in a race.
    """
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE dashboard_users
            SET status='active'
            WHERE username = ? AND role='admin' AND status='awaiting_approval'
            """,
            (username,),
        )
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(
            status_code=404, detail="no pending admin with that username"
        )
    audit_event(principal.username, "signup.approve", username, {})
    return {"ok": True, "username": username}


@router.post("/auth/signup/reject/{username}")
def auth_signup_reject(
    username: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Reject a pending admin signup; purge their DB rows.

    Ordering of the three DELETEs is intentional:
      1. ``dashboard_users`` first — its ``rowcount`` is what we
         use for the 404 response, so it must run before any
         sidecar cleanup.
      2. ``role_policies`` next — the policy row is keyed on
         ``username`` and would otherwise dangle.
      3. ``verifications`` last — purges any unconsumed signup
         OTPs so a re-signup with the same username starts fresh.

    We do NOT soft-delete (status='rejected') because that would
    block re-signup attempts with the same username via the
    ``UNIQUE(username)`` constraint. Audit log is the long-term
    record of rejections.
    """
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            DELETE FROM dashboard_users
            WHERE username = ? AND role='admin' AND status='awaiting_approval'
            """,
            (username,),
        )
        n = cur.rowcount
        cur.execute("DELETE FROM role_policies WHERE username = ?", (username,))
        cur.execute("DELETE FROM verifications WHERE username = ?", (username,))
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(
            status_code=404, detail="no pending admin with that username"
        )
    audit_event(principal.username, "signup.reject", username, {})
    return {"ok": True}


__all__ = ("router",)
