"""Bootstrap seeding (Phase-74 split from ``schema.py``).

This module owns the data-priming half of ``init_db``:

  * Insert a bootstrap superadmin row when ``dashboard_users`` is empty
    *and* ``BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD`` is set in config.
  * Backfill ``role_policies`` rows for every dashboard user using
    ``default_policy_for_role(role)`` so new policy columns land with
    sensible defaults.

These steps are idempotent:

  * The superadmin insert runs **only** when there are zero users
    (``SELECT COUNT(*)`` short-circuits on a populated DB).
  * The role_policies backfill uses ``INSERT OR IGNORE`` so existing
    rows are preserved verbatim.

Schema DDL stays in ``schema.py`` and idempotent migrations live in
``schema_migrations.py``. Putting seeding in its own module keeps the
"what data should exist on a fresh deploy" concern separate from "what
shape should the DB have" — and makes the bootstrap path easy to
re-run from a maintenance shell when an operator needs to (eg.
recovering a tenant after a disaster).
"""
from __future__ import annotations

import json
import logging
import sqlite3

from config import (
    BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD,
    BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME,
)
from helpers import default_policy_for_role, utc_now_iso
from security import hash_password

logger = logging.getLogger("croc-api.schema.seed")


def _bootstrap_superadmin_if_empty(conn: sqlite3.Connection) -> None:
    """Insert a superadmin row when the user table is empty.

    Guarded by:
      1. ``COUNT(*) == 0`` on dashboard_users (so subsequent restarts
         after first user creation never re-insert).
      2. ``BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD`` non-empty (so
         operators that disable bootstrapping at deploy time are
         honored even on a fresh DB).

    The created user has ``role='superadmin'`` and
    ``allowed_zones_json='["*"]'`` — full reach. The password is
    hashed via ``hash_password`` (bcrypt) before storage.
    """
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM dashboard_users")
    n_users = int(cur.fetchone()["c"])
    if n_users == 0 and BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD:
        username = BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME or "superadmin"
        cur.execute(
            """
            INSERT INTO dashboard_users
                (username, password_hash, role, allowed_zones_json, created_at)
            VALUES (?, ?, 'superadmin', ?, ?)
            """,
            (
                username,
                hash_password(BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD),
                json.dumps(["*"], ensure_ascii=True),
                utc_now_iso(),
            ),
        )
        logger.info("bootstrapped superadmin %r (empty dashboard_users)", username)


def _backfill_role_policies(conn: sqlite3.Connection) -> None:
    """Ensure every dashboard_users row has a matching role_policies row.

    For each user we look up the role-default policy via
    ``default_policy_for_role`` and ``INSERT OR IGNORE`` it so existing
    customizations are preserved. New users created after this call
    get their row inserted by the user-create flow in ``app.py``;
    this backfill exists for legacy databases that pre-date the
    role_policies table.
    """
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM dashboard_users")
    for ur in cur.fetchall():
        pol = default_policy_for_role(str(ur["role"]))
        cur.execute(
            """
            INSERT OR IGNORE INTO role_policies
                (username, can_alert, can_send_command, can_claim_device,
                 can_manage_users, can_backup_restore, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(ur["username"]),
                pol["can_alert"],
                pol["can_send_command"],
                pol["can_claim_device"],
                pol["can_manage_users"],
                pol["can_backup_restore"],
                utc_now_iso(),
            ),
        )


def seed_bootstrap(conn: sqlite3.Connection) -> None:
    """Run every idempotent seeding step in order.

    Order rationale:
      1. ``_bootstrap_superadmin_if_empty`` — creates the seed user
         row when needed; later step depends on this row existing
         on a fresh DB so the superadmin gets a role_policies row.
      2. ``_backfill_role_policies`` — fans out across whatever set
         of users exists (which now includes step 1's superadmin).
    """
    _bootstrap_superadmin_if_empty(conn)
    _backfill_role_policies(conn)


__all__ = ["seed_bootstrap"]
