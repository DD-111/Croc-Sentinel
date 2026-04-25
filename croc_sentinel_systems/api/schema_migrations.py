"""Idempotent schema migrations (Phase-74 split from ``schema.py``).

The ``init_db()`` orchestrator in ``schema.py`` originally bundled three
concerns into a single ~700 line function:

  1. CREATE TABLE / CREATE INDEX (DDL)               — stays in schema.py
  2. ensure_column / one-shot data normalization     — this module
  3. Bootstrap superadmin + role_policies backfill   — schema_seed.py

Phase 74 moves the migration block (concern #2) here so ``init_db`` can
read like a top-level recipe:

    DDL → run_migrations(conn, cur) → seed_bootstrap(conn, cur) → commit.

Everything in this module is **idempotent** and **additive**:

  * ``ensure_column`` is a no-op if the column already exists (it
    catches the SQLite "duplicate column" error). New columns added
    here always have a default so existing rows stay valid.
  * ``_normalize_trigger_policies`` only touches rows that would
    actually collide under the ``_sibling_group_norm`` grouping; on
    a fully-migrated DB it scans ``trigger_policies`` once and writes
    nothing.
  * ``_backfill_dashboard_users_status`` only touches NULL/'' status.
  * ``_ensure_provisioned_credentials_unique_index`` skips the unique
    index when stale duplicates still exist (they would have to be
    cleaned up by an operator first; we never silently delete creds).

This file is therefore safe to call on every startup. The cost on a
freshly-migrated DB is < 5 ms.
"""
from __future__ import annotations

import logging
import sqlite3

from config import DEFAULT_PANIC_FANOUT_MS
from db import ensure_column
from helpers import _sibling_group_norm

logger = logging.getLogger("croc-api.schema.migrations")


def _run_ensure_columns(conn: sqlite3.Connection) -> None:
    """Add columns that were introduced after the first ship of each table.

    Each call is a no-op if the column already exists. The whole block
    runs in well under a millisecond on a current DB.

    The order matters only insofar as the rest of ``init_db`` reads
    these columns immediately after this function returns — keep new
    additions at the bottom of the relevant table group so that
    history reads chronologically.
    """
    ensure_column(conn, "device_state", "chip_target", "TEXT")
    ensure_column(conn, "device_state", "board_profile", "TEXT")
    ensure_column(conn, "device_state", "net_type", "TEXT")
    ensure_column(conn, "device_state", "provisioned", "INTEGER")
    ensure_column(conn, "device_state", "display_label", "TEXT")
    ensure_column(conn, "device_state", "notification_group", "TEXT")
    ensure_column(conn, "dashboard_users", "manager_admin", "TEXT")
    ensure_column(conn, "dashboard_users", "tenant", "TEXT")
    ensure_column(conn, "dashboard_users", "email", "TEXT")
    ensure_column(conn, "dashboard_users", "phone", "TEXT")
    ensure_column(conn, "dashboard_users", "email_verified_at", "TEXT")
    ensure_column(conn, "dashboard_users", "phone_verified_at", "TEXT")
    # status ∈ pending | active | disabled | awaiting_approval
    ensure_column(conn, "dashboard_users", "status", "TEXT")
    ensure_column(conn, "dashboard_users", "welcome_email_sent", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "dashboard_users", "alarm_push_style", "TEXT NOT NULL DEFAULT 'fullscreen'")
    ensure_column(conn, "dashboard_users", "avatar_url", "TEXT")
    ensure_column(conn, "role_policies", "tg_view_logs", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "role_policies", "tg_view_devices", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "role_policies", "tg_siren_on", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "role_policies", "tg_siren_off", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "role_policies", "tg_test_single", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "role_policies", "tg_test_bulk", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "trigger_policies", "panic_link_enabled", "INTEGER NOT NULL DEFAULT 1")
    # Phase 93: ownership-side cmd_key shadow for cross-table consistency checks.
    # Keep default empty so legacy rows remain valid until backfilled.
    ensure_column(conn, "device_ownership", "cmd_key_shadow", "TEXT NOT NULL DEFAULT ''")
    ensure_column(
        conn,
        "trigger_policies",
        "panic_fanout_duration_ms",
        f"INTEGER NOT NULL DEFAULT {DEFAULT_PANIC_FANOUT_MS}",
    )


def _normalize_trigger_policies(conn: sqlite3.Connection) -> None:
    """Collapse trigger_policies rows that differ only in scope_group casing.

    Background: the sibling-match path in the alarm pipeline normalizes
    its lookup key with ``_sibling_group_norm`` (lower + trim + collapse
    internal whitespace). Older clients wrote rows with mixed casing,
    leading to two rows for the same logical group — the worker would
    pick whichever it found first, and admins would see "edits don't
    stick".

    Resolution: bucket rows by ``(owner_admin, normalized scope_group)``;
    keep the row with the newest ``updated_at`` and rewrite its
    ``scope_group`` to the normalized form; delete the rest. We never
    touch policy values, only the key.

    Cheap on a fully-normalized DB: a single SELECT, an in-memory
    bucketization, then an early-skip per bucket.
    """
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT rowid, owner_admin, scope_group, updated_at FROM trigger_policies"
        )
        rows = cur.fetchall()
        buckets: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for r in rows:
            key = (
                str(r["owner_admin"] or ""),
                _sibling_group_norm(str(r["scope_group"] or "")),
            )
            buckets.setdefault(key, []).append(r)
        for (_owner, norm_key), group_rows in buckets.items():
            # Already canonical singletons short-circuit (the common case).
            if len(group_rows) <= 1 and (
                len(group_rows) == 0
                or str(group_rows[0]["scope_group"] or "") == norm_key
            ):
                continue
            winner = max(group_rows, key=lambda x: str(x["updated_at"] or ""))
            winner_rowid = int(winner["rowid"])
            for r in group_rows:
                if int(r["rowid"]) == winner_rowid:
                    continue
                cur.execute(
                    "DELETE FROM trigger_policies WHERE rowid = ?",
                    (int(r["rowid"]),),
                )
            if str(winner["scope_group"] or "") != norm_key:
                cur.execute(
                    "UPDATE trigger_policies SET scope_group = ? WHERE rowid = ?",
                    (norm_key, winner_rowid),
                )
        conn.commit()
    except Exception as exc:
        logger.warning("trigger_policies normalization migration skipped: %s", exc)


def _backfill_dashboard_users_status(conn: sqlite3.Connection) -> None:
    """Backfill empty/NULL ``status`` to 'active' on legacy rows.

    The ``status`` column was added later (see ``_run_ensure_columns``).
    Existing rows that pre-date the column ended up NULL, but the
    auth path treats anything not in {pending, active, disabled,
    awaiting_approval} as "soft block" because of older signup-flow
    code. Pin them to 'active' so they keep working.
    """
    cur = conn.cursor()
    cur.execute(
        "UPDATE dashboard_users SET status='active' "
        "WHERE status IS NULL OR status = ''"
    )


def _ensure_provisioned_credentials_unique_index(conn: sqlite3.Connection) -> None:
    """Add UNIQUE(mac_nocolon) on provisioned_credentials when safe.

    The original schema didn't enforce uniqueness on ``mac_nocolon``.
    A buggy claim path could double-insert and break later lookups.
    This index plugs the hole — but only when the existing data is
    already clean. If duplicates exist, an operator must dedup
    manually before the index can be created (we don't silently
    delete creds rows because that would orphan a real device).
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT mac_nocolon, COUNT(*) AS c "
        "FROM provisioned_credentials "
        "GROUP BY mac_nocolon HAVING c > 1"
    )
    dup = cur.fetchone()
    if dup:
        logger.warning(
            "provisioned_credentials has duplicate mac_nocolon=%r "
            "(count=%d) — skipping unique index until duplicates are "
            "cleaned up manually",
            str(dup["mac_nocolon"] or ""),
            int(dup["c"] or 0),
        )
        return
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_provisioned_mac_nocolon "
        "ON provisioned_credentials(mac_nocolon)"
    )


def _backfill_device_ownership_cmd_key_shadow(conn: sqlite3.Connection) -> None:
    """Backfill empty ownership cmd_key_shadow from provisioned_credentials.

    Why:
      * ``device_ownership`` is the long-lived binding ledger.
      * ``provisioned_credentials`` is the active runtime credential row.
      * We keep a shadow copy so drift can be detected (and repaired) without
        relying on a single table as the only historical source.

    Policy:
      * Backfill only when ``cmd_key_shadow`` is empty.
      * Do not overwrite non-empty shadow values here; runtime paths perform
        explicit drift checks and controlled repairs with audit/event logs.
    """
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE device_ownership
        SET cmd_key_shadow = (
            SELECT IFNULL(pc.cmd_key, '')
            FROM provisioned_credentials pc
            WHERE pc.device_id = device_ownership.device_id
            LIMIT 1
        )
        WHERE IFNULL(cmd_key_shadow, '') = ''
          AND EXISTS (
            SELECT 1 FROM provisioned_credentials pc
            WHERE pc.device_id = device_ownership.device_id
          )
        """
    )


def run_migrations(conn: sqlite3.Connection) -> None:
    """Run every idempotent migration step.

    Order rationale:
      1. ensure_column — every later step may read columns added here.
      2. trigger_policies normalization — operates on data shape only,
         never schema; safe to run after column adds.
      3. dashboard_users status backfill — column added in step 1.
      4. provisioned_credentials unique index — runs last because the
         dedup check is cheap and the unique constraint we add could
         fail any later INSERTs in this transaction.
    """
    _run_ensure_columns(conn)
    _normalize_trigger_policies(conn)
    _backfill_dashboard_users_status(conn)
    _backfill_device_ownership_cmd_key_shadow(conn)
    _ensure_provisioned_credentials_unique_index(conn)


__all__ = ["run_migrations"]
