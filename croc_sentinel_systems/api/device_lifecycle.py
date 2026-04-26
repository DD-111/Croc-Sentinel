"""Device lifecycle state + version transitions (DB-first helper).

Single write path for lifecycle transitions to avoid duplicated SQL across
routers/helpers. This module is intentionally cursor-only so callers can keep
their existing transaction boundaries.
"""

from __future__ import annotations

from typing import Optional

from helpers import utc_now_iso

LIFECYCLE_ACTIVE = "ACTIVE"
LIFECYCLE_UNBOUND = "UNBOUND"
LIFECYCLE_RESETTING = "RESETTING"
LIFECYCLE_OFFLINE = "OFFLINE"

_ALLOWED_STATES = {
    LIFECYCLE_ACTIVE,
    LIFECYCLE_UNBOUND,
    LIFECYCLE_RESETTING,
    LIFECYCLE_OFFLINE,
}


def transition_device_lifecycle_cur(
    cur,
    device_id: str,
    state: str,
    *,
    owner_admin: Optional[str] = None,
    bump_version: bool = False,
) -> int:
    """Upsert lifecycle row and optionally increment version.

    Returns the current version after transition.
    """
    st = str(state or "").strip().upper()
    if st not in _ALLOWED_STATES:
        raise ValueError(f"invalid lifecycle state: {state!r}")
    did = str(device_id or "").strip()
    if not did:
        raise ValueError("device_id is required")
    now = utc_now_iso()
    owner = str(owner_admin or "")
    cur.execute(
        """
        INSERT INTO device_lifecycle (device_id, lifecycle_state, lifecycle_version, owner_admin, updated_at)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            lifecycle_state = excluded.lifecycle_state,
            lifecycle_version = CASE
                WHEN ? THEN device_lifecycle.lifecycle_version + 1
                ELSE device_lifecycle.lifecycle_version
            END,
            owner_admin = excluded.owner_admin,
            updated_at = excluded.updated_at
        """,
        (did, st, owner, now, 1 if bump_version else 0),
    )
    cur.execute("SELECT lifecycle_version FROM device_lifecycle WHERE device_id = ? LIMIT 1", (did,))
    row = cur.fetchone()
    return int(row["lifecycle_version"] if row and row["lifecycle_version"] is not None else 1)


__all__ = [
    "LIFECYCLE_ACTIVE",
    "LIFECYCLE_UNBOUND",
    "LIFECYCLE_RESETTING",
    "LIFECYCLE_OFFLINE",
    "transition_device_lifecycle_cur",
]

