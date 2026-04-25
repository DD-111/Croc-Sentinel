"""Audit log helpers extracted from ``app.py`` (Phase-6 modularization).

Three pieces:

* :data:`_HIGH_RISK_AUDIT_PREFIXES` — the action prefixes whose successful
  completion still warrants warn-level fan-out (Telegram / email).
* :func:`_audit_action_is_high_risk` — boolean wrapper around the prefix
  check, kept private because the action-string contract belongs to this
  module.
* :func:`audit_event` — write a row into ``audit_events`` *and* mirror the
  same record into the unified event center so a superadmin watching the
  live feed sees audit entries inline with alarms / OTA / presence.

Why not also move ``emit_event`` here? Because ``emit_event`` itself
depends on a dozen other helpers still living in ``app.py`` (event_bus,
_insert_event_row, _redis_event_forward, _maybe_dispatch_fcm_for_ev,
telegram_notify glue, etc.). That is its own, larger phase. Until then,
this module reaches into ``app`` *at call time* via attribute access:
``app.emit_event(...)``. The ``import app`` at module top is safe because
Python's partial-load semantics give us the module object as soon as
``app.py`` starts loading, and ``app.emit_event`` is resolved at call
time — well after ``app.py`` has finished loading.

The same trick is used for ``_VALID_CATEGORIES``, the canonical category
allow-list that emit_event also consults. Keeping a single source of
truth in ``app.py`` for now beats duplicating the tuple here.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import app  # late-bound access to emit_event and _VALID_CATEGORIES; see docstring
from db import db_lock, get_conn
from helpers import utc_now_iso

__all__ = [
    "_HIGH_RISK_AUDIT_PREFIXES",
    "_audit_action_is_high_risk",
    "audit_event",
]


# Actions that are *irreversible* or *security-sensitive* and deserve a warn-level
# event → Telegram/email notification even when the action itself succeeded.
# Matched as prefixes so e.g. "device.unclaim" and "device.unclaim_reset" both hit.
_HIGH_RISK_AUDIT_PREFIXES: tuple[str, ...] = (
    "device.unclaim",
    "device.factory_unregister",
    "device.factory_unlink",
    "device.revoke",
    "device.delete",
    "user.delete",
    "user.deactivate",
    "admin.close",
    "admin.hard_close",
    "admin.suspend",
    "admin.delete",
    "ota.rollback",
    "ota.force_rollback",
    "bootstrap.unblock",
    "security.key_rotate",
)


def _audit_action_is_high_risk(action: str) -> bool:
    a = (action or "").lower()
    return any(a.startswith(p) for p in _HIGH_RISK_AUDIT_PREFIXES)


def audit_event(actor: str, action: str, target: str = "", detail: Optional[dict[str, Any]] = None) -> None:
    """Legacy audit log helper — kept for compatibility but now ALSO mirrors
    the entry into the unified event center so the superadmin sees it live.
    """
    audit_id = 0
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_events (actor, action, target, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor,
                action,
                target,
                json.dumps(detail or {}, ensure_ascii=True),
                utc_now_iso(),
            ),
        )
        audit_id = int(cur.lastrowid or 0)
        conn.commit()
        conn.close()

    parts = str(action).split(".", 1)
    cat_hint = parts[0] if parts else "audit"
    category = cat_hint if cat_hint in app._VALID_CATEGORIES else "audit"
    # Heuristic severity: *.fail / rollback / revoke / reject → warn; error → error.
    low = action.lower()
    if "fail" in low or "reject" in low or "revoke" in low or "rollback" in low or "block" in low:
        level = "warn"
    elif "error" in low or "crash" in low:
        level = "error"
    else:
        level = "info"
    # Escalate irreversible / security-sensitive actions to warn so Telegram /
    # email fan-out notifies the superadmin even on a clean success path.
    if level == "info" and _audit_action_is_high_risk(action):
        level = "warn"
    owner_admin = None
    device_id = None
    if isinstance(detail, dict):
        owner_admin = detail.get("owner_admin") or None
        device_id = detail.get("device_id") or None
    # "device:<id>" actor convention used elsewhere.
    if not device_id and str(actor).startswith("device:"):
        device_id = actor.split(":", 1)[1]
    app.emit_event(
        level=level,
        category=category,
        event_type=f"audit.{action}",
        summary=f"{actor} {action} {target}".strip(),
        actor=actor,
        target=target,
        owner_admin=owner_admin,
        device_id=device_id,
        detail=detail or {},
        ref_table="audit_events",
        ref_id=audit_id,
    )
