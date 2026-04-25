"""Pure leaf helpers extracted from ``app.py`` (Phase-4 modularization).

Three small, dependency-free functions that were defined at module level in
``app.py`` and are imported across the API module graph:

* :func:`utc_now_iso` — canonical UTC ISO timestamp used as the primary
  ``ts`` / ``created_at`` value everywhere (chosen for lexicographic
  ordering inside SQLite).
* :func:`_sibling_group_norm` — Unicode-aware normalisation of
  ``notification_group`` strings so case / accent / whitespace variants
  collide for sibling-fan-out lookups.
* :func:`default_policy_for_role` — the static fallback row inserted into
  ``role_policies`` when a user's policy override is missing.

All three are pure (no DB, no MQTT, no app state). They live here in their
own module so:

1. ``schema.py`` and any future leaf modules can ``from helpers import …``
   at the top of the file instead of doing in-function lazy imports to
   break a synthetic ``app → schema → app`` cycle.
2. The functions can be unit-tested in isolation without booting FastAPI.
3. ``app.py`` shrinks and is easier to audit.

The names and signatures are unchanged so every existing call site keeps
working — ``app.py`` re-exports them via star-import-equivalent so e.g.
``from app import utc_now_iso`` is still legal.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone

__all__ = [
    "utc_now_iso",
    "_sibling_group_norm",
    "default_policy_for_role",
    "contains_insecure_marker",
    "is_hex_16",
    "_normalize_delete_confirm",
]


def utc_now_iso() -> str:
    """UTC ISO string for SQLite storage and lexicographic ordering (canonical ``ts``)."""
    return datetime.now(timezone.utc).isoformat()


def contains_insecure_marker(value: str) -> bool:
    """True when an env value is a CHANGE_ME / placeholder default the
    production-env check refuses to ship with."""
    markers = ["CHANGE_ME", "YOUR_", "your.vps.domain", "bootstrap_user", "bootstrap_pass", "mqtt_pass", "mqtt_user"]
    return any(m in value for m in markers)


def is_hex_16(value: str) -> bool:
    """True when ``value`` is exactly 16 hex characters (the cmd_auth_key /
    challenge-key shape used across the device protocol)."""
    if len(value) != 16:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def _normalize_delete_confirm(raw: str) -> str:
    """Strip invisible chars / odd spacing so pasted confirmation still matches DELETE."""
    s = raw or ""
    s = re.sub(r"[\u200b-\u200d\ufeff]", "", s)
    return re.sub(r"\s+", " ", s).strip().upper()


def _sibling_group_norm(raw: str) -> str:
    """Normalize ``notification_group`` for sibling matching (case-fold + NFC + whitespace)."""
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        s = unicodedata.normalize("NFC", s)
    except Exception:
        pass
    s = " ".join(s.split())
    try:
        return s.casefold()
    except Exception:
        return s.lower()


def default_policy_for_role(role: str) -> dict[str, int]:
    """Built-in policy row for a role when no per-user override exists.

    Three tiers — superadmin (everything on), admin (everything except
    backup/restore), and the implicit "user" tier (everything off). The
    return value is a fresh ``dict`` on every call so callers may mutate
    it freely without leaking state across requests.
    """
    if role == "superadmin":
        return {
            "can_alert": 1,
            "can_send_command": 1,
            "can_claim_device": 1,
            "can_manage_users": 1,
            "can_backup_restore": 1,
            "tg_view_logs": 1,
            "tg_view_devices": 1,
            "tg_siren_on": 1,
            "tg_siren_off": 1,
            "tg_test_single": 1,
            "tg_test_bulk": 1,
        }
    if role == "admin":
        return {
            "can_alert": 1,
            "can_send_command": 1,
            "can_claim_device": 1,
            "can_manage_users": 1,
            "can_backup_restore": 0,
            "tg_view_logs": 1,
            "tg_view_devices": 1,
            "tg_siren_on": 1,
            "tg_siren_off": 1,
            "tg_test_single": 1,
            "tg_test_bulk": 1,
        }
    return {
        "can_alert": 0,
        "can_send_command": 0,
        "can_claim_device": 0,
        "can_manage_users": 0,
        "can_backup_restore": 0,
        "tg_view_logs": 0,
        "tg_view_devices": 0,
        "tg_siren_on": 0,
        "tg_siren_off": 0,
        "tg_test_single": 0,
        "tg_test_bulk": 0,
    }
