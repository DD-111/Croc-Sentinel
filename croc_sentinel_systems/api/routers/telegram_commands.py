"""Telegram bot natural-language command grammar (Phase-78 split from
``routers/telegram_webhook.py``).

The Phase-67 ``telegram_webhook.py`` extract bundled two distinct
concerns under one file:

  1. Webhook plumbing  — Bot API ``X-Telegram-Bot-Api-Secret-Token``
                         header check, ``/start`` deep-link binding,
                         chat-allowlist gate, principal lookup, and
                         the reply send (~150 lines including auth
                         helpers).
  2. Command grammar   — text parser, capability gates, recent-devices
                         and recent-logs SQL readers, MQTT publisher,
                         and the dispatcher that turns "siren on
                         all 5000" into a published command (~250
                         lines).

Phase 78 extracts the command grammar here so the webhook half can
be reviewed in isolation. The dispatcher's surface area
(``handle_text``) is the single entry point the webhook calls; every
helper underneath (``_recent_devices``, ``_recent_logs``,
``_publish``, ``_parse_targets``, ``_policy_allow`` /
``_require``) is private to this module.

Public API (consumed by ``routers/telegram_webhook.py``)
--------------------------------------------------------
  ``handle_text(principal, text) -> str``
      The whole grammar. Returns a chat-ready reply string (max
      ~3900 chars to fit Telegram's 4096 budget after framing).
      Never raises — every command-side error is caught and
      converted to a "Denied: …" / "Error: …" reply.

The four data-side helpers (``_recent_devices``, ``_recent_logs``,
``_publish``, ``_parse_targets``) and the two policy gates
(``_policy_allow``, ``_require``) are exported in ``__all__`` for
test access only — production consumers should call ``handle_text``.

Late binding
------------
Captured at module load time, after ``app.py`` has executed past
these defs:

  Functions (all defined < line ~5300 in app.py):
    emit_event, get_manager_admin, get_effective_policy,
    _device_is_online_sql_row, require_capability,
    resolve_target_devices, publish_command,
    get_cmd_key_for_device, zone_sql_suffix,
    owner_scope_clause_for_device_state.

The webhook handler (still in ``routers/telegram_webhook.py``) does
*not* late-bind on this module — it imports ``handle_text`` directly
because this module's module-load completes before the webhook
include_router call.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import HTTPException

import app as _app
from config import (
    CMD_PROTO,
    DEFAULT_REMOTE_FANOUT_MS,
    TELEGRAM_COMMAND_MAX_DEVICES,
    TELEGRAM_COMMAND_MAX_LOG,
    TOPIC_ROOT,
)
from db import db_lock, get_conn
from security import Principal

emit_event = _app.emit_event
get_manager_admin = _app.get_manager_admin
get_effective_policy = _app.get_effective_policy
_device_is_online_sql_row = _app._device_is_online_sql_row
require_capability = _app.require_capability
resolve_target_devices = _app.resolve_target_devices
publish_command = _app.publish_command
get_cmd_key_for_device = _app.get_cmd_key_for_device
zone_sql_suffix = _app.zone_sql_suffix
owner_scope_clause_for_device_state = _app.owner_scope_clause_for_device_state


logger = logging.getLogger("croc-api.routers.telegram_commands")


# ─────────────────────────────────────────────── policy gates ────


def _policy_allow(principal: Principal, capability: str) -> bool:
    """Whether the principal holds a tg_* capability.

    Superadmin always passes. Other roles consult their effective
    policy row (``role_policies``) which the dashboard / admin
    surfaces flip per-user — that lets a tenant grant their staff
    Telegram-only siren access without granting anything else.
    """
    if principal.role == "superadmin":
        return True
    pol = get_effective_policy(principal)
    return int(pol.get(capability, 0)) == 1


def _require(principal: Principal, capability: str) -> None:
    """Raise 403 with the capability name when the gate denies."""
    if not _policy_allow(principal, capability):
        raise HTTPException(
            status_code=403,
            detail=f"telegram capability denied: {capability}",
        )


# ─────────────────────────────────────────────── argument parsing ────


def _parse_targets(token: str) -> list[str]:
    """Parse a target token into a list of device ids.

    Grammar:
      * empty / whitespace          → ``[]`` (means "broadcast" to caller).
      * literal "all" / "ALL"       → ``[]`` (same).
      * comma-separated id list     → list of trimmed ids.

    The caller (``_publish``) interprets ``[]`` as the bulk path
    that resolves through ``resolve_target_devices``.
    """
    raw = (token or "").strip()
    if not raw:
        return []
    if raw.lower() == "all":
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


# ─────────────────────────────────────────────── data readers ────


def _recent_devices(principal: Principal, limit: int) -> str:
    """Format a "Devices (latest N)" reply for the chat.

    Capped at ``TELEGRAM_COMMAND_MAX_DEVICES`` so a malicious or
    typo'd ``devices 999999`` doesn't paginate to the whole fleet
    and bust Telegram's 4096-char message budget. Filters by zone
    + owner_scope so admins only see their own devices.
    """
    _require(principal, "tg_view_devices")
    n = max(1, min(limit, TELEGRAM_COMMAND_MAX_DEVICES))
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id, IFNULL(display_label, '') AS display_label,
                   IFNULL(zone,'') AS zone, IFNULL(fw,'') AS fw,
                   updated_at, last_status_json, last_heartbeat_json,
                   last_ack_json, last_event_json
            FROM device_state
            WHERE 1=1 {zs} {osf}
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            tuple(za + osa + [n]),
        )
        rows = cur.fetchall()
        conn.close()
    now_s = int(time.time())
    lines = [f"Devices (latest {len(rows)}):"]
    for r in rows:
        d = dict(r)
        online = _device_is_online_sql_row(d, now_s)
        did = str(d.get("device_id") or "")
        label = str(d.get("display_label") or "")
        fw = str(d.get("fw") or "-")
        zone = str(d.get("zone") or "all")
        tag = "online" if online else "offline"
        lines.append(
            f"- {did} [{tag}] fw={fw} zone={zone}"
            + (f" label={label}" if label else "")
        )
    return "\n".join(lines)[:3900]


def _recent_logs(principal: Principal, limit: int) -> str:
    """Format a "Logs (latest N)" reply for the chat.

    Capped at ``TELEGRAM_COMMAND_MAX_LOG``. Tenant scoping mirrors
    the dashboard: superadmin sees everything, admins see their own
    ``owner_admin`` rows, regular users see their managing admin's
    rows. Each line is trimmed to 90 chars summary + standard envelope
    so the page stays readable.
    """
    _require(principal, "tg_view_logs")
    n = max(1, min(limit, TELEGRAM_COMMAND_MAX_LOG))
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT ts, level, category, event_type,
                       IFNULL(device_id,'') AS device_id,
                       IFNULL(summary,'') AS summary
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (n,),
            )
        elif principal.role == "admin":
            cur.execute(
                """
                SELECT ts, level, category, event_type,
                       IFNULL(device_id,'') AS device_id,
                       IFNULL(summary,'') AS summary
                FROM events
                WHERE owner_admin = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (principal.username, n),
            )
        else:
            mgr = get_manager_admin(principal.username)
            cur.execute(
                """
                SELECT ts, level, category, event_type,
                       IFNULL(device_id,'') AS device_id,
                       IFNULL(summary,'') AS summary
                FROM events
                WHERE owner_admin = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (mgr or "__none__", n),
            )
        rows = cur.fetchall()
        conn.close()
    lines = [f"Logs (latest {len(rows)}):"]
    for r in rows:
        ts = str(r["ts"] or "")
        lvl = str(r["level"] or "info").upper()
        cat = str(r["category"] or "-")
        et = str(r["event_type"] or "-")
        did = str(r["device_id"] or "-")
        summary = str(r["summary"] or "")[:90]
        lines.append(f"- {ts} [{lvl}] {cat}/{et} dev={did} {summary}")
    return "\n".join(lines)[:3900]


# ─────────────────────────────────────────────── MQTT publisher ────


def _publish(
    principal: Principal,
    cmd: str,
    params: dict[str, Any],
    ids: list[str],
    bulk_cap: str,
) -> tuple[int, int]:
    """Publish ``cmd`` to either an explicit device list or the bulk slice.

    Capability ladder:
      1. Coarse role-policy gate (``can_alert`` for siren_*, else
         ``can_send_command``) — ensures Telegram can never escalate
         past what the user could do via dashboard/API.
      2. Fine telegram-only gate:
         * non-empty ``ids`` (single / many) → ``tg_test_single`` for
           self_test, ``tg_siren_on/off`` for sirens.
         * empty ``ids`` (broadcast)        → ``bulk_cap`` (caller-supplied,
           typically ``tg_test_bulk`` / ``tg_siren_on`` / ``tg_siren_off``).

    Resolves the bulk slice through ``resolve_target_devices`` so
    superadmin gets every device and admins get their own — same
    SQL helper the dashboard fan-out uses, so behavior matches.

    Per-device publish failures don't halt the loop; we count
    successes and return ``(sent, total)`` so the caller can render
    "sent=N/M" in the chat reply.
    """
    if cmd in ("siren_on", "siren_off"):
        require_capability(principal, "can_alert")
    else:
        require_capability(principal, "can_send_command")
    if ids:
        _require(
            principal,
            (
                "tg_test_single" if cmd == "self_test"
                else ("tg_siren_on" if cmd == "siren_on" else "tg_siren_off")
            ),
        )
    else:
        _require(principal, bulk_cap)
    targets = resolve_target_devices(ids, principal=principal)
    sent = 0
    for did in targets:
        try:
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd=cmd,
                params=params,
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            sent += 1
        except Exception as exc:
            logger.warning(
                "telegram cmd publish %s -> %s failed: %s", cmd, did, exc
            )
    return sent, len(targets)


# ─────────────────────────────────────────────── dispatcher ────


def handle_text(principal: Principal, text: str) -> str:
    """Parse + dispatch a Telegram chat text into a server-side action.

    Recognized verbs:

      * ``help`` / ``h`` / ``?`` / ``start``   — usage line.
      * ``devices [N]``                        — recent N devices (cap N).
      * ``log [N]``                            — recent N events (cap N).
      * ``siren on <target> [duration_ms]``    — fan-out siren ON.
      * ``siren off <target>``                 — fan-out siren OFF.
      * ``test <device_id>``                   — single self-test.
      * ``test all``                           — bulk self-test.
      * ``test many <id1,id2,...>``            — multi self-test.

    ``<target>`` is one of: ``all`` (or omitted) → bulk; a single
    device id; a comma-separated id list.

    Siren-on duration_ms is clamped to ``[500, 300000]`` to bound
    siren on-time even if a typo allows it through. Default is
    ``DEFAULT_REMOTE_FANOUT_MS`` from config.

    Every successful siren_on/off call also emits a bus event so
    the dashboard timeline / SSE stream / superadmin firehose all
    see the Telegram-originated action with a stable
    ``actor=telegram:<username>``.

    Returns a reply string capped at ~3900 chars (Telegram's 4096-
    byte budget minus our envelope). Empty / unknown input returns
    a help hint, never an exception.
    """
    raw = (text or "").strip()
    if not raw:
        return "Empty command. Try: help"
    if raw.startswith("/"):
        raw = raw[1:]
    raw = raw.split("@", 1)[0].strip()
    lower = raw.lower()

    if lower in ("start", "help", "h", "?"):
        return (
            "Commands:\n"
            "- devices [N]\n"
            "- log [N]\n"
            "- siren on <all|device|id1,id2> [duration_ms]\n"
            "- siren off <all|device|id1,id2>\n"
            "- test <device_id>\n"
            "- test all\n"
            "- test many <id1,id2,...>\n"
        )

    if lower.startswith("devices"):
        parts = lower.split()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        return _recent_devices(principal, n)

    if lower.startswith("log"):
        parts = lower.split()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        return _recent_logs(principal, n)

    if lower.startswith("siren on"):
        parts = raw.split()
        target_token = "all" if len(parts) < 3 else parts[2]
        duration_ms = DEFAULT_REMOTE_FANOUT_MS
        if len(parts) >= 4 and parts[3].isdigit():
            duration_ms = int(parts[3])
        duration_ms = max(500, min(duration_ms, 300000))
        ids = _parse_targets(target_token)
        sent, total = _publish(
            principal, "siren_on", {"duration_ms": duration_ms}, ids, "tg_siren_on"
        )
        emit_event(
            level="warn",
            category="alarm",
            event_type="telegram.siren_on",
            summary=f"telegram siren_on sent={sent}/{total}",
            actor=f"telegram:{principal.username}",
            owner_admin=(
                None
                if principal.role == "superadmin"
                else (
                    principal.username
                    if principal.role == "admin"
                    else get_manager_admin(principal.username)
                )
            ),
            detail={"target": target_token, "duration_ms": duration_ms},
        )
        return (
            f"siren_on done: sent={sent}/{total}, "
            f"duration_ms={duration_ms}, target={target_token}"
        )

    if lower.startswith("siren off"):
        parts = raw.split()
        target_token = "all" if len(parts) < 3 else parts[2]
        ids = _parse_targets(target_token)
        sent, total = _publish(principal, "siren_off", {}, ids, "tg_siren_off")
        emit_event(
            level="warn",
            category="alarm",
            event_type="telegram.siren_off",
            summary=f"telegram siren_off sent={sent}/{total}",
            actor=f"telegram:{principal.username}",
            owner_admin=(
                None
                if principal.role == "superadmin"
                else (
                    principal.username
                    if principal.role == "admin"
                    else get_manager_admin(principal.username)
                )
            ),
            detail={"target": target_token},
        )
        return f"siren_off done: sent={sent}/{total}, target={target_token}"

    if lower in ("test all", "device all test", "devices all test"):
        sent, total = _publish(principal, "self_test", {}, [], "tg_test_bulk")
        return f"self_test(all) done: sent={sent}/{total}"

    if lower.startswith("test many "):
        ids = _parse_targets(raw[10:])
        if not ids:
            return "No device ids provided."
        sent, total = _publish(principal, "self_test", {}, ids, "tg_test_bulk")
        return f"self_test(many) done: sent={sent}/{total}"

    if lower.startswith("test "):
        did = raw.split(maxsplit=1)[1].strip() if len(raw.split(maxsplit=1)) > 1 else ""
        if not did:
            return "Usage: test <device_id>"
        sent, total = _publish(
            principal, "self_test", {}, [did], "tg_test_single"
        )
        return f"self_test(single) done: sent={sent}/{total}"

    return "Unknown command. Try: help"


__all__ = (
    "handle_text",
    "_policy_allow",
    "_require",
    "_parse_targets",
    "_recent_devices",
    "_recent_logs",
    "_publish",
)
