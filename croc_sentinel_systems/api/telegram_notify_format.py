"""Pure event → Telegram-message formatting (Phase-75 split from
``telegram_notify.py``).

The original ``_TelegramQueue.maybe_enqueue`` mixed three concerns:

  1. ENV parsing (``_strip_bom``, ``_parse_chat_ids``, level-rank lookup).
  2. Per-event filtering (duplicate-event suppression, level/category
     gates) and message-line composition (the 120-line block that
     turns an event dict into a multi-line ``[INFO] auth/login\\n…``
     blob).
  3. Queue management + HTTP send (threads, SSL, urllib).

This module owns concerns #1 and #2 so the queue/transport half of
``telegram_notify.py`` reads as: "filter (delegate) → format
(delegate) → enqueue → worker → send". The transport class still lives
in ``telegram_notify.py`` because that's where the singleton + worker
thread + SSL context plumbing belong.

Everything here is **stateless** and **side-effect free** — no
sockets, no env reads, no logging that mutates module state.
``format_event_for_chat`` is the single entry point used by
``_TelegramQueue.maybe_enqueue``; it returns ``None`` whenever the
event should be dropped (true duplicate, or no eligible channel
under the supplied env budget). On a hit it returns the composed
text line plus the dedupe fingerprint and the resolved channel
plan, so the caller's responsibilities collapse to:

    plan = format_event_for_chat(ev, env_chats=…, extras=…, min_rank=…)
    if plan is None:
        return
    text, fingerprint, targets = plan
    enqueue((text, targets))

Public API
----------
  _LEVEL_RANK              — debug=0, info=1, warn=2, error=3, critical=4
  _strip_bom               — UTF-8 BOM/quote stripper for env values
  _parse_chat_ids          — split TELEGRAM_CHAT_IDS on ASCII + CJK separators
  is_env_eligible          — env-channel level + category gate (excluding extras)
  is_duplicate_event       — true-duplicate suppressor (alarm-only fan-out twins)
  format_event_for_chat    — full pipeline: filter → compose → resolve targets

The ENV / extras separation is preserved verbatim from the original:
``env_chats`` go through level + category filters; ``extras`` (per-
event chat_ids, e.g. superadmin firehose bindings) bypass them. The
true-duplicate filter applies to **everyone** including extras —
that's a correctness invariant, not a setting.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

_LEVEL_RANK = {"debug": 0, "info": 1, "warn": 2, "error": 3, "critical": 4}


def _strip_bom(s: str) -> str:
    """Strip UTF-8 BOM and stray surrounding quotes from env values.

    Cursor / VS Code / Notepad sometimes inject a BOM at the head of
    .env files; copy-pasting Telegram tokens occasionally drags
    quotes along. Be liberal in what we accept.
    """
    s = (s or "").strip()
    if s.startswith("\ufeff"):
        s = s[1:].strip()
    return s.strip().strip('"').strip("'")


def _parse_chat_ids(raw: str) -> list[str]:
    """Split ``TELEGRAM_CHAT_IDS`` on commas / semicolons / whitespace.

    Accepts both ASCII separators and the CJK fullwidth comma (``、``)
    and fullwidth semicolon (``；``) so operators pasting from a
    Chinese keyboard layout don't end up with a single concatenated
    chat-id string.
    """
    import re
    raw = _strip_bom(raw.replace("\u3001", ",").replace("\uff1b", ";"))
    out: list[str] = []
    for part in re.split(r"[\s,;]+", raw):
        p = part.strip().strip('"').strip("'")
        if not p:
            continue
        out.append(p)
    return out


def is_duplicate_event(ev: dict[str, Any]) -> bool:
    """Return True if this event is a known duplicate of another we send.

    The alarm pipeline emits two parallel events for every fan-out:

      * ``alarm/*``       — the canonical, normalized record
      * ``device/alarm.trigger.*`` — the raw device-level twin
      * ``audit.alarm.fanout*``    — the audit echo

    Sending all three would triple-spam every operator chat. We keep
    the canonical ``alarm/*`` record and drop the other two here.

    This applies to **every** channel including superadmin firehose
    extras — duplicates are duplicates regardless of subscriber type.
    """
    cat = str(ev.get("category") or "")
    et = str(ev.get("event_type") or "")
    if cat == "device" and "alarm.trigger" in et:
        return True
    if et.startswith("audit.alarm.fanout"):
        return True
    return False


def is_env_eligible(ev: dict[str, Any], min_rank: int) -> bool:
    """Env-channel level + category gate.

    Env subscribers (``TELEGRAM_CHAT_IDS``) are operator-curated and
    expect a "signal-clean" feed:

      * Below the configured ``TELEGRAM_MIN_LEVEL`` is dropped.
      * info/debug events outside the {alarm, auth, ota} categories
        are also dropped (general-noise filter).

    Per-event extras (e.g. superadmin firehose bindings stored in
    the DB) bypass this filter — they explicitly want the firehose.
    """
    lvl = str(ev.get("level") or "info").lower()
    cat = str(ev.get("category") or "")
    if _LEVEL_RANK.get(lvl, 1) < min_rank:
        return False
    if lvl in ("debug", "info") and cat not in ("alarm", "auth", "ota"):
        return False
    return True


def _extract_detail_map(ev: dict[str, Any]) -> dict[str, Any]:
    """Pluck the subset of ``ev['detail']`` keys we surface in chat lines.

    We deliberately allow-list keys so a future event type with a
    1 MB blob can't blow up Telegram's 4 KiB message budget. Order
    of keys here mirrors the order they're rendered in
    ``format_event_for_chat``.
    """
    detail_map: dict[str, Any] = {}
    try:
        d = ev.get("detail") or {}
        if not isinstance(d, dict) or not d:
            return detail_map
        keep: dict[str, Any] = {}
        for k in ("reason", "error", "result", "state", "duration_ms", "fanout_count"):
            if k in d and d.get(k) not in (None, ""):
                keep[k] = d.get(k)
        if "login_user" in d and d.get("login_user") not in (None, ""):
            keep["login_user"] = d.get("login_user")
        for k in ("ip", "platform", "device_type", "mac_hint", "geo"):
            if k in d and d.get(k) not in (None, ""):
                keep[k] = d.get(k)
        if "owner_admin" in d and d.get("owner_admin") not in (None, ""):
            keep["owner_admin"] = d.get("owner_admin")
        if "device_ids" in d and isinstance(d.get("device_ids"), list):
            keep["device_ids"] = d.get("device_ids")
        if "owner_admins" in d and isinstance(d.get("owner_admins"), list):
            keep["owner_admins"] = d.get("owner_admins")
        for k in ("trigger_kind", "client_kind"):
            if k in d and d.get(k) not in (None, ""):
                keep[k] = d.get(k)
        detail_map = keep
    except Exception:
        pass
    return detail_map


def _resolve_trigger_label(detail_map: dict[str, Any]) -> str:
    """Map raw trigger codes to human labels for the ``trigger:`` line.

    ``remote_button`` → ``push_button`` (matches dashboard term).
    ``api``           → ``web/app``    (originator was an HTTP client).
    Anything else passes through unchanged so future trigger codes
    don't need a code change here to render readably.
    """
    trigger = str(detail_map.get("trigger_kind") or detail_map.get("client_kind") or "")
    if trigger == "remote_button":
        return "push_button"
    if trigger == "api":
        return "web/app"
    return trigger


def _device_name_from_summary(summary: str) -> str:
    """Best-effort device label parse out of the summary line.

    Event summaries are conventionally ``"<label> · <verb-phrase>"``
    or ``"[<zone>] <label> · <verb-phrase>"``. We pull the part
    before the first ``·`` and strip the optional ``[zone]`` prefix.
    Returns ``""`` when the summary doesn't look like that shape.
    """
    if "·" not in summary:
        return ""
    dev_name = summary.split("·", 1)[0].strip()
    if dev_name.startswith("[") and "]" in dev_name:
        dev_name = dev_name.split("]", 1)[1].strip() or dev_name
    return dev_name


def _compose_text(ev: dict[str, Any], detail_map: dict[str, Any]) -> str:
    """Compose the multi-line message body for an event.

    Layout shapes:

      auth/login → label by ``login_user``, then actor + target.
      alarm/*    → label by event_type, then device + actor + target.
      else       → category/event_type, device + actor + target.

    Common tail lines (when present in detail_map):
      device_name, trigger, owner_admin, device_ids[…12], owner_admins[…12],
      ip / geo / platform / device_type / mac_hint /
      reason / error / result / state / duration_ms / fanout_count.
    """
    lvl = str(ev.get("level") or "info").lower()
    cat = str(ev.get("category") or "")
    et = str(ev.get("event_type") or "")
    actor = str(ev.get("actor") or "-")
    target = str(ev.get("target") or "-")
    device_id = str(ev.get("device_id") or "-")
    summary = str(ev.get("summary") or et or "").strip()
    trigger = _resolve_trigger_label(detail_map)
    dev_name = _device_name_from_summary(summary)

    if cat == "auth" and ("login" in et):
        who = str(detail_map.get("login_user") or target or actor or "-")
        lines = [
            f"[{lvl.upper()}] auth/login",
            f"user: {who}",
            f"actor: {actor}",
            f"target: {target}",
        ]
    elif cat == "alarm":
        if device_id in ("", "-", "none", "None"):
            dids = detail_map.get("device_ids") if isinstance(detail_map.get("device_ids"), list) else []
            if dids:
                device_id = str(dids[0])
        lines = [
            f"[{lvl.upper()}] alarm",
            f"event: {et}",
            f"device: {device_id}",
            f"actor: {actor}",
            f"target: {target}",
        ]
    else:
        lines = [
            f"[{lvl.upper()}] {cat}/{et}",
            f"device: {device_id}",
            f"actor: {actor}",
            f"target: {target}",
        ]
    if summary:
        lines.insert(1, summary)
    if dev_name:
        lines.insert(3, f"device_name: {dev_name}")
    if trigger:
        lines.append(f"trigger: {trigger}")
    if "owner_admin" in detail_map and detail_map.get("owner_admin") not in (None, ""):
        lines.append(f"owner_admin: {detail_map.get('owner_admin')}")
    if "device_ids" in detail_map and isinstance(detail_map.get("device_ids"), list):
        dids = [str(x) for x in detail_map.get("device_ids") if str(x).strip()]
        if dids:
            lines.append(f"device_ids: {','.join(dids[:12])}")
    if "owner_admins" in detail_map and isinstance(detail_map.get("owner_admins"), list):
        ows = [str(x) for x in detail_map.get("owner_admins") if str(x).strip()]
        if ows:
            lines.append(f"owner_admins: {','.join(ows[:12])}")
    for k in (
        "ip", "geo", "platform", "device_type", "mac_hint",
        "reason", "error", "result", "state", "duration_ms", "fanout_count",
    ):
        if k in detail_map and detail_map.get(k) not in (None, ""):
            lines.append(f"{k}: {detail_map.get(k)}")
    return "\n".join(lines)


def _compute_fingerprint(ev: dict[str, Any]) -> str:
    """Stable 1-line key used to suppress near-duplicate spam.

    ``level|category|event_type|device_id|summary`` is granular enough
    that distinct alarms on the same device still pass (the summary
    differs) but a retry storm on the same event collapses to one
    delivery within the dedupe window.
    """
    lvl = str(ev.get("level") or "info").lower()
    cat = str(ev.get("category") or "")
    et = str(ev.get("event_type") or "")
    device_id = str(ev.get("device_id") or "-")
    summary = str(ev.get("summary") or et or "").strip()
    return f"{lvl}|{cat}|{et}|{device_id}|{summary}"


def _resolve_targets(
    *,
    env_chats: Iterable[str],
    extras: Iterable[str],
    env_eligible: bool,
    extras_eligible: bool,
) -> list[str]:
    """Union env_chats and extras into a deduped target list.

    Order: env first (matches original behavior), then extras. Empty
    or whitespace-only ids are dropped silently. Same id appearing
    in both lists is sent to once.
    """
    final_targets: list[str] = []
    seen: set[str] = set()
    if env_eligible:
        for c in env_chats:
            cs = str(c).strip()
            if cs and cs not in seen:
                seen.add(cs)
                final_targets.append(cs)
    if extras_eligible:
        for c in extras:
            cs = str(c).strip()
            if cs and cs not in seen:
                seen.add(cs)
                final_targets.append(cs)
    return final_targets


def format_event_for_chat(
    ev: dict[str, Any],
    *,
    env_chats: list[str],
    extras: list[str],
    min_rank: int,
) -> Optional[tuple[str, str, list[str]]]:
    """Run the full enqueue-time pipeline and return the message plan.

    Returns ``None`` when the event should be dropped (true duplicate
    via :func:`is_duplicate_event`, no eligible channel after env
    filtering, or no resolvable target ids after dedup).

    Returns ``(text, fingerprint, targets)`` on a hit, where:

      * ``text`` — the composed multi-line message body to send.
      * ``fingerprint`` — caller uses this against its dedupe map to
        collapse retries within the configured window.
      * ``targets`` — final, ordered, deduped list of chat_ids the
        worker should ``sendMessage`` to.

    The caller is responsible for the dedupe-window check and the
    actual queue insertion — this function is pure and stateless.
    """
    if is_duplicate_event(ev):
        return None
    extras_clean = [str(c).strip() for c in (extras or []) if str(c).strip()]
    env_eligible = bool(env_chats) and is_env_eligible(ev, min_rank)
    extras_eligible = bool(extras_clean)
    if not (env_eligible or extras_eligible):
        return None
    detail_map = _extract_detail_map(ev)
    text = _compose_text(ev, detail_map)
    fingerprint = _compute_fingerprint(ev)
    targets = _resolve_targets(
        env_chats=env_chats,
        extras=extras_clean,
        env_eligible=env_eligible,
        extras_eligible=extras_eligible,
    )
    if not targets:
        return None
    return text, fingerprint, targets


__all__ = [
    "_LEVEL_RANK",
    "_strip_bom",
    "_parse_chat_ids",
    "is_duplicate_event",
    "is_env_eligible",
    "format_event_for_chat",
]
