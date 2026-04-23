"""
Human-facing timestamps in Asia/Kuala_Lumpur (UTC+08, no DST).

Internal DB rows and API field `ts` may remain UTC ISO for ordering and
compat; use `iso_timestamp_to_malaysia` or `malaysia_now_iso` for emails,
labels, and optional `ts_malaysia` on emitted events.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo

    MY_TZ = ZoneInfo("Asia/Kuala_Lumpur")
except Exception:  # pragma: no cover — minimal env without IANA tzdata
    MY_TZ = timezone(timedelta(hours=8))


def malaysia_now_iso(timespec: str = "seconds") -> str:
    """Current wall clock in Malaysia as ISO 8601 with +08:00 offset."""
    return datetime.now(MY_TZ).isoformat(timespec=timespec)


def iso_timestamp_to_malaysia(iso_str: str | None, *, timespec: str = "seconds") -> str:
    """Parse ISO 8601 (Z or numeric offset) and format in Asia/Kuala_Lumpur."""
    if not iso_str:
        return ""
    s = str(iso_str).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(MY_TZ).isoformat(timespec=timespec)
    except Exception:
        return str(iso_str)
