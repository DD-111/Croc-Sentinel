"""Shared factory serial / signed QR generation + optional server registration."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CROCKFORD = "ABCDEFGHJKLMNPQRSTUVWXYZ234567"

# Default API root when .env does not set FACTORY_UI_API_BASE (no path suffix; /factory/* on this host).
# Production: API behind Traefik with PathPrefix /api (StripPrefix). Use /api — no trailing slash.
DEFAULT_FACTORY_UI_API_BASE = "https://esasecure.com/api"

DEFAULT_QR_POLICY = re.compile(
    r"^CROC\|SN-[A-Z2-7]{16}\|\d{10}\|[A-Za-z0-9_-]{20,120}$"
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_dotenv_path() -> Path:
    return repo_root() / "croc_sentinel_systems" / ".env"


def read_dotenv_keys(path: Path, keys: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {k: "" for k in keys}
    keyset = set(keys)
    if not path.is_file():
        return out
    # utf-8-sig strips BOM; allow "KEY=value" or "KEY = value".
    for line in path.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        name, _, rest = s.partition("=")
        name = name.strip()
        if name not in keyset:
            continue
        val = rest.strip().strip('"').strip("'")
        if "#" in val and not (val.startswith('"') and val.endswith('"')):
            val = val.split("#", 1)[0].strip()
        out[name] = val
    return out


def random_serial() -> str:
    return "SN-" + "".join(secrets.choice(CROCKFORD) for _ in range(16))


def sign_qr(serial: str, ts: int, secret: str) -> str:
    raw = f"{serial}|{ts}"
    dig = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(dig).decode("ascii").rstrip("=")


def verify_qr_local(qr_code: str, secret: str) -> bool:
    if not secret:
        return True
    parts = qr_code.split("|")
    if len(parts) != 4:
        return False
    prefix, device_id, ts_str, sig = parts
    if prefix != "CROC":
        return False
    if not ts_str.isdigit():
        return False
    raw = f"{device_id}|{ts_str}"
    expect = base64.urlsafe_b64encode(
        hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return hmac.compare_digest(expect, sig)


def build_qr(serial: str, secret: str) -> tuple[str, int]:
    ts = int(time.time())
    sig = sign_qr(serial, ts, secret)
    return f"CROC|{serial}|{ts}|{sig}", ts


def generate_items(
    count: int,
    secret: str,
    batch: str,
    policy: re.Pattern[str] | None = None,
) -> list[dict[str, str | None]]:
    pol = policy or DEFAULT_QR_POLICY
    items: list[dict[str, str | None]] = []
    for _ in range(count):
        serial = random_serial()
        qr, _ts = build_qr(serial, secret)
        if not pol.fullmatch(qr):
            raise ValueError(f"generated QR failed policy: {qr!r}")
        if not verify_qr_local(qr, secret):
            raise ValueError(f"HMAC self-check failed for {serial}")
        items.append(
            {"serial": serial, "mac_nocolon": None, "qr_code": qr, "batch": batch, "note": ""}
        )
    return items


def build_output_dir_name(count: int, now_ts: int | None = None) -> str:
    """Directory name under factory_serial_exports/ — epoch-based only (matches legacy CLI).

    `count` is kept for call-site compatibility; output folder naming does not embed it,
    so batch outputs stay `output_<unix_ts>/` like `output_1776861458`.
    """
    _ = int(count)  # unused; retained for stable API
    ts = int(now_ts if now_ts is not None else time.time())
    return f"output_{ts}"


def write_batch_files(
    out: Path,
    items: list[dict[str, str | None]],
    batch: str,
    *,
    qr_secret: str = "",
) -> None:
    import qrcode  # local import so verify-only tools can skip PIL

    out.mkdir(parents=True, exist_ok=True)
    png_dir = out / "png"
    png_dir.mkdir(parents=True, exist_ok=True)
    csv_lines = ["serial,mac_nocolon,qr_code,batch"]
    for it in items:
        serial = str(it["serial"])
        qr = str(it["qr_code"] or "")
        if not DEFAULT_QR_POLICY.fullmatch(qr):
            raise ValueError(f"QR policy check failed for {serial}")
        if qr_secret and not verify_qr_local(qr, qr_secret):
            raise ValueError(f"QR signature check failed for {serial}")
        b = str(it.get("batch") or batch)
        csv_lines.append(f"{serial},,{qr},{b}")
        img = qrcode.make(qr, border=2)
        img.save(png_dir / f"{serial}.png")

    (out / "manifest.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    (out / "factory_devices_bulk.json").write_text(
        json.dumps({"items": items}, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    (out / "README_BATCH.txt").write_text(
        "\n".join(
            [
                "Croc Sentinel — factory batch",
                "",
                "QR: CROC|<serial>|<unix_ts>|<HMAC>",
                "Server verifies with QR_SIGN_SECRET (see api verify_qr_signature).",
                "",
            ]
        ),
        encoding="utf-8",
    )


def post_factory_devices(
    api_base: str,
    factory_token: str,
    items: list[dict[str, str | None]],
    insecure_ssl: bool = False,
    timeout_s: float = 120.0,
    chunk_size: int = 2000,
) -> tuple[int, str]:
    """POST /factory/devices in chunks (API max 2000 items). Returns (http_code, body)."""
    factory_token = (factory_token or "").strip()
    base = api_base.rstrip("/")
    url = f"{base}/factory/devices"
    ctx = ssl._create_unverified_context() if insecure_ssl else None
    last_code = 200
    bodies: list[str] = []
    for off in range(0, len(items), chunk_size):
        chunk = items[off : off + chunk_size]
        body = json.dumps({"items": chunk}, ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Factory-Token": factory_token,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                last_code = resp.getcode() or 200
                bodies.append(raw)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            return e.code, err_body or str(e)
        except Exception as e:
            return -1, str(e)
    return last_code, "\n---\n".join(bodies)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_pending_push_queue(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def save_pending_push_queue(path: Path, queue: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(queue, ensure_ascii=True, indent=2), encoding="utf-8")


def append_pending_push_queue(
    path: Path,
    batch: str,
    items: list[dict[str, str | None]],
    reason: str,
) -> int:
    queue = load_pending_push_queue(path)
    queue.append(
        {
            "batch": batch,
            "items": items,
            "reason": reason,
            "queued_at": utc_now_iso(),
            "retry_count": 0,
        }
    )
    save_pending_push_queue(path, queue)
    return len(queue)


def drain_pending_push_queue(
    path: Path,
    api_base: str,
    factory_token: str,
    insecure_ssl: bool = False,
    max_batches: int = 20,
) -> tuple[int, list[dict]]:
    queue = load_pending_push_queue(path)
    if not queue:
        return 0, []
    attempted: list[dict] = []
    keep: list[dict] = []
    drained = 0
    for item in queue:
        if drained >= max_batches:
            keep.append(item)
            continue
        batch = str(item.get("batch") or "")
        items = item.get("items") or []
        if not isinstance(items, list) or not items:
            continue
        code, body = post_factory_devices(
            api_base,
            factory_token,
            items,
            insecure_ssl=insecure_ssl,
        )
        ok = code in (200, 201)
        attempted.append({"batch": batch, "code": code, "ok": ok, "body": body[:500]})
        if ok:
            drained += 1
            continue
        item["retry_count"] = int(item.get("retry_count") or 0) + 1
        item["reason"] = f"HTTP {code}: {body[:500]}"
        keep.append(item)
    save_pending_push_queue(path, keep)
    return drained, attempted


def write_push_status_file(
    out: Path,
    batch: str,
    items: list[dict[str, str | None]],
    http_code: int,
    response_body: str,
    pushed_ok: bool,
    retry_attempt: int,
) -> Path:
    rows = []
    for i, it in enumerate(items, 1):
        rows.append(
            {
                "index": i,
                "serial": it.get("serial"),
                "batch": batch,
                "push_status": "success" if pushed_ok else "failed",
                "retry_count": retry_attempt,
                "http_code": http_code,
            }
        )
    obj = {
        "batch": batch,
        "created_at": utc_now_iso(),
        "item_count": len(items),
        "push_ok": pushed_ok,
        "http_code": http_code,
        "retry_attempt": retry_attempt,
        "response_snippet": (response_body or "")[:2000],
        "items": rows,
    }
    p = out / "push_status.json"
    p.write_text(json.dumps(obj, ensure_ascii=True, indent=2), encoding="utf-8")
    return p


def _format_factory_ping_transport_error(exc: BaseException, *, url: str, timeout_s: float) -> str:
    """Turn urllib/socket errors into actionable text (WinError 10060 etc.)."""
    lines = [
        f"URL: {url}",
        f"client timeout={timeout_s}s (connect+read, single urllib timeout)",
        f"raw: {str(exc).strip()}",
    ]
    winerr: int | None = None
    cur: BaseException | None = exc
    for _ in range(12):
        if isinstance(cur, OSError):
            we = getattr(cur, "winerror", None)
            if we is not None:
                winerr = int(we)
                break
        nxt = getattr(cur, "reason", None)
        cur = nxt if isinstance(nxt, BaseException) else None

    if winerr == 10060:
        lines.append(
            "hint[10060]: TCP timed out — host:port did not respond in time. Check: (1) server up; (2) firewall/VPN; "
            "(3) FACTORY_UI_API_BASE is the public API root (Traefik: https://host/api; direct: http://127.0.0.1:8088) "
            f'(default {DEFAULT_FACTORY_UI_API_BASE}); (4) curl -vk "{url}"'
        )
    elif winerr == 10061:
        lines.append(
            "hint[10061]: connection refused — nothing accepts TCP on this host:port (wrong port or service stopped)."
        )
    elif isinstance(exc, urllib.error.URLError) and "timed out" in str(exc).lower():
        lines.append(
            "hint: request timed out before TCP/TLS completed — network slow or server overloaded; try larger timeout or fix routing."
        )
    return "\n".join(lines)


def get_factory_ping(
    api_base: str,
    factory_token: str,
    insecure_ssl: bool = False,
    timeout_s: float = 45.0,
) -> tuple[int, str]:
    """GET /factory/ping — verify X-Factory-Token before bulk upload."""
    factory_token = (factory_token or "").strip()
    base = api_base.rstrip("/")
    url = f"{base}/factory/ping"
    ctx = ssl._create_unverified_context() if insecure_ssl else None
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"X-Factory-Token": factory_token},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.getcode() or 200, raw
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return e.code, err_body or str(e)
    except Exception as e:
        return -1, _format_factory_ping_transport_error(e, url=url, timeout_s=timeout_s)
