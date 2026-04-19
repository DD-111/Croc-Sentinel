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
from pathlib import Path

CROCKFORD = "ABCDEFGHJKLMNPQRSTUVWXYZ234567"

# Default API root when .env does not set FACTORY_UI_API_BASE (no path suffix; /factory/* on this host).
DEFAULT_FACTORY_UI_API_BASE = "https://esasecure.com:8088"

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


def write_batch_files(out: Path, items: list[dict[str, str | None]], batch: str) -> None:
    import qrcode  # local import so verify-only tools can skip PIL

    out.mkdir(parents=True, exist_ok=True)
    png_dir = out / "png"
    png_dir.mkdir(parents=True, exist_ok=True)
    csv_lines = ["serial,mac_nocolon,qr_code,batch"]
    for it in items:
        serial = str(it["serial"])
        qr = str(it["qr_code"] or "")
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


def get_factory_ping(
    api_base: str,
    factory_token: str,
    insecure_ssl: bool = False,
    timeout_s: float = 30.0,
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
        return -1, str(e)
