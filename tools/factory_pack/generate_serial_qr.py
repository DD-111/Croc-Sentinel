#!/usr/bin/env python3
"""Generate SN-* serials + signed CROC|... QR codes + bulk JSON for /factory/devices.

Must use the **same** QR_SIGN_SECRET as production API .env.

Output layout (default under repo factory_serial_exports/output_<stamp>/):
  manifest.csv          — serial,mac_nocolon,qr_code,batch
  factory_devices_bulk.json — {"items":[{serial, qr_code, batch, ...}, ...]}
  png/<serial>.png      — QR image for sticker printing
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

import qrcode

CROCKFORD = "ABCDEFGHJKLMNPQRSTUVWXYZ234567"


def random_serial() -> str:
    return "SN-" + "".join(secrets.choice(CROCKFORD) for _ in range(16))


def sign_qr(serial: str, ts: int, secret: str) -> str:
    raw = f"{serial}|{ts}"
    dig = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(dig).decode("ascii").rstrip("=")


def build_qr(serial: str, secret: str) -> tuple[str, int]:
    ts = int(time.time())
    sig = sign_qr(serial, ts, secret)
    return f"CROC|{serial}|{ts}|{sig}", ts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--qr-secret", required=True, help="Same value as server QR_SIGN_SECRET")
    ap.add_argument("--batch", default="", help="Batch label stored in DB")
    ap.add_argument(
        "--out",
        default="",
        help="Output directory (default: factory_serial_exports/output_<unix>)",
    )
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[2]
    default_out = root / "factory_serial_exports" / f"output_{int(time.time())}"
    out = Path(args.out) if args.out else default_out
    out.mkdir(parents=True, exist_ok=True)
    png_dir = out / "png"
    png_dir.mkdir(exist_ok=True)
    batch = args.batch or out.name

    items = []
    csv_lines = ["serial,mac_nocolon,qr_code,batch"]
    for _ in range(args.count):
        serial = random_serial()
        qr, _ts = build_qr(serial, args.qr_secret)
        items.append({"serial": serial, "mac_nocolon": None, "qr_code": qr, "batch": batch, "note": ""})
        csv_lines.append(f"{serial},,{qr},{batch}")
        img = qrcode.make(qr, border=2)
        img.save(png_dir / f"{serial}.png")

    (out / "manifest.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    bulk = {"items": items}
    (out / "factory_devices_bulk.json").write_text(json.dumps(bulk, ensure_ascii=True, indent=2), encoding="utf-8")
    print(f"Wrote {args.count} devices to:\n  {out}\nImport with POST /factory/devices using factory_devices_bulk.json")


if __name__ == "__main__":
    main()
