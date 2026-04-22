#!/usr/bin/env python3
"""Print random QR_SIGN_SECRET + FACTORY_API_TOKEN for pasting into .env.

FACTORY_UI_API_BASE must still be set (e.g. public https://host/api with Traefik, not :8088 on the domain).
Run: python tools/factory_pack/gen_factory_secrets.py
"""
from __future__ import annotations

import secrets


def main() -> None:
    qr = secrets.token_hex(32)  # 64 hex chars >= 24
    fac = secrets.token_hex(32)
    print("# --- Paste into croc_sentinel_systems/.env (then restart api) ---")
    print(f"QR_SIGN_SECRET={qr}")
    print(f"FACTORY_API_TOKEN={fac}")
    print("# FACTORY_UI_API_BASE=https://YOUR_HOST/api   # Traefik StripPrefix /api → Uvicorn /")
    print("# --- Keep this output private; do not commit to git ---")


if __name__ == "__main__":
    main()
