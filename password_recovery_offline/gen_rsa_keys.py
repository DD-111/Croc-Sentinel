#!/usr/bin/env python3
"""Generate RSA-2048 keypair for offline dashboard password recovery.

Writes:
  ../password_recovery_keys/private.pem   (KEEP OFFLINE — never on VPS)
  ../password_recovery_keys/public.pem    (copy to server .env / file path)

Requires: pip install cryptography
"""
from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parent.parent / "password_recovery_keys"),
        help="Directory for PEM output (default: repo password_recovery_keys/)",
    )
    args = ap.parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (out / "private.pem").write_bytes(priv_pem)
    (out / "public.pem").write_bytes(pub_pem)
    print(f"Wrote:\n  {out / 'private.pem'}\n  {out / 'public.pem'}")
    print("Next: configure API with PASSWORD_RECOVERY_PUBLIC_KEY_PATH or _PEM.")


if __name__ == "__main__":
    main()
