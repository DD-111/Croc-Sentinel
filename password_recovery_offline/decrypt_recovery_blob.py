#!/usr/bin/env python3
"""Decrypt recovery_blob_hex from POST /auth/forgot/start (offline, private key).

Prints ONE LINE JSON — the user pastes this string into the dashboard
「解密明文」field together with the new password (twice).

Requires: pip install cryptography
"""
from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CRPW"
VERSION = 1


def decrypt_blob(priv_pem: bytes, blob: bytes) -> str:
    if not blob.startswith(MAGIC) or len(blob) < 6:
        raise ValueError("invalid blob header")
    if blob[4] != VERSION:
        raise ValueError(f"unsupported blob version {blob[4]}")
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    rsa_len = priv.key_size // 8
    if len(blob) < 5 + rsa_len + 12 + 16:
        raise ValueError("blob too short")
    rsa_cipher = blob[5 : 5 + rsa_len]
    tail = blob[5 + rsa_len :]
    iv = tail[:12]
    ct = tail[12:]
    aes_key = priv.decrypt(
        rsa_cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(aes_key) != 32:
        raise ValueError("unexpected AES key length after RSA decrypt")
    pt = AESGCM(aes_key).decrypt(iv, ct, None)
    return pt.rstrip(b"\x00").decode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--private", required=True, help="Path to private.pem")
    ap.add_argument("--hex", dest="hexdata", help="recovery_blob_hex from user")
    ap.add_argument("--file", help="read hex from file instead of --hex")
    args = ap.parse_args()
    pem = Path(args.private).read_bytes()
    if args.file:
        hx = Path(args.file).read_text(encoding="utf-8").strip()
    elif args.hexdata:
        hx = args.hexdata.strip()
    else:
        raise SystemExit("need --hex or --file")
    hx = "".join(hx.split())  # drop whitespace / newlines
    plain = decrypt_blob(pem, bytes.fromhex(hx))
    # Single line for easy copy-paste into the web form
    print(plain.replace("\n", "").replace("\r", ""))


if __name__ == "__main__":
    main()
