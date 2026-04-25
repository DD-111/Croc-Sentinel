"""Device-facing identity gates extracted from ``app.py`` (Phase-5).

Four small functions that decide *whether a particular device is allowed
to talk to the API*:

* :func:`is_device_revoked` / :func:`ensure_not_revoked` — DB-backed kill
  switch. ``revoked_devices`` is a tiny table; this is on the hot path of
  every device endpoint.
* :func:`verify_device_signature` — verify a device's payload signature
  with its public key (EC P-256 ECDSA or RSA-PKCS1v15).
* :func:`verify_qr_signature` — verify the HMAC tag baked into provisioning
  QR codes (``CROC|<device_id>|<ts>|<sig>``).

Why a separate module?
  * These are *device-side* security primitives. ``security.py`` owns the
    *user-side* primitives (Principal, JWT, password hashing). Mixing
    them obscures who is being authenticated.
  * They depend on ``db`` and ``config`` only — no FastAPI app state, no
    MQTT client, no event center — so extracting them is risk-free.
  * Several future device-related extracts (provision challenges, factory
    QR helpers, etc.) will live alongside these four.

The names and signatures are unchanged. ``app.py`` re-exports all four
so legacy callers (``from app import is_device_revoked``) keep working.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from fastapi import HTTPException

from config import QR_SIGN_SECRET
from db import db_lock, get_conn

__all__ = [
    "is_device_revoked",
    "ensure_not_revoked",
    "verify_device_signature",
    "verify_qr_signature",
]


def is_device_revoked(device_id: str) -> bool:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM revoked_devices WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    return row is not None


def ensure_not_revoked(device_id: str) -> None:
    if is_device_revoked(device_id):
        raise HTTPException(status_code=403, detail="device is revoked")


def verify_device_signature(public_key_pem: str, nonce: str, signature_b64: str) -> bool:
    """Verify ``sign(nonce)`` using the device's stored public key.

    Accepts either an EC P-256 key (ECDSA-SHA256, the default for new
    firmware) or an RSA key (PKCS1v15-SHA256, kept for legacy units).
    Returns ``False`` on any malformed input or signature mismatch — never
    raises, so callers can use it as a plain boolean guard.
    """
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        sig = base64.b64decode(signature_b64)
        msg = nonce.encode("utf-8")
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def verify_qr_signature(qr_code: str) -> bool:
    """Verify the HMAC tag baked into a provisioning QR code.

    Format: ``CROC|<device_id>|<ts>|<sig>`` where ``<sig>`` is
    ``base64url(HMAC-SHA256(QR_SIGN_SECRET, "<device_id>|<ts>"))`` with
    trailing ``=`` stripped.

    When ``QR_SIGN_SECRET`` is unset (dev / sandbox) this is a permissive
    no-op returning ``True``. Production deployments must set the secret.
    """
    if not QR_SIGN_SECRET:
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
        hmac.new(QR_SIGN_SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return hmac.compare_digest(expect, sig)
