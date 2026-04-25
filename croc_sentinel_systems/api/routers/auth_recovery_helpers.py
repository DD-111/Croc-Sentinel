"""Stateless helpers for the password-recovery flows
(Phase-84 split from ``routers/auth_recovery.py``).

The Phase-72 ``routers/auth_recovery.py`` extract bundled three
distinct concerns under one module:

  * **RSA-blob cipher helpers** — load the recovery public key,
    compute on-wire blob length, encrypt the payload with AES-GCM
    wrapped under RSA-OAEP, and emit a length-matched fake blob for
    the "username does not exist" path (so an attacker cannot
    distinguish missing-user from rate-limited).
  * **Per-IP rate limiter** — ``_check_forgot_ip_rate`` is shared
    between the offline-RSA flow (this module's parent
    ``auth_recovery``) and the email-OTP flow
    (``auth_recovery_email``). Both flows must count toward the same
    budget so a token-flooder can't burn through one path while the
    other resets independently.
  * **Token sweeper** — ``_prune_password_reset_tokens`` is invoked
    by the scheduler thread (via the ``_app._prune_password_reset_tokens``
    pin in ``routes_registry``).

Phase 84 carves all six off into this module so
``routers/auth_recovery.py`` becomes a pure routes module:
two schemas, three routes, and the late-binding wrappers it
needs to call back into ``app``.

Why a sibling module instead of a top-level ``recovery_crypto.py``?
The helpers are intentionally scoped to the ``routers/`` package —
they have no consumers outside the auth-recovery flows and we don't
want to suggest they're general-purpose. Living next to
``auth_recovery.py`` and ``auth_recovery_email.py`` makes the trio
obvious as a single feature surface.

Public surface
--------------
- ``_password_recovery_load_public()`` — lazy-load the configured
  RSA public key (PEM or path); cache the result so repeated calls
  during a request burst don't re-parse PEM.
- ``_password_recovery_blob_byte_len(pub)`` — exact on-wire length
  of the offline blob for a given key. Used both by the real
  encryption path and by ``_fake_password_recovery_hex`` to keep
  the lengths matched.
- ``_encrypt_password_recovery_payload(pub, inner)`` — encrypt the
  ``inner`` dict with the format
  ``MAGIC || version || RSA-OAEP(aes_key) || IV || AES-GCM(pt)``.
- ``_fake_password_recovery_hex(pub)`` — random hex of the same
  length as a real blob; the response shape for unknown usernames
  is byte-identical to the success path.
- ``_check_forgot_ip_rate(ip)`` — opens db_lock, prunes expired
  attempts, raises ``HTTPException(429)`` if the IP is over budget,
  inserts a fresh attempt row.
- ``_prune_password_reset_tokens()`` — sweep ``password_reset_tokens``
  older than 7 days past expiry. Idempotent.

Cache state
-----------
The lazy public-key cache is held module-global because every
recovery request needs it; reading PEM on each call would burn
syscalls and CPU on a cold cache. ``_pwrec_pubkey_cache`` uses a
three-state encoding: ``None`` = unread, ``False`` = read-failed
(treat as disabled), else the parsed RSAPublicKey instance.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException

from config import (
    FORGOT_PASSWORD_IP_MAX,
    FORGOT_PASSWORD_IP_WINDOW_SECONDS,
    PASSWORD_RECOVERY_BLOB_MAGIC,
    PASSWORD_RECOVERY_BLOB_VERSION,
    PASSWORD_RECOVERY_PLAINTEXT_PAD,
    PASSWORD_RECOVERY_PUBLIC_KEY_PATH,
    PASSWORD_RECOVERY_PUBLIC_KEY_PEM,
)
from db import db_lock, get_conn

logger = logging.getLogger("croc-api.routers.auth_recovery_helpers")


# ─── Public-key cache ───────────────────────────────────────────────────────
# Held module-global because every recovery request needs the parsed key
# and PEM parsing is expensive enough to skip on the hot path. Lock guards
# the slow first read; subsequent reads after the first successful parse
# observe the cache directly without contention.
_pwrec_pubkey_lock = threading.Lock()
_pwrec_pubkey_cache: Any = None  # None=unset, False=missing, else RSAPublicKey


def _password_recovery_load_public() -> Optional[Any]:
    """Lazy-load PEM from PASSWORD_RECOVERY_PUBLIC_KEY_PEM or *_PATH.

    Returns the parsed ``RSAPublicKey`` on success, ``None`` when no
    PEM is configured or the configured PEM is invalid (so the caller
    can flip the route into "recovery disabled" mode without
    branching on exceptions).
    """
    global _pwrec_pubkey_cache
    with _pwrec_pubkey_lock:
        if _pwrec_pubkey_cache is not None:
            if _pwrec_pubkey_cache is False:
                return None
            return _pwrec_pubkey_cache
        pem = (PASSWORD_RECOVERY_PUBLIC_KEY_PEM or "").replace("\\n", "\n").strip()
        if not pem and PASSWORD_RECOVERY_PUBLIC_KEY_PATH:
            try:
                from pathlib import Path

                pem = (
                    Path(PASSWORD_RECOVERY_PUBLIC_KEY_PATH)
                    .expanduser()
                    .read_text(encoding="utf-8")
                    .strip()
                )
            except Exception as exc:
                logger.warning("PASSWORD_RECOVERY_PUBLIC_KEY_PATH read failed: %s", exc)
                pem = ""
        if not pem:
            _pwrec_pubkey_cache = False
            return None
        try:
            key = serialization.load_pem_public_key(pem.encode("utf-8"))
            if not isinstance(key, rsa.RSAPublicKey):
                logger.warning("password recovery: PEM must be an RSA public key")
                _pwrec_pubkey_cache = False
                return None
            if key.key_size < 2048:
                logger.warning("password recovery: RSA key must be >= 2048 bits")
                _pwrec_pubkey_cache = False
                return None
            _pwrec_pubkey_cache = key
            return key
        except Exception as exc:
            logger.warning("password recovery: invalid PEM: %s", exc)
            _pwrec_pubkey_cache = False
            return None


def _password_recovery_blob_byte_len(pub: rsa.RSAPublicKey) -> int:
    """Exact on-wire byte length of the offline recovery blob.

    Format: ``MAGIC || version_byte || RSA-OAEP(aes_key) || IV(12) ||
    AES-GCM(plaintext_padded)``. The plaintext is padded to
    ``PASSWORD_RECOVERY_PLAINTEXT_PAD`` so its length doesn't leak
    payload size; AES-GCM adds a fixed 16-byte tag on top.
    """
    rsa_len = pub.key_size // 8
    return (
        len(PASSWORD_RECOVERY_BLOB_MAGIC)
        + 1
        + rsa_len
        + 12
        + (PASSWORD_RECOVERY_PLAINTEXT_PAD + 16)
    )


def _encrypt_password_recovery_payload(
    pub: rsa.RSAPublicKey, inner: dict[str, Any]
) -> bytes:
    """Encrypt the inner JSON dict for offline recovery.

    Uses RSA-OAEP(SHA-256) to wrap a fresh AES-256-GCM key, then
    encrypts a length-padded JSON blob of ``inner`` under that key.
    Pads the plaintext to ``PASSWORD_RECOVERY_PLAINTEXT_PAD`` bytes
    so blob size is constant for any payload smaller than the pad.
    Raises ``ValueError`` if ``inner`` doesn't fit.
    """
    pad = int(PASSWORD_RECOVERY_PLAINTEXT_PAD)
    pt = json.dumps(inner, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(pt) > pad:
        raise ValueError("inner JSON exceeds PASSWORD_RECOVERY_PLAINTEXT_PAD")
    pt = pt + (b"\x00" * (pad - len(pt)))
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(iv, pt, None)
    rsa_cipher = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(rsa_cipher) != pub.key_size // 8:
        raise ValueError("RSA ciphertext length mismatch")
    return (
        PASSWORD_RECOVERY_BLOB_MAGIC
        + bytes([PASSWORD_RECOVERY_BLOB_VERSION])
        + rsa_cipher
        + iv
        + ct
    )


def _fake_password_recovery_hex(pub: rsa.RSAPublicKey) -> str:
    """Random hex of the same length as a real blob.

    Used for the "username does not exist" branch so the response
    body is indistinguishable from a successful start. Length match
    is critical — a shorter response would leak username existence
    via Content-Length.
    """
    return secrets.token_bytes(_password_recovery_blob_byte_len(pub)).hex()


def _check_forgot_ip_rate(ip: str) -> None:
    """Per-IP rate gate for both recovery flows.

    Sliding window of ``FORGOT_PASSWORD_IP_WINDOW_SECONDS`` with a
    cap of ``FORGOT_PASSWORD_IP_MAX`` attempts. Both the RSA-blob
    flow and the email-OTP flow share this single budget so a
    flooder can't switch between them to evade the limit.

    Raises ``HTTPException(429)`` when the budget is exhausted.
    Side-effect: inserts a fresh attempt row on each call (even
    when accepted — the row IS the rate-limit ledger).
    """
    now = int(time.time())
    cut = now - FORGOT_PASSWORD_IP_WINDOW_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM forgot_password_attempts WHERE ts_epoch < ?", (cut,))
        cur.execute(
            "SELECT COUNT(*) AS c FROM forgot_password_attempts WHERE ip = ? AND ts_epoch >= ?",
            (ip, cut),
        )
        c = int(cur.fetchone()["c"])
        if c >= FORGOT_PASSWORD_IP_MAX:
            conn.commit()
            conn.close()
            raise HTTPException(
                status_code=429,
                detail=f"too many recovery attempts from this IP — try again in {FORGOT_PASSWORD_IP_WINDOW_SECONDS}s",
            )
        cur.execute(
            "INSERT INTO forgot_password_attempts (ip, ts_epoch) VALUES (?, ?)",
            (ip, now),
        )
        conn.commit()
        conn.close()


def _prune_password_reset_tokens() -> None:
    """Drop expired rows (used or unused) older than 7 days past expiry.

    Called by ``scheduler`` via the ``_app._prune_password_reset_tokens``
    pin set up in ``routes_registry.register_routers``. Idempotent —
    safe to call any number of times in a row.
    """
    now = int(time.time())
    cut = now - 7 * 86400
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM password_reset_tokens WHERE expires_at_ts < ?", (cut,))
        conn.commit()
        conn.close()


__all__ = (
    "_pwrec_pubkey_lock",
    "_pwrec_pubkey_cache",
    "_password_recovery_load_public",
    "_password_recovery_blob_byte_len",
    "_encrypt_password_recovery_payload",
    "_fake_password_recovery_hex",
    "_check_forgot_ip_rate",
    "_prune_password_reset_tokens",
)
