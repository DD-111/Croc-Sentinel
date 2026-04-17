"""
Dashboard auth: legacy API bearer (superadmin) or JWT after /auth/login.
RBAC: superadmin > admin > user (zone-scoped where applicable).
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Optional

import bcrypt
import jwt
from fastapi import Header, HTTPException


JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALG = "HS256"
JWT_EXPIRE_S = int(os.getenv("JWT_EXPIRE_SECONDS", str(8 * 3600)))


@dataclass
class Principal:
    username: str
    role: str  # superadmin | admin | user
    zones: list[str]

    def is_superadmin(self) -> bool:
        return self.role == "superadmin"

    def is_adminish(self) -> bool:
        return self.role in ("superadmin", "admin")

    def has_all_zones(self) -> bool:
        return "*" in self.zones

    def zone_ok(self, device_zone: Optional[str]) -> bool:
        if self.is_superadmin() or self.has_all_zones():
            return True
        dz = (device_zone or "").strip() or "all"
        return dz in self.zones


ROLE_ORDER = {"user": 0, "admin": 1, "superadmin": 2}


def min_role_ok(principal: Principal, need: str) -> bool:
    return ROLE_ORDER.get(principal.role, 0) >= ROLE_ORDER.get(need, 0)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except ValueError:
        return False


def zones_from_json(raw: str) -> list[str]:
    import json

    try:
        z = json.loads(raw or "[]")
        if isinstance(z, list) and all(isinstance(x, str) for x in z):
            return z
    except json.JSONDecodeError:
        pass
    return ["*"]


def issue_jwt(username: str, role: str, zones: list[str]) -> str:
    if not JWT_SECRET or len(JWT_SECRET) < 32:
        raise HTTPException(status_code=500, detail="JWT_SECRET not configured (min 32 chars)")
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": username,
        "role": role,
        "zones": zones,
        "iat": now,
        "exp": now + JWT_EXPIRE_S,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_jwt(token: str) -> Principal:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    username = str(payload.get("sub", ""))
    role = str(payload.get("role", "user"))
    if role not in ROLE_ORDER:
        role = "user"
    zones = payload.get("zones")
    if not isinstance(zones, list):
        zones = ["*"]
    zones = [str(z) for z in zones]
    if not zones:
        zones = ["*"]
    return Principal(username=username, role=role, zones=zones)


def principal_from_legacy_bearer(token: str, api_token: str) -> Optional[Principal]:
    if api_token and token == api_token:
        return Principal(username="api-legacy", role="superadmin", zones=["*"])
    return None


def assert_zone_for_device(principal: Principal, device_zone: Optional[str]) -> None:
    if not principal.zone_ok(device_zone):
        raise HTTPException(status_code=403, detail="forbidden for this zone")


def assert_min_role(principal: Principal, need: str) -> None:
    if not min_role_ok(principal, need):
        raise HTTPException(status_code=403, detail="insufficient role")


def fernet_key_from_hex64(hex64: str) -> bytes:
    """Derive urlsafe 32-byte Fernet key from 64 hex chars (256-bit secret)."""
    import base64
    import hashlib
    import re

    h = hex64.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", h):
        raise HTTPException(status_code=400, detail="X-Backup-Encryption-Key must be 64 hex chars")
    digest = hashlib.sha256(bytes.fromhex(h)).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_blob(plaintext: bytes, hex64_key: str) -> bytes:
    from cryptography.fernet import Fernet

    f = Fernet(fernet_key_from_hex64(hex64_key))
    return f.encrypt(plaintext)


def decrypt_blob(blob: bytes, hex64_key: str) -> bytes:
    from cryptography.fernet import Fernet

    f = Fernet(fernet_key_from_hex64(hex64_key))
    try:
        return f.decrypt(blob)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"decrypt failed: {exc}") from exc
