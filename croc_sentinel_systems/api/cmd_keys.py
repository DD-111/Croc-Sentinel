"""Per-device MQTT credentials, bootstrap publish, and target
resolution (Phase-51 extraction from ``app.py``).

This module owns the small set of helpers that turn device IDs into
the things the publisher actually needs (credentials / signing keys /
the resolved set of targetable devices) and the bootstrap-time
fan-out that hands those credentials to a freshly claimed device:

* :func:`generate_device_credentials` — produce
  ``(mqtt_username, mqtt_password, cmd_key)`` for a brand-new
  claim. When ``PROVISION_USE_SHARED_MQTT_CREDS`` is on (and per-device
  enforcement is off), the device shares ``MQTT_USERNAME`` /
  ``MQTT_PASSWORD`` and only the ``cmd_key`` is unique; otherwise
  the username is derived from the device id and the password is
  random urlsafe-24.
* :func:`get_cmd_key_for_device` — single-device cmd_key resolver.
  Looks up ``provisioned_credentials`` case-insensitively (the
  claim row may be mixed-case while the console route is
  uppercase) and falls back to ``CMD_AUTH_KEY`` when no row
  matches. Always returns an upper-cased key.
* :func:`get_cmd_keys_for_devices` — batch variant; returns
  ``{ UPPER(device_id) -> cmd_key }`` for the inputs that have a
  row. Empty inputs / empty cmd_keys are silently dropped.
* :func:`publish_bootstrap_claim` — one-shot QoS-1 publish of a
  ``bootstrap.assign`` envelope on
  ``<TOPIC_ROOT>/bootstrap/assign/<mac_nocolon>``. Includes the
  bind key, claim nonce, device id, zone, QR string, and the
  freshly-minted credentials. Reads the live ``app.mqtt_client``
  at call time so reconnects (which reassign the global) are
  picked up. Raises 500 if the client isn't ready, 502 if the
  broker doesn't ACK the publish within 3 seconds.
* :func:`resolve_target_devices` — resolves a (possibly empty)
  list of device IDs against ``device_state`` × ``device_ownership``
  × ``revoked_devices`` for the calling principal. Empty input
  means "every device the principal can target". Filters by zone
  scope after the SQL fetch (the SQL only narrows owner_admin /
  not-revoked); enforces ``MAX_BULK_TARGETS`` so a runaway broadcast
  can't fan-out to thousands of devices.

Wiring
------
* Pulls config values
  (``ENFORCE_PER_DEVICE_CREDS`` / ``PROVISION_USE_SHARED_MQTT_CREDS``
  / ``MQTT_USERNAME`` / ``MQTT_PASSWORD`` / ``CMD_AUTH_KEY`` /
  ``BOOTSTRAP_BIND_KEY`` / ``TOPIC_ROOT`` / ``MAX_BULK_TARGETS``)
  straight from :mod:`config`.
* Pulls ``Principal`` from :mod:`security` and ``get_manager_admin``
  from :mod:`authz` directly (acyclic).
* Reads ``app.mqtt_client`` and ``app.zone_sql_suffix`` at call time
  via ``import app as _app`` — the MQTT client is a mutable global
  reassigned by the connect/disconnect callbacks, and zone_sql_suffix
  still lives in app.py for now (small enough that it doesn't justify
  its own module yet).
* Re-exported from ``app.py`` so every router's
  ``_app.publish_bootstrap_claim`` / ``_app.resolve_target_devices``
  / ``_app.get_cmd_key_for_device`` shim and the in-module call
  sites (claim handlers, scheduler_loop, fan-out workers, OTA
  rollout) keep working unchanged.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Optional

from fastapi import HTTPException

import app as _app
from authz import get_manager_admin
from config import (
    BOOTSTRAP_BIND_KEY,
    CMD_AUTH_KEY,
    ENFORCE_PER_DEVICE_CREDS,
    MAX_BULK_TARGETS,
    MQTT_PASSWORD,
    MQTT_USERNAME,
    PROVISION_USE_SHARED_MQTT_CREDS,
    TOPIC_ROOT,
)
from db import db_lock, get_conn
from security import Principal

__all__ = (
    "generate_device_credentials",
    "get_cmd_key_for_device",
    "get_cmd_keys_for_devices",
    "publish_bootstrap_claim",
    "resolve_target_devices",
)

logger = logging.getLogger(__name__)


def generate_device_credentials(device_id: str) -> tuple[str, str, str]:
    if (not ENFORCE_PER_DEVICE_CREDS) and PROVISION_USE_SHARED_MQTT_CREDS and MQTT_USERNAME:
        mqtt_username = MQTT_USERNAME
        mqtt_password = MQTT_PASSWORD
    else:
        suffix = device_id.replace("-", "").lower()[:12]
        mqtt_username = f"dev_{suffix}"
        mqtt_password = secrets.token_urlsafe(24)
    cmd_key = secrets.token_hex(8).upper()
    return mqtt_username, mqtt_password, cmd_key


def get_cmd_key_for_device(device_id: str) -> str:
    """Resolve signing key for MQTT /cmd. Match credentials case-insensitively — claim may
    have stored mixed-case device_id while the console route uses uppercase (or vice versa);
    falling back to CMD_AUTH_KEY then breaks every Danger-zone /commands publish."""
    raw = str(device_id or "").strip()
    if not raw:
        return str(CMD_AUTH_KEY or "").strip().upper()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT cmd_key FROM provisioned_credentials WHERE UPPER(device_id) = UPPER(?) LIMIT 1",
            (raw,),
        )
        row = cur.fetchone()
        conn.close()
    if row and row["cmd_key"]:
        return str(row["cmd_key"]).strip().upper()
    return str(CMD_AUTH_KEY or "").strip().upper()


def get_cmd_keys_for_devices(device_ids: list[str]) -> dict[str, str]:
    """Batch-resolve MQTT /cmd signing keys. Keys are ``UPPER(device_id)`` → cmd_key."""
    ids = sorted({str(x or "").strip().upper() for x in device_ids if str(x or "").strip()})
    if not ids:
        return {}
    out: dict[str, str] = {}
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        ph = ",".join(["?"] * len(ids))
        cur.execute(
            f"SELECT UPPER(device_id) AS u, cmd_key FROM provisioned_credentials WHERE UPPER(device_id) IN ({ph})",
            tuple(ids),
        )
        for r in cur.fetchall():
            ck = str(r["cmd_key"] or "").strip().upper()
            if ck:
                out[str(r["u"])] = ck
        conn.close()
    return out


def publish_bootstrap_claim(
    mac_nocolon: str,
    claim_nonce: str,
    device_id: str,
    zone: str,
    qr_code: str,
    mqtt_username: str,
    mqtt_password: str,
    cmd_key: str,
) -> None:
    mqtt_client = _app.mqtt_client
    if mqtt_client is None:
        raise HTTPException(status_code=500, detail="mqtt client not ready")

    topic = f"{TOPIC_ROOT}/bootstrap/assign/{mac_nocolon}"
    payload = {
        "type": "bootstrap.assign",
        "bind_key": BOOTSTRAP_BIND_KEY,
        "mac_nocolon": mac_nocolon,
        "claim_nonce": claim_nonce,
        "device_id": device_id,
        "zone": zone,
        "qr_code": qr_code,
        "mqtt_username": mqtt_username,
        "mqtt_password": mqtt_password,
        "cmd_key": cmd_key,
        "ts": int(time.time()),
    }
    info = mqtt_client.publish(topic, json.dumps(payload, ensure_ascii=True), qos=1)
    info.wait_for_publish(timeout=3.0)
    if not info.is_published():
        raise HTTPException(status_code=502, detail="bootstrap publish failed")


def resolve_target_devices(
    device_ids: list[str], principal: Optional[Principal] = None
) -> list[str]:
    unique = sorted(set([d for d in device_ids if d]))
    zs, za = _app.zone_sql_suffix(principal) if principal else ("", [])
    osf, osa = ("", [])
    if principal and not principal.is_superadmin():
        if principal.role == "admin":
            osf = " AND o.owner_admin = ? "
            osa = [principal.username]
        else:
            manager = get_manager_admin(principal.username)
            if not manager:
                osf = " AND 1=0 "
                osa = []
            else:
                osf = " AND o.owner_admin = ? "
                osa = [manager]
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if unique:
            placeholders = ",".join(["?"] * len(unique))
            cur.execute(
                f"""
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN revoked_devices r ON d.device_id = r.device_id
                LEFT JOIN device_ownership o ON d.device_id = o.device_id
                WHERE d.device_id IN ({placeholders}){zs} {osf} AND r.device_id IS NULL
                """,
                tuple(unique) + tuple(za) + tuple(osa),
            )
        else:
            cur.execute(
                f"""
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN revoked_devices r ON d.device_id = r.device_id
                LEFT JOIN device_ownership o ON d.device_id = o.device_id
                WHERE 1=1 {zs} {osf} AND r.device_id IS NULL
                """,
                tuple(za) + tuple(osa),
            )
        rows = cur.fetchall()
        conn.close()
    out: list[str] = []
    for r in rows:
        did = str(r["device_id"])
        z = str(r["zone"]) if r["zone"] is not None else ""
        if principal is None or principal.is_superadmin() or principal.has_all_zones() or principal.zone_ok(z):
            out.append(did)
    if len(out) > MAX_BULK_TARGETS:
        raise HTTPException(status_code=413, detail=f"target set too large (> {MAX_BULK_TARGETS})")
    return out
