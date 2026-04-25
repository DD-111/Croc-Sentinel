"""OTA firmware staging + diagnostics + direct broadcast (Phase-13,
trimmed in Phase-65 / Phase-79).

Surface evolution:
  Phase 13 — original module: 14 routes (~870 lines) covering the
              full OTA surface.
  Phase 65 — extracted the 8 *campaign-lifecycle* routes into
              ``routers/ota_campaigns.py``.
  Phase 77 — split campaign accept/decline/rollback into
              ``routers/ota_campaigns_lifecycle.py``.
  Phase 79 — extracted the 6 firmware-bytes helpers into
              ``routers/ota_storage.py`` so this file is now
              routes-only.

Routes (still here)
-------------------
  GET    /ota/service-check          — diagnostics (no secrets).
  GET    /ota/firmware-reachability  — HEAD-probe a staged file.
  GET    /ota/firmwares              — superadmin: full inventory.
  GET    /ota/firmware-verify        — re-hash a stored .bin.
  POST   /ota/broadcast              — direct fan-out, no campaign row.
  POST   /ota/firmware/upload        — stage a .bin without creating a
                                       campaign row.

Helpers (re-exported from ``routers/ota_storage`` for backward compat)
----------------------------------------------------------------------
``_sha256_for``, ``_sha256_sidecar_only``, ``_safe_ota_stored_filename``,
``_ota_bin_path_for_stored_name``, ``_require_ota_upload_password``,
and ``_ota_store_uploaded_bin`` all live in ``routers/ota_storage.py``
now. We re-export them via ``__all__`` so any historical caller
that did ``from routers.ota import _sha256_for`` keeps working
(test rigs in particular).

``routers/ota_campaigns.py`` was switched to import directly from
``routers/ota_storage`` in Phase 79 — single source of truth — so
the ``import app as _app`` capture window in this file no longer
matters for those four helpers.

Stays in ``app.py`` (late-bound here)
-------------------------------------
``_public_firmware_url``, ``_verify_firmware_file_on_service``,
``_effective_ota_verify_base``, ``_get_ota_firmware_catalog``,
``_version_str_for_ota_bin_file``, ``resolve_target_devices``,
``publish_command``, ``get_cmd_key_for_device``,
``require_capability``, ``require_principal``.

We deliberately reference function objects directly in
``Depends(require_principal)`` — never wrap in a lambda. See
``routers/factory.py`` for the long write-up of the trap.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    CMD_PROTO,
    OTA_FIRMWARE_DIR,
    OTA_MAX_FIRMWARE_BINS,
    OTA_PUBLIC_BASE_URL,
    OTA_TOKEN,
    OTA_UPLOAD_PASSWORD,
    OTA_VERIFY_BASE_URL,
    TOPIC_ROOT,
)
from routers.ota_storage import (
    _ota_bin_path_for_stored_name,  # noqa: F401  re-export for ota_campaigns / tests
    _ota_store_uploaded_bin,
    _require_ota_upload_password,
    _safe_ota_stored_filename,  # noqa: F401  re-export
    _sha256_for,  # noqa: F401  re-export
    _sha256_sidecar_only,
)
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
resolve_target_devices = _app.resolve_target_devices
publish_command = _app.publish_command
get_cmd_key_for_device = _app.get_cmd_key_for_device
_public_firmware_url = _app._public_firmware_url
_verify_firmware_file_on_service = _app._verify_firmware_file_on_service
_effective_ota_verify_base = _app._effective_ota_verify_base
_version_str_for_ota_bin_file = _app._version_str_for_ota_bin_file
_get_ota_firmware_catalog = _app._get_ota_firmware_catalog


logger = logging.getLogger("croc-api.routers.ota")
router = APIRouter(tags=["ota"])


# ───────────────────────────────────────────────────── request schemas ────

class OtaBroadcastRequest(BaseModel):
    url: str = Field(min_length=8, max_length=400)
    fw: str = Field(default="", max_length=40)
    device_ids: list[str] = Field(default_factory=list)


# ───────────────────────────────────────────────── routes: diagnostics ────

@router.get("/ota/service-check")
def ota_service_check(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin: safe diagnostics for OTA URL probing (no secrets)."""
    assert_min_role(principal, "superadmin")
    hints: list[str] = []
    tok = bool((OTA_TOKEN or "").strip())
    if not tok:
        hints.append("OTA_TOKEN is unset — nginx /fw/ token rule returns 403; devices and probes need the same token as config.h.")
    if OTA_PUBLIC_BASE_URL and not OTA_VERIFY_BASE_URL:
        hints.append(
            "If probes fail with connection refused from the API container, set OTA_VERIFY_BASE_URL=http://ota-nginx:9231 "
            "(Docker Compose service name on croc_net)."
        )
    if not OTA_PUBLIC_BASE_URL:
        hints.append("Set OTA_PUBLIC_BASE_URL for device-facing URLs (must match config.h OTA_ALLOWED_HOST).")
    if not OTA_UPLOAD_PASSWORD:
        hints.append("OTA_UPLOAD_PASSWORD is unset — superadmin cannot stage .bin via POST /ota/firmware/upload until you set it in the API environment.")
    return {
        "OTA_FIRMWARE_DIR": OTA_FIRMWARE_DIR,
        "OTA_PUBLIC_BASE_URL": OTA_PUBLIC_BASE_URL or None,
        "OTA_VERIFY_BASE_URL": OTA_VERIFY_BASE_URL or None,
        "effective_verify_base": _effective_ota_verify_base() or None,
        "OTA_TOKEN_configured": tok,
        "OTA_MAX_FIRMWARE_BINS": OTA_MAX_FIRMWARE_BINS,
        "OTA_UPLOAD_PASSWORD_configured": bool(OTA_UPLOAD_PASSWORD),
        "hints": hints,
    }


@router.get("/ota/firmware-reachability")
def ota_firmware_reachability(
    name: str = Query(..., min_length=5, max_length=220),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Dashboard: confirm the staged .bin is reachable like a device (HEAD with OTA_TOKEN). Catalog-only name."""
    assert_min_role(principal, "user")
    require_capability(principal, "can_send_command")
    safe = os.path.basename((name or "").strip())
    if not safe.endswith(".bin") or safe != (name or "").strip() or "/" in (name or "") or "\\" in (name or ""):
        raise HTTPException(status_code=400, detail="invalid firmware filename")
    cat = _get_ota_firmware_catalog()
    if not any(str(e.get("name") or "") == safe for e in cat):
        raise HTTPException(status_code=404, detail="firmware not in catalog")
    ok, detail, masked = _verify_firmware_file_on_service(safe)
    tok = bool((OTA_TOKEN or "").strip())
    return {
        "ok": ok,
        "detail": detail,
        "probe_url_masked": masked,
        "ota_token_configured": tok,
        "public_base_configured": bool((OTA_PUBLIC_BASE_URL or "").strip()),
        "filename": safe,
    }


@router.get("/ota/firmwares")
def list_firmwares(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    # Only superadmin can even see the firmware inventory.
    assert_min_role(principal, "superadmin")
    items: list[dict[str, Any]] = []
    base = OTA_FIRMWARE_DIR
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            if not name.endswith(".bin"):
                continue
            path = os.path.join(base, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            url = ""
            if OTA_PUBLIC_BASE_URL:
                url = f"{OTA_PUBLIC_BASE_URL}/fw/{name}"
            fw_label = _version_str_for_ota_bin_file(path, name)
            items.append({
                "name": name,
                "fw_version": fw_label,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
                "sha256": _sha256_sidecar_only(path),
                "download_url": url,
            })
    return {
        "dir": base,
        "public_base": OTA_PUBLIC_BASE_URL,
        "items": items,
        "retention": {
            "max_bins": OTA_MAX_FIRMWARE_BINS,
            "stored_count": len(items),
            "upload_password_configured": bool(OTA_UPLOAD_PASSWORD),
        },
    }


@router.get("/ota/firmware-verify")
def ota_firmware_verify(
    fname: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Re-hash a stored .bin and compare with its sidecar ``.sha256`` file.

    Use this to confirm a firmware artifact on disk has not been corrupted (or
    swapped) since upload. Only superadmin may call this; it reads the full
    file so don't hit it in tight loops.
    """
    assert_min_role(principal, "superadmin")
    safe = os.path.basename((fname or "").strip())
    if not safe or not safe.lower().endswith(".bin") or "/" in safe or "\\" in safe or ".." in safe:
        raise HTTPException(status_code=400, detail="invalid firmware filename")
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    path = os.path.join(OTA_FIRMWARE_DIR, safe)
    try:
        rp = os.path.realpath(path)
    except OSError:
        raise HTTPException(status_code=400, detail="invalid firmware path")
    if not (rp == os.path.join(base_dir, safe) or rp.startswith(base_dir + os.sep)):
        raise HTTPException(status_code=400, detail="path traversal rejected")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="firmware not found")
    sidecar = path + ".sha256"
    expected = ""
    if os.path.isfile(sidecar):
        try:
            with open(sidecar, "r", encoding="utf-8") as f:
                first = (f.readline() or "").strip()
                expected = (first.split()[0] if first else "").lower()
        except OSError:
            expected = ""
    h = hashlib.sha256()
    nbytes = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                nbytes += len(chunk)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"read error: {exc}")
    actual = h.hexdigest().lower()
    ok = bool(expected) and actual == expected
    return {
        "fname": safe,
        "bytes": nbytes,
        "sha256_expected": expected,
        "sha256_actual": actual,
        "ok": ok,
        "has_sidecar": bool(expected),
    }


# ──────────────────────────────────────────────────────── direct broadcast ────

@router.post("/ota/broadcast")
def ota_broadcast(req: OtaBroadcastRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    # OTA is sensitive: the .bin can brick the fleet. Only superadmin may
    # dispatch it, and because superadmin's scope is global the resulting
    # target set is "every non-revoked device" (or the explicit subset).
    assert_min_role(principal, "superadmin")
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")
    targets = resolve_target_devices(req.device_ids, principal)
    if not targets:
        return {"ok": True, "sent_count": 0, "device_ids": []}
    params: dict[str, Any] = {"url": req.url}
    if req.fw:
        params["fw"] = req.fw
    sent = 0
    for did in targets:
        try:
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="ota",
                params=params,
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
                dedupe_key=f"ota-broadcast:{did}:{req.fw or req.url}",
                dedupe_ttl_s=60.0,
            )
            sent += 1
        except Exception as exc:
            logger.warning("ota broadcast to %s failed: %s", did, exc)
    audit_event(principal.username, "ota.broadcast", req.fw or req.url, {
        "sent_count": sent,
        "target_count": len(targets),
        "fw": req.fw,
    })
    return {"ok": True, "sent_count": sent, "device_ids": targets}


# ────────────────────────────────────────────── upload (no campaign row) ────

@router.post("/ota/firmware/upload")
async def ota_firmware_upload_stage(
    principal: Principal = Depends(require_principal),
    file: UploadFile = File(...),
    fw_version: str = Form(...),
    upload_password: str = Form(...),
) -> dict[str, Any]:
    """Superadmin: store .bin only. Runs HEAD against the public URL for diagnostics; does **not** create a campaign (file kept even if HEAD fails)."""
    assert_min_role(principal, "superadmin")
    _require_ota_upload_password(upload_password)
    if not OTA_PUBLIC_BASE_URL:
        raise HTTPException(
            status_code=400,
            detail="OTA_PUBLIC_BASE_URL is not set (e.g. https://ota.esasecure.com). Devices must match config.h OTA_ALLOWED_HOST + OTA_TOKEN.",
        )
    fname, sha_hex, nbytes = await _ota_store_uploaded_bin(file, fw_version)
    url = _public_firmware_url(fname)
    ok, verify_detail, probe_masked = _verify_firmware_file_on_service(fname)
    audit_event(principal.username, "ota.firmware.stage", fname, {"size": nbytes, "url": url, "head_ok": ok})
    hint = None
    if not ok:
        hint = (
            "Probe failed — ensure nginx serves /fw/ with ?token= (OTA_TOKEN). "
            "From inside Docker use OTA_VERIFY_BASE_URL=http://ota-nginx:9231; "
            "on the host ensure HTTPS server_name ota.esasecure.com proxies to 127.0.0.1:9231."
        )
    return {
        "ok": True,
        "stored_as": fname,
        "download_url": url,
        "sha256": sha_hex,
        "size": nbytes,
        "head_ok": ok,
        "verify": verify_detail,
        "probe_url": probe_masked,
        "verify_base_used": _effective_ota_verify_base(),
        "public_base": OTA_PUBLIC_BASE_URL,
        "hint": hint,
    }


__all__ = (
    "router",
    "OtaBroadcastRequest",
    "_sha256_for",
    "_sha256_sidecar_only",
    "_safe_ota_stored_filename",
    "_ota_bin_path_for_stored_name",
    "_require_ota_upload_password",
    "_ota_store_uploaded_bin",
)
