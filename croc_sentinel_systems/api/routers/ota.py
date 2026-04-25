"""OTA firmware staging + campaign routes (Phase-13 modularization extract from ``app.py``).

Fourteen endpoints covering firmware staging, broadcast, and the
2-stage campaign flow (superadmin -> admin accept/decline -> rollout):

  GET    /ota/service-check                       — diagnostics (no secrets)
  GET    /ota/firmware-reachability               — HEAD-probe staged file
  GET    /ota/firmwares                           — superadmin: inventory
  GET    /ota/firmware-verify                     — re-hash a stored .bin
  POST   /ota/broadcast                           — direct fan-out (no campaign row)
  POST   /ota/firmware/upload                     — stage .bin, return URL
  POST   /ota/campaigns/from-stored               — campaign from already-staged .bin
  POST   /ota/campaigns                           — campaign from explicit URL
  POST   /ota/campaigns/from-upload               — upload .bin AND create campaign
  GET    /ota/campaigns                           — list (admin/superadmin)
  GET    /ota/campaigns/{campaign_id}             — detail (admin/superadmin)
  POST   /ota/campaigns/{campaign_id}/accept      — admin accept -> rollout
  POST   /ota/campaigns/{campaign_id}/decline     — admin decline
  POST   /ota/campaigns/{campaign_id}/rollback    — manual rollback trigger

Helpers and request schemas
---------------------------
The following are *moved with* the routes (only callers were inside
this block):

  Request schemas:
    OtaBroadcastRequest, OtaCampaignCreateRequest,
    OtaCampaignFromStoredRequest

  Helpers (internal-only):
    _sha256_sidecar_only, _sha256_for, _list_all_admin_usernames,
    _insert_ota_campaign, _safe_ota_stored_filename,
    _ota_bin_path_for_stored_name, _require_ota_upload_password,
    _ota_store_uploaded_bin

The following helpers stay in ``app.py`` because non-OTA code paths
reference them (we late-bind from here):

  _public_firmware_url, _verify_firmware_file_on_service,
  _effective_ota_verify_base, _verify_ota_url,
  _ota_campaign_targets_for_admin, _rollback_admin_devices,
  _start_ota_rollout_for_admin, _version_str_for_ota_bin_file,
  _get_ota_firmware_catalog, _invalidate_ota_firmware_catalog_cache,
  _ota_enforce_max_stored_bins (still called from non-OTA path),
  resolve_target_devices, publish_command, get_cmd_key_for_device,
  require_capability, require_principal

We deliberately reference function objects directly in
``Depends(require_principal)`` — never wrap in a lambda. See
routers/factory.py for the long write-up of the trap.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    CMD_PROTO,
    MAX_OTA_UPLOAD_BYTES,
    OTA_FIRMWARE_DIR,
    OTA_MAX_FIRMWARE_BINS,
    OTA_PUBLIC_BASE_URL,
    OTA_TOKEN,
    OTA_UPLOAD_PASSWORD,
    OTA_VERIFY_BASE_URL,
    TOPIC_ROOT,
)
from db import db_lock, db_read_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
require_capability = _app.require_capability
resolve_target_devices = _app.resolve_target_devices
publish_command = _app.publish_command
get_cmd_key_for_device = _app.get_cmd_key_for_device
_public_firmware_url = _app._public_firmware_url
_verify_firmware_file_on_service = _app._verify_firmware_file_on_service
_effective_ota_verify_base = _app._effective_ota_verify_base
_verify_ota_url = _app._verify_ota_url
_ota_campaign_targets_for_admin = _app._ota_campaign_targets_for_admin
_rollback_admin_devices = _app._rollback_admin_devices
_start_ota_rollout_for_admin = _app._start_ota_rollout_for_admin
_version_str_for_ota_bin_file = _app._version_str_for_ota_bin_file
_get_ota_firmware_catalog = _app._get_ota_firmware_catalog
_invalidate_ota_firmware_catalog_cache = _app._invalidate_ota_firmware_catalog_cache
# `_ota_enforce_max_stored_bins` is *defined later* in app.py (after the
# ``include_router`` line for this module, since the retention helpers
# stay in app.py for non-OTA callers). Use a call-time lookup instead of
# a module-load-time attribute capture, otherwise we'd hit AttributeError
# during `import app`.
def _ota_enforce_max_stored_bins() -> None:
    _app._ota_enforce_max_stored_bins()

logger = logging.getLogger("croc-api.routers.ota")

router = APIRouter(tags=["ota"])


# ───────────────────────────────────────────────────── request schemas ────

class OtaBroadcastRequest(BaseModel):
    url: str = Field(min_length=8, max_length=400)
    fw: str = Field(default="", max_length=40)
    device_ids: list[str] = Field(default_factory=list)


class OtaCampaignCreateRequest(BaseModel):
    fw_version: str = Field(min_length=1, max_length=40)
    url: str = Field(min_length=8, max_length=400)
    sha256: Optional[str] = Field(default=None, max_length=128)
    notes: Optional[str] = Field(default=None, max_length=500)
    # ["*"] = every admin; otherwise an explicit list.
    target_admins: list[str] = Field(default_factory=lambda: ["*"], max_length=256)


class OtaCampaignFromStoredRequest(BaseModel):
    filename: str = Field(min_length=4, max_length=200)
    # Deprecated: was required; version is now always taken from server-side staged metadata
    # (.version sidecar and/or filename), same as GET /ota/firmwares "fw_version".
    fw_version: Optional[str] = Field(default=None, max_length=40)
    notes: Optional[str] = Field(default=None, max_length=500)
    target_admins: list[str] = Field(default_factory=lambda: ["*"], max_length=256)


# ─────────────────────────────────────── helpers (OTA-only, moved here) ────

def _sha256_sidecar_only(path: str) -> Optional[str]:
    """Fast path for listings: use .sha256 sidecar only (no full-file read)."""
    sidecar = path + ".sha256"
    if not os.path.isfile(sidecar):
        return None
    try:
        with open(sidecar, "r", encoding="utf-8", errors="ignore") as f:
            line = f.readline().strip()
        if line:
            return line.split()[0]
    except Exception:
        return None
    return None


def _sha256_for(path: str) -> Optional[str]:
    hit = _sha256_sidecar_only(path)
    if hit:
        return hit
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _list_all_admin_usernames() -> list[str]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username FROM dashboard_users WHERE role = 'admin' AND (status IS NULL OR status='' OR status='active')",
        )
        rows = cur.fetchall()
        conn.close()
    return [str(r["username"]) for r in rows]


def _insert_ota_campaign(principal: Principal, req: OtaCampaignCreateRequest) -> dict[str, Any]:
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")

    if req.target_admins == ["*"] or not req.target_admins:
        admins = _list_all_admin_usernames()
    else:
        admins = [a for a in req.target_admins if a and a != "*"]
        if not admins:
            raise HTTPException(status_code=400, detail="no target admins")

    campaign_id = "otac-" + secrets.token_urlsafe(10)
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ota_campaigns (id, created_by, fw_version, url, sha256, notes, target_admins_json, state, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'dispatched', ?, ?)
            """,
            (campaign_id, principal.username, req.fw_version, req.url, req.sha256 or "", req.notes or "", json.dumps(admins), now_iso, now_iso),
        )
        conn.commit()
        conn.close()

    audit_event(principal.username, "ota.campaign.create", campaign_id, {
        "fw_version": req.fw_version, "url": req.url, "target_admins": admins,
    })
    return {"ok": True, "campaign_id": campaign_id, "target_admins": admins, "state": "dispatched"}


def _safe_ota_stored_filename(fw_version: str, original_filename: str) -> str:
    base = os.path.basename(original_filename or "")
    if not base.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="upload must be a .bin file")
    safe_fw = re.sub(r"[^a-zA-Z0-9._-]", "_", (fw_version or "").strip())[:28]
    if not safe_fw:
        safe_fw = "fw"
    tail = secrets.token_hex(4)
    return f"croc-{safe_fw}-{tail}.bin"


def _ota_bin_path_for_stored_name(fname: str) -> str:
    """Resolve a firmware basename under OTA_FIRMWARE_DIR (no path traversal)."""
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    name = os.path.basename((fname or "").strip())
    if not name.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="filename must be a .bin file")
    path = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, name))
    if not path.startswith(base_dir + os.sep):
        raise HTTPException(status_code=400, detail="invalid firmware filename")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="firmware file not found on server")
    return path


def _require_ota_upload_password(provided: str | None) -> None:
    """Server-side shared secret for staging .bin (separate from JWT). Constant-time compare."""
    if not OTA_UPLOAD_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="OTA_UPLOAD_PASSWORD is not set on the server; firmware uploads are disabled. Set it in the API environment.",
        )
    a = OTA_UPLOAD_PASSWORD
    b = (provided or "")
    if len(a) != len(b) or not hmac.compare_digest(a, b):
        raise HTTPException(status_code=403, detail="Invalid upload password")


async def _ota_store_uploaded_bin(file: UploadFile, fw_version: str) -> tuple[str, str, int]:
    """Save multipart upload to OTA_FIRMWARE_DIR. Returns (fname_on_disk, sha256_hex, byte_size)."""
    os.makedirs(OTA_FIRMWARE_DIR, mode=0o755, exist_ok=True)
    fname = _safe_ota_stored_filename(fw_version, file.filename or "")
    dest = os.path.join(OTA_FIRMWARE_DIR, fname)
    body = await file.read()
    if len(body) > MAX_OTA_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"file exceeds {MAX_OTA_UPLOAD_BYTES} bytes")
    if len(body) < 1024:
        raise HTTPException(status_code=400, detail="file too small to be a firmware image")
    sha_hex = hashlib.sha256(body).hexdigest()
    try:
        with open(dest, "wb") as out:
            out.write(body)
        with open(dest + ".sha256", "w", encoding="utf-8") as sf:
            sf.write(f"{sha_hex}  {fname}\n")
        ver = (fw_version or "").strip()
        if ver:
            with open(dest + ".version", "w", encoding="utf-8") as vf:
                vf.write(ver + "\n")
        else:
            try:
                if os.path.isfile(dest + ".version"):
                    os.remove(dest + ".version")
            except OSError:
                pass
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"failed to save firmware: {exc}") from exc
    _ota_enforce_max_stored_bins()
    return fname, sha_hex, len(body)


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


# ────────────────────────────────────────────── upload + create campaign ────

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


@router.post("/ota/campaigns/from-stored")
def create_ota_campaign_from_stored(req: OtaCampaignFromStoredRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin: create an OTA campaign for a file already under OTA_FIRMWARE_DIR (uploaded or copied). HEAD must succeed."""
    assert_min_role(principal, "superadmin")
    if not OTA_PUBLIC_BASE_URL:
        raise HTTPException(
            status_code=400,
            detail="OTA_PUBLIC_BASE_URL is not set (e.g. https://ota.esasecure.com). Devices must match config.h OTA_ALLOWED_HOST + OTA_TOKEN.",
        )
    path = _ota_bin_path_for_stored_name(req.filename)
    fname = os.path.basename(path)
    sha_hex = _sha256_for(path)
    if not sha_hex:
        raise HTTPException(status_code=500, detail="could not compute firmware SHA-256")
    url = _public_firmware_url(fname)
    ok, verify_detail, probe_masked = _verify_firmware_file_on_service(fname)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail=(
                f"firmware HTTP check failed ({verify_detail}); probed {probe_masked}. "
                "Set OTA_TOKEN to match nginx; optional OTA_VERIFY_BASE_URL=http://ota-nginx:9231 for Docker. "
                "Public URL for devices remains OTA_PUBLIC_BASE_URL."
            ),
        )
    # Campaign version label: single source of truth = staged .bin metadata (not client hand-typed).
    resolved_fw = _version_str_for_ota_bin_file(path, fname).strip()
    if not resolved_fw:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve firmware version for this file. Add a <name>.version file next to the .bin, or re-upload from the dashboard with a version label.",
        )
    insert_req = OtaCampaignCreateRequest(
        fw_version=resolved_fw,
        url=url,
        sha256=sha_hex,
        notes=(req.notes or "").strip() or None,
        target_admins=req.target_admins,
    )
    out = _insert_ota_campaign(principal, insert_req)
    out["stored_as"] = fname
    out["download_url"] = url
    out["sha256"] = sha_hex
    out["verify"] = verify_detail
    out["fw_version"] = resolved_fw
    audit_event(principal.username, "ota.campaign.from_stored", fname, {"fw_version": resolved_fw, "url": url})
    return out


@router.post("/ota/campaigns")
def create_ota_campaign(req: OtaCampaignCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    return _insert_ota_campaign(principal, req)


@router.post("/ota/campaigns/from-upload")
async def ota_campaign_from_upload(
    principal: Principal = Depends(require_principal),
    file: UploadFile = File(...),
    fw_version: str = Form(...),
    upload_password: str = Form(...),
    notes: str = Form(""),
    target_admins: str = Form("*"),
) -> dict[str, Any]:
    """Superadmin: upload .bin to OTA_FIRMWARE_DIR, HEAD-verify public URL, then create the same campaign row as POST /ota/campaigns."""
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
    if not ok:
        dest = os.path.join(OTA_FIRMWARE_DIR, fname)
        try:
            if os.path.isfile(dest):
                os.remove(dest)
            if os.path.isfile(dest + ".sha256"):
                os.remove(dest + ".sha256")
            if os.path.isfile(dest + ".version"):
                os.remove(dest + ".version")
        except OSError:
            pass
        _invalidate_ota_firmware_catalog_cache()
        raise HTTPException(
            status_code=400,
            detail=(
                f"firmware saved but HTTP check failed ({verify_detail}); probed {probe_masked}. "
                "Set OTA_TOKEN (nginx token gate). Use OTA_VERIFY_BASE_URL=http://ota-nginx:9231 if public hostname is unreachable from the API container."
            ),
        )

    ta = (target_admins or "").strip()
    if not ta or ta == "*":
        admins_list: list[str] = ["*"]
    else:
        admins_list = [x for x in re.split(r"[\s,;]+", ta) if x]

    req = OtaCampaignCreateRequest(
        fw_version=fw_version.strip(),
        url=url,
        sha256=sha_hex,
        notes=(notes.strip() or None),
        target_admins=admins_list,
    )
    out = _insert_ota_campaign(principal, req)
    out["stored_as"] = fname
    out["download_url"] = url
    out["sha256"] = sha_hex
    out["verify"] = verify_detail
    audit_event(principal.username, "ota.firmware.upload", fname, {"size": nbytes, "url": url})
    return out


# ──────────────────────────────────────────────────── campaigns: read ────

@router.get("/ota/campaigns")
def list_ota_campaigns(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin sees every campaign; admin sees only campaigns that list them."""
    # Campaign metadata is a fleet-management concern — sub-users (role=user)
    # have no legitimate reason to enumerate it, and for target_admins=['*']
    # they'd otherwise see every in-flight OTA. Gate at admin.
    assert_min_role(principal, "admin")
    items: list[dict[str, Any]] = []
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, created_by, fw_version, url, sha256, notes, target_admins_json, state, created_at, updated_at FROM ota_campaigns ORDER BY created_at DESC LIMIT 200",
        )
        rows = [dict(r) for r in cur.fetchall()]
        # Enrich with per-admin decision + counters.
        for r in rows:
            r["target_admins"] = json.loads(str(r.pop("target_admins_json") or "[]"))
            cur.execute(
                "SELECT admin_username, action, decided_at, detail FROM ota_decisions WHERE campaign_id = ?",
                (r["id"],),
            )
            r["decisions"] = [dict(x) for x in cur.fetchall()]
            cur.execute(
                "SELECT state, COUNT(*) AS c FROM ota_device_runs WHERE campaign_id = ? GROUP BY state",
                (r["id"],),
            )
            counters = {str(x["state"]): int(x["c"]) for x in cur.fetchall()}
            r["counters"] = counters
        conn.close()

    if principal.role == "superadmin":
        items = rows
    else:
        user = principal.username
        for r in rows:
            if "*" in r["target_admins"] or user in r["target_admins"]:
                items.append(r)
    return {"items": items}


@router.get("/ota/campaigns/{campaign_id}")
def get_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    # Same reasoning as list endpoint: fleet OTA detail is admin+ territory.
    assert_min_role(principal, "admin")
    with db_read_lock():
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM ota_campaigns WHERE id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="campaign not found")
        camp = dict(row)
        camp["target_admins"] = json.loads(str(camp.pop("target_admins_json") or "[]"))

        visible = principal.role == "superadmin" or "*" in camp["target_admins"] or principal.username in camp["target_admins"]
        if not visible:
            conn.close()
            raise HTTPException(status_code=403, detail="not your campaign")

        cur.execute("SELECT admin_username, action, decided_at, detail FROM ota_decisions WHERE campaign_id = ?", (campaign_id,))
        camp["decisions"] = [dict(x) for x in cur.fetchall()]

        runs_query = "SELECT campaign_id, admin_username, device_id, prev_fw, prev_url, target_fw, target_url, state, error, started_at, finished_at FROM ota_device_runs WHERE campaign_id = ?"
        runs_args: list[Any] = [campaign_id]
        if principal.role == "admin":
            runs_query += " AND admin_username = ?"
            runs_args.append(principal.username)
        runs_query += " ORDER BY admin_username, device_id"
        cur.execute(runs_query, tuple(runs_args))
        camp["device_runs"] = [dict(x) for x in cur.fetchall()]
        conn.close()
    return camp


# ─────────────────────────────────────────── campaigns: state machine ────

@router.post("/ota/campaigns/{campaign_id}/accept")
def accept_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Admin accepts the campaign → server verifies URL then fans OTA cmd out
    to every device the admin owns."""
    assert_min_role(principal, "admin")
    admin_username = principal.username

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM ota_campaigns WHERE id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="campaign not found")
        camp = dict(row)
        targets = json.loads(str(camp.get("target_admins_json") or "[]"))
        if "*" not in targets and admin_username not in targets:
            conn.close()
            raise HTTPException(status_code=403, detail="not your campaign")

        cur.execute(
            "SELECT action FROM ota_decisions WHERE campaign_id = ? AND admin_username = ?",
            (campaign_id, admin_username),
        )
        prev = cur.fetchone()
        if prev and str(prev["action"]) in ("accepted",):
            conn.close()
            raise HTTPException(status_code=409, detail="already accepted")
        conn.close()

    ok, detail = _verify_ota_url(str(camp["url"]))
    if not ok:
        audit_event(admin_username, "ota.campaign.url_verify_fail", campaign_id, {"detail": detail})
        raise HTTPException(status_code=400, detail=f"url verify failed: {detail}")

    # Pre-populate ota_device_runs with every device this admin owns.
    targets_rows = _ota_campaign_targets_for_admin(admin_username, str(camp["fw_version"]), str(camp["url"]))
    if not targets_rows:
        # Still mark decision as accepted so superadmin can see the admin reacted.
        now_iso = utc_now_iso()
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
                VALUES (?, ?, 'accepted', ?, 'no devices')
                ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
                  action='accepted', decided_at=excluded.decided_at, detail=excluded.detail
                """,
                (campaign_id, admin_username, now_iso),
            )
            conn.commit()
            conn.close()
        return {"ok": True, "dispatched": 0, "note": "no devices owned by this admin"}

    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for t in targets_rows:
            cur.execute(
                """
                INSERT INTO ota_device_runs
                    (campaign_id, admin_username, device_id, prev_fw, prev_url, target_fw, target_url, state, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                ON CONFLICT(campaign_id, device_id) DO UPDATE SET
                    admin_username = excluded.admin_username,
                    prev_fw        = excluded.prev_fw,
                    prev_url       = excluded.prev_url,
                    target_fw      = excluded.target_fw,
                    target_url     = excluded.target_url,
                    state          = CASE WHEN ota_device_runs.state IN ('success','failed','rolled_back') THEN ota_device_runs.state ELSE 'pending' END,
                    updated_at     = excluded.updated_at
                """,
                (campaign_id, admin_username, t["device_id"], t["prev_fw"], t["prev_url"], str(camp["fw_version"]), str(camp["url"]), now_iso, now_iso),
            )
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'accepted', ?, ?)
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='accepted', decided_at=excluded.decided_at, detail=excluded.detail
            """,
            (campaign_id, admin_username, now_iso, detail),
        )
        cur.execute("UPDATE ota_campaigns SET state='running', updated_at=? WHERE id=?", (now_iso, campaign_id))
        conn.commit()
        conn.close()

    dispatched, failures = _start_ota_rollout_for_admin(campaign_id, admin_username)
    audit_event(admin_username, "ota.campaign.accept", campaign_id, {
        "dispatched": dispatched,
        "failures": failures[:5],
        "target_count": len(targets_rows),
        "verify": detail,
    })
    return {"ok": True, "dispatched": dispatched, "target_count": len(targets_rows), "verify": detail, "failures": failures[:5]}


@router.post("/ota/campaigns/{campaign_id}/decline")
def decline_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    admin_username = principal.username
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT target_admins_json FROM ota_campaigns WHERE id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="campaign not found")
        targets = json.loads(str(row["target_admins_json"] or "[]"))
        if "*" not in targets and admin_username not in targets:
            conn.close()
            raise HTTPException(status_code=403, detail="not your campaign")
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'declined', ?, '')
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='declined', decided_at=excluded.decided_at
            """,
            (campaign_id, admin_username, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    audit_event(admin_username, "ota.campaign.decline", campaign_id, {})
    return {"ok": True}


@router.post("/ota/campaigns/{campaign_id}/rollback")
def rollback_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Explicit rollback trigger (in addition to automatic rollback on failure)."""
    assert_min_role(principal, "admin")
    admin_username = principal.username
    if principal.role == "superadmin":
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT admin_username FROM ota_device_runs WHERE campaign_id = ?", (campaign_id,))
            admins = [str(r["admin_username"]) for r in cur.fetchall()]
            conn.close()
        rolled_total = 0
        for a in admins:
            rolled_total += _rollback_admin_devices(campaign_id, a, reason=f"manual rollback by superadmin {principal.username}")
        return {"ok": True, "rolled_back": rolled_total, "admins": admins}
    rolled = _rollback_admin_devices(campaign_id, admin_username, reason=f"manual rollback by admin {admin_username}")
    return {"ok": True, "rolled_back": rolled}
