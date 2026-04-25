"""OTA campaign creation + read views (Phase-65 split from
``routers/ota.py``, trimmed Phase 77).

Owns the **build + browse** half of the 2-stage OTA campaign flow:

  * Superadmin creates a campaign (3 routes — explicit URL,
    staged .bin, upload+create combo).
  * Admins list / read campaigns to see what's pending acceptance.

The **state-machine** half (accept / decline / rollback) lives in
``routers/ota_campaigns_lifecycle.py`` (Phase 77 split). That
module is responsible for re-verifying the URL on accept, fanning
out the actual rollout via ``_start_ota_rollout_for_admin``, and
the manual ``_rollback_admin_devices`` path.

Routes hosted here (all behind ``Depends(require_principal)``)
---------------------------------------------------------------
  POST /ota/campaigns                  [superadmin]  — explicit URL
  POST /ota/campaigns/from-stored      [superadmin]  — staged .bin
  POST /ota/campaigns/from-upload      [superadmin]  — upload + create
  GET  /ota/campaigns                  [admin+]      — list
  GET  /ota/campaigns/{campaign_id}    [admin+]      — detail

What stays in ``routers/ota.py``
--------------------------------
The diagnostics endpoints, the inventory listing, the file-on-disk
verifier, the direct broadcast, and the staging-only upload route
(``/ota/firmware/upload``) all live in ``routers/ota.py`` because
they share the upload helpers (``_ota_store_uploaded_bin`` /
``_ota_bin_path_for_stored_name`` / ``_require_ota_upload_password``)
which are produced there. We import those four names back here so
``/ota/campaigns/from-stored`` and ``/ota/campaigns/from-upload`` —
the two campaign routes that touch the firmware bytes — still work.

Late binding
------------
Captured off ``app`` at module-load time:
  ``require_principal``, ``_public_firmware_url``,
  ``_verify_firmware_file_on_service``, ``_verify_ota_url``,
  ``_version_str_for_ota_bin_file``,
  ``_invalidate_ota_firmware_catalog_cache``.

(Lifecycle-only late-binds — ``_ota_campaign_targets_for_admin``,
``_rollback_admin_devices``, ``_start_ota_rollout_for_admin`` —
moved with the routes to ``routers/ota_campaigns_lifecycle.py``.)
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    OTA_FIRMWARE_DIR,
    OTA_PUBLIC_BASE_URL,
)
from db import db_lock, db_read_lock, get_conn
from helpers import utc_now_iso
from routers.ota_storage import (
    _ota_bin_path_for_stored_name,
    _ota_store_uploaded_bin,
    _require_ota_upload_password,
    _sha256_for,
)
from security import Principal, assert_min_role

require_principal = _app.require_principal
_public_firmware_url = _app._public_firmware_url
_verify_firmware_file_on_service = _app._verify_firmware_file_on_service
_verify_ota_url = _app._verify_ota_url
_version_str_for_ota_bin_file = _app._version_str_for_ota_bin_file
_invalidate_ota_firmware_catalog_cache = _app._invalidate_ota_firmware_catalog_cache


logger = logging.getLogger("croc-api.routers.ota_campaigns")
router = APIRouter(tags=["ota-campaigns"])


# ───────────────────────────────────────────────────── request schemas ────

class OtaCampaignCreateRequest(BaseModel):
    fw_version: str = Field(min_length=1, max_length=40)
    url: str = Field(min_length=8, max_length=400)
    sha256: Optional[str] = Field(default=None, max_length=128)
    notes: Optional[str] = Field(default=None, max_length=500)
    target_admins: list[str] = Field(default_factory=lambda: ["*"], max_length=256)


class OtaCampaignFromStoredRequest(BaseModel):
    filename: str = Field(min_length=4, max_length=200)
    fw_version: Optional[str] = Field(default=None, max_length=40)
    notes: Optional[str] = Field(default=None, max_length=500)
    target_admins: list[str] = Field(default_factory=lambda: ["*"], max_length=256)


# ─────────────────────────────────────────── helpers (campaigns-only) ────

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


# ─────────────────────────────────────── routes: campaign creation ────

@router.post("/ota/campaigns")
def create_ota_campaign(req: OtaCampaignCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    return _insert_ota_campaign(principal, req)


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


__all__ = (
    "router",
    "OtaCampaignCreateRequest",
    "OtaCampaignFromStoredRequest",
)
