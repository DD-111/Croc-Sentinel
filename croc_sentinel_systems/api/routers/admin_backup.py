"""Admin DB backup router (Phase-25 modularization).

Two superadmin-only endpoints that wrap an offline encrypted dump of
the SQLite database file. The encryption key is supplied per-request
via ``X-Backup-Encryption-Key`` and never persisted; if it's lost,
the backup blob is unrecoverable.

Routes
------
  GET  /admin/backup/export   (download SQLite file → AES-GCM blob)
  POST /admin/backup/import   (decrypt blob → write {DB_PATH}.restored)

Late-binding strategy
---------------------
``require_principal`` is the only cross-feature dependency and it's
defined < line ~1500 in app.py, so it's early-bound (identity-
preserved). All other helpers come from the security module directly.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, File, Header, HTTPException, Response, UploadFile

import app as _app
from db import DB_PATH
from security import Principal, assert_min_role, decrypt_blob, encrypt_blob

require_principal = _app.require_principal


logger = logging.getLogger("croc-api.routers.admin_backup")

router = APIRouter(tags=["admin-backup"])


# ---- Routes ----------------------------------------------------------------

@router.get("/admin/backup/export")
def admin_backup_export(
    principal: Principal = Depends(require_principal),
    x_backup_key: str = Header(..., alias="X-Backup-Encryption-Key"),
) -> Response:
    assert_min_role(principal, "superadmin")
    if not os.path.isfile(DB_PATH):
        raise HTTPException(status_code=404, detail="database file not found")
    with open(DB_PATH, "rb") as f:
        raw = f.read()
    if len(raw) < 16 or raw[:15] != b"SQLite format 3":
        raise HTTPException(status_code=500, detail="database file invalid")
    enc = encrypt_blob(raw, x_backup_key)
    return Response(
        content=enc,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="sentinel-backup.enc"'},
    )


@router.post("/admin/backup/import")
async def admin_backup_import(
    principal: Principal = Depends(require_principal),
    x_backup_key: str = Header(..., alias="X-Backup-Encryption-Key"),
    file: UploadFile = File(...),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    body = await file.read()
    plain = decrypt_blob(body, x_backup_key)
    if len(plain) < 16 or plain[:15] != b"SQLite format 3":
        raise HTTPException(status_code=400, detail="decrypted payload is not sqlite")
    out_path = DB_PATH + ".restored"
    with open(out_path, "wb") as f:
        f.write(plain)
    return {
        "ok": True,
        "written_path": out_path,
        "hint": "Stop the API container, replace the live DB file with this path, then start again (see docs).",
    }
