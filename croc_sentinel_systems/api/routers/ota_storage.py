"""Firmware-bytes storage helpers (Phase-79 split from ``routers/ota.py``).

Phase 65 carved the OTA-campaigns surface out of the original
``routers/ota.py`` (8 routes → ``routers/ota_campaigns.py``) and
Phase 77 split its lifecycle half off again
(``routers/ota_campaigns_lifecycle.py``). What was left on
``routers/ota.py`` was ~250 lines of *route* handlers and ~100 lines
of *byte-handling* helpers — the helpers stayed in ``routers/ota.py``
because they're shared with ``routers/ota_campaigns.py`` (the
``/ota/campaigns/from-upload`` and ``/ota/campaigns/from-stored``
routes need them).

Phase 79 splits those helpers here so:

  * ``routers/ota.py`` becomes a routes-only file (~340 lines, one
    short re-export block at the top for backward compat).
  * ``routers/ota_storage.py`` owns the byte-handling primitives —
    a pure stateless layer with no FastAPI / Pydantic / DB
    dependencies, importable from unit tests without
    spinning up the API.
  * ``routers/ota_campaigns.py`` continues to work because either
    (a) it imports from ``routers/ota_storage`` directly (single
    source of truth) OR (b) the ``routers/ota`` star-export still
    surfaces these names for any historical caller.

Public surface
--------------
  ``_sha256_sidecar_only(path)``        — fast path: read ``.sha256``
                                          sidecar file only, no
                                          full-file read.
  ``_sha256_for(path)``                 — sidecar-first; falls back
                                          to a streaming SHA-256 of
                                          the .bin (chunked at 64 KiB
                                          so we don't OOM on a 10 MB
                                          firmware).
  ``_safe_ota_stored_filename(...)``    — sanitize ``fw_version`` →
                                          ``croc-<fw>-<random>.bin``.
                                          Bounds the version to 28
                                          chars, restricts to
                                          ``[A-Za-z0-9._-]``, and
                                          appends a 4-byte random tail
                                          so concurrent uploads don't
                                          collide.
  ``_ota_bin_path_for_stored_name(name)`` — resolve a basename under
                                            ``OTA_FIRMWARE_DIR``
                                            with strict path-traversal
                                            rejection (must end up
                                            under the realpath of the
                                            firmware dir).
  ``_require_ota_upload_password(p)``   — constant-time compare against
                                          ``OTA_UPLOAD_PASSWORD``;
                                          raises 503 when unset (so
                                          uploads are explicitly
                                          disabled rather than
                                          silently accepting any
                                          password).
  ``_ota_store_uploaded_bin(file, fw)`` — async multipart writer that
                                          enforces ``MAX_OTA_UPLOAD_BYTES``,
                                          rejects implausibly small
                                          files (<1 KiB), writes the
                                          .bin + .sha256 sidecar +
                                          optional .version sidecar,
                                          then calls
                                          ``_ota_enforce_max_stored_bins``
                                          for retention.

Late-bound dependency
---------------------
``_ota_enforce_max_stored_bins`` is **defined later** in ``app.py``
than this module's import time, so we late-bind it via
``import app as _app`` and a thin call-time wrapper. (Same
trick the original ``routers/ota.py`` used for the same reason.)

Design notes
------------
We deliberately raise ``HTTPException`` (not ``ValueError``) inside
these helpers — they're called from FastAPI routes and we want a
proper 4xx response with a useful detail string at the user-facing
boundary. Tests can ``import HTTPException`` and ``pytest.raises``
on it like any other exception.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Optional

from fastapi import HTTPException, UploadFile

import app as _app
from config import (
    MAX_OTA_UPLOAD_BYTES,
    OTA_FIRMWARE_DIR,
    OTA_UPLOAD_PASSWORD,
)


# ``_ota_enforce_max_stored_bins`` is *defined later* in app.py (after
# ``include_router`` for the ota module, since the retention helpers
# stay in app.py for non-OTA callers). Late-bind via a wrapper
# instead of a module-load-time attribute capture, otherwise we'd
# hit AttributeError during ``import app``.
def _ota_enforce_max_stored_bins() -> None:
    _app._ota_enforce_max_stored_bins()


# ─────────────────────────────────────────────── SHA-256 readers ────


def _sha256_sidecar_only(path: str) -> Optional[str]:
    """Return the SHA-256 hex from the ``.sha256`` sidecar, or ``None``.

    Used in catalog listings to avoid streaming the full firmware
    on every dashboard render. The sidecar format is the standard
    ``sha256sum`` two-column output (``<hex>  <fname>``); we only
    consume the first whitespace-separated token.
    """
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
    """SHA-256 hex for ``path``: sidecar-first, then chunked stream.

    Returns ``None`` on any read error so callers can degrade gracefully
    (e.g. the dashboard shows ``sha256: null`` rather than 500ing the
    whole listing because one .bin is unreadable).

    Chunked at 64 KiB so a multi-MB firmware can't blow up the API
    process's memory budget while we hash it.
    """
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


# ─────────────────────────────────────────────── filename safety ────


def _safe_ota_stored_filename(fw_version: str, original_filename: str) -> str:
    """Compose a safe stored filename from a user-supplied fw_version.

    Output shape: ``croc-<safe_fw>-<8-hex-bytes>.bin``.

    * Rejects anything that doesn't end in ``.bin`` (this is the
      first defense against operators uploading non-firmware files
      that nginx might happily serve as ``application/octet-stream``).
    * Restricts ``fw_version`` to ``[A-Za-z0-9._-]`` so the rendered
      filename can't smuggle path separators or shell metacharacters.
    * Caps ``fw_version`` at 28 chars (filename total fits comfortably
      in 64 chars, leaving room for the ``croc-`` prefix and 9-byte
      random tail).
    * The 8-hex-byte tail makes filenames unique even when two
      operators upload the same fw_version simultaneously.
    """
    base = os.path.basename(original_filename or "")
    if not base.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="upload must be a .bin file")
    safe_fw = re.sub(r"[^a-zA-Z0-9._-]", "_", (fw_version or "").strip())[:28]
    if not safe_fw:
        safe_fw = "fw"
    tail = secrets.token_hex(4)
    return f"croc-{safe_fw}-{tail}.bin"


def _ota_bin_path_for_stored_name(fname: str) -> str:
    """Resolve a basename under ``OTA_FIRMWARE_DIR`` with no path traversal.

    Three failure modes (all raise 4xx):
      1. Filename doesn't end in ``.bin`` → 400.
      2. Resolved real path escapes ``OTA_FIRMWARE_DIR`` → 400
         (path-traversal rejection — guards against ``../../etc/passwd``-
         style attacks even though we already basename-strip the input).
      3. File doesn't exist → 404.
    """
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


# ─────────────────────────────────────── upload-password gate ────


def _require_ota_upload_password(provided: str | None) -> None:
    """Constant-time compare against ``OTA_UPLOAD_PASSWORD``.

    Two intentional design choices:

      * **Unset password ≠ allow anything.** When
        ``OTA_UPLOAD_PASSWORD`` is empty we raise 503 (service
        unavailable) so an operator who forgets to set it doesn't
        accidentally expose unauthenticated firmware staging — the
        dashboard surfaces the 503 with the explicit
        "set OTA_UPLOAD_PASSWORD" remediation hint.
      * **Constant-time compare.** ``hmac.compare_digest`` resists
        timing oracles even though length-comparison short-circuits
        the early exit; the length check itself is fine because the
        attacker already knows the password length isn't the secret.
    """
    if not OTA_UPLOAD_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail=(
                "OTA_UPLOAD_PASSWORD is not set on the server; firmware uploads "
                "are disabled. Set it in the API environment."
            ),
        )
    a = OTA_UPLOAD_PASSWORD
    b = (provided or "")
    if len(a) != len(b) or not hmac.compare_digest(a, b):
        raise HTTPException(status_code=403, detail="Invalid upload password")


# ─────────────────────────────────────── multipart writer ────


async def _ota_store_uploaded_bin(file: UploadFile, fw_version: str) -> tuple[str, str, int]:
    """Persist a multipart .bin upload + sha256 + version sidecars.

    Returns ``(stored_basename, sha256_hex, byte_size)``.

    Order of operations (strict — don't reorder):
      1. ``mkdir -p`` the firmware dir (idempotent).
      2. Compute the sanitized stored basename (see
         ``_safe_ota_stored_filename``).
      3. Read full body. Reject >``MAX_OTA_UPLOAD_BYTES`` (413) and
         <1 KiB (400 — anything that small is a misdial, not a
         firmware).
      4. Compute SHA-256 of body in-memory (already in RAM from
         step 3 anyway).
      5. Write .bin + .sha256 sidecar; write .version sidecar only
         if ``fw_version`` is non-empty (delete a stale .version
         sidecar otherwise).
      6. Run retention sweep (``_ota_enforce_max_stored_bins``) so a
         single upload can't push the dir past
         ``OTA_MAX_FIRMWARE_BINS``.
    """
    os.makedirs(OTA_FIRMWARE_DIR, mode=0o755, exist_ok=True)
    fname = _safe_ota_stored_filename(fw_version, file.filename or "")
    dest = os.path.join(OTA_FIRMWARE_DIR, fname)
    body = await file.read()
    if len(body) > MAX_OTA_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413, detail=f"file exceeds {MAX_OTA_UPLOAD_BYTES} bytes"
        )
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


__all__ = (
    "_sha256_sidecar_only",
    "_sha256_for",
    "_safe_ota_stored_filename",
    "_ota_bin_path_for_stored_name",
    "_require_ota_upload_password",
    "_ota_store_uploaded_bin",
)
