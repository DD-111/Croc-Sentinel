"""OTA URL/file utilities (Phase-40 modularization).

Ten small utility functions split into three concerns:

URL shaping
-----------
* ``_append_ota_token_to_url`` — append ``?token=OTA_TOKEN`` so the
  nginx OTA template's auth gate accepts the request (see SECURITY.md).
* ``_effective_ota_verify_base`` — internal verify base preferred over
  the public one so the API can probe ``ota-nginx`` inside Docker.
* ``_service_check_url_for_firmware`` — internal HEAD/GET URL we
  ourselves use for verification.
* ``_public_firmware_url`` — canonical URL stored in campaigns and
  shown to devices (no token in DB; the ESP32 firmware appends it).

Reachability probes
-------------------
* ``_http_probe_ota`` — HEAD first, fall back to a 1-byte ranged GET if
  the server returns 405. Returns ``(ok, detail)``.
* ``_verify_ota_url`` — token-aware wrapper around ``_http_probe_ota``.
* ``_verify_firmware_file_on_service`` — verify a stored ``.bin`` is
  reachable through ``OTA_VERIFY_BASE_URL`` / ``OTA_PUBLIC_BASE_URL``;
  returns the masked URL alongside the result so the dashboard can
  show what we actually hit (with the secret token redacted).

Disk retention
--------------
* ``_ota_delete_artifacts_for_stored_basename`` — cascade-delete a
  ``.bin`` and its sidecars (``.sha256``, ``.version``, release-notes
  ``.txt`` / ``.md`` / ``.notes``).
* ``_ota_in_use_basenames`` — set of ``.bin`` basenames referenced by
  a non-terminal OTA campaign. We refuse to prune these so devices
  mid-download don't 404 on the artifact.
* ``_ota_enforce_max_stored_bins`` — keep at most
  ``OTA_MAX_FIRMWARE_BINS`` .bin files; remove oldest by mtime first
  while protecting in-use bins. Invalidates the catalog cache when
  done so the dashboard's firmware list reflects the new state.

No late-binding needed — every dependency is either stdlib (``os``,
``urllib.*``), config (``OTA_*``), the SQLite primitives in ``db.py``,
or the catalog-cache invalidator in ``ota_catalog.py``.
"""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from config import (
    OTA_FIRMWARE_DIR,
    OTA_MAX_FIRMWARE_BINS,
    OTA_PUBLIC_BASE_URL,
    OTA_TOKEN,
    OTA_URL_VERIFY_TIMEOUT_SECONDS,
    OTA_VERIFY_BASE_URL,
)
from db import db_lock, get_conn
from ota_catalog import _invalidate_ota_firmware_catalog_cache

logger = logging.getLogger("crocapi.ota_files")


# ─────────────────────────────────────────────────────────────────────────
# URL shaping
# ─────────────────────────────────────────────────────────────────────────

def _append_ota_token_to_url(url: str) -> str:
    """Append ``?token=OTA_TOKEN`` when set — the nginx OTA template requires it (see SECURITY.md)."""
    tok = (OTA_TOKEN or "").strip()
    if not tok:
        return url
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    if q.get("token"):
        return url
    q["token"] = tok
    new_query = urlencode(q)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _effective_ota_verify_base() -> str:
    """Prefer ``OTA_VERIFY_BASE_URL`` so the API can reach ``ota-nginx`` inside Docker."""
    return (OTA_VERIFY_BASE_URL or OTA_PUBLIC_BASE_URL).rstrip("/")


def _service_check_url_for_firmware(fname: str) -> str:
    """URL the API uses for HTTP checks (may be internal Docker base)."""
    base = _effective_ota_verify_base()
    return _append_ota_token_to_url(f"{base}/fw/{fname}")


def _public_firmware_url(fname: str) -> str:
    """Canonical URL stored in campaigns / shown to devices (no token in DB; ESP adds token)."""
    return f"{OTA_PUBLIC_BASE_URL}/fw/{fname}"


# ─────────────────────────────────────────────────────────────────────────
# Reachability probes
# ─────────────────────────────────────────────────────────────────────────

def _http_probe_ota(url: str) -> tuple[bool, str]:
    """HEAD first (with optional Range GET fallback). URL should already include token if required."""
    if not url.startswith(("http://", "https://")):
        return False, "scheme_not_http"

    def _read_response(resp: Any) -> tuple[int, str]:
        code = int(getattr(resp, "status", getattr(resp, "code", 200)))
        length = resp.headers.get("content-length", "") if hasattr(resp, "headers") else ""
        return code, length or "?"

    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code, length = _read_response(resp)
            if 200 <= code < 400:
                return True, f"HEAD http_{code} size={length}"
            return False, f"HEAD http_{code}"
    except urllib.error.HTTPError as exc:
        if int(exc.code) == 405:
            pass  # fall through to GET range
        else:
            return False, f"HEAD http_{exc.code}:{exc.reason}"
    except Exception as exc:
        return False, f"HEAD_err:{exc.__class__.__name__}:{exc}"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Range", "bytes=0-0")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code, length = _read_response(resp)
            if code in (200, 206) or (200 <= code < 400):
                return True, f"GET_range http_{code} size={length}"
            return False, f"GET_range http_{code}"
    except urllib.error.HTTPError as exc:
        return False, f"GET http_{exc.code}:{exc.reason}"
    except Exception as exc:
        return False, f"GET_err:{exc.__class__.__name__}:{exc}"


def _verify_ota_url(url: str) -> tuple[bool, str]:
    """Verify the firmware URL responds (HEAD or byte-range GET). Appends ``OTA_TOKEN`` for nginx."""
    return _http_probe_ota(_append_ota_token_to_url(url))


def _verify_firmware_file_on_service(fname: str) -> tuple[bool, str, str]:
    """Check reachability via ``OTA_VERIFY_BASE_URL`` or public base; returns ``(ok, detail, checked_url_masked)``."""
    safe = os.path.basename(fname.strip())
    u = _service_check_url_for_firmware(safe)
    ok, detail = _http_probe_ota(u)
    masked = u
    tok = (OTA_TOKEN or "").strip()
    if tok:
        masked = u.replace(tok, "***")
    return ok, detail, masked


# ─────────────────────────────────────────────────────────────────────────
# Disk retention
# ─────────────────────────────────────────────────────────────────────────

def _ota_delete_artifacts_for_stored_basename(basename: str) -> None:
    """Delete ``.bin``, ``.bin.sha256``, ``.bin.version``, and sidecar release notes (stem + ``.txt``/``.md``/``.notes``)."""
    if not str(basename).endswith(".bin") or ".." in basename or "/" in basename or "\\" in basename:
        return
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    path = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, basename))
    if not path.startswith(base_dir + os.sep) or not path.lower().endswith(".bin"):
        return
    stem_name = path[:-4]  # full path without ".bin" suffix; basename for sidecars
    base_name = os.path.basename(stem_name)
    to_try: list[str] = [path, path + ".sha256", path + ".version"]
    for ext in (".txt", ".md", ".notes"):
        to_try.append(os.path.join(OTA_FIRMWARE_DIR, base_name + ext))
    for p in to_try:
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass


def _ota_in_use_basenames() -> set[str]:
    """Set of ``.bin`` basenames currently referenced by a non-terminal OTA campaign.

    We refuse to prune these so devices mid-download don't 404 on the artifact.
    """
    out: set[str] = set()
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT url FROM ota_campaigns
                WHERE state NOT IN ('success', 'failed', 'cancelled', 'rolled_back')
                """
            )
            rows = cur.fetchall() or []
            conn.close()
    except Exception as exc:
        logger.warning("in-use OTA campaign lookup failed: %s", exc)
        return out
    for r in rows:
        url = str((r["url"] if r else "") or "")
        if not url:
            continue
        try:
            tail = url.rsplit("/", 1)[-1]
            # Strip query string.
            if "?" in tail:
                tail = tail.split("?", 1)[0]
            if tail.lower().endswith(".bin"):
                out.add(tail)
        except Exception:
            continue
    return out


def _ota_enforce_max_stored_bins() -> None:
    """Keep at most ``OTA_MAX_FIRMWARE_BINS`` .bin files; remove oldest by mtime first, with artifacts.

    Never prunes a ``.bin`` that's currently referenced by an active OTA campaign — doing
    so would cause in-flight devices to fail the download and fall back to rollback.
    If the number of in-use bins alone already exceeds the limit, we keep them all and
    warn so the operator can raise ``OTA_MAX_FIRMWARE_BINS``.
    """
    base = os.path.realpath(OTA_FIRMWARE_DIR)
    if not os.path.isdir(base):
        return
    in_use = _ota_in_use_basenames()
    items: list[tuple[int, str, str]] = []  # mtime, name, relpath join path
    for name in os.listdir(OTA_FIRMWARE_DIR):
        if not str(name).lower().endswith(".bin"):
            continue
        p = os.path.join(OTA_FIRMWARE_DIR, name)
        if not os.path.isfile(p):
            continue
        try:
            rp = os.path.realpath(p)
        except OSError:
            continue
        if not str(rp).startswith(base + os.sep):
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        items.append((int(st.st_mtime), str(name), p))
    items.sort(key=lambda t: (t[0], t[1]))
    idx = 0
    kept_protected = 0
    while len(items) > OTA_MAX_FIRMWARE_BINS and idx < len(items):
        _m, name, _p = items[idx]
        if name in in_use:
            kept_protected += 1
            idx += 1
            continue
        items.pop(idx)
        _ota_delete_artifacts_for_stored_basename(name)
    if len(items) > OTA_MAX_FIRMWARE_BINS and kept_protected > 0:
        logger.warning(
            "OTA retention: %d artifact(s) kept above limit=%d because they are in-use by active campaigns",
            kept_protected, OTA_MAX_FIRMWARE_BINS,
        )
    _invalidate_ota_firmware_catalog_cache()


__all__ = [
    "_append_ota_token_to_url",
    "_effective_ota_verify_base",
    "_service_check_url_for_firmware",
    "_public_firmware_url",
    "_http_probe_ota",
    "_verify_ota_url",
    "_verify_firmware_file_on_service",
    "_ota_delete_artifacts_for_stored_basename",
    "_ota_in_use_basenames",
    "_ota_enforce_max_stored_bins",
]
