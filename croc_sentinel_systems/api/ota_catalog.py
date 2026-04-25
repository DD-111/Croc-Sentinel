"""OTA firmware-catalog kernel (Phase-35 modularization).

Twelve small pure-ish helpers that walk the configured firmware
directory, parse out version strings (sidecar > filename), and decide
whether a given device's running ``fw`` is older than the best
candidate on disk. They power both the operator-facing ``/ota/*``
routes (firmware listing, broadcast, campaigns) and the
``/devices/firmware-hints`` route on the device-read side.

No DB, no MQTT, no notifier — only ``os`` / ``time`` / ``re`` /
``config``. The single piece of state is the in-memory cache
``_OTA_CATALOG_CACHE`` with a 45-second TTL; ``invalidate``-style
hooks (`_invalidate_ota_firmware_catalog_cache`) are called from
upload sites in routers/ota.py.

Public API
----------
Version parsing:
  _parse_fw_version_tuple(s)         → tuple[int,...] | None
  _fw_version_gt(newer, current)     → bool
  _version_str_from_ota_bin_name(n)  → str
  _read_ota_stored_version_sidecar(p)→ str
  _version_str_for_ota_bin_file(p,n) → str
  _read_ota_release_notes_for_stem(stem) → str

Catalog cache:
  _invalidate_ota_firmware_catalog_cache()         → None
  _get_ota_firmware_catalog()                      → list[dict]

Diff / hint shape:
  _catalog_entry_beats(a, b)                                 → bool
  _best_catalog_entry_newer_than_fw(current_fw, catalog)     → dict | None
  _firmware_hint_dict_from_entry(best)                       → dict
  _firmware_update_hint_for_current_in_catalog(current, cat) → dict | None
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

from config import OTA_FIRMWARE_DIR, OTA_PUBLIC_BASE_URL


# ---- version-string parsing ------------------------------------------------

def _parse_fw_version_tuple(s: str) -> tuple[int, ...] | None:
    t = (s or "").strip()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:\D|$)", t)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m2 = re.search(r"(\d+)\.(\d+)(?:\D|$)", t)
    if m2:
        return (int(m2.group(1)), int(m2.group(2)), 0)
    return None


def _fw_version_gt(newer: str, current: str) -> bool:
    a, b = (newer or "").strip(), (current or "").strip()
    if not a:
        return False
    if not b:
        return bool(a)
    ta, tb = _parse_fw_version_tuple(a), _parse_fw_version_tuple(b)
    if ta and tb:
        return ta > tb
    return a > b


def _version_str_from_ota_bin_name(name: str) -> str:
    base = os.path.basename(name)
    m = re.match(r"^croc-(.+)-[a-f0-9]{8}\.bin$", base, re.I)
    if m:
        return m.group(1).replace("_", ".")
    m2 = re.search(r"(\d+\.\d+\.\d+)", base)
    if m2:
        return m2.group(1)
    m3 = re.search(r"(\d+\.\d+)(?:\D|$)", base)
    if m3:
        return m3.group(1) + ".0"
    if base.lower().endswith(".bin"):
        return base[:-4] or base
    return base


def _read_ota_stored_version_sidecar(bin_path: str) -> str:
    """Canonical version string from OTA upload (`<name>.version`, one line). Not derived from the filename."""
    b = (bin_path or "").strip()
    if not b or ".." in b:
        return ""
    p = b + ".version"
    if not os.path.isfile(p):
        return ""
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            line = f.readline()
        v = (line or "").strip()
        return v[:80] if v else ""
    except OSError:
        return ""


def _version_str_for_ota_bin_file(bin_path: str, name: str) -> str:
    v = _read_ota_stored_version_sidecar(bin_path).strip()
    if v:
        return v
    return str(_version_str_from_ota_bin_name(name) or "").strip()


def _read_ota_release_notes_for_stem(stem: str) -> str:
    if not stem or ".." in stem or "/" in stem or "\\" in stem:
        return ""
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    for ext in (".txt", ".md", ".notes"):
        p = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, stem + ext))
        if not p.startswith(base_dir + os.sep) or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                return f.read(8000)
        except OSError:
            continue
    return ""


# ---- 45-second TTL catalog cache ------------------------------------------

_OTA_CATALOG_TTL = 45.0
_OTA_CATALOG_CACHE: tuple[float, list[dict[str, Any]]] | None = None


def _invalidate_ota_firmware_catalog_cache() -> None:
    global _OTA_CATALOG_CACHE
    _OTA_CATALOG_CACHE = None


def _get_ota_firmware_catalog() -> list[dict[str, Any]]:
    global _OTA_CATALOG_CACHE
    now = time.time()
    if _OTA_CATALOG_CACHE and (now - _OTA_CATALOG_CACHE[0]) < _OTA_CATALOG_TTL:
        return _OTA_CATALOG_CACHE[1]
    items: list[dict[str, Any]] = []
    base = OTA_FIRMWARE_DIR
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            if not str(name).endswith(".bin"):
                continue
            p = os.path.join(base, name)
            if not os.path.isfile(p):
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            vs = _version_str_for_ota_bin_file(p, name).strip()
            if not vs:
                continue
            items.append(
                {
                    "name": name,
                    "version_str": vs,
                    "version_tuple": _parse_fw_version_tuple(vs),
                    "mtime": int(st.st_mtime),
                },
            )
    _OTA_CATALOG_CACHE = (now, items)
    return items


# ---- diff / hint shape -----------------------------------------------------

def _catalog_entry_beats(a: dict[str, Any], b: dict[str, Any] | None) -> bool:
    """True if `a` is a strictly better upgrade candidate than `b` (newer version, or same version + newer mtime)."""
    if b is None:
        return True
    va, vb = str(a.get("version_str") or "").strip(), str(b.get("version_str") or "").strip()
    if not va:
        return False
    if _fw_version_gt(va, vb):
        return True
    if va == vb and int(a.get("mtime", 0)) > int(b.get("mtime", 0)):
        return True
    return False


def _best_catalog_entry_newer_than_fw(current_fw: str, catalog: list[dict[str, Any]]) -> dict[str, Any] | None:
    cur = (current_fw or "").strip()
    if not cur or not catalog:
        return None
    best: dict[str, Any] | None = None
    for ent in catalog:
        v = str(ent.get("version_str") or "").strip()
        if not v or not _fw_version_gt(v, cur):
            continue
        if _catalog_entry_beats(ent, best):
            best = ent
    return best


def _firmware_hint_dict_from_entry(best: dict[str, Any]) -> dict[str, Any]:
    name = str(best["name"])
    stem = name[:-4] if name.lower().endswith(".bin") else name
    notes = _read_ota_release_notes_for_stem(stem)
    dl = ""
    if OTA_PUBLIC_BASE_URL:
        dl = f"{OTA_PUBLIC_BASE_URL}/fw/{name}"
    return {
        "update_available": True,
        "to_version": str(best["version_str"]),
        "to_file": name,
        "release_notes": notes,
        "download_url": dl or None,
    }


def _firmware_update_hint_for_current_in_catalog(
    current_fw: str, catalog: list[dict[str, Any]]
) -> dict[str, Any] | None:
    best = _best_catalog_entry_newer_than_fw(current_fw, catalog)
    if not best:
        return None
    cur = (current_fw or "").strip().lower()
    tgt = str(best.get("version_str") or "").strip().lower()
    if cur and tgt and cur == tgt:
        return None
    return _firmware_hint_dict_from_entry(best)


__all__ = [
    "_parse_fw_version_tuple",
    "_fw_version_gt",
    "_version_str_from_ota_bin_name",
    "_read_ota_stored_version_sidecar",
    "_version_str_for_ota_bin_file",
    "_read_ota_release_notes_for_stem",
    "_invalidate_ota_firmware_catalog_cache",
    "_get_ota_firmware_catalog",
    "_catalog_entry_beats",
    "_best_catalog_entry_newer_than_fw",
    "_firmware_hint_dict_from_entry",
    "_firmware_update_hint_for_current_in_catalog",
]
