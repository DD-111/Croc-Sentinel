"""Contracts for DB object-storage backup path (Phase 94)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
CONFIG_PY = API_DIR / "config.py"
SCHEDULER_PY = API_DIR / "scheduler.py"
LIFESPAN_PY = API_DIR / "lifespan.py"


@pytest.fixture(scope="module")
def config_src() -> str:
    return CONFIG_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def scheduler_src() -> str:
    return SCHEDULER_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lifespan_src() -> str:
    return LIFESPAN_PY.read_text(encoding="utf-8")


def _function_src(path: Path, source: str, name: str) -> str:
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            seg = ast.get_source_segment(source, node)
            if seg:
                return seg
    raise AssertionError(f"function {name} not found in {path}")


def test_config_has_backup_knobs(config_src: str) -> None:
    assert "DB_BACKUP_ENABLED" in config_src
    assert "DB_BACKUP_INTERVAL_SECONDS" in config_src
    assert "DB_BACKUP_TIMEOUT_SECONDS" in config_src
    assert "DB_BACKUP_PRESIGNED_URL_TEMPLATE" in config_src


def test_scheduler_has_backup_tick(scheduler_src: str) -> None:
    tick = _function_src(SCHEDULER_PY, scheduler_src, "_db_backup_tick")
    loop = _function_src(SCHEDULER_PY, scheduler_src, "scheduler_loop")
    assert "_upload_db_backup_once" in tick
    assert "DB_BACKUP_ENABLED" in tick
    assert "next_db_backup_at = _db_backup_tick(now, next_db_backup_at)" in loop


def test_scheduler_uses_sqlite_snapshot_and_put_upload(scheduler_src: str) -> None:
    up = _function_src(SCHEDULER_PY, scheduler_src, "_upload_db_backup_once")
    assert "src.backup(dst)" in up, "Must use sqlite backup API for online-consistent snapshots."
    assert "method=\"PUT\"" in up
    assert "application/gzip" in up
    assert "DB_BACKUP_PRESIGNED_URL_TEMPLATE" in up


def test_lifespan_validates_backup_env(lifespan_src: str) -> None:
    vf = _function_src(LIFESPAN_PY, lifespan_src, "validate_production_env")
    assert "DB_BACKUP_ENABLED" in vf
    assert "DB_BACKUP_PRESIGNED_URL_TEMPLATE" in vf
    assert "DB_BACKUP_ENABLED=1 requires DB_BACKUP_PRESIGNED_URL_TEMPLATE" in vf

