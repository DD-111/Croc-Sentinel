"""Contracts for server-first unbind/reset state machine (Phase 95 Part 0/1)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PY = API_DIR / "schema.py"
DEVICE_DELETE_PY = API_DIR / "routers" / "device_delete.py"
SCHEDULER_PY = API_DIR / "scheduler.py"


@pytest.fixture(scope="module")
def schema_src() -> str:
    return SCHEMA_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def delete_src() -> str:
    return DEVICE_DELETE_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def scheduler_src() -> str:
    return SCHEDULER_PY.read_text(encoding="utf-8")


def _fn_source(path: Path, src: str, name: str) -> str:
    tree = ast.parse(src, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            seg = ast.get_source_segment(src, node)
            if seg:
                return seg
    raise AssertionError(f"Function not found: {name}")


def test_schema_has_device_unbind_jobs(schema_src: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS device_unbind_jobs" in schema_src
    assert "request_id TEXT NOT NULL UNIQUE" in schema_src
    assert "state TEXT NOT NULL" in schema_src


def test_delete_reset_records_lifecycle(delete_src: str) -> None:
    fn = _fn_source(DEVICE_DELETE_PY, delete_src, "_device_delete_reset_impl")
    assert "INSERT INTO device_unbind_jobs" in fn, "Must create unbind lifecycle row."
    assert "'requested'" in fn, "Must start lifecycle at requested."
    assert "state='server_unbound'" in fn, "Must record server-side unlink completion."
    assert "device_reset_pending" in fn, "Must report pending when no ACK."
    assert "completed" in fn, "Must report completed when reset ACKed."
    assert '"request_id": req_id' in fn, "API response must expose request_id."
    assert '"unbind_state": "completed" if nvs_purge_acked else "device_reset_pending"' in fn


def test_scheduler_retries_pending_unbind_reset(scheduler_src: str) -> None:
    fn = _fn_source(SCHEDULER_PY, scheduler_src, "_unbind_reset_compensation_tick")
    loop = _fn_source(SCHEDULER_PY, scheduler_src, "scheduler_loop")
    assert "WHERE state = 'device_reset_pending'" in fn
    assert "_app._try_mqtt_unclaim_reset(did)" in fn
    assert "new_state = \"completed\" if acked else \"device_reset_pending\"" in fn
    assert "next_unbind_reset_retry_at" in loop
    assert "_unbind_reset_compensation_tick(limit=10)" in loop

