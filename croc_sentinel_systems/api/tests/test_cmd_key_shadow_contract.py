"""Contracts for ownership-side cmd_key shadow redundancy (Phase 93).

Guards the minimum guarantees:
  1) schema migration adds ``device_ownership.cmd_key_shadow``
  2) migrations backfill empty shadow values from provisioned_credentials
  3) claim flow writes cmd_key_shadow on (re)claim
  4) device boot-sync path reconciles shadow drift
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
SCHEMA_MIGRATIONS_PY = API_DIR / "schema_migrations.py"
PROVISION_LIFECYCLE_PY = API_DIR / "routers" / "provision_lifecycle.py"
DEVICE_HTTP_PY = API_DIR / "routers" / "device_http.py"


@pytest.fixture(scope="module")
def schema_migrations_src() -> str:
    return SCHEMA_MIGRATIONS_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def provision_lifecycle_src() -> str:
    return PROVISION_LIFECYCLE_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def device_http_src() -> str:
    return DEVICE_HTTP_PY.read_text(encoding="utf-8")


def _function_src(tree: ast.Module, source: str, name: str) -> str:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            seg = ast.get_source_segment(source, node)
            if seg:
                return seg
    raise AssertionError(f"function {name} not found")


def test_schema_migration_adds_cmd_key_shadow_column(schema_migrations_src: str) -> None:
    assert 'ensure_column(conn, "device_ownership", "cmd_key_shadow"' in schema_migrations_src, (
        "device_ownership.cmd_key_shadow ensure_column is missing; ownership-side "
        "redundancy will not exist on upgraded databases."
    )


def test_schema_migration_backfills_shadow(schema_migrations_src: str) -> None:
    assert "_backfill_device_ownership_cmd_key_shadow" in schema_migrations_src, (
        "Expected _backfill_device_ownership_cmd_key_shadow migration helper."
    )
    assert "UPDATE device_ownership" in schema_migrations_src and "cmd_key_shadow" in schema_migrations_src, (
        "cmd_key_shadow backfill SQL is missing from schema_migrations.py."
    )
    assert "_backfill_device_ownership_cmd_key_shadow(conn)" in schema_migrations_src, (
        "run_migrations() must call _backfill_device_ownership_cmd_key_shadow(conn)."
    )


def test_claim_flow_writes_shadow(provision_lifecycle_src: str) -> None:
    assert "INSERT INTO device_ownership (device_id, owner_admin, assigned_by, assigned_at, cmd_key_shadow)" in provision_lifecycle_src, (
        "Claim flow must write cmd_key_shadow when inserting/updating device_ownership."
    )
    assert "cmd_key_shadow = excluded.cmd_key_shadow" in provision_lifecycle_src, (
        "Claim upsert must update cmd_key_shadow on conflict."
    )


def test_device_boot_sync_reconciles_shadow(device_http_src: str) -> None:
    tree = ast.parse(device_http_src, filename=str(DEVICE_HTTP_PY))
    helper = _function_src(tree, device_http_src, "_reconcile_ownership_cmd_key_shadow")
    boot = _function_src(tree, device_http_src, "device_boot_sync")
    assert "SELECT IFNULL(cmd_key_shadow,'')" in helper
    assert "UPDATE device_ownership SET cmd_key_shadow = ?" in helper
    assert "_reconcile_ownership_cmd_key_shadow(did, db_key)" in boot, (
        "device_boot_sync must reconcile ownership cmd_key shadow for known devices."
    )

