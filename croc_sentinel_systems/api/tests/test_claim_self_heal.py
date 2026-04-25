"""
Phase 89: bootstrap.register self-heal contract tests.

When the firmware re-publishes ``bootstrap.register`` because its NVS lost
the cmd_key (re-flash, factory clear, watchdog reset between accept and
NVS commit, etc.) but the server still has a row in
``provisioned_credentials``, the server must re-publish the *existing*
``bootstrap.assign`` so the device can write the existing cmd_key to NVS
without operator action.

These tests guard the wiring (mqtt_pipeline → auto_reconcile) so the
self-heal cannot regress to "treat re-register as a brand-new claim".
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
AUTO_RECONCILE_PY = API_DIR / "auto_reconcile.py"
MQTT_PIPELINE_PY = API_DIR / "mqtt_pipeline.py"


@pytest.fixture(scope="module")
def auto_reconcile_tree() -> ast.Module:
    return ast.parse(AUTO_RECONCILE_PY.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def mqtt_pipeline_tree() -> ast.Module:
    return ast.parse(MQTT_PIPELINE_PY.read_text(encoding="utf-8"))


def _has_function(tree: ast.Module, name: str) -> bool:
    return any(
        isinstance(node, ast.FunctionDef) and node.name == name
        for node in ast.walk(tree)
    )


def _function_body(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def test_reissue_helper_is_defined(auto_reconcile_tree: ast.Module) -> None:
    """The bootstrap-register self-heal helper must exist."""
    assert _has_function(auto_reconcile_tree, "_reissue_existing_assign_for_mac"), (
        "Phase 89 helper _reissue_existing_assign_for_mac is missing — the "
        "MQTT bootstrap.register dispatcher would fall back to treating each "
        "re-register as a brand-new claim, leaving operators to re-claim "
        "manually after every NVS clear."
    )


def test_reissue_helper_exported(auto_reconcile_tree: ast.Module) -> None:
    """__all__ must export the helper so callers can rely on the contract."""
    for node in ast.walk(auto_reconcile_tree):
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
            if any(t.id == "__all__" for t in targets):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    names = {
                        e.value
                        for e in node.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    }
                    assert "_reissue_existing_assign_for_mac" in names, (
                        "_reissue_existing_assign_for_mac missing from __all__"
                    )
                    return
    pytest.fail("__all__ not found in auto_reconcile.py")


def test_reissue_helper_uses_existing_credentials(auto_reconcile_tree: ast.Module) -> None:
    """The helper MUST re-use existing cmd_key/mqtt creds (NOT call
    generate_device_credentials). Generating new creds here would
    invalidate any sibling that has the prior key and would re-trigger
    the legacy ack-key-mismatch reconcile loop."""
    fn = _function_body(auto_reconcile_tree, "_reissue_existing_assign_for_mac")
    assert fn is not None
    src = ast.unparse(fn)
    assert "generate_device_credentials" not in src, (
        "_reissue_existing_assign_for_mac must NOT call "
        "generate_device_credentials — it MUST re-publish the *existing* "
        "credentials so already-healthy siblings stay valid."
    )
    assert "publish_bootstrap_claim" in src, (
        "_reissue_existing_assign_for_mac must call publish_bootstrap_claim"
    )
    assert "provisioned_credentials" in src, (
        "_reissue_existing_assign_for_mac must look up existing creds in "
        "provisioned_credentials"
    )


def test_mqtt_pipeline_calls_reissue_on_bootstrap_register(
    mqtt_pipeline_tree: ast.Module,
) -> None:
    """The MQTT bootstrap.register dispatcher must call the self-heal
    helper. Without this wiring, a device with cleared NVS would only
    appear in pending_claims and require operator action to re-claim."""
    fn = _function_body(mqtt_pipeline_tree, "_dispatch_mqtt_payload")
    assert fn is not None
    src = ast.unparse(fn)
    assert "_reissue_existing_assign_for_mac" in src, (
        "_dispatch_mqtt_payload must invoke _reissue_existing_assign_for_mac "
        "in the bootstrap.register branch — otherwise NVS-lost devices "
        "remain stuck until an operator re-claims."
    )


def test_mqtt_pipeline_imports_reissue(mqtt_pipeline_tree: ast.Module) -> None:
    """The import must be top-level so the dispatcher hot path doesn't
    pay an import cost on every bootstrap.register."""
    found = False
    for node in ast.walk(mqtt_pipeline_tree):
        if isinstance(node, ast.ImportFrom) and node.module == "auto_reconcile":
            for alias in node.names:
                if alias.name == "_reissue_existing_assign_for_mac":
                    found = True
                    break
    assert found, (
        "_reissue_existing_assign_for_mac must be imported from "
        "auto_reconcile at module load time."
    )


def test_reissue_helper_has_per_mac_cooldown(auto_reconcile_tree: ast.Module) -> None:
    """The helper must respect a per-MAC cooldown so a boot-looping
    device cannot flood the bootstrap topic."""
    fn = _function_body(auto_reconcile_tree, "_reissue_existing_assign_for_mac")
    assert fn is not None
    src = ast.unparse(fn)
    assert "reissue_assign_last_seen" in src, (
        "Per-MAC cooldown ledger reissue_assign_last_seen is missing"
    )
    assert "AUTO_RECONCILE_COOLDOWN_SEC" in src, (
        "Per-MAC cooldown must use AUTO_RECONCILE_COOLDOWN_SEC so the "
        "operator can tune both self-heal flows from one knob."
    )
