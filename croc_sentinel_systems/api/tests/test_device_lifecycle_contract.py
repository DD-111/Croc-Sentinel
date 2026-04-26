from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_schema_has_device_lifecycle_table():
    src = _read("schema.py")
    assert "CREATE TABLE IF NOT EXISTS device_lifecycle" in src
    assert "lifecycle_state TEXT NOT NULL" in src
    assert "lifecycle_version INTEGER NOT NULL" in src


def test_claim_flow_updates_lifecycle_and_version():
    src = _read("routers/provision_lifecycle.py")
    assert "transition_device_lifecycle_cur" in src
    assert "LIFECYCLE_ACTIVE" in src
    assert "bump_version=True" in src


def test_unbind_flow_is_non_blocking_and_unsubscribes():
    src = _read("routers/device_delete.py")
    assert "_try_mqtt_unclaim_reset(device_id, wait_for_ack=False)" in src
    assert "_mqtt_unsubscribe_device_topics(device_id)" in src
    assert '"status": "queued"' in src


def test_tenant_helper_exposes_unsubscribe_and_wait_toggle():
    src = _read("tenant_admin.py")
    assert "def _mqtt_unsubscribe_device_topics(" in src
    assert "def _try_mqtt_unclaim_reset(device_id: str, *, wait_for_ack: bool = True)" in src

