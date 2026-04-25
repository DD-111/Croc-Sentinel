"""Phase 89 runtime test: verify the self-heal helper actually re-publishes
the existing bootstrap.assign with the device's current nonce.

This is the runtime counterpart to ``test_claim_self_heal.py`` (which only
checks code shape). We import the module under controlled conditions and
exercise three branches:

  1. unknown MAC → returns False (caller falls through to pending_claims)
  2. known MAC + fresh nonce → publish_bootstrap_claim called with the
     *existing* cmd_key + the device's nonce
  3. cooldown active → returns True but does NOT call publish (boot-loop
     suppression)
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent


def _stub_app_module() -> tuple[types.ModuleType, list[dict]]:
    """Build a minimal stand-in for ``app.py`` so importing
    ``auto_reconcile`` doesn't drag the entire FastAPI bootstrap.

    The real ``audit.py`` does ``import app`` and reads
    ``app._VALID_CATEGORIES`` / ``app.emit_event`` — we provide just
    enough to keep that path happy."""
    captured: list[dict] = []

    app_mod = types.ModuleType("app")

    def _publish(**kwargs):
        captured.append(kwargs)

    def _emit(**kwargs):
        # Audit emits via app.emit_event; swallow.
        captured.append({"_event": True, **kwargs})

    app_mod.publish_bootstrap_claim = _publish
    app_mod.emit_event = _emit
    app_mod._VALID_CATEGORIES = (
        "auth", "provision", "device", "alarm", "ota",
        "system", "telegram", "fcm", "mqtt", "csrf",
    )
    return app_mod, captured


@pytest.fixture
def isolated_modules(tmp_path, monkeypatch):
    """Build a fresh in-memory DB + isolate the api/ import graph for one
    test. Each test gets its own captured-publish list."""
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.setenv("CMD_AUTH_KEY", "0123456789ABCDEF")
    monkeypatch.setenv("AUTO_RECONCILE_ENABLED", "1")
    monkeypatch.setenv("AUTO_RECONCILE_COOLDOWN_SEC", "60")
    monkeypatch.setenv("FACTORY_DEVICES_FILE", "")
    monkeypatch.setenv("ENFORCE_FACTORY_REGISTRATION", "0")
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("REDIS_BRIDGE_ENABLED", "0")

    sys.path.insert(0, str(API_DIR))
    # Stub paho-mqtt so config.py doesn't fail on missing broker creds.
    mqtt_pkg = types.ModuleType("paho")
    mqtt_sub = types.ModuleType("paho.mqtt")
    mqtt_client = types.ModuleType("paho.mqtt.client")

    class _FakeClient:
        on_connect = on_disconnect = on_message = None

        def __init__(self, *a, **kw):
            pass

        def username_pw_set(self, *a, **kw):
            pass

        def tls_set(self, *a, **kw):
            pass

        def tls_insecure_set(self, *a, **kw):
            pass

        def connect(self, *a, **kw):
            pass

        def loop_start(self):
            pass

        def loop_stop(self):
            pass

        def disconnect(self):
            pass

        def subscribe(self, *a, **kw):
            pass

    mqtt_client.Client = _FakeClient
    mqtt_client.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)
    sys.modules.setdefault("paho", mqtt_pkg)
    sys.modules.setdefault("paho.mqtt", mqtt_sub)
    sys.modules["paho.mqtt.client"] = mqtt_client

    # Inject our app stub BEFORE auto_reconcile is imported (audit.py
    # imports app at module load).
    app_mod, captured = _stub_app_module()
    sys.modules["app"] = app_mod

    # Now import the api modules. db needs an in-memory schema first.
    import importlib

    if "db" in sys.modules:
        importlib.reload(sys.modules["db"])
    import db  # noqa: F401
    if "schema" in sys.modules:
        importlib.reload(sys.modules["schema"])
    import schema  # noqa: F401

    schema.init_db()

    if "auto_reconcile" in sys.modules:
        importlib.reload(sys.modules["auto_reconcile"])
    import auto_reconcile  # noqa: F401

    yield {
        "ar": auto_reconcile,
        "db": db,
        "captured": captured,
        "app": app_mod,
    }

    # Teardown: clear cached modules so the next test sees a clean slate.
    for mod in (
        "auto_reconcile", "db", "app", "audit", "config",
        "event_bus", "schema", "schema_migrations", "schema_seed",
    ):
        sys.modules.pop(mod, None)


def _seed_provisioned(db_mod, mac: str, did: str, cmd_key: str) -> None:
    with db_mod.db_lock:
        conn = db_mod.get_conn()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM provisioned_credentials WHERE mac_nocolon = ? OR device_id = ?",
            (mac, did),
        )
        cur.execute(
            """
            INSERT INTO provisioned_credentials
              (device_id, mac_nocolon, mqtt_username, mqtt_password,
               cmd_key, zone, qr_code, claimed_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (did, mac, f"u_{did}", f"p_{did}", cmd_key,
             "all", f"CROC-{mac}", "2026-04-25T00:00:00Z"),
        )
        conn.commit()
        conn.close()


def test_unknown_mac_returns_false(isolated_modules):
    ar = isolated_modules["ar"]
    captured = isolated_modules["captured"]
    captured.clear()

    result = ar._reissue_existing_assign_for_mac(
        "ABCDEF012345", "1111222233334444"
    )

    assert result is False, (
        "Unknown MAC must return False so the caller falls through to "
        "the normal pending_claims flow."
    )
    publishes = [c for c in captured if "_event" not in c]
    assert publishes == [], (
        "Unknown MAC must NOT trigger a bootstrap.assign publish."
    )


def test_known_mac_reissues_existing_credentials(isolated_modules):
    ar = isolated_modules["ar"]
    db_mod = isolated_modules["db"]
    captured = isolated_modules["captured"]
    captured.clear()

    mac = "B0CBD8899590"
    did = "SN-RGZ3VUAEG2MKG5PN"
    cmd_key = "AABBCCDDEEFF0011"
    _seed_provisioned(db_mod, mac, did, cmd_key)

    nonce = "ABCDEF1234567890"
    result = ar._reissue_existing_assign_for_mac(mac, nonce)

    assert result is True, "Known MAC + fresh nonce must self-heal"

    publishes = [c for c in captured if "_event" not in c]
    assert len(publishes) == 1, f"Expected exactly one publish, got {publishes!r}"
    p = publishes[0]
    assert p["mac_nocolon"] == mac
    assert p["device_id"] == did
    assert p["claim_nonce"] == nonce, (
        "Re-issue must echo the device's current nonce so the firmware's "
        "saveProvisioningFromClaim nonce check passes."
    )
    assert p["cmd_key"] == cmd_key, (
        "Re-issue must use the *existing* cmd_key — regenerating here "
        "would invalidate any sibling that already has the prior key."
    )
    assert p["mqtt_username"] == f"u_{did}"
    assert p["mqtt_password"] == f"p_{did}"


def test_cooldown_suppresses_repeat_within_window(isolated_modules):
    ar = isolated_modules["ar"]
    db_mod = isolated_modules["db"]
    captured = isolated_modules["captured"]

    mac = "112233445566"
    did = "SN-COOLDOWN"
    _seed_provisioned(db_mod, mac, did, "FFEEDDCCBBAA0099")

    captured.clear()
    first = ar._reissue_existing_assign_for_mac(mac, "0000111122223333")
    second = ar._reissue_existing_assign_for_mac(mac, "0000111122223333")

    assert first is True
    # Cooldown must absorb the second call AND must report True so the
    # caller doesn't fall through to "treat as new device" — a
    # recently-healed MAC is still legitimately a known device.
    assert second is True, (
        "Within-cooldown calls must still return True so the caller "
        "knows the MAC is provisioned."
    )
    publishes = [c for c in captured if "_event" not in c]
    assert len(publishes) == 1, (
        f"Cooldown must collapse boot-loop floods to one publish, "
        f"got {len(publishes)} publishes"
    )


def test_invalid_nonce_length_short_circuits(isolated_modules):
    ar = isolated_modules["ar"]
    db_mod = isolated_modules["db"]
    captured = isolated_modules["captured"]
    captured.clear()

    mac = "AABBCCDDEEFF"
    _seed_provisioned(db_mod, mac, "SN-NONCE-CHK", "1234567890ABCDEF")

    result = ar._reissue_existing_assign_for_mac(mac, "short")
    assert result is False, "Bad nonce length must abort before publish"
    publishes = [c for c in captured if "_event" not in c]
    assert publishes == []


def test_disabled_module_no_op(isolated_modules):
    ar = isolated_modules["ar"]
    captured = isolated_modules["captured"]
    captured.clear()

    saved = ar.AUTO_RECONCILE_ENABLED
    ar.AUTO_RECONCILE_ENABLED = False
    try:
        result = ar._reissue_existing_assign_for_mac(
            "B0CBD8899590", "ABCDEF1234567890"
        )
    finally:
        ar.AUTO_RECONCILE_ENABLED = saved

    assert result is False
    publishes = [c for c in captured if "_event" not in c]
    assert publishes == []
