"""Centralized FastAPI router-include wiring (Phase-62 extraction from ``app.py``).

For 60+ phases ``app.py`` carried 27 separate
``from routers.X import router as _X_router; app.include_router(_X_router)``
blocks plus their explanatory comments. With the actual *logic* now
fully extracted into helper modules (lifespan, csrf, scheduler,
event_bus, mqtt_pipeline, etc.), the only thing left was the wiring
itself — and it had grown to ~500 lines of comments + imports + include
calls scattered through the middle of ``app.py``.

This module owns that wiring. :func:`register_routers` is called from
``app.py`` once, immediately after the FastAPI middleware stack and the
helper re-exports are installed, and:

* imports each router module in the same order the original ``app.py``
  did (FastAPI route precedence depends on registration order);
* calls ``app.include_router(...)`` for each one;
* re-exports the single auxiliary helper that ``app.py``'s scheduler
  consumer still needs — :func:`_prune_password_reset_tokens` — back
  onto the ``app`` module so ``scheduler.py`` keeps finding it via
  ``_app._prune_password_reset_tokens()``.

Why call-time, not import-time
------------------------------
Many router modules do module-level ``import app as _app`` plus
``something = _app.<helper>`` to capture a stable callable identity.
Those module-level binds run the first time the router module is
imported. That import only happens here, when ``register_routers(app)``
runs. By the time ``app.py`` invokes us, every helper re-export
(``zone_sql_suffix``, ``require_principal``, ``publish_command``, …) is
already set on the ``app`` module, so every ``_app.<helper>`` resolves
correctly.

Order is preserved exactly as the historical ``app.py`` had it. Do not
reorder without checking FastAPI route precedence — overlapping path
patterns will resolve to the FIRST registered handler.
"""

from __future__ import annotations

from fastapi import FastAPI


def register_routers(app: FastAPI) -> None:
    """Mount every API router on ``app`` in the historical order.

    Side effects:
        * Imports each ``routers.<name>`` module (this triggers each
          router's module-level ``_app.<helper>`` capture binds).
        * Calls ``app.include_router(...)`` for each router.
        * Pins ``_prune_password_reset_tokens`` from
          ``routers.auth_recovery`` onto the ``app`` module so
          ``scheduler.py`` keeps finding it via late-binding.
    """
    # Phase-33: SPA-mount redirect routes (/, /ui[/], /dashboard[/], /ui/{path:path}).
    from routers.ui_mounts import router as _ui_mounts_router

    app.include_router(_ui_mounts_router)

    # Phase-64: split into two halves —
    #   * routers.auth_signup (7 signup/activate/approval routes + 3 schemas)
    #   * routers.auth_recovery (7 forgot-password routes + 4 schemas + 6 helpers)
    # Both are unauthenticated-by-default; signup goes first to keep the
    # original /auth/signup/* registration order from Phase-17.
    from routers.auth_signup import router as _auth_signup_router

    app.include_router(_auth_signup_router)

    # Re-export _prune_password_reset_tokens onto app so scheduler.py late-binds.
    from routers.auth_recovery import _prune_password_reset_tokens
    from routers.auth_recovery import router as _auth_recovery_router

    import app as _app

    _app._prune_password_reset_tokens = _prune_password_reset_tokens
    app.include_router(_auth_recovery_router)

    # Phase-22: login / csrf / logout.
    from routers.auth_core import router as _auth_core_router

    app.include_router(_auth_core_router)

    # Phase-15: device-side HTTP fallback (4 /device/* endpoints + schemas + auth helpers).
    from routers.device_http import router as _device_http_router

    app.include_router(_device_http_router)

    # Phase-20: self-service /auth/me/* (10 routes + 6 schemas + helpers).
    from routers.auth_self import router as _auth_self_router

    app.include_router(_auth_self_router)

    # Phase-21: admin/user CRUD /auth/admins, /auth/users (7 routes + 3 schemas).
    from routers.auth_users import router as _auth_users_router

    app.include_router(_auth_users_router)

    # Phase-25: admin DB backup (encrypted export / import).
    from routers.admin_backup import router as _admin_backup_router

    app.include_router(_admin_backup_router)

    # Phase-24: provisioning challenge (sign nonce -> verify).
    from routers.provision_challenge import router as _provision_challenge_router

    app.include_router(_provision_challenge_router)

    # Phase-23: device revoke / unrevoke.
    from routers.device_revoke import router as _device_revoke_router

    app.include_router(_device_revoke_router)

    # Phase-26: device delete-reset + factory-unregister.
    from routers.device_delete import router as _device_delete_router

    app.include_router(_device_delete_router)

    # Phase-32: /health, /admin/presence-probes, /diag/db-ping.
    from routers.diagnostics import router as _diagnostics_router

    app.include_router(_diagnostics_router)

    # Phase-28: read-only device endpoints (GET /devices, /devices/{id}, etc.).
    from routers.device_read import router as _device_read_router

    app.include_router(_device_read_router)

    # Phase-14: group-cards (siren fan-out by notification_group, 11 routes).
    from routers.group_cards import router as _group_cards_router

    app.include_router(_group_cards_router)

    # Phase-27: device-profile mutation routes (PATCH profile, display-label, bulk).
    from routers.device_profile import router as _device_profile_router

    app.include_router(_device_profile_router)

    # Phase-16: device sharing / ACL admin (4 /admin/share routes).
    from routers.device_shares import router as _device_shares_router

    app.include_router(_device_shares_router)

    # Phase-31: GET /dashboard/overview, GET /devices/{id}/messages.
    from routers.dashboard_read import router as _dashboard_read_router

    app.include_router(_dashboard_read_router)

    # Phase-29: provision-lifecycle (/provision/pending, /claim, /identify).
    from routers.provision_lifecycle import router as _provision_lifecycle_router

    app.include_router(_provision_lifecycle_router)

    # Phase-9: /audit, /logs/messages, /logs/file.
    from routers.audit_logs import router as _audit_logs_router

    app.include_router(_audit_logs_router)

    # Phase-19: trigger policy + Wi-Fi provisioning task (4 routes).
    from routers.device_provision import router as _device_provision_router

    app.include_router(_device_provision_router)

    # Phase-18: alert on/off + self-test + schedule-reboot (5 routes).
    from routers.device_control import router as _device_control_router

    app.include_router(_device_control_router)

    # Phase-30: send-command + bulk-alert + broadcast-command.
    from routers.device_commands import router as _device_commands_router

    app.include_router(_device_commands_router)

    # Phase-10: /alarms, /alarms/summary, /activity/signals.
    from routers.alarms import router as _alarms_router

    app.include_router(_alarms_router)

    # Phase-11: 10 admin notification-channel routes (SMTP/Telegram/FCM).
    from routers.notifications_admin import router as _notif_admin_router

    app.include_router(_notif_admin_router)

    # Phase-12: 6 Telegram link/bind/webhook routes + telegram-only helpers.
    from routers.telegram import router as _telegram_router

    app.include_router(_telegram_router)

    # Phase-13: every /ota/* route + schemas + 8 OTA-only helpers.
    from routers.ota import router as _ota_router

    app.include_router(_ota_router)

    # Phase-8: event center (paginated /events, CSV, by-device, taxonomy, SSE, WS).
    from routers.events import router as _events_router

    app.include_router(_events_router)

    # Phase-7: /factory/* (register / ping / list / block) + X-Factory-Token auth.
    from routers.factory import router as _factory_router

    app.include_router(_factory_router)


__all__ = ("register_routers",)
