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

    # Phase-64 / 72 / 82: auth signup + recovery split into four halves —
    #   * routers.auth_signup           — 4 public OTP-flow routes (start
    #                                     / verify / activate / resend)
    #                                     + 3 schemas.
    #   * routers.auth_signup_approval  — 3 superadmin approval routes
    #                                     (Phase 82: pending / approve
    #                                     / reject).
    #   * routers.auth_recovery         — offline RSA-blob password
    #                                     reset flow (3 routes, 2
    #                                     schemas, 6 helpers).
    #   * routers.auth_recovery_email   — email-OTP password reset flow
    #                                     (4 routes, 2 schemas).
    # The first two are unauthenticated-public + superadmin-gated;
    # ``auth_recovery*`` are unauthenticated-by-default. Signup family
    # goes first to keep the historical /auth/signup/* registration
    # order from Phase-17. Public OTP before approval keeps reading
    # the OpenAPI route list in lifecycle order (signup → approve →
    # reject). ``auth_recovery`` must be imported before
    # ``auth_recovery_email`` because the email module imports
    # ``_check_forgot_ip_rate`` from it at module-load time (the
    # rate-limit budget is shared across both flows).
    from routers.auth_signup import router as _auth_signup_router
    from routers.auth_signup_approval import router as _auth_signup_approval_router

    app.include_router(_auth_signup_router)
    app.include_router(_auth_signup_approval_router)

    # Re-export _prune_password_reset_tokens onto app so scheduler.py late-binds.
    from routers.auth_recovery import _prune_password_reset_tokens
    from routers.auth_recovery import router as _auth_recovery_router
    from routers.auth_recovery_email import router as _auth_recovery_email_router

    import app as _app

    _app._prune_password_reset_tokens = _prune_password_reset_tokens
    app.include_router(_auth_recovery_router)
    app.include_router(_auth_recovery_email_router)

    # Phase-22: login / csrf / logout.
    from routers.auth_core import router as _auth_core_router

    app.include_router(_auth_core_router)

    # Phase-15: device-side HTTP fallback (4 /device/* endpoints + schemas + auth helpers).
    # Phase-69: also mount under /api/* so firmware builds with the legacy
    # DEVICE_SYNC_*_PATH default (which prefixes /api/) keep working when
    # the reverse-proxy doesn't strip /api before forwarding to the API
    # container. Both prefixes resolve to the same handlers — the bare
    # /device/* paths remain canonical, /api/* is the back-compat alias.
    from routers.device_http import router as _device_http_router
    from routers.device_http import alias_router as _device_http_alias_router

    app.include_router(_device_http_router)
    app.include_router(_device_http_alias_router)

    # Phase-20 / 83: self-service /auth/me/* split into two modules —
    #   * routers.auth_self          — identity/account (5 routes:
    #                                   GET /me, PATCH profile,
    #                                   PATCH password, DELETE /me,
    #                                   POST /me/delete) + 3 schemas
    #                                   + ``_validate_avatar_url`` /
    #                                   ``_auth_me_delete_impl``.
    #   * routers.auth_self_devices  — mobile preferences (5 routes:
    #                                   POST/DELETE/POST-mirror FCM
    #                                   tokens + GET/PATCH
    #                                   notification-prefs) + 3 schemas.
    # Both share the ``"auth-self"`` tag so the OpenAPI doc still
    # groups them together for end users. Order is irrelevant (no
    # cross-module imports); register identity first so the OpenAPI
    # route list reads identity → preferences.
    from routers.auth_self import router as _auth_self_router
    from routers.auth_self_devices import router as _auth_self_devices_router

    app.include_router(_auth_self_router)
    app.include_router(_auth_self_devices_router)

    # Phase-21 / 69 / 80: admin+user surface split into three modules —
    #   * routers.auth_admins       — superadmin-only admin tenant
    #                                 management (GET /auth/admins,
    #                                 POST /auth/admins/{u}/close).
    #   * routers.auth_users        — admin-managed user identity CRUD
    #                                 (3 routes under /auth/users:
    #                                 list / create / delete).
    #   * routers.auth_user_policy  — admin-managed user policy
    #                                 (Phase-80: GET + PUT
    #                                 /auth/users/{u}/policy).
    # Order is irrelevant (no cross-module imports). Register admins
    # first so /auth/admins/* paths group naturally; users next; policy
    # last so the OpenAPI route list reads identity-then-capabilities.
    # All three share the ``"auth-users"`` / ``"auth-admins"`` tag groups.
    from routers.auth_admins import router as _auth_admins_router
    from routers.auth_users import router as _auth_users_router
    from routers.auth_user_policy import router as _auth_user_policy_router

    app.include_router(_auth_admins_router)
    app.include_router(_auth_users_router)
    app.include_router(_auth_user_policy_router)

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

    # Phase-14 / 66 / 73 / 81: group-cards lifecycle split into four modules —
    #   * routers.group_cards          — capabilities + read routes +
    #                                    shared helpers + schema (read).
    #   * routers.group_cards_save     — PUT /settings (Phase 81 — save).
    #   * routers.group_cards_apply    — siren fan-out (Phase 66 — apply).
    #   * routers.group_cards_delete   — delete + impl (Phase 73 — delete).
    # ``group_cards`` MUST ship first because both ``group_cards_save``
    # and ``group_cards_apply`` import ``_group_owner_scope`` /
    # ``_group_settings_defaults`` / ``_group_devices_with_owner`` /
    # ``GroupCardSettingsBody`` from it at module-load time.
    # ``group_cards_delete`` has no module-load-time dependency on the
    # other three (it pulls helpers from ``_app`` directly), so its
    # relative ordering is a wash; we register it last to keep the
    # lifecycle reading like a story (read → save → apply → delete).
    from routers.group_cards import router as _group_cards_router
    from routers.group_cards_save import router as _group_cards_save_router
    from routers.group_cards_apply import router as _group_cards_apply_router
    from routers.group_cards_delete import router as _group_cards_delete_router

    app.include_router(_group_cards_router)
    app.include_router(_group_cards_save_router)
    app.include_router(_group_cards_apply_router)
    app.include_router(_group_cards_delete_router)

    # Phase-27: device-profile mutation routes (PATCH profile, display-label, bulk).
    from routers.device_profile import router as _device_profile_router

    app.include_router(_device_profile_router)

    # Phase-16: device sharing / ACL admin (4 /admin/share routes).
    from routers.device_shares import router as _device_shares_router

    app.include_router(_device_shares_router)

    # Phase-31: GET /dashboard/overview, GET /devices/{id}/messages.
    from routers.dashboard_read import router as _dashboard_read_router

    app.include_router(_dashboard_read_router)

    # Phase-29 / 70: provision-lifecycle split into two halves —
    #   * routers.provision_lifecycle  — write-side claim flow
    #                                    (GET /provision/pending,
    #                                     POST /provision/claim)
    #   * routers.provision_identify   — read-only inspection
    #                                    (POST /provision/identify)
    # No cross-module imports; identify-first matches the operator
    # wizard order (identify -> pending -> claim) so log-grep follows
    # the natural UX sequence.
    from routers.provision_identify import router as _provision_identify_router
    from routers.provision_lifecycle import router as _provision_lifecycle_router

    app.include_router(_provision_identify_router)
    app.include_router(_provision_lifecycle_router)

    # Phase-9: /audit, /logs/messages, /logs/file.
    from routers.audit_logs import router as _audit_logs_router

    app.include_router(_audit_logs_router)

    # Phase-19 / 86: trigger policy + Wi-Fi provisioning split into
    # two modules —
    #   * routers.device_provision        — Wi-Fi provisioning task
    #                                       (2 routes: POST/GET
    #                                       /devices/{device_id}/
    #                                       provision/wifi-task[/{task_id}]).
    #                                       Hosts the shared
    #                                       ``_load_device_row_for_task``
    #                                       helper (re-exported by
    #                                       device_trigger_policy).
    #   * routers.device_trigger_policy   — trigger policy CRUD
    #                                       (2 routes: GET/PUT
    #                                       /devices/{device_id}/
    #                                       trigger-policy).
    # Both share the ``"device-provision"`` tag so the OpenAPI doc
    # still groups all 4 endpoints together for end users. Order is
    # critical: register device_provision first so its
    # ``_load_device_row_for_task`` is importable when
    # device_trigger_policy loads.
    from routers.device_provision import router as _device_provision_router
    from routers.device_trigger_policy import (
        router as _device_trigger_policy_router,
    )

    app.include_router(_device_provision_router)
    app.include_router(_device_trigger_policy_router)

    # Phase-18: alert on/off + self-test + schedule-reboot (5 routes).
    from routers.device_control import router as _device_control_router

    app.include_router(_device_control_router)

    # Phase-30: send-command + bulk-alert + broadcast-command.
    from routers.device_commands import router as _device_commands_router

    app.include_router(_device_commands_router)

    # Phase-10: /alarms, /alarms/summary, /activity/signals.
    from routers.alarms import router as _alarms_router

    app.include_router(_alarms_router)

    # Phase-11 / 85: 10 admin notification-channel routes split into
    # two modules —
    #   * routers.notifications_admin             — recipient CRUD
    #                                               (4 routes:
    #                                               GET/POST/PATCH/
    #                                               DELETE on
    #                                               /admin/alert-recipients).
    #   * routers.notifications_admin_diagnostics — channel diagnostics
    #                                               (6 routes: SMTP/
    #                                               Telegram/FCM
    #                                               status + test +
    #                                               webhook-info).
    # Both share the ``"notifications-admin"`` tag so the OpenAPI doc
    # still groups all 10 endpoints together for end users. Order is
    # irrelevant (no cross-module imports); register recipients first
    # so the OpenAPI route list reads CRUD → diagnostics.
    from routers.notifications_admin import router as _notif_admin_router
    from routers.notifications_admin_diagnostics import (
        router as _notif_admin_diag_router,
    )

    app.include_router(_notif_admin_router)
    app.include_router(_notif_admin_diag_router)

    # Phase-12 / 67 / 78: Telegram surface split into three modules —
    #   * routers.telegram           — link-token + bind/unbind/list/toggle
    #                                  CRUD (5 routes + shared
    #                                  ``_telegram_bind_chat``).
    #   * routers.telegram_commands  — natural-language command grammar
    #                                  (Phase-78). Function library (no
    #                                  router); webhook imports
    #                                  ``handle_text`` directly.
    #   * routers.telegram_webhook   — POST /integrations/telegram/webhook
    #                                  + bind / chat-allowlist / reply
    #                                  plumbing.
    # ``telegram`` must ship first because ``telegram_webhook`` imports
    # ``_telegram_bind_chat`` from it at module-load time (the
    # ``/start bind_<token>`` deep-link flow shares that helper).
    # ``telegram_commands`` has no router so it isn't included here —
    # the import chain ``telegram_webhook → telegram_commands → app``
    # gives it the same late-bound helper capture window as every other
    # router module.
    from routers.telegram import router as _telegram_router
    from routers.telegram_webhook import router as _telegram_webhook_router

    app.include_router(_telegram_router)
    app.include_router(_telegram_webhook_router)

    # Phase-13 / 65 / 77: OTA surface split into three halves —
    #   * routers.ota                          — diagnostics + listing +
    #                                            broadcast + firmware upload
    #                                            (no campaign row)
    #   * routers.ota_campaigns                — campaign create + read views
    #   * routers.ota_campaigns_lifecycle      — accept / decline / rollback
    # ``ota`` ships first because ``ota_campaigns`` imports the
    # firmware-bytes helpers (``_ota_store_uploaded_bin``,
    # ``_ota_bin_path_for_stored_name``, ``_require_ota_upload_password``,
    # ``_sha256_for``) from it at module-load time.
    # ``ota_campaigns_lifecycle`` has no module-load-time dep on the
    # other two (it pulls helpers from ``_app`` directly), so its
    # ordering relative to ``ota_campaigns`` is a wash; we register it
    # last so the lifecycle reads as a story (create/list → accept/etc).
    from routers.ota import router as _ota_router
    from routers.ota_campaigns import router as _ota_campaigns_router
    from routers.ota_campaigns_lifecycle import router as _ota_campaigns_lifecycle_router

    app.include_router(_ota_router)
    app.include_router(_ota_campaigns_router)
    app.include_router(_ota_campaigns_lifecycle_router)

    # Phase-8 / 68: event center split into two halves —
    #   * routers.events         — paginated /events, CSV, by-device, taxonomy
    #   * routers.events_stream  — SSE /events/stream + WebSocket /events/ws
    # The two halves share *no* helpers (history filters via SQL,
    # streaming filters via event_bus subscriber dicts), so order
    # is irrelevant — registering events first matches the historical
    # registration order for log-grep continuity.
    from routers.events import router as _events_router
    from routers.events_stream import router as _events_stream_router

    app.include_router(_events_router)
    app.include_router(_events_stream_router)

    # Phase-7: /factory/* (register / ping / list / block) + X-Factory-Token auth.
    from routers.factory import router as _factory_router

    app.include_router(_factory_router)


__all__ = ("register_routers",)
