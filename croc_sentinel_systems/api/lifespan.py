"""FastAPI lifespan + bootstrap pipeline (Phase-59 extraction from ``app.py``).

Carved out the four functions that ran the API's deferred startup
and clean shutdown:

* :func:`validate_production_env` — env-driven sanity checks
  (LEGACY_API_TOKEN strength, CMD_AUTH_KEY shape, BOOTSTRAP_BIND_KEY
  default, MQTT credentials, MAX_BULK_TARGETS bounds, retention,
  challenge / QR signing requirements). Either raises (when
  ``STRICT_STARTUP_ENV_CHECK=1``) or warns and continues. Imported
  back into ``app.py`` so the test harness can call it directly.
* :func:`_blocking_api_bootstrap_inner` — runs on the
  ``api-bootstrap`` daemon thread spawned by the lifespan hook.
  Validates env, opens the SQLite schema, runs the OTA retention
  prune, starts notifier + telegram + FCM workers, kicks the MQTT
  ingest worker thread + Paho client, the scheduler thread, and
  the optional Redis bridge.
* :func:`_shutdown_api`            — reverse-order teardown for
  the same workers, plus a 10s join on the MQTT worker so we never
  block the lifespan hook indefinitely.
* :func:`_app_lifespan`            — the asynccontextmanager
  FastAPI passes to ``FastAPI(..., lifespan=...)``. Binds HTTP
  immediately, runs ``_blocking_api_bootstrap_inner`` on a daemon
  thread (so uvicorn workers don't block their startup probe), then
  on shutdown joins the bootstrap thread (2s) and runs ``_shutdown_api``.

Why the mutable state still lives on ``app.py``
-----------------------------------------------
The lifespan needs to mutate the module-level ``mqtt_client``,
``mqtt_worker_thread``, ``mqtt_ingest_dropped`` (reset to 0 on
boot) plus the readiness signals ``api_ready_event`` and
``api_bootstrap_error``. Every cross-module reader (cmd_publish,
cmd_keys, csrf-readiness guard, routers/dashboard_read,
routers/diagnostics) expects those names on ``app.py`` because
module attribute access is dynamic. So this module mutates them
through ``import app as _app`` (e.g. ``_app.mqtt_client = ...``)
instead of forking the source of truth.

The helpers and worker entry points are imported directly:
``init_db`` from ``db``, ``notifier``, ``client_context``
(``_telegram_enabled_safe``, ``_fcm_enabled_safe``,
``_fcm_delete_stale_registration_token``), ``mqtt_pipeline``
(``_mqtt_ingest_worker``, ``start_mqtt_loop``, ``stop_mqtt_loop``),
``scheduler`` (``start_scheduler``, ``stop_scheduler``),
``redis_bridge`` (``_start_event_redis_bridge``,
``_stop_event_redis_bridge``), ``ota_files``
(``_ota_enforce_max_stored_bins``).
"""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI

from client_context import (
    _fcm_delete_stale_registration_token,
    _fcm_enabled_safe,
    _telegram_enabled_safe,
)
from config import (
    API_TOKEN,
    BOOTSTRAP_BIND_KEY,
    BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD,
    CMD_AUTH_KEY,
    DEVICE_CHALLENGE_TTL_SECONDS,
    DB_BACKUP_ENABLED,
    DB_BACKUP_PRESIGNED_URL_TEMPLATE,
    ENFORCE_DEVICE_CHALLENGE,
    JWT_SECRET,
    LEGACY_API_TOKEN_ENABLED,
    MAX_BULK_TARGETS,
    MESSAGE_RETENTION_DAYS,
    MQTT_HOST,
    MQTT_PASSWORD,
    MQTT_PORT,
    MQTT_TLS_VERIFY_HOSTNAME,
    MQTT_USE_TLS,
    MQTT_USERNAME,
    QR_SIGN_SECRET,
    STRICT_STARTUP_ENV_CHECK,
)
from db import DB_PATH
from schema import init_db
from helpers import contains_insecure_marker, is_hex_16
from mqtt_pipeline import _mqtt_ingest_worker, start_mqtt_loop, stop_mqtt_loop
from notifier import notifier
from ota_files import _ota_enforce_max_stored_bins
from redis_bridge import _start_event_redis_bridge, _stop_event_redis_bridge
from scheduler import start_scheduler, stop_scheduler

import app as _app

__all__ = (
    "validate_production_env",
    "_blocking_api_bootstrap_inner",
    "_shutdown_api",
    "_app_lifespan",
)

logger = logging.getLogger(__name__)


def validate_production_env() -> None:
    errors: list[str] = []
    if LEGACY_API_TOKEN_ENABLED and (
        not API_TOKEN or len(API_TOKEN) < 20 or contains_insecure_marker(API_TOKEN)
    ):
        errors.append("API_TOKEN is weak or default (LEGACY_API_TOKEN_ENABLED=1)")
    if not CMD_AUTH_KEY or not is_hex_16(CMD_AUTH_KEY):
        errors.append("CMD_AUTH_KEY must be 16 hex chars")
    if not BOOTSTRAP_BIND_KEY or len(BOOTSTRAP_BIND_KEY) < 16 or contains_insecure_marker(BOOTSTRAP_BIND_KEY):
        errors.append("BOOTSTRAP_BIND_KEY is default")
    if len(MQTT_USERNAME) < 4 or len(MQTT_PASSWORD) < 12:
        errors.append("MQTT credentials too weak")
    if contains_insecure_marker(MQTT_USERNAME) or contains_insecure_marker(MQTT_PASSWORD):
        errors.append("MQTT credentials are default/insecure")
    if contains_insecure_marker(MQTT_HOST):
        errors.append("MQTT_HOST is placeholder")
    if MAX_BULK_TARGETS < 1 or MAX_BULK_TARGETS > 5000:
        errors.append("MAX_BULK_TARGETS out of allowed range")
    if MESSAGE_RETENTION_DAYS < 1:
        errors.append("MESSAGE_RETENTION_DAYS must be >= 1")
    if ENFORCE_DEVICE_CHALLENGE and DEVICE_CHALLENGE_TTL_SECONDS < 30:
        errors.append("DEVICE_CHALLENGE_TTL_SECONDS must be >= 30 when ENFORCE_DEVICE_CHALLENGE=1")
    if ENFORCE_DEVICE_CHALLENGE and (not QR_SIGN_SECRET or len(QR_SIGN_SECRET) < 24):
        errors.append("QR_SIGN_SECRET must be set (>=24 chars) when ENFORCE_DEVICE_CHALLENGE=1")
    if BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD:
        if not JWT_SECRET or len(JWT_SECRET) < 32:
            errors.append("JWT_SECRET must be set (>=32 chars) when BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD is used")
    if DB_BACKUP_ENABLED and not DB_BACKUP_PRESIGNED_URL_TEMPLATE:
        errors.append("DB_BACKUP_ENABLED=1 requires DB_BACKUP_PRESIGNED_URL_TEMPLATE")
    if errors:
        msg = "Invalid production environment: " + "; ".join(errors)
        if STRICT_STARTUP_ENV_CHECK:
            raise RuntimeError(msg)
        logger.warning("%s (startup allowed because STRICT_STARTUP_ENV_CHECK=0)", msg)


def _blocking_api_bootstrap_inner() -> None:
    """Runs on thread api-bootstrap: DB init, notifier, MQTT ingest, scheduler."""
    validate_production_env()
    init_db()
    try:
        _ota_enforce_max_stored_bins()
    except Exception:
        logger.exception("OTA firmware retention prune at startup failed")
    notifier.start()
    try:
        from telegram_notify import start_telegram_worker

        start_telegram_worker()
    except Exception:
        logger.exception("Telegram worker failed to start (check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS)")
    try:
        from fcm_notify import set_invalid_token_handler, start_fcm_worker

        start_fcm_worker()
        set_invalid_token_handler(_fcm_delete_stale_registration_token)
    except Exception:
        logger.exception("FCM worker failed to start (check FCM_SERVICE_ACCOUNT_JSON / FCM_PROJECT_ID)")
    _app.mqtt_worker_stop.clear()
    _app.mqtt_ingest_dropped = 0
    _app.mqtt_worker_thread = threading.Thread(target=_mqtt_ingest_worker, name="mqtt-ingest", daemon=True)
    _app.mqtt_worker_thread.start()
    _app.mqtt_client = start_mqtt_loop()
    start_scheduler()
    _start_event_redis_bridge()
    logger.info(
        "API started mqtt_host=%s mqtt_port=%s mqtt_tls=%s "
        "mqtt_tls_verify_hostname=%s db=%s notifier_enabled=%s telegram=%s fcm=%s",
        MQTT_HOST,
        MQTT_PORT,
        MQTT_USE_TLS,
        MQTT_TLS_VERIFY_HOSTNAME,
        DB_PATH,
        notifier.enabled(),
        _telegram_enabled_safe(),
        _fcm_enabled_safe(),
    )


def _shutdown_api() -> None:
    _stop_event_redis_bridge()
    stop_scheduler()
    if _app.mqtt_client is not None:
        stop_mqtt_loop(_app.mqtt_client)
        _app.mqtt_client = None
    _app.mqtt_worker_stop.set()
    if _app.mqtt_worker_thread is not None:
        _app.mqtt_worker_thread.join(timeout=10.0)
        _app.mqtt_worker_thread = None
    try:
        from telegram_notify import stop_telegram_worker

        stop_telegram_worker()
    except Exception:
        pass
    try:
        from fcm_notify import stop_fcm_worker

        stop_fcm_worker()
    except Exception:
        pass
    notifier.stop()


@asynccontextmanager
async def _app_lifespan(app: FastAPI):
    """Bind HTTP immediately; heavy sync startup runs on api-bootstrap thread."""
    _app.api_ready_event.clear()
    _app.api_bootstrap_error = None

    def _run_bootstrap() -> None:
        try:
            _blocking_api_bootstrap_inner()
        except BaseException as exc:
            _app.api_bootstrap_error = repr(exc)
            logger.exception("API bootstrap failed")
        finally:
            _app.api_ready_event.set()

    _app._bootstrap_thread = threading.Thread(target=_run_bootstrap, name="api-bootstrap", daemon=True)
    _app._bootstrap_thread.start()
    yield
    if _app._bootstrap_thread is not None and _app._bootstrap_thread.is_alive():
        _app._bootstrap_thread.join(timeout=2.0)
    _shutdown_api()
