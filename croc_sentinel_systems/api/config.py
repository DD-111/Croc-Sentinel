"""Environment-derived configuration for the Croc Sentinel API.

Phase-2 modularization extract from ``app.py``: every module-level constant
that's read from ``os.getenv`` (plus the trivial validation logic that
normalizes those values) lives here. ``app.py`` does ``from config import *``
so all existing call sites remain spelt the same way.

Why a single ``config`` module?
  * One place to scan when an operator wants to know "what env vars does
    this service actually look at?" (the answer is now in this file's
    ``os.getenv`` calls).
  * ``app.py`` shrinks by ~230 lines without any behavior change.
  * Routers extracted in later phases (events, factory, ota, …) can pull
    just the knobs they need with explicit imports rather than relying on
    ``app.py``'s namespace.

Constants that have *no* env input (e.g. derived ``TOPIC_*`` strings,
the ``PASSWORD_RECOVERY_BLOB_*`` magic numbers, and the reserved-prefix
guard set used by ``DASHBOARD_PATH``) live here too because they're
configuration in spirit and cluster naturally with the env knobs they
support.

The DB-layer env knobs (``DB_PATH``, ``SQLITE_*``, ``CACHE_TTL_SECONDS``)
were moved to ``db.py`` in Phase 1 and are not duplicated here.
"""
from __future__ import annotations

import os

from security import JWT_EXPIRE_S


# --- MQTT broker -----------------------------------------------------------
MQTT_HOST: str = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT: int = int(os.getenv("MQTT_PORT", "8883"))
# Paho CONNECT keepalive (seconds). Higher values reduce control traffic and help some NATs;
# must stay below broker / firewall idle cuts; typical 45–120.
MQTT_KEEPALIVE: int = max(10, min(600, int(os.getenv("MQTT_KEEPALIVE", "60"))))
MQTT_USERNAME: str = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD: str = os.getenv("MQTT_PASSWORD", "")
# Broker listener is TLS-only (see mosquitto.conf.template): API must use TLS too.
MQTT_USE_TLS: bool = os.getenv("MQTT_USE_TLS", "1") == "1"
MQTT_CLIENT_CA: str = os.getenv("MQTT_CLIENT_CA", "/etc/sentinel/mqtt-ca.crt")
# When 0 (default): skip TLS hostname check; broker cert CN/SAN usually matches public
# hostname, not the Docker DNS name (e.g. mosquitto). Chain is still verified via CA.
MQTT_TLS_VERIFY_HOSTNAME: bool = os.getenv("MQTT_TLS_VERIFY_HOSTNAME", "0") == "1"
TOPIC_ROOT: str = os.getenv("TOPIC_ROOT", "sentinel")

# Derived MQTT topics (computed once from TOPIC_ROOT so the rest of the
# code base never has to template the prefix manually).
TOPIC_HEARTBEAT: str = f"{TOPIC_ROOT}/+/heartbeat"
TOPIC_STATUS: str = f"{TOPIC_ROOT}/+/status"
TOPIC_EVENT: str = f"{TOPIC_ROOT}/+/event"
TOPIC_ACK: str = f"{TOPIC_ROOT}/+/ack"
TOPIC_BOOTSTRAP_REGISTER: str = f"{TOPIC_ROOT}/bootstrap/register"

# --- Command channel auth --------------------------------------------------
CMD_AUTH_KEY: str = os.getenv("CMD_AUTH_KEY", "")
BOOTSTRAP_BIND_KEY: str = os.getenv("BOOTSTRAP_BIND_KEY", "")
CMD_PROTO: int = int(os.getenv("CMD_PROTO", "2"))
API_TOKEN: str = os.getenv("API_TOKEN", "")
# When 0 (default), the long-lived API_TOKEN bearer is not accepted — use JWT login only.
LEGACY_API_TOKEN_ENABLED: bool = os.getenv("LEGACY_API_TOKEN_ENABLED", "0") == "1"

# --- Process I/O paths -----------------------------------------------------
LOG_FILE_PATH: str = os.getenv("LOG_FILE_PATH", "/data/api.log")

# --- Provisioning / scheduler ----------------------------------------------
PROVISION_USE_SHARED_MQTT_CREDS: bool = os.getenv("PROVISION_USE_SHARED_MQTT_CREDS", "1") == "1"
SCHEDULER_POLL_SECONDS: float = float(os.getenv("SCHEDULER_POLL_SECONDS", "1.0"))
SLOW_REQUEST_LOG_MS: int = int(os.getenv("SLOW_REQUEST_LOG_MS", "0"))
CLAIM_RESPONSE_INCLUDE_SECRETS: bool = os.getenv("CLAIM_RESPONSE_INCLUDE_SECRETS", "0") == "1"
MAX_BULK_TARGETS: int = int(os.getenv("MAX_BULK_TARGETS", "500"))
MESSAGE_RETENTION_DAYS: int = int(os.getenv("MESSAGE_RETENTION_DAYS", "14"))
STRICT_STARTUP_ENV_CHECK: bool = os.getenv("STRICT_STARTUP_ENV_CHECK", "0") == "1"

# --- JWT / cookie / CSRF ---------------------------------------------------
JWT_SECRET: str = os.getenv("JWT_SECRET", "")
# Dashboard session: HttpOnly cookie (preferred) + optional JSON access_token for scripts.
JWT_USE_HTTPONLY_COOKIE: bool = os.getenv("JWT_USE_HTTPONLY_COOKIE", "1") == "1"
JWT_COOKIE_NAME: str = (os.getenv("JWT_COOKIE_NAME", "sentinel_jwt").strip() or "sentinel_jwt")
JWT_COOKIE_SECURE: bool = os.getenv("JWT_COOKIE_SECURE", "0") == "1"
_jwt_ss = (os.getenv("JWT_COOKIE_SAMESITE", "lax") or "lax").strip().lower()
JWT_COOKIE_SAMESITE: str = "strict" if _jwt_ss == "strict" else "lax"
JWT_RETURN_BODY_TOKEN: bool = os.getenv("JWT_RETURN_BODY_TOKEN", "0") == "1"
# CSRF protection (double-submit token). Turned ON by default whenever the
# session lives in an HttpOnly cookie — a cross-site request that sneaks the
# cookie along still can't guess the CSRF token because the browser won't let
# the other origin read `document.cookie` for our host. When auth is done via
# Authorization: Bearer (e.g., mobile apps, CI), CSRF is not applicable and
# the guard skips automatically.
CSRF_PROTECTION: bool = os.getenv("CSRF_PROTECTION", "1") == "1"
CSRF_COOKIE_NAME: str = (os.getenv("CSRF_COOKIE_NAME", "sentinel_csrf").strip() or "sentinel_csrf")
CSRF_HEADER_NAME: str = (os.getenv("CSRF_HEADER_NAME", "X-CSRF-Token").strip() or "X-CSRF-Token")
# Match JWT session lifetime so the CSRF cookie doesn't expire while the user
# is still signed in (would force a silent re-login). Falls back to 1 day.
CSRF_TOKEN_TTL_S: int = int(os.getenv("CSRF_TOKEN_TTL_S", str(int(JWT_EXPIRE_S) if int(JWT_EXPIRE_S) > 0 else 86400)))
# SSE: ?token= leaks via logs; disable unless legacy clients need it.
SSE_ALLOW_QUERY_TOKEN: bool = os.getenv("SSE_ALLOW_QUERY_TOKEN", "0") == "1"
# Public /health: set 1 only if load balancers need broker/smtp detail without auth.
HEALTH_PUBLIC_DETAIL: bool = os.getenv("HEALTH_PUBLIC_DETAIL", "0") == "1"

# --- Bootstrap superadmin --------------------------------------------------
BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME: str = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME", "superadmin").strip()
BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD: str = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD", "")

# --- Per-device hardening --------------------------------------------------
ENFORCE_PER_DEVICE_CREDS: bool = os.getenv("ENFORCE_PER_DEVICE_CREDS", "0") == "1"
ENFORCE_DEVICE_CHALLENGE: bool = os.getenv("ENFORCE_DEVICE_CHALLENGE", "0") == "1"
DEVICE_CHALLENGE_TTL_SECONDS: int = int(os.getenv("DEVICE_CHALLENGE_TTL_SECONDS", "300"))
DEVICE_ID_REGEX: str = os.getenv("DEVICE_ID_REGEX", r"^SN-[A-Z2-7]{16}$")
QR_CODE_REGEX: str = os.getenv("QR_CODE_REGEX", r"^CROC\|SN-[A-Z2-7]{16}\|\d{10}\|[A-Za-z0-9_-]{20,120}$")
QR_SIGN_SECRET: str = os.getenv("QR_SIGN_SECRET", "")

# --- Tenant scoping --------------------------------------------------------
ALLOW_LEGACY_UNOWNED: bool = os.getenv("ALLOW_LEGACY_UNOWNED", "1") == "1"
# When true (default), admins/users never see "unowned" devices in list/API scope unless they are
# the owning tenant — prevents cross-tenant leakage. Set TENANT_STRICT=0 for legacy lab behavior.
TENANT_STRICT: bool = os.getenv("TENANT_STRICT", "1") == "1"

# --- OTA firmware storage --------------------------------------------------
# Default: repo `croc_sentinel_systems/firmware` (alongside this package). Docker sets OTA_FIRMWARE_DIR=/opt/sentinel/firmware.
_API_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_OTA_FIRMWARE_DIR = os.path.normpath(os.path.join(_API_DIR, "..", "firmware"))
OTA_FIRMWARE_DIR: str = os.path.abspath(os.getenv("OTA_FIRMWARE_DIR", _DEFAULT_OTA_FIRMWARE_DIR))
OTA_PUBLIC_BASE_URL: str = os.getenv("OTA_PUBLIC_BASE_URL", "").rstrip("/")
# Required for API uploads (dashboard Upload & verify, POST /ota/firmware/upload, /ota/campaigns/from-upload).
# Use a long random secret. If unset, uploads are rejected.
OTA_UPLOAD_PASSWORD: str = (os.getenv("OTA_UPLOAD_PASSWORD") or os.getenv("FIRMWARE_UPLOAD_PASSWORD") or "").strip()
# How many .bin files to keep under OTA_FIRMWARE_DIR; oldest mtime is removed first when over limit.
OTA_MAX_FIRMWARE_BINS: int = max(1, int(os.getenv("OTA_MAX_FIRMWARE_BINS", "10")))
# Optional: base URL used only for server-side HEAD/GET checks (same /fw/ path as public).
# Use when devices resolve https://ota.example.com but the API container cannot (hairpin NAT),
# or before public TLS is ready: e.g. http://ota-nginx:9231 on the Docker network.
OTA_VERIFY_BASE_URL: str = os.getenv("OTA_VERIFY_BASE_URL", "").rstrip("/")
OTA_TOKEN: str = os.getenv("OTA_TOKEN", "")
MAX_OTA_UPLOAD_BYTES: int = int(os.getenv("MAX_OTA_UPLOAD_BYTES", str(16 * 1024 * 1024)))

# --- Alarm / fan-out -------------------------------------------------------
DEFAULT_REMOTE_FANOUT_MS: int = int(os.getenv("DEFAULT_REMOTE_FANOUT_MS", "180000"))
DEFAULT_PANIC_FANOUT_MS: int = int(os.getenv("DEFAULT_PANIC_FANOUT_MS", "300000"))
ALARM_FANOUT_DURATION_MS: int = int(os.getenv("ALARM_FANOUT_DURATION_MS", str(DEFAULT_REMOTE_FANOUT_MS)))
ALARM_FANOUT_MAX_TARGETS: int = int(os.getenv("ALARM_FANOUT_MAX_TARGETS", "200"))
# Max wall-clock seconds the ingest thread will spend on a single fan-out round
# (workers are daemon threads; unfinished publishes still complete in paho).
FANOUT_WALL_CLOCK_MAX_S: float = max(0.5, min(10.0, float(os.getenv("FANOUT_WALL_CLOCK_MAX_S", "1.5"))))
# Cap parallel MQTT publishes per fan-out round. Paho's single writer means too
# many concurrent publishes only add thread overhead; 8–16 is plenty for QoS 1.
FANOUT_WORKER_POOL_SIZE: int = max(1, min(64, int(os.getenv("FANOUT_WORKER_POOL_SIZE", "12"))))
ALARM_FANOUT_SELF: bool = os.getenv("ALARM_FANOUT_SELF", "0") == "1"
# QoS1 can redeliver duplicate event frames after reconnect; suppress repeated
# sibling fan-out for the same logical alarm event in this short window.
ALARM_EVENT_DEDUP_WINDOW_SEC: int = int(os.getenv("ALARM_EVENT_DEDUP_WINDOW_SEC", "8"))

# --- Auto-reconcile worker -------------------------------------------------
AUTO_RECONCILE_ENABLED: bool = os.getenv("AUTO_RECONCILE_ENABLED", "1") == "1"
AUTO_RECONCILE_COOLDOWN_SEC: int = int(os.getenv("AUTO_RECONCILE_COOLDOWN_SEC", "180"))
AUTO_RECONCILE_MAX_PER_TICK: int = max(1, int(os.getenv("AUTO_RECONCILE_MAX_PER_TICK", "2")))
PENDING_CLAIM_STALE_SECONDS: int = int(os.getenv("PENDING_CLAIM_STALE_SECONDS", str(24 * 3600)))

# --- Per-IP login lockout --------------------------------------------------
# Tier 0: FAILS wrong → lock LOCK0 s; tier 1: FAILS → lock LOCK1; tier 2+: FAILS → lock LOCK2. Success clears IP state.
LOGIN_LOCK_TIER0_FAILS: int = max(1, int(os.getenv("LOGIN_LOCK_TIER0_FAILS", "5")))
LOGIN_LOCK_TIER0_SECONDS: int = max(1, int(os.getenv("LOGIN_LOCK_TIER0_SECONDS", "60")))
LOGIN_LOCK_TIER1_FAILS: int = max(1, int(os.getenv("LOGIN_LOCK_TIER1_FAILS", "3")))
LOGIN_LOCK_TIER1_SECONDS: int = max(1, int(os.getenv("LOGIN_LOCK_TIER1_SECONDS", "180")))
LOGIN_LOCK_TIER2_FAILS: int = max(1, int(os.getenv("LOGIN_LOCK_TIER2_FAILS", "3")))
LOGIN_LOCK_TIER2_SECONDS: int = max(1, int(os.getenv("LOGIN_LOCK_TIER2_SECONDS", "600")))

# --- Signup / user activation ----------------------------------------------
# If 1, a superadmin must approve each admin signup before they can log in. Default 0: self-serve.
ADMIN_SIGNUP_REQUIRE_APPROVAL: bool = os.getenv("ADMIN_SIGNUP_REQUIRE_APPROVAL", "0") == "1"
# If 0, new public admin signups are refused entirely (for private deployments).
ALLOW_PUBLIC_ADMIN_SIGNUP: bool = os.getenv("ALLOW_PUBLIC_ADMIN_SIGNUP", "1") == "1"
REQUIRE_EMAIL_VERIFICATION: bool = os.getenv("REQUIRE_EMAIL_VERIFICATION", "1") == "1"
REQUIRE_PHONE_VERIFICATION: bool = os.getenv("REQUIRE_PHONE_VERIFICATION", "0") == "1"
SIGNUP_RATE_MAX: int = int(os.getenv("SIGNUP_RATE_MAX", "5"))
SIGNUP_RATE_WINDOW_SECONDS: int = int(os.getenv("SIGNUP_RATE_WINDOW_SECONDS", "3600"))
OTP_TTL_SECONDS: int = int(os.getenv("OTP_TTL_SECONDS", "900"))
OTP_RESEND_COOLDOWN_SECONDS: int = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))
# SMS: by default we run in email-only mode. If your VPS wires up a provider
# (Twilio / Aliyun / Tencent / Bandwidth), set SMS_PROVIDER to its name and
# implement the corresponding handler in notifier_sms.py. Absent that, phone
# verifications are a no-op and REQUIRE_PHONE_VERIFICATION must stay 0.
SMS_PROVIDER: str = os.getenv("SMS_PROVIDER", "none").strip().lower()

# --- Factory device registry (unguessable serial model) -------------------
# When ENFORCE_FACTORY_REGISTRATION=1 the API will refuse to record a
# pending_claims row for any device whose (serial, mac_nocolon) pair is not
# already listed in factory_devices. This is what makes serials truly
# unguessable in production.
ENFORCE_FACTORY_REGISTRATION: bool = os.getenv("ENFORCE_FACTORY_REGISTRATION", "0") == "1"
FACTORY_API_TOKEN: str = os.getenv("FACTORY_API_TOKEN", "")

# --- Telegram command bot --------------------------------------------------
TELEGRAM_COMMAND_SECRET: str = os.getenv("TELEGRAM_COMMAND_SECRET", "").strip()
TELEGRAM_COMMAND_CHAT_IDS_RAW: str = os.getenv("TELEGRAM_COMMAND_CHAT_IDS", "").strip()
TELEGRAM_COMMAND_MAX_LOG: int = int(os.getenv("TELEGRAM_COMMAND_MAX_LOG", "20"))
TELEGRAM_COMMAND_MAX_DEVICES: int = int(os.getenv("TELEGRAM_COMMAND_MAX_DEVICES", "30"))
TELEGRAM_BOT_USERNAME: str = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
TELEGRAM_LINK_TOKEN_TTL_SECONDS: int = int(os.getenv("TELEGRAM_LINK_TOKEN_TTL_SECONDS", "900"))

# --- Presence probe (last-resort liveness check) ---------------------------
# OFFLINE_THRESHOLD_SECONDS (90s) marks a device offline in the dashboard
# device list and the dashboard_read summary. Late-bound via
# ``_app.OFFLINE_THRESHOLD_SECONDS`` from device_presence.py / tenant_admin.py
# / routers/dashboard_read.py so any tweak via env reload is picked up live.
OFFLINE_THRESHOLD_SECONDS: int = int(os.getenv("OFFLINE_THRESHOLD_SECONDS", "90"))
# Devices in HYBRID mode should publish a keepalive every ~60s (see firmware
# HEARTBEAT_IDLE_KEEPALIVE_MS). If the device is still silent after IDLE_SECONDS
# the server publishes a single ``ping`` so we can distinguish "TCP quietly
# dropped" from "device genuinely dead". Keep this >> OFFLINE_THRESHOLD_SECONDS
# so we don't probe-spam devices that are merely momentarily late with a
# keepalive. Default 600s (10 min) = 10 missed keepalives, which is clearly
# abnormal.
PRESENCE_PROBE_IDLE_SECONDS: int = int(os.getenv("PRESENCE_PROBE_IDLE_SECONDS", "600"))
# How often the background worker scans for stale devices. Keep moderate so
# we don't hammer the DB; 120s is comfortably < IDLE_SECONDS/4.
PRESENCE_PROBE_SCAN_SECONDS: int = int(os.getenv("PRESENCE_PROBE_SCAN_SECONDS", "120"))
# Rate limit: don't probe the same device more than once per this window.
PRESENCE_PROBE_COOLDOWN_SECONDS: int = int(os.getenv("PRESENCE_PROBE_COOLDOWN_SECONDS", "900"))
# After N consecutive failed probes, the device is flagged offline and we back
# off to stop spamming the broker for obviously dead hardware.
PRESENCE_PROBE_MAX_CONSECUTIVE: int = int(os.getenv("PRESENCE_PROBE_MAX_CONSECUTIVE", "3"))
# A probe row stays outcome=sent until any device channel counts as an ack; if
# still sent after this many seconds, mark timeout (clears the outstanding row).
PRESENCE_PROBE_ACK_TIMEOUT_SEC: int = int(os.getenv("PRESENCE_PROBE_ACK_TIMEOUT_SEC", "480"))
# scheduled_commands still pending this long after execute_at_ts → mark failed.
SCHEDULED_CMD_STALE_PENDING_SEC: int = int(os.getenv("SCHEDULED_CMD_STALE_PENDING_SEC", "480"))

# --- OTA campaigns (superadmin -> admin approve -> per-device rollout) ----
# Per-device URL HEAD check timeout.
OTA_URL_VERIFY_TIMEOUT_SECONDS: float = float(os.getenv("OTA_URL_VERIFY_TIMEOUT_SECONDS", "10"))
# Max time we wait for a device to ack ota.result before marking it failed.
OTA_DEVICE_ACK_TIMEOUT_SECONDS: int = int(os.getenv("OTA_DEVICE_ACK_TIMEOUT_SECONDS", str(15 * 60)))
# If set, any device failure in a campaign auto-rolls-back the whole admin fleet.
OTA_AUTO_ROLLBACK_ON_FAILURE: bool = os.getenv("OTA_AUTO_ROLLBACK_ON_FAILURE", "1") == "1"

# --- Event center (global log + SSE stream) --------------------------------
# In-memory ring buffer size. ~500 B × N ≈ RAM footprint. 2000 ≈ 1 MB.
EVENT_RING_SIZE: int = int(os.getenv("EVENT_RING_SIZE", "2000"))
# Per-SSE-subscriber queue. Slow client → oldest events dropped with warning.
EVENT_SUB_QUEUE_SIZE: int = int(os.getenv("EVENT_SUB_QUEUE_SIZE", "500"))
# SSE keepalive: comment + named `ping` event so proxies that strip `:`
# comments still see traffic. Keep well below your reverse-proxy read_timeout (often 60s).
# Default 9s works better than 12s with strict proxies / mobile networks.
EVENT_SSE_KEEPALIVE_SECONDS: int = max(3, int(os.getenv("EVENT_SSE_KEEPALIVE_SECONDS", "9")))
# Hint for browser EventSource automatic reconnect delay (milliseconds).
EVENT_SSE_RETRY_MS: int = int(os.getenv("EVENT_SSE_RETRY_MS", "4000"))
# Toggle the WebSocket mirror of /events/stream at /events/ws. Off keeps
# the route reachable but it closes the connection with code 1008.
EVENT_WS_ENABLED: bool = os.getenv("EVENT_WS_ENABLED", "1") == "1"
# Hard cap on concurrent SSE subscribers (cheap, but bound the damage).
EVENT_MAX_SUBSCRIBERS: int = int(os.getenv("EVENT_MAX_SUBSCRIBERS", "128"))
# Level-based retention days. Debug rows go first; critical stays for audits.
EVENT_RETAIN_DAYS_DEBUG: int = int(os.getenv("EVENT_RETAIN_DAYS_DEBUG", "3"))
EVENT_RETAIN_DAYS_INFO: int = int(os.getenv("EVENT_RETAIN_DAYS_INFO", "14"))
EVENT_RETAIN_DAYS_WARN: int = int(os.getenv("EVENT_RETAIN_DAYS_WARN", "30"))
EVENT_RETAIN_DAYS_ERROR: int = int(os.getenv("EVENT_RETAIN_DAYS_ERROR", "90"))
EVENT_RETAIN_DAYS_CRITICAL: int = int(os.getenv("EVENT_RETAIN_DAYS_CRITICAL", "365"))
# Absolute backstop: delete any event older than this regardless of level.
EVENT_RETAIN_DAYS_MAX: int = int(os.getenv("EVENT_RETAIN_DAYS_MAX", "400"))
# How often the retention worker runs.
EVENT_RETENTION_SCAN_SECONDS: int = int(os.getenv("EVENT_RETENTION_SCAN_SECONDS", "3600"))
# MQTT → bounded RAM queue → single ingest worker (DB + emit_event + fan-out threads).
# Callback must stay O(1): only decode + put_nowait; never parse business JSON there.
MQTT_INGEST_QUEUE_MAX: int = int(os.getenv("MQTT_INGEST_QUEUE_MAX", "1000"))

# --- Offline password recovery (RSA public on server, private key only in
#     password_recovery_offline/ on the operator's air-gapped machine) -----
PASSWORD_RECOVERY_PUBLIC_KEY_PATH: str = os.getenv("PASSWORD_RECOVERY_PUBLIC_KEY_PATH", "").strip()
PASSWORD_RECOVERY_PUBLIC_KEY_PEM: str = os.getenv("PASSWORD_RECOVERY_PUBLIC_KEY_PEM", "").strip()
# Fixed-size inner plaintext so every blob is the same length (anti user-enumeration).
PASSWORD_RECOVERY_PLAINTEXT_PAD: int = int(os.getenv("PASSWORD_RECOVERY_PLAINTEXT_PAD", "512"))
FORGOT_PASSWORD_TOKEN_TTL_SECONDS: int = int(os.getenv("FORGOT_PASSWORD_TOKEN_TTL_SECONDS", str(24 * 3600)))
FORGOT_PASSWORD_IP_WINDOW_SECONDS: int = int(os.getenv("FORGOT_PASSWORD_IP_WINDOW_SECONDS", "3600"))
FORGOT_PASSWORD_IP_MAX: int = int(os.getenv("FORGOT_PASSWORD_IP_MAX", "12"))
# Magic header on the binary blob before hex-encoding for the dashboard.
PASSWORD_RECOVERY_BLOB_MAGIC: bytes = b"CRPW"
PASSWORD_RECOVERY_BLOB_VERSION: int = 1

# --- Dashboard mount path --------------------------------------------------
_dashboard_path = os.getenv("DASHBOARD_PATH", "/console").strip() or "/console"
if not _dashboard_path.startswith("/"):
    _dashboard_path = "/" + _dashboard_path
_dashboard_path = _dashboard_path.rstrip("/") or "/console"
# Guard: refuse to mount over known API prefixes. `/api` is included so an
# operator cannot accidentally point DASHBOARD_PATH at `/api`-style locations
# and shadow `/api/group-cards/*` (the dashboard's `/api/...` alias surface).
_RESERVED_PREFIXES = ("/auth", "/devices", "/commands", "/alerts", "/admin",
                      "/provision", "/health", "/dashboard", "/logs", "/audit",
                      "/ui", "/api", "/events", "/ota", "/factory",
                      "/integrations", "/ingest")
if any(_dashboard_path == p or _dashboard_path.startswith(p + "/") for p in _RESERVED_PREFIXES):
    # Fallback silently to /console to avoid shadowing API routes.
    _dashboard_path = "/console"
DASHBOARD_PATH: str = _dashboard_path


__all__ = [
    "ADMIN_SIGNUP_REQUIRE_APPROVAL",
    "ALARM_EVENT_DEDUP_WINDOW_SEC",
    "ALARM_FANOUT_DURATION_MS",
    "ALARM_FANOUT_MAX_TARGETS",
    "ALARM_FANOUT_SELF",
    "ALLOW_LEGACY_UNOWNED",
    "ALLOW_PUBLIC_ADMIN_SIGNUP",
    "API_TOKEN",
    "AUTO_RECONCILE_COOLDOWN_SEC",
    "AUTO_RECONCILE_ENABLED",
    "AUTO_RECONCILE_MAX_PER_TICK",
    "BOOTSTRAP_BIND_KEY",
    "BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD",
    "BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME",
    "CLAIM_RESPONSE_INCLUDE_SECRETS",
    "CMD_AUTH_KEY",
    "CMD_PROTO",
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "CSRF_PROTECTION",
    "CSRF_TOKEN_TTL_S",
    "DASHBOARD_PATH",
    "DEFAULT_PANIC_FANOUT_MS",
    "DEFAULT_REMOTE_FANOUT_MS",
    "DEVICE_CHALLENGE_TTL_SECONDS",
    "DEVICE_ID_REGEX",
    "ENFORCE_DEVICE_CHALLENGE",
    "ENFORCE_FACTORY_REGISTRATION",
    "ENFORCE_PER_DEVICE_CREDS",
    "EVENT_MAX_SUBSCRIBERS",
    "EVENT_RETAIN_DAYS_CRITICAL",
    "EVENT_RETAIN_DAYS_DEBUG",
    "EVENT_RETAIN_DAYS_ERROR",
    "EVENT_RETAIN_DAYS_INFO",
    "EVENT_RETAIN_DAYS_MAX",
    "EVENT_RETAIN_DAYS_WARN",
    "EVENT_RETENTION_SCAN_SECONDS",
    "EVENT_RING_SIZE",
    "EVENT_SSE_KEEPALIVE_SECONDS",
    "EVENT_SSE_RETRY_MS",
    "EVENT_SUB_QUEUE_SIZE",
    "EVENT_WS_ENABLED",
    "FACTORY_API_TOKEN",
    "FANOUT_WALL_CLOCK_MAX_S",
    "FANOUT_WORKER_POOL_SIZE",
    "FORGOT_PASSWORD_IP_MAX",
    "FORGOT_PASSWORD_IP_WINDOW_SECONDS",
    "FORGOT_PASSWORD_TOKEN_TTL_SECONDS",
    "HEALTH_PUBLIC_DETAIL",
    "JWT_COOKIE_NAME",
    "JWT_COOKIE_SAMESITE",
    "JWT_COOKIE_SECURE",
    "JWT_RETURN_BODY_TOKEN",
    "JWT_SECRET",
    "JWT_USE_HTTPONLY_COOKIE",
    "LEGACY_API_TOKEN_ENABLED",
    "LOGIN_LOCK_TIER0_FAILS",
    "LOGIN_LOCK_TIER0_SECONDS",
    "LOGIN_LOCK_TIER1_FAILS",
    "LOGIN_LOCK_TIER1_SECONDS",
    "LOGIN_LOCK_TIER2_FAILS",
    "LOGIN_LOCK_TIER2_SECONDS",
    "LOG_FILE_PATH",
    "MAX_BULK_TARGETS",
    "MAX_OTA_UPLOAD_BYTES",
    "MESSAGE_RETENTION_DAYS",
    "MQTT_CLIENT_CA",
    "MQTT_HOST",
    "MQTT_INGEST_QUEUE_MAX",
    "MQTT_KEEPALIVE",
    "MQTT_PASSWORD",
    "MQTT_PORT",
    "MQTT_TLS_VERIFY_HOSTNAME",
    "MQTT_USERNAME",
    "MQTT_USE_TLS",
    "OTA_AUTO_ROLLBACK_ON_FAILURE",
    "OTA_DEVICE_ACK_TIMEOUT_SECONDS",
    "OTA_FIRMWARE_DIR",
    "OTA_MAX_FIRMWARE_BINS",
    "OTA_PUBLIC_BASE_URL",
    "OTA_TOKEN",
    "OTA_UPLOAD_PASSWORD",
    "OTA_URL_VERIFY_TIMEOUT_SECONDS",
    "OTA_VERIFY_BASE_URL",
    "OFFLINE_THRESHOLD_SECONDS",
    "OTP_RESEND_COOLDOWN_SECONDS",
    "OTP_TTL_SECONDS",
    "PASSWORD_RECOVERY_BLOB_MAGIC",
    "PASSWORD_RECOVERY_BLOB_VERSION",
    "PASSWORD_RECOVERY_PLAINTEXT_PAD",
    "PASSWORD_RECOVERY_PUBLIC_KEY_PATH",
    "PASSWORD_RECOVERY_PUBLIC_KEY_PEM",
    "PENDING_CLAIM_STALE_SECONDS",
    "PRESENCE_PROBE_ACK_TIMEOUT_SEC",
    "PRESENCE_PROBE_COOLDOWN_SECONDS",
    "PRESENCE_PROBE_IDLE_SECONDS",
    "PRESENCE_PROBE_MAX_CONSECUTIVE",
    "PRESENCE_PROBE_SCAN_SECONDS",
    "PROVISION_USE_SHARED_MQTT_CREDS",
    "QR_CODE_REGEX",
    "QR_SIGN_SECRET",
    "REQUIRE_EMAIL_VERIFICATION",
    "REQUIRE_PHONE_VERIFICATION",
    "SCHEDULED_CMD_STALE_PENDING_SEC",
    "SCHEDULER_POLL_SECONDS",
    "SIGNUP_RATE_MAX",
    "SIGNUP_RATE_WINDOW_SECONDS",
    "SLOW_REQUEST_LOG_MS",
    "SMS_PROVIDER",
    "SSE_ALLOW_QUERY_TOKEN",
    "STRICT_STARTUP_ENV_CHECK",
    "TELEGRAM_BOT_USERNAME",
    "TELEGRAM_COMMAND_CHAT_IDS_RAW",
    "TELEGRAM_COMMAND_MAX_DEVICES",
    "TELEGRAM_COMMAND_MAX_LOG",
    "TELEGRAM_COMMAND_SECRET",
    "TELEGRAM_LINK_TOKEN_TTL_SECONDS",
    "TENANT_STRICT",
    "TOPIC_ACK",
    "TOPIC_BOOTSTRAP_REGISTER",
    "TOPIC_EVENT",
    "TOPIC_HEARTBEAT",
    "TOPIC_ROOT",
    "TOPIC_STATUS",
]
