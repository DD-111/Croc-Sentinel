import collections
import csv
import io
import json
import logging
import os
import queue as _stdqueue
import secrets
import sqlite3
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from contextlib import asynccontextmanager
import asyncio
import base64
import hashlib
import hmac
import re
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security import (
    JWT_EXPIRE_S,
    Principal,
    assert_min_role,
    assert_zone_for_device,
    decode_jwt,
    decrypt_blob,
    encrypt_blob,
    hash_password,
    issue_jwt,
    verify_password,
    zones_from_json,
)
from notifier import notifier, render_alarm_email, render_remote_siren_email
from email_templates import (
    render_otp_email,
    render_password_changed_email,
    render_smtp_test_email,
    render_welcome_email,
)
from tz_display import iso_timestamp_to_malaysia, malaysia_now_iso


def utc_now_iso() -> str:
    """UTC ISO string for SQLite storage and lexicographic ordering (canonical `ts`)."""
    return datetime.now(timezone.utc).isoformat()


def _normalize_delete_confirm(raw: str) -> str:
    """Strip invisible chars / odd spacing so pasted confirmation still matches DELETE."""
    s = raw or ""
    s = re.sub(r"[\u200b-\u200d\ufeff]", "", s)
    return re.sub(r"\s+", " ", s).strip().upper()


MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
# Paho CONNECT keepalive (seconds). Higher values reduce control traffic and help some NATs;
# must stay below broker / firewall idle cuts; typical 45–120.
MQTT_KEEPALIVE = max(10, min(600, int(os.getenv("MQTT_KEEPALIVE", "60"))))
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
# Broker listener is TLS-only (see mosquitto.conf.template): API must use TLS too.
MQTT_USE_TLS = os.getenv("MQTT_USE_TLS", "1") == "1"
MQTT_CLIENT_CA = os.getenv("MQTT_CLIENT_CA", "/etc/sentinel/mqtt-ca.crt")
# When 0 (default): skip TLS hostname check; broker cert CN/SAN usually matches public
# hostname, not the Docker DNS name (e.g. mosquitto). Chain is still verified via CA.
MQTT_TLS_VERIFY_HOSTNAME = os.getenv("MQTT_TLS_VERIFY_HOSTNAME", "0") == "1"
TOPIC_ROOT = os.getenv("TOPIC_ROOT", "sentinel")
CMD_AUTH_KEY = os.getenv("CMD_AUTH_KEY", "")
BOOTSTRAP_BIND_KEY = os.getenv("BOOTSTRAP_BIND_KEY", "")
CMD_PROTO = int(os.getenv("CMD_PROTO", "2"))
API_TOKEN = os.getenv("API_TOKEN", "")
# When 0 (default), the long-lived API_TOKEN bearer is not accepted — use JWT login only.
LEGACY_API_TOKEN_ENABLED = os.getenv("LEGACY_API_TOKEN_ENABLED", "0") == "1"
DB_PATH = os.getenv("DB_PATH", "/data/sentinel.db")
# sqlite3.connect(timeout=…): seconds waiting to acquire DB lock at open.
SQLITE_CONNECT_TIMEOUT_S = float(os.getenv("SQLITE_CONNECT_TIMEOUT_S", "10.0"))
_sqlite_busy_ms = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "5000"))
SQLITE_BUSY_TIMEOUT_MS = max(0, min(600_000, _sqlite_busy_ms))
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/data/api.log")
PROVISION_USE_SHARED_MQTT_CREDS = os.getenv("PROVISION_USE_SHARED_MQTT_CREDS", "1") == "1"
SCHEDULER_POLL_SECONDS = float(os.getenv("SCHEDULER_POLL_SECONDS", "1.0"))
CLAIM_RESPONSE_INCLUDE_SECRETS = os.getenv("CLAIM_RESPONSE_INCLUDE_SECRETS", "0") == "1"
MAX_BULK_TARGETS = int(os.getenv("MAX_BULK_TARGETS", "500"))
# Short TTL for dashboard list/overview JSON; higher = fewer DB hits on repeat views (good on flaky links).
CACHE_TTL_SECONDS = float(os.getenv("CACHE_TTL_SECONDS", "18.0"))
MESSAGE_RETENTION_DAYS = int(os.getenv("MESSAGE_RETENTION_DAYS", "14"))
STRICT_STARTUP_ENV_CHECK = os.getenv("STRICT_STARTUP_ENV_CHECK", "0") == "1"
JWT_SECRET = os.getenv("JWT_SECRET", "")
# Dashboard session: HttpOnly cookie (preferred) + optional JSON access_token for scripts.
JWT_USE_HTTPONLY_COOKIE = os.getenv("JWT_USE_HTTPONLY_COOKIE", "1") == "1"
JWT_COOKIE_NAME = (os.getenv("JWT_COOKIE_NAME", "sentinel_jwt").strip() or "sentinel_jwt")
JWT_COOKIE_SECURE = os.getenv("JWT_COOKIE_SECURE", "0") == "1"
_ss = (os.getenv("JWT_COOKIE_SAMESITE", "lax") or "lax").strip().lower()
JWT_COOKIE_SAMESITE: str = "strict" if _ss == "strict" else "lax"
JWT_RETURN_BODY_TOKEN = os.getenv("JWT_RETURN_BODY_TOKEN", "0") == "1"
# CSRF protection (double-submit token). Turned ON by default whenever the
# session lives in an HttpOnly cookie — a cross-site request that sneaks the
# cookie along still can't guess the CSRF token because the browser won't let
# the other origin read `document.cookie` for our host. When auth is done via
# Authorization: Bearer (e.g., mobile apps, CI), CSRF is not applicable and
# the guard skips automatically.
CSRF_PROTECTION = os.getenv("CSRF_PROTECTION", "1") == "1"
CSRF_COOKIE_NAME = (os.getenv("CSRF_COOKIE_NAME", "sentinel_csrf").strip() or "sentinel_csrf")
CSRF_HEADER_NAME = (os.getenv("CSRF_HEADER_NAME", "X-CSRF-Token").strip() or "X-CSRF-Token")
# Match JWT session lifetime so the CSRF cookie doesn't expire while the user
# is still signed in (would force a silent re-login). Falls back to 1 day.
CSRF_TOKEN_TTL_S = int(os.getenv("CSRF_TOKEN_TTL_S", str(int(JWT_EXPIRE_S) if int(JWT_EXPIRE_S) > 0 else 86400)))
# SSE: ?token= leaks via logs; disable unless legacy clients need it.
SSE_ALLOW_QUERY_TOKEN = os.getenv("SSE_ALLOW_QUERY_TOKEN", "0") == "1"
# Public /health: set 1 only if load balancers need broker/smtp detail without auth.
HEALTH_PUBLIC_DETAIL = os.getenv("HEALTH_PUBLIC_DETAIL", "0") == "1"
BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME", "superadmin").strip()
BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD", "")
ENFORCE_PER_DEVICE_CREDS = os.getenv("ENFORCE_PER_DEVICE_CREDS", "0") == "1"
ENFORCE_DEVICE_CHALLENGE = os.getenv("ENFORCE_DEVICE_CHALLENGE", "0") == "1"
DEVICE_CHALLENGE_TTL_SECONDS = int(os.getenv("DEVICE_CHALLENGE_TTL_SECONDS", "300"))
DEVICE_ID_REGEX = os.getenv("DEVICE_ID_REGEX", r"^SN-[A-Z2-7]{16}$")
QR_CODE_REGEX = os.getenv("QR_CODE_REGEX", r"^CROC\|SN-[A-Z2-7]{16}\|\d{10}\|[A-Za-z0-9_-]{20,120}$")
QR_SIGN_SECRET = os.getenv("QR_SIGN_SECRET", "")
ALLOW_LEGACY_UNOWNED = os.getenv("ALLOW_LEGACY_UNOWNED", "1") == "1"
# When true (default), admins/users never see "unowned" devices in list/API scope unless they are
# the owning tenant — prevents cross-tenant leakage. Set TENANT_STRICT=0 for legacy lab behavior.
TENANT_STRICT = os.getenv("TENANT_STRICT", "1") == "1"


def _legacy_unowned_device_scope(principal: "Principal") -> bool:
    """Whether unowned device_state rows appear in non-superadmin device queries."""
    if principal.is_superadmin():
        return False
    return bool(ALLOW_LEGACY_UNOWNED) and not TENANT_STRICT
# Default: repo `croc_sentinel_systems/firmware` (alongside this package). Docker sets OTA_FIRMWARE_DIR=/opt/sentinel/firmware.
_API_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_OTA_FIRMWARE_DIR = os.path.normpath(os.path.join(_API_DIR, "..", "firmware"))
OTA_FIRMWARE_DIR = os.path.abspath(os.getenv("OTA_FIRMWARE_DIR", _DEFAULT_OTA_FIRMWARE_DIR))
OTA_PUBLIC_BASE_URL = os.getenv("OTA_PUBLIC_BASE_URL", "").rstrip("/")
# Required for API uploads (dashboard Upload & verify, POST /ota/firmware/upload, /ota/campaigns/from-upload).
# Use a long random secret. If unset, uploads are rejected.
OTA_UPLOAD_PASSWORD = (os.getenv("OTA_UPLOAD_PASSWORD") or os.getenv("FIRMWARE_UPLOAD_PASSWORD") or "").strip()
# How many .bin files to keep under OTA_FIRMWARE_DIR; oldest mtime is removed first when over limit.
OTA_MAX_FIRMWARE_BINS = max(1, int(os.getenv("OTA_MAX_FIRMWARE_BINS", "10")))
# Optional: base URL used only for server-side HEAD/GET checks (same /fw/ path as public).
# Use when devices resolve https://ota.example.com but the API container cannot (hairpin NAT),
# or before public TLS is ready: e.g. http://ota-nginx:9231 on the Docker network.
OTA_VERIFY_BASE_URL = os.getenv("OTA_VERIFY_BASE_URL", "").rstrip("/")
OTA_TOKEN = os.getenv("OTA_TOKEN", "")
MAX_OTA_UPLOAD_BYTES = int(os.getenv("MAX_OTA_UPLOAD_BYTES", str(16 * 1024 * 1024)))
DEFAULT_REMOTE_FANOUT_MS = int(os.getenv("DEFAULT_REMOTE_FANOUT_MS", "180000"))
DEFAULT_PANIC_FANOUT_MS = int(os.getenv("DEFAULT_PANIC_FANOUT_MS", "300000"))
ALARM_FANOUT_DURATION_MS = int(os.getenv("ALARM_FANOUT_DURATION_MS", str(DEFAULT_REMOTE_FANOUT_MS)))
ALARM_FANOUT_MAX_TARGETS = int(os.getenv("ALARM_FANOUT_MAX_TARGETS", "200"))
# Max wall-clock seconds the ingest thread will spend on a single fan-out round
# (workers are daemon threads; unfinished publishes still complete in paho).
FANOUT_WALL_CLOCK_MAX_S = max(0.5, min(10.0, float(os.getenv("FANOUT_WALL_CLOCK_MAX_S", "1.5"))))
# Cap parallel MQTT publishes per fan-out round. Paho's single writer means too
# many concurrent publishes only add thread overhead; 8–16 is plenty for QoS 1.
FANOUT_WORKER_POOL_SIZE = max(1, min(64, int(os.getenv("FANOUT_WORKER_POOL_SIZE", "12"))))
ALARM_FANOUT_SELF = os.getenv("ALARM_FANOUT_SELF", "0") == "1"
# QoS1 can redeliver duplicate event frames after reconnect; suppress repeated
# sibling fan-out for the same logical alarm event in this short window.
ALARM_EVENT_DEDUP_WINDOW_SEC = int(os.getenv("ALARM_EVENT_DEDUP_WINDOW_SEC", "8"))
AUTO_RECONCILE_ENABLED = os.getenv("AUTO_RECONCILE_ENABLED", "1") == "1"
AUTO_RECONCILE_COOLDOWN_SEC = int(os.getenv("AUTO_RECONCILE_COOLDOWN_SEC", "180"))
AUTO_RECONCILE_MAX_PER_TICK = max(1, int(os.getenv("AUTO_RECONCILE_MAX_PER_TICK", "2")))
PENDING_CLAIM_STALE_SECONDS = int(os.getenv("PENDING_CLAIM_STALE_SECONDS", str(24 * 3600)))
# Per-IP login lockout (replaces old sliding-window LOGIN_RATE_* on /auth/login only).
# Tier 0: FAILS wrong → lock LOCK0 s; tier 1: FAILS → lock LOCK1; tier 2+: FAILS → lock LOCK2. Success clears IP state.
LOGIN_LOCK_TIER0_FAILS = max(1, int(os.getenv("LOGIN_LOCK_TIER0_FAILS", "5")))
LOGIN_LOCK_TIER0_SECONDS = max(1, int(os.getenv("LOGIN_LOCK_TIER0_SECONDS", "60")))
LOGIN_LOCK_TIER1_FAILS = max(1, int(os.getenv("LOGIN_LOCK_TIER1_FAILS", "3")))
LOGIN_LOCK_TIER1_SECONDS = max(1, int(os.getenv("LOGIN_LOCK_TIER1_SECONDS", "180")))
LOGIN_LOCK_TIER2_FAILS = max(1, int(os.getenv("LOGIN_LOCK_TIER2_FAILS", "3")))
LOGIN_LOCK_TIER2_SECONDS = max(1, int(os.getenv("LOGIN_LOCK_TIER2_SECONDS", "600")))

# --- Signup / user activation ---
# If 1, a superadmin must approve each admin signup before they can log in. Default 0: self-serve.
ADMIN_SIGNUP_REQUIRE_APPROVAL = os.getenv("ADMIN_SIGNUP_REQUIRE_APPROVAL", "0") == "1"
# If 0, new public admin signups are refused entirely (for private deployments).
ALLOW_PUBLIC_ADMIN_SIGNUP = os.getenv("ALLOW_PUBLIC_ADMIN_SIGNUP", "1") == "1"
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "1") == "1"
REQUIRE_PHONE_VERIFICATION = os.getenv("REQUIRE_PHONE_VERIFICATION", "0") == "1"
SIGNUP_RATE_MAX = int(os.getenv("SIGNUP_RATE_MAX", "5"))
SIGNUP_RATE_WINDOW_SECONDS = int(os.getenv("SIGNUP_RATE_WINDOW_SECONDS", "3600"))
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "900"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))
# SMS: by default we run in email-only mode. If your VPS wires up a provider
# (Twilio / Aliyun / Tencent / Bandwidth), set SMS_PROVIDER to its name and
# implement the corresponding handler in notifier_sms.py. Absent that, phone
# verifications are a no-op and REQUIRE_PHONE_VERIFICATION must stay 0.
SMS_PROVIDER = os.getenv("SMS_PROVIDER", "none").strip().lower()

# --- Factory device registry (unguessable serial model) ---
# When ENFORCE_FACTORY_REGISTRATION=1 the API will refuse to record a
# pending_claims row for any device whose (serial, mac_nocolon) pair is not
# already listed in factory_devices. This is what makes serials truly
# unguessable in production.
ENFORCE_FACTORY_REGISTRATION = os.getenv("ENFORCE_FACTORY_REGISTRATION", "0") == "1"
FACTORY_API_TOKEN = os.getenv("FACTORY_API_TOKEN", "")
TELEGRAM_COMMAND_SECRET = os.getenv("TELEGRAM_COMMAND_SECRET", "").strip()
TELEGRAM_COMMAND_CHAT_IDS_RAW = os.getenv("TELEGRAM_COMMAND_CHAT_IDS", "").strip()
TELEGRAM_COMMAND_MAX_LOG = int(os.getenv("TELEGRAM_COMMAND_MAX_LOG", "20"))
TELEGRAM_COMMAND_MAX_DEVICES = int(os.getenv("TELEGRAM_COMMAND_MAX_DEVICES", "30"))
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
TELEGRAM_LINK_TOKEN_TTL_SECONDS = int(os.getenv("TELEGRAM_LINK_TOKEN_TTL_SECONDS", "900"))

# --- Presence probe (last-resort liveness check) ---
# Devices in HYBRID mode should publish a keepalive every ~60s (see firmware
# HEARTBEAT_IDLE_KEEPALIVE_MS). OFFLINE_THRESHOLD_SECONDS (90s) marks a device
# offline in the UI. If the device is still silent after IDLE_SECONDS the
# server publishes a single `ping` so we can distinguish "TCP quietly dropped"
# from "device genuinely dead". Keep this >> OFFLINE_THRESHOLD_SECONDS so we
# don't probe-spam devices that are merely momentarily late with a keepalive.
# Default 600s (10 min) = 10 missed keepalives, which is clearly abnormal.
PRESENCE_PROBE_IDLE_SECONDS = int(os.getenv("PRESENCE_PROBE_IDLE_SECONDS", "600"))
# How often the background worker scans for stale devices. Keep moderate so
# we don't hammer the DB; 120s is comfortably < IDLE_SECONDS/4.
PRESENCE_PROBE_SCAN_SECONDS = int(os.getenv("PRESENCE_PROBE_SCAN_SECONDS", "120"))
# Rate limit: don't probe the same device more than once per this window.
PRESENCE_PROBE_COOLDOWN_SECONDS = int(os.getenv("PRESENCE_PROBE_COOLDOWN_SECONDS", "900"))
# After N consecutive failed probes, the device is flagged offline and we back
# off to stop spamming the broker for obviously dead hardware.
PRESENCE_PROBE_MAX_CONSECUTIVE = int(os.getenv("PRESENCE_PROBE_MAX_CONSECUTIVE", "3"))
# A probe row stays outcome=sent until any device channel counts as an ack; if
# still sent after this many seconds, mark timeout (clears the outstanding row).
PRESENCE_PROBE_ACK_TIMEOUT_SEC = int(os.getenv("PRESENCE_PROBE_ACK_TIMEOUT_SEC", "480"))
# scheduled_commands still pending this long after execute_at_ts → mark failed.
SCHEDULED_CMD_STALE_PENDING_SEC = int(os.getenv("SCHEDULED_CMD_STALE_PENDING_SEC", "480"))

# --- OTA campaigns (superadmin -> admin approve -> per-device rollout) ---
# Per-device URL HEAD check timeout.
OTA_URL_VERIFY_TIMEOUT_SECONDS = float(os.getenv("OTA_URL_VERIFY_TIMEOUT_SECONDS", "10"))
# Max time we wait for a device to ack ota.result before marking it failed.
OTA_DEVICE_ACK_TIMEOUT_SECONDS = int(os.getenv("OTA_DEVICE_ACK_TIMEOUT_SECONDS", str(15 * 60)))
# If set, any device failure in a campaign auto-rolls-back the whole admin fleet.
OTA_AUTO_ROLLBACK_ON_FAILURE = os.getenv("OTA_AUTO_ROLLBACK_ON_FAILURE", "1") == "1"

# --- Event center (global log + SSE stream) ---
# In-memory ring buffer size. ~500 B × N ≈ RAM footprint. 2000 ≈ 1 MB.
EVENT_RING_SIZE = int(os.getenv("EVENT_RING_SIZE", "2000"))
# Per-SSE-subscriber queue. Slow client → oldest events dropped with warning.
EVENT_SUB_QUEUE_SIZE = int(os.getenv("EVENT_SUB_QUEUE_SIZE", "500"))
# SSE keepalive: comment + named `ping` event so proxies that strip `:`
# comments still see traffic. Keep well below your reverse-proxy read_timeout (often 60s).
# Default 9s works better than 12s with strict proxies / mobile networks.
EVENT_SSE_KEEPALIVE_SECONDS = max(3, int(os.getenv("EVENT_SSE_KEEPALIVE_SECONDS", "9")))
# Hint for browser EventSource automatic reconnect delay (milliseconds).
EVENT_SSE_RETRY_MS = int(os.getenv("EVENT_SSE_RETRY_MS", "4000"))
# Hard cap on concurrent SSE subscribers (cheap, but bound the damage).
EVENT_MAX_SUBSCRIBERS = int(os.getenv("EVENT_MAX_SUBSCRIBERS", "128"))
# Level-based retention days. Debug rows go first; critical stays for audits.
EVENT_RETAIN_DAYS_DEBUG = int(os.getenv("EVENT_RETAIN_DAYS_DEBUG", "3"))
EVENT_RETAIN_DAYS_INFO = int(os.getenv("EVENT_RETAIN_DAYS_INFO", "14"))
EVENT_RETAIN_DAYS_WARN = int(os.getenv("EVENT_RETAIN_DAYS_WARN", "30"))
EVENT_RETAIN_DAYS_ERROR = int(os.getenv("EVENT_RETAIN_DAYS_ERROR", "90"))
EVENT_RETAIN_DAYS_CRITICAL = int(os.getenv("EVENT_RETAIN_DAYS_CRITICAL", "365"))
# Absolute backstop: delete any event older than this regardless of level.
EVENT_RETAIN_DAYS_MAX = int(os.getenv("EVENT_RETAIN_DAYS_MAX", "400"))
# How often the retention worker runs.
EVENT_RETENTION_SCAN_SECONDS = int(os.getenv("EVENT_RETENTION_SCAN_SECONDS", "3600"))
# MQTT → bounded RAM queue → single ingest worker (DB + emit_event + fan-out threads).
# Callback must stay O(1): only decode + put_nowait; never parse business JSON there.
MQTT_INGEST_QUEUE_MAX = int(os.getenv("MQTT_INGEST_QUEUE_MAX", "1000"))

# --- Offline password recovery (RSA public on server, private key only in
#     password_recovery_offline/ on the operator's air-gapped machine) ---
PASSWORD_RECOVERY_PUBLIC_KEY_PATH = os.getenv("PASSWORD_RECOVERY_PUBLIC_KEY_PATH", "").strip()
PASSWORD_RECOVERY_PUBLIC_KEY_PEM = os.getenv("PASSWORD_RECOVERY_PUBLIC_KEY_PEM", "").strip()
# Fixed-size inner plaintext so every blob is the same length (anti user-enumeration).
PASSWORD_RECOVERY_PLAINTEXT_PAD = int(os.getenv("PASSWORD_RECOVERY_PLAINTEXT_PAD", "512"))
FORGOT_PASSWORD_TOKEN_TTL_SECONDS = int(os.getenv("FORGOT_PASSWORD_TOKEN_TTL_SECONDS", str(24 * 3600)))
FORGOT_PASSWORD_IP_WINDOW_SECONDS = int(os.getenv("FORGOT_PASSWORD_IP_WINDOW_SECONDS", "3600"))
FORGOT_PASSWORD_IP_MAX = int(os.getenv("FORGOT_PASSWORD_IP_MAX", "12"))
# Magic header on the binary blob before hex-encoding for the dashboard.
PASSWORD_RECOVERY_BLOB_MAGIC = b"CRPW"
PASSWORD_RECOVERY_BLOB_VERSION = 1
DASHBOARD_PATH = os.getenv("DASHBOARD_PATH", "/console").strip() or "/console"
if not DASHBOARD_PATH.startswith("/"):
    DASHBOARD_PATH = "/" + DASHBOARD_PATH
DASHBOARD_PATH = DASHBOARD_PATH.rstrip("/") or "/console"
# Guard: refuse to mount over known API prefixes.
_RESERVED_PREFIXES = ("/auth", "/devices", "/commands", "/alerts", "/admin",
                      "/provision", "/health", "/dashboard", "/logs", "/audit", "/ui")
if any(DASHBOARD_PATH == p or DASHBOARD_PATH.startswith(p + "/") for p in _RESERVED_PREFIXES):
    # Fallback silently to /console to avoid shadowing API routes.
    DASHBOARD_PATH = "/console"

TOPIC_HEARTBEAT = f"{TOPIC_ROOT}/+/heartbeat"
TOPIC_STATUS = f"{TOPIC_ROOT}/+/status"
TOPIC_EVENT = f"{TOPIC_ROOT}/+/event"
TOPIC_ACK = f"{TOPIC_ROOT}/+/ack"
TOPIC_BOOTSTRAP_REGISTER = f"{TOPIC_ROOT}/bootstrap/register"


db_lock = threading.Lock()
mqtt_client: Optional[mqtt.Client] = None
mqtt_connected = False
mqtt_ingest_queue: _stdqueue.Queue[Optional[dict[str, Any]]] = _stdqueue.Queue(maxsize=MQTT_INGEST_QUEUE_MAX)
mqtt_worker_stop = threading.Event()
mqtt_worker_thread: Optional[threading.Thread] = None
mqtt_ingest_dropped = 0
mqtt_last_connect_at = ""
mqtt_last_disconnect_at = ""
mqtt_last_disconnect_reason = ""
alarm_event_dedup_lock = threading.Lock()
alarm_event_dedup_seen: dict[str, float] = {}
auto_reconcile_lock = threading.Lock()
auto_reconcile_queue: collections.deque[tuple[str, str]] = collections.deque()
auto_reconcile_last_seen: dict[str, float] = {}
# Deferred bootstrap: ASGI binds immediately; heavy IO runs on api-bootstrap thread.
api_ready_event = threading.Event()
api_bootstrap_error: Optional[str] = None
_bootstrap_thread: Optional[threading.Thread] = None
scheduler_stop = threading.Event()
scheduler_thread: Optional[threading.Thread] = None
cache_lock = threading.Lock()
api_cache: dict[str, tuple[float, Any]] = {}

log_dir = os.path.dirname(LOG_FILE_PATH)
if log_dir:
    os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("croc-api")


def _parse_chat_ids(raw: str) -> set[str]:
    out: set[str] = set()
    for part in re.split(r"[\s,;]+", (raw or "").strip()):
        p = part.strip().strip('"').strip("'")
        if p:
            out.add(p)
    return out


TELEGRAM_COMMAND_CHAT_IDS = _parse_chat_ids(TELEGRAM_COMMAND_CHAT_IDS_RAW)


def contains_insecure_marker(value: str) -> bool:
    markers = ["CHANGE_ME", "YOUR_", "your.vps.domain", "bootstrap_user", "bootstrap_pass", "mqtt_pass", "mqtt_user"]
    return any(m in value for m in markers)


def is_hex_16(value: str) -> bool:
    if len(value) != 16:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


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
    if errors:
        msg = "Invalid production environment: " + "; ".join(errors)
        if STRICT_STARTUP_ENV_CHECK:
            raise RuntimeError(msg)
        logger.warning("%s (startup allowed because STRICT_STARTUP_ENV_CHECK=0)", msg)


def cache_get(key: str) -> Optional[Any]:
    now = time.time()
    with cache_lock:
        item = api_cache.get(key)
        if not item:
            return None
        exp, val = item
        if exp < now:
            api_cache.pop(key, None)
            return None
        return val


def cache_put(key: str, val: Any, ttl: float = CACHE_TTL_SECONDS) -> None:
    with cache_lock:
        api_cache[key] = (time.time() + ttl, val)


def cache_invalidate(prefix: str = "") -> None:
    with cache_lock:
        if not prefix:
            api_cache.clear()
            return
        keys = [k for k in api_cache if k.startswith(prefix)]
        for k in keys:
            api_cache.pop(k, None)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=max(1.0, SQLITE_CONNECT_TIMEOUT_S))
    conn.row_factory = sqlite3.Row
    # Per-connection pragmas. WAL + synchronous are set once in init_db_pragmas
    # because they're persistent; these here are per-connection tuning.
    try:
        cur = conn.cursor()
        cur.execute(f"PRAGMA busy_timeout = {int(SQLITE_BUSY_TIMEOUT_MS)}")
        cur.execute("PRAGMA cache_size = -32768")   # 32 MB page cache / conn
        cur.execute("PRAGMA temp_store = MEMORY")
        cur.execute("PRAGMA foreign_keys = ON")
    except Exception:
        pass
    return conn


def init_db_pragmas() -> None:
    """Persistent, one-shot PRAGMA setup. Called once from init_db() after
    all CREATE TABLE statements so we don't race with schema migration.
    Tuned for an 8 GB / 100 GB NVMe VPS: WAL mode is ~5x faster for the
    write-heavy event pipeline and multi-reader friendly; mmap avoids
    copying hot pages between kernel and user space.
    """
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute("PRAGMA synchronous = NORMAL")
            cur.execute("PRAGMA wal_autocheckpoint = 1000")
            cur.execute("PRAGMA mmap_size = 268435456")  # 256 MB
            conn.commit()
            conn.close()
    except Exception as exc:
        logger.warning("init_db_pragmas failed: %s", exc)


def ensure_column(conn: sqlite3.Connection, table: str, column: str, col_def: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


def init_db() -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                channel TEXT NOT NULL,
                device_id TEXT,
                payload_json TEXT NOT NULL,
                ts_device INTEGER,
                ts_received TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_state (
                device_id TEXT PRIMARY KEY,
                fw TEXT,
                chip_target TEXT,
                board_profile TEXT,
                net_type TEXT,
                zone TEXT,
                provisioned INTEGER,
                last_status_json TEXT,
                last_heartbeat_json TEXT,
                last_ack_json TEXT,
                last_event_json TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_zone_overrides (
                device_id TEXT PRIMARY KEY,
                zone TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_zone_overrides_zone ON device_zone_overrides(zone)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_claims (
                mac_nocolon TEXT PRIMARY KEY,
                mac TEXT,
                qr_code TEXT,
                fw TEXT,
                claim_nonce TEXT NOT NULL,
                proposed_device_id TEXT,
                payload_json TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS provisioned_credentials (
                device_id TEXT PRIMARY KEY,
                mac_nocolon TEXT NOT NULL,
                mqtt_username TEXT NOT NULL,
                mqtt_password TEXT NOT NULL,
                cmd_key TEXT NOT NULL,
                zone TEXT,
                qr_code TEXT,
                claimed_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scheduled_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                cmd TEXT NOT NULL,
                params_json TEXT NOT NULL,
                target_id TEXT NOT NULL,
                proto INTEGER NOT NULL,
                execute_at_ts INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                executed_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS dashboard_users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                allowed_zones_json TEXT NOT NULL DEFAULT '["*"]',
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_identities (
                device_id TEXT PRIMARY KEY,
                mac_nocolon TEXT,
                public_key_pem TEXT NOT NULL,
                attestation_json TEXT,
                registered_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS provision_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_nocolon TEXT NOT NULL,
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_ts INTEGER NOT NULL,
                verified_at TEXT,
                used INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS revoked_devices (
                device_id TEXT PRIMARY KEY,
                reason TEXT,
                revoked_by TEXT,
                revoked_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                detail_json TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS role_policies (
                username TEXT PRIMARY KEY,
                can_alert INTEGER NOT NULL DEFAULT 0,
                can_send_command INTEGER NOT NULL DEFAULT 0,
                can_claim_device INTEGER NOT NULL DEFAULT 0,
                can_manage_users INTEGER NOT NULL DEFAULT 0,
                can_backup_restore INTEGER NOT NULL DEFAULT 0,
                tg_view_logs INTEGER NOT NULL DEFAULT 0,
                tg_view_devices INTEGER NOT NULL DEFAULT 0,
                tg_siren_on INTEGER NOT NULL DEFAULT 0,
                tg_siren_off INTEGER NOT NULL DEFAULT 0,
                tg_test_single INTEGER NOT NULL DEFAULT 0,
                tg_test_bulk INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_chat_bindings (
                chat_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_tg_bindings_user ON telegram_chat_bindings(username)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_link_tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at_ts INTEGER NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_tg_link_tokens_user ON telegram_link_tokens(username)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_fcm_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token TEXT NOT NULL,
                platform TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                UNIQUE(username, token)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_user_fcm_tokens_username ON user_fcm_tokens(username)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_ownership (
                device_id TEXT PRIMARY KEY,
                owner_admin TEXT NOT NULL,
                assigned_by TEXT NOT NULL,
                assigned_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_acl (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                grantee_username TEXT NOT NULL,
                can_view INTEGER NOT NULL DEFAULT 1,
                can_operate INTEGER NOT NULL DEFAULT 0,
                granted_by TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                revoked_at TEXT,
                UNIQUE(device_id, grantee_username)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_device_acl_device ON device_acl(device_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_device_acl_user ON device_acl(grantee_username)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alarms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                owner_admin TEXT,
                zone TEXT,
                triggered_by TEXT NOT NULL,   -- remote_button | network | api
                ts_device INTEGER,
                nonce TEXT,
                sig TEXT,
                fanout_count INTEGER NOT NULL DEFAULT 0,
                email_sent INTEGER NOT NULL DEFAULT 0,
                email_detail TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_alarms_source ON alarms(source_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_alarms_owner ON alarms(owner_admin)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_alarms_created ON alarms(created_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS signal_triggers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                device_id TEXT NOT NULL,
                owner_admin TEXT,
                zone TEXT,
                actor_username TEXT NOT NULL,
                duration_ms INTEGER,
                target_count INTEGER NOT NULL DEFAULT 1,
                detail_json TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_signal_triggers_created ON signal_triggers(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_signal_triggers_owner ON signal_triggers(owner_admin)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_alert_recipients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_admin TEXT NOT NULL,
                email TEXT NOT NULL,
                label TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                UNIQUE(owner_admin, email)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS group_card_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_admin TEXT NOT NULL,
                group_key TEXT NOT NULL,
                trigger_mode TEXT NOT NULL DEFAULT 'continuous',
                trigger_duration_ms INTEGER NOT NULL DEFAULT 10000,
                delay_seconds INTEGER NOT NULL DEFAULT 0,
                reboot_self_check INTEGER NOT NULL DEFAULT 0,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner_admin, group_key)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_group_card_settings_owner ON group_card_settings(owner_admin)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_group_card_settings_group ON group_card_settings(group_key)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS trigger_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_admin TEXT NOT NULL,
                scope_group TEXT NOT NULL DEFAULT '',
                panic_local_siren INTEGER NOT NULL DEFAULT 1,
                remote_silent_link_enabled INTEGER NOT NULL DEFAULT 1,
                remote_loud_link_enabled INTEGER NOT NULL DEFAULT 1,
                remote_loud_duration_ms INTEGER NOT NULL DEFAULT 10000,
                fanout_exclude_self INTEGER NOT NULL DEFAULT 1,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner_admin, scope_group)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_trigger_policies_owner ON trigger_policies(owner_admin)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_trigger_policies_group ON trigger_policies(scope_group)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS provision_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL UNIQUE,
                owner_admin TEXT,
                device_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                message TEXT,
                request_json TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_provision_tasks_device ON provision_tasks(device_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_provision_tasks_owner ON provision_tasks(owner_admin)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_provision_tasks_updated ON provision_tasks(updated_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS login_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                ts_epoch INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_login_failures_ip_ts ON login_failures(ip, ts_epoch)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_login_failures_user_ts ON login_failures(username, ts_epoch)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS login_ip_state (
                ip TEXT PRIMARY KEY,
                fail_count INTEGER NOT NULL DEFAULT 0,
                phase INTEGER NOT NULL DEFAULT 0,
                lock_until INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                jti TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at_ts INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                request_ip TEXT,
                used_at TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_pwd_reset_user_exp ON password_reset_tokens(username, expires_at_ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_pwd_reset_exp ON password_reset_tokens(expires_at_ts)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS forgot_password_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                ts_epoch INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_forgot_ip_ts ON forgot_password_attempts(ip, ts_epoch)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                channel TEXT NOT NULL,          -- email | phone
                target TEXT NOT NULL,           -- the email address / phone number
                purpose TEXT NOT NULL,          -- signup | activate | reset
                code_hash TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                used INTEGER NOT NULL DEFAULT 0,
                expires_at_ts INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_verifications_lookup ON verifications(username, channel, purpose, used)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS signup_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                email TEXT NOT NULL,
                ts_epoch INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_signup_attempts_ip_ts ON signup_attempts(ip, ts_epoch)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_signup_attempts_email_ts ON signup_attempts(email, ts_epoch)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS factory_devices (
                serial TEXT PRIMARY KEY,
                mac_nocolon TEXT,
                qr_code TEXT,
                batch TEXT,
                status TEXT NOT NULL DEFAULT 'unclaimed',  -- unclaimed | claimed | blocked
                note TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_factory_devices_mac ON factory_devices(mac_nocolon)")
        # --- Presence probes (12h idle ping log) ---
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS presence_probes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                owner_admin TEXT,
                probe_ts TEXT NOT NULL,
                idle_seconds INTEGER,
                outcome TEXT NOT NULL DEFAULT 'sent',   -- sent | acked | timeout | skipped
                detail TEXT,
                updated_at TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_presence_probes_dev_ts ON presence_probes(device_id, probe_ts DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_presence_probes_admin_ts ON presence_probes(owner_admin, probe_ts DESC)")
        # --- OTA campaigns (superadmin dispatch -> admin accept -> device rollout) ---
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ota_campaigns (
                id TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,            -- superadmin username
                fw_version TEXT NOT NULL,
                url TEXT NOT NULL,
                sha256 TEXT,
                notes TEXT,
                target_admins_json TEXT NOT NULL,    -- JSON list, or ["*"] for all admins
                state TEXT NOT NULL DEFAULT 'dispatched',  -- dispatched | running | success | partial | failed | rolled_back | cancelled
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ota_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT NOT NULL,
                admin_username TEXT NOT NULL,
                action TEXT NOT NULL,        -- accepted | declined | rolled_back
                decided_at TEXT NOT NULL,
                detail TEXT,
                UNIQUE(campaign_id, admin_username)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ota_device_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT NOT NULL,
                admin_username TEXT NOT NULL,
                device_id TEXT NOT NULL,
                prev_fw TEXT,
                prev_url TEXT,
                target_fw TEXT NOT NULL,
                target_url TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',  -- pending | dispatched | success | failed | rolled_back
                error TEXT,
                started_at TEXT,
                finished_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(campaign_id, device_id)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_ota_runs_campaign ON ota_device_runs(campaign_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_ota_runs_admin ON ota_device_runs(admin_username)")

        # --- Global event center (unified log for SSE + historical query) ---
        # Every meaningful action in the system (auth, alarm fan-out, ota
        # campaign transitions, presence probes, claims, revokes, system
        # warnings) gets one row here. Rows are compact (< ~500 B on avg).
        # With 100 GB NVMe and default level-based retention, this handles
        # tens of millions of events comfortably.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ts_epoch_ms INTEGER NOT NULL,
                level TEXT NOT NULL,           -- debug | info | warn | error | critical
                category TEXT NOT NULL,        -- auth | alarm | ota | presence | provision | device | system | audit
                event_type TEXT NOT NULL,      -- eg. 'ota.campaign.accept'
                actor TEXT,                    -- user or 'system' or 'device:<id>'
                target TEXT,                   -- user or device id
                owner_admin TEXT,              -- tenant this event belongs to; NULL = global/system
                device_id TEXT,
                summary TEXT NOT NULL,         -- one-line human-readable
                detail_json TEXT,
                ref_table TEXT,                -- where the full payload lives (alarms|messages|audit_events|...)
                ref_id INTEGER
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_epoch_ms DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_events_owner_ts ON events(owner_admin, ts_epoch_ms DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_events_category_ts ON events(category, ts_epoch_ms DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_events_level_ts ON events(level, ts_epoch_ms DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_events_device_ts ON events(device_id, ts_epoch_ms DESC)")
        # Hot-path indexes added in the post-mortem debug pass — these queries all
        # showed up in slow-log sampling under load.
        #
        # scheduled_commands worker: `WHERE status='pending' AND execute_at_ts <= ?`
        cur.execute("CREATE INDEX IF NOT EXISTS ix_scheduled_cmds_status_ts ON scheduled_commands(status, execute_at_ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_scheduled_cmds_device ON scheduled_commands(device_id)")
        # device_state: fleet listings filter by zone + freshness, presence scan by provisioned.
        cur.execute("CREATE INDEX IF NOT EXISTS ix_device_state_zone ON device_state(zone)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_device_state_updated ON device_state(updated_at DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_device_state_provisioned ON device_state(provisioned)")
        # audit_events: superadmin history view orders by created_at and filters by actor/target.
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_events(created_at DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_actor_created ON audit_events(actor, created_at DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_target_created ON audit_events(target, created_at DESC)")
        # provisioned_credentials: MAC lookups during bootstrap/claim.
        cur.execute("CREATE INDEX IF NOT EXISTS ix_provcreds_mac ON provisioned_credentials(mac_nocolon)")
        ensure_column(conn, "device_state", "chip_target", "TEXT")
        ensure_column(conn, "device_state", "board_profile", "TEXT")
        ensure_column(conn, "device_state", "net_type", "TEXT")
        ensure_column(conn, "device_state", "provisioned", "INTEGER")
        ensure_column(conn, "device_state", "display_label", "TEXT")
        ensure_column(conn, "device_state", "notification_group", "TEXT")
        ensure_column(conn, "dashboard_users", "manager_admin", "TEXT")
        ensure_column(conn, "dashboard_users", "tenant", "TEXT")
        ensure_column(conn, "dashboard_users", "email", "TEXT")
        ensure_column(conn, "dashboard_users", "phone", "TEXT")
        ensure_column(conn, "dashboard_users", "email_verified_at", "TEXT")
        ensure_column(conn, "dashboard_users", "phone_verified_at", "TEXT")
        # status ∈ pending | active | disabled | awaiting_approval
        ensure_column(conn, "dashboard_users", "status", "TEXT")
        ensure_column(conn, "dashboard_users", "welcome_email_sent", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "dashboard_users", "alarm_push_style", "TEXT NOT NULL DEFAULT 'fullscreen'")
        ensure_column(conn, "dashboard_users", "avatar_url", "TEXT")
        ensure_column(conn, "role_policies", "tg_view_logs", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_view_devices", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_siren_on", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_siren_off", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_test_single", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_test_bulk", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "trigger_policies", "panic_link_enabled", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(conn, "trigger_policies", "panic_fanout_duration_ms", f"INTEGER NOT NULL DEFAULT {DEFAULT_PANIC_FANOUT_MS}")
        cur.execute("UPDATE dashboard_users SET status='active' WHERE status IS NULL OR status = ''")
        cur.execute("SELECT mac_nocolon, COUNT(*) AS c FROM provisioned_credentials GROUP BY mac_nocolon HAVING c > 1")
        dup = cur.fetchone()
        if not dup:
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_provisioned_mac_nocolon ON provisioned_credentials(mac_nocolon)")
        cur.execute("SELECT COUNT(*) AS c FROM dashboard_users")
        n_users = int(cur.fetchone()["c"])
        if n_users == 0 and BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD:
            cur.execute(
                """
                INSERT INTO dashboard_users (username, password_hash, role, allowed_zones_json, created_at)
                VALUES (?, ?, 'superadmin', ?, ?)
                """,
                (
                    BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME or "superadmin",
                    hash_password(BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD),
                    json.dumps(["*"], ensure_ascii=True),
                    utc_now_iso(),
                ),
            )
        cur.execute("SELECT username, role FROM dashboard_users")
        for ur in cur.fetchall():
            pol = default_policy_for_role(str(ur["role"]))
            cur.execute(
                """
                INSERT OR IGNORE INTO role_policies
                (username, can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(ur["username"]),
                    pol["can_alert"],
                    pol["can_send_command"],
                    pol["can_claim_device"],
                    pol["can_manage_users"],
                    pol["can_backup_restore"],
                    utc_now_iso(),
                ),
            )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    # After all schema is in place, enable WAL + mmap one-shot.
    init_db_pragmas()


def zone_sql_suffix(principal: Principal, column: str = "zone") -> tuple[str, list[Any]]:
    """Extra WHERE fragment for zone-scoped roles."""
    if principal.is_superadmin() or principal.has_all_zones():
        return "", []
    placeholders = ",".join(["?"] * len(principal.zones))
    frag = (
        f" AND ({column} IN ({placeholders}) OR IFNULL({column},'') IN ('all','')) "
    )
    return frag, list(principal.zones)


# ═══════════════════════════════════════════════
#  Event center — global real-time log bus
#
#  Two sinks for every emitted event:
#    (a) SQLite row in `events` (durable, indexed by time + owner_admin
#        + category + level + device_id)
#    (b) broadcast to every subscribed SSE queue
#
#  Memory budget: each subscriber holds up to EVENT_SUB_QUEUE_SIZE events,
#  the ring buffer holds EVENT_RING_SIZE, events are ≤ ~500 B JSON.
#  Default 2000 + 128 × 500 ≈ 33 MB worst-case — well within the 8 GB VPS.
# ═══════════════════════════════════════════════

_VALID_LEVELS = ("debug", "info", "warn", "error", "critical")
_VALID_CATEGORIES = ("auth", "alarm", "ota", "presence", "provision", "device", "system", "audit")


class _EventBus:
    def __init__(self, ring_size: int = 2000) -> None:
        self._lock = threading.Lock()
        self._ring: collections.deque[dict[str, Any]] = collections.deque(maxlen=ring_size)
        self._subs: dict[int, _EventSub] = {}
        self._next_sub_id = 1

    def subscribe(self, principal: "Principal", filters: dict[str, Any]) -> "_EventSub":
        with self._lock:
            if len(self._subs) >= EVENT_MAX_SUBSCRIBERS:
                raise HTTPException(status_code=503, detail="event subscribers at capacity")
            sid = self._next_sub_id
            self._next_sub_id += 1
            sub = _EventSub(sid, principal, filters)
            self._subs[sid] = sub
            return sub

    def unsubscribe(self, sub: "_EventSub") -> None:
        with self._lock:
            self._subs.pop(sub.id, None)

    def backlog(self, principal: "Principal", filters: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        """Return recent ring-buffer events the principal is allowed to see."""
        with self._lock:
            items = list(self._ring)
        out: list[dict[str, Any]] = []
        for ev in reversed(items):
            if not _event_visible(principal, ev):
                continue
            if not _event_matches_filters(ev, filters):
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return list(reversed(out))

    def _fanout_locked(self, ev: dict[str, Any]) -> None:
        for sub in list(self._subs.values()):
            if not _event_visible(sub.principal, ev):
                continue
            if not _event_matches_filters(ev, sub.filters):
                continue
            try:
                sub.q.put_nowait(ev)
            except _stdqueue.Full:
                try:
                    sub.q.get_nowait()
                    sub.q.put_nowait(ev)
                    sub.dropped += 1
                except Exception:
                    sub.dropped += 1

    def publish(self, ev: dict[str, Any]) -> None:
        with self._lock:
            self._ring.append(ev)
            self._fanout_locked(ev)

    def publish_from_peer(self, ev: dict[str, Any]) -> None:
        """Fan-in from another API worker (Redis). Same ring + local subscribers; no DB insert."""
        with self._lock:
            self._ring.append(ev)
            self._fanout_locked(ev)


class _EventSub:
    def __init__(self, sid: int, principal: "Principal", filters: dict[str, Any]) -> None:
        self.id = sid
        self.principal = principal
        self.filters = filters
        self.q: _stdqueue.Queue[dict[str, Any]] = _stdqueue.Queue(maxsize=EVENT_SUB_QUEUE_SIZE)
        self.dropped = 0
        self.created_at = time.time()


def _event_visible(principal: "Principal", ev: dict[str, Any]) -> bool:
    """Tenant isolation: superadmin sees everything; admin sees events where
    owner_admin == self OR actor == self; user sees only events in its
    manager_admin's tenant (and that involve it)."""
    if principal.role == "superadmin":
        return True
    owner = str(ev.get("owner_admin") or "")
    actor = str(ev.get("actor") or "")
    target = str(ev.get("target") or "")
    if _is_superadmin_username(actor):
        return False
    if principal.role == "admin":
        if owner == principal.username:
            return True
        if actor == principal.username or target == principal.username:
            return True
        # system-global events (owner_admin='') are hidden from admins by
        # default to avoid spamming every tenant with cross-cutting noise.
        return False
    # user
    if str(ev.get("category") or "") == "auth":
        return False
    my_admin = get_manager_admin(principal.username) or ""
    if my_admin and owner == my_admin and (actor == principal.username or target == principal.username or str(ev.get("level")) in ("warn", "error", "critical")):
        return True
    return False


def _event_matches_filters(ev: dict[str, Any], filters: dict[str, Any]) -> bool:
    lvl = filters.get("level")
    if lvl and ev.get("level") != lvl:
        # Allow "at least X" too if it was passed in {'min_level': ...}.
        pass
    min_lvl = filters.get("min_level")
    if min_lvl:
        try:
            if _VALID_LEVELS.index(str(ev.get("level") or "info")) < _VALID_LEVELS.index(str(min_lvl)):
                return False
        except ValueError:
            pass
    cat = filters.get("category")
    if cat and ev.get("category") != cat:
        return False
    device_id = filters.get("device_id")
    if device_id and ev.get("device_id") != device_id:
        return False
    q = filters.get("q")
    if q:
        q_lc = str(q).lower()
        blob = " ".join(str(ev.get(k) or "") for k in ("event_type", "actor", "target", "summary", "device_id")).lower()
        if q_lc not in blob:
            return False
    return True


event_bus = _EventBus(ring_size=EVENT_RING_SIZE)

# --- Multi-instance event bus (optional Redis Pub/Sub) ---
BUS_INSTANCE_ID = str(uuid.uuid4())
REDIS_URL = (os.getenv("REDIS_URL") or "").strip()
EVENT_BUS_REDIS_CHANNEL = (os.getenv("EVENT_BUS_REDIS_CHANNEL") or "sentinel:event_bus").strip() or "sentinel:event_bus"
EVENT_WS_ENABLED = os.getenv("EVENT_WS_ENABLED", "1") == "1"
SLOW_REQUEST_LOG_MS = int(os.getenv("SLOW_REQUEST_LOG_MS", "0"))
_redis_sync_client: Optional[Any] = None
_redis_bridge_stop = threading.Event()
_redis_listener_thread: Optional[threading.Thread] = None

_superadmin_cache: set[str] = set()
_superadmin_cache_ts = 0.0

# Cached list of Telegram chat_ids bound to a superadmin dashboard user. Used
# to fan EVERY event out to superadmin Telegram (filters on env chats still
# apply normally — see telegram_notify.maybe_enqueue). Cached briefly so we
# don't hit sqlite once per event on a hot emit_event path.
_superadmin_tg_chats_cache: list[str] = []
_superadmin_tg_chats_ts: float = 0.0
_superadmin_tg_chats_ttl_s: float = 20.0


def _is_superadmin_username(username: str) -> bool:
    u = str(username or "").strip()
    if not u:
        return False
    global _superadmin_cache_ts, _superadmin_cache
    now = time.time()
    if (now - _superadmin_cache_ts) > 20.0:
        if not db_lock.acquire(blocking=False):
            # Avoid lock inversion on hot paths; conservative fallback still hides default superadmin names.
            return u.lower().startswith("superadmin")
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT username FROM dashboard_users WHERE role = 'superadmin'")
            _superadmin_cache = {str(r["username"]) for r in cur.fetchall() if r["username"]}
            conn.close()
        finally:
            db_lock.release()
        _superadmin_cache_ts = now
    return u in _superadmin_cache


def _superadmin_telegram_chat_ids() -> list[str]:
    """All enabled Telegram chat_ids bound to a superadmin dashboard user.

    Returns an empty list on any DB/config error; callers treat it as
    "no extras" which is safe. Result is cached for ~20s to avoid hitting
    sqlite on every emit_event.
    """
    global _superadmin_tg_chats_cache, _superadmin_tg_chats_ts
    now = time.time()
    if _superadmin_tg_chats_cache and (now - _superadmin_tg_chats_ts) < _superadmin_tg_chats_ttl_s:
        return list(_superadmin_tg_chats_cache)
    # Best-effort non-blocking lock to avoid starving the emit_event hot path.
    if not db_lock.acquire(blocking=False):
        return list(_superadmin_tg_chats_cache)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT b.chat_id
            FROM telegram_chat_bindings b
            JOIN dashboard_users u ON u.username = b.username
            WHERE b.enabled = 1 AND u.role = 'superadmin'
            """
        )
        chats = [str(r["chat_id"]) for r in cur.fetchall() if r["chat_id"]]
        conn.close()
    except Exception as exc:
        logger.warning("superadmin telegram chat lookup failed: %s", exc)
        chats = list(_superadmin_tg_chats_cache)
    finally:
        db_lock.release()
    _superadmin_tg_chats_cache = chats
    _superadmin_tg_chats_ts = now
    return list(chats)


def _invalidate_superadmin_telegram_chats_cache() -> None:
    """Reset the cached superadmin->chat mapping so the next emit_event
    picks up a fresh bind/unbind/toggle immediately instead of after TTL."""
    global _superadmin_tg_chats_cache, _superadmin_tg_chats_ts
    _superadmin_tg_chats_cache = []
    _superadmin_tg_chats_ts = 0.0


def _insert_event_row(ev: dict[str, Any]) -> int:
    """Append to the events table. Returns row id (0 on failure)."""
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO events
                    (ts, ts_epoch_ms, level, category, event_type, actor, target, owner_admin, device_id, summary, detail_json, ref_table, ref_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev["ts"], ev["ts_epoch_ms"], ev["level"], ev["category"], ev["event_type"],
                    ev.get("actor"), ev.get("target"), ev.get("owner_admin"), ev.get("device_id"),
                    ev.get("summary") or "", json.dumps(ev.get("detail") or {}, ensure_ascii=True),
                    ev.get("ref_table"), ev.get("ref_id"),
                ),
            )
            rid = int(cur.lastrowid or 0)
            conn.commit()
            conn.close()
        return rid
    except Exception as exc:
        logger.warning("event insert failed: %s (%s)", exc, ev.get("event_type"))
        return 0


def emit_event(
    *,
    level: str,
    category: str,
    event_type: str,
    summary: str = "",
    actor: Optional[str] = None,
    target: Optional[str] = None,
    owner_admin: Optional[str] = None,
    device_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    ref_table: Optional[str] = None,
    ref_id: Optional[int] = None,
) -> None:
    """Write one event to the DB AND broadcast it to every subscribed SSE.

    This is the single shared entry-point used by audit / alarm / ota /
    presence / provision / device / system / auth paths.
    """
    if level not in _VALID_LEVELS:
        level = "info"
    if category not in _VALID_CATEGORIES:
        category = "system"
    now = datetime.now(timezone.utc)
    ts_iso = now.isoformat()
    ts_ms = int(now.timestamp() * 1000)
    sum_line = summary or event_type
    did = (device_id or "").strip()
    if did:
        pfx = _notify_subject_prefix(did)
        if pfx and not str(sum_line).startswith(pfx):
            sum_line = f"{pfx}{sum_line}"
    ev: dict[str, Any] = {
        "ts": ts_iso,
        "ts_epoch_ms": ts_ms,
        "ts_malaysia": iso_timestamp_to_malaysia(ts_iso),
        "level": level,
        "category": category,
        "event_type": event_type,
        "actor": actor or "",
        "target": target or "",
        "owner_admin": owner_admin or "",
        "device_id": device_id or "",
        "summary": sum_line,
        "detail": detail or {},
        "ref_table": ref_table,
        "ref_id": ref_id,
    }
    ev["_actor_superadmin"] = _is_superadmin_username(str(ev.get("actor") or ""))
    rid = _insert_event_row(ev)
    ev["id"] = rid
    event_bus.publish(ev)
    _redis_event_forward(ev)
    try:
        from telegram_notify import maybe_notify_telegram

        # Superadmin bindings get the firehose; env TELEGRAM_CHAT_IDS stays
        # filtered as before (signal hygiene for operators).
        try:
            sa_chats = _superadmin_telegram_chat_ids()
        except Exception:
            sa_chats = []
        maybe_notify_telegram(ev, extra_chat_ids=sa_chats)
    except Exception as exc:
        # Avoid silent failures when Telegram module/env is misconfigured (default log level INFO).
        logger.warning("telegram_notify skipped: %s", exc)
    try:
        _maybe_dispatch_fcm_for_ev(ev)
    except Exception as exc:
        logger.warning("fcm_notify skipped: %s", exc)


def _redis_event_forward(ev: dict[str, Any]) -> None:
    if _redis_sync_client is None:
        return
    try:
        out = dict(ev)
        out["_bus_origin"] = BUS_INSTANCE_ID
        _redis_sync_client.publish(EVENT_BUS_REDIS_CHANNEL, json.dumps(out, default=str))
    except Exception as exc:
        logger.warning("redis event forward failed: %s", exc)


def _redis_listener_main() -> None:
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("redis package not installed; pip install redis")
        return
    try:
        r2 = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r2.pubsub()
        pubsub.subscribe(EVENT_BUS_REDIS_CHANNEL)
        while not _redis_bridge_stop.is_set():
            msg = pubsub.get_message(timeout=1.0)
            if not msg or msg.get("type") != "message":
                continue
            raw = msg.get("data")
            if not raw or not isinstance(raw, str):
                continue
            try:
                data = json.loads(raw)
            except Exception:
                logger.warning("redis event bus bad json")
                continue
            origin = str(data.pop("_bus_origin", "") or "")
            if origin == BUS_INSTANCE_ID:
                continue
            try:
                event_bus.publish_from_peer(data)
            except Exception:
                logger.exception("event_bus.publish_from_peer failed")
        try:
            pubsub.close()
        except Exception:
            pass
        try:
            r2.close()
        except Exception:
            pass
    except Exception:
        logger.exception("redis event bus listener exited")


def _start_event_redis_bridge() -> None:
    global _redis_sync_client, _redis_listener_thread
    if not REDIS_URL:
        logger.info("REDIS_URL unset — event bus is single-process memory only")
        return
    try:
        import redis as redis_lib
    except ImportError:
        logger.error("REDIS_URL set but redis package missing; install redis or unset REDIS_URL")
        return
    try:
        _redis_sync_client = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_sync_client.ping()
    except Exception as exc:
        logger.error("redis connect failed (event bus): %s", exc)
        _redis_sync_client = None
        return
    _redis_bridge_stop.clear()
    _redis_listener_thread = threading.Thread(target=_redis_listener_main, name="redis-event-bus", daemon=True)
    _redis_listener_thread.start()
    logger.info(
        "event bus redis bridge ok channel=%s instance=%s",
        EVENT_BUS_REDIS_CHANNEL,
        BUS_INSTANCE_ID[:8],
    )


def _stop_event_redis_bridge() -> None:
    global _redis_sync_client, _redis_listener_thread
    _redis_bridge_stop.set()
    if _redis_listener_thread is not None:
        _redis_listener_thread.join(timeout=4.0)
        _redis_listener_thread = None
    if _redis_sync_client is not None:
        try:
            _redis_sync_client.close()
        except Exception:
            pass
        _redis_sync_client = None


def _alarm_severity_bucket(level: str) -> str:
    lv = (level or "").lower()
    if lv == "critical":
        return "HIGH"
    if lv in ("error", "warn"):
        return "MEDIUM"
    return "LOW"


def _sound_hint_from_severity(sev: str) -> str:
    if sev == "HIGH":
        return "siren"
    if sev == "MEDIUM":
        return "beep"
    return "tone"


def _trigger_method_from_ev(ev: dict[str, Any]) -> str:
    actor = str(ev.get("actor") or "")
    if actor.startswith("device:"):
        return "MQTT"
    if actor.startswith("telegram:"):
        return "Telegram"
    return "API"


def _maybe_dispatch_fcm_for_ev(ev: dict[str, Any]) -> None:
    """Tenant-owner FCM: ALARM lane for admin/user; SYSTEM (no siren) if owner row is superadmin."""
    if str(ev.get("category") or "") != "alarm":
        return
    owner = str(ev.get("owner_admin") or "").strip()
    if not owner:
        return
    device_id = str(ev.get("device_id") or "").strip()
    grp, label = ("", "")
    if device_id:
        grp, label = _device_notify_labels(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT role, IFNULL(alarm_push_style,'fullscreen') AS alarm_push_style, IFNULL(tenant,'') AS tenant "
            "FROM dashboard_users WHERE username = ?",
            (owner,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return
        role = str(row["role"] or "")
        alarm_push_style = str(row["alarm_push_style"] or "fullscreen").strip() or "fullscreen"
        system_name = str(row["tenant"] or "").strip() or owner
        cur.execute(
            "SELECT token, platform FROM user_fcm_tokens WHERE username = ? ORDER BY updated_at DESC",
            (owner,),
        )
        tok_rows = cur.fetchall()
        conn.close()
    if not tok_rows:
        return
    sev = _alarm_severity_bucket(str(ev.get("level") or "warn"))
    sound_hint = _sound_hint_from_severity(sev)
    detail = ev.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}
    triggered_by = str(
        detail.get("trigger_kind") or detail.get("client_kind") or ev.get("event_type") or "",
    ).strip()
    push_kind = "SYSTEM" if role == "superadmin" else "ALARM"
    if push_kind == "SYSTEM":
        sound_hint = "none"
        alarm_push_style = "heads_up"
    method = _trigger_method_from_ev(ev)
    lat = str(detail.get("lat") or detail.get("latitude") or "")
    lng = str(detail.get("lng") or detail.get("longitude") or "")
    loc = f"{lat},{lng}" if lat and lng else ""
    ui_mode = "heads_up" if (push_kind == "SYSTEM" or alarm_push_style == "heads_up") else "fullscreen"
    base: dict[str, str] = {
        "push_kind": push_kind,
        "severity": sev,
        "sound_hint": sound_hint,
        "alarm_ui_mode": ui_mode,
        "event_id": str(int(ev.get("id") or 0)),
        "event_type": str(ev.get("event_type") or ""),
        "ts": str(ev.get("ts_malaysia") or iso_timestamp_to_malaysia(str(ev.get("ts") or "")))[:500],
        "alarm_title": "ALARM",
        "device_id": device_id,
        "device_name": (label or device_id)[:200],
        "system_name": system_name[:200],
        "group": grp[:120],
        "triggered_by": (triggered_by or "unknown")[:120],
        "trigger_method": method[:32],
        "summary": str(ev.get("summary") or "")[:500],
        "location": loc[:120],
    }
    from fcm_notify import enqueue_alarm_payloads

    out: list[dict[str, str]] = []
    for tr in tok_rows:
        tok = str(tr["token"] or "").strip()
        if not tok:
            continue
        rowd = dict(base)
        rowd["token"] = tok
        rowd["platform"] = str(tr["platform"] or "")[:32]
        out.append(rowd)
    if out:
        enqueue_alarm_payloads(out)


# Actions that are *irreversible* or *security-sensitive* and deserve a warn-level
# event → Telegram/email notification even when the action itself succeeded.
# Matched as prefixes so e.g. "device.unclaim" and "device.unclaim_reset" both hit.
_HIGH_RISK_AUDIT_PREFIXES: tuple[str, ...] = (
    "device.unclaim",
    "device.factory_unregister",
    "device.factory_unlink",
    "device.revoke",
    "device.delete",
    "user.delete",
    "user.deactivate",
    "admin.close",
    "admin.hard_close",
    "admin.suspend",
    "admin.delete",
    "ota.rollback",
    "ota.force_rollback",
    "bootstrap.unblock",
    "security.key_rotate",
)


def _audit_action_is_high_risk(action: str) -> bool:
    a = (action or "").lower()
    return any(a.startswith(p) for p in _HIGH_RISK_AUDIT_PREFIXES)


def audit_event(actor: str, action: str, target: str = "", detail: Optional[dict[str, Any]] = None) -> None:
    """Legacy audit log helper — kept for compatibility but now ALSO mirrors
    the entry into the unified event center so the superadmin sees it live.
    """
    audit_id = 0
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_events (actor, action, target, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor,
                action,
                target,
                json.dumps(detail or {}, ensure_ascii=True),
                utc_now_iso(),
            ),
        )
        audit_id = int(cur.lastrowid or 0)
        conn.commit()
        conn.close()

    # Infer tenant / level / category from the action string.
    parts = str(action).split(".", 1)
    cat_hint = parts[0] if parts else "audit"
    category = cat_hint if cat_hint in _VALID_CATEGORIES else "audit"
    # Heuristic severity: *.fail / rollback / revoke / reject → warn; error → error.
    low = action.lower()
    if "fail" in low or "reject" in low or "revoke" in low or "rollback" in low or "block" in low:
        level = "warn"
    elif "error" in low or "crash" in low:
        level = "error"
    else:
        level = "info"
    # Escalate irreversible / security-sensitive actions to warn so Telegram /
    # email fan-out notifies the superadmin even on a clean success path.
    if level == "info" and _audit_action_is_high_risk(action):
        level = "warn"
    owner_admin = None
    device_id = None
    if isinstance(detail, dict):
        owner_admin = detail.get("owner_admin") or None
        device_id = detail.get("device_id") or None
    # "device:<id>" actor convention used elsewhere.
    if not device_id and str(actor).startswith("device:"):
        device_id = actor.split(":", 1)[1]
    emit_event(
        level=level,
        category=category,
        event_type=f"audit.{action}",
        summary=f"{actor} {action} {target}".strip(),
        actor=actor,
        target=target,
        owner_admin=owner_admin,
        device_id=device_id,
        detail=detail or {},
        ref_table="audit_events",
        ref_id=audit_id,
    )


def is_device_revoked(device_id: str) -> bool:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM revoked_devices WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    return row is not None


def ensure_not_revoked(device_id: str) -> None:
    if is_device_revoked(device_id):
        raise HTTPException(status_code=403, detail="device is revoked")


def verify_device_signature(public_key_pem: str, nonce: str, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        sig = base64.b64decode(signature_b64)
        msg = nonce.encode("utf-8")
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def verify_qr_signature(qr_code: str) -> bool:
    if not QR_SIGN_SECRET:
        return True
    parts = qr_code.split("|")
    if len(parts) != 4:
        return False
    prefix, device_id, ts_str, sig = parts
    if prefix != "CROC":
        return False
    if not ts_str.isdigit():
        return False
    raw = f"{device_id}|{ts_str}"
    expect = base64.urlsafe_b64encode(
        hmac.new(QR_SIGN_SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return hmac.compare_digest(expect, sig)


def get_manager_admin(username: str) -> str:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT manager_admin FROM dashboard_users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return ""
    return str(row["manager_admin"] or "")


def principal_for_username(username: str) -> Principal:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT username, role, allowed_zones_json, status
            FROM dashboard_users
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="telegram binding user not found")
    status = str(row["status"] or "active")
    if status not in ("active", ""):
        raise HTTPException(status_code=403, detail=f"user not active: {status}")
    role = str(row["role"] or "user")
    zones = zones_from_json(str(row["allowed_zones_json"] or "[]"))
    return Principal(username=str(row["username"]), role=role, zones=zones)


def default_policy_for_role(role: str) -> dict[str, int]:
    if role == "superadmin":
        return {
            "can_alert": 1,
            "can_send_command": 1,
            "can_claim_device": 1,
            "can_manage_users": 1,
            "can_backup_restore": 1,
            "tg_view_logs": 1,
            "tg_view_devices": 1,
            "tg_siren_on": 1,
            "tg_siren_off": 1,
            "tg_test_single": 1,
            "tg_test_bulk": 1,
        }
    if role == "admin":
        return {
            "can_alert": 1,
            "can_send_command": 1,
            "can_claim_device": 1,
            "can_manage_users": 1,
            "can_backup_restore": 0,
            "tg_view_logs": 1,
            "tg_view_devices": 1,
            "tg_siren_on": 1,
            "tg_siren_off": 1,
            "tg_test_single": 1,
            "tg_test_bulk": 1,
        }
    return {
        "can_alert": 0,
        "can_send_command": 0,
        "can_claim_device": 0,
        "can_manage_users": 0,
        "can_backup_restore": 0,
        "tg_view_logs": 0,
        "tg_view_devices": 0,
        "tg_siren_on": 0,
        "tg_siren_off": 0,
        "tg_test_single": 0,
        "tg_test_bulk": 0,
    }


def get_effective_policy(principal: Principal) -> dict[str, int]:
    base = default_policy_for_role(principal.role)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk
            FROM role_policies WHERE username = ?
            """,
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return base
    out = dict(base)
    for k in out.keys():
        out[k] = int(row[k]) if k in row.keys() else out[k]
    return out


def require_capability(principal: Principal, capability: str) -> None:
    if principal.role == "superadmin":
        return
    pol = get_effective_policy(principal)
    if int(pol.get(capability, 0)) != 1:
        raise HTTPException(status_code=403, detail=f"capability denied: {capability}")


def _device_access_flags(principal: Principal, device_id: str) -> tuple[bool, bool]:
    """Return (can_view, can_operate) with strict tenant ownership isolation."""
    if principal.role == "superadmin":
        return True, True
    manager = get_manager_admin(principal.username) if principal.role == "user" else ""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        own = cur.fetchone()
        conn.close()
    owner = str(own["owner_admin"]) if own and own["owner_admin"] is not None else ""
    if principal.role == "admin":
        owner_view = bool(owner) and owner == principal.username
        if not owner and _legacy_unowned_device_scope(principal):
            owner_view = True
        owner_operate = bool(owner) and owner == principal.username
        # Strict isolation mode: admin cannot view/operate cross-tenant shared devices.
        return owner_view, owner_operate
    owner_view = bool(owner) and bool(manager) and owner == manager
    if not owner and _legacy_unowned_device_scope(principal) and bool(manager):
        owner_view = True
    owner_operate = bool(owner) and bool(manager) and owner == manager
    # Tenant user follows manager tenant only; shared ACL does not cross tenant boundary.
    return owner_view, owner_operate


def _principal_tenant_owns_device(principal: Principal, owner_admin: Optional[str]) -> bool:
    """True if principal is the registered owning tenant — not an ACL grantee on someone else's device."""
    if principal.role == "superadmin":
        return True
    o = str(owner_admin or "").strip()
    if not o:
        return _legacy_unowned_device_scope(principal)
    if principal.role == "admin":
        return o == principal.username
    mgr = get_manager_admin(principal.username) or ""
    return bool(mgr) and o == mgr


def _redact_notification_group_for_principal(
    principal: Principal, owner_admin: Optional[str], payload: dict[str, Any]
) -> None:
    """Hide owner's notification_group in JSON for ACL grantees (device-only sharing)."""
    if _principal_tenant_owns_device(principal, owner_admin):
        return
    payload["notification_group"] = ""


def assert_device_view_access(principal: Principal, device_id: str) -> None:
    can_view, _ = _device_access_flags(principal, device_id)
    if not can_view:
        raise HTTPException(status_code=403, detail="device not in your scope")


def assert_device_siren_access(principal: Principal, device_id: str) -> None:
    """Remote siren ON/OFF: same visibility as dashboard device view + role ``can_alert`` (checked on route)."""
    assert_device_view_access(principal, device_id)


def assert_device_operate_access(principal: Principal, device_id: str) -> None:
    _, can_operate = _device_access_flags(principal, device_id)
    if not can_operate:
        raise HTTPException(status_code=403, detail="device operation denied")


def assert_device_owner(principal: Principal, device_id: str) -> None:
    # Backward-compatible alias used by existing routes.
    assert_device_operate_access(principal, device_id)


def assert_device_command_actor(
    principal: Principal, device_id: str, *, check_revoked: bool = True
) -> None:
    """Publish-style device commands: at least user, policy capability, operate ACL, optional revoke."""
    assert_min_role(principal, "user")
    require_capability(principal, "can_send_command")
    if check_revoked:
        ensure_not_revoked(device_id)
    assert_device_operate_access(principal, device_id)


def owner_sql_suffix(principal: Principal, alias: str = "d") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    col = f"{alias}.owner_admin"
    leg = _legacy_unowned_device_scope(principal)
    if principal.role == "admin":
        return f" AND ({col} = ? {'OR '+col+' IS NULL' if leg else ''}) ", [principal.username]
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    return f" AND ({col} = ? {'OR '+col+' IS NULL' if leg else ''}) ", [manager]


def owner_scope_clause_for_device_state(principal: Principal, device_alias: str = "device_state") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    if principal.role == "admin":
        if _legacy_unowned_device_scope(principal):
            return (
                f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
                f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
                [principal.username],
            )
        return (
            f" AND (EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) ",
            [principal.username],
        )
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    if _legacy_unowned_device_scope(principal):
        return (
            f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
            f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
            [manager],
        )
    return (
        f" AND (EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) ",
        [manager],
    )


def parse_topic(topic: str) -> tuple[Optional[str], Optional[str]]:
    parts = topic.split("/")
    if len(parts) != 3:
        return None, None
    if parts[0] != TOPIC_ROOT:
        return None, None
    return parts[1], parts[2]


def upsert_pending_claim(payload: dict[str, Any]) -> None:
    mac_nocolon = str(payload.get("mac_nocolon", "")).upper()
    claim_nonce = str(payload.get("claim_nonce", ""))
    if len(mac_nocolon) != 12 or len(claim_nonce) != 16:
        return
    # Production mode: the device must be listed in factory_devices. This is
    # the mechanism that makes the serial number "unguessable": an attacker
    # who types a random serial on the dashboard will 404 because there is no
    # matching factory row AND because the real devices are the only ones that
    # ever get into pending_claims via the bootstrap MQTT credential.
    serial = str(payload.get("serial", "")).strip().upper()
    if ENFORCE_FACTORY_REGISTRATION:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT serial, mac_nocolon, status FROM factory_devices "
                "WHERE mac_nocolon = ? OR serial = ? LIMIT 1",
                (mac_nocolon, serial),
            )
            fdev = cur.fetchone()
            conn.close()
        if not fdev:
            logger.warning(
                "pending_claims rejected: MAC %s serial %s not in factory_devices (ENFORCE_FACTORY_REGISTRATION=1)",
                mac_nocolon, serial or "-",
            )
            return
        if str(fdev["status"] or "unclaimed") == "blocked":
            logger.warning("pending_claims rejected: serial %s is blocked", serial or fdev["serial"])
            return

    mac = str(payload.get("mac", ""))
    qr_code = str(payload.get("qr_code", ""))
    fw = str(payload.get("fw", ""))
    proposed_device_id = str(payload.get("device_id", ""))
    now = utc_now_iso()

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pending_claims (
                mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, payload_json, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_nocolon) DO UPDATE SET
                mac = excluded.mac,
                qr_code = excluded.qr_code,
                fw = excluded.fw,
                claim_nonce = excluded.claim_nonce,
                proposed_device_id = excluded.proposed_device_id,
                payload_json = excluded.payload_json,
                last_seen_at = excluded.last_seen_at
            """,
            (
                mac_nocolon,
                mac,
                qr_code,
                fw,
                claim_nonce,
                proposed_device_id,
                json.dumps(payload, ensure_ascii=True),
                now,
            ),
        )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")


def upsert_device_state(device_id: str, channel: str, payload: dict[str, Any]) -> None:
    now = utc_now_iso()
    fw = str(payload.get("fw", ""))
    chip_target = str(payload.get("chip_target", ""))
    board_profile = str(payload.get("board_profile", ""))
    net_type = str(payload.get("net_type", ""))
    provisioned = payload.get("provisioned")
    if isinstance(provisioned, bool):
        provisioned_val = 1 if provisioned else 0
    else:
        provisioned_val = None
    zone = str(payload.get("zone", ""))
    payload_str = json.dumps(payload, ensure_ascii=True)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_zone_overrides WHERE device_id = ?", (device_id,))
        zov = cur.fetchone()
        if zov and zov["zone"] is not None:
            zone = str(zov["zone"])
        cur.execute("SELECT device_id FROM device_state WHERE device_id = ?", (device_id,))
        exists = cur.fetchone() is not None

        if not exists:
            cur.execute(
                """
                INSERT INTO device_state (
                    device_id, fw, chip_target, board_profile, net_type, zone, provisioned, last_status_json, last_heartbeat_json,
                    last_ack_json, last_event_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)
                """,
                (device_id, fw, chip_target, board_profile, net_type, zone, provisioned_val, now),
            )

        update_fields = ["updated_at = ?"]
        update_args: list[Any] = [now]

        if fw:
            update_fields.append("fw = ?")
            update_args.append(fw)
        if chip_target:
            update_fields.append("chip_target = ?")
            update_args.append(chip_target)
        if board_profile:
            update_fields.append("board_profile = ?")
            update_args.append(board_profile)
        if net_type:
            update_fields.append("net_type = ?")
            update_args.append(net_type)
        if zone:
            update_fields.append("zone = ?")
            update_args.append(zone)
        if provisioned_val is not None:
            update_fields.append("provisioned = ?")
            update_args.append(provisioned_val)

        if channel == "status":
            update_fields.append("last_status_json = ?")
            update_args.append(payload_str)
        elif channel == "heartbeat":
            update_fields.append("last_heartbeat_json = ?")
            update_args.append(payload_str)
        elif channel == "ack":
            update_fields.append("last_ack_json = ?")
            update_args.append(payload_str)
        elif channel == "event":
            update_fields.append("last_event_json = ?")
            update_args.append(payload_str)

        update_args.append(device_id)
        cur.execute(
            f"UPDATE device_state SET {', '.join(update_fields)} WHERE device_id = ?",
            tuple(update_args),
        )
        conn.commit()
        conn.close()


def _extract_zone_from_device_state_row(row: Any) -> str:
    """Best-effort fallback zone from latest stored MQTT payloads."""
    if not row:
        return "all"
    for k in ("last_status_json", "last_heartbeat_json", "last_ack_json", "last_event_json"):
        raw = row[k] if k in row.keys() else None
        if not raw:
            continue
        try:
            obj = json.loads(str(raw))
        except Exception:
            continue
        z = str(obj.get("zone") or "").strip()
        if z:
            return z
    return "all"


def insert_message(topic: str, channel: str, device_id: Optional[str], payload: dict[str, Any]) -> None:
    ts_device = payload.get("ts")
    if not isinstance(ts_device, int):
        ts_device = None

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO messages (topic, channel, device_id, payload_json, ts_device, ts_received)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                topic,
                channel,
                device_id,
                json.dumps(payload, ensure_ascii=True),
                ts_device,
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()


def on_connect(client: mqtt.Client, _userdata: Any, _flags: Any, rc: int, _properties: Any = None) -> None:
    global mqtt_connected, mqtt_last_connect_at, mqtt_last_disconnect_reason
    mqtt_connected = rc == 0
    if rc == 0:
        mqtt_last_connect_at = utc_now_iso()
        mqtt_last_disconnect_reason = ""
        logger.info("MQTT connected")
        client.subscribe(TOPIC_HEARTBEAT, qos=1)
        client.subscribe(TOPIC_STATUS, qos=1)
        client.subscribe(TOPIC_EVENT, qos=1)
        client.subscribe(TOPIC_ACK, qos=1)
        client.subscribe(TOPIC_BOOTSTRAP_REGISTER, qos=1)
    else:
        logger.error("MQTT connect failed rc=%s", rc)


def on_disconnect(_client: mqtt.Client, _userdata: Any, _disconnect_flags: Any, _reason_code: Any, _properties: Any = None) -> None:
    global mqtt_connected, mqtt_last_disconnect_at, mqtt_last_disconnect_reason
    mqtt_connected = False
    mqtt_last_disconnect_at = utc_now_iso()
    mqtt_last_disconnect_reason = str(_reason_code or "")
    logger.warning("MQTT disconnected reason=%s", mqtt_last_disconnect_reason)


def _sibling_group_norm(raw: str) -> str:
    """Normalize notification_group for sibling matching (case-fold + NFC + whitespace)."""
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        s = unicodedata.normalize("NFC", s)
    except Exception:
        pass
    s = " ".join(s.split())
    try:
        return s.casefold()
    except Exception:
        return s.lower()


def _alarm_event_is_duplicate(device_id: str, payload: dict[str, Any]) -> bool:
    """Best-effort dedup for repeated `alarm.trigger` payloads in a short window."""
    win = max(0, int(ALARM_EVENT_DEDUP_WINDOW_SEC))
    if win <= 0:
        return False
    nonce = str(payload.get("nonce") or "").strip()
    ts_raw = str(payload.get("ts") or "").strip()
    trig = str(payload.get("trigger_kind") or "").strip()
    zone = str(payload.get("source_zone") or "").strip()
    # Prefer nonce when present; fall back to ts+kind+zone signature.
    sig = nonce or f"ts={ts_raw}|kind={trig}|zone={zone}"
    key = f"{device_id}|{sig}"
    now = time.time()
    cutoff = now - win
    with alarm_event_dedup_lock:
        stale = [k for k, exp in alarm_event_dedup_seen.items() if exp < cutoff]
        for k in stale:
            alarm_event_dedup_seen.pop(k, None)
        last = alarm_event_dedup_seen.get(key)
        if last and (now - last) <= win:
            return True
        alarm_event_dedup_seen[key] = now
    return False


def _is_ack_key_mismatch(payload: dict[str, Any]) -> bool:
    """Detect device-side command auth mismatch from ACK payload."""
    if bool(payload.get("ok", True)):
        return False
    detail = str(payload.get("detail") or "").strip().lower()
    if not detail:
        return False
    return detail in ("bad key", "device cmd_key unset", "key not 16 hex", "missing key")


def _enqueue_auto_reconcile(device_id: str, reason: str) -> None:
    if not AUTO_RECONCILE_ENABLED:
        return
    did = str(device_id or "").strip().upper()
    if not did:
        return
    now = time.time()
    with auto_reconcile_lock:
        last = auto_reconcile_last_seen.get(did, 0.0)
        if (now - last) < max(1, AUTO_RECONCILE_COOLDOWN_SEC):
            return
        auto_reconcile_last_seen[did] = now
        auto_reconcile_queue.append((did, str(reason or "auto")))


def _run_auto_reconcile_once(device_id: str, reason: str) -> bool:
    """Re-dispatch bootstrap assign with a fresh cmd_key for mismatched devices."""
    if not AUTO_RECONCILE_ENABLED:
        return False
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT pc.device_id, pc.mac_nocolon, IFNULL(pc.zone,'all') AS zone, IFNULL(pc.qr_code,'') AS qr_code
            FROM provisioned_credentials pc
            WHERE UPPER(pc.device_id)=UPPER(?)
            LIMIT 1
            """,
            (device_id,),
        )
        prov = cur.fetchone()
        if not prov:
            conn.close()
            return False
        did = str(prov["device_id"])
        mac = str(prov["mac_nocolon"] or "").upper()
        zone = str(prov["zone"] or "all").strip() or "all"
        qr = str(prov["qr_code"] or "")
        cur.execute(
            """
            SELECT claim_nonce, IFNULL(proposed_device_id,'') AS proposed_device_id
            FROM pending_claims
            WHERE mac_nocolon = ?
            LIMIT 1
            """,
            (mac,),
        )
        pending = cur.fetchone()
        if not pending:
            conn.close()
            emit_event(
                level="warn",
                category="provision",
                event_type="provision.auto_reconcile.skipped",
                summary=f"auto-reconcile skipped for {did} (no pending_claim)",
                actor="system",
                target=did,
                device_id=did,
                detail={"reason": reason, "mac_nocolon": mac},
            )
            return False
        claim_nonce = str(pending["claim_nonce"] or "").strip()
        if len(claim_nonce) != 16:
            conn.close()
            return False
        mqtt_u, mqtt_p, cmd_key = generate_device_credentials(did)
        cur.execute(
            """
            UPDATE provisioned_credentials
            SET mqtt_username=?, mqtt_password=?, cmd_key=?, zone=?, qr_code=?, claimed_at=?
            WHERE device_id=?
            """,
            (mqtt_u, mqtt_p, cmd_key, zone, qr, utc_now_iso(), did),
        )
        # Auto-rebind: keep pending proposed ID aligned to active provisioned device_id.
        cur.execute(
            "UPDATE pending_claims SET proposed_device_id = ? WHERE mac_nocolon = ?",
            (did, mac),
        )
        conn.commit()
        conn.close()
    publish_bootstrap_claim(
        mac_nocolon=mac,
        claim_nonce=claim_nonce,
        device_id=did,
        zone=zone,
        qr_code=qr if qr else f"CROC-{mac}",
        mqtt_username=mqtt_u,
        mqtt_password=mqtt_p,
        cmd_key=cmd_key,
    )
    audit_event("system", "provision.auto_reconcile", did, {"reason": reason, "mac_nocolon": mac})
    emit_event(
        level="warn",
        category="provision",
        event_type="provision.auto_reconcile.dispatched",
        summary=f"auto-reconcile assign dispatched for {did}",
        actor="system",
        target=did,
        device_id=did,
        detail={"reason": reason, "mac_nocolon": mac},
    )
    return True


def _auto_reconcile_tick() -> None:
    if not AUTO_RECONCILE_ENABLED:
        return
    batch: list[tuple[str, str]] = []
    with auto_reconcile_lock:
        for _ in range(min(AUTO_RECONCILE_MAX_PER_TICK, len(auto_reconcile_queue))):
            batch.append(auto_reconcile_queue.popleft())
    for did, why in batch:
        try:
            _run_auto_reconcile_once(did, why)
        except Exception as exc:
            logger.warning("auto_reconcile failed for %s: %s", did, exc)


def _prune_stale_pending_claims() -> None:
    """Remove old pending_claim rows and keep proposed_device_id aligned by MAC."""
    if PENDING_CLAIM_STALE_SECONDS <= 0:
        return
    cutoff = datetime.fromtimestamp(time.time() - PENDING_CLAIM_STALE_SECONDS, tz=timezone.utc).isoformat()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        # Rebind pending proposed_device_id to known provisioned device_id by MAC.
        cur.execute(
            """
            UPDATE pending_claims
            SET proposed_device_id = (
                SELECT pc.device_id FROM provisioned_credentials pc
                WHERE pc.mac_nocolon = pending_claims.mac_nocolon LIMIT 1
            )
            WHERE EXISTS (
                SELECT 1 FROM provisioned_credentials pc
                WHERE pc.mac_nocolon = pending_claims.mac_nocolon
            )
            """
        )
        # Clear stale rows that no longer refreshed by bootstrap.register.
        cur.execute("DELETE FROM pending_claims WHERE last_seen_at < ?", (cutoff,))
        deleted = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    if deleted:
        logger.info("pending_claims: pruned %d stale row(s)", deleted)


def _lookup_owner_admin(device_id: str) -> Optional[str]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    if row and row["owner_admin"]:
        return str(row["owner_admin"])
    return None


def _tenant_siblings(
    owner_admin: Optional[str],
    source_id: str,
    *,
    source_zone: str = "",
    source_group: str = "",
    include_source: bool = False,
) -> tuple[list[tuple[str, str]], int]:
    """Devices that receive group fan-out commands ("siblings") for this source_id.

    Selection: same ``owner_admin``, not revoked, optional matching ``source_zone``
    (unless zone is ``all``/``*``), and **normalized match** on ``notification_group``
    (NFC, collapse whitespace, case-fold) so minor string drift does not break linkage.

    Non-siblings (other tenants, empty group, revoked) are never targeted.

    ``include_source``: when False (default), the originating ``source_id`` is omitted.

    If the source group's normalized key is empty, there are **no** siblings.

    Returns ``(targets, eligible_total)``: ``targets`` is capped at
    ``ALARM_FANOUT_MAX_TARGETS``, sorted by ``device_id`` for stable ordering;
    ``eligible_total`` is how many devices matched before the cap.
    """
    zone_filter = source_zone.strip()
    norm_source = _sibling_group_norm(source_group)
    if not norm_source:
        return [], 0
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if owner_admin:
            sql = """
                SELECT d.device_id, d.zone, IFNULL(d.notification_group,'') AS notification_group
                FROM device_state d
                JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.owner_admin = ? AND r.device_id IS NULL
                  AND TRIM(IFNULL(d.notification_group,'')) != ''
            """
            args: list[Any] = [owner_admin]
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            cur.execute(sql, args)
        else:
            sql = """
                SELECT d.device_id, d.zone, IFNULL(d.notification_group,'') AS notification_group
                FROM device_state d
                LEFT JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.device_id IS NULL AND r.device_id IS NULL
                  AND TRIM(IFNULL(d.notification_group,'')) != ''
            """
            args: list[Any] = []
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            cur.execute(sql, args)
        rows = cur.fetchall()
        conn.close()
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for r in rows:
        if _sibling_group_norm(str(r["notification_group"] or "")) != norm_source:
            continue
        did = str(r["device_id"])
        if did == source_id and not include_source:
            continue
        if did in seen:
            continue
        seen.add(did)
        candidates.append((did, str(r["zone"] or "")))
    candidates.sort(key=lambda t: t[0])
    eligible_total = len(candidates)
    out = candidates[:ALARM_FANOUT_MAX_TARGETS]
    return out, eligible_total


def _recipients_for_admin(owner_admin: Optional[str]) -> list[str]:
    if not owner_admin:
        return []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT email FROM admin_alert_recipients WHERE owner_admin = ? AND enabled = 1",
            (owner_admin,),
        )
        rows = cur.fetchall()
        conn.close()
    return [str(r["email"]) for r in rows if r["email"]]


def _insert_alarm(source_id: str, owner_admin: Optional[str], zone: str,
                  triggered_by: str, payload: dict[str, Any]) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alarms
                (source_id, owner_admin, zone, triggered_by, ts_device, nonce, sig,
                 fanout_count, email_sent, email_detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?)
            """,
            (
                source_id,
                owner_admin,
                zone,
                triggered_by,
                int(payload.get("ts") or 0) or None,
                str(payload.get("nonce") or "") or None,
                str(payload.get("sig") or "") or None,
                utc_now_iso(),
            ),
        )
        alarm_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    return alarm_id


def _update_alarm(alarm_id: int, fanout_count: int, email_sent: bool, email_detail: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE alarms SET fanout_count = ?, email_sent = ?, email_detail = ? WHERE id = ?
            """,
            (fanout_count, 1 if email_sent else 0, email_detail[:400], alarm_id),
        )
        conn.commit()
        conn.close()


def _log_signal_trigger(
    kind: str,
    device_id: str,
    zone: str,
    actor_username: str,
    owner_admin: Optional[str],
    duration_ms: Optional[int] = None,
    target_count: int = 1,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO signal_triggers (
                created_at, kind, device_id, owner_admin, zone, actor_username,
                duration_ms, target_count, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                kind,
                device_id,
                owner_admin,
                zone,
                actor_username,
                duration_ms,
                target_count,
                json.dumps(detail or {}, ensure_ascii=True),
            ),
        )
        conn.commit()
        conn.close()


def _device_notify_labels(device_id: str) -> tuple[str, str]:
    """Returns (notification_group, display_label) from device_state; may be empty."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(notification_group,''), IFNULL(display_label,'') "
            "FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return "", ""
    return str(row[0] or "").strip(), str(row[1] or "").strip()


def _trigger_policy_defaults() -> dict[str, Any]:
    return {
        "panic_local_siren": True,
        # MQTT fan-out of panic_button to same-group siblings (independent of remote loud link).
        "panic_link_enabled": True,
        "panic_fanout_duration_ms": int(DEFAULT_PANIC_FANOUT_MS),
        "remote_silent_link_enabled": True,
        "remote_loud_link_enabled": True,
        "remote_loud_duration_ms": int(ALARM_FANOUT_DURATION_MS),
        "fanout_exclude_self": True,
    }


def _trigger_policy_for(owner_admin: Optional[str], scope_group: str) -> dict[str, Any]:
    base = _trigger_policy_defaults()
    if not owner_admin:
        return base
    group_key = scope_group.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT panic_local_siren, remote_silent_link_enabled, remote_loud_link_enabled,
                   remote_loud_duration_ms, fanout_exclude_self,
                   panic_link_enabled, panic_fanout_duration_ms
            FROM trigger_policies
            WHERE owner_admin = ? AND scope_group = ?
            """,
            (owner_admin, group_key),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return base
    base["panic_local_siren"] = bool(row["panic_local_siren"])
    base["remote_silent_link_enabled"] = bool(row["remote_silent_link_enabled"])
    base["remote_loud_link_enabled"] = bool(row["remote_loud_link_enabled"])
    base["remote_loud_duration_ms"] = int(row["remote_loud_duration_ms"] or ALARM_FANOUT_DURATION_MS)
    base["fanout_exclude_self"] = bool(row["fanout_exclude_self"])
    base["panic_link_enabled"] = bool(row["panic_link_enabled"])
    base["panic_fanout_duration_ms"] = int(row["panic_fanout_duration_ms"] or DEFAULT_PANIC_FANOUT_MS)
    return base


def _notify_subject_prefix(device_id: str) -> str:
    """Prefix for emails / Telegram: '[Group] DisplayName · ' or fallback to device_id."""
    grp, name = _device_notify_labels(device_id)
    parts: list[str] = []
    if grp:
        parts.append(f"[{grp}]")
    if name:
        parts.append(name)
    if parts:
        return " ".join(parts) + " · "
    return f"{device_id} · "


def _remote_siren_notify_email(
    *,
    action: str,
    device_id: str,
    zone: str,
    actor: str,
    owner_admin: Optional[str],
    duration_ms: Optional[int],
) -> None:
    recipients = _recipients_for_admin(owner_admin) if owner_admin else []
    grp, disp = _device_notify_labels(device_id)
    if not recipients or not notifier.enabled():
        return
    subject, text, html = render_remote_siren_email(
        action=action,
        device_id=device_id,
        display_label=disp,
        notification_group=grp,
        zone=zone,
        actor=actor,
        duration_ms=duration_ms,
    )
    notifier.enqueue(recipients, subject, text, html)


# ═══════════════════════════════════════════════
#  Presence probes (12h idle → server-initiated ping)
# ═══════════════════════════════════════════════

def _insert_presence_probe(device_id: str, owner_admin: Optional[str], idle_seconds: int, outcome: str, detail: str) -> int:
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO presence_probes (device_id, owner_admin, probe_ts, idle_seconds, outcome, detail, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (device_id, owner_admin, now_iso, idle_seconds, outcome, detail, now_iso),
        )
        pid = int(cur.lastrowid or 0)
        conn.commit()
        conn.close()
    return pid


def _mark_presence_probe_acked(device_id: str) -> None:
    """Flip the most recent 'sent' probe for this device to 'acked'."""
    flipped_id = 0
    owner = None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, owner_admin FROM presence_probes
            WHERE device_id = ? AND outcome = 'sent'
            ORDER BY id DESC LIMIT 1
            """,
            (device_id,),
        )
        row = cur.fetchone()
        if row:
            flipped_id = int(row["id"])
            owner = str(row["owner_admin"] or "") or None
            cur.execute(
                "UPDATE presence_probes SET outcome='acked', updated_at=? WHERE id=?",
                (utc_now_iso(), flipped_id),
            )
            conn.commit()
        conn.close()
    if flipped_id:
        emit_event(
            level="info",
            category="presence",
            event_type="presence.probe.acked",
            summary=f"{device_id} came back",
            actor=f"device:{device_id}",
            owner_admin=owner,
            device_id=device_id,
            detail={"probe_id": flipped_id},
        )


def _find_stale_devices(idle_seconds: int, cooldown_seconds: int, limit: int = 100) -> list[tuple[str, Optional[str], int]]:
    """Return [(device_id, owner_admin, idle_seconds_actual), ...] for devices
    whose last message is older than idle_seconds, excluding devices we already
    probed within cooldown_seconds.
    """
    now_ts = int(time.time())
    idle_cutoff_iso = datetime.fromtimestamp(now_ts - idle_seconds, tz=timezone.utc).isoformat()
    cooldown_cutoff_iso = datetime.fromtimestamp(now_ts - cooldown_seconds, tz=timezone.utc).isoformat()

    results: list[tuple[str, Optional[str], int]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.device_id, d.updated_at,
                   (SELECT o.owner_admin FROM device_ownership o WHERE o.device_id = d.device_id) AS owner_admin,
                   (SELECT MAX(p.probe_ts) FROM presence_probes p WHERE p.device_id = d.device_id) AS last_probe_ts
            FROM device_state d
            WHERE d.updated_at IS NOT NULL AND d.updated_at < ?
            ORDER BY d.updated_at ASC
            LIMIT ?
            """,
            (idle_cutoff_iso, limit),
        )
        rows = cur.fetchall()
        conn.close()
    for r in rows:
        last_probe = str(r["last_probe_ts"] or "")
        if last_probe and last_probe > cooldown_cutoff_iso:
            continue
        updated = _parse_iso(str(r["updated_at"] or ""))
        idle_actual = int(time.time() - (updated.timestamp() if updated else 0))
        results.append((str(r["device_id"]), (str(r["owner_admin"]) if r["owner_admin"] else None), idle_actual))
    return results


def _send_presence_probe(device_id: str, owner_admin: Optional[str], idle_seconds: int) -> None:
    """Publish a `ping` command and log the probe."""
    try:
        publish_command(
            topic=f"{TOPIC_ROOT}/{device_id}/cmd",
            cmd="ping",
            params={},
            target_id=device_id,
            proto=CMD_PROTO,
            cmd_key=get_cmd_key_for_device(device_id),
        )
        _insert_presence_probe(device_id, owner_admin, idle_seconds, "sent", f"idle>{PRESENCE_PROBE_IDLE_SECONDS}s")
        emit_event(
            level="warn",
            category="presence",
            event_type="presence.probe.sent",
            summary=f"{device_id} silent {idle_seconds}s → ping",
            actor="system",
            target=device_id,
            owner_admin=owner_admin,
            device_id=device_id,
            detail={"idle_seconds": idle_seconds},
        )
    except Exception as exc:
        logger.warning("presence probe publish failed dev=%s err=%s", device_id, exc)
        _insert_presence_probe(device_id, owner_admin, idle_seconds, "skipped", f"publish_err:{exc}")


def _events_retention_tick() -> None:
    """Delete old rows from the `events` table according to the level-based
    retention windows. Runs every EVENT_RETENTION_SCAN_SECONDS."""
    retention_map = {
        "debug": EVENT_RETAIN_DAYS_DEBUG,
        "info": EVENT_RETAIN_DAYS_INFO,
        "warn": EVENT_RETAIN_DAYS_WARN,
        "error": EVENT_RETAIN_DAYS_ERROR,
        "critical": EVENT_RETAIN_DAYS_CRITICAL,
    }
    now_ms = int(time.time() * 1000)
    try:
        total_deleted = 0
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            for level, days in retention_map.items():
                if days <= 0:
                    continue
                cutoff = now_ms - (days * 86400 * 1000)
                cur.execute("DELETE FROM events WHERE level = ? AND ts_epoch_ms < ?", (level, cutoff))
                total_deleted += cur.rowcount or 0
            if EVENT_RETAIN_DAYS_MAX > 0:
                hard_cut = now_ms - (EVENT_RETAIN_DAYS_MAX * 86400 * 1000)
                cur.execute("DELETE FROM events WHERE ts_epoch_ms < ?", (hard_cut,))
                total_deleted += cur.rowcount or 0
            conn.commit()
            conn.close()
        if total_deleted:
            logger.info("events retention: pruned %d rows", total_deleted)
    except Exception as exc:
        logger.warning("events retention failed: %s", exc)


def _presence_probe_tick() -> None:
    """One pass of the stale-device scanner. Called from scheduler_loop."""
    try:
        stale = _find_stale_devices(PRESENCE_PROBE_IDLE_SECONDS, PRESENCE_PROBE_COOLDOWN_SECONDS, limit=200)
    except Exception as exc:
        logger.warning("presence probe scan failed: %s", exc)
        return
    for device_id, owner_admin, idle_seconds in stale:
        _send_presence_probe(device_id, owner_admin, idle_seconds)


def _expire_presence_probes_waiting_ack() -> None:
    """Mark long-running ``sent`` probes as ``timeout`` so they do not appear stuck."""
    if PRESENCE_PROBE_ACK_TIMEOUT_SEC <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=PRESENCE_PROBE_ACK_TIMEOUT_SEC)
    cutoff_iso = cutoff.isoformat()
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE presence_probes
            SET outcome='timeout', updated_at=?, detail=COALESCE(detail, '') || ' | ack_timeout'
            WHERE outcome='sent' AND probe_ts < ?
            """,
            (now_iso, cutoff_iso),
        )
        n = cur.rowcount or 0
        conn.commit()
        conn.close()
    if n:
        logger.info("presence_probes: marked %d sent row(s) as timeout (>%ss)", n, PRESENCE_PROBE_ACK_TIMEOUT_SEC)


def _fail_stale_scheduled_commands(now_ts: int) -> None:
    """Pending jobs whose execute_at is far in the past should not hang forever."""
    if SCHEDULED_CMD_STALE_PENDING_SEC <= 0:
        return
    boundary = int(now_ts) - SCHEDULED_CMD_STALE_PENDING_SEC
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE scheduled_commands
            SET status='failed', executed_at=?
            WHERE status='pending' AND execute_at_ts < ?
            """,
            (now_iso, boundary),
        )
        n = cur.rowcount or 0
        conn.commit()
        conn.close()
    if n:
        logger.warning(
            "scheduled_commands: marked %d stale pending row(s) failed (execute_at >%ss ago)",
            n,
            SCHEDULED_CMD_STALE_PENDING_SEC,
        )


# ═══════════════════════════════════════════════
#  OTA campaigns (superadmin -> admin accept -> per-device rollout)
# ═══════════════════════════════════════════════

def _append_ota_token_to_url(url: str) -> str:
    """Append ?token=OTA_TOKEN when set — nginx OTA template requires it (SECURITY.md)."""
    tok = (OTA_TOKEN or "").strip()
    if not tok:
        return url
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    if q.get("token"):
        return url
    q["token"] = tok
    new_query = urlencode(q)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _effective_ota_verify_base() -> str:
    """Prefer OTA_VERIFY_BASE_URL so the API can reach ota-nginx inside Docker."""
    return (OTA_VERIFY_BASE_URL or OTA_PUBLIC_BASE_URL).rstrip("/")


def _service_check_url_for_firmware(fname: str) -> str:
    """URL the API uses for HTTP checks (may be internal Docker base)."""
    base = _effective_ota_verify_base()
    return _append_ota_token_to_url(f"{base}/fw/{fname}")


def _public_firmware_url(fname: str) -> str:
    """Canonical URL stored in campaigns / shown to devices (no token in DB; ESP adds token)."""
    return f"{OTA_PUBLIC_BASE_URL}/fw/{fname}"


def _http_probe_ota(url: str) -> tuple[bool, str]:
    """HEAD first (with optional Range GET fallback). URL should already include token if required."""
    if not url.startswith(("http://", "https://")):
        return False, "scheme_not_http"

    def _read_response(resp: Any) -> tuple[int, str]:
        code = int(getattr(resp, "status", getattr(resp, "code", 200)))
        length = resp.headers.get("content-length", "") if hasattr(resp, "headers") else ""
        return code, length or "?"

    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code, length = _read_response(resp)
            if 200 <= code < 400:
                return True, f"HEAD http_{code} size={length}"
            return False, f"HEAD http_{code}"
    except urllib.error.HTTPError as exc:
        if int(exc.code) == 405:
            pass  # fall through to GET range
        else:
            return False, f"HEAD http_{exc.code}:{exc.reason}"
    except Exception as exc:
        return False, f"HEAD_err:{exc.__class__.__name__}:{exc}"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Range", "bytes=0-0")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code, length = _read_response(resp)
            if code in (200, 206) or (200 <= code < 400):
                return True, f"GET_range http_{code} size={length}"
            return False, f"GET_range http_{code}"
    except urllib.error.HTTPError as exc:
        return False, f"GET http_{exc.code}:{exc.reason}"
    except Exception as exc:
        return False, f"GET_err:{exc.__class__.__name__}:{exc}"


def _verify_ota_url(url: str) -> tuple[bool, str]:
    """Verify the firmware URL responds (HEAD or byte-range GET). Appends OTA_TOKEN for nginx."""
    return _http_probe_ota(_append_ota_token_to_url(url))


def _verify_firmware_file_on_service(fname: str) -> tuple[bool, str, str]:
    """Check reachability via OTA_VERIFY_BASE_URL or public base; returns (ok, detail, checked_url_masked)."""
    safe = os.path.basename(fname.strip())
    u = _service_check_url_for_firmware(safe)
    ok, detail = _http_probe_ota(u)
    masked = u
    tok = (OTA_TOKEN or "").strip()
    if tok:
        masked = u.replace(tok, "***")
    return ok, detail, masked


def _ota_campaign_targets_for_admin(admin_username: str, fw_version: str, target_url: str) -> list[dict[str, Any]]:
    """Return the list of device rows that belong to `admin_username` along
    with their current fw/url so we can roll them back if needed."""
    rows: list[dict[str, Any]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT d.device_id, d.fw, d.last_status_json
            FROM device_state d
            JOIN device_ownership o ON o.device_id = d.device_id
            WHERE o.owner_admin = ?
            """,
            (admin_username,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    out: list[dict[str, Any]] = []
    for r in rows:
        prev_fw = str(r.get("fw") or "")
        prev_url = ""
        raw_status = r.get("last_status_json") or ""
        if raw_status:
            try:
                js = json.loads(str(raw_status))
                prev_url = str(js.get("ota_source_url") or "")
            except Exception:
                pass
        out.append({"device_id": str(r["device_id"]), "prev_fw": prev_fw, "prev_url": prev_url})
    return out


def _dispatch_ota_to_device(campaign_id: str, device_id: str, target_fw: str, target_url: str) -> None:
    publish_command(
        topic=f"{TOPIC_ROOT}/{device_id}/cmd",
        cmd="ota",
        params={"url": target_url, "fw": target_fw, "campaign_id": campaign_id},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=get_cmd_key_for_device(device_id),
        dedupe_key=f"ota:{device_id}:{campaign_id or target_fw or target_url}",
        dedupe_ttl_s=60.0,
    )


def _start_ota_rollout_for_admin(campaign_id: str, admin_username: str) -> tuple[int, list[str]]:
    """Dispatch the OTA command to every device owned by admin_username.
    Returns (dispatched_count, failures)."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT fw_version, url FROM ota_campaigns WHERE id = ?", (campaign_id,),
        )
        camp = cur.fetchone()
        if not camp:
            conn.close()
            return 0, ["campaign_not_found"]
        target_fw = str(camp["fw_version"])
        target_url = str(camp["url"])

        cur.execute(
            "SELECT device_id, target_fw, target_url FROM ota_device_runs WHERE campaign_id = ? AND admin_username = ?",
            (campaign_id, admin_username),
        )
        device_rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    dispatched = 0
    failures: list[str] = []
    for r in device_rows:
        did = str(r["device_id"])
        try:
            _dispatch_ota_to_device(campaign_id, did, target_fw, target_url)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='dispatched', started_at=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (utc_now_iso(), utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
            dispatched += 1
        except Exception as exc:
            failures.append(f"{did}:{exc}")
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='failed', error=?, finished_at=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (str(exc)[:240], utc_now_iso(), utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
    return dispatched, failures


def _rollback_admin_devices(campaign_id: str, admin_username: str, reason: str) -> int:
    """Send OTA with the previously-known url/fw to every device that had
    already flipped to success for this campaign under this admin."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_id, prev_fw, prev_url
            FROM ota_device_runs
            WHERE campaign_id = ? AND admin_username = ? AND state = 'success'
            """,
            (campaign_id, admin_username),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    rolled = 0
    for r in rows:
        did = str(r["device_id"])
        prev_url = str(r.get("prev_url") or "")
        prev_fw = str(r.get("prev_fw") or "")
        if not prev_url:
            continue
        try:
            _dispatch_ota_to_device(f"{campaign_id}#rollback", did, prev_fw or "rollback", prev_url)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE ota_device_runs SET state='rolled_back', error=?, updated_at=? WHERE campaign_id=? AND device_id=?",
                    (reason[:240], utc_now_iso(), campaign_id, did),
                )
                conn.commit()
                conn.close()
            rolled += 1
        except Exception:
            pass

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'rolled_back', ?, ?)
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='rolled_back', decided_at=excluded.decided_at, detail=excluded.detail
            """,
            (campaign_id, admin_username, utc_now_iso(), reason[:240]),
        )
        conn.commit()
        conn.close()

    try:
        audit_event("system", "ota.rollback", target=admin_username, detail={"campaign_id": campaign_id, "reason": reason, "rolled": rolled})
    except Exception:
        pass
    return rolled


def _handle_ota_result_safe(device_id: str, payload: dict[str, Any]) -> None:
    try:
        _handle_ota_result(device_id, payload)
    except Exception as exc:
        logger.exception("ota result handling failed for %s: %s", device_id, exc)


def _handle_ota_result(device_id: str, payload: dict[str, Any]) -> None:
    campaign_id = str(payload.get("campaign_id") or "").strip()
    if not campaign_id or campaign_id.endswith("#rollback"):
        return
    ok = bool(payload.get("ok"))
    detail = str(payload.get("detail") or "")[:240]
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE ota_device_runs
            SET state = ?, error = ?, finished_at = ?, updated_at = ?
            WHERE campaign_id = ? AND device_id = ?
            """,
            ("success" if ok else "failed", "" if ok else detail, now_iso, now_iso, campaign_id, device_id),
        )
        # Find admin for rollback logic.
        cur.execute(
            "SELECT admin_username FROM ota_device_runs WHERE campaign_id = ? AND device_id = ?",
            (campaign_id, device_id),
        )
        row = cur.fetchone()
        admin_username = str(row["admin_username"]) if row else ""

        # Aggregate campaign state.
        cur.execute(
            "SELECT state, COUNT(*) AS c FROM ota_device_runs WHERE campaign_id = ? GROUP BY state",
            (campaign_id,),
        )
        agg = {str(r["state"]): int(r["c"]) for r in cur.fetchall()}
        conn.commit()
        conn.close()

    emit_event(
        level="info" if ok else "error",
        category="ota",
        event_type="ota.device.result",
        summary=f"{device_id} ota {'ok' if ok else 'FAILED'} [{campaign_id}]",
        actor=f"device:{device_id}",
        target=admin_username or None,
        owner_admin=admin_username or None,
        device_id=device_id,
        detail={"campaign_id": campaign_id, "ok": ok, "detail": detail},
    )

    if not ok and OTA_AUTO_ROLLBACK_ON_FAILURE and admin_username:
        _rollback_admin_devices(campaign_id, admin_username, reason=f"device {device_id} failed: {detail}")

    # Update top-level campaign state for the dashboard.
    total = sum(agg.values())
    if total:
        failed = agg.get("failed", 0)
        success = agg.get("success", 0)
        pending = agg.get("pending", 0) + agg.get("dispatched", 0)
        rolled = agg.get("rolled_back", 0)
        if pending == 0 and failed == 0 and rolled == 0 and success == total:
            new_state = "success"
        elif pending == 0 and rolled > 0:
            new_state = "rolled_back"
        elif pending == 0 and failed > 0:
            new_state = "partial" if success > 0 else "failed"
        else:
            new_state = "running"
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE ota_campaigns SET state=?, updated_at=? WHERE id=?",
                (new_state, utc_now_iso(), campaign_id),
            )
            conn.commit()
            conn.close()


def _fan_out_alarm(device_id: str, payload: dict[str, Any]) -> None:
    """Called from the MQTT thread when an `alarm.trigger` event arrives.

    Steps:
      1. Resolve ``owner_admin`` and this device's ``notification_group`` / zone (sibling scope).
      2. Apply policy: remote silent vs loud vs panic use different linkage toggles.
      3. Build target list: **siblings only** for ``remote_loud_button``,
         ``remote_silent_button`` and ``remote_pause_button`` (never MQTT the transmitting unit).
         For ``panic_button``,
         MQTT **siblings** only; the pressing unit relies on firmware local siren.
      4. Publish per-target ``siren_on`` / ``siren_off`` / ``alarm_signal``, insert alarm row,
         queue email.
    """
    if _alarm_event_is_duplicate(device_id, payload):
        emit_event(
            level="debug",
            category="alarm",
            event_type="alarm.trigger.duplicate",
            summary=f"duplicate alarm.trigger ignored for {device_id}",
            actor=f"device:{device_id}",
            device_id=device_id,
            detail={
                "nonce": str(payload.get("nonce") or ""),
                "ts": payload.get("ts"),
                "dedup_window_sec": ALARM_EVENT_DEDUP_WINDOW_SEC,
            },
        )
        return

    source_zone = str(payload.get("source_zone") or "all")
    local_trigger = bool(payload.get("local_trigger"))
    triggered_by = str(payload.get("trigger_kind") or ("remote_button" if local_trigger else "network"))
    owner_admin = _lookup_owner_admin(device_id)
    source_group, _source_label = _device_notify_labels(device_id)
    policy = _trigger_policy_for(owner_admin, source_group)

    alarm_id = _insert_alarm(device_id, owner_admin, source_zone, triggered_by, payload)
    emit_event(
        level="warn",
        category="alarm",
        event_type="alarm.trigger",
        summary=f"alarm from {device_id} ({triggered_by})",
        actor=f"device:{device_id}",
        target=owner_admin or "",
        owner_admin=owner_admin,
        device_id=device_id,
        detail={"alarm_id": alarm_id, "zone": source_zone, "trigger_kind": triggered_by},
        ref_table="alarms",
        ref_id=alarm_id,
    )

    should_fanout = triggered_by in (
        "remote_button",
        "remote_loud_button",
        "remote_silent_button",
        "remote_pause_button",
        "network",
        "group_link",
        "panic_button",
    )
    if triggered_by == "remote_silent_button" and not bool(policy.get("remote_silent_link_enabled", True)):
        should_fanout = False
    # Remote "loud" pathways only (not panic — panic has its own toggle).
    if triggered_by in ("remote_button", "remote_loud_button", "remote_pause_button", "network", "group_link") and not bool(
        policy.get("remote_loud_link_enabled", True)
    ):
        should_fanout = False
    if triggered_by == "panic_button" and not bool(policy.get("panic_link_enabled", True)):
        should_fanout = False

    # Who receives MQTT commands: siblings in the same tenant + notification_group (+ zone).
    # Remote #1 silent / #2 loud: never command the originating device.
    # Panic: MQTT to siblings only; originator sounds via firmware TRIGGER_SELF_SIREN.
    include_source = not bool(policy.get("fanout_exclude_self", True))
    if triggered_by in ("remote_button", "remote_loud_button", "remote_silent_button", "remote_pause_button", "panic_button"):
        include_source = False

    targets, eligible_total = (
        _tenant_siblings(
            owner_admin,
            device_id,
            source_zone=source_zone,
            source_group=source_group,
            include_source=include_source,
        )
        if should_fanout
        else ([], 0)
    )
    fanout_capped = bool(should_fanout and eligible_total > len(targets))
    sent = 0
    failures: list[str] = []
    loud_ms = int(policy.get("remote_loud_duration_ms", ALARM_FANOUT_DURATION_MS))
    panic_ms = int(policy.get("panic_fanout_duration_ms", DEFAULT_PANIC_FANOUT_MS))
    default_cmd_key = str(CMD_AUTH_KEY or "").strip().upper()
    cmd_key_map = get_cmd_keys_for_devices([did for did, _ in targets]) if targets else {}

    def _fanout_publish_one(did: str, ckey: str) -> None:
        if triggered_by == "remote_silent_button":
            cmd, params = "alarm_signal", {"kind": "silent"}
        elif triggered_by == "remote_pause_button":
            cmd, params = "siren_off", {}
        else:
            dur_ms = panic_ms if triggered_by == "panic_button" else loud_ms
            cmd, params = "siren_on", {"duration_ms": dur_ms}
        # wait_publish=False: fan-out runs in a thread pool; we don't want each
        # target to block waiting for paho drain, otherwise a 50-device group can
        # stall the MQTT ingest thread for tens of seconds and back up the queue.
        publish_command(
            topic=f"{TOPIC_ROOT}/{did}/cmd",
            cmd=cmd,
            params=params,
            target_id=did,
            proto=CMD_PROTO,
            cmd_key=ckey,
            wait_publish=False,
        )

    if should_fanout and targets:
        sent_lock = threading.Lock()
        fail_lock = threading.Lock()

        # Bounded concurrency: on a 200-device group we do not want 200 threads.
        pool = min(max(4, FANOUT_WORKER_POOL_SIZE), max(1, len(targets)))
        sem = threading.BoundedSemaphore(pool)

        def _worker(did: str) -> None:
            nonlocal sent
            ck = cmd_key_map.get(did.strip().upper(), default_cmd_key)
            with sem:
                try:
                    _fanout_publish_one(did, ck)
                    with sent_lock:
                        sent += 1
                except Exception as exc:
                    with fail_lock:
                        failures.append(f"{did}:{exc}")

        workers = [
            threading.Thread(target=_worker, args=(did,), name=f"fanout-{did}", daemon=True)
            for did, _z in targets
        ]
        for t in workers:
            t.start()
        # Cap wall-clock on the ingest thread: even in a 100-device group, we should
        # return in ~1.5s. QoS 1 retries remain paho's responsibility.
        deadline = time.time() + float(FANOUT_WALL_CLOCK_MAX_S)
        for t in workers:
            left = max(0.05, deadline - time.time())
            t.join(timeout=left)
        if failures:
            retry_ids = [x.split(":", 1)[0] for x in failures if ":" in x and x.split(":", 1)[0]]
            if retry_ids:
                time.sleep(0.3)
                failures.clear()
                retry_threads = [
                    threading.Thread(target=_worker, args=(did,), name=f"fanout-retry-{did}", daemon=True)
                    for did in retry_ids
                ]
                for t in retry_threads:
                    t.start()
                retry_deadline = time.time() + float(FANOUT_WALL_CLOCK_MAX_S)
                for t in retry_threads:
                    left = max(0.05, retry_deadline - time.time())
                    t.join(timeout=left)

    email_sent = False
    email_detail = ""
    try:
        recipients = _recipients_for_admin(owner_admin)
        if recipients and notifier.enabled():
            g, n = _device_notify_labels(device_id)
            subject, text, html = render_alarm_email({
                "source_id": device_id,
                "zone": source_zone,
                "triggered_by": triggered_by,
                "created_at": utc_now_iso(),
                "fanout_count": sent,
                "notification_group": g,
                "display_label": n,
                "notify_prefix": _notify_subject_prefix(device_id),
            })
            email_sent = notifier.enqueue(recipients, subject, text, html)
            email_detail = f"queued={email_sent} to={len(recipients)}"
        elif recipients:
            email_detail = "smtp_disabled"
        else:
            email_detail = "no_recipients"
    except Exception as exc:
        email_detail = f"queue_err:{exc}"

    _update_alarm(alarm_id, sent, email_sent, email_detail)

    try:
        audit_event(
            f"device:{device_id}",
            "alarm.fanout",
            target=owner_admin or "(unowned)",
            detail={
                "alarm_id": alarm_id,
                "triggered_by": triggered_by,
                "fanout_count": sent,
                "target_total": len(targets),
                "eligible_total": eligible_total,
                "fanout_capped": fanout_capped,
                "fanout_max": ALARM_FANOUT_MAX_TARGETS,
                "failures": failures[:5],
                "email": email_detail,
            },
        )
    except Exception:
        pass


def _dispatch_mqtt_payload(topic: str, payload: dict[str, Any]) -> None:
    """All MQTT business logic: runs on the mqtt-ingest worker thread only."""
    if topic == TOPIC_BOOTSTRAP_REGISTER:
        upsert_pending_claim(payload)
        insert_message(topic, "bootstrap_register", str(payload.get("device_id", "")), payload)
        did_try = str(payload.get("device_id", ""))
        emit_event(
            level="info",
            category="provision",
            event_type="provision.bootstrap_register",
            summary=f"{did_try} bootstrap register",
            actor=f"device:{did_try}",
            device_id=did_try,
            detail={"serial": payload.get("serial"), "mac": payload.get("mac"), "qr_code": payload.get("qr_code")},
        )
        return

    device_id, channel = parse_topic(topic)
    if not channel:
        return

    insert_message(topic, channel, device_id, payload)
    if device_id:
        upsert_device_state(device_id, channel, payload)

    # Flow EVERY device channel into the unified event stream (at debug
    # level so subscribers can opt in). This gives the superadmin a true
    # firehose while staying out of the tenant admin's default view.
    if device_id and channel in ("heartbeat", "status", "ack", "event"):
        try:
            owner = _lookup_owner_admin(device_id) if "lookup_owner" not in payload else None
        except Exception:
            owner = None
        ev_level = "debug"
        ev_type = f"device.{channel}"
        ev_sum = f"{device_id} {channel}"
        # Elevate important ones.
        if channel == "event":
            p_type = str(payload.get("type") or "")
            if p_type:
                ev_type = f"device.event.{p_type}"
                ev_sum = f"{device_id} event {p_type}"
                if p_type.startswith("alarm."):
                    ev_level = "warn"
        elif channel == "ack":
            if str(payload.get("type") or "") == "ota.result":
                ev_level = "warn" if not bool(payload.get("ok")) else "info"
                ev_type = "device.ota.result"
                ev_sum = f"{device_id} ota {'ok' if payload.get('ok') else 'FAIL'}"
        emit_event(
            level=ev_level,
            category="device",
            event_type=ev_type,
            summary=ev_sum,
            actor=f"device:{device_id}",
            owner_admin=owner,
            device_id=device_id,
            detail={"topic": topic, **{k: v for k, v in payload.items() if k in ("type", "ok", "detail", "campaign_id", "rssi", "vbat", "net_type", "fw", "throughput_rx_bps", "throughput_tx_bps")}},
        )

    if channel == "event" and device_id and str(payload.get("type") or "") == "alarm.trigger":
        # Dispatch fan-out to a worker thread so the MQTT ingest queue keeps draining.
        t = threading.Thread(
            target=_fan_out_alarm_safe,
            name=f"alarm-fanout-{device_id}",
            args=(device_id, payload),
            daemon=True,
        )
        t.start()

    if channel == "ack" and device_id and str(payload.get("type") or "") == "ota.result":
        t = threading.Thread(
            target=_handle_ota_result_safe,
            name=f"ota-result-{device_id}",
            args=(device_id, payload),
            daemon=True,
        )
        t.start()

    if channel == "ack" and device_id and _is_ack_key_mismatch(payload):
        _enqueue_auto_reconcile(device_id, "ack_key_mismatch")

    if channel in ("heartbeat", "status", "ack", "event") and device_id:
        try:
            _mark_presence_probe_acked(device_id)
        except Exception:
            logger.debug("presence probe ack update failed for %s", device_id, exc_info=True)


def _mqtt_ingest_worker() -> None:
    """Drain mqtt_ingest_queue: JSON parse + _dispatch_mqtt_payload (DB, emit_event, side threads)."""
    while True:
        try:
            item = mqtt_ingest_queue.get(timeout=0.3)
        except _stdqueue.Empty:
            if mqtt_worker_stop.is_set():
                break
            continue
        if not item:
            continue
        topic = str(item.get("topic") or "")
        raw = item.get("payload")
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                continue
        except Exception:
            continue
        try:
            _dispatch_mqtt_payload(topic, payload)
        except Exception as exc:
            logger.exception("mqtt ingest worker failed topic=%s: %s", topic, exc)


def on_message(_client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
    """Paho callback: enqueue only — never DB, JSON business logic, or emit_event here."""
    global mqtt_ingest_dropped
    try:
        raw = msg.payload.decode("utf-8", errors="replace")
    except Exception:
        return
    try:
        mqtt_ingest_queue.put_nowait({"topic": msg.topic, "payload": raw, "ts": time.time()})
    except _stdqueue.Full:
        mqtt_ingest_dropped += 1
        if mqtt_ingest_dropped == 1 or mqtt_ingest_dropped % 250 == 0:
            logger.warning(
                "mqtt ingest queue full (max=%s); dropped=%s last_topic=%r",
                MQTT_INGEST_QUEUE_MAX,
                mqtt_ingest_dropped,
                getattr(msg, "topic", ""),
            )


def _fan_out_alarm_safe(device_id: str, payload: dict[str, Any]) -> None:
    try:
        _fan_out_alarm(device_id, payload)
    except Exception as exc:
        logger.exception("alarm fan-out failed for %s: %s", device_id, exc)


def start_mqtt_loop() -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if MQTT_USE_TLS:
        if not MQTT_CLIENT_CA or not os.path.isfile(MQTT_CLIENT_CA):
            logging.getLogger(__name__).error(
                "MQTT_USE_TLS=1 but CA file missing at MQTT_CLIENT_CA=%r "
                "(mount host certs/ca.crt into the api container; see docker-compose.yml).",
                MQTT_CLIENT_CA,
            )
        else:
            ctx = ssl.create_default_context(cafile=MQTT_CLIENT_CA)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if not MQTT_TLS_VERIFY_HOSTNAME:
                ctx.check_hostname = False
            client.tls_set_context(ctx)
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=60)
    client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
    client.loop_start()
    return client


def stop_mqtt_loop(client: mqtt.Client) -> None:
    try:
        client.loop_stop()
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def require_principal(
    authorization: Optional[str] = Header(default=None),
    sentinel_jwt_cookie: Optional[str] = Cookie(default=None, alias=JWT_COOKIE_NAME),
) -> Principal:
    """
    JWT: Authorization Bearer, or HttpOnly cookie (when JWT_USE_HTTPONLY_COOKIE).
    Optional legacy API_TOKEN superadmin bearer when LEGACY_API_TOKEN_ENABLED=1.
    """
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    elif JWT_USE_HTTPONLY_COOKIE and sentinel_jwt_cookie:
        token = str(sentinel_jwt_cookie).strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    if LEGACY_API_TOKEN_ENABLED and API_TOKEN:
        try:
            if secrets.compare_digest(token, API_TOKEN):
                return Principal(username="api-legacy", role="superadmin", zones=["*"])
        except (TypeError, ValueError):
            pass
    return decode_jwt(token)


class CommandRequest(BaseModel):
    cmd: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    target_id: Optional[str] = None
    proto: int = Field(default=CMD_PROTO, ge=1, le=16)


class BroadcastCommandRequest(BaseModel):
    cmd: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    target_id: str = Field(default="all")
    proto: int = Field(default=CMD_PROTO, ge=1, le=16)


class ClaimDeviceRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=3, max_length=23)
    zone: str = Field(default="all", min_length=1, max_length=31)
    qr_code: Optional[str] = Field(default=None, max_length=47)


class ScheduleRebootRequest(BaseModel):
    delay_s: Optional[int] = Field(default=None, ge=5, le=604800)
    at_ts: Optional[int] = Field(default=None, ge=0)


class BulkAlertRequest(BaseModel):
    action: str = Field(pattern="^(on|off)$")
    duration_ms: int = Field(default=int(DEFAULT_REMOTE_FANOUT_MS), ge=500, le=300000)
    device_ids: list[str] = Field(default_factory=list)


_WIFI_DEFERRED_CMDS = frozenset({"get_info", "ping", "self_test", "set_param"})


class WifiDeferredCmd(BaseModel):
    """Executed on-device after Wi-Fi credentials are saved + reboot, once MQTT reconnects (order preserved)."""

    cmd: str = Field(min_length=1, max_length=32)
    params: dict[str, Any] = Field(default_factory=dict)


class ProvisionWifiTaskRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=32)
    password: str = Field(default="", max_length=64)
    chain: list[WifiDeferredCmd] = Field(default_factory=list, max_length=4)


class TriggerPolicyBody(BaseModel):
    panic_local_siren: bool = True
    panic_link_enabled: bool = True
    panic_fanout_duration_ms: int = Field(default=DEFAULT_PANIC_FANOUT_MS, ge=500, le=600000)
    remote_silent_link_enabled: bool = True
    remote_loud_link_enabled: bool = True
    remote_loud_duration_ms: int = Field(default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000)
    fanout_exclude_self: bool = True


class DeviceChallengeRequest(BaseModel):
    mac_nocolon: str = Field(min_length=12, max_length=12)
    device_id: str = Field(min_length=8, max_length=40)
    public_key_pem: str = Field(min_length=64, max_length=4096)
    attestation: Optional[dict[str, Any]] = None


class DeviceChallengeVerifyRequest(BaseModel):
    challenge_id: int = Field(ge=1)
    signature_b64: str = Field(min_length=32, max_length=1024)


class DeviceRevokeRequest(BaseModel):
    reason: str = Field(default="manual revoke", min_length=3, max_length=200)


class DeviceDeleteRequest(BaseModel):
    confirm_text: str = Field(min_length=3, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class SelfPasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    new_password_confirm: str = Field(min_length=8, max_length=128)


class SelfDeleteRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    confirm_text: str = Field(min_length=3, max_length=32)
    # Admin only: must be true — unclaims all owned devices (factory unclaimed) and deletes subordinate users.
    acknowledge_admin_tenant_closure: bool = Field(default=False)


class FcmTokenRegisterRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)
    platform: str = Field(default="", max_length=32)


class FcmTokenDeleteRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class NotificationPrefsPatchRequest(BaseModel):
    """Mobile alarm presentation: fullscreen (high-urgency) vs heads_up (standard notification)."""

    alarm_push_style: str = Field(pattern="^(fullscreen|heads_up)$")


class MeProfilePatchRequest(BaseModel):
    """User-editable console profile (sidebar avatar, etc.)."""

    avatar_url: str = Field(default="", max_length=800)


def _validate_avatar_url(raw: str) -> str:
    """Empty clears. Otherwise require https: URL suitable for <img src>."""
    s = (raw or "").strip()
    if not s:
        return ""
    if len(s) > 800:
        raise HTTPException(status_code=400, detail="avatar_url too long")
    from urllib.parse import urlparse

    u = urlparse(s)
    if u.scheme != "https":
        raise HTTPException(status_code=400, detail="avatar_url must be https or empty")
    if not (u.netloc and str(u.netloc).strip()):
        raise HTTPException(status_code=400, detail="avatar_url has no host")
    if u.username is not None or u.password is not None:
        raise HTTPException(status_code=400, detail="avatar_url must not contain credentials")
    return s


class AdminTenantCloseRequest(BaseModel):
    """Superadmin closes another admin tenant; optional device transfer instead of unclaim."""

    confirm_text: str = Field(min_length=8, max_length=64)
    transfer_devices_to: Optional[str] = Field(default=None, max_length=64)


class ForgotStartRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class ForgotEmailStartRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)


class ForgotEmailCompleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    sha_code: str = Field(min_length=6, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


class ForgotCompleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    recovery_plain: str = Field(min_length=8, max_length=4096)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


class UserCreateRequest(BaseModel):
    # NOTE: superadmin is NEVER creatable through the API. It is seeded once
    # from BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD on first boot and that's it.
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(pattern="^(admin|user)$")
    zones: list[str] = Field(default_factory=lambda: ["*"])
    manager_admin: Optional[str] = Field(default=None, min_length=2, max_length=64)
    tenant: Optional[str] = Field(default=None, min_length=1, max_length=64)
    email: Optional[str] = Field(default=None, min_length=3, max_length=254)
    phone: Optional[str] = Field(default=None, min_length=4, max_length=32)


class UserPolicyUpdateRequest(BaseModel):
    can_alert: Optional[bool] = None
    can_send_command: Optional[bool] = None
    can_claim_device: Optional[bool] = None
    can_manage_users: Optional[bool] = None
    can_backup_restore: Optional[bool] = None
    tg_view_logs: Optional[bool] = None
    tg_view_devices: Optional[bool] = None
    tg_siren_on: Optional[bool] = None
    tg_siren_off: Optional[bool] = None
    tg_test_single: Optional[bool] = None
    tg_test_bulk: Optional[bool] = None


def _blocking_api_bootstrap_inner() -> None:
    """Runs on thread api-bootstrap: DB init, notifier, MQTT ingest, scheduler."""
    global mqtt_client, scheduler_thread, mqtt_worker_thread, mqtt_ingest_dropped
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
    mqtt_worker_stop.clear()
    mqtt_ingest_dropped = 0
    mqtt_worker_thread = threading.Thread(target=_mqtt_ingest_worker, name="mqtt-ingest", daemon=True)
    mqtt_worker_thread.start()
    mqtt_client = start_mqtt_loop()
    scheduler_stop.clear()
    scheduler_thread = threading.Thread(target=scheduler_loop, name="cmd-scheduler", daemon=True)
    scheduler_thread.start()
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
    global mqtt_client, scheduler_thread, mqtt_worker_thread
    _stop_event_redis_bridge()
    scheduler_stop.set()
    if scheduler_thread is not None:
        scheduler_thread.join(timeout=2.0)
        scheduler_thread = None
    if mqtt_client is not None:
        stop_mqtt_loop(mqtt_client)
        mqtt_client = None
    mqtt_worker_stop.set()
    if mqtt_worker_thread is not None:
        mqtt_worker_thread.join(timeout=10.0)
        mqtt_worker_thread = None
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
    global _bootstrap_thread, api_bootstrap_error
    api_ready_event.clear()
    api_bootstrap_error = None

    def _run_bootstrap() -> None:
        global api_bootstrap_error
        try:
            _blocking_api_bootstrap_inner()
        except BaseException as exc:
            api_bootstrap_error = repr(exc)
            logger.exception("API bootstrap failed")
        finally:
            api_ready_event.set()

    _bootstrap_thread = threading.Thread(target=_run_bootstrap, name="api-bootstrap", daemon=True)
    _bootstrap_thread.start()
    yield
    if _bootstrap_thread is not None and _bootstrap_thread.is_alive():
        _bootstrap_thread.join(timeout=2.0)
    _shutdown_api()


app = FastAPI(title="Croc Sentinel API", version="1.1.0", lifespan=_app_lifespan)
app.add_middleware(GZipMiddleware, minimum_size=700)


@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    """Baseline hardening for dashboard + API responses (CSP allows Google Fonts used by index.html)."""
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'",
    )
    return resp


# ----------------------------------------------------------------- CSRF guard
# Double-submit token (cookie + header). Written to the client alongside the
# JWT cookie at login; every state-changing request must echo the value via
# the CSRF_HEADER_NAME header. Because the cookie is NOT HttpOnly, first-party
# JS can read it; a cross-origin attacker can't — that's the security property.

def _issue_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _set_csrf_cookie(response: Response, token: Optional[str] = None) -> str:
    tok = (token or "").strip() or _issue_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=tok,
        max_age=int(CSRF_TOKEN_TTL_S),
        path="/",
        httponly=False,  # JS must be able to read this one.
        secure=bool(JWT_COOKIE_SECURE),
        samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
    )
    return tok


def _clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        path="/",
        secure=bool(JWT_COOKIE_SECURE),
        httponly=False,
        samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
    )


# Paths that cookie-authenticated browsers are allowed to POST/PUT/PATCH/DELETE
# without a CSRF token. Auth endpoints issue the token so they can't require it
# pre-login; device-side paths run over MQTT or per-device HMAC so the cookie
# flow doesn't apply.
_CSRF_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/auth/login",
    "/auth/register",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/auth/account-activate",
    "/auth/resend-activation",
    "/auth/logout",
    "/api/device/",
    "/api/devices/",  # device-side self-service endpoints
    "/ingest/",
    "/integrations/telegram/webhook",
    "/health",
    "/dashboard/",
    "/ui/",
)


def _csrf_path_exempt(path: str) -> bool:
    p = str(path or "")
    if p in ("/", "/favicon.ico", "/openapi.json", "/redoc", "/docs"):
        return True
    for pref in _CSRF_EXEMPT_PREFIXES:
        if p == pref.rstrip("/") or p.startswith(pref):
            return True
    # Let the mounted /console SPA serve its static files freely.
    if p == DASHBOARD_PATH or p.startswith(DASHBOARD_PATH + "/"):
        return True
    return False


@app.middleware("http")
async def _csrf_guard(request: Request, call_next):
    """Enforce double-submit CSRF token for cookie-authenticated writes."""
    if not CSRF_PROTECTION:
        return await call_next(request)
    method = str(request.method or "GET").upper()
    if method in ("GET", "HEAD", "OPTIONS"):
        return await call_next(request)
    path = request.url.path
    if _csrf_path_exempt(path):
        return await call_next(request)
    # If the caller is using Authorization: Bearer, CSRF is n/a (token is not
    # ambient-authed via the browser). Browser-based attacks can't set this
    # header cross-origin.
    auth_hdr = str(request.headers.get("authorization") or "")
    if auth_hdr.lower().startswith("bearer "):
        return await call_next(request)
    # Only enforce when the request actually carries our session cookie —
    # otherwise the request will fail auth anyway and CSRF is moot.
    jwt_ck = request.cookies.get(JWT_COOKIE_NAME)
    if not jwt_ck:
        return await call_next(request)
    sent = str(request.headers.get(CSRF_HEADER_NAME) or "").strip()
    expected = str(request.cookies.get(CSRF_COOKIE_NAME) or "").strip()
    if not sent or not expected or not secrets.compare_digest(sent, expected):
        return JSONResponse(
            status_code=403,
            content={"detail": "csrf token missing or invalid", "code": "csrf_invalid"},
        )
    return await call_next(request)

_dash_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")
if os.path.isdir(_dash_dir):
    app.mount(DASHBOARD_PATH, StaticFiles(directory=_dash_dir, html=True), name="dashboard")


def _readiness_public_paths(path: str) -> bool:
    """Paths that must never be blocked by startup / bootstrap-failure guard (SPA shell + probes)."""
    if path == "/health" or path == "/" or path.startswith("/docs") or path in (
        "/openapi.json",
        "/redoc",
        "/favicon.ico",
    ):
        return True
    # Telegram pushes updates during boot; handler returns 503 until DB ready so Telegram retries.
    if path == "/integrations/telegram/webhook":
        return True
    # Mounted dashboard (StaticFiles at DASHBOARD_PATH) — was missing and caused 503 on entire UI.
    base = DASHBOARD_PATH
    if path == base or path.startswith(base + "/"):
        return True
    # Legacy redirects into the console
    if path.startswith("/ui"):
        return True
    if path == "/dashboard" or path.startswith("/dashboard/"):
        return True
    return False


@app.middleware("http")
async def _readiness_guard(request: Request, call_next):
    """503 JSON API routes until deferred bootstrap finishes; never block static dashboard."""
    path = request.url.path
    if _readiness_public_paths(path):
        return await call_next(request)
    if not api_ready_event.is_set():
        return JSONResponse(
            status_code=503,
            content={"detail": "service starting", "ready": False},
        )
    if api_bootstrap_error:
        return JSONResponse(
            status_code=503,
            content={"detail": "bootstrap failed", "ready": False, "error": api_bootstrap_error},
        )
    return await call_next(request)


@app.middleware("http")
async def _slow_request_log_middleware(request: Request, call_next):
    if SLOW_REQUEST_LOG_MS <= 0:
        return await call_next(request)
    t0 = time.perf_counter()
    resp = await call_next(request)
    dt_ms = (time.perf_counter() - t0) * 1000
    if dt_ms >= float(SLOW_REQUEST_LOG_MS):
        logger.warning("slow HTTP %s %s %.0fms", request.method, request.url.path, dt_ms)
    return resp


@app.get("/", include_in_schema=False)
def _root_redirect() -> RedirectResponse:
    return RedirectResponse(url=DASHBOARD_PATH + "/", status_code=302)


@app.get("/ui", include_in_schema=False)
@app.get("/ui/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
def _legacy_ui_redirect() -> RedirectResponse:
    return RedirectResponse(url=DASHBOARD_PATH + "/", status_code=301)


@app.get("/ui/{path:path}", include_in_schema=False)
def _legacy_ui_deep_redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=f"{DASHBOARD_PATH}/{path}", status_code=301)


def _telegram_enabled_safe() -> bool:
    try:
        from telegram_notify import telegram_status

        return bool(telegram_status().get("enabled"))
    except Exception:
        return False


def _fcm_enabled_safe() -> bool:
    try:
        from fcm_notify import fcm_status

        return bool(fcm_status().get("enabled"))
    except Exception:
        return False


def _fcm_delete_stale_registration_token(token: str) -> None:
    """Remove invalid FCM tokens reported by HTTP v1 (404 / unregistered)."""
    tok = (token or "").strip()
    if not tok or len(tok) < 32:
        return
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("DELETE FROM user_fcm_tokens WHERE token = ?", (tok,))
            n = int(cur.rowcount or 0)
            conn.commit()
            conn.close()
        if n:
            logger.info("fcm removed stale registration token (rows=%s)", n)
    except Exception as exc:
        logger.warning("fcm stale token delete failed: %s", exc)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "?"


_ip_geo_cache: dict[str, tuple[float, str]] = {}


def _ip_geo_text(ip: str) -> str:
    """Best-effort geo text for a public IP. Returns '' when unavailable."""
    ip = str(ip or "").strip()
    if not ip or ip in ("?", "127.0.0.1", "::1"):
        return ""
    now = time.time()
    ent = _ip_geo_cache.get(ip)
    if ent and (now - ent[0]) < 1800:
        return ent[1]
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,query",
            headers={"User-Agent": "CrocSentinel-Geo/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        j = json.loads(raw)
        if str(j.get("status")) == "success":
            city = str(j.get("city") or "").strip()
            region = str(j.get("regionName") or "").strip()
            country = str(j.get("country") or "").strip()
            txt = ", ".join([x for x in (city, region, country) if x]) or ""
            _ip_geo_cache[ip] = (now, txt)
            return txt
    except Exception:
        pass
    _ip_geo_cache[ip] = (now, "")
    return ""


def _client_context(request: Request) -> dict[str, str]:
    """Best-effort client context for auth logs (IP + UA-derived platform).

    Browser and HTTP clients do not expose endpoint MAC reliably; if an upstream
    proxy/device gateway sets one, we accept it via x-client-mac/x-device-mac.
    """
    ip = _client_ip(request)
    ua = str(request.headers.get("user-agent") or "").strip()
    ua_l = ua.lower()
    if "iphone" in ua_l or "ipad" in ua_l or "ios" in ua_l:
        platform = "iPhone/iOS"
    elif "android" in ua_l:
        platform = "Android"
    elif "windows" in ua_l:
        platform = "Windows"
    elif "mac os" in ua_l or "macintosh" in ua_l:
        platform = "macOS"
    elif "linux" in ua_l:
        platform = "Linux"
    else:
        platform = "Unknown"
    if "mobile" in ua_l:
        device_type = "mobile"
    elif "tablet" in ua_l or "ipad" in ua_l:
        device_type = "tablet"
    else:
        device_type = "desktop"
    mac_hint = str(request.headers.get("x-client-mac") or request.headers.get("x-device-mac") or "").strip()
    client_kind = "app" if any(x in ua_l for x in ("okhttp", "dalvik", "cfnetwork", "flutter", "reactnative")) else "web"
    geo = _ip_geo_text(ip)
    out = {
        "ip": ip,
        "platform": platform,
        "device_type": device_type,
        "client_kind": client_kind,
        "ua": ua[:220],
    }
    if geo:
        out["geo"] = geo
    if mac_hint:
        out["mac_hint"] = mac_hint[:64]
    return out


def _check_login_ip_lockout(ip: str, username: str) -> None:
    """Raise 429 if this client IP is in an active post-failure lock window."""
    now = int(time.time())
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT fail_count, phase, lock_until FROM login_ip_state WHERE ip = ?", (ip,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return
    lock_until = int(row["lock_until"] or 0)
    if lock_until <= now:
        return
    remaining = max(1, lock_until - now)
    phase = int(row["phase"] or 0)
    fail_count = int(row["fail_count"] or 0)
    emit_event(
        level="error",
        category="auth",
        event_type="auth.login.rate_limited",
        summary=f"login locked {username}@{ip}",
        actor=f"ip:{ip}",
        target=username,
        detail={
            "remaining_s": remaining,
            "phase": phase,
            "fail_count": fail_count,
        },
    )
    raise HTTPException(
        status_code=429,
        detail=f"too many login attempts — try again in {remaining}s",
        headers={"Retry-After": str(remaining)},
    )


def _record_login_failure_ip(ip: str) -> None:
    """Increment per-IP failure count; at threshold apply timed lock and advance phase."""
    now = int(time.time())
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT fail_count, phase, lock_until FROM login_ip_state WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if row:
            fail_count = int(row["fail_count"] or 0)
            phase = int(row["phase"] or 0)
        else:
            fail_count, phase = 0, 0
        fail_count += 1
        if phase == 0:
            th = LOGIN_LOCK_TIER0_FAILS
        elif phase == 1:
            th = LOGIN_LOCK_TIER1_FAILS
        else:
            th = LOGIN_LOCK_TIER2_FAILS
        new_fail = fail_count
        new_phase = phase
        new_lock = 0
        if new_fail >= th:
            if phase == 0:
                new_lock = now + LOGIN_LOCK_TIER0_SECONDS
                new_phase = 1
            elif phase == 1:
                new_lock = now + LOGIN_LOCK_TIER1_SECONDS
                new_phase = 2
            else:
                new_lock = now + LOGIN_LOCK_TIER2_SECONDS
                new_phase = 2
            new_fail = 0
        cur.execute(
            """
            INSERT INTO login_ip_state (ip, fail_count, phase, lock_until)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              fail_count = excluded.fail_count,
              phase = excluded.phase,
              lock_until = excluded.lock_until
            """,
            (ip, new_fail, new_phase, new_lock),
        )
        conn.commit()
        conn.close()


def _record_login_failure(ip: str, username: str) -> None:
    """Keep append-only failure log + update per-IP lockout state."""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO login_failures (ip, username, ts_epoch) VALUES (?, ?, ?)",
            (ip, username, int(time.time())),
        )
        conn.commit()
        conn.close()
    _record_login_failure_ip(ip)


def _clear_login_ip_state(ip: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM login_ip_state WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()


def _clear_login_failures(username: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM login_failures WHERE username = ?", (username,))
        conn.commit()
        conn.close()


# ────────────────────────────────────────────────────────────────────
#  Signup / activation helpers
# ────────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,64}$")
# Loose phone normalizer: keep + and digits only. Callers still have to pick a
# country prefix for SMS delivery; we don't do E.164 validation because the
# SMS provider will reject anything unusable.
_PHONE_RE = re.compile(r"[^\d+]")


def _looks_like_email(s: str) -> bool:
    return bool(_EMAIL_RE.match(s or ""))


def _normalize_phone(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    cleaned = _PHONE_RE.sub("", s.strip())
    return cleaned if 4 <= len(cleaned) <= 32 else None


def _hash_otp(code: str) -> str:
    """One-way hash so we never store plaintext OTPs at rest."""
    return hashlib.sha256((code + "|" + (JWT_SECRET or "jwt-unset")).encode("utf-8")).hexdigest()


def _generate_otp() -> str:
    """6-digit numeric OTP, CSPRNG backed."""
    n = secrets.randbelow(1_000_000)
    return f"{n:06d}"


def _generate_sha_code() -> str:
    """10-char SHA-like reset code for email delivery."""
    seed = f"{time.time_ns()}|{secrets.token_hex(16)}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10].upper()


def _check_signup_rate(ip: str, email: str) -> None:
    cutoff = int(time.time()) - SIGNUP_RATE_WINDOW_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM signup_attempts WHERE ts_epoch < ?", (cutoff,))
        cur.execute(
            "SELECT COUNT(*) AS c FROM signup_attempts WHERE ip = ? AND ts_epoch >= ?",
            (ip, cutoff),
        )
        ip_c = int(cur.fetchone()["c"])
        cur.execute(
            "SELECT COUNT(*) AS c FROM signup_attempts WHERE email = ? AND ts_epoch >= ?",
            (email, cutoff),
        )
        email_c = int(cur.fetchone()["c"])
        conn.commit()
        conn.close()
    if ip_c >= SIGNUP_RATE_MAX or email_c >= SIGNUP_RATE_MAX:
        raise HTTPException(status_code=429, detail="too many signup attempts — slow down")


def _record_signup_attempt(ip: str, email: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO signup_attempts (ip, email, ts_epoch) VALUES (?, ?, ?)",
            (ip, email, int(time.time())),
        )
        conn.commit()
        conn.close()


def _send_email_otp(to: str, code: str, purpose: str) -> None:
    """Registration / activation / reset OTP — distinct HTML themes + no-reply footer."""
    subject_prefix = (os.getenv("SMTP_SUBJECT_PREFIX", "[Sentinel]") or "[Sentinel]").strip()
    ttl_min = max(1, int(OTP_TTL_SECONDS // 60))
    subject, body, body_html = render_otp_email(
        purpose=purpose,
        code=code,
        ttl_min=ttl_min,
        subject_prefix=subject_prefix,
    )
    notifier.send_sync([to], subject, body, body_html)


def _send_sms_otp(phone: str, code: str, purpose: str) -> None:
    if SMS_PROVIDER in ("", "none"):
        # In email-only mode we silently skip — callers already checked
        # REQUIRE_PHONE_VERIFICATION, so this branch is only reached when the
        # admin provided a phone but no provider is installed.
        logger.info("sms provider not configured; skipping %s otp for %s", purpose, phone)
        return
    raise NotImplementedError(
        f"SMS_PROVIDER={SMS_PROVIDER} is not implemented in this build; "
        f"wire up notifier_sms.py or keep SMS_PROVIDER=none"
    )


def _issue_verification(
    username: str,
    channel: str,
    target: str,
    purpose: str,
    *,
    explicit_code: Optional[str] = None,
) -> int:
    """Create and deliver a fresh OTP. Returns remaining TTL in seconds."""
    if channel not in ("email", "phone"):
        raise ValueError("channel must be email|phone")
    code = explicit_code or _generate_otp()
    code_hash = _hash_otp(code)
    expires_at = int(time.time()) + OTP_TTL_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        # Cooldown: prevent hammering the mailer.
        cur.execute(
            """SELECT created_at FROM verifications
               WHERE username = ? AND channel = ? AND purpose = ? AND used = 0
               ORDER BY id DESC LIMIT 1""",
            (username, channel, purpose),
        )
        last = cur.fetchone()
        if last:
            try:
                last_ts = int(datetime.fromisoformat(str(last["created_at"])).timestamp())
            except Exception:
                last_ts = 0
            if int(time.time()) - last_ts < OTP_RESEND_COOLDOWN_SECONDS:
                conn.close()
                wait = OTP_RESEND_COOLDOWN_SECONDS - (int(time.time()) - last_ts)
                raise HTTPException(
                    status_code=429,
                    detail=f"Resend cooldown: wait {max(1, wait)}s before requesting another code",
                )
        # Invalidate previous pending codes for this (user, channel, purpose).
        cur.execute(
            "UPDATE verifications SET used = 1 WHERE username = ? AND channel = ? AND purpose = ? AND used = 0",
            (username, channel, purpose),
        )
        cur.execute(
            """INSERT INTO verifications
               (username, channel, target, purpose, code_hash, expires_at_ts, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (username, channel, target, purpose, code_hash, expires_at, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    if channel == "email":
        _send_email_otp(target, code, purpose)
    else:
        _send_sms_otp(target, code, purpose)
    return OTP_TTL_SECONDS


def _verification_resend_wait_seconds(username: str, channel: str, purpose: str) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT created_at FROM verifications
               WHERE username = ? AND channel = ? AND purpose = ? AND used = 0
               ORDER BY id DESC LIMIT 1""",
            (username, channel, purpose),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return 0
    try:
        last_ts = int(datetime.fromisoformat(str(row["created_at"])).timestamp())
    except Exception:
        return 0
    delta = int(time.time()) - last_ts
    if delta >= OTP_RESEND_COOLDOWN_SECONDS:
        return 0
    return max(1, OTP_RESEND_COOLDOWN_SECONDS - delta)


def _consume_verification(username: str, channel: str, purpose: str, code: str) -> bool:
    """Check code; mark used if it matches. Return True/False."""
    code_hash = _hash_otp(code or "")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, code_hash, attempts, expires_at_ts, used FROM verifications
               WHERE username = ? AND channel = ? AND purpose = ?
               ORDER BY id DESC LIMIT 1""",
            (username, channel, purpose),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return False
        if int(row["used"]) == 1:
            conn.close()
            return False
        if int(time.time()) > int(row["expires_at_ts"]):
            conn.close()
            return False
        if int(row["attempts"]) >= 5:
            conn.close()
            return False
        if not secrets.compare_digest(str(row["code_hash"]), code_hash):
            cur.execute("UPDATE verifications SET attempts = attempts + 1 WHERE id = ?", (int(row["id"]),))
            conn.commit()
            conn.close()
            return False
        cur.execute("UPDATE verifications SET used = 1 WHERE id = ?", (int(row["id"]),))
        conn.commit()
        conn.close()
    return True


class SignupStartRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: str = Field(min_length=3, max_length=254)
    phone: Optional[str] = Field(default=None, min_length=4, max_length=32)


class VerifyCodeRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    email_code: Optional[str] = Field(default=None, min_length=4, max_length=12)
    phone_code: Optional[str] = Field(default=None, min_length=4, max_length=12)


class ResendCodeRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    channel: str = Field(pattern="^(email|phone)$")
    purpose: str = Field(default="activate", pattern="^(signup|activate|reset)$")


@app.post("/auth/signup/start")
def auth_signup_start(body: SignupStartRequest, request: Request) -> dict[str, Any]:
    """Public admin self-signup (role=admin only, never superadmin).

    Creates a `dashboard_users` row in status='pending' and emails an OTP.
    The account becomes usable only after /auth/signup/verify succeeds AND,
    When ADMIN_SIGNUP_REQUIRE_APPROVAL=1, a superadmin must approve after OTP.
    """
    if not ALLOW_PUBLIC_ADMIN_SIGNUP:
        raise HTTPException(status_code=403, detail="public signup disabled")
    ip = _client_ip(request)
    username = body.username.strip()
    if not _USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="username must be 2–64 chars of [A-Za-z0-9_.-]")
    email_norm = body.email.strip().lower()
    if not _looks_like_email(email_norm):
        raise HTTPException(status_code=400, detail="email format invalid")
    phone_norm = _normalize_phone(body.phone)
    if REQUIRE_PHONE_VERIFICATION and not phone_norm:
        raise HTTPException(status_code=400, detail="phone is required")
    _check_signup_rate(ip, email_norm)
    _record_signup_attempt(ip, email_norm)
    initial_status = "pending"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, status FROM dashboard_users WHERE username = ?", (username,))
        existing = cur.fetchone()
        if existing:
            conn.close()
            # Don't disclose why it failed beyond a generic conflict.
            raise HTTPException(status_code=409, detail="username not available")
        cur.execute("SELECT username FROM dashboard_users WHERE LOWER(email) = ?", (email_norm,))
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=409, detail="email already registered")
        try:
            cur.execute(
                """INSERT INTO dashboard_users (
                       username, password_hash, role, allowed_zones_json,
                       manager_admin, tenant, email, phone, status, created_at
                   ) VALUES (?, ?, 'admin', '["*"]', '', ?, ?, ?, ?, ?)""",
                (
                    username,
                    hash_password(body.password),
                    username,  # tenant defaults to self
                    email_norm,
                    phone_norm,
                    initial_status,
                    utc_now_iso(),
                ),
            )
            pol = default_policy_for_role("admin")
            cur.execute(
                """INSERT OR IGNORE INTO role_policies
                   (username, can_alert, can_send_command, can_claim_device,
                    can_manage_users, can_backup_restore, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    username,
                    pol["can_alert"], pol["can_send_command"], pol["can_claim_device"],
                    pol["can_manage_users"], pol["can_backup_restore"], utc_now_iso(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="username not available")
        conn.close()
    try:
        _issue_verification(username, "email", email_norm, purpose="signup")
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("signup email OTP failed for %s: %s", username, exc)
        raise HTTPException(status_code=502, detail=f"failed to send email verification: {exc}")
    if phone_norm and REQUIRE_PHONE_VERIFICATION:
        try:
            _issue_verification(username, "phone", phone_norm, purpose="signup")
        except Exception as exc:
            logger.warning("signup phone OTP failed for %s: %s", username, exc)
            raise HTTPException(status_code=502, detail=f"failed to send SMS verification: {exc}")
    audit_event(username, "signup.start", username, {"email": email_norm, "phone": bool(phone_norm), "ip": ip})
    return {
        "ok": True,
        "username": username,
        "email_otp_sent": True,
        "phone_otp_sent": bool(phone_norm and REQUIRE_PHONE_VERIFICATION),
        "ttl_seconds": OTP_TTL_SECONDS,
        "requires_approval": ADMIN_SIGNUP_REQUIRE_APPROVAL,
    }


@app.post("/auth/signup/verify")
def auth_signup_verify(body: VerifyCodeRequest) -> dict[str, Any]:
    username = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, status, email, phone, email_verified_at, phone_verified_at "
            "FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        conn.close()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    if u["role"] != "admin":
        # Users go through /auth/activate, which is semantically identical but
        # a separate route so future logic can diverge cleanly.
        raise HTTPException(status_code=400, detail="wrong verification route for this user")
    if str(u["status"]) in ("active", "disabled"):
        return {"ok": True, "already_verified": True, "status": str(u["status"])}
    if REQUIRE_EMAIL_VERIFICATION:
        if not body.email_code:
            raise HTTPException(status_code=400, detail="email_code required")
        if not _consume_verification(username, "email", "signup", body.email_code):
            raise HTTPException(status_code=401, detail="invalid or expired email code")
    if REQUIRE_PHONE_VERIFICATION and u["phone"]:
        if not body.phone_code:
            raise HTTPException(status_code=400, detail="phone_code required")
        if not _consume_verification(username, "phone", "signup", body.phone_code):
            raise HTTPException(status_code=401, detail="invalid or expired phone code")
    next_status = "awaiting_approval" if ADMIN_SIGNUP_REQUIRE_APPROVAL else "active"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """UPDATE dashboard_users
               SET email_verified_at = ?,
                   phone_verified_at = CASE WHEN phone IS NOT NULL AND phone <> '' AND ? <> '' THEN ? ELSE phone_verified_at END,
                   status = ?
               WHERE username = ?""",
            (
                utc_now_iso(),
                (body.phone_code or ""),
                utc_now_iso(),
                next_status,
                username,
            ),
        )
        conn.commit()
        conn.close()
    audit_event(username, "signup.verify", username, {"next_status": next_status})
    return {"ok": True, "status": next_status, "requires_approval": ADMIN_SIGNUP_REQUIRE_APPROVAL}


@app.post("/auth/activate")
def auth_activate_user(body: VerifyCodeRequest) -> dict[str, Any]:
    """Admin-created users activate themselves with the OTP the admin triggered."""
    username = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, status, email, phone FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        conn.close()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    if str(u["status"]) == "active":
        return {"ok": True, "already_active": True}
    if REQUIRE_EMAIL_VERIFICATION:
        if not body.email_code:
            raise HTTPException(status_code=400, detail="email_code required")
        if not _consume_verification(username, "email", "activate", body.email_code):
            raise HTTPException(status_code=401, detail="invalid or expired email code")
    if REQUIRE_PHONE_VERIFICATION and u["phone"]:
        if not body.phone_code:
            raise HTTPException(status_code=400, detail="phone_code required")
        if not _consume_verification(username, "phone", "activate", body.phone_code):
            raise HTTPException(status_code=401, detail="invalid or expired phone code")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """UPDATE dashboard_users
               SET email_verified_at = ?, status = 'active'
               WHERE username = ?""",
            (utc_now_iso(), username),
        )
        conn.commit()
        conn.close()
    audit_event(username, "account.activate", username, {})
    return {"ok": True, "status": "active"}


@app.post("/auth/code/resend")
def auth_code_resend(body: ResendCodeRequest) -> dict[str, Any]:
    username = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT role, status, email, phone FROM dashboard_users WHERE username = ?",
            (username,),
        )
        u = cur.fetchone()
        conn.close()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    if str(u["status"]) == "active" and body.purpose != "reset":
        return {"ok": True, "already_active": True}
    target = str(u["email"] or "") if body.channel == "email" else str(u["phone"] or "")
    if not target:
        raise HTTPException(status_code=400, detail=f"{body.channel} not on file")
    try:
        _issue_verification(username, body.channel, target, purpose=body.purpose)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("resend verification failed for %s %s: %s", username, body.channel, exc)
        raise HTTPException(status_code=502, detail=f"failed to send code: {exc}") from exc
    return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS}


@app.get("/auth/signup/pending")
def auth_signup_pending(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin queue: admins who passed OTP but await approval."""
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT username, email, phone, created_at, email_verified_at
               FROM dashboard_users
               WHERE role = 'admin' AND status = 'awaiting_approval'
               ORDER BY created_at ASC"""
        )
        items = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": items}


@app.post("/auth/signup/approve/{username}")
def auth_signup_approve(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE dashboard_users SET status='active' WHERE username = ? AND role='admin' AND status='awaiting_approval'",
            (username,),
        )
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="no pending admin with that username")
    audit_event(principal.username, "signup.approve", username, {})
    return {"ok": True, "username": username}


@app.post("/auth/signup/reject/{username}")
def auth_signup_reject(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM dashboard_users WHERE username = ? AND role='admin' AND status='awaiting_approval'",
            (username,),
        )
        n = cur.rowcount
        cur.execute("DELETE FROM role_policies WHERE username = ?", (username,))
        cur.execute("DELETE FROM verifications WHERE username = ?", (username,))
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="no pending admin with that username")
    audit_event(principal.username, "signup.reject", username, {})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Offline password recovery — RSA public key on server, private key only in
# `password_recovery_offline/` (never committed). User copies hex blob →
# operator runs decrypt script → user pastes JSON plaintext + new password.
# ---------------------------------------------------------------------------

_pwrec_pubkey_lock = threading.Lock()
_pwrec_pubkey_cache: Any = None  # None=unset, False=missing, else RSAPublicKey


def _password_recovery_load_public() -> Optional[Any]:
    """Lazy-load PEM from PASSWORD_RECOVERY_PUBLIC_KEY_PEM or *_PATH."""
    global _pwrec_pubkey_cache
    with _pwrec_pubkey_lock:
        if _pwrec_pubkey_cache is not None:
            if _pwrec_pubkey_cache is False:
                return None
            return _pwrec_pubkey_cache
        pem = (PASSWORD_RECOVERY_PUBLIC_KEY_PEM or "").replace("\\n", "\n").strip()
        if not pem and PASSWORD_RECOVERY_PUBLIC_KEY_PATH:
            try:
                from pathlib import Path

                pem = Path(PASSWORD_RECOVERY_PUBLIC_KEY_PATH).expanduser().read_text(encoding="utf-8").strip()
            except Exception as exc:
                logger.warning("PASSWORD_RECOVERY_PUBLIC_KEY_PATH read failed: %s", exc)
                pem = ""
        if not pem:
            _pwrec_pubkey_cache = False
            return None
        try:
            key = serialization.load_pem_public_key(pem.encode("utf-8"))
            if not isinstance(key, rsa.RSAPublicKey):
                logger.warning("password recovery: PEM must be an RSA public key")
                _pwrec_pubkey_cache = False
                return None
            if key.key_size < 2048:
                logger.warning("password recovery: RSA key must be >= 2048 bits")
                _pwrec_pubkey_cache = False
                return None
            _pwrec_pubkey_cache = key
            return key
        except Exception as exc:
            logger.warning("password recovery: invalid PEM: %s", exc)
            _pwrec_pubkey_cache = False
            return None


def _password_recovery_blob_byte_len(pub: rsa.RSAPublicKey) -> int:
    rsa_len = pub.key_size // 8
    return len(PASSWORD_RECOVERY_BLOB_MAGIC) + 1 + rsa_len + 12 + (PASSWORD_RECOVERY_PLAINTEXT_PAD + 16)


def _encrypt_password_recovery_payload(pub: rsa.RSAPublicKey, inner: dict[str, Any]) -> bytes:
    pad = int(PASSWORD_RECOVERY_PLAINTEXT_PAD)
    pt = json.dumps(inner, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(pt) > pad:
        raise ValueError("inner JSON exceeds PASSWORD_RECOVERY_PLAINTEXT_PAD")
    pt = pt + (b"\x00" * (pad - len(pt)))
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(iv, pt, None)
    rsa_cipher = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(rsa_cipher) != pub.key_size // 8:
        raise ValueError("RSA ciphertext length mismatch")
    return PASSWORD_RECOVERY_BLOB_MAGIC + bytes([PASSWORD_RECOVERY_BLOB_VERSION]) + rsa_cipher + iv + ct


def _fake_password_recovery_hex(pub: rsa.RSAPublicKey) -> str:
    return secrets.token_bytes(_password_recovery_blob_byte_len(pub)).hex()


def _check_forgot_ip_rate(ip: str) -> None:
    now = int(time.time())
    cut = now - FORGOT_PASSWORD_IP_WINDOW_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM forgot_password_attempts WHERE ts_epoch < ?", (cut,))
        cur.execute(
            "SELECT COUNT(*) AS c FROM forgot_password_attempts WHERE ip = ? AND ts_epoch >= ?",
            (ip, cut),
        )
        c = int(cur.fetchone()["c"])
        if c >= FORGOT_PASSWORD_IP_MAX:
            conn.commit()
            conn.close()
            raise HTTPException(
                status_code=429,
                detail=f"too many recovery attempts from this IP — try again in {FORGOT_PASSWORD_IP_WINDOW_SECONDS}s",
            )
        cur.execute("INSERT INTO forgot_password_attempts (ip, ts_epoch) VALUES (?, ?)", (ip, now))
        conn.commit()
        conn.close()


def _prune_password_reset_tokens() -> None:
    """Drop expired rows (used or unused) older than 7 days past expiry."""
    now = int(time.time())
    cut = now - 7 * 86400
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM password_reset_tokens WHERE expires_at_ts < ?", (cut,))
        conn.commit()
        conn.close()


@app.get("/auth/forgot/enabled")
def auth_forgot_enabled() -> dict[str, Any]:
    return {"enabled": bool(_password_recovery_load_public())}


@app.get("/auth/forgot/email/enabled")
def auth_forgot_email_enabled() -> dict[str, Any]:
    return {"enabled": bool(notifier.enabled())}


@app.post("/auth/forgot/email/check")
def auth_forgot_email_check(body: ForgotEmailStartRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    _check_forgot_ip_rate(ip)
    username = body.username.strip()
    email = body.email.strip().lower()
    if not _looks_like_email(email):
        raise HTTPException(status_code=400, detail="email format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT status, email FROM dashboard_users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return {"ok": True, "matched": False, "can_send": False, "resend_after_seconds": 0}
    if str(row["status"] or "active") == "disabled":
        return {"ok": True, "matched": False, "can_send": False, "resend_after_seconds": 0}
    reg_email = str(row["email"] or "").strip().lower()
    matched = bool(reg_email) and reg_email == email
    if not matched:
        return {"ok": True, "matched": False, "can_send": False, "resend_after_seconds": 0}
    wait = _verification_resend_wait_seconds(username, "email", "reset")
    return {"ok": True, "matched": True, "can_send": wait <= 0, "resend_after_seconds": wait}


@app.post("/auth/forgot/email/start")
def auth_forgot_email_start(body: ForgotEmailStartRequest, request: Request) -> dict[str, Any]:
    ip = _client_ip(request)
    _check_forgot_ip_rate(ip)
    username = body.username.strip()
    email = body.email.strip().lower()
    if not _looks_like_email(email):
        raise HTTPException(status_code=400, detail="email format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, status, email FROM dashboard_users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        conn.close()
    # Keep error response generic to avoid account probing.
    if not row:
        return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}
    if str(row["status"] or "active") == "disabled":
        return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}
    reg_email = str(row["email"] or "").strip().lower()
    if not reg_email or reg_email != email:
        return {"ok": True, "ttl_seconds": OTP_TTL_SECONDS, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}
    if not notifier.enabled():
        raise HTTPException(status_code=503, detail="email sender is not configured")
    sha_code = _generate_sha_code()
    try:
        ttl = _issue_verification(username, "email", email, "reset", explicit_code=sha_code)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("password reset email send failed for %s: %s", username, exc)
        raise HTTPException(
            status_code=502,
            detail=f"failed to send recovery email: {exc}",
        ) from exc
    emit_event(
        level="info",
        category="auth",
        event_type="auth.password_reset.email_code.started",
        summary=f"password reset sha code sent for {username}",
        actor=f"ip:{ip}",
        target=username,
        owner_admin=username if str(row["role"] or "") == "admin" else get_manager_admin(username),
        detail={"email": email},
    )
    return {"ok": True, "ttl_seconds": ttl, "resend_after_seconds": OTP_RESEND_COOLDOWN_SECONDS}


@app.post("/auth/forgot/email/complete")
def auth_forgot_email_complete(body: ForgotEmailCompleteRequest, request: Request) -> dict[str, Any]:
    if body.password != body.password_confirm:
        raise HTTPException(status_code=400, detail="passwords do not match")
    username = body.username.strip()
    email = body.email.strip().lower()
    if not _looks_like_email(email):
        raise HTTPException(status_code=400, detail="email format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT status, role, email FROM dashboard_users WHERE username = ?", (username,))
        urow = cur.fetchone()
        conn.close()
    if not urow:
        raise HTTPException(status_code=404, detail="user not found")
    if str(urow["status"] or "active") == "disabled":
        raise HTTPException(status_code=403, detail="account disabled")
    if str(urow["email"] or "").strip().lower() != email:
        raise HTTPException(status_code=400, detail="email does not match registered email")
    ok = _consume_verification(username, "email", "reset", body.sha_code.strip())
    if not ok:
        raise HTTPException(status_code=400, detail="invalid or expired sha code")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE dashboard_users SET password_hash = ? WHERE username = ?",
            (hash_password(body.password), username),
        )
        conn.commit()
        conn.close()
    _clear_login_failures(username)
    ip = _client_ip(request)
    _clear_login_ip_state(ip)
    audit_event(username, "auth.password_reset.email_code.ok", "", {"ip": ip, "email": email})
    emit_event(
        level="warn",
        category="auth",
        event_type="auth.password_reset.email_code.completed",
        summary=f"password reset via email code for {username}",
        actor=username,
        target=username,
        owner_admin=username if str(urow["role"] or "") == "admin" else get_manager_admin(username),
        detail={"ip": ip, "email": email},
    )
    return {"ok": True}


@app.post("/auth/forgot/start")
def auth_forgot_start(body: ForgotStartRequest, request: Request) -> dict[str, Any]:
    """Return a hex-encoded blob. Only blobs tied to a real account can be
    completed; invalid usernames still receive a same-length random blob."""
    ip = _client_ip(request)
    pub = _password_recovery_load_public()
    if not pub:
        raise HTTPException(
            status_code=503,
            detail="password recovery is not configured (missing PASSWORD_RECOVERY_PUBLIC_KEY_*)",
        )
    _check_forgot_ip_rate(ip)
    un = body.username.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, status, role FROM dashboard_users WHERE username = ?", (un,))
        row = cur.fetchone()
        conn.close()
    blob_hex = _fake_password_recovery_hex(pub)
    if not row:
        return {
            "ok": True,
            "recovery_blob_hex": blob_hex,
            "ttl_seconds": FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
            "blob_byte_len": _password_recovery_blob_byte_len(pub),
        }
    status = str(row["status"] or "active")
    if status == "disabled":
        return {
            "ok": True,
            "recovery_blob_hex": blob_hex,
            "ttl_seconds": FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
            "blob_byte_len": _password_recovery_blob_byte_len(pub),
        }
    secret = os.urandom(32)
    secret_hash = hashlib.sha256(secret).hexdigest()
    jti = str(uuid.uuid4())
    exp_ts = int(time.time()) + FORGOT_PASSWORD_TOKEN_TTL_SECONDS
    inner = {
        "jti": jti,
        "u": un,
        "s": base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="),
        "e": exp_ts,
    }
    try:
        raw = _encrypt_password_recovery_payload(pub, inner)
    except Exception as exc:
        logger.error("password recovery encrypt failed: %s", exc)
        raise HTTPException(status_code=500, detail="could not build recovery blob") from exc
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO password_reset_tokens (jti, username, secret_hash, created_at, expires_at_ts, used, request_ip)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (jti, un, secret_hash, now_iso, exp_ts, ip),
        )
        conn.commit()
        conn.close()
    emit_event(
        level="info",
        category="auth",
        event_type="auth.password_reset.started",
        summary=f"recovery blob issued for {un}",
        actor=f"ip:{ip}",
        target=un,
        owner_admin=un if str(row["role"]) == "admin" else get_manager_admin(un),
        detail={"jti": jti},
    )
    return {
        "ok": True,
        "recovery_blob_hex": raw.hex(),
        "ttl_seconds": FORGOT_PASSWORD_TOKEN_TTL_SECONDS,
        "blob_byte_len": len(raw),
    }


@app.post("/auth/forgot/complete")
def auth_forgot_complete(body: ForgotCompleteRequest, request: Request) -> dict[str, Any]:
    if body.password != body.password_confirm:
        raise HTTPException(status_code=400, detail="passwords do not match")
    pub = _password_recovery_load_public()
    if not pub:
        raise HTTPException(status_code=503, detail="password recovery is not configured")
    un = body.username.strip()
    try:
        data = json.loads(body.recovery_plain.strip())
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="recovery_plain must be valid JSON — paste the entire single-line output from decrypt_recovery_blob.py",
        ) from exc
    jti = str(data.get("jti") or "")
    u = str(data.get("u") or "")
    s_b64 = str(data.get("s") or "")
    exp = int(data.get("e") or 0)
    if not jti or not u or not s_b64:
        raise HTTPException(status_code=400, detail="recovery JSON missing jti / u / s")
    if u != un:
        raise HTTPException(status_code=400, detail="username does not match recovery token (u field)")
    if int(time.time()) > exp:
        raise HTTPException(status_code=400, detail="recovery token expired")
    pad = "=" * ((4 - len(s_b64) % 4) % 4)
    try:
        secret = base64.urlsafe_b64decode((s_b64 + pad).encode("ascii"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid secret field in recovery JSON") from exc
    if len(secret) != 32:
        raise HTTPException(status_code=400, detail="invalid secret length")
    digest = hashlib.sha256(secret).hexdigest()
    ip = _client_ip(request)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM password_reset_tokens WHERE jti = ? AND username = ? AND used = 0",
            (jti, un),
        )
        tok = cur.fetchone()
        if not tok or not secrets.compare_digest(str(tok["secret_hash"]), digest):
            conn.close()
            audit_event(f"ip:{ip}", "auth.password_reset.fail", un, {"reason": "bad token"})
            raise HTTPException(status_code=400, detail="invalid or already-used recovery token")
        if int(time.time()) > int(tok["expires_at_ts"]):
            conn.close()
            raise HTTPException(status_code=400, detail="recovery token expired")
        cur.execute("SELECT status, role FROM dashboard_users WHERE username = ?", (un,))
        urow = cur.fetchone()
        if not urow:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        st = str(urow["status"] or "active")
        role = str(urow["role"] or "")
        if st == "disabled":
            conn.close()
            raise HTTPException(status_code=403, detail="account disabled")
        new_hash = hash_password(body.password)
        cur.execute(
            "UPDATE dashboard_users SET password_hash = ? WHERE username = ?",
            (new_hash, un),
        )
        cur.execute(
            "UPDATE password_reset_tokens SET used = 1, used_at = ? WHERE jti = ?",
            (utc_now_iso(), jti),
        )
        conn.commit()
        conn.close()
    _clear_login_failures(un)
    _clear_login_ip_state(ip)
    audit_event(un, "auth.password_reset.ok", "", {"ip": ip})
    emit_event(
        level="warn",
        category="auth",
        event_type="auth.password_reset.completed",
        summary=f"password reset for {un}",
        actor=un,
        target=un,
        owner_admin=un if role == "admin" else get_manager_admin(un),
        detail={"ip": ip},
    )
    return {"ok": True}


@app.post("/auth/login")
def auth_login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    ctx = _client_context(request)
    ip = ctx["ip"]
    _check_login_ip_lockout(ip, body.username)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM dashboard_users WHERE username = ?", (body.username,))
        row = cur.fetchone()
        conn.close()
    if not row or not verify_password(body.password, str(row["password_hash"])):
        _record_login_failure(ip, body.username)
        fail_detail = dict(ctx)
        fail_detail["owner_admin"] = ""
        fail_detail["login_user"] = body.username
        audit_event(f"ip:{ip}", "auth.login.fail", body.username, fail_detail)
        raise HTTPException(status_code=401, detail="invalid credentials")
    # Status gate: pending / awaiting_approval / disabled cannot log in.
    status = str(row["status"] if "status" in row.keys() else "active") or "active"
    role = str(row["role"])
    owner_admin = str(row["username"]) if role == "admin" else str(row["manager_admin"] or "")
    if status == "disabled":
        dis_detail = dict(ctx)
        dis_detail["owner_admin"] = owner_admin
        dis_detail["login_user"] = str(row["username"])
        audit_event(f"ip:{ip}", "auth.login.disabled", str(row["username"]), dis_detail)
        raise HTTPException(status_code=403, detail="account disabled")
    if status == "pending":
        raise HTTPException(status_code=403, detail="account not activated yet — please enter the verification code sent to your email")
    if status == "awaiting_approval":
        raise HTTPException(status_code=403, detail="account awaiting superadmin approval")
    _clear_login_failures(body.username)
    _clear_login_ip_state(ip)
    zones = zones_from_json(str(row["allowed_zones_json"]))
    token = issue_jwt(str(row["username"]), str(row["role"]), zones)
    csrf_tok = ""
    if JWT_USE_HTTPONLY_COOKIE:
        response.set_cookie(
            key=JWT_COOKIE_NAME,
            value=token,
            max_age=int(JWT_EXPIRE_S),
            path="/",
            httponly=True,
            secure=bool(JWT_COOKIE_SECURE),
            samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
        )
        # Paired CSRF token — required on every cookie-authenticated write.
        csrf_tok = _set_csrf_cookie(response)
    ok_detail = dict(ctx)
    ok_detail["owner_admin"] = owner_admin
    ok_detail["login_user"] = str(row["username"])
    audit_event(str(row["username"]), "auth.login.ok", str(row["username"]), ok_detail)
    # One-time welcome email after first successful login. Runs in a background
    # thread so a slow SMTP server never stalls the login response (was seen as
    # "sometimes login freezes").
    try:
        email_u = str(row["email"] or "").strip()
        rk = row.keys()
        wel_sent = int(row["welcome_email_sent"] or 0) if "welcome_email_sent" in rk else 0
        if notifier.enabled() and email_u and wel_sent == 0:
            uname_snap = str(row["username"])
            role_snap = str(row["role"])

            def _send_welcome_async() -> None:
                try:
                    ws, wt, wh = render_welcome_email(username=uname_snap, role=role_snap)
                    # Prefer the async enqueue if available (non-blocking + retried).
                    if hasattr(notifier, "enqueue"):
                        try:
                            notifier.enqueue([email_u], ws, wt, wh)
                        except Exception:
                            notifier.send_sync([email_u], ws, wt, wh)
                    else:
                        notifier.send_sync([email_u], ws, wt, wh)
                    with db_lock:
                        c2 = get_conn()
                        cu2 = c2.cursor()
                        cu2.execute(
                            "UPDATE dashboard_users SET welcome_email_sent = 1 WHERE username = ?",
                            (uname_snap,),
                        )
                        c2.commit()
                        c2.close()
                except Exception:
                    logger.warning("welcome email skipped or failed for %s", uname_snap, exc_info=True)

            threading.Thread(target=_send_welcome_async, name=f"welcome-mail-{uname_snap}", daemon=True).start()
    except Exception:
        logger.warning("welcome email scheduling failed for %s", body.username, exc_info=True)
    out: dict[str, Any] = {"token_type": "bearer", "role": row["role"], "zones": zones}
    if JWT_RETURN_BODY_TOKEN or not JWT_USE_HTTPONLY_COOKIE:
        out["access_token"] = token
    if csrf_tok:
        # Also echo the CSRF token in the JSON body so SPA clients that ignore
        # document.cookie (for whatever reason) can still bootstrap the header.
        out["csrf_token"] = csrf_tok
    return out


@app.get("/auth/csrf")
def auth_csrf(
    response: Response,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """
    Refresh / read the paired CSRF token for the signed-in session.

    The SPA calls this on boot (or whenever it notices the header is rejected)
    to re-sync its double-submit token without forcing a logout-login cycle.
    """
    tok = _set_csrf_cookie(response)
    return {"csrf_token": tok, "header": CSRF_HEADER_NAME}


@app.post("/auth/logout")
def auth_logout(response: Response) -> dict[str, Any]:
    """Clear HttpOnly session cookie (no auth required)."""
    response.delete_cookie(
        JWT_COOKIE_NAME,
        path="/",
        secure=bool(JWT_COOKIE_SECURE),
        httponly=True,
        samesite=JWT_COOKIE_SAMESITE,  # type: ignore[arg-type]
    )
    _clear_csrf_cookie(response)
    return {"ok": True}


def _norm_mac_nocolon12(raw: str) -> str:
    s = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    return s[:12].upper() if len(s) >= 12 else ""


def _provision_row_for_device_mac(device_id: str, mac12: str) -> Optional[sqlite3.Row]:
    """Return provisioned_credentials row when device_id and MAC both match (anti impersonation)."""
    if len(mac12) != 12:
        return None
    did = (device_id or "").strip()
    if not did:
        return None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_id, mac_nocolon, mqtt_username, mqtt_password, cmd_key, zone, qr_code
            FROM provisioned_credentials
            WHERE UPPER(device_id) = UPPER(?) AND UPPER(mac_nocolon) = UPPER(?)
            LIMIT 1
            """,
            (did, mac12),
        )
        row = cur.fetchone()
        conn.close()
    return row


class DeviceBootSyncRequest(BaseModel):
    device_id: str = Field(min_length=3, max_length=40)
    mac_nocolon: str = Field(min_length=12, max_length=24)
    cmd_key: str = Field(default="", max_length=32)
    fw: str = Field(default="", max_length=48)


class DeviceOtaReportRequest(BaseModel):
    device_id: str = Field(min_length=3, max_length=40)
    mac_nocolon: str = Field(min_length=12, max_length=24)
    cmd_key: str = Field(default="", max_length=32)
    ok: bool
    detail: str = Field(default="", max_length=480)
    campaign_id: str = Field(default="", max_length=120)
    target_fw: str = Field(default="", max_length=48)
    current_fw: str = Field(default="", max_length=48)


@app.post("/device/boot-sync")
def device_boot_sync(body: DeviceBootSyncRequest) -> dict[str, Any]:
    """Device HTTP: verify NVS cmd_key vs DB; return resync payload when mismatched (MAC+device_id bound)."""
    mac = _norm_mac_nocolon12(body.mac_nocolon)
    if len(mac) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    row = _provision_row_for_device_mac(body.device_id, mac)
    if not row:
        return {"status": "unprovisioned"}
    did = str(row["device_id"])
    db_key = str(row["cmd_key"] or "").strip().upper()
    rep = (body.cmd_key or "").strip().upper()
    if rep and is_hex_16(rep) and rep == db_key:
        return {"status": "ok"}
    owner = _lookup_owner_admin(did) or ""
    emit_event(
        level="warn",
        category="provision",
        event_type="device.boot_sync.resync",
        summary=f"boot-sync resync {did}",
        actor=f"device:{did}",
        target=did,
        owner_admin=owner or None,
        device_id=did,
        detail={"fw": (body.fw or "").strip(), "had_cmd_key": bool(rep)},
    )
    audit_event(
        f"device:{did}",
        "device.boot_sync.resync",
        did,
        {"mac_nocolon": mac, "fw": (body.fw or "").strip()},
    )
    return {
        "status": "resync",
        "cmd_key": db_key,
        "mqtt_username": str(row["mqtt_username"] or ""),
        "mqtt_password": str(row["mqtt_password"] or ""),
        "zone": str(row["zone"] or "all").strip() or "all",
        "qr_code": str(row["qr_code"] or ""),
    }


@app.post("/device/ota/report")
def device_ota_report(body: DeviceOtaReportRequest) -> dict[str, Any]:
    """Device HTTP: OTA outcome (duplicate path alongside MQTT ota.result for post-OTA recovery)."""
    mac = _norm_mac_nocolon12(body.mac_nocolon)
    if len(mac) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    row = _provision_row_for_device_mac(body.device_id, mac)
    if not row:
        raise HTTPException(status_code=404, detail="device not provisioned")
    did = str(row["device_id"])
    db_key = str(row["cmd_key"] or "").strip().upper()
    rep = (body.cmd_key or "").strip().upper()
    if rep and (not is_hex_16(rep) or rep != db_key):
        raise HTTPException(status_code=403, detail="cmd_key does not match server")
    owner = _lookup_owner_admin(did) or ""
    payload: dict[str, Any] = {
        "type": "ota.result",
        "ok": bool(body.ok),
        "detail": (body.detail or "")[:240],
        "campaign_id": (body.campaign_id or "").strip(),
        "target_fw": (body.target_fw or "").strip(),
        "current_fw": (body.current_fw or "").strip(),
    }
    cid = str(payload.get("campaign_id") or "")
    if cid and not cid.endswith("#rollback"):
        _handle_ota_result_safe(did, payload)
    else:
        emit_event(
            level="info" if body.ok else "warn",
            category="ota",
            event_type="ota.device.http_report",
            summary=f"{did} ota http report ok={body.ok}",
            actor=f"device:{did}",
            target=owner or None,
            owner_admin=owner or None,
            device_id=did,
            detail=payload,
        )
    return {"ok": True, "status": "recorded"}


@app.get("/auth/me")
def auth_me(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    alarm_push_style = "fullscreen"
    avatar_url = ""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(alarm_push_style,'fullscreen') AS s, IFNULL(avatar_url,'') AS a FROM dashboard_users WHERE username = ?",
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if row:
        alarm_push_style = str(row["s"] or "fullscreen").strip() or "fullscreen"
        avatar_url = str(row["a"] or "").strip()
    return {
        "username": principal.username,
        "role": principal.role,
        "zones": principal.zones,
        "policy": get_effective_policy(principal),
        "manager_admin": get_manager_admin(principal.username) if principal.role == "user" else "",
        "alarm_push_style": alarm_push_style,
        "avatar_url": avatar_url,
    }


@app.post("/auth/me/fcm-token")
def auth_me_fcm_token_register(
    body: FcmTokenRegisterRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Register or refresh one FCM device token for the signed-in user."""
    assert_min_role(principal, "user")
    tok = body.token.strip()
    plat = (body.platform or "").strip().lower()[:32]
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_fcm_tokens (username, token, platform, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(username, token) DO UPDATE SET
              platform = excluded.platform,
              updated_at = excluded.updated_at
            """,
            (principal.username, tok, plat, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "auth.fcm_token.upsert", principal.username, {"platform": plat})
    return {"ok": True}


@app.delete("/auth/me/fcm-token")
def auth_me_fcm_token_delete(
    body: FcmTokenDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    tok = body.token.strip()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM user_fcm_tokens WHERE username = ? AND token = ?", (principal.username, tok))
        n = cur.rowcount
        conn.commit()
        conn.close()
    audit_event(principal.username, "auth.fcm_token.delete", principal.username, {"removed": int(n or 0)})
    return {"ok": True, "removed": int(n or 0)}


@app.post("/auth/me/fcm-token/delete")
def auth_me_fcm_token_delete_post(
    body: FcmTokenDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Same as DELETE /auth/me/fcm-token when reverse proxies drop DELETE bodies."""
    return auth_me_fcm_token_delete(body, principal)


@app.get("/auth/me/notification-prefs")
def auth_me_notification_prefs_get(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(alarm_push_style,'fullscreen') AS s FROM dashboard_users WHERE username = ?",
            (principal.username,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"alarm_push_style": str(row["s"] or "fullscreen")}


@app.patch("/auth/me/notification-prefs")
def auth_me_notification_prefs_patch(
    body: NotificationPrefsPatchRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE dashboard_users SET alarm_push_style = ? WHERE username = ?",
            (body.alarm_push_style, principal.username),
        )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "auth.notification_prefs.patch",
        principal.username,
        {"alarm_push_style": body.alarm_push_style},
    )
    return {"ok": True, "alarm_push_style": body.alarm_push_style}


@app.patch("/auth/me/profile")
def auth_me_profile_patch(
    body: MeProfilePatchRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    val = _validate_avatar_url(body.avatar_url)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE dashboard_users SET avatar_url = ? WHERE username = ?", (val or None, principal.username))
        if cur.rowcount == 0:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "auth.profile.patch",
        principal.username,
        {"avatar_set": bool(val)},
    )
    return {"ok": True, "avatar_url": val}


@app.patch("/auth/me/password")
def auth_me_change_password(body: SelfPasswordChangeRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if body.new_password != body.new_password_confirm:
        raise HTTPException(status_code=400, detail="new password confirmation does not match")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="new password must be different")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, role, email FROM dashboard_users WHERE username = ?",
            (principal.username,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if not verify_password(body.current_password, str(row["password_hash"])):
            conn.close()
            raise HTTPException(status_code=401, detail="current password invalid")
        rk = row.keys()
        notify_email = str(row["email"] or "").strip() if "email" in rk else ""
        cur.execute(
            "UPDATE dashboard_users SET password_hash = ? WHERE username = ?",
            (hash_password(body.new_password), principal.username),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "auth.password.change", principal.username, {})
    if notify_email and notifier.enabled():
        try:
            ps, pt, ph = render_password_changed_email(username=principal.username, iso_ts=malaysia_now_iso())
            notifier.send_sync([notify_email], ps, pt, ph)
        except Exception:
            logger.warning("password-changed email failed for %s", principal.username, exc_info=True)
    return {"ok": True}


def _auth_me_delete_impl(body: SelfDeleteRequest, principal: Principal) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if _normalize_delete_confirm(body.confirm_text) != "DELETE":
        raise HTTPException(status_code=400, detail="confirm_text must be exactly: DELETE")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT password_hash, role FROM dashboard_users WHERE username = ?", (principal.username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if not verify_password(body.password, str(row["password_hash"])):
            conn.close()
            raise HTTPException(status_code=401, detail="password invalid")
        role = str(row["role"] or "")
        if role == "superadmin":
            conn.close()
            raise HTTPException(status_code=400, detail="superadmin account cannot be deleted via self-service")
        if role == "admin":
            if not body.acknowledge_admin_tenant_closure:
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail="admin tenant closure requires acknowledge_admin_tenant_closure=true "
                    "(all owned devices unclaimed to factory; subordinate users removed; email released)",
                )
            summary = _close_admin_tenant_cur(cur, principal.username, None, principal.username)
            conn.commit()
            conn.close()
            cache_invalidate("devices")
            cache_invalidate("overview")
            audit_event(principal.username, "auth.account.delete.admin_tenant", principal.username, summary)
            return {"ok": True, **summary}
        _delete_user_auxiliary_cur(cur, principal.username)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "auth.account.delete.self", principal.username, {})
    return {"ok": True}


@app.delete("/auth/me")
def auth_me_delete(body: SelfDeleteRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Self-service account deletion. Prefer POST /auth/me/delete behind proxies that strip DELETE bodies."""
    return _auth_me_delete_impl(body, principal)


@app.post("/auth/me/delete")
def auth_me_delete_post(body: SelfDeleteRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Same as DELETE /auth/me — JSON body is reliably forwarded by nginx/CDN stacks."""
    return _auth_me_delete_impl(body, principal)


@app.get("/auth/admins")
def auth_list_admins(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """For superadmin only. Returns admins usable as manager_admin."""
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username FROM dashboard_users WHERE role IN ('admin','superadmin') ORDER BY username ASC"
        )
        rows = [str(r["username"]) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.post("/auth/admins/{username}/close")
def auth_close_admin_tenant(
    username: str,
    body: AdminTenantCloseRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Superadmin: close an admin tenant — unclaim devices (or transfer to another admin) and delete the admin."""
    assert_min_role(principal, "superadmin")
    if body.confirm_text.strip() != "CLOSE TENANT":
        raise HTTPException(status_code=400, detail="confirm_text must be exactly: CLOSE TENANT")
    target = username.strip()
    if secrets.compare_digest(target, principal.username):
        raise HTTPException(status_code=400, detail="use Account page to close your own tenant if you are an admin")
    transfer_to = (body.transfer_devices_to or "").strip() or None
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        summary = _close_admin_tenant_cur(cur, target, transfer_to, principal.username)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "auth.admin.tenant.close", target, summary)
    return {"ok": True, **summary}


@app.get("/auth/users")
def auth_list_users(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                "SELECT username, role, allowed_zones_json, manager_admin, tenant, created_at FROM dashboard_users ORDER BY username ASC"
            )
        else:
            cur.execute(
                """
                SELECT username, role, allowed_zones_json, manager_admin, tenant, created_at
                FROM dashboard_users
                WHERE role = 'user' AND manager_admin = ?
                ORDER BY username ASC
                """,
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        r["zones"] = zones_from_json(str(r.pop("allowed_zones_json")))
    return {"items": rows}


@app.post("/auth/users")
def auth_create_user(req: UserCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    # Hard guard: nobody can make a superadmin via the API even by forging role.
    if req.role == "superadmin":
        raise HTTPException(status_code=403, detail="superadmin is not creatable via API")
    if principal.role == "admin" and req.role != "user":
        raise HTTPException(status_code=403, detail="admin can only create user role")
    # admin-created users MUST have an email so the activation code can be sent.
    # (phone is optional; see REQUIRE_PHONE_VERIFICATION env flag)
    if not req.email:
        raise HTTPException(status_code=400, detail="email is required")
    email_norm = req.email.strip().lower()
    if not _looks_like_email(email_norm):
        raise HTTPException(status_code=400, detail="email format invalid")
    phone_norm = _normalize_phone(req.phone) if req.phone else None
    if REQUIRE_PHONE_VERIFICATION and not phone_norm:
        raise HTTPException(status_code=400, detail="phone is required")
    now = utc_now_iso()
    zones_json = json.dumps(req.zones, ensure_ascii=True)
    manager_admin = req.manager_admin or (principal.username if principal.role == "admin" else "")
    if req.role == "admin":
        manager_admin = ""
    if req.role == "user" and not manager_admin:
        raise HTTPException(status_code=400, detail="manager_admin is required when creating a user role")
    if req.role == "user":
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT role FROM dashboard_users WHERE username = ?",
                (manager_admin,),
            )
            mrow = cur.fetchone()
            conn.close()
        if not mrow or str(mrow["role"]) not in ("admin", "superadmin"):
            raise HTTPException(status_code=400, detail="manager_admin must be an existing admin/superadmin")
    tenant = req.tenant or (principal.username if principal.role == "admin" else (manager_admin or req.username))
    initial_status = "pending"  # activation code will flip to 'active'
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO dashboard_users (
                    username, password_hash, role, allowed_zones_json,
                    manager_admin, tenant, email, phone, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.username,
                    hash_password(req.password),
                    req.role,
                    zones_json,
                    manager_admin,
                    tenant,
                    email_norm,
                    phone_norm,
                    initial_status,
                    now,
                ),
            )
            pol = default_policy_for_role(req.role)
            cur.execute(
                """
                INSERT INTO role_policies (username, can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                  can_alert=excluded.can_alert,
                  can_send_command=excluded.can_send_command,
                  can_claim_device=excluded.can_claim_device,
                  can_manage_users=excluded.can_manage_users,
                  can_backup_restore=excluded.can_backup_restore,
                  updated_at=excluded.updated_at
                """,
                (
                    req.username,
                    pol["can_alert"],
                    pol["can_send_command"],
                    pol["can_claim_device"],
                    pol["can_manage_users"],
                    pol["can_backup_restore"],
                    now,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="username exists")
        conn.close()
    cache_invalidate("devices")
    audit_event(principal.username, "user.create", req.username, {
        "role": req.role, "zones": req.zones, "email": email_norm, "phone": bool(phone_norm),
    })
    # Send activation OTPs. We don't fail user creation if SMTP is down — the
    # admin can click "re-send code" from the dashboard.
    activation_msg = ""
    try:
        _issue_verification(req.username, "email", email_norm, purpose="activate")
        activation_msg = "Email verification code sent."
    except Exception as exc:
        logger.warning("email OTP issue failed for %s: %s", req.username, exc)
        activation_msg = f"Email code not sent: {exc}"
    if phone_norm:
        try:
            _issue_verification(req.username, "phone", phone_norm, purpose="activate")
            activation_msg += " SMS code sent."
        except Exception as exc:
            logger.warning("phone OTP issue failed for %s: %s", req.username, exc)
    return {
        "ok": True,
        "username": req.username,
        "status": initial_status,
        "message": activation_msg,
    }


@app.delete("/auth/users/{username}")
def auth_delete_user(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    if secrets.compare_digest(username, principal.username):
        raise HTTPException(status_code=400, detail="cannot delete self")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "admin":
            cur.execute("SELECT role, manager_admin FROM dashboard_users WHERE username = ?", (username,))
            row = cur.fetchone()
            if not row:
                conn.close()
                raise HTTPException(status_code=404, detail="user not found")
            if str(row["role"]) != "user" or str(row["manager_admin"] or "") != principal.username:
                conn.close()
                raise HTTPException(status_code=403, detail="cannot delete this user")
        else:
            cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (username,))
            row = cur.fetchone()
            if not row:
                conn.close()
                raise HTTPException(status_code=404, detail="user not found")
            if str(row["role"] or "") == "admin":
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail="use POST /auth/admins/{username}/close to remove an admin tenant",
                )
        cur.execute("SELECT username FROM dashboard_users WHERE username = ?", (username,))
        exists = cur.fetchone()
        if not exists:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        _delete_user_auxiliary_cur(cur, username)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "user.delete", username, {})
    return {"ok": True}


@app.get("/auth/users/{username}/policy")
def auth_get_user_policy(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, role, manager_admin FROM dashboard_users WHERE username = ?", (username,))
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if principal.role == "admin" and (str(u["role"]) != "user" or str(u["manager_admin"] or "") != principal.username):
            conn.close()
            raise HTTPException(status_code=403, detail="not your managed user")
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk,
                   updated_at
            FROM role_policies WHERE username = ?
            """,
            (username,),
        )
        p = cur.fetchone()
        conn.close()
    if not p:
        out = default_policy_for_role(str(u["role"]))
        out["updated_at"] = ""
        return out
    return dict(p)


@app.put("/auth/users/{username}/policy")
def auth_set_user_policy(
    username: str,
    req: UserPolicyUpdateRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, role, manager_admin FROM dashboard_users WHERE username = ?", (username,))
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(status_code=404, detail="user not found")
        if str(u["role"]) != "user":
            conn.close()
            raise HTTPException(status_code=400, detail="policy endpoint is for user role")
        if principal.role == "admin" and str(u["manager_admin"] or "") != principal.username:
            conn.close()
            raise HTTPException(status_code=403, detail="not your managed user")
        base = default_policy_for_role("user")
        cur.execute(
            """
            SELECT can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                   tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk
            FROM role_policies WHERE username = ?
            """,
            (username,),
        )
        curp = cur.fetchone()
        if curp:
            for k in base.keys():
                base[k] = int(curp[k])
        updates = {
            "can_alert": req.can_alert,
            "can_send_command": req.can_send_command,
            "can_claim_device": req.can_claim_device,
            "can_manage_users": req.can_manage_users,
            "can_backup_restore": req.can_backup_restore,
            "tg_view_logs": req.tg_view_logs,
            "tg_view_devices": req.tg_view_devices,
            "tg_siren_on": req.tg_siren_on,
            "tg_siren_off": req.tg_siren_off,
            "tg_test_single": req.tg_test_single,
            "tg_test_bulk": req.tg_test_bulk,
        }
        for k, v in updates.items():
            if v is not None:
                base[k] = 1 if v else 0
        # guardrail: regular users never get backup/manage_users
        base["can_backup_restore"] = 0
        base["can_manage_users"] = 0
        cur.execute(
            """
            INSERT INTO role_policies (
                username, can_alert, can_send_command, can_claim_device, can_manage_users, can_backup_restore,
                tg_view_logs, tg_view_devices, tg_siren_on, tg_siren_off, tg_test_single, tg_test_bulk, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                can_alert=excluded.can_alert,
                can_send_command=excluded.can_send_command,
                can_claim_device=excluded.can_claim_device,
                can_manage_users=excluded.can_manage_users,
                can_backup_restore=excluded.can_backup_restore,
                tg_view_logs=excluded.tg_view_logs,
                tg_view_devices=excluded.tg_view_devices,
                tg_siren_on=excluded.tg_siren_on,
                tg_siren_off=excluded.tg_siren_off,
                tg_test_single=excluded.tg_test_single,
                tg_test_bulk=excluded.tg_test_bulk,
                updated_at=excluded.updated_at
            """,
            (
                username,
                base["can_alert"],
                base["can_send_command"],
                base["can_claim_device"],
                base["can_manage_users"],
                base["can_backup_restore"],
                base["tg_view_logs"],
                base["tg_view_devices"],
                base["tg_siren_on"],
                base["tg_siren_off"],
                base["tg_test_single"],
                base["tg_test_bulk"],
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "user.policy.update", username, base)
    return {"ok": True, "username": username, "policy": base}


@app.get("/admin/backup/export")
def admin_backup_export(
    principal: Principal = Depends(require_principal),
    x_backup_key: str = Header(..., alias="X-Backup-Encryption-Key"),
) -> Response:
    assert_min_role(principal, "superadmin")
    if not os.path.isfile(DB_PATH):
        raise HTTPException(status_code=404, detail="database file not found")
    with open(DB_PATH, "rb") as f:
        raw = f.read()
    if len(raw) < 16 or raw[:15] != b"SQLite format 3":
        raise HTTPException(status_code=500, detail="database file invalid")
    enc = encrypt_blob(raw, x_backup_key)
    return Response(
        content=enc,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="sentinel-backup.enc"'},
    )


@app.post("/admin/backup/import")
async def admin_backup_import(
    principal: Principal = Depends(require_principal),
    x_backup_key: str = Header(..., alias="X-Backup-Encryption-Key"),
    file: UploadFile = File(...),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    body = await file.read()
    plain = decrypt_blob(body, x_backup_key)
    if len(plain) < 16 or plain[:15] != b"SQLite format 3":
        raise HTTPException(status_code=400, detail="decrypted payload is not sqlite")
    out_path = DB_PATH + ".restored"
    with open(out_path, "wb") as f:
        f.write(plain)
    return {
        "ok": True,
        "written_path": out_path,
        "hint": "Stop the API container, replace the live DB file with this path, then start again (see docs).",
    }


@app.post("/provision/challenge/request")
def provision_challenge_request(
    req: DeviceChallengeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    device_id = req.device_id.strip().upper()
    mac_nocolon = req.mac_nocolon.strip().upper()
    if not re.fullmatch(DEVICE_ID_REGEX, device_id):
        raise HTTPException(status_code=400, detail="device_id format rejected by policy")
    nonce = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + DEVICE_CHALLENGE_TTL_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_identities (device_id, mac_nocolon, public_key_pem, attestation_json, registered_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                mac_nocolon = excluded.mac_nocolon,
                public_key_pem = excluded.public_key_pem,
                attestation_json = excluded.attestation_json,
                registered_at = excluded.registered_at
            """,
            (
                device_id,
                mac_nocolon,
                req.public_key_pem,
                json.dumps(req.attestation or {}, ensure_ascii=True),
                utc_now_iso(),
            ),
        )
        cur.execute(
            """
            INSERT INTO provision_challenges (mac_nocolon, device_id, nonce, expires_at_ts, verified_at, used)
            VALUES (?, ?, ?, ?, NULL, 0)
            """,
            (mac_nocolon, device_id, nonce, expires_at),
        )
        challenge_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    audit_event(principal.username, "challenge.request", device_id, {"challenge_id": challenge_id})
    return {"challenge_id": challenge_id, "nonce": nonce, "expires_at_ts": expires_at}


@app.post("/provision/challenge/verify")
def provision_challenge_verify(
    req: DeviceChallengeVerifyRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.id, c.device_id, c.nonce, c.expires_at_ts, c.used, i.public_key_pem
            FROM provision_challenges c
            JOIN device_identities i ON c.device_id = i.device_id
            WHERE c.id = ?
            """,
            (req.challenge_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="challenge not found")
        if int(row["used"]) == 1:
            conn.close()
            raise HTTPException(status_code=409, detail="challenge already used")
        if int(time.time()) > int(row["expires_at_ts"]):
            conn.close()
            raise HTTPException(status_code=410, detail="challenge expired")
        ok = verify_device_signature(str(row["public_key_pem"]), str(row["nonce"]), req.signature_b64)
        if not ok:
            conn.close()
            raise HTTPException(status_code=401, detail="device signature verification failed")
        cur.execute(
            "UPDATE provision_challenges SET verified_at = ? WHERE id = ?",
            (utc_now_iso(), req.challenge_id),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "challenge.verify", str(row["device_id"]), {"challenge_id": req.challenge_id})
    return {"ok": True, "device_id": row["device_id"], "challenge_id": req.challenge_id}


@app.get("/devices/revoked")
def list_revoked_devices(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("SELECT device_id, reason, revoked_by, revoked_at FROM revoked_devices ORDER BY revoked_at DESC")
        else:
            cur.execute(
                """
                SELECT r.device_id, r.reason, r.revoked_by, r.revoked_at
                FROM revoked_devices r
                JOIN device_ownership o ON r.device_id = o.device_id
                WHERE o.owner_admin = ?
                ORDER BY r.revoked_at DESC
                """,
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.post("/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    req: DeviceRevokeRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO revoked_devices (device_id, reason, revoked_by, revoked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                reason = excluded.reason,
                revoked_by = excluded.revoked_by,
                revoked_at = excluded.revoked_at
            """,
            (device_id, req.reason, principal.username, utc_now_iso()),
        )
        cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
        deleted_acl_rows = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(
        principal.username,
        "device.revoke",
        device_id,
        {"reason": req.reason, "deleted_device_acl_rows": deleted_acl_rows},
    )
    return {"ok": True, "device_id": device_id}


@app.post("/devices/{device_id}/unrevoke")
def unrevoke_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "device.unrevoke", device_id, {})
    return {"ok": True, "device_id": device_id}


def _delete_user_auxiliary_cur(cur: Any, username: str) -> None:
    """Remove dashboard user row and attached rows (not device ownership)."""
    cur.execute("DELETE FROM role_policies WHERE username = ?", (username,))
    cur.execute("DELETE FROM verifications WHERE username = ?", (username,))
    cur.execute("DELETE FROM device_acl WHERE grantee_username = ?", (username,))
    cur.execute("DELETE FROM telegram_chat_bindings WHERE username = ?", (username,))
    cur.execute("DELETE FROM telegram_link_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM user_fcm_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM password_reset_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))
    # If the deleted user was a superadmin, the cached chat list is stale;
    # same for the username->role cache.
    _invalidate_superadmin_telegram_chats_cache()


def _apply_device_factory_unclaim_cur(cur: Any, device_id: str) -> None:
    """Same data effect as factory-unregister: unclaim in DB + factory_devices status (caller holds lock)."""
    cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (device_id,))
    p = cur.fetchone()
    mac_nocolon = str(p["mac_nocolon"]) if p and p["mac_nocolon"] else ""
    cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
    cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
    if mac_nocolon:
        cur.execute(
            "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE mac_nocolon = ?",
            (utc_now_iso(), mac_nocolon),
        )
    else:
        cur.execute(
            "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE serial = ?",
            (utc_now_iso(), device_id),
        )


def _close_admin_tenant_cur(
    cur: Any,
    admin_username: str,
    transfer_devices_to: Optional[str],
    actor_username: str,
) -> dict[str, Any]:
    """
    admin_username: role must be 'admin'. Transfers or unclaims all owned devices, deletes
    subordinate users, then deletes the admin row. Does not commit.
    """
    cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (admin_username,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    role = str(row["role"] or "")
    if role == "superadmin":
        raise HTTPException(status_code=400, detail="cannot close a superadmin account with this action")
    if role != "admin":
        raise HTTPException(status_code=400, detail="target is not an admin tenant")
    summary: dict[str, Any] = {
        "admin": admin_username,
        "devices_unclaimed": 0,
        "devices_transferred": 0,
        "subordinate_users_deleted": 0,
    }
    transfer_to = (transfer_devices_to or "").strip() or None
    if transfer_to:
        cur.execute("SELECT role FROM dashboard_users WHERE username = ?", (transfer_to,))
        trow = cur.fetchone()
        if not trow or str(trow["role"] or "") not in ("admin", "superadmin"):
            raise HTTPException(status_code=400, detail="transfer_devices_to must be an existing admin or superadmin")
        if secrets.compare_digest(transfer_to, admin_username):
            raise HTTPException(status_code=400, detail="cannot transfer to the same admin")
        cur.execute("SELECT device_id FROM device_ownership WHERE owner_admin = ?", (admin_username,))
        transfer_ids = [str(r["device_id"]) for r in cur.fetchall() if r and r["device_id"]]
        cur.execute(
            """
            UPDATE device_ownership
            SET owner_admin = ?, assigned_by = ?, assigned_at = ?
            WHERE owner_admin = ?
            """,
            (transfer_to, actor_username, utc_now_iso(), admin_username),
        )
        summary["devices_transferred"] = int(cur.rowcount or 0)
        if transfer_ids:
            ph = ",".join("?" * len(transfer_ids))
            cur.execute(
                f"UPDATE device_state SET display_label = '', notification_group = '' WHERE device_id IN ({ph})",
                transfer_ids,
            )
    else:
        cur.execute("SELECT device_id FROM device_ownership WHERE owner_admin = ?", (admin_username,))
        for r in cur.fetchall():
            did = str(r["device_id"] or "")
            if not did:
                continue
            _apply_device_factory_unclaim_cur(cur, did)
            summary["devices_unclaimed"] += 1
    cur.execute(
        "SELECT username FROM dashboard_users WHERE manager_admin = ? AND role = 'user'",
        (admin_username,),
    )
    for r in cur.fetchall():
        su = str(r["username"] or "")
        if su:
            _delete_user_auxiliary_cur(cur, su)
            summary["subordinate_users_deleted"] += 1
    _delete_user_auxiliary_cur(cur, admin_username)
    return summary


def _wait_cmd_ack(device_id: str, cmd: str, timeout_s: float = 2.5, cmd_id: Optional[str] = None) -> bool:
    deadline = time.time() + max(0.2, float(timeout_s))
    cid = (cmd_id or "").strip()
    while time.time() < deadline:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT IFNULL(last_ack_json,'') AS last_ack_json FROM device_state WHERE device_id = ?", (device_id,))
            row = cur.fetchone()
            conn.close()
        try:
            ack = json.loads(str((row["last_ack_json"] if row else "") or ""))
        except Exception:
            ack = {}
        if str(ack.get("cmd") or "") != cmd or not bool(ack.get("ok")):
            time.sleep(0.12)
            continue
        if cid and str(ack.get("cmd_id") or "") != cid:
            time.sleep(0.12)
            continue
        return True
    return False


def _try_mqtt_unclaim_reset(device_id: str) -> tuple[bool, bool]:
    """Best-effort dispatch + short ack wait for unclaim_reset before DB unlink.

    Returns (sent, acked). Fails fast (no blocking) when the broker is down or
    the device is offline — the HTTP request must not hang for a dead device.
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 1 AS ok,
                   IFNULL((SELECT updated_at FROM device_state WHERE device_id = pc.device_id),'') AS updated_at
            FROM provisioned_credentials pc
            WHERE pc.device_id = ?
            """,
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        return False, False
    last_seen = str(row["updated_at"] or "")
    # If the device hasn't been seen recently, skip the ACK wait entirely.
    # The command is still published (broker queues for QoS 1), but the HTTP caller
    # won't block waiting for an ACK that's never coming.
    online_hint = False
    try:
        last_ts = _parse_iso(last_seen)
        if last_ts > 0:
            online_hint = (time.time() - last_ts) < max(60, int(OFFLINE_THRESHOLD_SECONDS))
    except Exception:
        online_hint = False
    try:
        cmd_id = publish_command(
            f"{TOPIC_ROOT}/{device_id}/cmd",
            "unclaim_reset",
            {},
            device_id,
            CMD_PROTO,
            get_cmd_key_for_device(device_id),
            dedupe_key=f"unclaim_reset:{device_id}",
        )
    except HTTPException as exc:
        # 503 = broker disconnected → no MQTT, don't wait.
        logger.warning("unclaim_reset MQTT not delivered for %s: %s", device_id, getattr(exc, "detail", exc))
        return False, False
    except Exception as exc:
        logger.warning("unclaim_reset MQTT error for %s: %s", device_id, exc)
        return False, False
    if not online_hint:
        return True, False
    return True, _wait_cmd_ack(device_id, "unclaim_reset", timeout_s=2.2, cmd_id=cmd_id)


def _device_delete_reset_impl(
    device_id: str,
    principal: Principal,
    req: DeviceDeleteRequest,
    *,
    super_unclaim: bool,
) -> dict[str, Any]:
    if str(req.confirm_text or "").strip().upper() != str(device_id or "").strip().upper():
        raise HTTPException(status_code=400, detail="confirm_text must exactly match device_id")
    require_capability(principal, "can_send_command")
    if super_unclaim:
        # Factory rollback: admin+ only (not subordinate "user" accounts).
        assert_min_role(principal, "admin")
        if not principal.is_superadmin():
            assert_device_owner(principal, device_id)
    else:
        assert_min_role(principal, "user")
        assert_device_owner(principal, device_id)
    nvs_purge_sent, nvs_purge_acked = _try_mqtt_unclaim_reset(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        p = cur.fetchone()
        mac_nocolon = str(p["mac_nocolon"]) if p and p["mac_nocolon"] else ""
        cur.execute("DELETE FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        del_cred = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_ownership WHERE device_id = ?", (device_id,))
        del_owner = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_acl WHERE device_id = ?", (device_id,))
        del_acl = int(cur.rowcount or 0)
        cur.execute("DELETE FROM revoked_devices WHERE device_id = ?", (device_id,))
        del_revoked = int(cur.rowcount or 0)
        cur.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
        del_state = int(cur.rowcount or 0)
        cur.execute("DELETE FROM scheduled_commands WHERE device_id = ?", (device_id,))
        del_sched = int(cur.rowcount or 0)
        if super_unclaim:
            if mac_nocolon:
                cur.execute(
                    "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE mac_nocolon = ?",
                    (utc_now_iso(), mac_nocolon),
                )
            else:
                cur.execute(
                    "UPDATE factory_devices SET status='unclaimed', updated_at=? WHERE serial = ?",
                    (utc_now_iso(), device_id),
                )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    action = "device.factory_unclaim" if super_unclaim else "device.delete_reset"
    audit_event(
        principal.username,
        action,
        device_id,
        {
            "mac_nocolon": mac_nocolon or "",
            "nvs_purge_mqtt": nvs_purge_sent,
            "nvs_purge_ack": nvs_purge_acked,
            "deleted_credentials": del_cred,
            "deleted_owner": del_owner,
            "deleted_acl": del_acl,
            "deleted_revoked": del_revoked,
            "deleted_state": del_state,
            "deleted_scheduled": del_sched,
            "factory_unclaimed": super_unclaim,
        },
    )
    return {
        "ok": True,
        "device_id": device_id,
        "mode": "factory_unclaim" if super_unclaim else "delete_reset",
        "factory_unclaimed": super_unclaim,
        "nvs_purge_sent": nvs_purge_sent,
        "nvs_purge_acked": nvs_purge_acked,
        "nvs_purge_note": "sent=true means command reached broker; acked=true means device confirmed unclaim_reset before DB unlink.",
    }


@app.post("/devices/{device_id}/delete-reset")
def device_delete_reset(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Tenant user (operate) / admin / superadmin: unlink device + best-effort unclaim_reset."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=False)


@app.post("/devices/{device_id}/factory-unregister")
def device_factory_unregister(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Rollback to unregistered while keeping factory serial: superadmin (any device) or owning admin."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=True)


def _health_notify_summary_public() -> tuple[dict[str, Any], dict[str, Any]]:
    """Mail/TG liveness without secrets (for HEALTH_PUBLIC_DETAIL=0). Keeps dashboard pills honest."""
    smtp = {"configured": notifier.enabled(), "worker_running": notifier.worker_alive()}
    tg: dict[str, Any] = {"enabled": False, "worker_running": False, "last_error": ""}
    try:
        from telegram_notify import telegram_status

        full = dict(telegram_status())
        tg = {
            "enabled": bool(full.get("enabled")),
            "worker_running": bool(full.get("worker_running")),
            "last_error": str(full.get("last_error") or "")[:240],
        }
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "last_error": str(exc)[:240]}
    return smtp, tg


def _health_db_probe(timeout_s: float = 1.5) -> dict[str, Any]:
    """Fast DB liveness probe: run `SELECT 1` with a tight budget.
    Returns {ok, latency_ms, error?}. Never raises.
    """
    t0 = time.monotonic()
    out: dict[str, Any] = {"ok": False, "latency_ms": 0}
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            out["ok"] = True
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as exc:
        out["error"] = str(exc)[:240]
    latency_ms = int((time.monotonic() - t0) * 1000)
    out["latency_ms"] = latency_ms
    out["slow"] = latency_ms > int(timeout_s * 1000)
    return out


def _health_subscriber_summary() -> dict[str, Any]:
    try:
        with event_bus._lock:  # noqa: SLF001 — intentional peek
            n = len(event_bus._subs)  # noqa: SLF001
            dropped = sum(int(getattr(s, "dropped", 0)) for s in event_bus._subs.values())  # noqa: SLF001
        return {"count": n, "cap": int(EVENT_MAX_SUBSCRIBERS), "dropped_total": dropped}
    except Exception:
        return {"count": 0, "cap": int(EVENT_MAX_SUBSCRIBERS), "dropped_total": 0}


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness for load balancers / `curl` — intentionally **no** auth so Uptime
    Kuma, Docker healthchecks, and reverse proxies can probe without a token."""
    ready = api_ready_event.is_set() and not api_bootstrap_error
    db_probe = _health_db_probe()
    # Flip `ok` to False when DB is actually stalled — this is the load-balancer
    # signal that says "pull this worker out of rotation".
    db_ok = bool(db_probe.get("ok"))
    subs = _health_subscriber_summary()
    if not HEALTH_PUBLIC_DETAIL:
        smtp, tg = _health_notify_summary_public()
        # MQTT + mail/TG worker truth; FCM/token hints still only when HEALTH_PUBLIC_DETAIL=1.
        body = {
            "ok": bool(ready and db_ok),
            "ready": ready,
            "starting": not api_ready_event.is_set(),
            "db": db_probe,
            "sse_subscribers": subs,
            "mqtt_connected": mqtt_connected,
            "mqtt_ingest_queue_depth": mqtt_ingest_queue.qsize(),
            "mqtt_ingest_dropped": mqtt_ingest_dropped,
            "mqtt_last_connect_at": mqtt_last_connect_at,
            "mqtt_last_disconnect_at": mqtt_last_disconnect_at,
            "mqtt_last_disconnect_reason": mqtt_last_disconnect_reason,
            "smtp": smtp,
            "telegram": tg,
            "ts": int(time.time()),
        }
        if api_bootstrap_error:
            body["bootstrap_error"] = api_bootstrap_error
        return body
    tg: dict[str, Any] = {}
    try:
        from telegram_notify import telegram_status

        tg = dict(telegram_status())
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "error": str(exc)}
    fcm: dict[str, Any] = {}
    try:
        from fcm_notify import fcm_status

        fcm = dict(fcm_status())
    except Exception as exc:
        fcm = {"enabled": False, "error": str(exc), "queue_size": 0, "worker_running": False}
    body = {
        "ok": bool(ready and db_ok),
        "ready": ready,
        "starting": not api_ready_event.is_set(),
        "db": db_probe,
        "sse_subscribers": subs,
        "mqtt_connected": mqtt_connected,
        "mqtt_ingest_queue_depth": mqtt_ingest_queue.qsize(),
        "mqtt_ingest_dropped": mqtt_ingest_dropped,
        "mqtt_last_connect_at": mqtt_last_connect_at,
        "mqtt_last_disconnect_at": mqtt_last_disconnect_at,
        "mqtt_last_disconnect_reason": mqtt_last_disconnect_reason,
        "smtp": {
            "configured": notifier.enabled(),
            "worker_running": notifier.worker_alive(),
        },
        "telegram": tg,
        "fcm": fcm,
        "ts": int(time.time()),
    }
    if api_bootstrap_error:
        body["bootstrap_error"] = api_bootstrap_error
    return body


OFFLINE_THRESHOLD_SECONDS = int(os.getenv("OFFLINE_THRESHOLD_SECONDS", "90"))


def _parse_iso(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _payload_ts(d: dict[str, Any]) -> int:
    """Device JSON `ts` field (epoch seconds or millis fallback before NTP)."""
    t = d.get("ts")
    if isinstance(t, int):
        return t
    if isinstance(t, float):
        return int(t)
    return 0


def _effective_online_for_presence(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
) -> bool:
    """
    True when the device is up on MQTT, even if last /status snapshot is stale.

    Retained LWT (online=false) can remain in last_status_json while newer
    heartbeat, ack, or event traffic (same row `updated_at`) proves the device is back.
    """
    ts_s = _payload_ts(last_status)
    ts_hb = _payload_ts(last_heartbeat)
    ts_a = _payload_ts(last_ack)
    ts_e = _payload_ts(last_event)
    if ts_a > ts_s or ts_e > ts_s:
        return True
    if ts_hb > ts_s:
        return bool(last_heartbeat.get("online"))
    if ts_s == 0 and ts_hb == 0 and ts_a == 0 and ts_e == 0:
        return False
    return bool(last_status.get("online"))


def _device_is_online_parsed(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
    updated_at_iso: str,
    now_s: int,
) -> bool:
    """Same rule as dashboard overview presence: payload truth + row freshness."""
    updated = _parse_iso(str(updated_at_iso or ""))
    fresh = (now_s - updated) < OFFLINE_THRESHOLD_SECONDS
    return _effective_online_for_presence(last_status, last_heartbeat, last_ack, last_event) and fresh


def _device_presence_ages(
    last_status: dict[str, Any],
    last_heartbeat: dict[str, Any],
    last_ack: dict[str, Any],
    last_event: dict[str, Any],
    updated_at_iso: str,
    now_s: int,
) -> dict[str, int]:
    """
    Returns granular age-in-seconds fields for UI/health display.

    Anything we can't compute comes back as -1 (render as "--" in the UI) so
    the frontend never has to invent placeholder values.

    - `last_heartbeat_age_s`: seconds since the device last sent /heartbeat
      (HYBRID mode keepalive or an event heartbeat). -1 before first hb.
    - `last_signal_age_s`: seconds since ANY channel (status/heartbeat/ack/
      event) touched the row — this is the same clock the presence logic
      compares against OFFLINE_THRESHOLD_SECONDS.
    - `last_updated_age_s`: seconds since the DB row's updated_at column.
    """
    def _age(ts: int) -> int:
        if ts <= 0:
            return -1
        return max(0, int(now_s) - int(ts))

    hb_age = _age(_payload_ts(last_heartbeat))
    signal_ts = max(
        _payload_ts(last_status) or 0,
        _payload_ts(last_heartbeat) or 0,
        _payload_ts(last_ack) or 0,
        _payload_ts(last_event) or 0,
    )
    updated = _parse_iso(str(updated_at_iso or ""))
    return {
        "last_heartbeat_age_s": hb_age,
        "last_signal_age_s": _age(signal_ts),
        "last_updated_age_s": _age(int(updated) if updated > 0 else 0),
    }


def _device_is_online_sql_row(row: dict[str, Any], now_s: int) -> bool:
    def _pj(col: str) -> dict[str, Any]:
        raw = row.get(col)
        if not raw:
            return {}
        try:
            return json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            return {}

    return _device_is_online_parsed(
        _pj("last_status_json"),
        _pj("last_heartbeat_json"),
        _pj("last_ack_json"),
        _pj("last_event_json"),
        str(row.get("updated_at") or ""),
        now_s,
    )


def _row_json_val(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        j = json.loads(raw) if isinstance(raw, str) else dict(raw)
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _status_preview_from_device_row(d: dict[str, Any]) -> dict[str, Any]:
    """Compact live hints for the device list (one round-trip, no N+1)."""
    st = _row_json_val(d.get("last_status_json"))
    hb = _row_json_val(d.get("last_heartbeat_json"))
    rssi: int | None = None
    _w = st.get("wifi")
    wifi = _w if isinstance(_w, dict) else {}
    for cand in (st.get("rssi"), wifi.get("rssi") if isinstance(wifi, dict) else None, hb.get("rssi")):
        if cand is None:
            continue
        try:
            r = int(cand)
        except (TypeError, ValueError):
            continue
        if r != -127:
            rssi = r
            break
    vbat: float | None
    vbat = None
    if st.get("vbat") is not None:
        try:
            vb = float(st["vbat"])
            if vb >= 0:
                vbat = round(vb, 2)
        except (TypeError, ValueError):
            vbat = None
    parts: list[str] = []
    if rssi is not None:
        parts.append(f"RSSI {rssi} dBm")
    if vbat is not None:
        parts.append(f"{vbat:.2f} V")
    hb_on = bool(hb.get("online")) if "online" in hb else None
    if hb_on is True and not parts:
        parts.append("heartbeat")
    if hb_on is False and not parts:
        parts.append("heartbeat lost")
    line = " · ".join(parts) if parts else "—"
    return {"line": line, "rssi": rssi, "vbat": vbat}


def _parse_fw_version_tuple(s: str) -> tuple[int, ...] | None:
    t = (s or "").strip()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:\D|$)", t)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m2 = re.search(r"(\d+)\.(\d+)(?:\D|$)", t)
    if m2:
        return (int(m2.group(1)), int(m2.group(2)), 0)
    return None


def _fw_version_gt(newer: str, current: str) -> bool:
    a, b = (newer or "").strip(), (current or "").strip()
    if not a:
        return False
    if not b:
        return bool(a)
    ta, tb = _parse_fw_version_tuple(a), _parse_fw_version_tuple(b)
    if ta and tb:
        return ta > tb
    return a > b


def _version_str_from_ota_bin_name(name: str) -> str:
    base = os.path.basename(name)
    m = re.match(r"^croc-(.+)-[a-f0-9]{8}\.bin$", base, re.I)
    if m:
        return m.group(1).replace("_", ".")
    m2 = re.search(r"(\d+\.\d+\.\d+)", base)
    if m2:
        return m2.group(1)
    m3 = re.search(r"(\d+\.\d+)(?:\D|$)", base)
    if m3:
        return m3.group(1) + ".0"
    if base.lower().endswith(".bin"):
        return base[:-4] or base
    return base


def _read_ota_stored_version_sidecar(bin_path: str) -> str:
    """Canonical version string from OTA upload (`<name>.version`, one line). Not derived from the filename."""
    b = (bin_path or "").strip()
    if not b or ".." in b:
        return ""
    p = b + ".version"
    if not os.path.isfile(p):
        return ""
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            line = f.readline()
        v = (line or "").strip()
        return v[:80] if v else ""
    except OSError:
        return ""


def _version_str_for_ota_bin_file(bin_path: str, name: str) -> str:
    v = _read_ota_stored_version_sidecar(bin_path).strip()
    if v:
        return v
    return str(_version_str_from_ota_bin_name(name) or "").strip()


def _read_ota_release_notes_for_stem(stem: str) -> str:
    if not stem or ".." in stem or "/" in stem or "\\" in stem:
        return ""
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    for ext in (".txt", ".md", ".notes"):
        p = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, stem + ext))
        if not p.startswith(base_dir + os.sep) or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                return f.read(8000)
        except OSError:
            continue
    return ""


_OTA_CATALOG_TTL = 45.0
_OTA_CATALOG_CACHE: tuple[float, list[dict[str, Any]]] | None = None


def _invalidate_ota_firmware_catalog_cache() -> None:
    global _OTA_CATALOG_CACHE
    _OTA_CATALOG_CACHE = None


def _get_ota_firmware_catalog() -> list[dict[str, Any]]:
    global _OTA_CATALOG_CACHE
    now = time.time()
    if _OTA_CATALOG_CACHE and (now - _OTA_CATALOG_CACHE[0]) < _OTA_CATALOG_TTL:
        return _OTA_CATALOG_CACHE[1]
    items: list[dict[str, Any]] = []
    base = OTA_FIRMWARE_DIR
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            if not str(name).endswith(".bin"):
                continue
            p = os.path.join(base, name)
            if not os.path.isfile(p):
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            vs = _version_str_for_ota_bin_file(p, name).strip()
            if not vs:
                continue
            items.append(
                {
                    "name": name,
                    "version_str": vs,
                    "version_tuple": _parse_fw_version_tuple(vs),
                    "mtime": int(st.st_mtime),
                },
            )
    _OTA_CATALOG_CACHE = (now, items)
    return items


def _catalog_entry_beats(a: dict[str, Any], b: dict[str, Any] | None) -> bool:
    """True if `a` is a strictly better upgrade candidate than `b` (newer version, or same version + newer mtime)."""
    if b is None:
        return True
    va, vb = str(a.get("version_str") or "").strip(), str(b.get("version_str") or "").strip()
    if not va:
        return False
    if _fw_version_gt(va, vb):
        return True
    if va == vb and int(a.get("mtime", 0)) > int(b.get("mtime", 0)):
        return True
    return False


def _best_catalog_entry_newer_than_fw(current_fw: str, catalog: list[dict[str, Any]]) -> dict[str, Any] | None:
    cur = (current_fw or "").strip()
    if not cur or not catalog:
        return None
    best: dict[str, Any] | None = None
    for ent in catalog:
        v = str(ent.get("version_str") or "").strip()
        if not v or not _fw_version_gt(v, cur):
            continue
        if _catalog_entry_beats(ent, best):
            best = ent
    return best


def _firmware_hint_dict_from_entry(best: dict[str, Any]) -> dict[str, Any]:
    name = str(best["name"])
    stem = name[:-4] if name.lower().endswith(".bin") else name
    notes = _read_ota_release_notes_for_stem(stem)
    dl = ""
    if OTA_PUBLIC_BASE_URL:
        dl = f"{OTA_PUBLIC_BASE_URL}/fw/{name}"
    return {
        "update_available": True,
        "to_version": str(best["version_str"]),
        "to_file": name,
        "release_notes": notes,
        "download_url": dl or None,
    }


def _firmware_update_hint_for_current_in_catalog(
    current_fw: str, catalog: list[dict[str, Any]]
) -> dict[str, Any] | None:
    best = _best_catalog_entry_newer_than_fw(current_fw, catalog)
    if not best:
        return None
    cur = (current_fw or "").strip().lower()
    tgt = str(best.get("version_str") or "").strip().lower()
    if cur and tgt and cur == tgt:
        return None
    return _firmware_hint_dict_from_entry(best)


@app.get("/dashboard/overview")
def dashboard_overview(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "overview" if (principal.is_superadmin() or principal.has_all_zones()) else f"overview:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    args = tuple(za + osa)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) AS c FROM device_state WHERE 1=1 {zs} {osf}", args)
        total = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM device_state
            WHERE last_status_json IS NOT NULL {zs} {osf}
            """,
            args,
        )
        with_status = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT fw, chip_target, board_profile, net_type, COUNT(*) AS c
            FROM device_state
            WHERE 1=1 {zs} {osf}
            GROUP BY fw, chip_target, board_profile, net_type
            ORDER BY c DESC
            """,
            args,
        )
        grouped = [dict(r) for r in cur.fetchall()]
        cur.execute(
            f"""
            SELECT device_id, updated_at, last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state
            WHERE 1=1 {zs} {osf}
            """,
            args,
        )
        presence_rows = cur.fetchall()
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM alarms
            WHERE created_at >= datetime('now', '-24 hours')
              AND (? = '' OR owner_admin = ?)
            """,
            ("" if principal.is_superadmin() else "x",
             "" if principal.is_superadmin() else (
                 principal.username if principal.role == "admin"
                 else get_manager_admin(principal.username)
             )),
        )
        alarms_24h = int(cur.fetchone()["c"])
        conn.close()
    now_s = time.time()
    presence = {
        "online": 0,
        "offline_total": 0,
        "reason_power_low": 0,
        "reason_network_lost": 0,
        "reason_signal_weak": 0,
        "reason_unknown": 0,
    }
    tx_bps_total = 0.0
    rx_bps_total = 0.0
    for r in presence_rows:
        raw = r["last_status_json"] or ""
        try:
            s = json.loads(raw) if raw else {}
        except Exception:
            s = {}
        raw_hb = r["last_heartbeat_json"] or ""
        try:
            hb = json.loads(raw_hb) if raw_hb else {}
        except Exception:
            hb = {}
        raw_ack = r["last_ack_json"] or ""
        try:
            ack = json.loads(raw_ack) if raw_ack else {}
        except Exception:
            ack = {}
        raw_ev = r["last_event_json"] or ""
        try:
            ev = json.loads(raw_ev) if raw_ev else {}
        except Exception:
            ev = {}
        updated = _parse_iso(str(r["updated_at"] or ""))
        fresh = (now_s - updated) < OFFLINE_THRESHOLD_SECONDS
        is_online = _effective_online_for_presence(s, hb, ack, ev) and fresh
        if is_online:
            presence["online"] += 1
            try:
                tx_bps_total += float(s.get("tx_bps") or 0)
                rx_bps_total += float(s.get("rx_bps") or 0)
            except (TypeError, ValueError):
                pass
        else:
            presence["offline_total"] += 1
            reason = str(s.get("disconnect_reason") or "")
            if reason == "power_low":
                presence["reason_power_low"] += 1
            elif reason == "network_lost" or (now_s - updated) >= OFFLINE_THRESHOLD_SECONDS:
                presence["reason_network_lost"] += 1
            elif reason == "signal_weak":
                presence["reason_signal_weak"] += 1
            else:
                presence["reason_unknown"] += 1
    out = {
        "total_devices": total,
        "devices_with_status": with_status,
        "groups": grouped,
        "mqtt_connected": mqtt_connected,
        "presence": presence,
        "throughput": {
            "tx_bps_total": round(tx_bps_total, 1),
            "rx_bps_total": round(rx_bps_total, 1),
        },
        "alarms_24h": alarms_24h,
        "notifier": notifier.status() if principal.is_adminish() else {"enabled": notifier.enabled()},
        "ts": int(time.time()),
    }
    cache_put(cache_key, out)
    return out


@app.get("/devices")
def list_devices(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "devices:list" if (principal.is_superadmin() or principal.has_all_zones()) else f"devices:list:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, d.fw, d.chip_target, d.board_profile, d.net_type, d.zone, d.provisioned,
                   o.owner_admin,
                   IFNULL(display_label, '') AS display_label,
                   IFNULL(notification_group, '') AS notification_group, updated_at,
                   last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE 1=1 {zs} {osf}
            ORDER BY d.updated_at DESC
            """,
            tuple(za + osa),
        )
        now_s = int(time.time())
        rows_out: list[dict[str, Any]] = []
        for r in cur.fetchall():
            d = dict(r)
            d["is_online"] = _device_is_online_sql_row(d, now_s)
            d["status_preview"] = _status_preview_from_device_row(d)
            d.update(
                _device_presence_ages(
                    _row_json_val(d.get("last_status_json")),
                    _row_json_val(d.get("last_heartbeat_json")),
                    _row_json_val(d.get("last_ack_json")),
                    _row_json_val(d.get("last_event_json")),
                    str(d.get("updated_at") or ""),
                    now_s,
                )
            )
            owner_admin = str(d.get("owner_admin") or "")
            d.pop("last_status_json", None)
            d.pop("last_heartbeat_json", None)
            d.pop("last_ack_json", None)
            d.pop("last_event_json", None)
            _redact_notification_group_for_principal(principal, owner_admin, d)
            if principal.role != "superadmin":
                viewer_admin = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or "")
                is_shared = bool(owner_admin) and bool(viewer_admin) and owner_admin != viewer_admin
                d["is_shared"] = bool(is_shared)
                if is_shared:
                    d["shared_by"] = owner_admin
                d.pop("owner_admin", None)
            rows_out.append(d)
        conn.close()
    out = {"items": rows_out}
    cache_put(cache_key, out)
    return out


@app.get("/devices/firmware-hints")
def list_devices_firmware_hints(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Per-device “newer .bin on disk” hint for the signed-in scope (no superadmin OTA UI required)."""
    assert_min_role(principal, "user")
    catalog = _get_ota_firmware_catalog()
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, d.fw
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE 1=1 {zs} {osf}
            """,
            tuple(za + osa),
        )
        rows = [dict(x) for x in cur.fetchall()]
        conn.close()
    hints: dict[str, Any] = {}
    for r in rows:
        did = str(r.get("device_id") or "")
        if not did:
            continue
        cur_fw = str(r.get("fw") or "")
        h = _firmware_update_hint_for_current_in_catalog(cur_fw, catalog)
        if h:
            hints[did] = h
    return {"hints": hints, "ts": int(time.time())}


@app.get("/devices/{device_id}")
def get_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM device_state WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(row["zone"]) if row["zone"] is not None else "")
    can_view, can_operate = _device_access_flags(principal, device_id)

    out = dict(row)
    for key in ("last_status_json", "last_heartbeat_json", "last_ack_json", "last_event_json"):
        if out.get(key):
            out[key] = json.loads(out[key])
    now_s = int(time.time())
    out["is_online"] = _device_is_online_parsed(
        out.get("last_status_json") or {},
        out.get("last_heartbeat_json") or {},
        out.get("last_ack_json") or {},
        out.get("last_event_json") or {},
        str(out.get("updated_at") or ""),
        now_s,
    )
    out.update(
        _device_presence_ages(
            out.get("last_status_json") or {},
            out.get("last_heartbeat_json") or {},
            out.get("last_ack_json") or {},
            out.get("last_event_json") or {},
            str(out.get("updated_at") or ""),
            now_s,
        )
    )
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT o.owner_admin, o.assigned_by, o.assigned_at, IFNULL(u.email, '') AS owner_email
            FROM device_ownership o
            LEFT JOIN dashboard_users u ON u.username = o.owner_admin
            WHERE o.device_id = ?
            """,
            (device_id,),
        )
        ow = cur.fetchone()
        conn.close()
    owner_admin = str(ow["owner_admin"]) if ow and ow["owner_admin"] is not None else ""
    out["owner_admin"] = owner_admin
    out["owner_email"] = str(ow["owner_email"]) if ow and ow["owner_email"] is not None else ""
    if principal.role == "superadmin":
        out["registered_by"] = str(ow["assigned_by"]) if ow else ""
        out["registered_at"] = str(ow["assigned_at"]) if ow else ""
    else:
        viewer_admin = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or "")
        is_shared = bool(owner_admin) and bool(viewer_admin) and owner_admin != viewer_admin
        out["is_shared"] = bool(is_shared)
        if is_shared:
            out["shared_by"] = owner_admin
    _redact_notification_group_for_principal(principal, owner_admin, out)
    out["can_view"] = bool(can_view)
    out["can_operate"] = bool(can_operate)
    cat = _get_ota_firmware_catalog()
    out["firmware_hint"] = _firmware_update_hint_for_current_in_catalog(str(out.get("fw") or ""), cat)
    return out


@app.get("/devices/{device_id}/siblings-preview")
def preview_device_siblings(
    device_id: str,
    include_source: bool = Query(default=False),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Debug helper: resolve current sibling fan-out targets for a device."""
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT IFNULL(zone,''), IFNULL(notification_group,'') FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    zone = str(row[0] or "").strip()
    group_key = str(row[1] or "").strip()
    assert_zone_for_device(principal, zone)
    owner_admin = _lookup_owner_admin(device_id)
    if not _principal_tenant_owns_device(principal, owner_admin):
        raise HTTPException(
            status_code=403,
            detail="sibling preview is available to the owning tenant only",
        )
    targets, eligible_total = _tenant_siblings(
        owner_admin,
        device_id,
        source_zone=zone,
        source_group=group_key,
        include_source=bool(include_source),
    )
    out: dict[str, Any] = {
        "ok": True,
        "device_id": device_id,
        "zone": zone,
        "notification_group": group_key,
        "fanout_enabled": bool(group_key),
        "target_count": len(targets),
        "eligible_total": eligible_total,
        "fanout_capped": eligible_total > len(targets),
        "fanout_max": ALARM_FANOUT_MAX_TARGETS,
        "targets": [{"device_id": did, "zone": z} for did, z in targets],
    }
    if principal.role == "superadmin":
        out["owner_admin"] = owner_admin or ""
    return out


class DeviceDisplayLabelBody(BaseModel):
    display_label: str = Field(default="", max_length=80)


class DeviceProfileBody(BaseModel):
    display_label: Optional[str] = Field(default=None, max_length=80)
    notification_group: Optional[str] = Field(default=None, max_length=80)


class DeviceBulkProfileBody(BaseModel):
    device_ids: list[str] = Field(default_factory=list, min_length=1, max_length=500)
    set_notification_group: bool = False
    notification_group: Optional[str] = Field(default=None, max_length=80)
    set_zone_override: bool = False
    zone_override: Optional[str] = Field(default=None, max_length=31)
    clear_zone_override: bool = False


class GroupCardSettingsBody(BaseModel):
    trigger_mode: str = Field(default="continuous", pattern="^(continuous|delay)$")
    trigger_duration_ms: int = Field(default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000)
    delay_seconds: int = Field(default=0, ge=0, le=3600)
    reboot_self_check: bool = False
    # Superadmin only: which tenant's group_card_settings row / device slice to target.
    owner_admin: Optional[str] = Field(default=None, max_length=64)


class DeviceShareRequest(BaseModel):
    grantee_username: str = Field(min_length=2, max_length=64)
    can_view: bool = True
    can_operate: bool = False


def _delete_group_card_impl(
    group_key: str,
    principal: Principal,
    *,
    tenant_owner: Optional[str] = None,
) -> dict[str, Any]:
    """Delete a group card by clearing notification_group on target devices.

    Security rule:
      - admin: can only delete groups fully owned by self (shared devices block deletion)
      - superadmin: can delete any group; pass `tenant_owner` to clear only that admin's slice
        (recommended when multiple tenants reuse the same group_key).
    """
    assert_min_role(principal, "admin")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    tenant = (tenant_owner or "").strip()
    if principal.role != "superadmin" and tenant:
        raise HTTPException(status_code=400, detail="owner_admin filter is superadmin-only")
    slice_sql = ""
    slice_args: list[Any] = []
    if principal.role == "superadmin" and tenant:
        slice_sql = " AND IFNULL(o.owner_admin,'') = ? "
        slice_args.append(tenant)
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, IFNULL(o.owner_admin,'') AS owner_admin
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE IFNULL(d.notification_group,'') = ? {zs} {osf} {slice_sql}
            ORDER BY d.device_id ASC
            """,
            tuple([g] + za + osa + slice_args),
        )
        rows = [dict(r) for r in cur.fetchall()]
        if not rows:
            conn.close()
            raise HTTPException(status_code=404, detail="group not found in your scope")
        if principal.role != "superadmin":
            # Shared group/device must not be deletable by grantee.
            for r in rows:
                owner = str(r.get("owner_admin") or "")
                if owner and owner != principal.username:
                    conn.close()
                    raise HTTPException(status_code=403, detail="shared group cannot be deleted")
                if not owner:
                    conn.close()
                    raise HTTPException(status_code=403, detail="unowned group cannot be deleted by admin")
        ids = [str(r["device_id"]) for r in rows if r.get("device_id")]
        ph = ",".join(["?"] * len(ids))
        cur.execute(
            f"UPDATE device_state SET notification_group = '' WHERE device_id IN ({ph})",
            tuple(ids),
        )
        changed = int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            if tenant:
                cur.execute(
                    "DELETE FROM group_card_settings WHERE owner_admin = ? AND group_key = ?",
                    (tenant, g),
                )
            else:
                cur.execute("DELETE FROM group_card_settings WHERE group_key = ?", (g,))
        else:
            owner_scope = (
                principal.username
                if principal.role == "admin"
                else (get_manager_admin(principal.username) or principal.username)
            )
            cur.execute(
                "DELETE FROM group_card_settings WHERE owner_admin = ? AND group_key = ?",
                (owner_scope, g),
            )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "group.delete",
        g,
        {"device_count": len(ids), "changed": changed, "tenant_owner": tenant or None},
    )
    return {"ok": True, "group_key": g, "device_count": len(ids), "changed": changed}


@app.delete("/group-cards/{group_key}")
def delete_group_card(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


@app.post("/group-cards/{group_key}/delete")
def delete_group_card_post(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Proxy-friendly delete route for environments that block HTTP DELETE."""
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


@app.get("/group-cards/capabilities")
def group_cards_capabilities(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {
        "ok": True,
        "prefixes": ["/group-cards", "/api/group-cards"],
        "routes": {
            "settings_list": ["GET /group-cards/settings", "GET /api/group-cards/settings"],
            "settings_get": ["GET /group-cards/{group_key}/settings", "GET /api/group-cards/{group_key}/settings"],
            "settings_put": ["PUT /group-cards/{group_key}/settings", "PUT /api/group-cards/{group_key}/settings"],
            "apply": ["POST /group-cards/{group_key}/apply", "POST /api/group-cards/{group_key}/apply"],
            "delete_post": ["POST /group-cards/{group_key}/delete", "POST /api/group-cards/{group_key}/delete"],
            "delete_delete": ["DELETE /group-cards/{group_key}", "DELETE /api/group-cards/{group_key}"],
        },
    }


def _group_owner_scope(principal: Principal) -> str:
    if principal.role == "admin":
        return principal.username
    if principal.role == "user":
        return get_manager_admin(principal.username) or principal.username
    return principal.username


def _group_settings_defaults(group_key: str) -> dict[str, Any]:
    return {
        "group_key": group_key,
        "trigger_mode": "continuous",
        "trigger_duration_ms": int(DEFAULT_REMOTE_FANOUT_MS),
        "delay_seconds": 0,
        "reboot_self_check": False,
        "updated_by": "",
        "updated_at": "",
    }


def _group_devices_with_owner(
    group_key: str,
    principal: Principal,
    *,
    tenant_owner: Optional[str] = None,
) -> list[dict[str, str]]:
    g = (group_key or "").strip()
    if not g:
        return []
    tenant = (tenant_owner or "").strip()
    if principal.role != "superadmin" and tenant:
        raise HTTPException(status_code=400, detail="owner_admin filter is superadmin-only")
    slice_sql = ""
    slice_args: list[Any] = []
    if principal.role == "superadmin" and tenant:
        slice_sql = " AND IFNULL(o.owner_admin,'') = ? "
        slice_args.append(tenant)
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT d.device_id, IFNULL(o.owner_admin,'') AS owner_admin
            FROM device_state d
            LEFT JOIN device_ownership o ON d.device_id = o.device_id
            WHERE IFNULL(d.notification_group,'') = ? {zs} {osf} {slice_sql}
            ORDER BY d.device_id ASC
            """,
            tuple([g] + za + osa + slice_args),
        )
        rows = [{"device_id": str(r["device_id"]), "owner_admin": str(r["owner_admin"] or "")} for r in cur.fetchall()]
        conn.close()
    return rows


@app.get("/group-cards/settings")
def list_group_card_settings(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    owner_scope = _group_owner_scope(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                       reboot_self_check, updated_by, updated_at
                FROM group_card_settings
                ORDER BY owner_admin ASC, group_key ASC
                """
            )
        else:
            cur.execute(
                """
                SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                       reboot_self_check, updated_by, updated_at
                FROM group_card_settings
                WHERE owner_admin = ?
                ORDER BY group_key ASC
                """,
                (owner_scope,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    out = []
    for r in rows:
        out.append(
            {
                "owner_admin": str(r.get("owner_admin") or ""),
                "group_key": str(r.get("group_key") or ""),
                "trigger_mode": str(r.get("trigger_mode") or "continuous"),
                "trigger_duration_ms": int(r.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS),
                "delay_seconds": int(r.get("delay_seconds") or 0),
                "reboot_self_check": bool(int(r.get("reboot_self_check") or 0)),
                "updated_by": str(r.get("updated_by") or ""),
                "updated_at": str(r.get("updated_at") or ""),
            }
        )
    return {"items": out}


@app.get("/api/group-cards/settings")
def list_group_card_settings_api(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    return list_group_card_settings(principal)


@app.get("/group-cards/{group_key}/settings")
def get_group_card_settings(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    tenant_q = (owner_admin or "").strip()
    if principal.role != "superadmin" and tenant_q:
        raise HTTPException(status_code=400, detail="owner_admin query is superadmin-only")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            if tenant_q:
                cur.execute(
                    """
                    SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                           reboot_self_check, updated_by, updated_at
                    FROM group_card_settings
                    WHERE owner_admin = ? AND group_key = ?
                    """,
                    (tenant_q, g),
                )
                row = cur.fetchone()
            else:
                cur.execute(
                    """
                    SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                           reboot_self_check, updated_by, updated_at
                    FROM group_card_settings
                    WHERE group_key = ?
                    """,
                    (g,),
                )
                matches = cur.fetchall()
                if not matches:
                    row = None
                elif len(matches) == 1:
                    row = matches[0]
                else:
                    conn.close()
                    raise HTTPException(
                        status_code=400,
                        detail="owner_admin query parameter required (multiple tenants use this group_key)",
                    )
        else:
            cur.execute(
                """
                SELECT owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                       reboot_self_check, updated_by, updated_at
                FROM group_card_settings
                WHERE owner_admin = ? AND group_key = ?
                """,
                (owner_scope, g),
            )
            row = cur.fetchone()
        conn.close()
    if not row:
        return _group_settings_defaults(g)
    r = dict(row)
    return {
        "owner_admin": str(r.get("owner_admin") or ""),
        "group_key": g,
        "trigger_mode": str(r.get("trigger_mode") or "continuous"),
        "trigger_duration_ms": int(r.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS),
        "delay_seconds": int(r.get("delay_seconds") or 0),
        "reboot_self_check": bool(int(r.get("reboot_self_check") or 0)),
        "updated_by": str(r.get("updated_by") or ""),
        "updated_at": str(r.get("updated_at") or ""),
    }


@app.get("/api/group-cards/{group_key}/settings")
def get_group_card_settings_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return get_group_card_settings(group_key, owner_admin=owner_admin, principal=principal)


@app.put("/group-cards/{group_key}/settings")
def save_group_card_settings(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    tenant_body = (body.owner_admin or "").strip()
    if principal.role != "superadmin" and tenant_body:
        raise HTTPException(status_code=400, detail="owner_admin in body is superadmin-only")
    tenant_for_slice: Optional[str] = None
    if principal.role == "superadmin" and tenant_body:
        owner_scope = tenant_body
        tenant_for_slice = tenant_body
    rows = _group_devices_with_owner(g, principal, tenant_owner=tenant_for_slice)
    if principal.role == "superadmin" and not tenant_body:
        owners_set = {str(r.get("owner_admin") or "").strip() for r in rows}
        owners_set.discard("")
        if len(owners_set) > 1:
            raise HTTPException(
                status_code=400,
                detail="owner_admin required in body (multiple tenants share this group_key)",
            )
        if len(owners_set) == 1:
            owner_scope = next(iter(owners_set))
    # Allow saving even when no devices are tagged yet: otherwise UI 404s before any
    # `device_state.notification_group` is written (e.g. group name saved before members).
    # Sibling fan-out and apply still require devices with matching notification_group.
    # Shared groups are owner-managed: grantee cannot override owner strategy.
    if principal.role != "superadmin":
        for r in rows:
            o = str(r.get("owner_admin") or "")
            if o and o != owner_scope:
                raise HTTPException(status_code=403, detail="shared group settings are managed by owner")
    now = utc_now_iso()
    resolved_mode = "delay" if int(body.delay_seconds) > 0 else "continuous"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO group_card_settings (
                owner_admin, group_key, trigger_mode, trigger_duration_ms, delay_seconds,
                reboot_self_check, updated_by, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_admin, group_key) DO UPDATE SET
                trigger_mode=excluded.trigger_mode,
                trigger_duration_ms=excluded.trigger_duration_ms,
                delay_seconds=excluded.delay_seconds,
                reboot_self_check=excluded.reboot_self_check,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (
                owner_scope,
                g,
                resolved_mode,
                int(body.trigger_duration_ms),
                int(body.delay_seconds),
                1 if body.reboot_self_check else 0,
                principal.username,
                now,
            ),
        )
        conn.commit()
        conn.close()
    audit_event(
        principal.username,
        "group.settings.save",
        g,
        {
            "trigger_mode": resolved_mode,
            "trigger_duration_ms": int(body.trigger_duration_ms),
            "delay_seconds": int(body.delay_seconds),
            "reboot_self_check": bool(body.reboot_self_check),
            "owner_admin": owner_scope,
        },
    )
    return {
        "ok": True,
        "owner_admin": owner_scope,
        "group_key": g,
        "trigger_mode": resolved_mode,
        "trigger_duration_ms": int(body.trigger_duration_ms),
        "delay_seconds": int(body.delay_seconds),
        "reboot_self_check": bool(body.reboot_self_check),
        "updated_by": principal.username,
        "updated_at": now,
        "device_count": len(rows),
    }


@app.put("/api/group-cards/{group_key}/settings")
def save_group_card_settings_api(
    group_key: str,
    body: GroupCardSettingsBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return save_group_card_settings(group_key, body, principal)


@app.post("/group-cards/{group_key}/apply")
def apply_group_card_settings(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    tenant_q = (owner_admin or "").strip()
    if principal.role != "superadmin" and tenant_q:
        raise HTTPException(status_code=400, detail="owner_admin query is superadmin-only")
    tenant_for_slice: Optional[str] = tenant_q or None
    rows = _group_devices_with_owner(g, principal, tenant_owner=tenant_for_slice)
    if principal.role == "superadmin" and not tenant_for_slice:
        owners_set = {str(r.get("owner_admin") or "").strip() for r in rows}
        owners_set.discard("")
        if len(owners_set) > 1:
            raise HTTPException(
                status_code=400,
                detail="owner_admin query required (multiple tenants share this group_key)",
            )
    rows = [r for r in rows if _principal_tenant_owns_device(principal, str(r.get("owner_admin") or ""))]
    targets = [str(r["device_id"]) for r in rows if r.get("device_id")]
    if not targets:
        raise HTTPException(
            status_code=404,
            detail="group has no devices owned by your tenant for this key (shared devices are excluded from group apply)",
        )

    # Settings ownership policy:
    # - own devices => use caller's owner_scope setting
    # - shared devices => follow real owner's setting (read-only for grantee)
    device_owner_map: dict[str, str] = {str(r["device_id"]): str(r.get("owner_admin") or "") for r in rows}
    owners_needed: set[str] = set()
    for did in targets:
        owner_real = str(device_owner_map.get(did) or "")
        owner_for_cfg = owner_real or owner_scope
        owners_needed.add(owner_for_cfg)
    settings_by_owner: dict[str, dict[str, Any]] = {}
    if owners_needed:
        ph = ",".join(["?"] * len(owners_needed))
        args = [g] + list(owners_needed)
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT owner_admin, trigger_mode, trigger_duration_ms, delay_seconds, reboot_self_check
                FROM group_card_settings
                WHERE group_key = ? AND owner_admin IN ({ph})
                """,
                tuple(args),
            )
            for r in cur.fetchall():
                settings_by_owner[str(r["owner_admin"])] = {
                    "trigger_mode": str(r["trigger_mode"] or "continuous"),
                    "trigger_duration_ms": int(r["trigger_duration_ms"] or DEFAULT_REMOTE_FANOUT_MS),
                    "delay_seconds": int(r["delay_seconds"] or 0),
                    "reboot_self_check": bool(int(r["reboot_self_check"] or 0)),
                }
            conn.close()

    siren_sent = 0
    siren_scheduled = 0
    reboot_jobs = 0
    self_tests = 0
    for did in targets:
        ensure_not_revoked(did)
        owner_real = str(device_owner_map.get(did) or "")
        owner_for_cfg = owner_real or owner_scope
        cfg = settings_by_owner.get(owner_for_cfg, _group_settings_defaults(g))
        dur_ms = int(cfg.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS)
        reboot_self_check = bool(cfg.get("reboot_self_check"))
        # Delay is config-only for UI visibility; execution is immediate.
        publish_command(
            topic=f"{TOPIC_ROOT}/{did}/cmd",
            cmd="siren_on",
            params={"duration_ms": dur_ms},
            target_id=did,
            proto=CMD_PROTO,
            cmd_key=get_cmd_key_for_device(did),
        )
        siren_sent += 1

        if reboot_self_check:
            require_capability(principal, "can_send_command")
            _, can_op = _device_access_flags(principal, did)
            if not can_op:
                continue
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="self_test",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            self_tests += 1
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="reboot",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            reboot_jobs += 1

    owner = _lookup_owner_admin(targets[0]) if targets else ""
    # Report the first owner's effective setting for compact response fields.
    first_owner = str(device_owner_map.get(targets[0]) or owner_scope) if targets else owner_scope
    first_cfg = settings_by_owner.get(first_owner, _group_settings_defaults(g))
    mode = "continuous"
    dur_ms = int(first_cfg.get("trigger_duration_ms") or DEFAULT_REMOTE_FANOUT_MS)
    delay_seconds = 0
    reboot_self_check = bool(first_cfg.get("reboot_self_check"))
    _log_signal_trigger(
        "group_card_apply",
        "*",
        "",
        principal.username,
        owner,
        duration_ms=dur_ms,
        target_count=len(targets),
        detail={
            "group_key": g,
            "trigger_mode": mode,
            "delay_seconds": delay_seconds,
            "reboot_self_check": reboot_self_check,
            "sent_now": siren_sent,
            "scheduled": siren_scheduled,
            "self_tests": self_tests,
            "reboot_jobs": reboot_jobs,
        },
    )
    emit_event(
        level="warn",
        category="alarm",
        event_type="group.trigger.apply",
        summary=f"group settings applied for {g} ({len(targets)} devices) by {principal.username}",
        actor=principal.username,
        target=g,
        owner_admin=owner or "",
        detail={
            "group_key": g,
            "mode": mode,
            "duration_ms": dur_ms,
            "delay_seconds": delay_seconds,
            "reboot_self_check": reboot_self_check,
            "owner_scope": owner_scope,
            "owners_count": len(owners_needed),
            "device_count": len(targets),
            "sent_now": siren_sent,
            "scheduled": siren_scheduled,
            "self_tests": self_tests,
            "reboot_jobs": reboot_jobs,
        },
    )
    return {
        "ok": True,
        "group_key": g,
        "device_count": len(targets),
        "mode": mode,
        "trigger_duration_ms": dur_ms,
        "delay_seconds": delay_seconds,
        "reboot_self_check": reboot_self_check,
        "sent_now": siren_sent,
        "scheduled": siren_scheduled,
        "self_tests": self_tests,
        "reboot_jobs": reboot_jobs,
    }


@app.post("/api/group-cards/{group_key}/apply")
def apply_group_card_settings_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return apply_group_card_settings(group_key, owner_admin=owner_admin, principal=principal)


@app.delete("/api/group-cards/{group_key}")
def delete_group_card_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


@app.post("/api/group-cards/{group_key}/delete")
def delete_group_card_post_api(
    group_key: str,
    owner_admin: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal, tenant_owner=owner_admin)


def _apply_device_profile_update(
    device_id: str,
    principal: Principal,
    body: DeviceProfileBody,
) -> dict[str, Any]:
    if body.display_label is None and body.notification_group is None:
        raise HTTPException(
            status_code=400,
            detail="provide at least one of display_label, notification_group",
        )
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row_owner = _lookup_owner_admin(device_id) or ""
    if body.notification_group is not None and not _principal_tenant_owns_device(principal, row_owner):
        raise HTTPException(
            status_code=403,
            detail="only the owning tenant may change notification_group; shared access is device-scoped",
        )
    sets: list[str] = []
    args: list[Any] = []
    if body.display_label is not None:
        sets.append("display_label = ?")
        args.append(body.display_label.strip())
    if body.notification_group is not None:
        sets.append("notification_group = ?")
        args.append(body.notification_group.strip())
    # Do not touch device_state.updated_at here: it is used for MQTT freshness
    # (overview presence, dashboard isOnline). Profile edits are not device traffic.
    args.append(device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT zone, display_label, notification_group FROM device_state WHERE device_id = ?",
            (device_id,),
        )
        zr = cur.fetchone()
        if not zr:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
        old_label = (str(zr["display_label"]).strip() if zr["display_label"] is not None else "")
        old_group = (str(zr["notification_group"]).strip() if zr["notification_group"] is not None else "")
        cur.execute(
            f"UPDATE device_state SET {', '.join(sets)} WHERE device_id = ?",
            tuple(args),
        )
        conn.commit()
        conn.close()
    new_label = (body.display_label.strip() if body.display_label is not None else old_label)
    new_group = (body.notification_group.strip() if body.notification_group is not None else old_group)
    group_changed = body.notification_group is not None and new_group != old_group
    label_changed = body.display_label is not None and new_label != old_label
    cache_invalidate("devices")
    cache_invalidate("overview")
    emit_event(
        level="info",
        category="device",
        event_type="device.profile",
        summary=f"device profile updated {device_id}",
        actor=principal.username,
        target=device_id,
        device_id=device_id,
        detail={
            "display_label": new_label,
            "notification_group": new_group,
            "previous_display_label": old_label,
            "previous_notification_group": old_group,
            "display_label_changed": label_changed,
            "notification_group_changed": group_changed,
        },
    )
    out: dict[str, Any] = {"ok": True, "device_id": device_id}
    if body.display_label is not None:
        out["display_label"] = new_label
    if body.notification_group is not None:
        out["notification_group"] = new_group
    return out


@app.patch("/devices/{device_id}/profile")
def patch_device_profile(
    device_id: str,
    body: DeviceProfileBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return _apply_device_profile_update(device_id, principal, body)


@app.patch("/devices/{device_id}/display-label")
def patch_device_display_label(
    device_id: str,
    body: DeviceDisplayLabelBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Legacy: only updates display_label."""
    return _apply_device_profile_update(
        device_id,
        principal,
        DeviceProfileBody(display_label=body.display_label, notification_group=None),
    )


@app.post("/devices/bulk/profile")
def bulk_patch_device_profile(
    body: DeviceBulkProfileBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Bulk profile update for production operations (group + zone override)."""
    assert_min_role(principal, "user")
    ids = []
    seen = set()
    for raw in body.device_ids:
        did = str(raw or "").strip()
        if not did or did in seen:
            continue
        seen.add(did)
        ids.append(did)
    if not ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    if len(ids) > 500:
        raise HTTPException(status_code=400, detail="too many device_ids (max 500)")
    if not body.set_notification_group and not body.set_zone_override and not body.clear_zone_override:
        raise HTTPException(status_code=400, detail="no bulk operation selected")
    if body.set_zone_override and body.clear_zone_override:
        raise HTTPException(status_code=400, detail="set_zone_override and clear_zone_override are mutually exclusive")
    for did in ids:
        assert_device_owner(principal, did)
        if body.set_notification_group:
            o = _lookup_owner_admin(did) or ""
            if not _principal_tenant_owns_device(principal, o):
                raise HTTPException(
                    status_code=403,
                    detail=f"notification_group bulk-set denied for shared device {did} (owner-tenant only)",
                )
    notif_group = (str(body.notification_group or "").strip() if body.set_notification_group else None)
    zone_override = (str(body.zone_override or "").strip() if body.set_zone_override else None)
    if body.set_zone_override and not zone_override:
        raise HTTPException(status_code=400, detail="zone_override cannot be empty when set_zone_override=true")
    changed_group = 0
    changed_zone = 0
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for did in ids:
            if body.set_notification_group:
                cur.execute(
                    "UPDATE device_state SET notification_group = ? WHERE device_id = ?",
                    (notif_group, did),
                )
                changed_group += int(cur.rowcount or 0)
            if body.set_zone_override:
                cur.execute(
                    """
                    INSERT INTO device_zone_overrides (device_id, zone, updated_by, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                      zone = excluded.zone,
                      updated_by = excluded.updated_by,
                      updated_at = excluded.updated_at
                    """,
                    (did, zone_override, principal.username, now),
                )
                cur.execute("UPDATE device_state SET zone = ? WHERE device_id = ?", (zone_override, did))
                changed_zone += int(cur.rowcount or 0)
            if body.clear_zone_override:
                cur.execute("DELETE FROM device_zone_overrides WHERE device_id = ?", (did,))
                cur.execute(
                    """
                    SELECT last_status_json, last_heartbeat_json, last_ack_json, last_event_json
                    FROM device_state WHERE device_id = ?
                    """,
                    (did,),
                )
                zrow = cur.fetchone()
                zone_from_payload = _extract_zone_from_device_state_row(zrow)
                cur.execute("UPDATE device_state SET zone = ? WHERE device_id = ?", (zone_from_payload, did))
                changed_zone += int(cur.rowcount or 0)
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    emit_event(
        level="info",
        category="device",
        event_type="device.bulk_profile",
        summary=f"bulk profile update {len(ids)} device(s)",
        actor=principal.username,
        target="devices",
        detail={
            "count": len(ids),
            "set_notification_group": bool(body.set_notification_group),
            "notification_group": notif_group if body.set_notification_group else None,
            "set_zone_override": bool(body.set_zone_override),
            "zone_override": zone_override if body.set_zone_override else None,
            "clear_zone_override": bool(body.clear_zone_override),
            "changed_group_rows": changed_group,
            "changed_zone_rows": changed_zone,
        },
    )
    return {
        "ok": True,
        "count": len(ids),
        "changed_group_rows": changed_group,
        "changed_zone_rows": changed_zone,
        "set_notification_group": bool(body.set_notification_group),
        "set_zone_override": bool(body.set_zone_override),
        "clear_zone_override": bool(body.clear_zone_override),
    }


@app.get("/admin/devices/{device_id}/shares")
def list_device_shares(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
        assert_device_owner(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT a.device_id, a.grantee_username, u.role AS grantee_role,
                       a.can_view, a.can_operate, a.granted_by, a.granted_at, a.revoked_at
                FROM device_acl a
                LEFT JOIN dashboard_users u ON u.username = a.grantee_username
                WHERE a.device_id = ?
                ORDER BY a.revoked_at IS NOT NULL ASC, a.granted_at DESC
                """,
                (device_id,),
            )
        else:
            cur.execute(
                """
                SELECT a.device_id, a.grantee_username, u.role AS grantee_role,
                       a.can_view, a.can_operate, a.granted_by, a.granted_at, a.revoked_at
                FROM device_acl a
                LEFT JOIN dashboard_users u ON u.username = a.grantee_username
                WHERE a.device_id = ?
                  AND u.role = 'user'
                  AND IFNULL(u.manager_admin,'') = ?
                ORDER BY a.revoked_at IS NOT NULL ASC, a.granted_at DESC
                """,
                (device_id, principal.username),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.get("/admin/shares")
def list_all_shares(
    principal: Principal = Depends(require_principal),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=128),
    grantee_username: Optional[str] = Query(default=None, min_length=2, max_length=64),
    include_revoked: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=2000),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
    clauses = ["1=1"]
    args: list[Any] = []
    if device_id:
        clauses.append("a.device_id = ?")
        args.append(device_id.strip())
    if grantee_username:
        clauses.append("a.grantee_username = ?")
        args.append(grantee_username.strip())
    if not include_revoked:
        clauses.append("a.revoked_at IS NULL")
    if principal.role == "admin":
        clauses.append("IFNULL(o.owner_admin,'') = ?")
        args.append(principal.username)
        clauses.append("u.role = 'user'")
        clauses.append("IFNULL(u.manager_admin,'') = ?")
        args.append(principal.username)
    where = " AND ".join(clauses)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT a.device_id, a.grantee_username, u.role AS grantee_role,
                   a.can_view, a.can_operate, a.granted_by, a.granted_at, a.revoked_at,
                   o.owner_admin
            FROM device_acl a
            LEFT JOIN dashboard_users u ON u.username = a.grantee_username
            LEFT JOIN device_ownership o ON o.device_id = a.device_id
            WHERE {where}
            ORDER BY a.revoked_at IS NOT NULL ASC, a.granted_at DESC
            LIMIT ?
            """,
            tuple(args + [limit]),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows, "count": len(rows)}


@app.post("/admin/devices/{device_id}/share")
def share_device(
    device_id: str,
    req: DeviceShareRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
        assert_device_owner(principal, device_id)
    grantee = req.grantee_username.strip()
    if not grantee:
        raise HTTPException(status_code=400, detail="grantee_username required")
    if not req.can_view and not req.can_operate:
        raise HTTPException(status_code=400, detail="at least one permission is required")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM device_state WHERE device_id = ?", (device_id,))
        if not cur.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        cur.execute("SELECT role, status, manager_admin FROM dashboard_users WHERE username = ?", (grantee,))
        ur = cur.fetchone()
        if not ur:
            conn.close()
            raise HTTPException(status_code=404, detail="grantee not found")
        role = str(ur["role"] or "")
        status = str(ur["status"] or "active")
        if principal.role == "superadmin":
            if role not in ("admin", "user"):
                conn.close()
                raise HTTPException(status_code=400, detail="only admin/user can be shared")
        else:
            # Admin can only share to own managed users.
            if role != "user":
                conn.close()
                raise HTTPException(status_code=400, detail="admin can only share to user")
            if str(ur["manager_admin"] or "") != principal.username:
                conn.close()
                raise HTTPException(status_code=403, detail="target user is not under this admin")
        if status not in ("active", ""):
            conn.close()
            raise HTTPException(status_code=400, detail=f"grantee is not active: {status}")
        now = utc_now_iso()
        cur.execute(
            """
            INSERT INTO device_acl (
                device_id, grantee_username, can_view, can_operate, granted_by, granted_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(device_id, grantee_username) DO UPDATE SET
                can_view = excluded.can_view,
                can_operate = excluded.can_operate,
                granted_by = excluded.granted_by,
                granted_at = excluded.granted_at,
                revoked_at = NULL
            """,
            (device_id, grantee, 1 if req.can_view else 0, 1 if req.can_operate else 0, principal.username, now),
        )
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(
        principal.username,
        "device.share.grant",
        device_id,
        {"grantee_username": grantee, "can_view": bool(req.can_view), "can_operate": bool(req.can_operate)},
    )
    return {
        "ok": True,
        "device_id": device_id,
        "grantee_username": grantee,
        "can_view": bool(req.can_view),
        "can_operate": bool(req.can_operate),
    }


@app.delete("/admin/devices/{device_id}/share/{grantee_username}")
def unshare_device(
    device_id: str,
    grantee_username: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_manage_users")
        assert_device_owner(principal, device_id)
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT role, manager_admin FROM dashboard_users WHERE username = ?", (grantee_username,))
            ur = cur.fetchone()
            conn.close()
        if not ur or str(ur["role"] or "") != "user" or str(ur["manager_admin"] or "") != principal.username:
            raise HTTPException(status_code=403, detail="cannot revoke share for this grantee")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE device_acl
            SET revoked_at = ?
            WHERE device_id = ? AND grantee_username = ? AND revoked_at IS NULL
            """,
            (utc_now_iso(), device_id, grantee_username),
        )
        changed = cur.rowcount
        conn.commit()
        conn.close()
    if changed == 0:
        raise HTTPException(status_code=404, detail="active share not found")
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "device.share.revoke", device_id, {"grantee_username": grantee_username})
    return {"ok": True, "device_id": device_id, "grantee_username": grantee_username}


@app.get("/devices/{device_id}/messages")
def get_device_messages(
    device_id: str,
    channel: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_view_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")

    query = """
        SELECT id, topic, channel, device_id, payload_json, ts_device, ts_received
        FROM messages
        WHERE device_id = ?
    """
    args: list[Any] = [device_id]
    if channel:
        query += " AND channel = ?"
        args.append(channel)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    for r in rows:
        r["payload"] = json.loads(r.pop("payload_json"))
    return {"items": rows}


def generate_device_credentials(device_id: str) -> tuple[str, str, str]:
    if (not ENFORCE_PER_DEVICE_CREDS) and PROVISION_USE_SHARED_MQTT_CREDS and MQTT_USERNAME:
        mqtt_username = MQTT_USERNAME
        mqtt_password = MQTT_PASSWORD
    else:
        suffix = device_id.replace("-", "").lower()[:12]
        mqtt_username = f"dev_{suffix}"
        mqtt_password = secrets.token_urlsafe(24)
    cmd_key = secrets.token_hex(8).upper()
    return mqtt_username, mqtt_password, cmd_key


def get_cmd_key_for_device(device_id: str) -> str:
    """Resolve signing key for MQTT /cmd. Match credentials case-insensitively — claim may
    have stored mixed-case device_id while the console route uses uppercase (or vice versa);
    falling back to CMD_AUTH_KEY then breaks every Danger-zone /commands publish."""
    raw = str(device_id or "").strip()
    if not raw:
        return str(CMD_AUTH_KEY or "").strip().upper()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT cmd_key FROM provisioned_credentials WHERE UPPER(device_id) = UPPER(?) LIMIT 1",
            (raw,),
        )
        row = cur.fetchone()
        conn.close()
    if row and row["cmd_key"]:
        return str(row["cmd_key"]).strip().upper()
    return str(CMD_AUTH_KEY or "").strip().upper()


def get_cmd_keys_for_devices(device_ids: list[str]) -> dict[str, str]:
    """Batch-resolve MQTT /cmd signing keys. Keys are ``UPPER(device_id)`` → cmd_key."""
    ids = sorted({str(x or "").strip().upper() for x in device_ids if str(x or "").strip()})
    if not ids:
        return {}
    out: dict[str, str] = {}
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        ph = ",".join(["?"] * len(ids))
        cur.execute(
            f"SELECT UPPER(device_id) AS u, cmd_key FROM provisioned_credentials WHERE UPPER(device_id) IN ({ph})",
            tuple(ids),
        )
        for r in cur.fetchall():
            ck = str(r["cmd_key"] or "").strip().upper()
            if ck:
                out[str(r["u"])] = ck
        conn.close()
    return out


def publish_bootstrap_claim(
    mac_nocolon: str,
    claim_nonce: str,
    device_id: str,
    zone: str,
    qr_code: str,
    mqtt_username: str,
    mqtt_password: str,
    cmd_key: str,
) -> None:
    global mqtt_client
    if mqtt_client is None:
        raise HTTPException(status_code=500, detail="mqtt client not ready")

    topic = f"{TOPIC_ROOT}/bootstrap/assign/{mac_nocolon}"
    payload = {
        "type": "bootstrap.assign",
        "bind_key": BOOTSTRAP_BIND_KEY,
        "mac_nocolon": mac_nocolon,
        "claim_nonce": claim_nonce,
        "device_id": device_id,
        "zone": zone,
        "qr_code": qr_code,
        "mqtt_username": mqtt_username,
        "mqtt_password": mqtt_password,
        "cmd_key": cmd_key,
        "ts": int(time.time()),
    }
    info = mqtt_client.publish(topic, json.dumps(payload, ensure_ascii=True), qos=1)
    info.wait_for_publish(timeout=3.0)
    if not info.is_published():
        raise HTTPException(status_code=502, detail="bootstrap publish failed")


MQTT_PUBLISH_WAIT_MS = max(0, min(5000, int(os.getenv("MQTT_PUBLISH_WAIT_MS", "800"))))
# TTL (seconds) for the idempotency cache. Must be long enough to eat a double-click
# or a rushed retry (UI, proxy, accidental re-post), short enough to not hide a
# genuinely re-issued operator action minutes later.
PUBLISH_DEDUPE_TTL_S = max(5, min(120, int(os.getenv("PUBLISH_DEDUPE_TTL_S", "30"))))

# In-memory idempotency cache: { dedupe_key -> (cmd_id, expire_epoch_s) }.
# Process-local only (ok: multi-worker deployments should use sticky sessions
# for the admin dashboard; background fan-out has its own wall-clock cap).
_publish_dedupe_cache: dict[str, tuple[str, float]] = {}
_publish_dedupe_lock = threading.Lock()


def _publish_dedupe_get(key: str) -> Optional[str]:
    if not key:
        return None
    now = time.time()
    with _publish_dedupe_lock:
        # Opportunistic prune so the cache can't grow unbounded under a flood.
        if len(_publish_dedupe_cache) > 2048:
            expired = [k for k, (_cid, exp) in _publish_dedupe_cache.items() if exp <= now]
            for k in expired:
                _publish_dedupe_cache.pop(k, None)
        entry = _publish_dedupe_cache.get(key)
        if not entry:
            return None
        cid, exp = entry
        if exp <= now:
            _publish_dedupe_cache.pop(key, None)
            return None
        return cid


def _publish_dedupe_set(key: str, cmd_id: str, ttl_s: float) -> None:
    if not key or not cmd_id:
        return
    with _publish_dedupe_lock:
        _publish_dedupe_cache[key] = (cmd_id, time.time() + max(1.0, ttl_s))


def publish_command(
    topic: str,
    cmd: str,
    params: dict[str, Any],
    target_id: str,
    proto: int,
    cmd_key: str,
    *,
    wait_publish: bool = True,
    dedupe_key: Optional[str] = None,
    dedupe_ttl_s: Optional[float] = None,
) -> str:
    """Publish a /cmd frame. Returns generated ``cmd_id`` (so callers can wait on ACK by id).

    Does **not** block for retries. If the broker is disconnected, raises 503 immediately
    instead of stalling the caller (fan-out and HTTP handlers must stay responsive).
    When ``wait_publish=True`` (default), briefly waits for paho to drain (``MQTT_PUBLISH_WAIT_MS``)
    so QoS 1 can start delivery; callers that do fan-out in a worker pool can pass False.

    ``dedupe_key`` makes the publish idempotent over a short TTL: if the same key is
    re-used within the TTL, the previously generated ``cmd_id`` is returned and
    **no new MQTT message is published**. This lets callers that represent
    irreversible operations (unclaim_reset, factory-unregister, reboot) absorb
    double-clicks and accidental retries without sending two commands to the device.
    """
    global mqtt_client
    if dedupe_key:
        cached = _publish_dedupe_get(dedupe_key)
        if cached:
            logger.info("publish_command dedupe hit: %s -> %s", dedupe_key, cached)
            return cached
    if mqtt_client is None:
        raise HTTPException(status_code=503, detail="mqtt client not ready")
    if not mqtt_connected:
        raise HTTPException(status_code=503, detail="mqtt broker disconnected")
    cmd_id = str(uuid.uuid4())
    payload = {
        "proto": proto,
        "key": cmd_key,
        "target_id": target_id,
        "cmd": cmd,
        "params": params,
        "cmd_id": cmd_id,
    }
    body = json.dumps(payload, ensure_ascii=True)
    try:
        info = mqtt_client.publish(topic, body, qos=1)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"mqtt publish error: {exc}")
    if getattr(info, "rc", 0) not in (0, None):
        raise HTTPException(status_code=502, detail=f"mqtt publish rc={info.rc}")
    if wait_publish and MQTT_PUBLISH_WAIT_MS > 0:
        try:
            info.wait_for_publish(timeout=max(0.05, MQTT_PUBLISH_WAIT_MS / 1000.0))
        except Exception:
            pass
    if dedupe_key:
        _publish_dedupe_set(dedupe_key, cmd_id, float(dedupe_ttl_s or PUBLISH_DEDUPE_TTL_S))
    return cmd_id


def enqueue_scheduled_command(device_id: str, cmd: str, params: dict[str, Any], target_id: str, proto: int, execute_at_ts: int) -> int:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scheduled_commands (
                device_id, cmd, params_json, target_id, proto, execute_at_ts, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                device_id,
                cmd,
                json.dumps(params, ensure_ascii=True),
                target_id,
                proto,
                execute_at_ts,
                utc_now_iso(),
            ),
        )
        job_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
    return job_id


def resolve_target_devices(device_ids: list[str], principal: Optional[Principal] = None) -> list[str]:
    unique = sorted(set([d for d in device_ids if d]))
    zs, za = zone_sql_suffix(principal) if principal else ("", [])
    osf, osa = ("", [])
    if principal and not principal.is_superadmin():
        if principal.role == "admin":
            osf = " AND o.owner_admin = ? "
            osa = [principal.username]
        else:
            manager = get_manager_admin(principal.username)
            if not manager:
                osf = " AND 1=0 "
                osa = []
            else:
                osf = " AND o.owner_admin = ? "
                osa = [manager]
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if unique:
            placeholders = ",".join(["?"] * len(unique))
            cur.execute(
                f"""
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN revoked_devices r ON d.device_id = r.device_id
                LEFT JOIN device_ownership o ON d.device_id = o.device_id
                WHERE d.device_id IN ({placeholders}){zs} {osf} AND r.device_id IS NULL
                """,
                tuple(unique) + tuple(za) + tuple(osa),
            )
        else:
            cur.execute(
                f"""
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN revoked_devices r ON d.device_id = r.device_id
                LEFT JOIN device_ownership o ON d.device_id = o.device_id
                WHERE 1=1 {zs} {osf} AND r.device_id IS NULL
                """,
                tuple(za) + tuple(osa),
            )
        rows = cur.fetchall()
        conn.close()
    out: list[str] = []
    for r in rows:
        did = str(r["device_id"])
        z = str(r["zone"]) if r["zone"] is not None else ""
        if principal is None or principal.is_superadmin() or principal.has_all_zones() or principal.zone_ok(z):
            out.append(did)
    if len(out) > MAX_BULK_TARGETS:
        raise HTTPException(status_code=413, detail=f"target set too large (> {MAX_BULK_TARGETS})")
    return out


def scheduler_loop() -> None:
    next_cleanup_at = time.time() + 60
    next_probe_at = time.time() + 30  # kick probe worker ~30s after boot
    next_events_retention_at = time.time() + 300  # first retention pass ~5 min after boot
    next_pwd_prune_at = time.time() + 900
    next_pending_claim_prune_at = time.time() + 120
    while not scheduler_stop.is_set():
        now_ts = int(time.time())
        jobs: list[sqlite3.Row] = []
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, device_id, cmd, params_json, target_id, proto
                FROM scheduled_commands
                WHERE status = 'pending' AND execute_at_ts <= ?
                ORDER BY id ASC
                LIMIT 50
                """,
                (now_ts,),
            )
            jobs = cur.fetchall()
            conn.close()

        for job in jobs:
            jid = int(job["id"])
            try:
                topic = f"{TOPIC_ROOT}/{job['device_id']}/cmd"
                publish_command(
                    topic=topic,
                    cmd=str(job["cmd"]),
                    params=json.loads(str(job["params_json"])),
                    target_id=str(job["target_id"]),
                    proto=int(job["proto"]),
                    cmd_key=get_cmd_key_for_device(str(job["device_id"])),
                )
                with db_lock:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scheduled_commands SET status='done', executed_at=? WHERE id=?",
                        (utc_now_iso(), jid),
                    )
                    conn.commit()
                    conn.close()
            except Exception as exc:
                logger.exception("scheduled command failed id=%s err=%s", jid, exc)
                with db_lock:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scheduled_commands SET status='failed', executed_at=? WHERE id=?",
                        (utc_now_iso(), jid),
                    )
                    conn.commit()
                    conn.close()

        try:
            _fail_stale_scheduled_commands(now_ts)
        except Exception as exc:
            logger.warning("stale scheduled_commands cleanup failed: %s", exc)
        try:
            _expire_presence_probes_waiting_ack()
        except Exception as exc:
            logger.warning("presence probe ack expiry failed: %s", exc)
        try:
            _auto_reconcile_tick()
        except Exception as exc:
            logger.warning("auto reconcile tick failed: %s", exc)

        now = time.time()
        if now >= next_cleanup_at:
            cutoff = datetime.fromtimestamp(now - (MESSAGE_RETENTION_DAYS * 86400), tz=timezone.utc).isoformat()
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("DELETE FROM messages WHERE ts_received < ?", (cutoff,))
                cur.execute(
                    """
                    DELETE FROM scheduled_commands
                    WHERE status IN ('done','failed') AND executed_at IS NOT NULL AND executed_at < ?
                    """,
                    (cutoff,),
                )
                conn.commit()
                conn.close()
            next_cleanup_at = now + 3600

        if now >= next_probe_at:
            try:
                _presence_probe_tick()
            except Exception as exc:
                logger.warning("presence probe tick failed: %s", exc)
            next_probe_at = now + max(30, PRESENCE_PROBE_SCAN_SECONDS)

        if now >= next_events_retention_at:
            try:
                _events_retention_tick()
            except Exception as exc:
                logger.warning("events retention tick failed: %s", exc)
            next_events_retention_at = now + max(300, EVENT_RETENTION_SCAN_SECONDS)

        if now >= next_pwd_prune_at:
            try:
                _prune_password_reset_tokens()
            except Exception as exc:
                logger.warning("password reset token prune failed: %s", exc)
            next_pwd_prune_at = now + 21600  # every 6h

        if now >= next_pending_claim_prune_at:
            try:
                _prune_stale_pending_claims()
            except Exception as exc:
                logger.warning("pending_claim prune failed: %s", exc)
            next_pending_claim_prune_at = now + 900

        scheduler_stop.wait(SCHEDULER_POLL_SECONDS)


@app.get("/provision/pending")
def list_pending_claims(
    principal: Principal = Depends(require_principal),
    q: Optional[str] = Query(default=None, max_length=64, description="Filter by MAC (no colon) or QR substring"),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role != "superadmin":
        raise HTTPException(status_code=403, detail="pending claim list is superadmin-only")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if q and q.strip():
            like = f"%{q.strip()}%"
            like_mac = f"%{q.strip().upper().replace(':', '').replace('-', '')}%"
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                WHERE (mac_nocolon LIKE ? OR UPPER(mac) LIKE ? OR IFNULL(qr_code,'') LIKE ?)
                  AND NOT EXISTS (
                    SELECT 1 FROM provisioned_credentials pc
                    WHERE pc.device_id = pending_claims.proposed_device_id
                  )
                ORDER BY last_seen_at DESC
                """,
                (like_mac, like, like),
            )
        else:
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                WHERE NOT EXISTS (
                  SELECT 1 FROM provisioned_credentials pc
                  WHERE pc.device_id = pending_claims.proposed_device_id
                )
                ORDER BY last_seen_at DESC
                """
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.post("/provision/claim")
def claim_device(req: ClaimDeviceRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    mac_nocolon = req.mac_nocolon.upper()
    if len(mac_nocolon) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    if not re.fullmatch(DEVICE_ID_REGEX, req.device_id.strip().upper()):
        raise HTTPException(status_code=400, detail="device_id format rejected by policy")
    if not BOOTSTRAP_BIND_KEY:
        raise HTTPException(status_code=500, detail="server BOOTSTRAP_BIND_KEY not configured")
    did_norm = req.device_id.strip().upper()
    ensure_not_revoked(did_norm)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM pending_claims WHERE mac_nocolon = ?", (mac_nocolon,))
        pending = cur.fetchone()
        if not pending:
            conn.close()
            raise HTTPException(status_code=404, detail="pending device not found")
        cur.execute(
            "SELECT mac_nocolon FROM provisioned_credentials WHERE UPPER(device_id) = UPPER(?) LIMIT 1",
            (did_norm,),
        )
        exist_id = cur.fetchone()
        if exist_id:
            conn.close()
            raise HTTPException(status_code=409, detail="device_id already registered")
        cur.execute(
            "SELECT device_id FROM provisioned_credentials WHERE mac_nocolon = ?",
            (mac_nocolon,),
        )
        existing = cur.fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=409, detail="device already claimed")

        claim_nonce = str(pending["claim_nonce"])
        qr_code = req.qr_code if req.qr_code else (str(pending["qr_code"] or "") or f"CROC-{mac_nocolon}")
        if req.qr_code:
            if not re.fullmatch(QR_CODE_REGEX, req.qr_code):
                conn.close()
                raise HTTPException(status_code=400, detail="qr_code format rejected by policy")
            if QR_SIGN_SECRET and not verify_qr_signature(req.qr_code):
                conn.close()
                raise HTTPException(status_code=401, detail="qr_code signature invalid")
        if ENFORCE_DEVICE_CHALLENGE:
            cur.execute(
                """
                SELECT id, verified_at, used
                FROM provision_challenges
                WHERE mac_nocolon = ? AND device_id = ? AND expires_at_ts >= ?
                ORDER BY id DESC LIMIT 1
                """,
                (mac_nocolon, did_norm, int(time.time())),
            )
            ch = cur.fetchone()
            if not ch or not ch["verified_at"] or int(ch["used"]) == 1:
                conn.close()
                raise HTTPException(status_code=412, detail="verified device challenge required before claim")
        mqtt_username, mqtt_password, cmd_key = generate_device_credentials(did_norm)

        cur.execute(
            """
            INSERT INTO provisioned_credentials (
                device_id, mac_nocolon, mqtt_username, mqtt_password, cmd_key, zone, qr_code, claimed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                mac_nocolon = excluded.mac_nocolon,
                mqtt_username = excluded.mqtt_username,
                mqtt_password = excluded.mqtt_password,
                cmd_key = excluded.cmd_key,
                zone = excluded.zone,
                qr_code = excluded.qr_code,
                claimed_at = excluded.claimed_at
            """,
            (
                did_norm,
                mac_nocolon,
                mqtt_username,
                mqtt_password,
                cmd_key,
                req.zone,
                qr_code,
                utc_now_iso(),
            ),
        )
        conn.commit()
        conn.close()
    owner_admin = principal.username
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_ownership (device_id, owner_admin, assigned_by, assigned_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
              owner_admin = excluded.owner_admin,
              assigned_by = excluded.assigned_by,
              assigned_at = excluded.assigned_at
            """,
            (did_norm, owner_admin, principal.username, utc_now_iso()),
        )
        # Stale device_state from a previous tenant/owner: clear profile fields on (re)claim
        cur.execute(
            "UPDATE device_state SET display_label = '', notification_group = '' WHERE device_id = ?",
            (did_norm,),
        )
        conn.commit()
        conn.close()
        cache_invalidate("devices")
        cache_invalidate("overview")
    if ENFORCE_DEVICE_CHALLENGE:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE provision_challenges SET used = 1
                WHERE mac_nocolon = ? AND device_id = ? AND verified_at IS NOT NULL AND used = 0
                """,
                (mac_nocolon, did_norm),
            )
            conn.commit()
            conn.close()

    publish_bootstrap_claim(
        mac_nocolon=mac_nocolon,
        claim_nonce=claim_nonce,
        device_id=did_norm,
        zone=req.zone,
        qr_code=qr_code,
        mqtt_username=mqtt_username,
        mqtt_password=mqtt_password,
        cmd_key=cmd_key,
    )

    resp = {
        "ok": True,
        "device_id": did_norm,
        "mac_nocolon": mac_nocolon,
        "mqtt_username": mqtt_username if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "mqtt_password": mqtt_password if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "cmd_key": cmd_key if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
    }
    audit_event(
        principal.username,
        "provision.claim",
        did_norm,
        {
            "mac_nocolon": mac_nocolon,
            "zone": req.zone,
            "owner_admin": owner_admin,
            "device_id": did_norm,
            "role": principal.role,
        },
    )
    return resp


@app.get("/audit")
def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    actor: Optional[str] = Query(default=None, max_length=64),
    action: Optional[str] = Query(default=None, max_length=64),
    target: Optional[str] = Query(default=None, max_length=128),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    clauses: list[str] = ["1=1"]
    args: list[Any] = []
    if principal.role == "admin":
        # admin only sees:
        #   - own actions
        #   - actions on users they manage
        #   - actions on devices they own (or legacy unowned if allowed)
        owned_sub = (
            "SELECT username FROM dashboard_users WHERE manager_admin = ?"
        )
        clauses.append(
            "(actor = ? OR target IN (" + owned_sub + ") OR target IN "
            "(SELECT device_id FROM device_ownership WHERE owner_admin = ?))"
        )
        args.extend([principal.username, principal.username, principal.username])
        clauses.append("actor NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin')")
    if actor:
        clauses.append("actor = ?")
        args.append(actor)
    if action:
        clauses.append("action LIKE ?")
        args.append(f"{action}%")
    if target:
        clauses.append("target = ?")
        args.append(target)
    where = " AND ".join(clauses)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT id, actor, action, target, detail_json, created_at
            FROM audit_events
            WHERE {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            tuple(args + [limit]),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        try:
            r["detail"] = json.loads(r.pop("detail_json") or "{}")
        except Exception:
            r["detail"] = {}
    return {"items": rows}


@app.get("/logs/messages")
def get_logs_messages(
    channel: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if principal.role == "user" and not device_id:
        raise HTTPException(status_code=403, detail="device_id is required for this role")
    zs, za = zone_sql_suffix(principal, "d.zone")
    osf, osa = owner_scope_clause_for_device_state(principal, "d")
    query = """
        SELECT m.id, m.topic, m.channel, m.device_id, m.payload_json, m.ts_device, m.ts_received
        FROM messages m
        JOIN device_state d ON m.device_id = d.device_id
        WHERE 1=1
    """
    args: list[Any] = []
    query += zs
    args.extend(za)
    query += osf
    args.extend(osa)
    if channel:
        query += " AND m.channel = ?"
        args.append(channel)
    if device_id:
        assert_device_view_access(principal, device_id)
        query += " AND m.device_id = ?"
        args.append(device_id)
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
            zr = cur.fetchone()
            conn.close()
        if not zr:
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    query += " ORDER BY m.id DESC LIMIT ?"
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(query, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    for row in rows:
        row["payload"] = json.loads(row.pop("payload_json"))
    return {"items": rows}


@app.get("/logs/file")
def get_log_file_tail(
    tail: int = Query(default=200, ge=10, le=5000),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    if not os.path.exists(LOG_FILE_PATH):
        return {"lines": []}
    with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return {"lines": [ln.rstrip("\n") for ln in lines[-tail:]]}


@app.post("/devices/{device_id}/commands")
def send_device_command(
    device_id: str,
    req: CommandRequest,
    request: Request,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    target = req.target_id or device_id
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    publish_command(topic, req.cmd, req.params, target, req.proto, get_cmd_key_for_device(device_id))
    ctx = _client_context(request)
    emit_event(
        level="info",
        category="device",
        event_type="device.command.send",
        summary=f"command {req.cmd} to {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=_lookup_owner_admin(device_id) or "",
        device_id=device_id,
        detail={
            "cmd": req.cmd,
            "target_id": target,
            "trigger_kind": ctx.get("client_kind", "web"),
            "ip": ctx.get("ip", ""),
            "platform": ctx.get("platform", ""),
            "device_type": ctx.get("device_type", ""),
            "mac_hint": ctx.get("mac_hint", ""),
            "geo": ctx.get("geo", ""),
        },
    )
    return {"ok": True, "topic": topic, "target_id": target}


def _load_device_row_for_task(device_id: str) -> tuple[dict[str, Any], Optional[str]]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone, IFNULL(notification_group,'') AS notification_group, IFNULL(last_ack_json,'') AS last_ack_json FROM device_state WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        ow = cur.fetchone()
        owner = str(ow["owner_admin"]) if ow and ow["owner_admin"] else None
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    return dict(row), owner


@app.get("/devices/{device_id}/trigger-policy")
def get_device_trigger_policy(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    if not _principal_tenant_owns_device(principal, owner):
        raise HTTPException(
            status_code=403,
            detail="trigger policy is managed by the owning tenant only (device share does not include group policy)",
        )
    group_key = str(row.get("notification_group") or "")
    pol = _trigger_policy_for(owner, group_key)
    return {"ok": True, "device_id": device_id, "scope_group": group_key, "policy": pol}


@app.put("/devices/{device_id}/trigger-policy")
def save_device_trigger_policy(
    device_id: str,
    body: TriggerPolicyBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id, check_revoked=False)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    if not _principal_tenant_owns_device(principal, owner):
        raise HTTPException(
            status_code=403,
            detail="trigger policy is managed by the owning tenant only (device share does not include group policy)",
        )
    group_key = str(row.get("notification_group") or "")
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO trigger_policies (
                owner_admin, scope_group, panic_local_siren, remote_silent_link_enabled,
                remote_loud_link_enabled, remote_loud_duration_ms, fanout_exclude_self,
                panic_link_enabled, panic_fanout_duration_ms, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_admin, scope_group) DO UPDATE SET
                panic_local_siren=excluded.panic_local_siren,
                remote_silent_link_enabled=excluded.remote_silent_link_enabled,
                remote_loud_link_enabled=excluded.remote_loud_link_enabled,
                remote_loud_duration_ms=excluded.remote_loud_duration_ms,
                fanout_exclude_self=excluded.fanout_exclude_self,
                panic_link_enabled=excluded.panic_link_enabled,
                panic_fanout_duration_ms=excluded.panic_fanout_duration_ms,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (
                owner or "",
                group_key,
                1 if body.panic_local_siren else 0,
                1 if body.remote_silent_link_enabled else 0,
                1 if body.remote_loud_link_enabled else 0,
                int(body.remote_loud_duration_ms),
                1 if body.fanout_exclude_self else 0,
                1 if body.panic_link_enabled else 0,
                int(body.panic_fanout_duration_ms),
                principal.username,
                now,
            ),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "trigger.policy.save", target=device_id, detail={"group": group_key, "owner_admin": owner or ""})
    return {"ok": True, "device_id": device_id, "scope_group": group_key}


@app.post("/devices/{device_id}/provision/wifi-task")
def start_wifi_provision_task(
    device_id: str,
    body: ProvisionWifiTaskRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    chain_out: list[dict[str, Any]] = []
    for it in body.chain:
        c = (it.cmd or "").strip()
        if c not in _WIFI_DEFERRED_CMDS:
            raise HTTPException(
                status_code=400,
                detail=f"chain cmd not allowed: {c!r} (allowed: {', '.join(sorted(_WIFI_DEFERRED_CMDS))})",
            )
        chain_out.append({"cmd": c, "params": dict(it.params or {})})
    now = utc_now_iso()
    task_id = secrets.token_hex(12)
    params: dict[str, Any] = {"ssid": body.ssid, "password": body.password}
    if chain_out:
        params["chain"] = chain_out
    publish_command(
        topic=f"{TOPIC_ROOT}/{device_id}/cmd",
        cmd="wifi_config",
        params=params,
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=get_cmd_key_for_device(device_id),
    )
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO provision_tasks (
                task_id, owner_admin, device_id, kind, status, progress, message,
                request_json, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                owner or "",
                device_id,
                "wifi_config",
                "running",
                35,
                "command sent, waiting ack",
                json.dumps({"ssid": body.ssid, "chain": chain_out}, ensure_ascii=False),
                principal.username,
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
    emit_event(
        level="info",
        category="provision",
        event_type="provision.wifi.task.start",
        summary=f"wifi task started for {device_id}",
        actor=principal.username,
        target=device_id,
        owner_admin=owner or "",
        device_id=device_id,
        detail={"task_id": task_id, "chain_len": len(chain_out)},
    )
    return {"ok": True, "task_id": task_id, "status": "running", "progress": 35}


@app.get("/devices/{device_id}/provision/wifi-task/{task_id}")
def get_wifi_provision_task(
    device_id: str,
    task_id: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT task_id, status, progress, message, created_at, updated_at, request_json
            FROM provision_tasks
            WHERE task_id = ? AND device_id = ?
            """,
            (task_id, device_id),
        )
        tr = cur.fetchone()
        if not tr:
            conn.close()
            raise HTTPException(status_code=404, detail="task not found")
        status = str(tr["status"])
        progress = int(tr["progress"] or 0)
        message = str(tr["message"] or "")
        if status == "running":
            ack_obj: dict[str, Any] = {}
            try:
                ack_raw = str(row.get("last_ack_json") or "")
                ack_obj = json.loads(ack_raw) if ack_raw else {}
            except Exception:
                ack_obj = {}
            if str(ack_obj.get("cmd") or "") == "wifi_config" and isinstance(ack_obj.get("ok"), bool):
                status = "success" if bool(ack_obj.get("ok")) else "failed"
                progress = 100
                message = str(ack_obj.get("detail") or ("wifi saved" if status == "success" else "wifi rejected"))
                cur.execute(
                    "UPDATE provision_tasks SET status=?, progress=?, message=?, updated_at=? WHERE task_id=?",
                    (status, progress, message, utc_now_iso(), task_id),
                )
                conn.commit()
            else:
                progress = max(progress, 60)
                message = "waiting device ack/reboot"
        req_obj: dict[str, Any] = {}
        try:
            req_obj = json.loads(str(tr["request_json"] or "{}"))
        except Exception:
            req_obj = {}
        conn.close()
    return {
        "ok": True,
        "task_id": task_id,
        "device_id": device_id,
        "owner_admin": owner or "",
        "status": status,
        "progress": progress,
        "message": message,
        "request": req_obj,
        "created_at": tr["created_at"],
        "updated_at": tr["updated_at"],
    }


@app.post("/devices/{device_id}/alert/on")
def device_alert_on(
    device_id: str,
    duration_ms: int = Query(default=DEFAULT_REMOTE_FANOUT_MS, ge=500, le=300000),
    request: Request = None,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    ensure_not_revoked(device_id)
    assert_device_siren_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    publish_command(
        topic=topic,
        cmd="siren_on",
        params={"duration_ms": duration_ms},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=get_cmd_key_for_device(device_id),
    )
    z = str(zr["zone"] if zr["zone"] is not None else "")
    owner = _lookup_owner_admin(device_id)
    ctx = _client_context(request) if request else {}
    _log_signal_trigger(
        "remote_siren_on",
        device_id,
        z,
        principal.username,
        owner,
        duration_ms=duration_ms,
        target_count=1,
        detail=ctx,
    )
    _remote_siren_notify_email(
        action="ON",
        device_id=device_id,
        zone=z,
        actor=principal.username,
        owner_admin=owner,
        duration_ms=duration_ms,
    )
    emit_event(
        level="warn",
        category="alarm",
        event_type="remote.siren_on",
        summary=f"Remote siren ON {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=owner or "",
        device_id=device_id,
        detail={"duration_ms": duration_ms, "zone": z, **ctx},
    )
    return {"ok": True}


@app.post("/devices/{device_id}/alert/off")
def device_alert_off(device_id: str, request: Request, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    ensure_not_revoked(device_id)
    assert_device_siren_access(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    publish_command(
        topic=topic,
        cmd="siren_off",
        params={},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=get_cmd_key_for_device(device_id),
    )
    z = str(zr["zone"] if zr["zone"] is not None else "")
    owner = _lookup_owner_admin(device_id)
    _log_signal_trigger(
        "remote_siren_off",
        device_id,
        z,
        principal.username,
        owner,
        duration_ms=None,
        target_count=1,
        detail=_client_context(request),
    )
    _remote_siren_notify_email(
        action="OFF",
        device_id=device_id,
        zone=z,
        actor=principal.username,
        owner_admin=owner,
        duration_ms=None,
    )
    emit_event(
        level="info",
        category="alarm",
        event_type="remote.siren_off",
        summary=f"Remote siren OFF {device_id} by {principal.username}",
        actor=principal.username,
        target=device_id,
        owner_admin=owner or "",
        device_id=device_id,
        detail={"zone": z, **_client_context(request)},
    )
    return {"ok": True}


@app.post("/alerts")
def bulk_alert(req: BulkAlertRequest, request: Request, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    targets = resolve_target_devices(req.device_ids, principal)
    if not targets:
        return {"ok": True, "sent_count": 0, "device_ids": []}

    sent = 0
    for did in targets:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        if req.action == "on":
            publish_command(
                topic=topic,
                cmd="siren_on",
                params={"duration_ms": req.duration_ms},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
        else:
            publish_command(
                topic=topic,
                cmd="siren_off",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
        sent += 1

    if sent > 0:
        own = _lookup_owner_admin(targets[0])
        owner_admins: list[str] = []
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            ph = ",".join(["?"] * len(targets))
            cur.execute(
                f"SELECT DISTINCT IFNULL(owner_admin,'') AS owner_admin FROM device_ownership WHERE device_id IN ({ph})",
                tuple(targets),
            )
            owner_admins = [str(r["owner_admin"]) for r in cur.fetchall() if r["owner_admin"]]
            conn.close()
        ctx = _client_context(request)
        _log_signal_trigger(
            f"bulk_siren_{req.action}",
            "*",
            "",
            principal.username,
            own,
            duration_ms=req.duration_ms if req.action == "on" else None,
            target_count=sent,
            detail={"device_ids": targets, "owner_admins": owner_admins[:16], **ctx},
        )
        if notifier.enabled() and own:
            rec = _recipients_for_admin(own)
            if rec:
                subj = f"[Croc Sentinel] Bulk siren {req.action} ×{sent} by {principal.username}"
                body = "Targets:\n" + "\n".join(targets[:120])
                notifier.enqueue(rec, subj, body, None)
        emit_event(
            level="warn" if req.action == "on" else "info",
            category="alarm",
            event_type=f"bulk.siren_{req.action}",
            summary=f"Bulk siren {req.action} {sent} device(s) by {principal.username}",
            actor=principal.username,
            target=",".join(targets[:8]),
            owner_admin=own or "",
            detail={
                "count": sent,
                "device_ids": targets[:64],
                "owner_admins": owner_admins[:16],
                "trigger_kind": ctx.get("client_kind", "web"),
                "ip": ctx.get("ip", ""),
                "platform": ctx.get("platform", ""),
                "device_type": ctx.get("device_type", ""),
                "mac_hint": ctx.get("mac_hint", ""),
                "geo": ctx.get("geo", ""),
            },
        )

    return {
        "ok": True,
        "action": req.action,
        "sent_count": sent,
        "device_ids": targets,
    }


@app.post("/devices/{device_id}/self-test")
def device_self_test(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    topic = f"{TOPIC_ROOT}/{device_id}/cmd"
    publish_command(
        topic=topic,
        cmd="self_test",
        params={},
        target_id=device_id,
        proto=CMD_PROTO,
        cmd_key=get_cmd_key_for_device(device_id),
    )
    return {"ok": True}


@app.post("/devices/{device_id}/schedule-reboot")
def device_schedule_reboot(device_id: str, req: ScheduleRebootRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        conn.close()
    if not zr:
        raise HTTPException(status_code=404, detail="device not found")
    assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
    now_ts = int(time.time())
    execute_at = 0
    if req.delay_s is not None:
        execute_at = now_ts + req.delay_s
    elif req.at_ts is not None and req.at_ts > now_ts + 5:
        execute_at = req.at_ts
    else:
        raise HTTPException(status_code=400, detail="provide valid delay_s or at_ts")

    job_id = enqueue_scheduled_command(
        device_id=device_id,
        cmd="reboot",
        params={},
        target_id=device_id,
        proto=CMD_PROTO,
        execute_at_ts=execute_at,
    )
    return {"ok": True, "job_id": job_id, "execute_at_ts": execute_at}


@app.get("/devices/{device_id}/scheduled-jobs")
def device_scheduled_jobs(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_device_command_actor(principal, device_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        if not zr:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
        conn.close()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, cmd, params_json, target_id, proto, execute_at_ts, status, created_at, executed_at
            FROM scheduled_commands
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT 200
            """,
            (device_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for row in rows:
        row["params"] = json.loads(row.pop("params_json"))
    return {"items": rows}


@app.post("/commands/broadcast")
def send_broadcast_command(req: BroadcastCommandRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id FROM device_state
            WHERE 1=1 {zs} {osf}
              AND device_id NOT IN (SELECT device_id FROM revoked_devices)
            """,
            tuple(za + osa),
        )
        device_ids = [r["device_id"] for r in cur.fetchall()]
        conn.close()

    if len(device_ids) > MAX_BULK_TARGETS:
        raise HTTPException(status_code=413, detail=f"target set too large (> {MAX_BULK_TARGETS})")

    for did in device_ids:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        publish_command(topic, req.cmd, req.params, req.target_id, req.proto, get_cmd_key_for_device(did))

    audit_event(principal.username, "command.broadcast", req.target_id, {
        "cmd": req.cmd,
        "sent_count": len(device_ids),
    })
    return {"ok": True, "target_id": req.target_id, "sent_count": len(device_ids)}


# =====================================================================
#  Alarms (server-side fan-out history)
# =====================================================================

def _alarm_scope_for(
    principal: Principal,
    *,
    device_id_sql: str = "alarms.source_id",
) -> tuple[str, list[Any]]:
    """SQL fragment restricting alarms/signal_triggers to what the principal may see.

    `device_id_sql` must be the device column in the current query (e.g. `alarms.source_id`, `a.source_id`, `s.device_id`)
    for ACL checks when a non-owner has a share.
    """
    if principal.is_superadmin():
        return "", []
    acl = (
        f"EXISTS (SELECT 1 FROM device_acl a2 "
        f"WHERE a2.device_id = {device_id_sql} AND a2.grantee_username = ? AND a2.revoked_at IS NULL "
        f"AND (a2.can_view=1 OR a2.can_operate=1))"
    )
    if principal.role == "admin":
        if _legacy_unowned_device_scope(principal):
            return (
                f" AND (owner_admin = ? OR owner_admin IS NULL OR ({acl})) ",
                [principal.username, principal.username],
            )
        return (
            f" AND (owner_admin = ? OR ({acl})) ",
            [principal.username, principal.username],
        )
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    if _legacy_unowned_device_scope(principal):
        return (
            f" AND (owner_admin = ? OR owner_admin IS NULL OR ({acl})) ",
            [manager, principal.username],
        )
    return (
        f" AND (owner_admin = ? OR ({acl})) ",
        [manager, principal.username],
    )


@app.get("/alarms")
def list_alarms(
    limit: int = Query(default=100, ge=1, le=500),
    since_hours: int = Query(default=168, ge=1, le=720),
    source_id: Optional[str] = Query(default=None),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    scope_sql, scope_args = _alarm_scope_for(principal, device_id_sql="alarms.source_id")
    args: list[Any] = list(scope_args)
    where_extra = ""
    if source_id:
        where_extra += " AND source_id = ? "
        args.append(source_id)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT id, source_id, owner_admin, zone, triggered_by, ts_device,
                   fanout_count, email_sent, email_detail, created_at
            FROM alarms
            WHERE created_at >= datetime('now', ?)
            {scope_sql}
            {where_extra}
            ORDER BY id DESC
            LIMIT ?
            """,
            tuple([f"-{since_hours} hours"] + args + [limit]),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.get("/alarms/summary")
def alarms_summary(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    scope_sql, scope_args = _alarm_scope_for(principal, device_id_sql="alarms.source_id")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"SELECT COUNT(*) AS c FROM alarms WHERE created_at >= datetime('now','-24 hours') {scope_sql}",
            tuple(scope_args),
        )
        last24 = int(cur.fetchone()["c"])
        cur.execute(
            f"SELECT COUNT(*) AS c FROM alarms WHERE created_at >= datetime('now','-7 days') {scope_sql}",
            tuple(scope_args),
        )
        last7 = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT source_id, COUNT(*) AS c
            FROM alarms
            WHERE created_at >= datetime('now','-7 days') {scope_sql}
            GROUP BY source_id
            ORDER BY c DESC
            LIMIT 10
            """,
            tuple(scope_args),
        )
        top = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"last_24h": last24, "last_7d": last7, "top_sources_7d": top}


@app.get("/activity/signals")
def list_activity_signals(
    limit: int = Query(default=100, ge=1, le=500),
    since_hours: int = Query(default=168, ge=1, le=720),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Unified feed: physical device alarms + dashboard/API remote siren actions."""
    assert_min_role(principal, "user")
    al_base, scope_args = _alarm_scope_for(principal, device_id_sql="a.source_id")
    since_arg = f"-{since_hours} hours"
    al_scope = al_base.replace("owner_admin", "a.owner_admin")
    st_scope = (
        al_base.replace("owner_admin", "s.owner_admin")
        .replace("a.source_id", "s.device_id", 1)
    )
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT a.id, a.created_at, 'device_alarm' AS kind, a.source_id AS device_id, a.zone,
                   a.triggered_by AS actor, a.fanout_count, a.email_sent, a.email_detail,
                   NULL AS duration_ms, IFNULL(d.display_label, '') AS display_label,
                   IFNULL(d.notification_group, '') AS notification_group
            FROM alarms a
            LEFT JOIN device_state d ON d.device_id = a.source_id
            WHERE a.created_at >= datetime('now', ?) {al_scope}
            ORDER BY a.id DESC LIMIT ?
            """,
            tuple([since_arg] + list(scope_args) + [limit]),
        )
        alarm_rows = [dict(r) for r in cur.fetchall()]
        sig_actor_hide = ""
        if principal.role != "superadmin":
            sig_actor_hide = " AND s.actor_username NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin') "
        cur.execute(
            f"""
            SELECT s.id, s.created_at, s.kind, s.device_id, s.zone,
                   s.actor_username AS actor, s.target_count AS fanout_count,
                   0 AS email_sent, '' AS email_detail, s.duration_ms,
                   IFNULL(d.display_label, '') AS display_label,
                   IFNULL(d.notification_group, '') AS notification_group, s.detail_json
            FROM signal_triggers s
            LEFT JOIN device_state d ON d.device_id = s.device_id
            WHERE s.created_at >= datetime('now', ?) {st_scope} {sig_actor_hide}
            ORDER BY s.id DESC LIMIT ?
            """,
            tuple([since_arg] + list(scope_args) + [limit]),
        )
        sig_rows = [dict(r) for r in cur.fetchall()]
        conn.close()

    all_dids = sorted(
        {str(r.get("device_id") or "").strip() for r in alarm_rows + sig_rows if r.get("device_id")}
    )
    owner_by_did: dict[str, str] = {}
    if all_dids:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            ph = ",".join(["?"] * len(all_dids))
            cur.execute(
                f"SELECT device_id, IFNULL(owner_admin,'') AS owner_admin FROM device_ownership WHERE device_id IN ({ph})",
                tuple(all_dids),
            )
            for owr in cur.fetchall():
                owner_by_did[str(owr["device_id"])] = str(owr["owner_admin"] or "")
            conn.close()

    merged: list[dict[str, Any]] = []
    for r in alarm_rows:
        did = str(r["device_id"] or "")
        ng = str(r.get("notification_group") or "")
        if did and not _principal_tenant_owns_device(principal, owner_by_did.get(did, "")):
            ng = ""
        merged.append(
            {
                "ts": r["created_at"],
                "kind": "device_alarm",
                "what": "alarm_fanout",
                "device_id": r["device_id"],
                "display_label": r["display_label"] or "",
                "notification_group": ng,
                "zone": r["zone"] or "",
                "who": r["actor"],
                "fanout_count": int(r["fanout_count"] or 0),
                "email_sent": bool(r["email_sent"]),
                "email_detail": r["email_detail"] or "",
                "duration_ms": r["duration_ms"],
                "_row": int(r["id"]),
            }
        )
    for r in sig_rows:
        did = str(r["device_id"] or "")
        ng = str(r.get("notification_group") or "")
        if did and not _principal_tenant_owns_device(principal, owner_by_did.get(did, "")):
            ng = ""
        merged.append(
            {
                "ts": r["created_at"],
                "kind": r["kind"],
                "what": r["kind"],
                "device_id": r["device_id"],
                "display_label": r["display_label"] or "",
                "notification_group": ng,
                "zone": r["zone"] or "",
                "who": r["actor"],
                "fanout_count": int(r["fanout_count"] or 0),
                "email_sent": bool(r["email_sent"]),
                "email_detail": r["email_detail"] or "",
                "duration_ms": r["duration_ms"],
                "detail_json": r.get("detail_json") or "",
                "_row": int(r["id"]),
            }
        )
    merged.sort(key=lambda x: (x["ts"] or "", x["_row"]), reverse=True)
    out_items = merged[:limit]
    for x in out_items:
        x.pop("_row", None)
    return {"items": out_items}


# =====================================================================
#  Email recipients (per-tenant) & SMTP test
# =====================================================================

class RecipientCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    label: Optional[str] = Field(default=None, max_length=80)
    enabled: bool = True


class RecipientUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    label: Optional[str] = Field(default=None, max_length=80)


def _admin_scope_for(principal: Principal) -> str:
    """Resolve which owner_admin the principal manages recipients for."""
    if principal.role == "superadmin":
        return ""  # superadmin must pick via ?for_admin=
    if principal.role == "admin":
        return principal.username
    return ""  # users can only view, not edit


@app.get("/admin/alert-recipients")
def list_recipients(
    for_admin: Optional[str] = Query(default=None),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    if principal.role == "user":
        target = get_manager_admin(principal.username)
    elif principal.role == "admin":
        target = principal.username
    else:
        target = (for_admin or "").strip()
        if not target:
            return {"items": [], "scope": ""}
    if not target:
        return {"items": [], "scope": ""}
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, owner_admin, email, label, enabled, created_at
            FROM admin_alert_recipients
            WHERE owner_admin = ?
            ORDER BY id ASC
            """,
            (target,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows, "scope": target}


@app.post("/admin/alert-recipients")
def create_recipient(
    req: RecipientCreateRequest,
    for_admin: Optional[str] = Query(default=None),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "superadmin":
        target = (for_admin or "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="for_admin query param required for superadmin")
    else:
        target = principal.username
    if "@" not in req.email:
        raise HTTPException(status_code=400, detail="email is not valid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO admin_alert_recipients (owner_admin, email, label, enabled, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target, req.email.strip(), req.label or "", 1 if req.enabled else 0, utc_now_iso()),
            )
            new_id = int(cur.lastrowid)
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="email already registered for this admin")
        conn.close()
    audit_event(principal.username, "recipient.add", target, {"email": req.email})
    return {"ok": True, "id": new_id}


@app.patch("/admin/alert-recipients/{rid}")
def update_recipient(
    rid: int,
    req: RecipientUpdateRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM admin_alert_recipients WHERE id = ?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="recipient not found")
        owner = str(row["owner_admin"])
        if principal.role == "admin" and owner != principal.username:
            conn.close()
            raise HTTPException(status_code=403, detail="not yours")
        fields: list[str] = []
        args: list[Any] = []
        if req.enabled is not None:
            fields.append("enabled = ?")
            args.append(1 if req.enabled else 0)
        if req.label is not None:
            fields.append("label = ?")
            args.append(req.label)
        if not fields:
            conn.close()
            return {"ok": True, "noop": True}
        args.append(rid)
        cur.execute(f"UPDATE admin_alert_recipients SET {', '.join(fields)} WHERE id = ?", tuple(args))
        conn.commit()
        conn.close()
    audit_event(principal.username, "recipient.update", owner, {"id": rid})
    return {"ok": True}


@app.delete("/admin/alert-recipients/{rid}")
def delete_recipient(rid: int, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM admin_alert_recipients WHERE id = ?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="recipient not found")
        owner = str(row["owner_admin"])
        if principal.role == "admin" and owner != principal.username:
            conn.close()
            raise HTTPException(status_code=403, detail="not yours")
        cur.execute("DELETE FROM admin_alert_recipients WHERE id = ?", (rid,))
        conn.commit()
        conn.close()
    audit_event(principal.username, "recipient.delete", owner, {"id": rid})
    return {"ok": True}


@app.get("/admin/smtp/status")
def smtp_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    return notifier.status()


class SmtpTestRequest(BaseModel):
    to: str = Field(min_length=3, max_length=120)
    subject: Optional[str] = Field(default=None, max_length=200)


@app.post("/admin/smtp/test")
def smtp_test(req: SmtpTestRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if "@" not in req.to:
        raise HTTPException(status_code=400, detail="invalid recipient")
    subject, text, html_body = render_smtp_test_email(
        actor_username=principal.username,
        iso_ts=malaysia_now_iso(),
        subject_override=req.subject,
    )
    try:
        notifier.send_sync([req.to], subject, text, html_body)
    except Exception as exc:
        audit_event(principal.username, "smtp.test.fail", req.to, {"error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Mail channel error: {exc}")
    audit_event(principal.username, "smtp.test.ok", req.to, {})
    return {"ok": True, "status": notifier.status()}


@app.get("/admin/telegram/status")
def telegram_admin_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import telegram_status

        return telegram_status()
    except Exception as exc:
        logging.getLogger(__name__).exception("telegram_admin_status import or call failed")
        return {
            "enabled": False,
            "chats": 0,
            "min_level": "info",
            "queue_size": 0,
            "worker_running": False,
            "last_error": str(exc),
            "last_send_ok": False,
            "token_hint": "",
            "status_module_error": True,
        }


@app.get("/admin/fcm/status")
def fcm_admin_status(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    try:
        from fcm_notify import fcm_status

        return fcm_status()
    except Exception as exc:
        logging.getLogger(__name__).exception("fcm_admin_status import or call failed")
        return {
            "enabled": False,
            "project_id": "",
            "detail": str(exc),
            "last_error": str(exc),
            "queue_size": 0,
            "worker_running": False,
        }


class TelegramTestRequest(BaseModel):
    text: str = Field(default="Croc Sentinel Telegram test OK", max_length=3900)


@app.post("/admin/telegram/test")
def telegram_admin_test(
    req: TelegramTestRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import send_telegram_text_now, telegram_status
    except ModuleNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="telegram_notify module missing from deployment image (rebuild API with telegram_notify.py)",
        ) from exc

    ok, detail = send_telegram_text_now(req.text.strip())
    if not ok:
        audit_event(principal.username, "telegram.test.fail", "", {"error": detail})
        raise HTTPException(status_code=502, detail=detail)
    audit_event(principal.username, "telegram.test.ok", "", {"detail": detail})
    return {"ok": True, "detail": detail, "telegram": telegram_status()}


@app.get("/admin/telegram/webhook-info")
def telegram_admin_webhook_info(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Shows Telegram getWebhookInfo (URL, last_error, pending updates) for debugging /start no-reply."""
    assert_min_role(principal, "admin")
    try:
        from telegram_notify import telegram_get_webhook_info
    except ModuleNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="telegram_notify module missing from deployment image",
        ) from exc
    ok, err, info = telegram_get_webhook_info()
    if not ok:
        raise HTTPException(status_code=502, detail=err)
    return {"ok": True, "webhook": info, "expected_path": "/integrations/telegram/webhook"}


class TelegramBindRequest(BaseModel):
    chat_id: str = Field(min_length=1, max_length=64)
    enabled: bool = True


class TelegramLinkTokenRequest(BaseModel):
    enabled_on_bind: bool = True


def _telegram_cmd_send_reply(chat_id: str, text: str) -> tuple[bool, str]:
    try:
        from telegram_notify import send_telegram_chat_text
    except Exception as exc:
        return False, f"telegram module unavailable: {exc}"
    return send_telegram_chat_text(chat_id, text)


def _telegram_cmd_send_reply_logged(chat_id: str, text: str, context: str) -> None:
    ok, detail = _telegram_cmd_send_reply(chat_id, text)
    if not ok:
        logger.warning("telegram webhook: send failed (%s) chat_id=%s: %s", context, chat_id, detail)


def _telegram_bind_chat(chat_id: str, username: str, enabled: bool) -> None:
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO telegram_chat_bindings (chat_id, username, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                username=excluded.username,
                enabled=excluded.enabled,
                updated_at=excluded.updated_at
            """,
            (chat_id, username, 1 if enabled else 0, now, now),
        )
        conn.commit()
        conn.close()
    _invalidate_superadmin_telegram_chats_cache()


def _telegram_policy_allow(principal: Principal, capability: str) -> bool:
    if principal.role == "superadmin":
        return True
    pol = get_effective_policy(principal)
    return int(pol.get(capability, 0)) == 1


def _telegram_require(principal: Principal, capability: str) -> None:
    if not _telegram_policy_allow(principal, capability):
        raise HTTPException(status_code=403, detail=f"telegram capability denied: {capability}")


def _telegram_bound_principal(chat_id: str) -> Principal:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, enabled FROM telegram_chat_bindings WHERE chat_id = ?", (chat_id,))
        row = cur.fetchone()
        conn.close()
    if not row:
        raise HTTPException(status_code=403, detail="chat is not bound")
    if int(row["enabled"] or 0) != 1:
        raise HTTPException(status_code=403, detail="chat binding disabled")
    return principal_for_username(str(row["username"]))


def _telegram_parse_targets(token: str) -> list[str]:
    raw = (token or "").strip()
    if not raw:
        return []
    if raw.lower() == "all":
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _telegram_cmd_recent_devices(principal: Principal, limit: int) -> str:
    _telegram_require(principal, "tg_view_devices")
    n = max(1, min(limit, TELEGRAM_COMMAND_MAX_DEVICES))
    zs, za = zone_sql_suffix(principal)
    osf, osa = owner_scope_clause_for_device_state(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id, IFNULL(display_label, '') AS display_label, IFNULL(zone,'') AS zone,
                   IFNULL(fw,'') AS fw, updated_at, last_status_json, last_heartbeat_json, last_ack_json, last_event_json
            FROM device_state
            WHERE 1=1 {zs} {osf}
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            tuple(za + osa + [n]),
        )
        rows = cur.fetchall()
        conn.close()
    now_s = int(time.time())
    lines = [f"Devices (latest {len(rows)}):"]
    for r in rows:
        d = dict(r)
        online = _device_is_online_sql_row(d, now_s)
        did = str(d.get("device_id") or "")
        label = str(d.get("display_label") or "")
        fw = str(d.get("fw") or "-")
        zone = str(d.get("zone") or "all")
        tag = "online" if online else "offline"
        lines.append(f"- {did} [{tag}] fw={fw} zone={zone}" + (f" label={label}" if label else ""))
    return "\n".join(lines)[:3900]


def _telegram_cmd_recent_logs(principal: Principal, limit: int) -> str:
    _telegram_require(principal, "tg_view_logs")
    n = max(1, min(limit, TELEGRAM_COMMAND_MAX_LOG))
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                """
                SELECT ts, level, category, event_type, IFNULL(device_id,'') AS device_id, IFNULL(summary,'') AS summary
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (n,),
            )
        elif principal.role == "admin":
            cur.execute(
                """
                SELECT ts, level, category, event_type, IFNULL(device_id,'') AS device_id, IFNULL(summary,'') AS summary
                FROM events
                WHERE owner_admin = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (principal.username, n),
            )
        else:
            mgr = get_manager_admin(principal.username)
            cur.execute(
                """
                SELECT ts, level, category, event_type, IFNULL(device_id,'') AS device_id, IFNULL(summary,'') AS summary
                FROM events
                WHERE owner_admin = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (mgr or "__none__", n),
            )
        rows = cur.fetchall()
        conn.close()
    lines = [f"Logs (latest {len(rows)}):"]
    for r in rows:
        ts = str(r["ts"] or "")
        lvl = str(r["level"] or "info").upper()
        cat = str(r["category"] or "-")
        et = str(r["event_type"] or "-")
        did = str(r["device_id"] or "-")
        summary = str(r["summary"] or "")[:90]
        lines.append(f"- {ts} [{lvl}] {cat}/{et} dev={did} {summary}")
    return "\n".join(lines)[:3900]


def _telegram_cmd_publish(principal: Principal, cmd: str, params: dict[str, Any], ids: list[str], bulk_cap: str) -> tuple[int, int]:
    if cmd in ("siren_on", "siren_off"):
        require_capability(principal, "can_alert")
    else:
        require_capability(principal, "can_send_command")
    if ids:
        _telegram_require(principal, "tg_test_single" if cmd == "self_test" else ("tg_siren_on" if cmd == "siren_on" else "tg_siren_off"))
    else:
        _telegram_require(principal, bulk_cap)
    targets = resolve_target_devices(ids, principal=principal)
    sent = 0
    for did in targets:
        try:
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd=cmd,
                params=params,
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            sent += 1
        except Exception as exc:
            logger.warning("telegram cmd publish %s -> %s failed: %s", cmd, did, exc)
    return sent, len(targets)


def _telegram_cmd_handle_text(principal: Principal, text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return "Empty command. Try: help"
    if raw.startswith("/"):
        raw = raw[1:]
    raw = raw.split("@", 1)[0].strip()
    lower = raw.lower()

    if lower in ("start", "help", "h", "?"):
        return (
            "Commands:\n"
            "- devices [N]\n"
            "- log [N]\n"
            "- siren on <all|device|id1,id2> [duration_ms]\n"
            "- siren off <all|device|id1,id2>\n"
            "- test <device_id>\n"
            "- test all\n"
            "- test many <id1,id2,...>\n"
        )

    if lower.startswith("devices"):
        parts = lower.split()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        return _telegram_cmd_recent_devices(principal, n)

    if lower.startswith("log"):
        parts = lower.split()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        return _telegram_cmd_recent_logs(principal, n)

    if lower.startswith("siren on"):
        parts = raw.split()
        target_token = "all" if len(parts) < 3 else parts[2]
        duration_ms = DEFAULT_REMOTE_FANOUT_MS
        if len(parts) >= 4 and parts[3].isdigit():
            duration_ms = int(parts[3])
        duration_ms = max(500, min(duration_ms, 300000))
        ids = _telegram_parse_targets(target_token)
        cap = "tg_siren_on"
        sent, total = _telegram_cmd_publish(principal, "siren_on", {"duration_ms": duration_ms}, ids, cap)
        emit_event(
            level="warn",
            category="alarm",
            event_type="telegram.siren_on",
            summary=f"telegram siren_on sent={sent}/{total}",
            actor=f"telegram:{principal.username}",
            owner_admin=None if principal.role == "superadmin" else (principal.username if principal.role == "admin" else get_manager_admin(principal.username)),
            detail={"target": target_token, "duration_ms": duration_ms},
        )
        return f"siren_on done: sent={sent}/{total}, duration_ms={duration_ms}, target={target_token}"

    if lower.startswith("siren off"):
        parts = raw.split()
        target_token = "all" if len(parts) < 3 else parts[2]
        ids = _telegram_parse_targets(target_token)
        cap = "tg_siren_off"
        sent, total = _telegram_cmd_publish(principal, "siren_off", {}, ids, cap)
        emit_event(
            level="warn",
            category="alarm",
            event_type="telegram.siren_off",
            summary=f"telegram siren_off sent={sent}/{total}",
            actor=f"telegram:{principal.username}",
            owner_admin=None if principal.role == "superadmin" else (principal.username if principal.role == "admin" else get_manager_admin(principal.username)),
            detail={"target": target_token},
        )
        return f"siren_off done: sent={sent}/{total}, target={target_token}"

    if lower in ("test all", "device all test", "devices all test"):
        sent, total = _telegram_cmd_publish(principal, "self_test", {}, [], "tg_test_bulk")
        return f"self_test(all) done: sent={sent}/{total}"

    if lower.startswith("test many "):
        ids = _telegram_parse_targets(raw[10:])
        if not ids:
            return "No device ids provided."
        sent, total = _telegram_cmd_publish(principal, "self_test", {}, ids, "tg_test_bulk")
        return f"self_test(many) done: sent={sent}/{total}"

    if lower.startswith("test "):
        did = raw.split(maxsplit=1)[1].strip() if len(raw.split(maxsplit=1)) > 1 else ""
        if not did:
            return "Usage: test <device_id>"
        sent, total = _telegram_cmd_publish(principal, "self_test", {}, [did], "tg_test_single")
        return f"self_test(single) done: sent={sent}/{total}"

    return "Unknown command. Try: help"


@app.post("/telegram/link-token")
def telegram_link_token(
    req: TelegramLinkTokenRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    token = secrets.token_urlsafe(24)
    expires_at_ts = int(time.time()) + max(60, TELEGRAM_LINK_TOKEN_TTL_SECONDS)
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO telegram_link_tokens (token, username, expires_at_ts, used_at, created_at)
            VALUES (?, ?, ?, NULL, ?)
            """,
            (token, principal.username, expires_at_ts, now),
        )
        conn.commit()
        conn.close()
    payload = f"bind_{token}"
    deep_link = ""
    open_chat_url = ""
    if TELEGRAM_BOT_USERNAME:
        open_chat_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}"
        deep_link = f"https://t.me/{TELEGRAM_BOT_USERNAME}?start={payload}"
    return {
        "ok": True,
        "token": token,
        "bot_username": TELEGRAM_BOT_USERNAME,
        "open_chat_url": open_chat_url,
        "start_payload": payload,
        "deep_link": deep_link,
        "expires_at_ts": expires_at_ts,
        "enabled_on_bind": bool(req.enabled_on_bind),
    }


@app.post("/admin/telegram/bind-self")
def telegram_bind_self(req: TelegramBindRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    chat_id = req.chat_id.strip()
    _telegram_bind_chat(chat_id, principal.username, bool(req.enabled))
    audit_event(principal.username, "telegram.bind.self", chat_id, {"enabled": req.enabled})
    return {"ok": True, "chat_id": chat_id, "username": principal.username, "enabled": bool(req.enabled)}


@app.get("/admin/telegram/bindings")
def telegram_bindings(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("SELECT chat_id, username, enabled, created_at, updated_at FROM telegram_chat_bindings ORDER BY updated_at DESC")
        else:
            cur.execute(
                "SELECT chat_id, username, enabled, created_at, updated_at FROM telegram_chat_bindings WHERE username = ? ORDER BY updated_at DESC",
                (principal.username,),
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.delete("/admin/telegram/bindings/{chat_id}")
def telegram_unbind(chat_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute("DELETE FROM telegram_chat_bindings WHERE chat_id = ?", (chat_id,))
        else:
            cur.execute("DELETE FROM telegram_chat_bindings WHERE chat_id = ? AND username = ?", (chat_id, principal.username))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="binding not found")
    _invalidate_superadmin_telegram_chats_cache()
    audit_event(principal.username, "telegram.unbind", chat_id, {})
    return {"ok": True}


@app.patch("/admin/telegram/bindings/{chat_id}/enabled")
def telegram_binding_set_enabled(
    chat_id: str,
    enabled: bool = Query(...),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if principal.role == "superadmin":
            cur.execute(
                "UPDATE telegram_chat_bindings SET enabled=?, updated_at=? WHERE chat_id=?",
                (1 if enabled else 0, utc_now_iso(), chat_id),
            )
        else:
            cur.execute(
                "UPDATE telegram_chat_bindings SET enabled=?, updated_at=? WHERE chat_id=? AND username=?",
                (1 if enabled else 0, utc_now_iso(), chat_id, principal.username),
            )
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="binding not found")
    _invalidate_superadmin_telegram_chats_cache()
    audit_event(principal.username, "telegram.bind.enabled", chat_id, {"enabled": bool(enabled)})
    return {"ok": True, "chat_id": chat_id, "enabled": bool(enabled)}


@app.post("/integrations/telegram/webhook")
def telegram_webhook(
    request: Request,
    payload: dict[str, Any],
    x_telegram_bot_api_secret_token: Optional[str] = Header(default=None, alias="X-Telegram-Bot-Api-Secret-Token"),
) -> dict[str, Any]:
    if not api_ready_event.is_set():
        raise HTTPException(status_code=503, detail="service starting")
    if api_bootstrap_error:
        raise HTTPException(status_code=503, detail="bootstrap failed")
    # Proxies sometimes preserve header casing differently; fall back to raw request.
    secret_hdr = (x_telegram_bot_api_secret_token or "").strip()
    if not secret_hdr:
        secret_hdr = (request.headers.get("x-telegram-bot-api-secret-token") or "").strip()
    if TELEGRAM_COMMAND_SECRET and secret_hdr != TELEGRAM_COMMAND_SECRET:
        logger.warning(
            "telegram webhook: rejected (TELEGRAM_COMMAND_SECRET mismatch or missing secret header). "
            "Set BotFather webhook secret_token to the same value as TELEGRAM_COMMAND_SECRET, "
            "or leave TELEGRAM_COMMAND_SECRET empty if not using a webhook secret."
        )
        return {"ok": True, "ignored": "bad_secret"}
    msg = payload.get("message") or payload.get("channel_post") or payload.get("edited_message") or {}
    if not isinstance(msg, dict):
        return {"ok": True, "ignored": "no_message"}
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "").strip()
    if not chat_id:
        return {"ok": True, "ignored": "no_chat_id"}
    text = str(msg.get("text") or "").strip()
    if not text:
        return {"ok": True, "ignored": "no_text"}

    # Allow everyone to discover chat_id and perform one-time deep-link bind.
    if text.strip().lower().startswith("/start") or text.strip().lower() in ("start", "/whoami", "whoami"):
        parts = text.strip().split(maxsplit=1)
        payload = parts[1].strip() if len(parts) > 1 else ""
        if payload.startswith("bind_"):
            token = payload[len("bind_"):].strip()
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT token, username, expires_at_ts, used_at
                    FROM telegram_link_tokens
                    WHERE token = ?
                    """,
                    (token,),
                )
                row = cur.fetchone()
                if not row:
                    conn.close()
                    _telegram_cmd_send_reply_logged(
                        chat_id, "Invalid link token. Generate a new one from dashboard.", "bind_bad_token"
                    )
                    return {"ok": True, "processed": True, "bound": False, "reason": "bad_token"}
                if row["used_at"]:
                    conn.close()
                    _telegram_cmd_send_reply_logged(chat_id, "This link token is already used.", "bind_used_token")
                    return {"ok": True, "processed": True, "bound": False, "reason": "used_token"}
                if int(row["expires_at_ts"]) < int(time.time()):
                    conn.close()
                    _telegram_cmd_send_reply_logged(
                        chat_id, "Link token expired. Generate a new one from dashboard.", "bind_expired"
                    )
                    return {"ok": True, "processed": True, "bound": False, "reason": "expired_token"}
                username = str(row["username"])
                cur.execute("UPDATE telegram_link_tokens SET used_at = ? WHERE token = ?", (utc_now_iso(), token))
                conn.commit()
                conn.close()
            _telegram_bind_chat(chat_id, username, True)
            _telegram_cmd_send_reply_logged(
                chat_id, f"Bound OK: {username}\nYou can now use bot commands.", "bind_ok"
            )
            return {"ok": True, "processed": True, "bound": True, "username": username}
        _telegram_cmd_send_reply_logged(
            chat_id,
            f"chat_id={chat_id}\nBind this in dashboard Telegram settings (or use a dashboard-generated bind link).",
            "start_chat_id",
        )
        return {"ok": True, "processed": True, "bound": False}

    # Command allowlist applies to command execution (not /start binding flow).
    if TELEGRAM_COMMAND_CHAT_IDS and chat_id not in TELEGRAM_COMMAND_CHAT_IDS:
        return {"ok": True, "ignored": "chat_not_allowed"}

    try:
        principal = _telegram_bound_principal(chat_id)
        reply = _telegram_cmd_handle_text(principal, text)
    except HTTPException as exc:
        reply = f"Denied: {exc.detail}"
    except Exception as exc:
        logger.exception("telegram command failed")
        reply = f"Error: {exc}"
    _telegram_cmd_send_reply_logged(chat_id, reply, "command_reply")
    return {"ok": True, "processed": True}


# =====================================================================
#  OTA — firmware listing & tenant-scoped broadcast
# =====================================================================

class OtaBroadcastRequest(BaseModel):
    url: str = Field(min_length=8, max_length=400)
    fw: str = Field(default="", max_length=40)
    device_ids: list[str] = Field(default_factory=list)


def _sha256_sidecar_only(path: str) -> Optional[str]:
    """Fast path for listings: use .sha256 sidecar only (no full-file read)."""
    sidecar = path + ".sha256"
    if not os.path.isfile(sidecar):
        return None
    try:
        with open(sidecar, "r", encoding="utf-8", errors="ignore") as f:
            line = f.readline().strip()
        if line:
            return line.split()[0]
    except Exception:
        return None
    return None


def _sha256_for(path: str) -> Optional[str]:
    hit = _sha256_sidecar_only(path)
    if hit:
        return hit
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


@app.get("/ota/service-check")
def ota_service_check(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin: safe diagnostics for OTA URL probing (no secrets)."""
    assert_min_role(principal, "superadmin")
    hints: list[str] = []
    tok = bool((OTA_TOKEN or "").strip())
    if not tok:
        hints.append("OTA_TOKEN is unset — nginx /fw/ token rule returns 403; devices and probes need the same token as config.h.")
    if OTA_PUBLIC_BASE_URL and not OTA_VERIFY_BASE_URL:
        hints.append(
            "If probes fail with connection refused from the API container, set OTA_VERIFY_BASE_URL=http://ota-nginx:9231 "
            "(Docker Compose service name on croc_net)."
        )
    if not OTA_PUBLIC_BASE_URL:
        hints.append("Set OTA_PUBLIC_BASE_URL for device-facing URLs (must match config.h OTA_ALLOWED_HOST).")
    if not OTA_UPLOAD_PASSWORD:
        hints.append("OTA_UPLOAD_PASSWORD is unset — superadmin cannot stage .bin via POST /ota/firmware/upload until you set it in the API environment.")
    return {
        "OTA_FIRMWARE_DIR": OTA_FIRMWARE_DIR,
        "OTA_PUBLIC_BASE_URL": OTA_PUBLIC_BASE_URL or None,
        "OTA_VERIFY_BASE_URL": OTA_VERIFY_BASE_URL or None,
        "effective_verify_base": _effective_ota_verify_base() or None,
        "OTA_TOKEN_configured": tok,
        "OTA_MAX_FIRMWARE_BINS": OTA_MAX_FIRMWARE_BINS,
        "OTA_UPLOAD_PASSWORD_configured": bool(OTA_UPLOAD_PASSWORD),
        "hints": hints,
    }


@app.get("/ota/firmware-reachability")
def ota_firmware_reachability(
    name: str = Query(..., min_length=5, max_length=220),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Dashboard: confirm the staged .bin is reachable like a device (HEAD with OTA_TOKEN). Catalog-only name."""
    assert_min_role(principal, "user")
    require_capability(principal, "can_send_command")
    safe = os.path.basename((name or "").strip())
    if not safe.endswith(".bin") or safe != (name or "").strip() or "/" in (name or "") or "\\" in (name or ""):
        raise HTTPException(status_code=400, detail="invalid firmware filename")
    cat = _get_ota_firmware_catalog()
    if not any(str(e.get("name") or "") == safe for e in cat):
        raise HTTPException(status_code=404, detail="firmware not in catalog")
    ok, detail, masked = _verify_firmware_file_on_service(safe)
    tok = bool((OTA_TOKEN or "").strip())
    return {
        "ok": ok,
        "detail": detail,
        "probe_url_masked": masked,
        "ota_token_configured": tok,
        "public_base_configured": bool((OTA_PUBLIC_BASE_URL or "").strip()),
        "filename": safe,
    }


@app.get("/ota/firmwares")
def list_firmwares(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    # Only superadmin can even see the firmware inventory.
    assert_min_role(principal, "superadmin")
    items: list[dict[str, Any]] = []
    base = OTA_FIRMWARE_DIR
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            if not name.endswith(".bin"):
                continue
            path = os.path.join(base, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            url = ""
            if OTA_PUBLIC_BASE_URL:
                url = f"{OTA_PUBLIC_BASE_URL}/fw/{name}"
            fw_label = _version_str_for_ota_bin_file(path, name)
            items.append({
                "name": name,
                "fw_version": fw_label,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
                "sha256": _sha256_sidecar_only(path),
                "download_url": url,
            })
    return {
        "dir": base,
        "public_base": OTA_PUBLIC_BASE_URL,
        "items": items,
        "retention": {
            "max_bins": OTA_MAX_FIRMWARE_BINS,
            "stored_count": len(items),
            "upload_password_configured": bool(OTA_UPLOAD_PASSWORD),
        },
    }


@app.get("/ota/firmware-verify")
def ota_firmware_verify(
    fname: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Re-hash a stored .bin and compare with its sidecar ``.sha256`` file.

    Use this to confirm a firmware artifact on disk has not been corrupted (or
    swapped) since upload. Only superadmin may call this; it reads the full
    file so don't hit it in tight loops.
    """
    assert_min_role(principal, "superadmin")
    safe = os.path.basename((fname or "").strip())
    if not safe or not safe.lower().endswith(".bin") or "/" in safe or "\\" in safe or ".." in safe:
        raise HTTPException(status_code=400, detail="invalid firmware filename")
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    path = os.path.join(OTA_FIRMWARE_DIR, safe)
    try:
        rp = os.path.realpath(path)
    except OSError:
        raise HTTPException(status_code=400, detail="invalid firmware path")
    if not (rp == os.path.join(base_dir, safe) or rp.startswith(base_dir + os.sep)):
        raise HTTPException(status_code=400, detail="path traversal rejected")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="firmware not found")
    sidecar = path + ".sha256"
    expected = ""
    if os.path.isfile(sidecar):
        try:
            with open(sidecar, "r", encoding="utf-8") as f:
                first = (f.readline() or "").strip()
                expected = (first.split()[0] if first else "").lower()
        except OSError:
            expected = ""
    # Stream-hash the file so we don't balloon memory on a 2+ MB image.
    h = hashlib.sha256()
    nbytes = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                nbytes += len(chunk)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"read error: {exc}")
    actual = h.hexdigest().lower()
    ok = bool(expected) and actual == expected
    return {
        "fname": safe,
        "bytes": nbytes,
        "sha256_expected": expected,
        "sha256_actual": actual,
        "ok": ok,
        "has_sidecar": bool(expected),
    }


@app.post("/ota/broadcast")
def ota_broadcast(req: OtaBroadcastRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    # OTA is sensitive: the .bin can brick the fleet. Only superadmin may
    # dispatch it, and because superadmin's scope is global the resulting
    # target set is "every non-revoked device" (or the explicit subset).
    assert_min_role(principal, "superadmin")
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")
    targets = resolve_target_devices(req.device_ids, principal)
    if not targets:
        return {"ok": True, "sent_count": 0, "device_ids": []}
    params: dict[str, Any] = {"url": req.url}
    if req.fw:
        params["fw"] = req.fw
    sent = 0
    for did in targets:
        try:
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="ota",
                params=params,
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
                dedupe_key=f"ota-broadcast:{did}:{req.fw or req.url}",
                dedupe_ttl_s=60.0,
            )
            sent += 1
        except Exception as exc:
            logger.warning("ota broadcast to %s failed: %s", did, exc)
    audit_event(principal.username, "ota.broadcast", req.fw or req.url, {
        "sent_count": sent,
        "target_count": len(targets),
        "fw": req.fw,
    })
    return {"ok": True, "sent_count": sent, "device_ids": targets}


# =====================================================================
#  OTA CAMPAIGNS (new 2-stage flow: superadmin → admin → devices)
#
#   1. superadmin POST /ota/campaigns   -> creates campaign, picks target admins
#   2. each admin sees pending campaign on their dashboard
#   3. admin POST /ota/campaigns/{id}/accept  -> server HEAD-checks url,
#      fills ota_device_runs, dispatches ota cmd to every owned device
#   4. devices emit ota.result; _handle_ota_result drives the state machine
#   5. if any device fails and OTA_AUTO_ROLLBACK_ON_FAILURE=1, every already-
#      upgraded device under that admin is pushed back to prev_url
#   6. admin may POST /ota/campaigns/{id}/decline to opt out
# =====================================================================

class OtaCampaignCreateRequest(BaseModel):
    fw_version: str = Field(min_length=1, max_length=40)
    url: str = Field(min_length=8, max_length=400)
    sha256: Optional[str] = Field(default=None, max_length=128)
    notes: Optional[str] = Field(default=None, max_length=500)
    # ["*"] = every admin; otherwise an explicit list.
    target_admins: list[str] = Field(default_factory=lambda: ["*"], max_length=256)


def _list_all_admin_usernames() -> list[str]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username FROM dashboard_users WHERE role = 'admin' AND (status IS NULL OR status='' OR status='active')",
        )
        rows = cur.fetchall()
        conn.close()
    return [str(r["username"]) for r in rows]


def _insert_ota_campaign(principal: Principal, req: OtaCampaignCreateRequest) -> dict[str, Any]:
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")

    if req.target_admins == ["*"] or not req.target_admins:
        admins = _list_all_admin_usernames()
    else:
        admins = [a for a in req.target_admins if a and a != "*"]
        if not admins:
            raise HTTPException(status_code=400, detail="no target admins")

    campaign_id = "otac-" + secrets.token_urlsafe(10)
    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ota_campaigns (id, created_by, fw_version, url, sha256, notes, target_admins_json, state, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'dispatched', ?, ?)
            """,
            (campaign_id, principal.username, req.fw_version, req.url, req.sha256 or "", req.notes or "", json.dumps(admins), now_iso, now_iso),
        )
        conn.commit()
        conn.close()

    audit_event(principal.username, "ota.campaign.create", campaign_id, {
        "fw_version": req.fw_version, "url": req.url, "target_admins": admins,
    })
    return {"ok": True, "campaign_id": campaign_id, "target_admins": admins, "state": "dispatched"}


def _safe_ota_stored_filename(fw_version: str, original_filename: str) -> str:
    base = os.path.basename(original_filename or "")
    if not base.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="upload must be a .bin file")
    safe_fw = re.sub(r"[^a-zA-Z0-9._-]", "_", (fw_version or "").strip())[:28]
    if not safe_fw:
        safe_fw = "fw"
    tail = secrets.token_hex(4)
    return f"croc-{safe_fw}-{tail}.bin"


def _ota_bin_path_for_stored_name(fname: str) -> str:
    """Resolve a firmware basename under OTA_FIRMWARE_DIR (no path traversal)."""
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    name = os.path.basename((fname or "").strip())
    if not name.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="filename must be a .bin file")
    path = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, name))
    if not path.startswith(base_dir + os.sep):
        raise HTTPException(status_code=400, detail="invalid firmware filename")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="firmware file not found on server")
    return path


def _require_ota_upload_password(provided: str | None) -> None:
    """Server-side shared secret for staging .bin (separate from JWT). Constant-time compare."""
    if not OTA_UPLOAD_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="OTA_UPLOAD_PASSWORD is not set on the server; firmware uploads are disabled. Set it in the API environment.",
        )
    a = OTA_UPLOAD_PASSWORD
    b = (provided or "")
    if len(a) != len(b) or not hmac.compare_digest(a, b):
        raise HTTPException(status_code=403, detail="Invalid upload password")


def _ota_delete_artifacts_for_stored_basename(basename: str) -> None:
    """Delete .bin, .bin.sha256, .bin.version, and sidecar release notes (stem + .txt/.md/.notes)."""
    if not str(basename).endswith(".bin") or ".." in basename or "/" in basename or "\\" in basename:
        return
    base_dir = os.path.realpath(OTA_FIRMWARE_DIR)
    path = os.path.realpath(os.path.join(OTA_FIRMWARE_DIR, basename))
    if not path.startswith(base_dir + os.sep) or not path.lower().endswith(".bin"):
        return
    stem_name = path[:-4]  # full path without ".bin" suffix; basename for sidecars
    base_name = os.path.basename(stem_name)
    to_try: list[str] = [path, path + ".sha256", path + ".version"]
    for ext in (".txt", ".md", ".notes"):
        to_try.append(os.path.join(OTA_FIRMWARE_DIR, base_name + ext))
    for p in to_try:
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass


def _ota_in_use_basenames() -> set[str]:
    """Set of .bin basenames currently referenced by a non-terminal OTA campaign.
    We refuse to prune these so devices mid-download don't 404 on the artifact.
    """
    out: set[str] = set()
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT url FROM ota_campaigns
                WHERE state NOT IN ('success', 'failed', 'cancelled', 'rolled_back')
                """
            )
            rows = cur.fetchall() or []
            conn.close()
    except Exception as exc:
        logger.warning("in-use OTA campaign lookup failed: %s", exc)
        return out
    for r in rows:
        url = str((r["url"] if r else "") or "")
        if not url:
            continue
        try:
            tail = url.rsplit("/", 1)[-1]
            # Strip query string.
            if "?" in tail:
                tail = tail.split("?", 1)[0]
            if tail.lower().endswith(".bin"):
                out.add(tail)
        except Exception:
            continue
    return out


def _ota_enforce_max_stored_bins() -> None:
    """Keep at most OTA_MAX_FIRMWARE_BINS .bin files; remove oldest by mtime first, with artifacts.

    Never prunes a .bin that's currently referenced by an active OTA campaign — doing
    so would cause in-flight devices to fail the download and fall back to rollback.
    If the number of in-use bins alone already exceeds the limit, we keep them all and
    warn so the operator can raise ``OTA_MAX_FIRMWARE_BINS``.
    """
    base = os.path.realpath(OTA_FIRMWARE_DIR)
    if not os.path.isdir(base):
        return
    in_use = _ota_in_use_basenames()
    items: list[tuple[int, str, str]] = []  # mtime, name, relpath join path
    for name in os.listdir(OTA_FIRMWARE_DIR):
        if not str(name).lower().endswith(".bin"):
            continue
        p = os.path.join(OTA_FIRMWARE_DIR, name)
        if not os.path.isfile(p):
            continue
        try:
            rp = os.path.realpath(p)
        except OSError:
            continue
        if not str(rp).startswith(base + os.sep):
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        items.append((int(st.st_mtime), str(name), p))
    # Oldest mtime first; break ties by name for stable order
    items.sort(key=lambda t: (t[0], t[1]))
    # Remove oldest until count ≤ max — but skip any in-use .bin.
    idx = 0
    kept_protected = 0
    while len(items) > OTA_MAX_FIRMWARE_BINS and idx < len(items):
        _m, name, _p = items[idx]
        if name in in_use:
            kept_protected += 1
            idx += 1
            continue
        items.pop(idx)
        _ota_delete_artifacts_for_stored_basename(name)
    if len(items) > OTA_MAX_FIRMWARE_BINS and kept_protected > 0:
        logger.warning(
            "OTA retention: %d artifact(s) kept above limit=%d because they are in-use by active campaigns",
            kept_protected, OTA_MAX_FIRMWARE_BINS,
        )
    _invalidate_ota_firmware_catalog_cache()


async def _ota_store_uploaded_bin(file: UploadFile, fw_version: str) -> tuple[str, str, str, int]:
    """Save multipart upload to OTA_FIRMWARE_DIR. Returns (fname_on_disk, sha256_hex, byte_size)."""
    os.makedirs(OTA_FIRMWARE_DIR, mode=0o755, exist_ok=True)
    fname = _safe_ota_stored_filename(fw_version, file.filename or "")
    dest = os.path.join(OTA_FIRMWARE_DIR, fname)
    body = await file.read()
    if len(body) > MAX_OTA_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"file exceeds {MAX_OTA_UPLOAD_BYTES} bytes")
    if len(body) < 1024:
        raise HTTPException(status_code=400, detail="file too small to be a firmware image")
    sha_hex = hashlib.sha256(body).hexdigest()
    try:
        with open(dest, "wb") as out:
            out.write(body)
        with open(dest + ".sha256", "w", encoding="utf-8") as sf:
            sf.write(f"{sha_hex}  {fname}\n")
        ver = (fw_version or "").strip()
        if ver:
            with open(dest + ".version", "w", encoding="utf-8") as vf:
                vf.write(ver + "\n")
        else:
            try:
                if os.path.isfile(dest + ".version"):
                    os.remove(dest + ".version")
            except OSError:
                pass
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"failed to save firmware: {exc}") from exc
    _ota_enforce_max_stored_bins()
    return fname, sha_hex, len(body)


class OtaCampaignFromStoredRequest(BaseModel):
    filename: str = Field(min_length=4, max_length=200)
    # Deprecated: was required; version is now always taken from server-side staged metadata
    # (.version sidecar and/or filename), same as GET /ota/firmwares "fw_version".
    fw_version: Optional[str] = Field(default=None, max_length=40)
    notes: Optional[str] = Field(default=None, max_length=500)
    target_admins: list[str] = Field(default_factory=lambda: ["*"], max_length=256)


@app.post("/ota/firmware/upload")
async def ota_firmware_upload_stage(
    principal: Principal = Depends(require_principal),
    file: UploadFile = File(...),
    fw_version: str = Form(...),
    upload_password: str = Form(...),
) -> dict[str, Any]:
    """Superadmin: store .bin only. Runs HEAD against the public URL for diagnostics; does **not** create a campaign (file kept even if HEAD fails)."""
    assert_min_role(principal, "superadmin")
    _require_ota_upload_password(upload_password)
    if not OTA_PUBLIC_BASE_URL:
        raise HTTPException(
            status_code=400,
            detail="OTA_PUBLIC_BASE_URL is not set (e.g. https://ota.esasecure.com). Devices must match config.h OTA_ALLOWED_HOST + OTA_TOKEN.",
        )
    fname, sha_hex, nbytes = await _ota_store_uploaded_bin(file, fw_version)
    url = _public_firmware_url(fname)
    ok, verify_detail, probe_masked = _verify_firmware_file_on_service(fname)
    audit_event(principal.username, "ota.firmware.stage", fname, {"size": nbytes, "url": url, "head_ok": ok})
    hint = None
    if not ok:
        hint = (
            "Probe failed — ensure nginx serves /fw/ with ?token= (OTA_TOKEN). "
            "From inside Docker use OTA_VERIFY_BASE_URL=http://ota-nginx:9231; "
            "on the host ensure HTTPS server_name ota.esasecure.com proxies to 127.0.0.1:9231."
        )
    return {
        "ok": True,
        "stored_as": fname,
        "download_url": url,
        "sha256": sha_hex,
        "size": nbytes,
        "head_ok": ok,
        "verify": verify_detail,
        "probe_url": probe_masked,
        "verify_base_used": _effective_ota_verify_base(),
        "public_base": OTA_PUBLIC_BASE_URL,
        "hint": hint,
    }


@app.post("/ota/campaigns/from-stored")
def create_ota_campaign_from_stored(req: OtaCampaignFromStoredRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin: create an OTA campaign for a file already under OTA_FIRMWARE_DIR (uploaded or copied). HEAD must succeed."""
    assert_min_role(principal, "superadmin")
    if not OTA_PUBLIC_BASE_URL:
        raise HTTPException(
            status_code=400,
            detail="OTA_PUBLIC_BASE_URL is not set (e.g. https://ota.esasecure.com). Devices must match config.h OTA_ALLOWED_HOST + OTA_TOKEN.",
        )
    path = _ota_bin_path_for_stored_name(req.filename)
    fname = os.path.basename(path)
    sha_hex = _sha256_for(path)
    if not sha_hex:
        raise HTTPException(status_code=500, detail="could not compute firmware SHA-256")
    url = _public_firmware_url(fname)
    ok, verify_detail, probe_masked = _verify_firmware_file_on_service(fname)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail=(
                f"firmware HTTP check failed ({verify_detail}); probed {probe_masked}. "
                "Set OTA_TOKEN to match nginx; optional OTA_VERIFY_BASE_URL=http://ota-nginx:9231 for Docker. "
                "Public URL for devices remains OTA_PUBLIC_BASE_URL."
            ),
        )
    # Campaign version label: single source of truth = staged .bin metadata (not client hand-typed).
    resolved_fw = _version_str_for_ota_bin_file(path, fname).strip()
    if not resolved_fw:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve firmware version for this file. Add a <name>.version file next to the .bin, or re-upload from the dashboard with a version label.",
        )
    insert_req = OtaCampaignCreateRequest(
        fw_version=resolved_fw,
        url=url,
        sha256=sha_hex,
        notes=(req.notes or "").strip() or None,
        target_admins=req.target_admins,
    )
    out = _insert_ota_campaign(principal, insert_req)
    out["stored_as"] = fname
    out["download_url"] = url
    out["sha256"] = sha_hex
    out["verify"] = verify_detail
    out["fw_version"] = resolved_fw
    audit_event(principal.username, "ota.campaign.from_stored", fname, {"fw_version": resolved_fw, "url": url})
    return out


@app.post("/ota/campaigns")
def create_ota_campaign(req: OtaCampaignCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    return _insert_ota_campaign(principal, req)


@app.post("/ota/campaigns/from-upload")
async def ota_campaign_from_upload(
    principal: Principal = Depends(require_principal),
    file: UploadFile = File(...),
    fw_version: str = Form(...),
    upload_password: str = Form(...),
    notes: str = Form(""),
    target_admins: str = Form("*"),
) -> dict[str, Any]:
    """Superadmin: upload .bin to OTA_FIRMWARE_DIR, HEAD-verify public URL, then create the same campaign row as POST /ota/campaigns."""
    assert_min_role(principal, "superadmin")
    _require_ota_upload_password(upload_password)
    if not OTA_PUBLIC_BASE_URL:
        raise HTTPException(
            status_code=400,
            detail="OTA_PUBLIC_BASE_URL is not set (e.g. https://ota.esasecure.com). Devices must match config.h OTA_ALLOWED_HOST + OTA_TOKEN.",
        )
    fname, sha_hex, nbytes = await _ota_store_uploaded_bin(file, fw_version)

    url = _public_firmware_url(fname)
    ok, verify_detail, probe_masked = _verify_firmware_file_on_service(fname)
    if not ok:
        dest = os.path.join(OTA_FIRMWARE_DIR, fname)
        try:
            if os.path.isfile(dest):
                os.remove(dest)
            if os.path.isfile(dest + ".sha256"):
                os.remove(dest + ".sha256")
            if os.path.isfile(dest + ".version"):
                os.remove(dest + ".version")
        except OSError:
            pass
        _invalidate_ota_firmware_catalog_cache()
        raise HTTPException(
            status_code=400,
            detail=(
                f"firmware saved but HTTP check failed ({verify_detail}); probed {probe_masked}. "
                "Set OTA_TOKEN (nginx token gate). Use OTA_VERIFY_BASE_URL=http://ota-nginx:9231 if public hostname is unreachable from the API container."
            ),
        )

    ta = (target_admins or "").strip()
    if not ta or ta == "*":
        admins_list: list[str] = ["*"]
    else:
        admins_list = [x for x in re.split(r"[\s,;]+", ta) if x]

    req = OtaCampaignCreateRequest(
        fw_version=fw_version.strip(),
        url=url,
        sha256=sha_hex,
        notes=(notes.strip() or None),
        target_admins=admins_list,
    )
    out = _insert_ota_campaign(principal, req)
    out["stored_as"] = fname
    out["download_url"] = url
    out["sha256"] = sha_hex
    out["verify"] = verify_detail
    audit_event(principal.username, "ota.firmware.upload", fname, {"size": nbytes, "url": url})
    return out


@app.get("/ota/campaigns")
def list_ota_campaigns(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin sees every campaign; admin sees only campaigns that list them."""
    # Campaign metadata is a fleet-management concern — sub-users (role=user)
    # have no legitimate reason to enumerate it, and for target_admins=['*']
    # they'd otherwise see every in-flight OTA. Gate at admin.
    assert_min_role(principal, "admin")
    items: list[dict[str, Any]] = []
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, created_by, fw_version, url, sha256, notes, target_admins_json, state, created_at, updated_at FROM ota_campaigns ORDER BY created_at DESC LIMIT 200",
        )
        rows = [dict(r) for r in cur.fetchall()]
        # Enrich with per-admin decision + counters.
        for r in rows:
            r["target_admins"] = json.loads(str(r.pop("target_admins_json") or "[]"))
            cur.execute(
                "SELECT admin_username, action, decided_at, detail FROM ota_decisions WHERE campaign_id = ?",
                (r["id"],),
            )
            r["decisions"] = [dict(x) for x in cur.fetchall()]
            cur.execute(
                "SELECT state, COUNT(*) AS c FROM ota_device_runs WHERE campaign_id = ? GROUP BY state",
                (r["id"],),
            )
            counters = {str(x["state"]): int(x["c"]) for x in cur.fetchall()}
            r["counters"] = counters
        conn.close()

    if principal.role == "superadmin":
        items = rows
    else:
        user = principal.username
        for r in rows:
            if "*" in r["target_admins"] or user in r["target_admins"]:
                items.append(r)
    return {"items": items}


@app.get("/ota/campaigns/{campaign_id}")
def get_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    # Same reasoning as list endpoint: fleet OTA detail is admin+ territory.
    assert_min_role(principal, "admin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM ota_campaigns WHERE id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="campaign not found")
        camp = dict(row)
        camp["target_admins"] = json.loads(str(camp.pop("target_admins_json") or "[]"))

        visible = principal.role == "superadmin" or "*" in camp["target_admins"] or principal.username in camp["target_admins"]
        if not visible:
            conn.close()
            raise HTTPException(status_code=403, detail="not your campaign")

        cur.execute("SELECT admin_username, action, decided_at, detail FROM ota_decisions WHERE campaign_id = ?", (campaign_id,))
        camp["decisions"] = [dict(x) for x in cur.fetchall()]

        runs_query = "SELECT campaign_id, admin_username, device_id, prev_fw, prev_url, target_fw, target_url, state, error, started_at, finished_at FROM ota_device_runs WHERE campaign_id = ?"
        runs_args: list[Any] = [campaign_id]
        if principal.role == "admin":
            runs_query += " AND admin_username = ?"
            runs_args.append(principal.username)
        runs_query += " ORDER BY admin_username, device_id"
        cur.execute(runs_query, tuple(runs_args))
        camp["device_runs"] = [dict(x) for x in cur.fetchall()]
        conn.close()
    return camp


@app.post("/ota/campaigns/{campaign_id}/accept")
def accept_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Admin accepts the campaign → server verifies URL then fans OTA cmd out
    to every device the admin owns."""
    assert_min_role(principal, "admin")
    admin_username = principal.username

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM ota_campaigns WHERE id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="campaign not found")
        camp = dict(row)
        targets = json.loads(str(camp.get("target_admins_json") or "[]"))
        if "*" not in targets and admin_username not in targets:
            conn.close()
            raise HTTPException(status_code=403, detail="not your campaign")

        cur.execute(
            "SELECT action FROM ota_decisions WHERE campaign_id = ? AND admin_username = ?",
            (campaign_id, admin_username),
        )
        prev = cur.fetchone()
        if prev and str(prev["action"]) in ("accepted",):
            conn.close()
            raise HTTPException(status_code=409, detail="already accepted")
        conn.close()

    ok, detail = _verify_ota_url(str(camp["url"]))
    if not ok:
        audit_event(admin_username, "ota.campaign.url_verify_fail", campaign_id, {"detail": detail})
        raise HTTPException(status_code=400, detail=f"url verify failed: {detail}")

    # Pre-populate ota_device_runs with every device this admin owns.
    targets_rows = _ota_campaign_targets_for_admin(admin_username, str(camp["fw_version"]), str(camp["url"]))
    if not targets_rows:
        # Still mark decision as accepted so superadmin can see the admin reacted.
        now_iso = utc_now_iso()
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
                VALUES (?, ?, 'accepted', ?, 'no devices')
                ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
                  action='accepted', decided_at=excluded.decided_at, detail=excluded.detail
                """,
                (campaign_id, admin_username, now_iso),
            )
            conn.commit()
            conn.close()
        return {"ok": True, "dispatched": 0, "note": "no devices owned by this admin"}

    now_iso = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for t in targets_rows:
            cur.execute(
                """
                INSERT INTO ota_device_runs
                    (campaign_id, admin_username, device_id, prev_fw, prev_url, target_fw, target_url, state, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                ON CONFLICT(campaign_id, device_id) DO UPDATE SET
                    admin_username = excluded.admin_username,
                    prev_fw        = excluded.prev_fw,
                    prev_url       = excluded.prev_url,
                    target_fw      = excluded.target_fw,
                    target_url     = excluded.target_url,
                    state          = CASE WHEN ota_device_runs.state IN ('success','failed','rolled_back') THEN ota_device_runs.state ELSE 'pending' END,
                    updated_at     = excluded.updated_at
                """,
                (campaign_id, admin_username, t["device_id"], t["prev_fw"], t["prev_url"], str(camp["fw_version"]), str(camp["url"]), now_iso, now_iso),
            )
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'accepted', ?, ?)
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='accepted', decided_at=excluded.decided_at, detail=excluded.detail
            """,
            (campaign_id, admin_username, now_iso, detail),
        )
        cur.execute("UPDATE ota_campaigns SET state='running', updated_at=? WHERE id=?", (now_iso, campaign_id))
        conn.commit()
        conn.close()

    dispatched, failures = _start_ota_rollout_for_admin(campaign_id, admin_username)
    audit_event(admin_username, "ota.campaign.accept", campaign_id, {
        "dispatched": dispatched,
        "failures": failures[:5],
        "target_count": len(targets_rows),
        "verify": detail,
    })
    return {"ok": True, "dispatched": dispatched, "target_count": len(targets_rows), "verify": detail, "failures": failures[:5]}


@app.post("/ota/campaigns/{campaign_id}/decline")
def decline_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    admin_username = principal.username
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT target_admins_json FROM ota_campaigns WHERE id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="campaign not found")
        targets = json.loads(str(row["target_admins_json"] or "[]"))
        if "*" not in targets and admin_username not in targets:
            conn.close()
            raise HTTPException(status_code=403, detail="not your campaign")
        cur.execute(
            """
            INSERT INTO ota_decisions (campaign_id, admin_username, action, decided_at, detail)
            VALUES (?, ?, 'declined', ?, '')
            ON CONFLICT(campaign_id, admin_username) DO UPDATE SET
              action='declined', decided_at=excluded.decided_at
            """,
            (campaign_id, admin_username, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    audit_event(admin_username, "ota.campaign.decline", campaign_id, {})
    return {"ok": True}


@app.post("/ota/campaigns/{campaign_id}/rollback")
def rollback_ota_campaign(campaign_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Explicit rollback trigger (in addition to automatic rollback on failure)."""
    assert_min_role(principal, "admin")
    admin_username = principal.username
    if principal.role == "superadmin":
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT admin_username FROM ota_device_runs WHERE campaign_id = ?", (campaign_id,))
            admins = [str(r["admin_username"]) for r in cur.fetchall()]
            conn.close()
        rolled_total = 0
        for a in admins:
            rolled_total += _rollback_admin_devices(campaign_id, a, reason=f"manual rollback by superadmin {principal.username}")
        return {"ok": True, "rolled_back": rolled_total, "admins": admins}
    rolled = _rollback_admin_devices(campaign_id, admin_username, reason=f"manual rollback by admin {admin_username}")
    return {"ok": True, "rolled_back": rolled}


# =====================================================================
#  Presence probes (admin-facing read-only view of the 12h ping log)
# =====================================================================

@app.get("/admin/presence-probes")
def list_presence_probes(
    principal: Principal = Depends(require_principal),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    sql = (
        "SELECT id, device_id, owner_admin, probe_ts, idle_seconds, outcome, detail "
        "FROM presence_probes WHERE 1=1 "
    )
    args: list[Any] = []
    if device_id:
        sql += "AND device_id = ? "
        args.append(device_id)
    if principal.role == "admin":
        sql += "AND (owner_admin = ? OR owner_admin IS NULL) "
        args.append(principal.username)
    sql += "ORDER BY probe_ts DESC LIMIT ?"
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


# =====================================================================
#  Event center — historical query + live SSE stream
#
#  Tenant isolation:
#    * superadmin  → every event in the system
#    * admin       → events where owner_admin = self OR actor/target = self
#    * user        → events in their manager_admin's tenant that mention them
#                    or are warn+
#
#  Two transports:
#    GET /events              paginated history (DB-backed)
#    GET /events/stream       Server-Sent Events, real-time
# =====================================================================

def _event_scope_sql(principal: Principal) -> tuple[str, list[Any]]:
    """Return WHERE fragment + args for the events table based on role."""
    if principal.role == "superadmin":
        return "", []
    if principal.role == "admin":
        frag = (
            " AND (owner_admin = ? OR actor = ? OR target = ?) "
            " AND actor NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin') "
        )
        return frag, [principal.username, principal.username, principal.username]
    my_admin = get_manager_admin(principal.username) or ""
    if not my_admin:
        return " AND 1=0 ", []
    frag = (
        " AND (owner_admin = ? AND (actor = ? OR target = ? OR level IN ('warn','error','critical'))) "
        " AND actor NOT IN (SELECT username FROM dashboard_users WHERE role = 'superadmin') "
    )
    return frag, [my_admin, principal.username, principal.username]


def _events_filter_sql_args(
    principal: Principal,
    *,
    min_level: Optional[str],
    category: Optional[str],
    device_id: Optional[str],
    q: Optional[str],
    since_id: int,
    ts_epoch_min: Optional[int] = None,
) -> tuple[str, list[Any]]:
    """Shared WHERE clause + bind values for `/events*` queries."""
    sql = "WHERE 1=1"
    args: list[Any] = []
    scope_frag, scope_args = _event_scope_sql(principal)
    sql += scope_frag
    args.extend(scope_args)
    if min_level:
        try:
            idx = _VALID_LEVELS.index(min_level)
            allowed = _VALID_LEVELS[idx:]
            ph = ",".join(["?"] * len(allowed))
            sql += f" AND level IN ({ph}) "
            args.extend(allowed)
        except ValueError:
            pass
    if category:
        sql += " AND category = ? "
        args.append(category)
    if device_id:
        sql += " AND device_id = ? "
        args.append(device_id)
    if q:
        sql += " AND (event_type LIKE ? OR summary LIKE ? OR actor LIKE ? OR target LIKE ? OR device_id LIKE ?) "
        like = f"%{q}%"
        args.extend([like, like, like, like, like])
    if since_id > 0:
        sql += " AND id > ? "
        args.append(since_id)
    if ts_epoch_min is not None:
        sql += " AND ts_epoch_ms >= ? "
        args.append(int(ts_epoch_min))
    return sql, args


@app.get("/events")
def list_events(
    principal: Principal = Depends(require_principal),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    since_id: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    """Paginated read-only access to the events table."""
    wf, wa = _events_filter_sql_args(
        principal,
        min_level=min_level,
        category=category,
        device_id=device_id,
        q=q,
        since_id=since_id,
    )
    sql = (
        "SELECT id, ts, ts_epoch_ms, level, category, event_type, actor, target, owner_admin, device_id, summary, detail_json, ref_table, ref_id "
        f"FROM events {wf} ORDER BY id DESC LIMIT ? "
    )
    args = list(wa)
    args.append(limit)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        raw = r.pop("detail_json", None)
        try:
            r["detail"] = json.loads(raw) if raw else {}
        except Exception:
            r["detail"] = {"_raw": raw}
        r["ts_malaysia"] = iso_timestamp_to_malaysia(str(r.get("ts") or ""))
    return {"items": rows, "count": len(rows)}


@app.get("/events/export.csv")
def export_events_csv(
    principal: Principal = Depends(require_principal),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    limit: int = Query(default=5000, ge=1, le=20000),
) -> StreamingResponse:
    """Download a UTF-8 CSV snapshot (same visibility rules as GET /events)."""
    wf, wa = _events_filter_sql_args(
        principal,
        min_level=min_level,
        category=category,
        device_id=device_id,
        q=q,
        since_id=0,
    )
    sql = (
        "SELECT id, ts, level, category, event_type, actor, target, owner_admin, device_id, summary, detail_json "
        f"FROM events {wf} ORDER BY id DESC LIMIT ? "
    )
    args = list(wa)
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = list(cur.fetchall())
        conn.close()

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            ["id", "ts", "ts_malaysia", "level", "category", "event_type", "actor", "target", "owner_admin", "device_id", "summary", "detail_json"],
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for r in rows:
            w.writerow(
                [
                    r["id"],
                    r["ts"],
                    iso_timestamp_to_malaysia(str(r["ts"] or "")),
                    r["level"],
                    r["category"],
                    r["event_type"],
                    r["actor"] or "",
                    r["target"] or "",
                    r["owner_admin"] or "",
                    r["device_id"] or "",
                    r["summary"] or "",
                    (r["detail_json"] or "").replace("\r\n", " ").replace("\n", " "),
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    headers = {"Content-Disposition": 'attachment; filename="croc_sentinel_events.csv"'}
    return StreamingResponse(gen(), media_type="text/csv; charset=utf-8", headers=headers)


@app.get("/events/stats/by-device")
def events_stats_by_device(
    principal: Principal = Depends(require_principal),
    hours: int = Query(default=168, ge=1, le=24 * 365),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    """Aggregate event counts per device_id over the last `hours` hours."""
    ts_min = int(time.time() * 1000) - hours * 3600 * 1000
    wf, wa = _events_filter_sql_args(
        principal,
        min_level=None,
        category=None,
        device_id=None,
        q=None,
        since_id=0,
        ts_epoch_min=ts_min,
    )
    sql = (
        f"SELECT device_id, COUNT(*) AS cnt FROM events {wf} "
        "AND IFNULL(device_id,'') != '' "
        "GROUP BY device_id ORDER BY cnt DESC LIMIT ? "
    )
    args = list(wa)
    args.append(limit)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        rows = [{"device_id": r["device_id"], "count": int(r["cnt"])} for r in cur.fetchall()]
        conn.close()
    return {"hours": hours, "items": rows}


@app.get("/events/categories")
def event_categories(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {"levels": list(_VALID_LEVELS), "categories": list(_VALID_CATEGORIES)}


def _sse_format(ev: dict[str, Any]) -> str:
    """Serialize one event as an SSE frame."""
    ev_out = {
        "id": ev.get("id"),
        "ts": ev.get("ts"),
        "ts_epoch_ms": ev.get("ts_epoch_ms"),
        "level": ev.get("level"),
        "category": ev.get("category"),
        "event_type": ev.get("event_type"),
        "actor": ev.get("actor"),
        "target": ev.get("target"),
        "owner_admin": ev.get("owner_admin"),
        "device_id": ev.get("device_id"),
        "summary": ev.get("summary"),
        "detail": ev.get("detail") or {},
    }
    return f"id: {ev.get('id') or ''}\nevent: {ev.get('event_type') or 'event'}\ndata: {json.dumps(ev_out, ensure_ascii=False)}\n\n"


def _principal_from_sse_headers_or_query(
    authorization: Optional[str],
    token: Optional[str],
    cookie_token: Optional[str],
) -> Principal:
    """Prefer Authorization; optional legacy ?token= when SSE_ALLOW_QUERY_TOKEN; else HttpOnly cookie."""
    auth_header = authorization
    if not auth_header and SSE_ALLOW_QUERY_TOKEN and token:
        auth_header = f"Bearer {token}"
    if not auth_header and JWT_USE_HTTPONLY_COOKIE and cookie_token:
        auth_header = f"Bearer {str(cookie_token).strip()}"
    if not auth_header:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return require_principal(authorization=auth_header)


@app.get("/events/stream")
def events_stream(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(
        default=None,
        description="Legacy only when SSE_ALLOW_QUERY_TOKEN=1. Prefer Authorization header or session cookie.",
    ),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    backlog: int = Query(default=100, ge=0, le=500),
) -> StreamingResponse:
    ck = request.cookies.get(JWT_COOKIE_NAME) if JWT_USE_HTTPONLY_COOKIE else None
    qtok = token if SSE_ALLOW_QUERY_TOKEN else None
    principal = _principal_from_sse_headers_or_query(authorization, qtok, ck)
    assert_min_role(principal, "user")

    filters: dict[str, Any] = {
        "min_level": min_level,
        "category": category,
        "device_id": device_id,
        "q": q,
    }
    filters = {k: v for k, v in filters.items() if v}

    sub = event_bus.subscribe(principal, filters)

    def generator():
        # Initial hello frame — tells the UI which role is connected and
        # flushes any proxy buffering.
        _hello_now = datetime.now(timezone.utc)
        _hello_ts = _hello_now.isoformat()
        hello = {
            "event_type": "stream.hello",
            "level": "info",
            "category": "system",
            "ts": _hello_ts,
            "ts_malaysia": iso_timestamp_to_malaysia(_hello_ts),
            "ts_epoch_ms": int(_hello_now.timestamp() * 1000),
            "summary": f"connected as {principal.role}",
            "actor": "system",
            "detail": {"role": principal.role, "filters": filters},
            "id": 0,
        }
        yield _sse_format(hello)
        # Hint browser EventSource backoff after dropped connections (proxies / sleep).
        yield f"retry: {max(500, EVENT_SSE_RETRY_MS)}\n\n"
        # Replay recent backlog so the dashboard isn't empty on first load.
        if backlog:
            for ev in event_bus.backlog(principal, filters, backlog):
                yield _sse_format(ev)
        last_keepalive = time.time()
        # NOTE: we rely on Starlette closing the generator when the client
        # disconnects (the write yield will raise and our `finally` fires).
        while True:
            try:
                ev = sub.q.get(timeout=1.0)
                yield _sse_format(ev)
            except _stdqueue.Empty:
                pass
            now = time.time()
            if now - last_keepalive >= EVENT_SSE_KEEPALIVE_SECONDS:
                last_keepalive = now
                yield f": keepalive {int(now)} dropped={sub.dropped}\n\n"
                # Data-bearing frame — some proxies buffer until they see `data:` lines.
                ping = json.dumps({"ts": int(now * 1000), "dropped": sub.dropped})
                yield f"event: ping\ndata: {ping}\n\n"

    def close():
        event_bus.unsubscribe(sub)

    headers = {
        "Cache-Control": "no-cache, no-store, no-transform, max-age=0",
        "Pragma": "no-cache",
        "CDN-Cache-Control": "no-store",
        "X-Accel-Buffering": "no",  # Nginx: disable proxy buffering (requires proxy_request_buffering off)
        "Connection": "keep-alive",
    }
    # Wrap generator so we unsubscribe on client disconnect.
    def wrapped():
        try:
            for chunk in generator():
                yield chunk
        finally:
            close()

    return StreamingResponse(
        wrapped(),
        media_type="text/event-stream; charset=utf-8",
        headers=headers,
    )


@app.websocket("/events/ws")
async def events_ws(websocket: WebSocket) -> None:
    """JSON WebSocket mirror of /events/stream (Phase 2). Cookie JWT auth; same filters as query params."""
    if not EVENT_WS_ENABLED:
        await websocket.close(code=1008, reason="ws disabled")
        return
    await websocket.accept()
    qp = websocket.query_params
    qtok = qp.get("token") if SSE_ALLOW_QUERY_TOKEN else None
    backlog = min(500, max(0, int(qp.get("backlog") or 100)))
    filters: dict[str, Any] = {
        "min_level": qp.get("min_level"),
        "category": qp.get("category"),
        "device_id": qp.get("device_id"),
        "q": qp.get("q"),
    }
    filters = {k: v for k, v in filters.items() if v}
    ck = websocket.cookies.get(JWT_COOKIE_NAME) if JWT_USE_HTTPONLY_COOKIE else None
    auth_header = websocket.headers.get("authorization") or None
    try:
        principal = _principal_from_sse_headers_or_query(auth_header, qtok, ck)
        assert_min_role(principal, "user")
    except HTTPException:
        await websocket.close(code=1008, reason="auth failed")
        return

    sub = event_bus.subscribe(principal, filters)
    try:
        _hello_now = datetime.now(timezone.utc)
        _hello_ts = _hello_now.isoformat()
        hello = {
            "type": "hello",
            "event_type": "stream.hello",
            "level": "info",
            "category": "system",
            "ts": _hello_ts,
            "ts_malaysia": iso_timestamp_to_malaysia(_hello_ts),
            "ts_epoch_ms": int(_hello_now.timestamp() * 1000),
            "summary": f"connected as {principal.role}",
            "actor": "system",
            "detail": {"role": principal.role, "filters": filters},
            "id": 0,
        }
        await websocket.send_text(json.dumps(hello, default=str))
        if backlog:
            for ev in event_bus.backlog(principal, filters, backlog):
                await websocket.send_text(json.dumps({"type": "event", "ev": ev}, default=str))
        last_keepalive = time.time()
        while True:
            try:
                ev = await asyncio.to_thread(lambda: sub.q.get(timeout=1.0))
                await websocket.send_text(json.dumps({"type": "event", "ev": ev}, default=str))
            except _stdqueue.Empty:
                pass
            now = time.time()
            if now - last_keepalive >= EVENT_SSE_KEEPALIVE_SECONDS:
                last_keepalive = now
                await websocket.send_text(
                    json.dumps({"type": "ping", "ts": int(now * 1000), "dropped": sub.dropped}, default=str)
                )
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("events_ws failed")
    finally:
        event_bus.unsubscribe(sub)


@app.get("/diag/db-ping")
def diag_db_ping(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Cheap SQLite latency probe — use when the UI feels slow (admin+)."""
    assert_min_role(principal, "admin")
    t0 = time.perf_counter()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
    return {"ok": True, "db_ms": round((time.perf_counter() - t0) * 1000, 3), "pid": os.getpid()}


# =====================================================================
#  Factory device registry & /provision/identify (the "unguessable" story)
# =====================================================================

# Serial format: SN-<16 uppercase base32 chars>. 80 bits of CSPRNG entropy.
# The factory side generates these, never the device. Device only uses
# (serial, mac_nocolon) tuples that were uploaded to /factory/devices.
FACTORY_SERIAL_RE = re.compile(r"^SN-[A-Z2-7]{16}$")
# QR format: "CROC|<serial>|<unix_ts>|<base64_hmac_sha256(QR_SIGN_SECRET)>"
FACTORY_QR_RE = re.compile(r"^CROC\|SN-[A-Z2-7]{16}\|\d{10}\|[A-Za-z0-9_\-]{20,120}$")


class FactoryDeviceItem(BaseModel):
    serial: str = Field(pattern=r"^SN-[A-Z2-7]{16}$")
    mac_nocolon: Optional[str] = Field(default=None, min_length=12, max_length=12)
    qr_code: Optional[str] = Field(default=None, max_length=512)
    batch: Optional[str] = Field(default=None, max_length=64)
    note: Optional[str] = Field(default=None, max_length=256)


class FactoryBulkRequest(BaseModel):
    items: list[FactoryDeviceItem] = Field(min_length=1, max_length=2000)


def _require_factory_auth(request: Request) -> str:
    """Either superadmin JWT OR X-Factory-Token header matches FACTORY_API_TOKEN.

    We do the auth by hand here so that CI / factory scripts can use only the
    token and skip the JWT flow entirely.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            token = auth.split(" ", 1)[1].strip()
            claims = decode_jwt(token)
            if claims and str(claims.get("role", "")) == "superadmin":
                return str(claims.get("sub", "superadmin"))
        except Exception:
            pass
    token = request.headers.get("x-factory-token", "")
    if FACTORY_API_TOKEN and token and secrets.compare_digest(token, FACTORY_API_TOKEN):
        return "factory-token"
    raise HTTPException(status_code=403, detail="factory auth required (superadmin JWT or X-Factory-Token)")


@app.post("/factory/devices")
def factory_register_bulk(body: FactoryBulkRequest, request: Request) -> dict[str, Any]:
    """Bulk-register (serial, mac, qr) tuples produced at manufacturing time.

    Authenticate as superadmin (JWT) **or** supply X-Factory-Token equal to
    FACTORY_API_TOKEN. Existing rows are updated in place.
    """
    actor = _require_factory_auth(request)
    now = utc_now_iso()
    written = 0
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        for it in body.items:
            mac = (it.mac_nocolon or "").upper() or None
            if mac and (len(mac) != 12 or not re.fullmatch(r"^[0-9A-F]{12}$", mac)):
                conn.close()
                raise HTTPException(status_code=400, detail=f"invalid mac for {it.serial}")
            cur.execute(
                """INSERT INTO factory_devices (serial, mac_nocolon, qr_code, batch, status, note, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'unclaimed', ?, ?, ?)
                   ON CONFLICT(serial) DO UPDATE SET
                       mac_nocolon = COALESCE(excluded.mac_nocolon, factory_devices.mac_nocolon),
                       qr_code     = COALESCE(excluded.qr_code,     factory_devices.qr_code),
                       batch       = COALESCE(excluded.batch,       factory_devices.batch),
                       note        = COALESCE(excluded.note,        factory_devices.note),
                       updated_at  = excluded.updated_at""",
                (it.serial, mac, it.qr_code, it.batch, it.note, now, now),
            )
            written += 1
        conn.commit()
        conn.close()
    audit_event(actor, "factory.register.bulk", f"count={written}", {"batch": body.items[0].batch if body.items else ""})
    return {"ok": True, "written": written}


@app.get("/factory/ping")
def factory_ping(request: Request) -> dict[str, Any]:
    """No-op auth probe for factory UIs / scripts (same auth as POST /factory/devices)."""
    _require_factory_auth(request)
    return {"ok": True, "factory_auth": True}


@app.get("/factory/devices")
def factory_list(
    request: Request,
    status: Optional[str] = Query(default=None, pattern="^(unclaimed|claimed|blocked)$"),
    batch: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    sql = "SELECT serial, mac_nocolon, qr_code, batch, status, note, created_at, updated_at FROM factory_devices WHERE 1=1"
    args: list[Any] = []
    if status:
        sql += " AND status = ?"
        args.append(status)
    if batch:
        sql += " AND batch = ?"
        args.append(batch)
    sql += " ORDER BY created_at DESC LIMIT 1000"
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, tuple(args))
        items = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": items}


@app.post("/factory/devices/{serial}/block")
def factory_block_device(serial: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE factory_devices SET status='blocked', updated_at=? WHERE serial=?", (utc_now_iso(), serial))
        n = cur.rowcount
        conn.commit()
        conn.close()
    if n == 0:
        raise HTTPException(status_code=404, detail="serial not found")
    audit_event(principal.username, "factory.block", serial, {})
    return {"ok": True}


class IdentifyRequest(BaseModel):
    serial: Optional[str] = Field(default=None, max_length=64)
    qr_code: Optional[str] = Field(default=None, max_length=512)


@app.post("/provision/identify")
def provision_identify(
    body: IdentifyRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Answer "what state is this device in right now?" for the claim UI.

    The operator either scans the factory QR sticker or types the serial. We
    return one of:

      - unknown_serial       -> the serial is not in our factory registry
      - blocked              -> factory revoked this serial (RMA etc.)
      - already_registered   -> device is claimed
      - offline              -> device is in factory registry but has never
                                published bootstrap.register, i.e. it was
                                never online. Operator must power it up and
                                connect it to the network first.
      - ready                -> factory-registered, has bootstrap row, not
                                yet claimed. Caller can POST /provision/claim
                                with the returned mac_nocolon.
    """
    assert_min_role(principal, "admin")
    require_capability(principal, "can_claim_device")
    serial = (body.serial or "").strip().upper()
    qr = (body.qr_code or "").strip()
    if qr:
        # QR can optionally be HMAC-signed; the claim step verifies the sig.
        # For identify we only need to pluck the serial out of the QR string.
        m = re.match(r"^CROC\|(SN-[A-Z2-7]{16})\|", qr)
        if m:
            serial = m.group(1)
    if not serial:
        raise HTTPException(status_code=400, detail="serial or qr_code is required")
    if not FACTORY_SERIAL_RE.match(serial):
        raise HTTPException(status_code=400, detail="serial format invalid")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT serial, mac_nocolon, qr_code, status FROM factory_devices WHERE serial = ?",
            (serial,),
        )
        fdev = cur.fetchone()
        conn.close()
    if not fdev:
        return {"status": "unknown_serial", "serial": serial,
                "message": "该序列号不在出厂清单，请确认扫描的是正品贴纸或联系管理员"}
    if str(fdev["status"] or "unclaimed") == "blocked":
        return {"status": "blocked", "serial": serial,
                "message": "该设备已被出厂侧禁用（RMA / 质量问题）"}
    # Already registered?
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT device_id, mac_nocolon, claimed_at FROM provisioned_credentials WHERE device_id = ?",
            (serial,),
        )
        prov = cur.fetchone()
        owner = None
        if prov:
            cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (serial,))
            ow = cur.fetchone()
            owner = str(ow["owner_admin"]) if ow else None
        conn.close()
    if prov:
        you = owner and (owner == principal.username or (
            principal.role == "user" and owner == get_manager_admin(principal.username)
        ))
        resp: dict[str, Any] = {
            "status": "already_registered",
            "serial": serial,
            "device_id": str(prov["device_id"]),
            "mac_nocolon": str(prov["mac_nocolon"]),
            "claimed_at": str(prov["claimed_at"]),
            "message": "设备已被登记，无法再次注册",
        }
        if principal.role == "superadmin":
            resp["owner_admin"] = owner
            resp["by_you"] = bool(you)
        return resp
    # Does it appear in pending_claims? That only happens after the device
    # comes online and publishes bootstrap.register on MQTT.
    mac_for_lookup = str(fdev["mac_nocolon"] or "").upper()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        pend = None
        if mac_for_lookup:
            cur.execute(
                "SELECT mac_nocolon, last_seen_at, fw FROM pending_claims WHERE mac_nocolon = ?",
                (mac_for_lookup,),
            )
            pend = cur.fetchone()
        # Factory CSV may still carry a placeholder MAC while bootstrap.register
        # upserts pending_claims with the real MAC — list_pending shows the row
        # but MAC-only identify would wrongly return offline without this fallback.
        if pend is None:
            cur.execute(
                "SELECT mac_nocolon, last_seen_at, fw FROM pending_claims "
                "WHERE UPPER(IFNULL(proposed_device_id,'')) = ? ORDER BY last_seen_at DESC LIMIT 1",
                (serial,),
            )
            pend = cur.fetchone()
        conn.close()
    if not pend:
        return {
            "status": "offline",
            "serial": serial,
            "mac_hint": mac_for_lookup,
            "message": "设备未联网。请先通电、连上 WiFi/网线，看到状态灯稳定后再扫码激活。",
        }
    return {
        "status": "ready",
        "serial": serial,
        "mac_nocolon": str(pend["mac_nocolon"]),
        "fw": str(pend["fw"] or ""),
        "last_seen_at": str(pend["last_seen_at"]),
        "message": "设备在线且尚未登记，可点击确认注册",
    }
