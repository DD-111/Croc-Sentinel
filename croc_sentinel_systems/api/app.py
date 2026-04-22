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
import urllib.request
from contextlib import asynccontextmanager
import base64
import hashlib
import hmac
import re
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security import (
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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_delete_confirm(raw: str) -> str:
    """Strip invisible chars / odd spacing so pasted confirmation still matches DELETE."""
    s = raw or ""
    s = re.sub(r"[\u200b-\u200d\ufeff]", "", s)
    return re.sub(r"\s+", " ", s).strip().upper()


MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
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
DB_PATH = os.getenv("DB_PATH", "/data/sentinel.db")
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/data/api.log")
PROVISION_USE_SHARED_MQTT_CREDS = os.getenv("PROVISION_USE_SHARED_MQTT_CREDS", "1") == "1"
SCHEDULER_POLL_SECONDS = float(os.getenv("SCHEDULER_POLL_SECONDS", "1.0"))
CLAIM_RESPONSE_INCLUDE_SECRETS = os.getenv("CLAIM_RESPONSE_INCLUDE_SECRETS", "0") == "1"
MAX_BULK_TARGETS = int(os.getenv("MAX_BULK_TARGETS", "500"))
# Short TTL for dashboard list/overview JSON; higher = snappier repeat-nav, slightly staler counts.
CACHE_TTL_SECONDS = float(os.getenv("CACHE_TTL_SECONDS", "10.0"))
MESSAGE_RETENTION_DAYS = int(os.getenv("MESSAGE_RETENTION_DAYS", "14"))
STRICT_STARTUP_ENV_CHECK = os.getenv("STRICT_STARTUP_ENV_CHECK", "0") == "1"
JWT_SECRET = os.getenv("JWT_SECRET", "")
BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME", "superadmin").strip()
BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD", "")
ENFORCE_PER_DEVICE_CREDS = os.getenv("ENFORCE_PER_DEVICE_CREDS", "0") == "1"
ENFORCE_DEVICE_CHALLENGE = os.getenv("ENFORCE_DEVICE_CHALLENGE", "0") == "1"
DEVICE_CHALLENGE_TTL_SECONDS = int(os.getenv("DEVICE_CHALLENGE_TTL_SECONDS", "300"))
DEVICE_ID_REGEX = os.getenv("DEVICE_ID_REGEX", r"^SN-[A-Z2-7]{16}$")
QR_CODE_REGEX = os.getenv("QR_CODE_REGEX", r"^CROC\|SN-[A-Z2-7]{16}\|\d{10}\|[A-Za-z0-9_-]{20,120}$")
QR_SIGN_SECRET = os.getenv("QR_SIGN_SECRET", "")
ALLOW_LEGACY_UNOWNED = os.getenv("ALLOW_LEGACY_UNOWNED", "1") == "1"
OTA_FIRMWARE_DIR = os.getenv("OTA_FIRMWARE_DIR", "/opt/sentinel/firmware")
OTA_PUBLIC_BASE_URL = os.getenv("OTA_PUBLIC_BASE_URL", "").rstrip("/")
OTA_TOKEN = os.getenv("OTA_TOKEN", "")
ALARM_FANOUT_DURATION_MS = int(os.getenv("ALARM_FANOUT_DURATION_MS", "8000"))
ALARM_FANOUT_MAX_TARGETS = int(os.getenv("ALARM_FANOUT_MAX_TARGETS", "200"))
ALARM_FANOUT_SELF = os.getenv("ALARM_FANOUT_SELF", "0") == "1"
LOGIN_RATE_MAX_FAILS = int(os.getenv("LOGIN_RATE_MAX_FAILS", "5"))
LOGIN_RATE_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_WINDOW_SECONDS", "900"))

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

# --- Presence probe (replaces firmware-side periodic heartbeat) ---
# Devices in EVENT mode only publish heartbeats on state change. If we haven't
# heard from a device in IDLE_SECONDS, the API publishes a single `ping`
# command. Every probe (outgoing + ack) is recorded in presence_probes so ops
# can audit "why is device X marked offline?".
PRESENCE_PROBE_IDLE_SECONDS = int(os.getenv("PRESENCE_PROBE_IDLE_SECONDS", str(12 * 3600)))
# How often the background worker scans for stale devices.
PRESENCE_PROBE_SCAN_SECONDS = int(os.getenv("PRESENCE_PROBE_SCAN_SECONDS", "300"))
# Rate limit: don't probe the same device more than once per this window.
PRESENCE_PROBE_COOLDOWN_SECONDS = int(os.getenv("PRESENCE_PROBE_COOLDOWN_SECONDS", "1800"))
# After N consecutive failed probes, the device is flagged offline and we back
# off to stop spamming the broker for obviously dead hardware.
PRESENCE_PROBE_MAX_CONSECUTIVE = int(os.getenv("PRESENCE_PROBE_MAX_CONSECUTIVE", "3"))

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
# comments still see traffic. Keep below ~50s if your proxy read_timeout is 60s.
EVENT_SSE_KEEPALIVE_SECONDS = int(os.getenv("EVENT_SSE_KEEPALIVE_SECONDS", "15"))
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
    if not API_TOKEN or len(API_TOKEN) < 20 or contains_insecure_marker(API_TOKEN):
        errors.append("API_TOKEN is weak or default")
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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Per-connection pragmas. WAL + synchronous are set once in init_db_pragmas
    # because they're persistent; these here are per-connection tuning.
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA busy_timeout = 5000")
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
        ensure_column(conn, "role_policies", "tg_view_logs", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_view_devices", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_siren_on", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_siren_off", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_test_single", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "role_policies", "tg_test_bulk", "INTEGER NOT NULL DEFAULT 0")
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

    def publish(self, ev: dict[str, Any]) -> None:
        with self._lock:
            self._ring.append(ev)
            for sub in list(self._subs.values()):
                if not _event_visible(sub.principal, ev):
                    continue
                if not _event_matches_filters(ev, sub.filters):
                    continue
                try:
                    sub.q.put_nowait(ev)
                except _stdqueue.Full:
                    # Slow consumer. Drop one oldest event, signal backpressure.
                    try:
                        sub.q.get_nowait()
                        sub.q.put_nowait(ev)
                        sub.dropped += 1
                    except Exception:
                        sub.dropped += 1


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
_superadmin_cache: set[str] = set()
_superadmin_cache_ts = 0.0


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
    try:
        from telegram_notify import maybe_notify_telegram

        maybe_notify_telegram(ev)
    except Exception as exc:
        # Avoid silent failures when Telegram module/env is misconfigured (default log level INFO).
        logger.warning("telegram_notify skipped: %s", exc)


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
    """Return (can_view, can_operate) after ownership + sharing ACL checks."""
    if principal.role == "superadmin":
        return True, True
    manager = get_manager_admin(principal.username) if principal.role == "user" else ""
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT owner_admin FROM device_ownership WHERE device_id = ?", (device_id,))
        own = cur.fetchone()
        cur.execute(
            """
            SELECT can_view, can_operate
            FROM device_acl
            WHERE device_id = ? AND grantee_username = ? AND revoked_at IS NULL
            LIMIT 1
            """,
            (device_id, principal.username),
        )
        acl = cur.fetchone()
        conn.close()
    owner = str(own["owner_admin"]) if own and own["owner_admin"] is not None else ""
    acl_view = bool(int(acl["can_view"])) if acl else False
    acl_operate = bool(int(acl["can_operate"])) if acl else False
    if principal.role == "admin":
        owner_view = bool(owner) and owner == principal.username
        if not owner and ALLOW_LEGACY_UNOWNED:
            owner_view = True
        owner_operate = bool(owner) and owner == principal.username
        return (owner_view or acl_view or acl_operate), (owner_operate or acl_operate)
    owner_view = bool(owner) and bool(manager) and owner == manager
    if not owner and ALLOW_LEGACY_UNOWNED and bool(manager):
        owner_view = True
    owner_operate = bool(owner) and bool(manager) and owner == manager
    return (owner_view or acl_view or acl_operate), (owner_operate or acl_operate)


def assert_device_view_access(principal: Principal, device_id: str) -> None:
    can_view, _ = _device_access_flags(principal, device_id)
    if not can_view:
        raise HTTPException(status_code=403, detail="device not in your scope")


def assert_device_operate_access(principal: Principal, device_id: str) -> None:
    _, can_operate = _device_access_flags(principal, device_id)
    if not can_operate:
        raise HTTPException(status_code=403, detail="device operation denied")


def assert_device_owner(principal: Principal, device_id: str) -> None:
    # Backward-compatible alias used by existing routes.
    assert_device_operate_access(principal, device_id)


def owner_sql_suffix(principal: Principal, alias: str = "d") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    col = f"{alias}.owner_admin"
    if principal.role == "admin":
        return f" AND ({col} = ? {'OR '+col+' IS NULL' if ALLOW_LEGACY_UNOWNED else ''}) ", [principal.username]
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    return f" AND ({col} = ? {'OR '+col+' IS NULL' if ALLOW_LEGACY_UNOWNED else ''}) ", [manager]


def owner_scope_clause_for_device_state(principal: Principal, device_alias: str = "device_state") -> tuple[str, list[Any]]:
    if principal.role == "superadmin":
        return "", []
    if principal.role == "admin":
        acl_clause = (
            f"EXISTS (SELECT 1 FROM device_acl a WHERE a.device_id={device_alias}.device_id "
            "AND a.grantee_username=? AND a.revoked_at IS NULL AND (a.can_view=1 OR a.can_operate=1))"
        )
        if ALLOW_LEGACY_UNOWNED:
            return (
                f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
                "OR (" + acl_clause + ") "
                f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
                [principal.username, principal.username],
            )
        return (
            f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
            "OR (" + acl_clause + ")) ",
            [principal.username, principal.username],
        )
    manager = get_manager_admin(principal.username)
    if not manager:
        return " AND 1=0 ", []
    acl_clause = (
        f"EXISTS (SELECT 1 FROM device_acl a WHERE a.device_id={device_alias}.device_id "
        "AND a.grantee_username=? AND a.revoked_at IS NULL AND (a.can_view=1 OR a.can_operate=1))"
    )
    if ALLOW_LEGACY_UNOWNED:
        return (
            f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
            "OR (" + acl_clause + ") "
            f"OR (NOT EXISTS (SELECT 1 FROM device_ownership o2 WHERE o2.device_id={device_alias}.device_id))) ",
            [manager, principal.username],
        )
    return (
        f" AND ((EXISTS (SELECT 1 FROM device_ownership o WHERE o.device_id={device_alias}.device_id AND o.owner_admin=?)) "
        "OR (" + acl_clause + ")) ",
        [manager, principal.username],
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
) -> list[tuple[str, str]]:
    """Siblings in the same tenant to fan out an alarm to.

    Returns list of (device_id, zone). Excludes revoked devices. If
    ALARM_FANOUT_SELF is false, the source is also excluded (default: the
    source device already sounded its siren locally).
    """
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        zone_filter = source_zone.strip()
        group_filter = source_group.strip()
        if owner_admin:
            sql = """
                SELECT d.device_id, d.zone
                FROM device_state d
                JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.owner_admin = ? AND r.device_id IS NULL
            """
            args: list[Any] = [owner_admin]
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            if group_filter:
                sql += " AND IFNULL(d.notification_group,'') = ?"
                args.append(group_filter)
            cur.execute(
                sql,
                args,
            )
        else:
            # No owner: treat as legacy-unowned pool. Only fan out to other
            # legacy-unowned devices to avoid leaking into tenants.
            sql = """
                SELECT d.device_id, d.zone
                FROM device_state d
                LEFT JOIN device_ownership o ON o.device_id = d.device_id
                LEFT JOIN revoked_devices r ON r.device_id = d.device_id
                WHERE o.device_id IS NULL AND r.device_id IS NULL
            """
            args = []
            if zone_filter and zone_filter.lower() not in ("all", "*"):
                sql += " AND IFNULL(d.zone,'') = ?"
                args.append(zone_filter)
            if group_filter:
                sql += " AND IFNULL(d.notification_group,'') = ?"
                args.append(group_filter)
            cur.execute(sql, args)
        rows = cur.fetchall()
        conn.close()
    out: list[tuple[str, str]] = []
    for r in rows:
        did = str(r["device_id"])
        if did == source_id and not include_source:
            continue
        out.append((did, str(r["zone"] or "")))
    return out[:ALARM_FANOUT_MAX_TARGETS]


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
                   remote_loud_duration_ms, fanout_exclude_self
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


# ═══════════════════════════════════════════════
#  OTA campaigns (superadmin -> admin accept -> per-device rollout)
# ═══════════════════════════════════════════════

def _verify_ota_url(url: str) -> tuple[bool, str]:
    """HEAD the firmware URL so we fail fast if the superadmin typoed it.
    Returns (ok, detail)."""
    if not url.startswith(("http://", "https://")):
        return False, "scheme_not_http"
    try:
        import urllib.request
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=OTA_URL_VERIFY_TIMEOUT_SECONDS) as resp:
            code = int(getattr(resp, "status", 200))
            length = resp.headers.get("content-length", "")
            if 200 <= code < 400:
                return True, f"http_{code} size={length or '?'}"
            return False, f"http_{code}"
    except Exception as exc:
        return False, f"head_err:{exc.__class__.__name__}:{exc}"


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
      1. Determine owner_admin (tenant).
      2. Find sibling devices with the same owner_admin (revoked excluded).
      3. Publish siren_on command to each sibling, with that device's cmd_key.
      4. Insert alarm record, queue email to the tenant's recipients.
    """
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
        "network",
        "group_link",
    )
    if triggered_by == "remote_silent_button" and not bool(policy.get("remote_silent_link_enabled", True)):
        should_fanout = False
    if triggered_by in ("remote_button", "remote_loud_button", "network", "group_link") and not bool(
        policy.get("remote_loud_link_enabled", True)
    ):
        should_fanout = False
    targets = _tenant_siblings(
        owner_admin,
        device_id,
        source_zone=source_zone,
        source_group=source_group,
        include_source=not bool(policy.get("fanout_exclude_self", True)),
    ) if should_fanout else []
    sent = 0
    failures: list[str] = []
    if should_fanout:
        for did, _z in targets:
            try:
                cmd = "siren_on"
                params: dict[str, Any] = {"duration_ms": int(policy.get("remote_loud_duration_ms", ALARM_FANOUT_DURATION_MS))}
                # Remote silent button: link to sibling devices without siren sound.
                if triggered_by == "remote_silent_button":
                    cmd = "alarm_signal"
                    params = {"kind": "silent"}
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
                failures.append(f"{did}:{exc}")

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
    client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
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


def require_principal(authorization: Optional[str] = Header(default=None)) -> Principal:
    """
    Accepts legacy long-lived API_TOKEN (superadmin) or JWT from POST /auth/login.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="empty bearer token")
    if API_TOKEN:
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
    duration_ms: int = Field(default=8000, ge=500, le=120000)
    device_ids: list[str] = Field(default_factory=list)


class ProvisionWifiTaskRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=32)
    password: str = Field(default="", max_length=64)


class TriggerPolicyBody(BaseModel):
    panic_local_siren: bool = True
    remote_silent_link_enabled: bool = True
    remote_loud_link_enabled: bool = True
    remote_loud_duration_ms: int = Field(default=10000, ge=500, le=120000)
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
    notifier.start()
    try:
        from telegram_notify import start_telegram_worker

        start_telegram_worker()
    except Exception:
        logger.exception("Telegram worker failed to start (check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS)")
    mqtt_worker_stop.clear()
    mqtt_ingest_dropped = 0
    mqtt_worker_thread = threading.Thread(target=_mqtt_ingest_worker, name="mqtt-ingest", daemon=True)
    mqtt_worker_thread.start()
    mqtt_client = start_mqtt_loop()
    scheduler_stop.clear()
    scheduler_thread = threading.Thread(target=scheduler_loop, name="cmd-scheduler", daemon=True)
    scheduler_thread.start()
    logger.info(
        "API started mqtt_host=%s mqtt_port=%s mqtt_tls=%s "
        "mqtt_tls_verify_hostname=%s db=%s notifier_enabled=%s telegram=%s",
        MQTT_HOST,
        MQTT_PORT,
        MQTT_USE_TLS,
        MQTT_TLS_VERIFY_HOSTNAME,
        DB_PATH,
        notifier.enabled(),
        _telegram_enabled_safe(),
    )


def _shutdown_api() -> None:
    global mqtt_client, scheduler_thread, mqtt_worker_thread
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


def _check_login_rate(ip: str, username: str) -> None:
    """Raise 429 if the ip OR username has too many recent failures."""
    cutoff = int(time.time()) - LOGIN_RATE_WINDOW_SECONDS
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM login_failures WHERE ts_epoch < ?", (cutoff,))
        cur.execute(
            "SELECT COUNT(*) AS c FROM login_failures WHERE ip = ? AND ts_epoch >= ?",
            (ip, cutoff),
        )
        ip_fails = int(cur.fetchone()["c"])
        cur.execute(
            "SELECT COUNT(*) AS c FROM login_failures WHERE username = ? AND ts_epoch >= ?",
            (username, cutoff),
        )
        user_fails = int(cur.fetchone()["c"])
        conn.commit()
        conn.close()
    if ip_fails >= LOGIN_RATE_MAX_FAILS or user_fails >= LOGIN_RATE_MAX_FAILS:
        emit_event(
            level="error",
            category="auth",
            event_type="auth.login.rate_limited",
            summary=f"rate-limit {username}@{ip}",
            actor=f"ip:{ip}",
            target=username,
            detail={"ip_fails": ip_fails, "user_fails": user_fails},
        )
        raise HTTPException(
            status_code=429,
            detail=f"too many login attempts — locked for up to {LOGIN_RATE_WINDOW_SECONDS}s",
        )


def _record_login_failure(ip: str, username: str) -> None:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO login_failures (ip, username, ts_epoch) VALUES (?, ?, ?)",
            (ip, username, int(time.time())),
        )
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
def auth_login(body: LoginRequest, request: Request) -> dict[str, Any]:
    ctx = _client_context(request)
    ip = ctx["ip"]
    _check_login_rate(ip, body.username)
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
    zones = zones_from_json(str(row["allowed_zones_json"]))
    token = issue_jwt(str(row["username"]), str(row["role"]), zones)
    ok_detail = dict(ctx)
    ok_detail["owner_admin"] = owner_admin
    ok_detail["login_user"] = str(row["username"])
    audit_event(str(row["username"]), "auth.login.ok", str(row["username"]), ok_detail)
    # One-time welcome email after first successful login (requires SMTP + stored email).
    try:
        email_u = str(row["email"] or "").strip()
        rk = row.keys()
        wel_sent = int(row["welcome_email_sent"] or 0) if "welcome_email_sent" in rk else 0
        if notifier.enabled() and email_u and wel_sent == 0:
            ws, wt, wh = render_welcome_email(username=str(row["username"]), role=str(row["role"]))
            notifier.send_sync([email_u], ws, wt, wh)
            with db_lock:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE dashboard_users SET welcome_email_sent = 1 WHERE username = ?",
                    (body.username,),
                )
                conn.commit()
                conn.close()
    except Exception:
        logger.warning("welcome email skipped or failed for %s", body.username, exc_info=True)
    return {"access_token": token, "token_type": "bearer", "role": row["role"], "zones": zones}


@app.get("/auth/me")
def auth_me(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {
        "username": principal.username,
        "role": principal.role,
        "zones": principal.zones,
        "policy": get_effective_policy(principal),
        "manager_admin": get_manager_admin(principal.username) if principal.role == "user" else "",
    }


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
            ps, pt, ph = render_password_changed_email(username=principal.username, iso_ts=utc_now_iso())
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
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")
    audit_event(principal.username, "device.revoke", device_id, {"reason": req.reason})
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
    cur.execute("DELETE FROM password_reset_tokens WHERE username = ?", (username,))
    cur.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))


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
        cur.execute(
            """
            UPDATE device_ownership
            SET owner_admin = ?, assigned_by = ?, assigned_at = ?
            WHERE owner_admin = ?
            """,
            (transfer_to, actor_username, utc_now_iso(), admin_username),
        )
        summary["devices_transferred"] = int(cur.rowcount or 0)
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


def _device_delete_reset_impl(
    device_id: str,
    principal: Principal,
    req: DeviceDeleteRequest,
    *,
    super_unclaim: bool,
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if str(req.confirm_text or "").strip().upper() != str(device_id or "").strip().upper():
        raise HTTPException(status_code=400, detail="confirm_text must exactly match device_id")
    if principal.role == "admin":
        require_capability(principal, "can_send_command")
    if super_unclaim:
        # Superadmin: any device. Admin: only own (non-shared) devices — same factory rollback as superadmin.
        if not principal.is_superadmin():
            assert_device_owner(principal, device_id)
    else:
        assert_device_owner(principal, device_id)
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
    }


@app.post("/devices/{device_id}/delete-reset")
def device_delete_reset(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Admin/superadmin: delete device records so it can be re-added/reset."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=False)


@app.post("/devices/{device_id}/factory-unregister")
def device_factory_unregister(
    device_id: str,
    req: DeviceDeleteRequest,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Rollback to unregistered while keeping factory serial: superadmin (any device) or owning admin."""
    return _device_delete_reset_impl(device_id, principal, req, super_unclaim=True)


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness for load balancers / `curl` — intentionally **no** auth so Uptime
    Kuma, Docker healthchecks, and reverse proxies can probe without a token."""
    tg: dict[str, Any] = {}
    try:
        from telegram_notify import telegram_status

        tg = dict(telegram_status())
    except Exception as exc:
        tg = {"enabled": False, "worker_running": False, "error": str(exc)}
    ready = api_ready_event.is_set() and not api_bootstrap_error
    body: dict[str, Any] = {
        "ok": bool(ready),
        "ready": ready,
        "starting": not api_ready_event.is_set(),
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
            owner_admin = str(d.get("owner_admin") or "")
            d.pop("last_status_json", None)
            d.pop("last_heartbeat_json", None)
            d.pop("last_ack_json", None)
            d.pop("last_event_json", None)
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
    return out


class DeviceDisplayLabelBody(BaseModel):
    display_label: str = Field(default="", max_length=80)


class DeviceProfileBody(BaseModel):
    display_label: Optional[str] = Field(default=None, max_length=80)
    notification_group: Optional[str] = Field(default=None, max_length=80)


class GroupCardSettingsBody(BaseModel):
    trigger_mode: str = Field(default="continuous", pattern="^(continuous|delay)$")
    trigger_duration_ms: int = Field(default=10000, ge=500, le=120000)
    delay_seconds: int = Field(default=0, ge=0, le=3600)
    reboot_self_check: bool = False


class DeviceShareRequest(BaseModel):
    grantee_username: str = Field(min_length=2, max_length=64)
    can_view: bool = True
    can_operate: bool = False


def _delete_group_card_impl(group_key: str, principal: Principal) -> dict[str, Any]:
    """Delete a group card by clearing notification_group on target devices.

    Security rule:
      - admin: can only delete groups fully owned by self (shared devices block deletion)
      - superadmin: can delete any group
    """
    assert_min_role(principal, "admin")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
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
            WHERE IFNULL(d.notification_group,'') = ? {zs} {osf}
            ORDER BY d.device_id ASC
            """,
            tuple([g] + za + osa),
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
    owner_scope = principal.username if principal.role == "admin" else (get_manager_admin(principal.username) or principal.username)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM group_card_settings WHERE owner_admin = ? AND group_key = ?",
            (owner_scope, g),
        )
        conn.commit()
        conn.close()
    audit_event(principal.username, "group.delete", g, {"device_count": len(ids), "changed": changed})
    return {"ok": True, "group_key": g, "device_count": len(ids), "changed": changed}


@app.delete("/group-cards/{group_key}")
def delete_group_card(group_key: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal)


@app.post("/group-cards/{group_key}/delete")
def delete_group_card_post(group_key: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Proxy-friendly delete route for environments that block HTTP DELETE."""
    return _delete_group_card_impl(group_key, principal)


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
        "trigger_duration_ms": 10000,
        "delay_seconds": 0,
        "reboot_self_check": False,
        "updated_by": "",
        "updated_at": "",
    }


def _group_devices_with_owner(group_key: str, principal: Principal) -> list[dict[str, str]]:
    g = (group_key or "").strip()
    if not g:
        return []
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
            WHERE IFNULL(d.notification_group,'') = ? {zs} {osf}
            ORDER BY d.device_id ASC
            """,
            tuple([g] + za + osa),
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
        cur.execute(
            """
            SELECT group_key, trigger_mode, trigger_duration_ms, delay_seconds, reboot_self_check, updated_by, updated_at
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
                "group_key": str(r.get("group_key") or ""),
                "trigger_mode": str(r.get("trigger_mode") or "continuous"),
                "trigger_duration_ms": int(r.get("trigger_duration_ms") or 10000),
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
def get_group_card_settings(group_key: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT group_key, trigger_mode, trigger_duration_ms, delay_seconds, reboot_self_check, updated_by, updated_at
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
        "group_key": g,
        "trigger_mode": str(r.get("trigger_mode") or "continuous"),
        "trigger_duration_ms": int(r.get("trigger_duration_ms") or 10000),
        "delay_seconds": int(r.get("delay_seconds") or 0),
        "reboot_self_check": bool(int(r.get("reboot_self_check") or 0)),
        "updated_by": str(r.get("updated_by") or ""),
        "updated_at": str(r.get("updated_at") or ""),
    }


@app.get("/api/group-cards/{group_key}/settings")
def get_group_card_settings_api(group_key: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    return get_group_card_settings(group_key, principal)


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
    rows = _group_devices_with_owner(g, principal)
    if not rows:
        raise HTTPException(status_code=404, detail="group not found in your scope")
    # Shared groups are owner-managed: grantee cannot override owner strategy.
    if principal.role != "superadmin":
        for r in rows:
            o = str(r.get("owner_admin") or "")
            if o and o != owner_scope:
                raise HTTPException(status_code=403, detail="shared group settings are managed by owner")
    now = utc_now_iso()
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
                body.trigger_mode,
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
            "trigger_mode": body.trigger_mode,
            "trigger_duration_ms": int(body.trigger_duration_ms),
            "delay_seconds": int(body.delay_seconds),
            "reboot_self_check": bool(body.reboot_self_check),
        },
    )
    return {
        "ok": True,
        "group_key": g,
        "trigger_mode": body.trigger_mode,
        "trigger_duration_ms": int(body.trigger_duration_ms),
        "delay_seconds": int(body.delay_seconds),
        "reboot_self_check": bool(body.reboot_self_check),
        "updated_by": principal.username,
        "updated_at": now,
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
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    g = (group_key or "").strip()
    if not g:
        raise HTTPException(status_code=400, detail="group_key required")
    owner_scope = _group_owner_scope(principal)
    rows = _group_devices_with_owner(g, principal)
    targets = [str(r["device_id"]) for r in rows if r.get("device_id")]
    if not targets:
        raise HTTPException(status_code=404, detail="group has no devices in your scope")

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
                    "trigger_duration_ms": int(r["trigger_duration_ms"] or 10000),
                    "delay_seconds": int(r["delay_seconds"] or 0),
                    "reboot_self_check": bool(int(r["reboot_self_check"] or 0)),
                }
            conn.close()

    now_ts = int(time.time())
    siren_sent = 0
    siren_scheduled = 0
    reboot_jobs = 0
    self_tests = 0
    for did in targets:
        ensure_not_revoked(did)
        owner_real = str(device_owner_map.get(did) or "")
        owner_for_cfg = owner_real or owner_scope
        cfg = settings_by_owner.get(owner_for_cfg, _group_settings_defaults(g))
        mode = str(cfg.get("trigger_mode") or "continuous")
        dur_ms = int(cfg.get("trigger_duration_ms") or 10000)
        delay_seconds = int(cfg.get("delay_seconds") or 0)
        reboot_self_check = bool(cfg.get("reboot_self_check"))
        if mode == "delay" and delay_seconds > 0:
            enqueue_scheduled_command(
                device_id=did,
                cmd="siren_on",
                params={"duration_ms": dur_ms},
                target_id=did,
                proto=CMD_PROTO,
                execute_at_ts=now_ts + delay_seconds,
            )
            siren_scheduled += 1
        else:
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
            assert_min_role(principal, "admin")
            require_capability(principal, "can_send_command")
            publish_command(
                topic=f"{TOPIC_ROOT}/{did}/cmd",
                cmd="self_test",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                cmd_key=get_cmd_key_for_device(did),
            )
            self_tests += 1
            enqueue_scheduled_command(
                device_id=did,
                cmd="reboot",
                params={},
                target_id=did,
                proto=CMD_PROTO,
                execute_at_ts=now_ts + max(5, delay_seconds + 5),
            )
            reboot_jobs += 1

    owner = _lookup_owner_admin(targets[0]) if targets else ""
    # Report the first owner's effective setting for compact response fields.
    first_owner = str(device_owner_map.get(targets[0]) or owner_scope) if targets else owner_scope
    first_cfg = settings_by_owner.get(first_owner, _group_settings_defaults(g))
    mode = str(first_cfg.get("trigger_mode") or "continuous")
    dur_ms = int(first_cfg.get("trigger_duration_ms") or 10000)
    delay_seconds = int(first_cfg.get("delay_seconds") or 0)
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
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return apply_group_card_settings(group_key, principal)


@app.delete("/api/group-cards/{group_key}")
def delete_group_card_api(group_key: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal)


@app.post("/api/group-cards/{group_key}/delete")
def delete_group_card_post_api(group_key: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    return _delete_group_card_impl(group_key, principal)


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
        cur.execute("SELECT zone FROM device_state WHERE device_id = ?", (device_id,))
        zr = cur.fetchone()
        if not zr:
            conn.close()
            raise HTTPException(status_code=404, detail="device not found")
        assert_zone_for_device(principal, str(zr["zone"]) if zr["zone"] is not None else "")
        cur.execute(
            f"UPDATE device_state SET {', '.join(sets)} WHERE device_id = ?",
            tuple(args),
        )
        conn.commit()
        conn.close()
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
            "display_label": body.display_label.strip() if body.display_label is not None else None,
            "notification_group": body.notification_group.strip() if body.notification_group is not None else None,
        },
    )
    out: dict[str, Any] = {"ok": True, "device_id": device_id}
    if body.display_label is not None:
        out["display_label"] = body.display_label.strip()
    if body.notification_group is not None:
        out["notification_group"] = body.notification_group.strip()
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
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT cmd_key FROM provisioned_credentials WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
    if row and row["cmd_key"]:
        return str(row["cmd_key"])
    return CMD_AUTH_KEY


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


def publish_command(topic: str, cmd: str, params: dict[str, Any], target_id: str, proto: int, cmd_key: str) -> None:
    global mqtt_client
    if mqtt_client is None:
        raise HTTPException(status_code=500, detail="mqtt client not ready")
    payload = {
        "proto": proto,
        "key": cmd_key,
        "target_id": target_id,
        "cmd": cmd,
        "params": params,
    }
    body = json.dumps(payload, ensure_ascii=True)
    for attempt in range(3):
        info = mqtt_client.publish(topic, body, qos=1)
        info.wait_for_publish(timeout=3.0)
        if info.is_published():
            return
        if attempt < 2:
            time.sleep(0.15)
    raise HTTPException(status_code=502, detail="mqtt publish failed")


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
            osf = (
                " AND ("
                "o.owner_admin = ? "
                "OR EXISTS (SELECT 1 FROM device_acl a WHERE a.device_id=d.device_id "
                "AND a.grantee_username=? AND a.revoked_at IS NULL AND a.can_operate=1)"
                ") "
            )
            osa = [principal.username, principal.username]
        else:
            manager = get_manager_admin(principal.username)
            if not manager:
                osf = " AND 1=0 "
                osa = []
            else:
                osf = (
                    " AND ("
                    "o.owner_admin = ? "
                    "OR EXISTS (SELECT 1 FROM device_acl a WHERE a.device_id=d.device_id "
                    "AND a.grantee_username=? AND a.revoked_at IS NULL AND a.can_operate=1)"
                    ") "
                )
                osa = [manager, principal.username]
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

        scheduler_stop.wait(SCHEDULER_POLL_SECONDS)


@app.get("/provision/pending")
def list_pending_claims(
    principal: Principal = Depends(require_principal),
    q: Optional[str] = Query(default=None, max_length=64, description="Filter by MAC (no colon) or QR substring"),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    if principal.role == "admin":
        require_capability(principal, "can_claim_device")
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
    ensure_not_revoked(req.device_id)

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM pending_claims WHERE mac_nocolon = ?", (mac_nocolon,))
        pending = cur.fetchone()
        if not pending:
            conn.close()
            raise HTTPException(status_code=404, detail="pending device not found")
        cur.execute("SELECT mac_nocolon FROM provisioned_credentials WHERE device_id = ?", (req.device_id,))
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
                (mac_nocolon, req.device_id.strip().upper(), int(time.time())),
            )
            ch = cur.fetchone()
            if not ch or not ch["verified_at"] or int(ch["used"]) == 1:
                conn.close()
                raise HTTPException(status_code=412, detail="verified device challenge required before claim")
        mqtt_username, mqtt_password, cmd_key = generate_device_credentials(req.device_id)

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
                req.device_id,
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
            (req.device_id, owner_admin, principal.username, utc_now_iso()),
        )
        conn.commit()
        conn.close()
    if ENFORCE_DEVICE_CHALLENGE:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE provision_challenges SET used = 1
                WHERE mac_nocolon = ? AND device_id = ? AND verified_at IS NOT NULL AND used = 0
                """,
                (mac_nocolon, req.device_id.strip().upper()),
            )
            conn.commit()
            conn.close()

    publish_bootstrap_claim(
        mac_nocolon=mac_nocolon,
        claim_nonce=claim_nonce,
        device_id=req.device_id,
        zone=req.zone,
        qr_code=qr_code,
        mqtt_username=mqtt_username,
        mqtt_password=mqtt_password,
        cmd_key=cmd_key,
    )

    resp = {
        "ok": True,
        "device_id": req.device_id,
        "mac_nocolon": mac_nocolon,
        "mqtt_username": mqtt_username if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "mqtt_password": mqtt_password if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
        "cmd_key": cmd_key if CLAIM_RESPONSE_INCLUDE_SECRETS else "***",
    }
    audit_event(principal.username, "provision.claim", req.device_id, {"mac_nocolon": mac_nocolon, "zone": req.zone})
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
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    ensure_not_revoked(device_id)
    assert_device_owner(principal, device_id)
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
    group_key = str(row.get("notification_group") or "")
    pol = _trigger_policy_for(owner, group_key)
    return {"ok": True, "device_id": device_id, "scope_group": group_key, "policy": pol}


@app.put("/devices/{device_id}/trigger-policy")
def save_device_trigger_policy(
    device_id: str,
    body: TriggerPolicyBody,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    group_key = str(row.get("notification_group") or "")
    now = utc_now_iso()
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO trigger_policies (
                owner_admin, scope_group, panic_local_siren, remote_silent_link_enabled,
                remote_loud_link_enabled, remote_loud_duration_ms, fanout_exclude_self, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_admin, scope_group) DO UPDATE SET
                panic_local_siren=excluded.panic_local_siren,
                remote_silent_link_enabled=excluded.remote_silent_link_enabled,
                remote_loud_link_enabled=excluded.remote_loud_link_enabled,
                remote_loud_duration_ms=excluded.remote_loud_duration_ms,
                fanout_exclude_self=excluded.fanout_exclude_self,
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
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    ensure_not_revoked(device_id)
    assert_device_owner(principal, device_id)
    row, owner = _load_device_row_for_task(device_id)
    assert_zone_for_device(principal, str(row.get("zone") or ""))
    now = utc_now_iso()
    task_id = secrets.token_hex(12)
    publish_command(
        topic=f"{TOPIC_ROOT}/{device_id}/cmd",
        cmd="wifi_config",
        params={"ssid": body.ssid, "password": body.password},
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
                json.dumps({"ssid": body.ssid}, ensure_ascii=False),
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
        detail={"task_id": task_id},
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
    duration_ms: int = Query(default=8000, ge=500, le=120000),
    request: Request = None,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
    require_capability(principal, "can_alert")
    ensure_not_revoked(device_id)
    assert_device_owner(principal, device_id)
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
    assert_device_owner(principal, device_id)
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
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    ensure_not_revoked(device_id)
    assert_device_owner(principal, device_id)
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
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    ensure_not_revoked(device_id)
    assert_device_owner(principal, device_id)
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
    assert_min_role(principal, "admin")
    require_capability(principal, "can_send_command")
    ensure_not_revoked(device_id)
    assert_device_owner(principal, device_id)
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
        if ALLOW_LEGACY_UNOWNED:
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
    if ALLOW_LEGACY_UNOWNED:
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

    merged: list[dict[str, Any]] = []
    for r in alarm_rows:
        merged.append(
            {
                "ts": r["created_at"],
                "kind": "device_alarm",
                "what": "alarm_fanout",
                "device_id": r["device_id"],
                "display_label": r["display_label"] or "",
                "notification_group": r.get("notification_group") or "",
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
        merged.append(
            {
                "ts": r["created_at"],
                "kind": r["kind"],
                "what": r["kind"],
                "device_id": r["device_id"],
                "display_label": r["display_label"] or "",
                "notification_group": r.get("notification_group") or "",
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
        iso_ts=utc_now_iso(),
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
        duration_ms = 10000
        if len(parts) >= 4 and parts[3].isdigit():
            duration_ms = int(parts[3])
        duration_ms = max(500, min(duration_ms, 120000))
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


def _sha256_for(path: str) -> Optional[str]:
    sidecar = path + ".sha256"
    if os.path.isfile(sidecar):
        try:
            with open(sidecar, "r", encoding="utf-8", errors="ignore") as f:
                line = f.readline().strip()
            if line:
                return line.split()[0]
        except Exception:
            return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


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
            items.append({
                "name": name,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
                "sha256": _sha256_for(path),
                "download_url": url,
            })
    return {"dir": base, "public_base": OTA_PUBLIC_BASE_URL, "items": items}


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


@app.post("/ota/campaigns")
def create_ota_campaign(req: OtaCampaignCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
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


@app.get("/ota/campaigns")
def list_ota_campaigns(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    """Superadmin sees every campaign; admin sees only campaigns that list them."""
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
        w.writerow(["id", "ts", "level", "category", "event_type", "actor", "target", "owner_admin", "device_id", "summary", "detail_json"])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for r in rows:
            w.writerow(
                [
                    r["id"],
                    r["ts"],
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


def _principal_from_sse_headers_or_query(authorization: Optional[str], token: Optional[str]) -> Principal:
    """Browsers can't set Authorization on EventSource, so fall back to ?token=."""
    auth_header = authorization
    if not auth_header and token:
        auth_header = f"Bearer {token}"
    if not auth_header:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return require_principal(authorization=auth_header)


@app.get("/events/stream")
def events_stream(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None, description="Fallback auth for EventSource which cannot set headers"),
    min_level: Optional[str] = Query(default=None, pattern="^(debug|info|warn|error|critical)$"),
    category: Optional[str] = Query(default=None, max_length=32),
    device_id: Optional[str] = Query(default=None, min_length=2, max_length=64),
    q: Optional[str] = Query(default=None, max_length=120),
    backlog: int = Query(default=100, ge=0, le=500),
) -> StreamingResponse:
    principal = _principal_from_sse_headers_or_query(authorization, token)
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
        hello = {
            "event_type": "stream.hello",
            "level": "info",
            "category": "system",
            "ts": utc_now_iso(),
            "ts_epoch_ms": int(time.time() * 1000),
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
        "Cache-Control": "no-cache, no-store, no-transform",
        "X-Accel-Buffering": "no",  # Nginx: disable proxy buffering
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
