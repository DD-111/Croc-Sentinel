import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import paho.mqtt.client as mqtt

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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
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
CACHE_TTL_SECONDS = float(os.getenv("CACHE_TTL_SECONDS", "2.0"))
MESSAGE_RETENTION_DAYS = int(os.getenv("MESSAGE_RETENTION_DAYS", "14"))
JWT_SECRET = os.getenv("JWT_SECRET", "")
BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME", "superadmin").strip()
BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD = os.getenv("BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD", "")

TOPIC_HEARTBEAT = f"{TOPIC_ROOT}/+/heartbeat"
TOPIC_STATUS = f"{TOPIC_ROOT}/+/status"
TOPIC_EVENT = f"{TOPIC_ROOT}/+/event"
TOPIC_ACK = f"{TOPIC_ROOT}/+/ack"
TOPIC_BOOTSTRAP_REGISTER = f"{TOPIC_ROOT}/bootstrap/register"


db_lock = threading.Lock()
mqtt_client: Optional[mqtt.Client] = None
mqtt_connected = False
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
    if BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD:
        if not JWT_SECRET or len(JWT_SECRET) < 32:
            errors.append("JWT_SECRET must be set (>=32 chars) when BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD is used")
    if errors:
        raise RuntimeError("Invalid production environment: " + "; ".join(errors))


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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


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
        ensure_column(conn, "device_state", "chip_target", "TEXT")
        ensure_column(conn, "device_state", "board_profile", "TEXT")
        ensure_column(conn, "device_state", "net_type", "TEXT")
        ensure_column(conn, "device_state", "provisioned", "INTEGER")
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
        conn.commit()
        conn.close()
    cache_invalidate("devices")
    cache_invalidate("overview")


def zone_sql_suffix(principal: Principal, column: str = "zone") -> tuple[str, list[Any]]:
    """Extra WHERE fragment for zone-scoped roles."""
    if principal.is_superadmin() or principal.has_all_zones():
        return "", []
    placeholders = ",".join(["?"] * len(principal.zones))
    frag = (
        f" AND ({column} IN ({placeholders}) OR IFNULL({column},'') IN ('all','')) "
    )
    return frag, list(principal.zones)


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
    global mqtt_connected
    mqtt_connected = rc == 0
    if rc == 0:
        logger.info("MQTT connected")
        client.subscribe(TOPIC_HEARTBEAT, qos=1)
        client.subscribe(TOPIC_STATUS, qos=1)
        client.subscribe(TOPIC_EVENT, qos=1)
        client.subscribe(TOPIC_ACK, qos=1)
        client.subscribe(TOPIC_BOOTSTRAP_REGISTER, qos=1)
    else:
        logger.error("MQTT connect failed rc=%s", rc)


def on_disconnect(_client: mqtt.Client, _userdata: Any, _disconnect_flags: Any, _reason_code: Any, _properties: Any = None) -> None:
    global mqtt_connected
    mqtt_connected = False
    logger.warning("MQTT disconnected")


def on_message(_client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
    topic = msg.topic

    try:
        payload = json.loads(msg.payload.decode("utf-8", errors="ignore"))
        if not isinstance(payload, dict):
            return
    except Exception:
        return

    if topic == TOPIC_BOOTSTRAP_REGISTER:
        upsert_pending_claim(payload)
        insert_message(topic, "bootstrap_register", str(payload.get("device_id", "")), payload)
        return

    device_id, channel = parse_topic(topic)
    if not channel:
        return

    insert_message(topic, channel, device_id, payload)
    if device_id:
        upsert_device_state(device_id, channel, payload)


def start_mqtt_loop() -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
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


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(pattern="^(superadmin|admin|user)$")
    zones: list[str] = Field(default_factory=lambda: ["*"])


app = FastAPI(title="Croc Sentinel API", version="1.0.0")

_dash_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")
if os.path.isdir(_dash_dir):
    app.mount("/dashboard", StaticFiles(directory=_dash_dir, html=True), name="dashboard")


@app.on_event("startup")
def startup() -> None:
    global mqtt_client, scheduler_thread
    validate_production_env()
    init_db()
    mqtt_client = start_mqtt_loop()
    scheduler_stop.clear()
    scheduler_thread = threading.Thread(target=scheduler_loop, name="cmd-scheduler", daemon=True)
    scheduler_thread.start()
    logger.info("API started mqtt_host=%s mqtt_port=%s db=%s", MQTT_HOST, MQTT_PORT, DB_PATH)


@app.on_event("shutdown")
def shutdown() -> None:
    global mqtt_client, scheduler_thread
    scheduler_stop.set()
    if scheduler_thread is not None:
        scheduler_thread.join(timeout=2.0)
        scheduler_thread = None
    if mqtt_client is not None:
        stop_mqtt_loop(mqtt_client)


@app.post("/auth/login")
def auth_login(body: LoginRequest) -> dict[str, Any]:
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM dashboard_users WHERE username = ?", (body.username,))
        row = cur.fetchone()
        conn.close()
    if not row or not verify_password(body.password, str(row["password_hash"])):
        raise HTTPException(status_code=401, detail="invalid credentials")
    zones = zones_from_json(str(row["allowed_zones_json"]))
    token = issue_jwt(str(row["username"]), str(row["role"]), zones)
    return {"access_token": token, "token_type": "bearer", "role": row["role"], "zones": zones}


@app.get("/auth/me")
def auth_me(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {"username": principal.username, "role": principal.role, "zones": principal.zones}


@app.get("/auth/users")
def auth_list_users(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, role, allowed_zones_json, created_at FROM dashboard_users ORDER BY username ASC"
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for r in rows:
        r["zones"] = zones_from_json(str(r.pop("allowed_zones_json")))
    return {"items": rows}


@app.post("/auth/users")
def auth_create_user(req: UserCreateRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    now = utc_now_iso()
    zones_json = json.dumps(req.zones, ensure_ascii=True)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO dashboard_users (username, password_hash, role, allowed_zones_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (req.username, hash_password(req.password), req.role, zones_json, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=409, detail="username exists")
        conn.close()
    cache_invalidate("devices")
    return {"ok": True, "username": req.username}


@app.delete("/auth/users/{username}")
def auth_delete_user(username: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "superadmin")
    if secrets.compare_digest(username, principal.username):
        raise HTTPException(status_code=400, detail="cannot delete self")
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))
        conn.commit()
        deleted = cur.rowcount
        conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="user not found")
    return {"ok": True}


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


@app.get("/health")
def health(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    return {
        "ok": True,
        "mqtt_connected": mqtt_connected,
        "ts": int(time.time()),
    }


@app.get("/dashboard/overview")
def dashboard_overview(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
    cache_key = "overview" if (principal.is_superadmin() or principal.has_all_zones()) else f"overview:{principal.username}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    zs, za = zone_sql_suffix(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) AS c FROM device_state WHERE 1=1 {zs}", tuple(za))
        total = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT COUNT(*) AS c FROM device_state
            WHERE last_status_json IS NOT NULL {zs}
            """,
            tuple(za),
        )
        with_status = int(cur.fetchone()["c"])
        cur.execute(
            f"""
            SELECT fw, chip_target, board_profile, net_type, COUNT(*) AS c
            FROM device_state
            WHERE 1=1 {zs}
            GROUP BY fw, chip_target, board_profile, net_type
            ORDER BY c DESC
            """,
            tuple(za),
        )
        grouped = [dict(r) for r in cur.fetchall()]
        conn.close()
    out = {
        "total_devices": total,
        "devices_with_status": with_status,
        "groups": grouped,
        "mqtt_connected": mqtt_connected,
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
    zs, za = zone_sql_suffix(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT device_id, fw, chip_target, board_profile, net_type, zone, provisioned, updated_at
            FROM device_state
            WHERE 1=1 {zs}
            ORDER BY updated_at DESC
            """,
            tuple(za),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    out = {"items": rows}
    cache_put(cache_key, out)
    return out


@app.get("/devices/{device_id}")
def get_device(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
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
    return out


@app.get("/devices/{device_id}/messages")
def get_device_messages(
    device_id: str,
    channel: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
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
    if PROVISION_USE_SHARED_MQTT_CREDS and MQTT_USERNAME:
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
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        if unique:
            placeholders = ",".join(["?"] * len(unique))
            cur.execute(
                f"SELECT device_id, zone FROM device_state WHERE device_id IN ({placeholders}){zs}",
                tuple(unique) + tuple(za),
            )
        else:
            cur.execute(f"SELECT device_id, zone FROM device_state WHERE 1=1 {zs}", tuple(za))
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

        scheduler_stop.wait(SCHEDULER_POLL_SECONDS)


@app.get("/provision/pending")
def list_pending_claims(
    principal: Principal = Depends(require_principal),
    q: Optional[str] = Query(default=None, max_length=64, description="Filter by MAC (no colon) or QR substring"),
) -> dict[str, Any]:
    assert_min_role(principal, "admin")
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
                WHERE mac_nocolon LIKE ? OR UPPER(mac) LIKE ? OR IFNULL(qr_code,'') LIKE ?
                ORDER BY last_seen_at DESC
                """,
                (like_mac, like, like),
            )
        else:
            cur.execute(
                """
                SELECT mac_nocolon, mac, qr_code, fw, claim_nonce, proposed_device_id, last_seen_at
                FROM pending_claims
                ORDER BY last_seen_at DESC
                """
            )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return {"items": rows}


@app.post("/provision/claim")
def claim_device(req: ClaimDeviceRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
    mac_nocolon = req.mac_nocolon.upper()
    if len(mac_nocolon) != 12:
        raise HTTPException(status_code=400, detail="invalid mac_nocolon")
    if not BOOTSTRAP_BIND_KEY:
        raise HTTPException(status_code=500, detail="server BOOTSTRAP_BIND_KEY not configured")

    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM pending_claims WHERE mac_nocolon = ?", (mac_nocolon,))
        pending = cur.fetchone()
        if not pending:
            conn.close()
            raise HTTPException(status_code=404, detail="pending device not found")

        claim_nonce = str(pending["claim_nonce"])
        qr_code = req.qr_code if req.qr_code else (str(pending["qr_code"] or "") or f"CROC-{mac_nocolon}")
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
    return resp


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
    query = """
        SELECT m.id, m.topic, m.channel, m.device_id, m.payload_json, m.ts_device, m.ts_received
        FROM messages m
        JOIN device_state d ON m.device_id = d.device_id
        WHERE 1=1
    """
    args: list[Any] = []
    query += zs
    args.extend(za)
    if channel:
        query += " AND m.channel = ?"
        args.append(channel)
    if device_id:
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
def send_device_command(device_id: str, req: CommandRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
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
    return {"ok": True, "topic": topic, "target_id": target}


@app.post("/devices/{device_id}/alert/on")
def device_alert_on(
    device_id: str,
    duration_ms: int = Query(default=8000, ge=500, le=120000),
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    assert_min_role(principal, "user")
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
    return {"ok": True}


@app.post("/devices/{device_id}/alert/off")
def device_alert_off(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
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
    return {"ok": True}


@app.post("/alerts")
def bulk_alert(req: BulkAlertRequest, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "user")
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

    return {
        "ok": True,
        "action": req.action,
        "sent_count": sent,
        "device_ids": targets,
    }


@app.post("/devices/{device_id}/self-test")
def device_self_test(device_id: str, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_min_role(principal, "admin")
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
    zs, za = zone_sql_suffix(principal)
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT device_id FROM device_state WHERE 1=1 {zs}", tuple(za))
        device_ids = [r["device_id"] for r in cur.fetchall()]
        conn.close()

    for did in device_ids:
        topic = f"{TOPIC_ROOT}/{did}/cmd"
        publish_command(topic, req.cmd, req.params, req.target_id, req.proto, get_cmd_key_for_device(did))

    return {"ok": True, "target_id": req.target_id, "sent_count": len(device_ids)}
