# Croc Sentinel Systems (Ubuntu Server Part)

This folder contains a production-oriented server stack for your ESP32 fleet:

- MQTT broker (Mosquitto)
- OTA firmware file hosting (Nginx)
- Dashboard API service (FastAPI + SQLite + MQTT subscriber/publisher)

## 1) Quick start on Ubuntu VPS

### 1.1 Install Docker + Compose plugin

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 1.2 Copy this folder to VPS and configure

```bash
cp .env.example .env
```

Edit `.env` and set:

- `MQTT_USERNAME`, `MQTT_PASSWORD`
- `BOOTSTRAP_MQTT_USERNAME`, `BOOTSTRAP_MQTT_PASSWORD`
- `CMD_AUTH_KEY` (must match ESP32 `config.h`)
- `BOOTSTRAP_BIND_KEY` (must match ESP32 `config.h`)
- `OTA_TOKEN` (must match ESP32 `config.h`)
- `API_TOKEN` (dashboard backend auth token)

Production guard is strict:
- API will refuse startup if key/token/host still looks like placeholder.
- Keep `CLAIM_RESPONSE_INCLUDE_SECRETS=0` in production.

### 1.3 Create Mosquitto password file

```bash
cd mosquitto
set -a
source ../.env
set +a
docker run --rm -it -v "$PWD:/mosquitto" eclipse-mosquitto:2 \
  mosquitto_passwd -b /mosquitto/passwd "${MQTT_USERNAME}" "${MQTT_PASSWORD}"
docker run --rm -it -v "$PWD:/mosquitto" eclipse-mosquitto:2 \
  mosquitto_passwd -b /mosquitto/passwd "${BOOTSTRAP_MQTT_USERNAME}" "${BOOTSTRAP_MQTT_PASSWORD}"
cd ..
```

### 1.4 Put OTA binaries

Place firmware files under:

```text
./firmware/
```

Example:

```text
firmware/sentinel-v2.1.0.bin
```

### 1.4.1 Put MQTT TLS certs

Create and place certificate files in:

```text
./certs/ca.crt
./certs/server.crt
./certs/server.key
```

Reference commands: `certs/README.md`

### 1.5 Start services

```bash
docker compose up -d --build
docker compose ps
```

## 2) Service map

- MQTT broker (TLS): `tls://<your-vps>:8883`
- OTA file URL: `http://<your-vps>:8070/fw/<firmware>.bin?token=<OTA_TOKEN>`
- API base: `http://<your-vps>:8088`
- **Dashboard (static UI):** `http://<your-vps>:8088/dashboard/` (device cards, alerts page 2, activate/claim helper)

Auth: legacy `Authorization: Bearer <API_TOKEN>` (superadmin) **or** `POST /auth/login` JWT.  
RBAC + backup details: `docs/DASHBOARD_RBAC_BACKUP_SPEC.md`.

## 3) API auth

Every API request must include:

```text
Authorization: Bearer <API_TOKEN>
```

## 4) Main API endpoints

- `GET /health`
- `GET /devices`
- `GET /devices/{device_id}`
- `GET /devices/{device_id}/messages?channel=status&limit=50`
- `POST /devices/{device_id}/commands`
- `POST /commands/broadcast`
- `GET /provision/pending`
- `POST /provision/claim`
- `GET /dashboard/overview`
- `POST /devices/{device_id}/alert/on`
- `POST /devices/{device_id}/alert/off`
- `POST /alerts` (all / multi / single)
- `POST /devices/{device_id}/self-test`
- `POST /devices/{device_id}/schedule-reboot`
- `GET /devices/{device_id}/scheduled-jobs`
- `GET /logs/messages`
- `GET /logs/file`

## 4.1 API quick test

```bash
curl -H "Authorization: Bearer CHANGE_ME_API_BEARER_TOKEN" \
  http://127.0.0.1:8088/health
```

## 5) Command payload examples

### 5.1 Device command

`POST /devices/{device_id}/commands`

```json
{
  "cmd": "get_info",
  "params": {},
  "proto": 2
}
```

### 5.2 Broadcast command (all devices)

`POST /commands/broadcast`

```json
{
  "cmd": "ota",
  "params": {
    "url": "http://your.vps.domain:8070/fw/sentinel-v2.1.0.bin",
    "fw": "2.1.0"
  },
  "target_id": "all",
  "proto": 2
}
```

### 5.3 Claim a new device (dashboard bind flow)

`GET /provision/pending` to list waiting devices, then claim:

`POST /provision/claim`

```json
{
  "mac_nocolon": "A1B2C3D4E5F6",
  "device_id": "gate-01",
  "zone": "north",
  "qr_code": "SITEA-GATE01"
}
```

After claim, server publishes bootstrap assignment and device restarts with new credentials.

### 5.4 Trigger red alert / cancel

```bash
curl -X POST -H "Authorization: Bearer <API_TOKEN>" \
  "http://127.0.0.1:8088/devices/gate-01/alert/on?duration_ms=10000"
curl -X POST -H "Authorization: Bearer <API_TOKEN>" \
  "http://127.0.0.1:8088/devices/gate-01/alert/off"
```

### 5.4.1 Trigger alert by scope (all / multi / single)

`POST /alerts`

All devices:

```json
{
  "action": "on",
  "duration_ms": 10000,
  "device_ids": []
}
```

Multiple devices:

```json
{
  "action": "on",
  "duration_ms": 10000,
  "device_ids": ["gate-01", "gate-02", "gate-03"]
}
```

Single device (same API):

```json
{
  "action": "off",
  "device_ids": ["gate-01"]
}
```

### 5.5 Schedule reboot

```bash
curl -X POST -H "Authorization: Bearer <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"delay_s":120}' \
  http://127.0.0.1:8088/devices/gate-01/schedule-reboot
```

## 5.6 Notes about claimed device credentials

- By default (`PROVISION_USE_SHARED_MQTT_CREDS=1`), claimed devices use shared MQTT creds from `.env`.
- This avoids claim success but MQTT reconnect failure when broker user provisioning is not automated.
- If you set `PROVISION_USE_SHARED_MQTT_CREDS=0`, you must provision generated users/passwords into Mosquitto externally.

## 5.7 Firmware CA rotation strategy (dual CA transition)

In `config.h`:

- `MQTT_CA_CERT_PRIMARY_PEM` = current CA
- `MQTT_CA_CERT_SECONDARY_PEM` = next CA during migration

Firmware behavior:

1. Start with primary CA
2. If TLS connect fails, fallback to secondary
3. If secondary fails later, fallback to primary again

Recommended rollout:

1. Add next CA as secondary on all devices
2. Rotate broker cert to new CA
3. Verify stable connectivity
4. Promote new CA to primary and clear secondary in next firmware release

## 6) Recommended firewall rules

Open only needed ports:

- `8883/tcp` MQTT TLS
- `8070/tcp` OTA file serving
- `8088/tcp` API

Example (UFW):

```bash
sudo ufw allow 8883/tcp
sudo ufw allow 8070/tcp
sudo ufw allow 8088/tcp
sudo ufw enable
```

## 7) Production readiness checklist

Use `PRODUCTION_READINESS_CHECKLIST.md` as a release gate.

## 8) Docker smoke test on VPS

After services are up:

```bash
chmod +x scripts/prod-smoke-test.sh
API_TOKEN='<your_api_token>' ./scripts/prod-smoke-test.sh
```
