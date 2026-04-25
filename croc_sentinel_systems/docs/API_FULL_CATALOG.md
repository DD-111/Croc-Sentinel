# Croc Sentinel API Full Catalog

This file consolidates both:
- Backend API routes (`api/app.py`)
- Frontend-in-use API calls (compiled bundle `api/dashboard/assets/app.js`, sources under `api/dashboard/src/`)

Base URL (pick what matches deployment):
- Production (Traefik): `https://<host>/api` — StripPrefix leaves FastAPI routes as `/health`, `/factory/...`, etc.
- Direct Uvicorn publish: `http://127.0.0.1:8088` or `https://<host>:8088` only if you actually expose that port (avoid public `:8088` when using Traefik on 443).

Auth:
- Most routes require `Authorization: Bearer <JWT>`
- Factory routes can use `X-Factory-Token`

---

## 1) Backend: Full Route List

### UI redirect/static helper routes
- `GET /ui`
- `GET /ui/`
- `GET /dashboard`
- `GET /dashboard/`
- `GET /ui/{path:path}`

### Auth & account
- `POST /auth/login`
- `GET /auth/me`
- `GET /auth/admins`
- `GET /auth/users`
- `POST /auth/users`
- `DELETE /auth/users/{username}`
- `GET /auth/users/{username}/policy`
- `PUT /auth/users/{username}/policy`

### Signup / activation / recovery
- `POST /auth/signup/start`
- `POST /auth/signup/verify`
- `POST /auth/activate`
- `POST /auth/code/resend`
- `GET /auth/signup/pending`
- `POST /auth/signup/approve/{username}`
- `POST /auth/signup/reject/{username}`
- `GET /auth/forgot/enabled`
- `POST /auth/forgot/start`
- `POST /auth/forgot/complete`

### Provisioning & challenge
- `POST /provision/challenge/request`
- `POST /provision/challenge/verify`
- `GET /provision/pending`
- `POST /provision/identify`
- `POST /provision/claim`

### Device revoke
- `GET /devices/revoked`
- `POST /devices/{device_id}/revoke`
- `POST /devices/{device_id}/unrevoke`

### Health & overview
- `GET /health`
- `GET /dashboard/overview`

### Device data & profile
- `GET /devices`
- `GET /devices/{device_id}`
- `PATCH /devices/{device_id}/profile`
- `PATCH /devices/{device_id}/display-label`
- `GET /devices/{device_id}/messages`

### Logs / audit / activities
- `GET /audit`
- `GET /logs/messages`
- `GET /logs/file`
- `GET /activity/signals`

### Commands / alert / test / jobs
- `POST /devices/{device_id}/commands`
- `POST /devices/{device_id}/alert/on`
- `POST /devices/{device_id}/alert/off`
- `POST /alerts`
- `POST /devices/{device_id}/self-test`
- `POST /devices/{device_id}/schedule-reboot`
- `GET /devices/{device_id}/scheduled-jobs`
- `POST /commands/broadcast`

### Alarm summary
- `GET /alarms`
- `GET /alarms/summary`

### Admin: recipients / smtp / telegram / backup / presence
- `GET /admin/alert-recipients`
- `POST /admin/alert-recipients`
- `PATCH /admin/alert-recipients/{rid}`
- `DELETE /admin/alert-recipients/{rid}`
- `GET /admin/smtp/status`
- `POST /admin/smtp/test`
- `GET /admin/telegram/status`
- `POST /admin/telegram/test`
- `GET /admin/telegram/webhook-info` (Bot API `getWebhookInfo`; debug when `/start` gets no reply)
- `POST /admin/telegram/bind-self`
- `GET /admin/telegram/bindings`
- `DELETE /admin/telegram/bindings/{chat_id}`
- `GET /admin/backup/export`
- `POST /admin/backup/import`
- `GET /admin/presence-probes`

### Telegram integration
- `POST /integrations/telegram/webhook`

### OTA
- `GET /ota/firmwares`
- `POST /ota/broadcast`
- `POST /ota/campaigns`
- `GET /ota/campaigns`
- `GET /ota/campaigns/{campaign_id}`
- `POST /ota/campaigns/{campaign_id}/accept`
- `POST /ota/campaigns/{campaign_id}/decline`
- `POST /ota/campaigns/{campaign_id}/rollback`

### Event center
- `GET /events`
- `GET /events/export.csv`
- `GET /events/stats/by-device`
- `GET /events/categories`
- `GET /events/stream`

### Factory
- `POST /factory/devices`
- `GET /factory/ping`
- `GET /factory/devices`
- `POST /factory/devices/{serial}/block`

---

## 2) Frontend-In-Use API Map

Routes called from dashboard frontend (`app.js`):

### Auth / signup / recovery (used)
- `GET /auth/me`
- `GET /auth/forgot/enabled`
- `POST /auth/forgot/start`
- `POST /auth/forgot/complete`
- `POST /auth/signup/start`
- `POST /auth/signup/verify`
- `POST /auth/code/resend`
- `POST /auth/activate`

### Dashboard / devices / claim (used)
- `GET /dashboard/overview`
- `GET /devices`
- `POST /alerts`
- `POST /provision/claim`
- `POST /provision/identify`
- `GET /provision/pending`

### Events / audit / alarm (used)
- `GET /events`
- `GET /events/stats/by-device`
- `GET /audit`
- `GET /activity/signals`
- `GET /alarms/summary`

### User/admin management (used)
- `GET /auth/admins`
- `GET /auth/users`
- `POST /auth/users`
- `GET /auth/signup/pending`

### Admin tools (used)
- `GET /admin/backup/export`
- `POST /admin/backup/import`
- `GET /admin/smtp/status`
- `GET /admin/alert-recipients`
- `POST /admin/alert-recipients`
- `POST /admin/smtp/test`
- `GET /admin/telegram/status`
- `POST /admin/telegram/test`

### OTA (used)
- `GET /ota/campaigns`
- `GET /ota/firmwares`
- `POST /ota/campaigns`

---

## 3) App Integration Notes

- For mobile app, prioritize these modules first:
  - Auth (`/auth/login`, `/auth/me`)
  - Device list/detail (`/devices`, `/devices/{id}`)
  - Alert control (`/alerts`, `/devices/{id}/alert/on|off`)
  - Event feed (`/events`, `/events/stream`)
  - OTA campaigns (`/ota/campaigns`, `/ota/firmwares`)

- For role-aware UI:
  - Call `/auth/me` first
  - Use role + policy endpoints to hide unsupported features

- For streaming:
  - `GET /events/stream` is SSE; mobile client should support reconnect/backoff

