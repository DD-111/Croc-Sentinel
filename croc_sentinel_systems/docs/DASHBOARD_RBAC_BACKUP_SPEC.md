# Dashboard UI · RBAC · Backup — Specification (Croc Sentinel)

This document matches the **implemented** server behavior in `api/app.py` + static UI under `api/dashboard/`.

## 1) Dashboard UI (static SPA)

Static files live under `api/dashboard/` and are served at **`${DASHBOARD_PATH}/`** (default **`/console/`**; see `.env` `DASHBOARD_PATH`). There is a **single** `index.html`; all views are **client routes** in `assets/app.js` (hash after `#`).

| View | Example URL | Purpose |
|------|-------------|---------|
| Device grid | `${DASHBOARD_PATH}/#/overview` | Unified cards: `device_id`, online/offline (heuristic from `updated_at`), fw, chip, board, net, zone |
| Red alerts | `${DASHBOARD_PATH}/#/alerts` | Bulk `/alerts` (empty list = all devices **visible to your role**) |
| Activate | `${DASHBOARD_PATH}/#/activate` | Search pending (`GET /provision/pending?q=`), manual claim (`POST /provision/claim`) |

**QR scan in browser:** use phone camera → paste decoded string into “搜索” or MAC field. True in-app `getUserMedia` barcode decode is **not** bundled (add e.g. QuaggaJS / ZXing in a later SPA build).

**Production hardening (recommended next steps):**

- Serve dashboard only on HTTPS behind reverse proxy; add `Content-Security-Policy`.
- Do not store long-lived tokens in `localStorage` if XSS risk exists; prefer httpOnly session cookies + CSRF for a future SPA.

## 2) Backend feature inventory

### Already present (MQTT / fleet)

- MQTT ingest: heartbeat, status, event, ack, bootstrap register
- Device state upsert (`device_state`)
- Message log (`messages`) with retention cleanup
- Provision: `GET /provision/pending` (+ `q` filter), `POST /provision/claim`
- Commands: per-device, broadcast (zone-filtered for scoped admins)
- Alerts: per-device + bulk `/alerts`
- Self-test, schedule reboot + job list
- Dashboard counts `GET /dashboard/overview`
- Logs: `GET /logs/messages` (join + zone filter), `GET /logs/file` (**superadmin only**)
- Health

### New in this iteration

- **Static dashboard** (mounted at `DASHBOARD_PATH`, default `/console`)
- **JWT login** `POST /auth/login`, `GET /auth/me`
- **User CRUD** `GET|POST /auth/users`, `DELETE /auth/users/{username}` (**superadmin**)
- **RBAC** on all fleet routes (see §3)
- **Encrypted DB backup** `GET /admin/backup/export` + **import file** `POST /admin/backup/import` (**superadmin** + 64-hex encryption header)

### Still missing for “完美生产” (recommended backlog)

| Gap | Why it matters |
|-----|----------------|
| Dedicated **audit_events** table | Tamper-evident log of who called which API (today: only API file log tail) |
| **Per-device MQTT ACL** | Broker-level isolation; today shared creds mode is simpler but weaker |
| **Rate limiting / lockout** on `/auth/login` | Brute-force protection |
| **2FA (TOTP)** for superadmin | Stolen password ≠ full compromise |
| **Organization / site** hierarchy | Multi-tenant separation beyond `zone` |
| **Automated restore** without container stop | SQLite file swap while process running is unsafe; current import writes `*.restored` |
| **Redis hot state** | Optional scale-out for presence (see prior architecture note) |
| **Bundled build (e.g. Vite) + camera QR** | Smaller assets / DX; in-app `getUserMedia` decode still optional |

## 3) Roles & permissions (implemented)

**Principals:** `superadmin` · `admin` · `user` · legacy `API_TOKEN` (treated as **superadmin**).

**Zone model:** `device_state.zone`. User/admin rows carry `allowed_zones_json` (default `["*"]` = all).  
Match rule: device visible if `principal.zone_ok(zone)` — superadmin / `*` passes; else device `zone` must be in the user’s list **or** device zone is `all`/empty (fleet-wide bucket).

| Capability | superadmin | admin | user |
|------------|:----------:|:-----:|:----:|
| `/health`, `/auth/me` | ✓ | ✓ | ✓ |
| `/dashboard/overview`, `/devices`, `/devices/{id}` (read) | ✓ | ✓ (zone) | ✓ (zone) |
| `/devices/{id}/messages` | ✓ | ✓ (zone) | ✓ (zone) |
| `/logs/messages` | ✓ | ✓ (zone join) | ✓ **requires `device_id`** |
| `/logs/file` | ✓ | ✗ | ✗ |
| `/provision/pending`, `/provision/claim` | ✓ | ✓ | ✗ |
| `/devices/{id}/alert/on|off`, `/alerts` | ✓ | ✓ (zone) | ✓ (zone) |
| `/devices/{id}/commands`, `/commands/broadcast` | ✓ | ✓ (zone) | ✗ |
| `/devices/{id}/self-test`, schedule reboot, list jobs | ✓ | ✓ (zone) | ✗ |
| `/auth/users` CRUD | ✓ | ✗ | ✗ |
| `/admin/backup/export|import` | ✓ | ✗ | ✗ |

**Data-leakage controls:** scoped SQL (`zone_sql_suffix`), join on `messages`↔`device_state`, explicit **403** when `user` hits `/logs/messages` without `device_id`.

## 4) Backup / restore (64-hex encryption key)

**Export** `GET /admin/backup/export`

- Auth: `Authorization: Bearer <JWT superadmin OR legacy API_TOKEN>`
- Header: `X-Backup-Encryption-Key: <64 hexadecimal characters>` (256-bit secret; **not** stored server-side)
- Body: Fernet-encrypted SQLite file (`application/octet-stream`)

**Import** `POST /admin/backup/import`

- Same auth + same header
- Body: raw encrypted file (multipart `file` field)
- Server **decrypts**, verifies `SQLite format 3` magic, writes **`{DB_PATH}.restored`**
- **You** stop API, replace live DB with restored file, start API (atomic swap under your orchestration).

Example curl (export):

```bash
curl -fsS -o backup.enc \
  -H "Authorization: Bearer $API_TOKEN_OR_JWT" \
  -H "X-Backup-Encryption-Key: $(openssl rand -hex 32)" \
  "http://127.0.0.1:8088/admin/backup/export"
```

Keep the hex key in an **offline** password manager; losing it = cannot decrypt backup.

## 5) Bootstrap users (first deploy)

In `.env`:

- `JWT_SECRET` — **≥ 32 chars** (required when `BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD` is set, enforced by `validate_production_env`)
- `BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME` (default `superadmin`)
- `BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD` — if DB has **zero** `dashboard_users`, API seeds this **once**

Then:

1. `POST /auth/login` → JWT  
2. `POST /auth/users` create `admin` / `user` with explicit `zones`  
3. Clear bootstrap password from `.env` on next redeploy (optional hygiene)

Legacy **`API_TOKEN`** remains valid as **superadmin** for automation / smoke tests.

**If you did not set `BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD`:** the `dashboard_users` table may stay empty. In that case use **`POST /auth/users`** once with `Authorization: Bearer <API_TOKEN>` to create the first superadmin (or admin) account, then use `/auth/login` for JWT day-to-day access.
