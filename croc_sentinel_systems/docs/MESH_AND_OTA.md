# Tenant‑isolated Siren Mesh & OTA

This document describes how ESP32 devices owned by the same `admin` form a
"siren mesh" (when one is triggered, all siblings scream), how that is kept
strictly isolated across admins, and how OTA updates ride the same
ownership boundary.

All of this is implemented on the **server side** — the devices remain
dumb, which is what lets us enforce the isolation rigorously.

---

## 1. Who‑owns‑what (authoritative model)

* Every activated device has a row in `device_ownership(device_id, owner_admin, …)`.
* `owner_admin` is **always** the username of an `admin` user — never a `user`
  and never a `superadmin`.
* `users` inherit their reachable devices from `users.manager_admin`
  (i.e. "the admin I report to").
* A `superadmin` can see everything but is explicitly excluded from the
  fan‑out target set unless they also own the device.

This is the only source of truth used by:

* `/devices`, `/dashboard/overview`, `/alarms*`, `/ota/*`
* the MQTT **alarm fan‑out dispatcher** described below.

Legacy devices that pre‑date the ownership table can be allowed for admins
via `ALLOW_LEGACY_UNOWNED=1`, but **never** participate in fan‑out until
they are claimed (owner_admin is required for dispatch).

---

## 2. Wire format

### 2.1 Alarm published by a device

Topic: `sentinel/<device_id>/event`  (QoS 1, not retained)

```json
{
  "type": "alarm.trigger",
  "source_id": "SN-XXXXXXXXXXXXXXXX",
  "source_zone": "warehouse-a",
  "local_trigger": true,
  "trigger_kind": "remote_button",
  "ts": 1713300000,
  "nonce": 2839123113,
  "sig": "7f3a0b1c2d4e5f60"
}
```

* `trigger_kind` ∈ `remote_button | network | api` — answers the user's
  requirement "哪个 ESP 接收到信号 / 谁按 remote 触发 要保存".
* `sig` is HMAC‑truncated over `source_id|zone|ts|nonce` with `CMD_AUTH_KEY`
  so the server can reject forged events on a shared broker.

> **Removed:** the old `sentinel/broadcast/alarm` topic. Devices no longer
> subscribe or publish to it — the macro is still defined in
> `config.h` purely so ancient firmwares keep compiling, but nothing
> references it.

### 2.2 Fan‑out command sent by the API to each sibling

Topic: `sentinel/<sibling_device_id>/cmd`  (QoS 1)

```json
{
  "cmd": "siren_on",
  "params": { "duration_ms": 8000,
              "source_id": "SN-XXXXXXXXXXXXXXXX",
              "source_zone": "warehouse-a" },
  "target_id": "SN-YYYYYYYYYYYYYYYY",
  "id": "…", "ts": …, "nonce": …, "sig": "…"
}
```

`duration_ms` comes from `ALARM_FANOUT_DURATION_MS`
(default 8000). Each sibling enforces its own cap via the existing
`SIREN_MAX_ON_MS` safety limit in firmware.

---

## 3. Dispatcher flow (single source of truth)

```
    ┌────────── esp32 (source) ──────────┐
    │ remote button / cmd / network      │
    │ → publish sentinel/<src>/event     │
    │   (type=alarm.trigger, sig, nonce) │
    └───────────────────┬────────────────┘
                        ▼
        api.on_message("+/event") ───► _fan_out_alarm_safe()   [thread]
                        │
                        ├─ _lookup_owner_admin(src)
                        │      └── device_ownership row
                        │
                        ├─ _tenant_siblings(owner_admin)
                        │      └── all claimed & NOT revoked device_ids
                        │         where owner_admin == src's owner_admin
                        │
                        ├─ for each sibling (≤ ALARM_FANOUT_MAX_TARGETS):
                        │      publish_command("siren_on", sig'd per‑device cmd_key)
                        │
                        ├─ _insert_alarm() + _update_alarm(fanout_count, email_detail)
                        └─ notifier.enqueue(render_alarm_email(...))
                              for every row in admin_alert_recipients
                              where owner_admin == src's owner_admin AND enabled=1
```

Key invariants:

1. **Ownership is re‑checked on every event** — not cached — so revoking a
   device in the dashboard instantly removes it from every future fan‑out.
2. **Cross‑admin leakage is structurally impossible** because the SQL that
   builds the target set filters by `owner_admin = ?` with a single bound
   parameter; there is no broadcast topic subscription at all.
3. The dispatcher runs in a **dedicated thread** spawned from the MQTT
   `on_message` callback (`_fan_out_alarm_safe` → `threading.Thread`), so a
   slow notifier / SMTP burst never blocks paho‑mqtt's network loop.
4. Duplicate events (same `nonce` within a short window) collapse to one
   alarm row — the server uses `(source_id, ts, nonce)` as an idempotency
   tuple when writing to the `alarms` table.

---

## 4. Network auto‑selection on the device (AutoNetIf)

Boards come in three flavours:

| Board profile                 | `BOARD_HAS_ETH` | default `NETIF_MODE` |
| ----------------------------- | :-------------: | :------------------: |
| `wifi_generic`                | 0               | `WIFI`               |
| `prodino_esp32_eth`           | 1               | `AUTO` (ETH→WiFi)    |
| `waveshare_esp32_p4_eth`      | 1               | `ETHERNET` only\*    |

\* The ESP32‑P4 Arduino core has no WiFi radio, so AUTO collapses to
Ethernet only.

At runtime, `AutoNetIf`:

1. Brings ETH up first, waits up to `ETH_LINK_WAIT_MS` for a link and a
   DHCP lease.
2. If that fails, it drops ETH and tries WiFi (`WIFI_CONNECT_WAIT_MS`).
3. On any disconnect it retries the preferred side first before falling
   back again — the preferred side is sticky within a boot to avoid
   flapping.
4. `netIf->type()` reports `"ethernet"` or `"wifi"` to the backend via
   the status JSON, which the dashboard shows in device detail.

`status` payloads already include `tx_bps`, `rx_bps`, `rssi`, `vbat`,
`power_state`, `disconnect_reason` — the dashboard uses these both for
the overview presence breakdown and for per‑device throughput.

---

## 5. Disconnect reasons (how the UI decides "why offline")

The ESP32 publishes one of the following in `disconnect_reason` on every
status tick, and the **Last Will** message (retained on the broker) also
sets `disconnect_reason = "network_lost"`:

| Reason          | Trigger on device                                   |
| --------------- | --------------------------------------------------- |
| `none`          | Everything healthy                                  |
| `power_low`     | `vbat < rtVbatThresh` (default `VBAT_LOW_THRESHOLD`) |
| `network_lost`  | Will message fired, or ETH/WiFi link is down        |
| `signal_weak`   | `rssi > -127` and `rssi < RSSI_WEAK_DBM` on WiFi    |

`/dashboard/overview.presence` counts each bucket so the **总览** page can
render "电量过低 / 网络中断 / 信号弱 / 原因未知" totals without any
client‑side guessing.

---

## 6. OTA

### 6.1 Server endpoints

* `GET  /ota/firmwares` — lists every `*.bin` under `OTA_FIRMWARE_DIR`,
  returns `size`, `mtime`, `sha256`, and (if `OTA_PUBLIC_BASE_URL` is
  set) a ready‑to‑use `download_url = {base}/fw/{name}`.
* `POST /ota/broadcast { url, fw?, device_ids?: [] }` — dispatches an
  `ota` command to every device in the caller's ownership scope, or to
  the explicit `device_ids` subset (still scope‑checked). Audited as
  `ota.broadcast`.

### 6.2 Why the dashboard doesn't serve .bin itself

Firmware hosting is deliberately **out of band**: the API only stores
`sha256` and tells the device where to fetch the file over HTTPS. This
keeps the API container small, avoids long‑running HTTP transfers through
FastAPI, and lets you serve firmware from any CDN/S3 that honours
bearer‑token URLs.

If you run everything on a single box, `OTA_PUBLIC_BASE_URL` pointing at
your reverse proxy + a static file route is enough.

### 6.3 Device side

The existing `ota` command in `Croc Sentinel.ino` already:

* downloads over HTTPS,
* validates length / optional SHA256 (pass it via `params.sha256`),
* flips to the new partition, and
* publishes `ota_status` ACKs which the dashboard surfaces on the device
  detail page.

---

## 7. Email notifications

`notifier.py` is a stand‑alone module with its own daemon thread and a
bounded `queue.Queue` (`SMTP_QUEUE_MAX`). When the dispatcher decides a
fan‑out is legitimate it calls:

```python
notifier.enqueue(MailJob(
    to=[r.email for r in recipients],
    subject=render_alarm_email(...).subject,
    body=render_alarm_email(...).body,
))
```

`recipients` comes from `admin_alert_recipients` scoped to `owner_admin`,
so admin A's alarms never email admin B's inbox.

Operational knobs:

* `/admin/smtp/status` — shows `host`, `port`, `mode`, `sender`,
  `sent_count`, `failed_count`, `last_error`, `worker running?`.
* `/admin/smtp/test` — enqueues a test email either to a provided
  address or to every enabled recipient of the calling admin.

If `SMTP_HOST` is blank the notifier stays in a no‑op state (safe default
for local dev) — alarm rows are still written, they just show
`email_detail = "smtp disabled"` in the history view.

---

## 8. Login lockout (per IP)

`POST /auth/login` enforces a **per client IP** lockout in `login_ip_state`:

* **Tier 0:** after `LOGIN_LOCK_TIER0_FAILS` bad passwords, lock for `LOGIN_LOCK_TIER0_SECONDS` (default 5 → 60s).
* **Tier 1:** then after `LOGIN_LOCK_TIER1_FAILS` bad passwords, lock for `LOGIN_LOCK_TIER1_SECONDS` (default 3 → 180s).
* **Tier 2+:** then after `LOGIN_LOCK_TIER2_FAILS` bad passwords, lock for `LOGIN_LOCK_TIER2_SECONDS` (default 3 → 600s).

Successful login **or** successful password reset clears **`login_ip_state` for that IP**; `login_failures` rows may still be appended for audit. HTTP **429** includes a **`Retry-After`** header (seconds).

---

## 9. Minimal smoke test

```bash
# 1. seed SMTP env + restart API
echo 'SMTP_HOST=smtp.example.com' >> .env
docker compose up -d --force-recreate api

# 2. add a recipient as admin
curl -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"email":"ops@example.com","label":"ops"}' \
  https://vps/console/api/admin/alert-recipients

# 3. trigger a single device
curl -H "Authorization: Bearer $TOK" -X POST \
  https://vps/console/api/devices/SN-XXXXXXXXXXXXXXXX/alert/on

# expected:
#   - sibling devices under the SAME admin start their siren for
#     ALARM_FANOUT_DURATION_MS;
#   - /alarms shows a new row with fanout_count=N-1;
#   - ops@example.com receives the formatted alarm email.
```
