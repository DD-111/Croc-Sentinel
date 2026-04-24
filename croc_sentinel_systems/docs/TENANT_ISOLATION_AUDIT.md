# Tenant Isolation Audit — Croc Sentinel API

_Date: 2026-04-24_
_Scope: every `@app.get/post/put/patch/delete` in `croc_sentinel_systems/api/app.py`._

## Summary

- **Total endpoints reviewed:** 100
- **Severity counts:** HIGH: 0 · MED: 2 · LOW: 9 · OK: 89
- **Top risk items (now fixed, see notes):**
  1. `GET /ota/campaigns` — missing `assert_min_role`. User-role sub-accounts could read campaign metadata when `target_admins` contains `*`. **Fixed:** role >= admin required.
  2. `GET /ota/campaigns/{campaign_id}` — same gap. **Fixed:** role >= admin required.
  3. `GET /ota/firmware-reachability` — user-role + `can_send_command` can trigger server-side HTTP probes (asset / timing side-channel, not data leak). **Left as-is** (capability gated; can revisit).
  4. `GET /admin/presence-probes` — superadmin global view by design (documented).
  5. `GET /health` — intentionally unauthenticated; toggled detail via `HEALTH_PUBLIC_DETAIL`.

## Role gates used

- `require_principal` — JWT/cookie → `Principal`
- `assert_min_role(principal, role)` — ladder: user < admin < superadmin
- `assert_device_view_access` / `assert_device_operate_access` / `assert_device_owner` (alias for operate)
- `assert_zone_for_device(principal, zone)`
- `zone_sql_suffix(principal, col)` + `owner_scope_clause_for_device_state(principal, alias)` — SQL WHERE builders
- `_device_access_flags(principal, device_id)` — returns `(can_view, can_operate)`
- `_principal_tenant_owns_device`, `_group_devices_with_owner`, `_alarm_scope_for`, `_event_scope_sql`

## Findings

| Path | Method | Role gate | Device/zone scope | Severity | Note |
|------|--------|-----------|-------------------|----------|------|
| `/` | GET | none | n/a | OK | Public redirect. |
| `/ui`, `/ui/`, `/dashboard`, `/dashboard/` | GET | none | n/a | OK | Public redirect. |
| `/ui/{path:path}` | GET | none | n/a | OK | Public redirect. |
| `/auth/signup/start` | POST | public (env-gated) | n/a | OK | Writes new admin row. |
| `/auth/signup/verify` | POST | public | n/a | OK | OTP bind. |
| `/auth/activate`, `/auth/code/resend` | POST | public | n/a | OK | Activation flows. |
| `/auth/signup/pending` | GET | `assert_min_role(superadmin)` | n/a | OK | |
| `/auth/signup/approve/{username}` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/auth/signup/reject/{username}` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/auth/forgot/*` | POST/GET | public (rate-limited) | n/a | OK | Password recovery. |
| `/auth/login` | POST | public | n/a | OK | Issues JWT. |
| `/auth/csrf` | GET | `require_principal` | n/a | OK | Refreshes CSRF pair. |
| `/auth/logout` | POST | public | n/a | OK | Clears cookies. |
| `/device/boot-sync` | POST | device MAC + `provisioned_credentials` | n/a | OK | Device auth. |
| `/device/ota/report` | POST | device MAC + `cmd_key` | n/a | OK | Device auth. |
| `/auth/me` | GET | `assert_min_role(user)` | n/a | OK | Self row only. |
| `/auth/me/fcm-token` | POST/DELETE | `assert_min_role(user)` | n/a | OK | Self-scoped. |
| `/auth/me/fcm-token/delete` | POST | `assert_min_role(user)` | n/a | OK | Body-delete alias. |
| `/auth/me/notification-prefs` | GET/PATCH | `assert_min_role(user)` | n/a | OK | |
| `/auth/me/profile` | PATCH | `assert_min_role(user)` | n/a | OK | |
| `/auth/me/password` | PATCH | `assert_min_role(user)` | n/a | OK | |
| `/auth/me` | DELETE | `assert_min_role(user)` | n/a | OK | |
| `/auth/me/delete` | POST | `assert_min_role(user)` | n/a | OK | Alias. |
| `/auth/admins` | GET | `assert_min_role(superadmin)` | n/a | OK | |
| `/auth/admins/{username}/close` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/auth/users` | GET/POST | `assert_min_role(admin)` + `can_manage_users` + scope to own tenant | n/a | OK | |
| `/auth/users/{username}` | DELETE | `assert_min_role(admin)` + per-target checks | n/a | OK | |
| `/auth/users/{username}/policy` | GET/PUT | `assert_min_role(admin)` + manager_admin check | n/a | OK | |
| `/admin/backup/export` | GET | `assert_min_role(superadmin)` + header key | n/a | OK | |
| `/admin/backup/import` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/provision/challenge/*` | POST | `assert_min_role(admin)` + `can_claim_device` | n/a | OK | |
| `/devices/revoked` | GET | `assert_min_role(admin)` + SQL owner scope | SQL-owner | OK | |
| `/devices/{device_id}/revoke` | POST | `assert_min_role(admin)` + `assert_device_owner` | operate | OK | |
| `/devices/{device_id}/unrevoke` | POST | `assert_min_role(admin)` + `assert_device_owner` | operate | OK | |
| `/devices/{device_id}/delete-reset` | POST | role + `assert_device_owner` | operate | OK | |
| `/devices/{device_id}/factory-unregister` | POST | admin+owner OR superadmin | operate (unless super) | OK | |
| `/health` | GET | public | n/a | LOW | Recon; `HEALTH_PUBLIC_DETAIL` toggles. |
| `/dashboard/overview` | GET | `assert_min_role(user)` | zone+owner SQL | OK | |
| `/devices` | GET | `assert_min_role(user)` | zone+owner SQL; `owner_admin` redacted non-super | OK | |
| `/devices/firmware-hints` | GET | `assert_min_role(user)` | zone+owner SQL | OK | |
| `/devices/{device_id}` | GET | `assert_min_role(user)` + view + zone | view+zone | OK | |
| `/devices/{device_id}/siblings-preview` | GET | view+zone+tenant-owns | full | OK | |
| `/group-cards/{group_key}` | DELETE / POST (delete alias) | `assert_min_role(admin)` + scope | owner+zone+shares | OK | |
| `/group-cards/capabilities` | GET | `assert_min_role(user)` | n/a | OK | Static map. |
| `/group-cards/settings` | GET | `assert_min_role(user)` + scope | n/a | OK | |
| `/group-cards/{group_key}/settings` | GET/PUT | `assert_min_role(user)` + owner disambiguation (super-only for `owner_admin` query) | full | OK | |
| `/group-cards/{group_key}/apply` | POST | `assert_min_role(user)` + tenant-owns + capability | full | OK | |
| `/api/group-cards/**` | * | delegates to `/group-cards/**` | — | OK | Alias. |
| `/devices/{device_id}/profile` | PATCH | `assert_device_owner` + zone | operate+zone | OK | |
| `/devices/{device_id}/display-label` | PATCH | (same) | (same) | OK | |
| `/devices/bulk/profile` | POST | `assert_min_role(user)` + per-id owner | operate | OK | |
| `/admin/devices/{device_id}/shares` | GET | admin + owner (or super) | full | OK | |
| `/admin/shares` | GET | admin + own rows | SQL-owner | OK | |
| `/admin/devices/{device_id}/share` | POST | admin + owner + grantee rules | full | OK | |
| `/admin/devices/{device_id}/share/{grantee}` | DELETE | admin + grantee rules; super: any | full (unless super) | OK | |
| `/devices/{device_id}/messages` | GET | `assert_min_role(user)` + view + zone | view+zone | OK | |
| `/provision/pending` | GET | `assert_min_role(admin)` + super-only filter | n/a | OK | |
| `/provision/claim` | POST | `assert_min_role(admin)` + `can_claim_device` | assigns owner=principal | OK | |
| `/audit` | GET | `assert_min_role(admin)` + row filter for admin | n/a | OK | |
| `/logs/messages` | GET | `assert_min_role(user)` + zone+owner SQL; device_id → view+zone | full | OK | |
| `/logs/file` | GET | `assert_min_role(superadmin)` | n/a | OK | Server log. |
| `/devices/{device_id}/commands` | POST | `assert_device_command_actor` (→ operate + capability + revoke + zone) | full | OK | |
| `/devices/{device_id}/trigger-policy` | GET/PUT | operate + zone + tenant-owns | full | OK | |
| `/devices/{device_id}/provision/wifi-task` | POST | command actor + zone | full | OK | |
| `/devices/{device_id}/provision/wifi-task/{task_id}` | GET | operate + zone | full | OK | |
| `/devices/{device_id}/alert/on` | POST | user + `can_alert` + siren access + zone + revoke | full | OK | |
| `/devices/{device_id}/alert/off` | POST | (same) | full | OK | |
| `/alerts` | POST | user + `can_alert` + `resolve_target_devices` (SQL-scoped) | zone+owner | OK | |
| `/devices/{device_id}/self-test` | POST | command actor + zone | full | OK | |
| `/devices/{device_id}/schedule-reboot` | POST | command actor + zone | full | OK | |
| `/devices/{device_id}/scheduled-jobs` | GET | command actor + zone | full | OK | |
| `/commands/broadcast` | POST | admin + capability + zone + owner SQL | full | OK | |
| `/alarms` | GET | `assert_min_role(user)` + `_alarm_scope_for` | scoped | OK | |
| `/alarms/summary` | GET | (same) | scoped | OK | |
| `/activity/signals` | GET | (same) + owner redaction | scoped | OK | |
| `/admin/alert-recipients` | GET | user scope (manager) + super = global | full | OK | |
| `/admin/alert-recipients` | POST | admin + `for_admin` super-only | full | OK | |
| `/admin/alert-recipients/{rid}` | PATCH/DELETE | admin + row owner (unless super) | full | OK | |
| `/admin/smtp/status` | GET | `assert_min_role(admin)` | n/a | OK | |
| `/admin/smtp/test` | POST | `assert_min_role(admin)` | n/a | LOW | Tenant SMTP abuse if creds valid. |
| `/admin/telegram/status` | GET | `assert_min_role(admin)` | n/a | OK | |
| `/admin/fcm/status` | GET | `assert_min_role(admin)` | n/a | OK | |
| `/admin/telegram/test` | POST | `assert_min_role(admin)` | n/a | OK | |
| `/admin/telegram/webhook-info` | GET | `assert_min_role(admin)` | n/a | OK | |
| `/telegram/link-token` | POST | `assert_min_role(user)` | n/a | OK | Self-scoped. |
| `/admin/telegram/bind-self` | POST | `assert_min_role(user)` | n/a | OK | Self. |
| `/admin/telegram/bindings` | GET | user scope; super=global | n/a | LOW | Operational by design. |
| `/admin/telegram/bindings/{chat_id}` | DELETE | user scope; super=any | n/a | LOW | By design. |
| `/admin/telegram/bindings/{chat_id}/enabled` | PATCH | (same) | n/a | LOW | By design. |
| `/integrations/telegram/webhook` | POST | `TELEGRAM_COMMAND_SECRET` | n/a | OK | Bot-side auth. |
| `/ota/service-check` | GET | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/firmware-reachability` | GET | `assert_min_role(user)` + `can_send_command` | n/a | LOW | Asset/timing side-channel. |
| `/ota/firmwares` | GET | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/firmware-verify` | GET | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/broadcast` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/firmware/upload` | POST | `assert_min_role(superadmin)` + upload password | n/a | OK | |
| `/ota/campaigns/from-stored` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/campaigns` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/campaigns/from-upload` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/ota/campaigns` | GET | **FIXED** → `assert_min_role(admin)` | n/a | was MED → OK | Sub-users no longer see fleet campaigns. |
| `/ota/campaigns/{campaign_id}` | GET | **FIXED** → `assert_min_role(admin)` | n/a | was MED → OK | Same. |
| `/ota/campaigns/{campaign_id}/accept` | POST | admin + in target + URL verify + own devices | full | OK | |
| `/ota/campaigns/{campaign_id}/decline` | POST | admin + in target | n/a | OK | |
| `/ota/campaigns/{campaign_id}/rollback` | POST | admin; super fans all | n/a | OK | |
| `/admin/presence-probes` | GET | `assert_min_role(admin)` + owner filter (admin) | scoped | LOW | Super=global by design. |
| `/events` | GET | `require_principal` + `_event_scope_sql` | scoped | OK | |
| `/events/export.csv` | GET | (same) | scoped | OK | |
| `/events/stats/by-device` | GET | (same) | scoped | OK | |
| `/events/categories` | GET | `assert_min_role(user)` | n/a | OK | |
| `/events/stream` | GET | custom principal + user | scoped | OK | SSE. |
| `/diag/db-ping` | GET | `assert_min_role(admin)` | n/a | OK | |
| `/factory/devices` | POST | `_require_factory_auth` | n/a | OK | |
| `/factory/ping` | GET | `_require_factory_auth` | n/a | OK | |
| `/factory/devices` | GET | `assert_min_role(superadmin)` (JWT only) | n/a | LOW | Factory scripts can only LIST via JWT. |
| `/factory/devices/{serial}/block` | POST | `assert_min_role(superadmin)` | n/a | OK | |
| `/provision/identify` | POST | `assert_min_role(admin)` + `can_claim_device` | owner hidden unless super | OK | |

## Action taken in this pass

- [x] Added `assert_min_role(principal, "admin")` to both `GET /ota/campaigns` and `GET /ota/campaigns/{campaign_id}`.
- [x] Saved this report.

## Deferred / intentional

- `GET /health` remains public (needed by load balancers). `HEALTH_PUBLIC_DETAIL=0` (default) keeps detail terse.
- `GET /ota/firmware-reachability` — stays user-role + capability gated; consider admin-only if abuse seen.
- Superadmin global-view endpoints (`/admin/telegram/bindings`, `/admin/presence-probes`) are by design — superadmin needs fleet-wide visibility.
- `POST /admin/smtp/test` allows arbitrary `to`; admins have SMTP creds configured by their org, so abuse is self-limited.
