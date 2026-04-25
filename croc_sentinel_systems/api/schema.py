"""SQLite schema bootstrap (Phase-3 modularization extract from ``app.py``).

This module owns:
  * ``CREATE TABLE IF NOT EXISTS`` statements for every persistent table.
  * Companion ``CREATE INDEX IF NOT EXISTS`` declarations for hot-path reads.
  * The ``ensure_column`` migration block that retro-fits new columns onto
    older databases (additive only — see db.ensure_column).
  * The cheap one-shot ``trigger_policies`` normalization migration.
  * The one-time bootstrap superadmin seeding (driven by
    ``BOOTSTRAP_DASHBOARD_SUPERADMIN_*``).

What is *not* here:
  * Connection management / locking → ``db.py``.
  * Pragmas (WAL, mmap_size, synchronous=NORMAL) → ``db.init_db_pragmas``.
  * Routes that consume the schema → ``app.py``.

Phase-4 follow-up: the seed-time helpers (``utc_now_iso``,
``default_policy_for_role``, ``_sibling_group_norm``) used to live in
``app.py`` and were lazy-imported inside ``init_db`` to dodge an
``app → schema → app`` cycle. They now live in ``helpers.py`` (a true
leaf module), so this file imports them at module top — no in-function
imports needed and the dependency graph stays acyclic at load time.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from config import (
    BOOTSTRAP_DASHBOARD_SUPERADMIN_PASSWORD,
    BOOTSTRAP_DASHBOARD_SUPERADMIN_USERNAME,
    DEFAULT_PANIC_FANOUT_MS,
)
from db import (
    cache_invalidate,
    db_lock,
    ensure_column,
    get_conn,
    init_db_pragmas,
)
from helpers import (
    _sibling_group_norm,
    default_policy_for_role,
    utc_now_iso,
)
from security import hash_password

logger = logging.getLogger("croc-api.schema")


def init_db() -> None:
    """Create / migrate every persistent table and seed bootstrap rows.

    Idempotent: every CREATE / ensure_column / one-shot migration uses
    ``IF NOT EXISTS`` or row-existence guards. Safe to call on every
    startup; cost on a fully-migrated DB is < 50 ms.
    """
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

        # ── cmd_queue: persistent /cmd pending queue ────────────────────────
        # Every `publish_command` call writes a row here keyed on the
        # generated ``cmd_id``. MQTT remains primary: the row is purely a
        # ledger that survives a disconnected device so we can:
        #   * Replay unacked commands via HTTP pull (firmware backup channel)
        #   * Audit delivery ("was this ACK'd?")
        #   * Re-deliver to a sibling that was offline at fan-out time when
        #     it comes back (see group offline-replay below)
        # Fields:
        #   cmd_id        — UUID matching the MQTT payload / ACK correlation
        #   device_id     — target device id (one row per target, not per command)
        #   cmd           — verb (siren_on / alarm_signal / ota_update / ...)
        #   params_json   — JSON-encoded params{}
        #   target_id     — original target_id for signed key check
        #   proto         — CMD_PROTO at publish time
        #   cmd_key       — cmd_key snapshot used by the MQTT payload
        #   created_at    — ISO UTC when enqueued
        #   expires_at    — ISO UTC when the row stops being retry-able (null = default TTL)
        #   delivered_via — 'mqtt' on initial publish; 'http' if backup pull served it
        #   delivered_at  — ISO UTC when paho reported publish accepted (or HTTP returned it)
        #   acked_at      — ISO UTC when the device ACK landed (via any channel)
        #   ack_ok        — 1/0 per ack payload
        #   ack_detail    — free-text ack reason; 'bad key' / 'unknown cmd' / ''
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cmd_queue (
                cmd_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                cmd TEXT NOT NULL,
                params_json TEXT,
                target_id TEXT,
                proto INTEGER,
                cmd_key TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                delivered_via TEXT,
                delivered_at TEXT,
                acked_at TEXT,
                ack_ok INTEGER,
                ack_detail TEXT
            )
            """
        )
        # Hot-path indexes: per-device "what is pending now" (HTTP pull and
        # group offline-replay) is the common read; acked_at IS NULL is the
        # dominant filter.
        cur.execute(
            "CREATE INDEX IF NOT EXISTS ix_cmd_queue_dev_pending "
            "ON cmd_queue(device_id, acked_at, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS ix_cmd_queue_created "
            "ON cmd_queue(created_at DESC)"
        )
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

        # One-shot migration: collapse trigger_policies rows that differ only
        # in group-string casing/whitespace so they match the sibling match
        # normalization (_sibling_group_norm). Newest updated_at wins, older
        # variants are deleted. Runs cheaply on every startup because it
        # only works on rows that would actually collide.
        try:
            cur.execute(
                "SELECT rowid, owner_admin, scope_group, updated_at "
                "FROM trigger_policies"
            )
            rows = cur.fetchall()
            buckets: dict[tuple[str, str], list[sqlite3.Row]] = {}
            for r in rows:
                key = (str(r["owner_admin"] or ""), _sibling_group_norm(str(r["scope_group"] or "")))
                buckets.setdefault(key, []).append(r)
            for (owner, norm_key), group_rows in buckets.items():
                if len(group_rows) <= 1 and (len(group_rows) == 0 or str(group_rows[0]["scope_group"] or "") == norm_key):
                    continue
                winner = max(group_rows, key=lambda x: str(x["updated_at"] or ""))
                winner_rowid = int(winner["rowid"])
                for r in group_rows:
                    if int(r["rowid"]) == winner_rowid:
                        continue
                    cur.execute("DELETE FROM trigger_policies WHERE rowid = ?", (int(r["rowid"]),))
                if str(winner["scope_group"] or "") != norm_key:
                    cur.execute(
                        "UPDATE trigger_policies SET scope_group = ? WHERE rowid = ?",
                        (norm_key, winner_rowid),
                    )
            conn.commit()
        except Exception as exc:
            logger.warning("trigger_policies normalization migration skipped: %s", exc)
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


__all__ = ["init_db"]


# Suppress "imported but unused" on Any when this module is run with a
# strict linter that doesn't see the runtime cur.execute(...) typing.
_unused_typing_marker: Any = None
