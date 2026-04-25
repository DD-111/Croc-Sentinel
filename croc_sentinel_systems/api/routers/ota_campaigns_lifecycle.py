"""OTA campaign lifecycle routes (Phase-77 split from
``routers/ota_campaigns.py``).

The Phase-65 ``ota_campaigns.py`` extract bundled three concerns:

  * Campaign creation        — POST /ota/campaigns, .../from-stored,
                               .../from-upload (3 routes, ~120 lines).
  * Campaign read views      — GET /ota/campaigns + GET /…/{id}
                               (2 routes, ~75 lines).
  * Campaign state-machine   — POST /…/{id}/accept, /decline, /rollback
                               (3 routes, ~150 lines).  ← THIS MODULE.

Phase 77 isolates the state-machine half here so creation/read can
focus on schemas + DB inserts. The lifecycle routes are
side-effect-heavy (URL re-verify, MQTT fan-out via the rollout
worker, decision-row writes, audit events, manual rollback) and
have a different mental model from "build a row".

Routes hosted here (all behind ``Depends(require_principal)``)
--------------------------------------------------------------
  POST /ota/campaigns/{campaign_id}/accept    [admin+] — start rollout
  POST /ota/campaigns/{campaign_id}/decline   [admin+] — record refusal
  POST /ota/campaigns/{campaign_id}/rollback  [admin+] — manual rollback

Why three is the right number
-----------------------------
The accept handler does the real work: it re-verifies the campaign
URL on the server (fail-closed if the binary moved/disappeared
since the campaign was created), reads the per-admin target list,
upserts ``ota_device_runs`` rows, flips ``ota_campaigns.state`` to
running, then delegates the actual MQTT fan-out to
``_start_ota_rollout_for_admin``. Decline writes a decision row
with no fan-out; rollback delegates to ``_rollback_admin_devices``
(per-admin for ``admin``, fan-out across every admin that ran the
campaign for ``superadmin``).

Late binding
------------
Captured at module load time, after ``app.py`` has executed past
these defs (identical to the parent module's late-bind list, minus
the create-only helpers we don't need here):

  Functions:
    require_principal,
    _verify_ota_url,
    _ota_campaign_targets_for_admin,
    _rollback_admin_devices,
    _start_ota_rollout_for_admin.

All five exist in app.py < line ~5300 — well before
``include_router`` for this module — so identity is preserved at
import time.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

import app as _app
from audit import audit_event
from db import db_lock, get_conn
from helpers import utc_now_iso
from security import Principal, assert_min_role

require_principal = _app.require_principal
_verify_ota_url = _app._verify_ota_url
_ota_campaign_targets_for_admin = _app._ota_campaign_targets_for_admin
_rollback_admin_devices = _app._rollback_admin_devices
_start_ota_rollout_for_admin = _app._start_ota_rollout_for_admin


logger = logging.getLogger("croc-api.routers.ota_campaigns_lifecycle")
router = APIRouter(tags=["ota-campaigns"])


# ─────────────────────────────────────────── campaigns: state machine ────


@router.post("/ota/campaigns/{campaign_id}/accept")
def accept_ota_campaign(
    campaign_id: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Admin accepts the campaign → server verifies URL then fans OTA cmd
    out to every device the admin owns.

    Sequence:
      1. Resolve the campaign row + check the admin is in
         ``target_admins_json`` (or ``["*"]``).
      2. Reject if a previous decision already says ``accepted``.
      3. Re-verify the firmware URL is reachable on the public-facing
         host (fail-closed: stops accepting a campaign whose binary
         was moved/deleted between create and accept).
      4. Resolve the per-admin target device set via
         ``_ota_campaign_targets_for_admin``. If empty, still record
         the decision so superadmin can see "this admin reacted, no
         devices to push".
      5. Upsert one ``ota_device_runs`` row per device — preserve any
         terminal state (``success``/``failed``/``rolled_back``) so a
         re-accept doesn't undo a prior outcome.
      6. Flip the campaign row to ``state='running'``.
      7. Delegate the actual MQTT fan-out to
         ``_start_ota_rollout_for_admin``; surface its dispatch count
         and the first 5 failures in the audit + response.
    """
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

    targets_rows = _ota_campaign_targets_for_admin(
        admin_username, str(camp["fw_version"]), str(camp["url"])
    )
    if not targets_rows:
        # Still mark decision as accepted so superadmin sees the admin reacted.
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
                (
                    campaign_id,
                    admin_username,
                    t["device_id"],
                    t["prev_fw"],
                    t["prev_url"],
                    str(camp["fw_version"]),
                    str(camp["url"]),
                    now_iso,
                    now_iso,
                ),
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
        cur.execute(
            "UPDATE ota_campaigns SET state='running', updated_at=? WHERE id=?",
            (now_iso, campaign_id),
        )
        conn.commit()
        conn.close()

    dispatched, failures = _start_ota_rollout_for_admin(campaign_id, admin_username)
    audit_event(
        admin_username,
        "ota.campaign.accept",
        campaign_id,
        {
            "dispatched": dispatched,
            "failures": failures[:5],
            "target_count": len(targets_rows),
            "verify": detail,
        },
    )
    return {
        "ok": True,
        "dispatched": dispatched,
        "target_count": len(targets_rows),
        "verify": detail,
        "failures": failures[:5],
    }


@router.post("/ota/campaigns/{campaign_id}/decline")
def decline_ota_campaign(
    campaign_id: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Record this admin's refusal of a campaign without dispatching.

    Decline is idempotent — re-calling overwrites the decision row
    via the ON CONFLICT clause. We never block the admin from later
    accepting a campaign they declined; that's a UX call enforced
    in the dashboard, not here.
    """
    assert_min_role(principal, "admin")
    admin_username = principal.username
    with db_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT target_admins_json FROM ota_campaigns WHERE id = ?",
            (campaign_id,),
        )
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


@router.post("/ota/campaigns/{campaign_id}/rollback")
def rollback_ota_campaign(
    campaign_id: str,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    """Explicit rollback trigger (in addition to automatic rollback on
    failure).

    Authorization model:
      * ``admin``      — rolls back only their own slice of the
                         campaign's ``ota_device_runs``.
      * ``superadmin`` — fans out a rollback across every admin that
                         participated in the campaign (computed by
                         ``SELECT DISTINCT admin_username``); useful
                         when a bad firmware was already accepted by
                         several tenants and we need to pull it
                         everywhere.

    The rollback itself is delegated to ``_rollback_admin_devices``
    so the per-device transition + cmd publish lives in one place
    (``ota_rollout.py``).
    """
    assert_min_role(principal, "admin")
    admin_username = principal.username
    if principal.role == "superadmin":
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT DISTINCT admin_username FROM ota_device_runs WHERE campaign_id = ?",
                (campaign_id,),
            )
            admins = [str(r["admin_username"]) for r in cur.fetchall()]
            conn.close()
        rolled_total = 0
        for a in admins:
            rolled_total += _rollback_admin_devices(
                campaign_id,
                a,
                reason=f"manual rollback by superadmin {principal.username}",
            )
        return {"ok": True, "rolled_back": rolled_total, "admins": admins}
    rolled = _rollback_admin_devices(
        campaign_id,
        admin_username,
        reason=f"manual rollback by admin {admin_username}",
    )
    return {"ok": True, "rolled_back": rolled}


__all__ = ("router",)
