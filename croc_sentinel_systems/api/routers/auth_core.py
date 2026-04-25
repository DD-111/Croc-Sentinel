"""Auth core: login, csrf, logout (Phase-22 modularization).

Three foundation auth endpoints that establish / refresh / drop the
HttpOnly JWT cookie + paired CSRF double-submit token.

Routes
------
  POST /auth/login    — credentials → JWT cookie + CSRF (also runs welcome email once)
  GET  /auth/csrf     — refresh CSRF token for the current session
  POST /auth/logout   — clear JWT cookie + CSRF (no auth required)

Schema moved with the routes
----------------------------
  LoginRequest

Late-binding strategy
---------------------
Cross-feature helpers all live in app.py and are captured at import
time (early-bound — they're all defined < line ~3300, well before the
``include_router`` hook that pulls this module in):

  require_principal,
  _client_context, _check_login_ip_lockout, _record_login_failure,
  _clear_login_ip_state, _clear_login_failures,
  _set_csrf_cookie, _clear_csrf_cookie
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

import app as _app
from audit import audit_event
from config import (
    CSRF_HEADER_NAME,
    JWT_COOKIE_NAME,
    JWT_COOKIE_SAMESITE,
    JWT_COOKIE_SECURE,
    JWT_RETURN_BODY_TOKEN,
    JWT_USE_HTTPONLY_COOKIE,
)
from db import db_lock, get_conn
from email_templates import render_welcome_email
from notifier import notifier
from security import JWT_EXPIRE_S, Principal, issue_jwt, verify_password, zones_from_json

require_principal = _app.require_principal
_client_context = _app._client_context
_check_login_ip_lockout = _app._check_login_ip_lockout
_record_login_failure = _app._record_login_failure
_clear_login_ip_state = _app._clear_login_ip_state
_clear_login_failures = _app._clear_login_failures
_set_csrf_cookie = _app._set_csrf_cookie
_clear_csrf_cookie = _app._clear_csrf_cookie


logger = logging.getLogger("croc-api.routers.auth_core")

router = APIRouter(tags=["auth-core"])


# ---- Schema ----------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


# ---- Routes ----------------------------------------------------------------

@router.post("/auth/login")
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


@router.get("/auth/csrf")
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


@router.post("/auth/logout")
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
