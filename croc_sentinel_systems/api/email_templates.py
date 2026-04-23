"""
Transactional email HTML + plain text for the dashboard and auth flows.
All templates include a visible no-reply notice in the footer.
"""
from __future__ import annotations

import html
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Shared footer (no-reply) — every template must end with this block
# ---------------------------------------------------------------------------
_FOOTER_NOREPLY = (
    "<tr><td style='padding:0 28px 24px'>"
    "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
    "style='border:1px solid #e2e8f0;border-radius:10px;background:#f8fafc'>"
    "<tr><td style='padding:14px 18px;font-size:12px;color:#64748b;line-height:1.55'>"
    "<strong style='color:#475569'>No-reply notice</strong><br/>"
    "This message was sent from an <strong>automated no-reply system</strong>. "
    "Please do not reply to this email — responses are not monitored."
    "</td></tr></table>"
    "<p style='margin:16px 0 0;font-size:11px;color:#94a3b8;text-align:center'>"
    "Croc Sentinel · Fleet Security Console"
    "</p>"
    "</td></tr>"
)


def _wrap_email(inner_rows_html: str, *, preheader: str = "") -> str:
    ph = (
        f"<div style='display:none;font-size:1px;color:#f5f7fb;line-height:1px;max-height:0;overflow:hidden'>"
        f"{html.escape(preheader)}</div>"
    )
    return (
        ph
        + "<div style='margin:0;padding:0;background:#f1f5f9;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='background:#f1f5f9;padding:32px 12px'>"
        "<tr><td align='center'>"
        "<table role='presentation' width='600' cellpadding='0' cellspacing='0' "
        "style='max-width:600px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;"
        "box-shadow:0 25px 50px -12px rgba(15,23,42,0.12);border:1px solid #e2e8f0'>"
        + inner_rows_html
        + _FOOTER_NOREPLY
        + "</table></td></tr></table></div>"
    )


def render_otp_email(
    *,
    purpose: str,
    code: str,
    ttl_min: int,
    subject_prefix: str,
) -> Tuple[str, str, str]:
    """signup | activate | reset — distinct visual themes."""
    code_esc = html.escape(str(code or "").strip().upper())
    ttl = max(1, int(ttl_min))
    sp = (subject_prefix or "[Sentinel]").strip()

    if purpose == "signup":
        subject = f"{sp} Complete your registration — verification code"
        headline = "Verify your email"
        sub = "You're almost inside Croc Sentinel. Enter this code to finish creating your administrator account."
        accent = "#4f46e5"
        badge = "Registration"
        hero_icon = "◆"
        plain = (
            f"Croc Sentinel — {headline}\n\n"
            f"{sub}\n\n"
            f"Your code: {code_esc}\n"
            f"Valid for {ttl} minutes.\n\n"
            f"This is an automated no-reply message.\n"
        )
        inner = (
            f"<tr><td style='background:linear-gradient(135deg,#312e81 0%,{accent} 55%,#6366f1 100%);padding:28px 28px 32px'>"
            f"<div style='font-size:11px;font-weight:700;letter-spacing:.2em;color:rgba(255,255,255,.85)'>{badge.upper()}</div>"
            f"<div style='margin-top:10px;font-size:42px;line-height:1;color:rgba(255,255,255,.35)'>{hero_icon}</div>"
            f"<h1 style='margin:12px 0 8px;font-size:26px;font-weight:700;color:#ffffff;letter-spacing:-0.02em'>{headline}</h1>"
            f"<p style='margin:0;font-size:15px;line-height:1.55;color:rgba(255,255,255,.92);max-width:460px'>{sub}</p>"
            "</td></tr>"
            "<tr><td style='padding:28px'>"
            "<div style='text-align:center;padding:28px 20px;border:2px dashed #c7d2fe;border-radius:14px;background:linear-gradient(180deg,#eef2ff 0%,#ffffff 100%)'>"
            "<div style='font-size:11px;font-weight:700;letter-spacing:.14em;color:#64748b;text-transform:uppercase'>One-time code</div>"
            f"<div style='margin-top:12px;font-size:38px;font-weight:800;letter-spacing:.35em;color:#1e1b4b;font-family:Consolas,ui-monospace,monospace'>{code_esc}</div>"
            f"<div style='margin-top:14px;font-size:13px;color:#475569'>Expires in <strong>{ttl}</strong> minutes</div>"
            "</div>"
            "<p style='margin:22px 0 0;font-size:13px;color:#64748b;line-height:1.65'>"
            "If you did not start registration, you can safely ignore this message."
            "</p>"
            "</td></tr>"
        )

    elif purpose == "activate":
        subject = f"{sp} Activate your account — verification code"
        headline = "Activate your workspace access"
        sub = "Your administrator invited you to Croc Sentinel. Confirm your email with the code below to unlock your account."
        accent = "#059669"
        badge = "Activation"
        hero_icon = "✓"
        plain = (
            f"Croc Sentinel — {headline}\n\n"
            f"{sub}\n\n"
            f"Your code: {code_esc}\n"
            f"Valid for {ttl} minutes.\n\n"
            "Automated no-reply — do not reply.\n"
        )
        inner = (
            f"<tr><td style='background:linear-gradient(135deg,#064e3b 0%,{accent} 45%,#34d399 100%);padding:28px 28px 32px'>"
            f"<div style='font-size:11px;font-weight:700;letter-spacing:.2em;color:rgba(255,255,255,.85)'>{badge.upper()}</div>"
            f"<div style='margin-top:8px;font-size:40px;line-height:1;color:rgba(255,255,255,.4)'>{hero_icon}</div>"
            f"<h1 style='margin:14px 0 8px;font-size:26px;font-weight:700;color:#ffffff'>{headline}</h1>"
            f"<p style='margin:0;font-size:15px;line-height:1.55;color:rgba(255,255,255,.93)'>{sub}</p>"
            "</td></tr>"
            "<tr><td style='padding:28px'>"
            "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='border-radius:14px;overflow:hidden;border:1px solid #a7f3d0'>"
            "<tr><td style='background:#ecfdf5;padding:26px 20px;text-align:center'>"
            "<div style='font-size:11px;font-weight:700;letter-spacing:.12em;color:#047857;text-transform:uppercase'>Activation code</div>"
            f"<div style='margin-top:10px;font-size:36px;font-weight:800;letter-spacing:.28em;color:#065f46;font-family:Consolas,ui-monospace,monospace'>{code_esc}</div>"
            f"<div style='margin-top:12px;font-size:13px;color:#047857'>Valid for <strong>{ttl}</strong> minutes</div>"
            "</td></tr></table>"
            "<p style='margin:20px 0 0;font-size:13px;color:#64748b;line-height:1.65'>"
            "Didn't expect this email? Ignore it — your account will stay unchanged."
            "</p>"
            "</td></tr>"
        )

    else:  # reset
        subject = f"{sp} Password reset verification"
        headline = "Secure password reset"
        sub = "We received a request to reset your password. Use this verification code to choose a new password."
        badge = "Security"
        hero_icon = "⚑"
        plain = (
            f"Croc Sentinel — {headline}\n\n"
            f"{sub}\n\n"
            f"Your code: {code_esc}\n"
            f"Valid for {ttl} minutes.\n\n"
            "If you didn't request a reset, ignore this email.\n"
            "(Automated no-reply)\n"
        )
        inner = (
            "<tr><td style='background:linear-gradient(135deg,#1e293b 0%,#475569 40%,#be123c 95%);padding:28px 28px 32px'>"
            f"<div style='font-size:11px;font-weight:700;letter-spacing:.2em;color:rgba(255,255,255,.85)'>{badge.upper()}</div>"
            f"<div style='margin-top:8px;font-size:38px;line-height:1;color:rgba(255,255,255,.35)'>{hero_icon}</div>"
            f"<h1 style='margin:12px 0 8px;font-size:26px;font-weight:700;color:#ffffff'>{headline}</h1>"
            f"<p style='margin:0;font-size:15px;line-height:1.55;color:rgba(255,255,255,.92)'>{sub}</p>"
            "</td></tr>"
            "<tr><td style='padding:28px'>"
            "<div style='border-radius:14px;background:#fff1f2;border:1px solid #fecdd3;padding:24px 18px;text-align:center'>"
            "<div style='font-size:11px;font-weight:700;letter-spacing:.12em;color:#be123c;text-transform:uppercase'>Verification code</div>"
            f"<div style='margin-top:10px;font-size:36px;font-weight:800;letter-spacing:.25em;color:#9f1239;font-family:Consolas,ui-monospace,monospace'>{code_esc}</div>"
            f"<div style='margin-top:12px;font-size:13px;color:#881337'>Expires in <strong>{ttl}</strong> minutes</div>"
            "</div>"
            "<p style='margin:20px 0 0;font-size:13px;color:#64748b;line-height:1.65'>"
            "<strong>Tip:</strong> Croc Sentinel staff will never ask you for this code by phone or chat."
            "</p>"
            "</td></tr>"
        )

    body_html = _wrap_email(inner, preheader=sub[:120])
    return subject, plain, body_html


def render_smtp_test_email(*, actor_username: str, iso_ts: str, subject_override: Optional[str]) -> Tuple[str, str, str]:
    """Admin mail channel connectivity test — diagnostic look."""
    ov = (subject_override or "").strip()
    subj = ov if ov else f"[Croc Sentinel] Mail channel test · {actor_username}"
    plain = (
        "Croc Sentinel — Mail channel diagnostic\n\n"
        f"This test message was sent by dashboard user: {actor_username}\n"
        f"Malaysia time (UTC+08:00): {iso_ts}\n\n"
        "If you can read this, SMTP configuration is working.\n\n"
        "(Automated no-reply)\n"
    )
    actor_e = html.escape(actor_username)
    ts_e = html.escape(iso_ts)
    inner = (
        "<tr><td style='background:linear-gradient(135deg,#581c87 0%,#7c3aed 50%,#a78bfa 100%);padding:26px 28px'>"
        "<div style='font-size:11px;font-weight:700;letter-spacing:.18em;color:rgba(255,255,255,.88)'>CHANNEL TEST</div>"
        "<h1 style='margin:10px 0 6px;font-size:24px;font-weight:700;color:#ffffff'>Delivery verified</h1>"
        "<p style='margin:0;font-size:14px;line-height:1.55;color:rgba(255,255,255,.92)'>"
        "Your SMTP integration successfully delivered this diagnostic message."
        "</p>"
        "</td></tr>"
        "<tr><td style='padding:26px 28px'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        "style='background:#faf5ff;border-radius:12px;border:1px solid #e9d5ff'>"
        "<tr><td style='padding:18px 20px;font-size:13px;color:#5b21b6'>"
        "<strong>Triggered by</strong><br/>"
        f"<span style='font-family:ui-monospace,Consolas,monospace;font-size:14px;color:#4c1d95'>{actor_e}</span>"
        "</td></tr>"
        "<tr><td style='padding:0 20px 18px;font-size:12px;color:#7e22ce'>"
        f"<strong>Timestamp (Malaysia UTC+08)</strong><br/><span style='font-family:ui-monospace,Consolas,monospace'>{ts_e}</span>"
        "</td></tr></table>"
        "<p style='margin:18px 0 0;font-size:13px;color:#64748b;line-height:1.65'>"
        "Use this check after changing <span style='font-family:monospace;font-size:12px'>SMTP_*</span> "
        "environment variables — no device data is transmitted in this email."
        "</p>"
        "</td></tr>"
    )
    return subj.strip(), plain, _wrap_email(inner, preheader="SMTP test delivery confirmed")


def render_welcome_email(*, username: str, role: str) -> Tuple[str, str, str]:
    """First-login welcome — executive brief style."""
    role_labels = {"admin": "Administrator", "user": "Operator", "superadmin": "Super administrator"}
    rl = role_labels.get(role, role)
    ue = html.escape(username)
    plain = (
        "Welcome to Croc Sentinel\n\n"
        f"Hello {username},\n\n"
        f"You're signed in as {rl}. The fleet console is ready.\n\n"
        "— Automated welcome (no-reply)\n"
    )
    inner = (
        "<tr><td style='background:linear-gradient(135deg,#0f172a 0%,#1e3a8a 48%,#2563eb 100%);padding:32px 28px 36px'>"
        "<div style='font-size:12px;font-weight:600;letter-spacing:.25em;color:rgba(255,255,255,.75)'>WELCOME</div>"
        "<h1 style='margin:12px 0 10px;font-size:28px;font-weight:800;color:#ffffff;letter-spacing:-0.03em'>You're in.</h1>"
        "<p style='margin:0;font-size:16px;line-height:1.6;color:rgba(255,255,255,.94)'>"
        "Your Croc Sentinel workspace is live — monitor devices, alerts, and fleet health from one console."
        "</p>"
        "</td></tr>"
        "<tr><td style='padding:28px'>"
        "<div style='border-left:4px solid #2563eb;padding:16px 18px;background:#eff6ff;border-radius:0 12px 12px 0'>"
        f"<div style='font-size:12px;color:#1d4ed8;font-weight:700;text-transform:uppercase;letter-spacing:.06em'>Account</div>"
        f"<div style='margin-top:6px;font-size:18px;font-weight:700;color:#0f172a;font-family:ui-monospace,Consolas,monospace'>{ue}</div>"
        f"<div style='margin-top:8px;font-size:14px;color:#475569'>Role: <strong>{html.escape(rl)}</strong></div>"
        "</div>"
        "<ul style='margin:22px 0 0;padding-left:20px;color:#334155;font-size:14px;line-height:1.8'>"
        "<li>Review the <strong>Overview</strong> dashboard for fleet status</li>"
        "<li>Configure notifications under <strong>Admin</strong> when you're ready</li>"
        "<li>Keep this email for your records — support links live inside the app</li>"
        "</ul>"
        "</td></tr>"
    )
    subject = "[Croc Sentinel] Welcome — your workspace is ready"
    return subject, plain, _wrap_email(inner, preheader=f"Welcome {username}")


def render_password_changed_email(*, username: str, iso_ts: str) -> Tuple[str, str, str]:
    """Password successfully changed — reassurance + security tone."""
    ue = html.escape(username)
    ts_e = html.escape(iso_ts)
    plain = (
        "Croc Sentinel — Password changed\n\n"
        f"Hello {username},\n\n"
        f"The password for your account was changed at {iso_ts} (Malaysia UTC+08).\n\n"
        "If you did not make this change, contact your administrator immediately.\n\n"
        "(Automated no-reply)\n"
    )
    inner = (
        "<tr><td style='background:linear-gradient(135deg,#14532d 0%,#166534 40%,#22c55e 100%);padding:28px 28px'>"
        "<div style='font-size:11px;font-weight:700;letter-spacing:.2em;color:rgba(255,255,255,.85)'>SECURITY</div>"
        "<h1 style='margin:10px 0 8px;font-size:24px;font-weight:700;color:#ffffff'>Password updated</h1>"
        "<p style='margin:0;font-size:15px;line-height:1.55;color:rgba(255,255,255,.93)'>"
        "Your account password was changed successfully."
        "</p>"
        "</td></tr>"
        "<tr><td style='padding:28px'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='border-radius:12px;border:1px solid #bbf7d0;background:#f0fdf4'>"
        "<tr><td style='padding:18px 20px'>"
        f"<div style='font-size:12px;color:#166534;font-weight:700'>Account</div>"
        f"<div style='font-size:16px;font-weight:700;color:#14532d;font-family:ui-monospace,Consolas,monospace;margin-top:4px'>{ue}</div>"
        f"<div style='margin-top:12px;font-size:12px;color:#15803d'><strong>When</strong> · {ts_e}</div>"
        "</td></tr></table>"
        "<p style='margin:20px 0 0;font-size:13px;color:#64748b;line-height:1.65'>"
        "<strong>Not you?</strong> Your credentials may be compromised — reset your password from the sign-in page "
        "and notify your organization."
        "</p>"
        "</td></tr>"
    )
    subject = "[Croc Sentinel] Your password was changed"
    return subject, plain, _wrap_email(inner, preheader="Password change confirmation")
