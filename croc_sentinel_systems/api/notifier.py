"""
Background SMTP notifier.

Design goals:
- Never block the MQTT on_message / HTTP request thread.
- Bounded queue; drop oldest with a logged warning on overflow.
- Single long-lived worker thread; reconnects per batch (SMTP sessions are cheap).
- Pluggable transport via env (STARTTLS, implicit TLS, or plaintext for local dev).

Environment variables (all optional; if SMTP_HOST empty → notifier is disabled):
- SMTP_HOST, SMTP_PORT (default 587)
- SMTP_USERNAME, SMTP_PASSWORD
- SMTP_FROM (falls back to SMTP_USERNAME)
- SMTP_MODE = starttls | ssl | plain  (default: starttls)
- SMTP_TIMEOUT_SECONDS (default 15)
- SMTP_QUEUE_MAX (default 500)
"""
from __future__ import annotations

import logging
import os
import queue
import smtplib
import ssl
import threading
import time
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Iterable, Optional


logger = logging.getLogger("croc-notifier")


@dataclass
class MailJob:
    to: list[str]
    subject: str
    body_text: str
    body_html: Optional[str] = None
    reply_to: Optional[str] = None


class Notifier:
    def __init__(self) -> None:
        self.host = os.getenv("SMTP_HOST", "").strip()
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.username = os.getenv("SMTP_USERNAME", "").strip()
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.sender = os.getenv("SMTP_FROM", "").strip() or self.username
        self.mode = (os.getenv("SMTP_MODE", "starttls").strip() or "starttls").lower()
        self.timeout = float(os.getenv("SMTP_TIMEOUT_SECONDS", "15"))
        self.queue_max = int(os.getenv("SMTP_QUEUE_MAX", "500"))
        self._queue: "queue.Queue[MailJob]" = queue.Queue(maxsize=self.queue_max)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._last_error: str = ""
        self._sent_count: int = 0
        self._failed_count: int = 0

    # ---------------------------------------------------------------- state
    def enabled(self) -> bool:
        return bool(self.host)

    def worker_alive(self) -> bool:
        """True if the background SMTP worker thread is running."""
        return self._worker is not None and self._worker.is_alive()

    def status(self) -> dict:
        return {
            "enabled": self.enabled(),
            "host": self.host,
            "port": self.port,
            "mode": self.mode,
            "sender": self.sender,
            "queue_size": self._queue.qsize(),
            "queue_max": self.queue_max,
            "sent": self._sent_count,
            "failed": self._failed_count,
            "last_error": self._last_error,
            "worker_running": self.worker_alive(),
        }

    # ----------------------------------------------------------------- api
    def enqueue(self, to: Iterable[str], subject: str, body_text: str, body_html: Optional[str] = None) -> bool:
        if not self.enabled():
            return False
        clean = [a.strip() for a in to if a and "@" in a]
        if not clean:
            return False
        try:
            self._queue.put_nowait(MailJob(to=clean, subject=subject, body_text=body_text, body_html=body_html))
            return True
        except queue.Full:
            try:
                self._queue.get_nowait()  # drop oldest
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(MailJob(to=clean, subject=subject, body_text=body_text, body_html=body_html))
                logger.warning("SMTP queue full: dropped oldest message")
                return True
            except queue.Full:
                return False

    def send_sync(self, to: Iterable[str], subject: str, body_text: str, body_html: Optional[str] = None) -> None:
        """Blocking send (used by /admin/smtp/test)."""
        if not self.enabled():
            raise RuntimeError("SMTP is not configured (set SMTP_HOST)")
        clean = [a.strip() for a in to if a and "@" in a]
        if not clean:
            raise RuntimeError("no valid recipients")
        self._deliver(MailJob(to=clean, subject=subject, body_text=body_text, body_html=body_html))

    # -------------------------------------------------------------- worker
    def start(self) -> None:
        if not self.enabled() or self._worker is not None:
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="smtp-notifier", daemon=True)
        self._worker.start()
        logger.info("Notifier started host=%s port=%s mode=%s", self.host, self.port, self.mode)

    def stop(self) -> None:
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=2.0)
            self._worker = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._deliver(job)
                self._sent_count += 1
            except Exception as exc:  # keep thread alive
                self._failed_count += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
                logger.exception("SMTP send failed: %s", exc)

    # -------------------------------------------------------------- transport
    def _build_message(self, job: MailJob) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = job.subject
        # From must be a mailbox many providers accept (often equals SMTP auth user).
        from_addr = (self.sender or self.username or "").strip()
        if not from_addr or "@" not in from_addr:
            from_addr = (self.username or "").strip() or "noreply@localhost"
        msg["From"] = from_addr
        msg["To"] = ", ".join(job.to)
        if job.reply_to:
            msg["Reply-To"] = job.reply_to
        msg.set_content(job.body_text or "")
        if job.body_html:
            msg.add_alternative(job.body_html, subtype="html")
        return msg

    def _deliver(self, job: MailJob) -> None:
        msg = self._build_message(job)
        context = ssl.create_default_context()
        if self.mode == "ssl":
            with smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context) as s:
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)
        elif self.mode == "plain":
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)
        else:  # starttls (default)
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
                s.ehlo()
                s.starttls(context=context)
                s.ehlo()
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)


notifier = Notifier()


def render_alarm_email(alarm: dict) -> tuple[str, str, str]:
    """Returns (subject, text, html)."""
    triggered_by = alarm.get("triggered_by") or "unknown"
    source = alarm.get("source_id") or "?"
    zone = alarm.get("zone") or "all"
    ts = alarm.get("created_at") or ""
    fanout = alarm.get("fanout_count")
    grp = str(alarm.get("notification_group") or "").strip()
    disp = str(alarm.get("display_label") or "").strip()
    pfx = str(alarm.get("notify_prefix") or "").strip()
    subject = f"[Croc Sentinel] {pfx}ALARM ({triggered_by})" if pfx else f"[Croc Sentinel] ALARM on {source} (zone {zone})"
    lines = [
        "A Croc Sentinel alarm was triggered.",
        "",
        f"Notify as     : {pfx.strip() or '(device id only)'}",
        f"Source device : {source}",
        f"Group         : {grp or '—'}",
        f"Display name  : {disp or '—'}",
        f"Zone          : {zone}",
        f"Triggered via : {triggered_by}",
        f"Time (UTC)    : {ts}",
    ]
    if fanout is not None:
        lines.append(f"Fanned out to : {fanout} sibling device(s)")
    text = "\n".join(lines) + "\n"
    rows = "".join(
        f"<tr><td style='padding:4px 12px;color:#64748b'>{k}</td>"
        f"<td style='padding:4px 12px'><code>{v}</code></td></tr>"
        for k, v in (
            ("Notify as", pfx.strip() or "—"),
            ("Source device", source),
            ("Group", grp or "—"),
            ("Display name", disp or "—"),
            ("Zone", zone),
            ("Triggered via", triggered_by),
            ("Time (UTC)", ts),
            ("Fanned out to", fanout if fanout is not None else "—"),
        )
    )
    html = (
        "<div style='font-family:system-ui,sans-serif'>"
        "<h2 style='color:#b91c1c;margin:0 0 8px'>Croc Sentinel Alarm</h2>"
        f"<p style='margin:0 0 12px'>A device reported an alarm.</p>"
        f"<table style='border-collapse:collapse'>{rows}</table>"
        "</div>"
    )
    return subject, text, html


def render_remote_siren_email(
    *,
    action: str,
    device_id: str,
    display_label: str,
    notification_group: str = "",
    zone: str,
    actor: str,
    duration_ms: Optional[int],
) -> tuple[str, str, str]:
    """Dashboard / API remote siren (not the device physical alarm fan-out)."""
    label = display_label.strip() or "—"
    grp = (notification_group or "").strip() or "—"
    pfx_parts = [f"[{notification_group.strip()}]"] if (notification_group or "").strip() else []
    if (display_label or "").strip():
        pfx_parts.append(display_label.strip())
    pfx = (" ".join(pfx_parts) + " · ") if pfx_parts else f"{device_id} · "
    subject = f"[Croc Sentinel] {pfx}Remote siren {action}"
    lines = [
        "A user triggered a remote siren command from the dashboard or API.",
        "",
        f"Notify as     : {pfx.strip()}",
        f"Action        : {action}",
        f"Device id     : {device_id}",
        f"Group         : {grp}",
        f"Display name  : {label}",
        f"Zone          : {zone or 'all'}",
        f"Triggered by  : {actor}",
    ]
    if duration_ms is not None:
        lines.append(f"Duration (ms) : {duration_ms}")
    text = "\n".join(lines) + "\n"
    rows = "".join(
        f"<tr><td style='padding:4px 12px;color:#64748b'>{k}</td>"
        f"<td style='padding:4px 12px'><code>{v}</code></td></tr>"
        for k, v in (
            ("Notify as", pfx.strip()),
            ("Action", action),
            ("Device id", device_id),
            ("Group", grp),
            ("Display name", label),
            ("Zone", zone or "all"),
            ("Triggered by", actor),
            ("Duration ms", duration_ms if duration_ms is not None else "—"),
        )
    )
    html = (
        "<div style='font-family:system-ui,sans-serif'>"
        "<h2 style='color:#1e3a8a;margin:0 0 8px'>Remote siren</h2>"
        f"<p style='margin:0 0 12px'>Operator action on a provisioned device.</p>"
        f"<table style='border-collapse:collapse'>{rows}</table>"
        "</div>"
    )
    return subject, text, html
