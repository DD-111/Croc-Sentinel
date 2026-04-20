#!/usr/bin/env python3
"""CLI: SN-* + signed QR + files; optional auto POST /factory/devices.

Uses factory_core (same HMAC as api verify_qr_signature).
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

from factory_core import (
    append_pending_push_queue,
    DEFAULT_FACTORY_UI_API_BASE,
    DEFAULT_QR_POLICY,
    default_dotenv_path,
    drain_pending_push_queue,
    generate_items,
    get_factory_ping,
    load_pending_push_queue,
    post_factory_devices,
    read_dotenv_keys,
    repo_root,
    verify_qr_local,
    write_push_status_file,
    write_batch_files,
)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Factory serials + HMAC QR; optional push to server /factory/devices."
    )
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--qr-secret", default="", help="Override QR_SIGN_SECRET (else read from .env)")
    ap.add_argument(
        "--dotenv",
        default="",
        metavar="PATH",
        help="Env file for QR_SIGN_SECRET / FACTORY_* (default: croc_sentinel_systems/.env)",
    )
    ap.add_argument("--batch", default="", help="Batch label")
    ap.add_argument("--out", default="", help="Output directory")
    ap.add_argument("--verify-qr", default="", metavar="STRING", help="Verify one CROC|... then exit")
    ap.add_argument("--policy-regex", default="", help="Override QR fullmatch regex")
    ap.add_argument(
        "--push",
        action="store_true",
        help="After writing files, POST items to server /factory/devices",
    )
    ap.add_argument(
        "--ping",
        action="store_true",
        help="GET /factory/ping then exit (checks FACTORY_UI_API_BASE + FACTORY_API_TOKEN)",
    )
    ap.add_argument(
        "--api-base",
        default="",
        help="API root e.g. https://host:8088 (else FACTORY_UI_API_BASE from .env)",
    )
    ap.add_argument(
        "--insecure-ssl",
        action="store_true",
        help="Skip TLS certificate verification (dev only)",
    )
    ap.add_argument(
        "--retry-queue-max",
        type=int,
        default=20,
        help="Max queued failed batches to retry before current push (default: 20)",
    )
    args = ap.parse_args()

    root = repo_root()
    dot = Path(args.dotenv).expanduser() if args.dotenv else default_dotenv_path()
    env = read_dotenv_keys(
        dot,
        ("QR_SIGN_SECRET", "FACTORY_API_TOKEN", "FACTORY_UI_API_BASE", "FACTORY_AUTO_PUSH"),
    )
    if args.ping:
        api_base = (args.api_base or env["FACTORY_UI_API_BASE"] or DEFAULT_FACTORY_UI_API_BASE).strip().rstrip("/")
        token = (env["FACTORY_API_TOKEN"] or "").strip()
        if not api_base or not token:
            print("Error: --ping needs FACTORY_API_TOKEN in .env and API base (--api-base, FACTORY_UI_API_BASE, or default host)", file=sys.stderr)
            sys.exit(4)
        code, body = get_factory_ping(api_base, token, insecure_ssl=args.insecure_ssl)
        print(f"GET /factory/ping -> HTTP {code}\n{body}")
        sys.exit(0 if code == 200 else 7)
    secret = (args.qr_secret or env["QR_SIGN_SECRET"] or "").strip()
    if not secret:
        print("Error: set QR_SIGN_SECRET in .env or pass --qr-secret", file=sys.stderr)
        sys.exit(2)
    if len(secret) < 24:
        print("[warn] QR_SIGN_SECRET < 24 chars may break ENFORCE_DEVICE_CHALLENGE=1", file=sys.stderr)

    if args.verify_qr:
        ok = verify_qr_local(args.verify_qr.strip(), secret)
        print("verify_qr:", "OK" if ok else "FAIL")
        sys.exit(0 if ok else 1)

    policy = re.compile(args.policy_regex) if args.policy_regex else DEFAULT_QR_POLICY
    batch = args.batch or f"batch_{int(time.time())}"
    try:
        items = generate_items(args.count, secret, batch, policy=policy)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

    default_out = root / "factory_serial_exports" / f"output_{int(time.time())}"
    out = Path(args.out) if args.out else default_out
    write_batch_files(out, items, batch)
    print(f"Wrote {len(items)} devices to:\n  {out}")
    queue_path = root / "factory_serial_exports" / "pending_push_queue.json"
    (out / "BATCH_ID.txt").write_text(batch + "\n", encoding="utf-8")

    do_push = bool(args.push) or (env.get("FACTORY_AUTO_PUSH") or "").strip() == "1"
    if do_push:
        api_base = (args.api_base or env["FACTORY_UI_API_BASE"] or DEFAULT_FACTORY_UI_API_BASE).strip().rstrip("/")
        token = (env["FACTORY_API_TOKEN"] or "").strip()
        if not api_base:
            print("Error: push needs API base (--api-base, FACTORY_UI_API_BASE, or built-in default)", file=sys.stderr)
            sys.exit(4)
        if not token:
            print("Error: push needs FACTORY_API_TOKEN in .env", file=sys.stderr)
            sys.exit(5)
        queued_before = len(load_pending_push_queue(queue_path))
        if queued_before:
            drained, attempts = drain_pending_push_queue(
                queue_path,
                api_base,
                token,
                insecure_ssl=args.insecure_ssl,
                max_batches=max(1, args.retry_queue_max),
            )
            print(f"[retry] queue_before={queued_before} drained={drained} remain={len(load_pending_push_queue(queue_path))}")
            for a in attempts:
                print(f"[retry] batch={a.get('batch')} code={a.get('code')} ok={a.get('ok')}")
        code, body = post_factory_devices(api_base, token, items, insecure_ssl=args.insecure_ssl)
        print(f"POST /factory/devices -> HTTP {code}\n{body}")
        ok = code in (200, 201)
        status_file = write_push_status_file(out, batch, items, code, body, pushed_ok=ok, retry_attempt=0)
        print(f"Push status file:\n  {status_file}")
        if not ok:
            qlen = append_pending_push_queue(queue_path, batch, items, reason=f"HTTP {code}: {body[:500]}")
            print(f"[queue] push failed; queued for auto-retry: {queue_path} (size={qlen})")
            sys.exit(6)


if __name__ == "__main__":
    main()
