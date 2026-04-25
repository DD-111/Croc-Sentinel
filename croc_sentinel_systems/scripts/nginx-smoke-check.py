"""Static smoke checks for nginx reverse proxy template.

This does not start nginx. It enforces required directives so accidental edits
cannot silently break the known-good routing contract:
  - dashboard at /console
  - API at /api with strip-prefix proxy_pass
  - SSE + WebSocket forwarding
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "nginx" / "reverse_proxy_api.conf.template"


def _must(text: str, pattern: str, why: str) -> None:
    if not re.search(pattern, text, flags=re.MULTILINE):
        raise AssertionError(f"Missing: {why}\nPattern: {pattern}")


def main() -> int:
    if not CFG.exists():
        print(f"FAIL: config not found: {CFG}")
        return 2
    txt = CFG.read_text(encoding="utf-8")

    _must(txt, r"location\s+/console/", "dashboard /console proxy path")
    _must(txt, r"location\s+/api/", "API /api location")
    _must(txt, r"proxy_pass\s+http://api:8088/;", "strip-prefix proxy_pass for /api/ (trailing slash)")
    _must(txt, r"location\s+/api/events/stream", "SSE location")
    _must(txt, r"add_header\s+X-Accel-Buffering\s+no", "SSE buffering disabled header")
    _must(txt, r"location\s+/api/events/ws", "WebSocket location")
    _must(txt, r"proxy_set_header\s+Upgrade\s+\$http_upgrade;", "WebSocket upgrade header")
    _must(txt, r"proxy_set_header\s+Connection\s+\$connection_upgrade;", "WebSocket connection header")
    _must(txt, r"return\s+302\s+/console/;", "root redirect to /console/")

    print("OK: nginx reverse proxy template smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

