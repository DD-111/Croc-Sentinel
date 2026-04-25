"""
SPA <-> backend API contract tests.

Mirrors the JS side `scripts/smoke-routes.mjs` (which only validates the SPA
internal manifest), but for the cross-stack contract:

    Every path the SPA calls via api(...) / apiBase()+"..." / fetch("/...", ...)
    MUST be served by a real @app.<verb>("...") route in api/app.py.

The test runs as static text/regex analysis. It deliberately does **not**
import app.py (which would need DB/Redis/MQTT secrets) and it does **not**
parse the JS as a real AST (which would need a JS parser); regex on the
source is good enough because the SPA uses very consistent call shapes.

If this test fails, options:
  1. The SPA has a typo / stale path → fix the call site.
  2. The backend route was renamed / removed → fix the route or the call.
  3. The path is intentionally external / 3rd party → add it to
     ALLOWED_OUT_OF_BAND below.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
APP_PY = API_DIR / "app.py"
SPA_SRC = API_DIR / "dashboard" / "src" / "console.raw.js"


# Paths that look like API calls but intentionally go elsewhere — keep tiny.
ALLOWED_OUT_OF_BAND: frozenset[str] = frozenset(
    {
        # Health check responses are read but never via apiBase() (loadHealth
        # uses fetchWithDeadline + apiBase()). Listed here just in case.
    }
)


# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def app_tree() -> ast.Module:
    return ast.parse(APP_PY.read_text(encoding="utf-8"), filename=str(APP_PY))


@pytest.fixture(scope="module")
def spa_source() -> str:
    return SPA_SRC.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Backend route extraction
# --------------------------------------------------------------------------- #
_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _backend_routes(tree: ast.Module) -> set[tuple[str, str]]:
    """Return {(METHOD, path), ...} for every @something.<verb>("...") in app.py."""
    out: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            if call is None or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in _VERBS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                out.add((call.func.attr.upper(), first.value))
    return out


def _backend_path_matches(method: str, path: str, routes: set[tuple[str, str]]) -> bool:
    """
    Return True if (method, path) is served by any backend route, accounting
    for FastAPI {param} placeholders. method=='ANY' matches any verb.
    """
    for be_method, be_path in routes:
        if method != "ANY" and method != be_method:
            continue
        if be_path == path:
            return True
        # Convert backend "/devices/{id}/state" into a regex.
        regex = "^" + re.escape(be_path).replace(r"\{", "{").replace(r"\}", "}")
        regex = re.sub(r"\{[^}]+\}", "[^/]+", regex) + "$"
        if re.match(regex, path):
            return True
    return False


# --------------------------------------------------------------------------- #
# SPA call extraction
# --------------------------------------------------------------------------- #
# 1. api("/path", { method: "POST" })  -- writes default to GET unless body / method
_API_CALL = re.compile(
    r"""\bapi\s*\(\s*["`']([^"`']+)["`']\s*(?:,\s*(\{[^}]*\}))?\s*\)""",
    re.MULTILINE,
)
# 2. apiBase() + "/path"
_API_BASE_LIT = re.compile(r"""apiBase\(\)\s*\+\s*["`']([^"`']+)["`']""")
# 3. fetch("/path", ...) with absolute literal
_FETCH_LIT = re.compile(r"""\bfetch\s*\(\s*["`'](\/[^"`']+)["`']""")


_METHOD_LITERAL = re.compile(r"""method\s*:\s*["']([A-Z]+)["']""")
_BODY_OPT = re.compile(r"""\bbody\s*:""")  # property `body:`, not the word


def _infer_method(opts: str | None, fallback: str = "GET") -> str:
    if not opts:
        return fallback
    m = _METHOD_LITERAL.search(opts)
    if m:
        return m.group(1).upper()
    if _BODY_OPT.search(opts):
        return "POST"
    return fallback


def _spa_calls(src: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for m in _API_CALL.finditer(src):
        path = m.group(1).split("?")[0].split("#")[0]
        if not path.startswith("/"):
            continue
        method = _infer_method(m.group(2), fallback="GET")
        out.add((method, path))
    for m in _API_BASE_LIT.finditer(src):
        path = m.group(1).split("?")[0].split("#")[0]
        # Best-effort: look at next ~400 chars for a method: literal.
        tail = src[m.start(): m.start() + 400]
        method = _infer_method(tail, fallback="ANY")
        out.add((method, path))
    for m in _FETCH_LIT.finditer(src):
        path = m.group(1).split("?")[0].split("#")[0]
        out.add(("ANY", path))
    return out


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_every_spa_call_hits_a_real_backend_route(
    app_tree: ast.Module, spa_source: str
) -> None:
    routes = _backend_routes(app_tree)
    calls = _spa_calls(spa_source)

    missing: list[str] = []
    for method, path in sorted(calls):
        if path in ALLOWED_OUT_OF_BAND:
            continue
        if not _backend_path_matches(method, path, routes):
            missing.append(f"{method} {path}")

    assert not missing, (
        "These SPA paths do NOT match any FastAPI route in app.py.\n"
        "  - SPA typo? rename in console.raw.js\n"
        "  - Backend rename? update both sides\n"
        "  - 3rd party? add to ALLOWED_OUT_OF_BAND in this test\n"
        f"\nOffenders ({len(missing)}):\n  "
        + "\n  ".join(missing)
    )


def test_no_legacy_dashed_auth_paths_in_spa(spa_source: str) -> None:
    """
    Lock in the auth path rename. The earlier scheme used hyphenated paths
    (`/auth/forgot-password`, `/auth/reset-password`, `/auth/account-activate`,
    `/auth/resend-activation`); the current scheme uses slashed segments
    (`/auth/forgot/...`, `/auth/activate`, `/auth/code/resend`). If anyone
    re-introduces the dashed paths we want a noisy red CI line.
    """
    legacy = [
        "/auth/forgot-password",
        "/auth/reset-password",
        "/auth/account-activate",
        "/auth/resend-activation",
        "/auth/register",  # signup/start replaced this
    ]
    found = [p for p in legacy if p in spa_source]
    assert not found, (
        "SPA still references legacy auth paths that the backend doesn't "
        f"serve: {found}. Use /auth/forgot/..., /auth/activate, "
        "/auth/code/resend, /auth/signup/... instead."
    )
