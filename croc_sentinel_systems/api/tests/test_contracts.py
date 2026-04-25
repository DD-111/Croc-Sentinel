"""
Static-analysis contract tests for api/app.py.

Goal: catch regressions of the bugs we already hit once, without booting the
full FastAPI app (which would need DB / Redis / MQTT / JWT secrets).

Covered contracts
-----------------
* `_CSRF_EXEMPT_PREFIXES` — every entry must cover at least one real route,
  OR be a reserved static-file mount we document inline. Prevents the class of
  bug where the exempt list drifted from the SPA's actual auth paths (see
  tests/README.md).

* `_RESERVED_PREFIXES` — must enumerate every top-level FastAPI router mount
  so `DASHBOARD_PATH` can never shadow an API root.

* `Principal` access — no `.get("role"/"sub"/"username"/"zones")` and no
  `["role"/"sub"/"username"/"zones"]` indexing on the result of
  `decode_jwt(...)` / `require_principal(...)`. That was exactly the
  `AttributeError` that silently broke factory JWT auth.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

APP_PY = Path(__file__).resolve().parent.parent / "app.py"


# --------------------------------------------------------------------------- #
# Loading / parsing
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def app_source() -> str:
    return APP_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def app_tree(app_source: str) -> ast.Module:
    return ast.parse(app_source, filename=str(APP_PY))


# --------------------------------------------------------------------------- #
# Extractors
# --------------------------------------------------------------------------- #
def _extract_tuple_of_str(tree: ast.Module, name: str) -> tuple[str, ...]:
    """Find `NAME: ... = (...)` or `NAME = (...)` at module top level."""
    for node in tree.body:
        targets = []
        value = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        if not value or not isinstance(value, ast.Tuple):
            continue
        for tgt in targets:
            if isinstance(tgt, ast.Name) and tgt.id == name:
                out: list[str] = []
                for elt in value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        out.append(elt.value)
                return tuple(out)
    raise AssertionError(f"tuple `{name}` not found at module level in app.py")


_DECORATOR_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _route_paths(tree: ast.Module) -> set[str]:
    """Collect every `@X.<verb>("<path>", ...)` decorator path."""
    paths: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            if call is None:
                continue
            if not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in _DECORATOR_METHODS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                paths.add(first.value)
    return paths


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
# Exempt entries that are allowed *without* a FastAPI route backing them,
# because they are handled by StaticFiles mounts, health probes, or legacy
# shells. Keep this list tiny and documented.
_CSRF_STATIC_EXEMPT = frozenset(
    {
        "/health",
        "/dashboard/",  # legacy SPA shell; DASHBOARD_PATH now defaults to /console
        "/ui/",         # legacy static shell
        "/ingest/",     # device-side ingest, may be mounted via sub-routers
    }
)


def test_csrf_exempt_prefixes_match_real_routes(app_tree: ast.Module) -> None:
    exempt = _extract_tuple_of_str(app_tree, "_CSRF_EXEMPT_PREFIXES")
    assert exempt, "_CSRF_EXEMPT_PREFIXES must not be empty"

    routes = _route_paths(app_tree)
    orphan: list[str] = []
    for entry in exempt:
        if entry in _CSRF_STATIC_EXEMPT:
            continue
        # A valid entry either matches exactly, or is a prefix of a real route.
        hit = any(
            r == entry or r == entry.rstrip("/") or r.startswith(entry)
            for r in routes
        )
        if not hit:
            orphan.append(entry)
    assert not orphan, (
        "These _CSRF_EXEMPT_PREFIXES entries do not match any real FastAPI "
        "route. Either add the matching route or delete the stale prefix:\n  "
        + "\n  ".join(orphan)
    )


# Routers that we know are mounted even though their decorators live on an
# `APIRouter` object with no single "prefix" literal. They still deserve to be
# in _RESERVED_PREFIXES so DASHBOARD_PATH cannot shadow them.
_EXPECTED_RESERVED = frozenset(
    {
        "/auth",
        "/admin",
        "/devices",
        "/commands",
        "/alerts",
        "/provision",
        "/health",
        "/dashboard",
        "/logs",
        "/audit",
        "/ui",
        "/api",
        "/events",
        "/ota",
        "/factory",
        "/integrations",
        "/ingest",
    }
)


def test_reserved_prefixes_cover_known_mounts(app_tree: ast.Module) -> None:
    reserved = set(_extract_tuple_of_str(app_tree, "_RESERVED_PREFIXES"))
    missing = _EXPECTED_RESERVED - reserved
    assert not missing, (
        "DASHBOARD_PATH guard (_RESERVED_PREFIXES) is missing known mounts: "
        f"{sorted(missing)}. Add them so operators can't set DASHBOARD_PATH "
        "to shadow these routers."
    )


_PRINCIPAL_FIELDS = frozenset({"role", "sub", "username", "zones"})


def test_no_dict_access_on_principal_role_fields(app_source: str) -> None:
    """
    Catch regressions of the factory-auth bug:

        principal = decode_jwt(token)
        principal.get("role")   # raises AttributeError → silently dies
        principal["role"]       # same

    Only the role-ish field names are flagged; unrelated `.get("foo")` calls
    on dicts are ignored.
    """
    tree = ast.parse(app_source, filename=str(APP_PY))
    offenders: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 (ast API)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value in _PRINCIPAL_FIELDS
            ):
                receiver = _receiver_name(node.func.value)
                if receiver and "principal" in receiver.lower():
                    offenders.append(
                        f"L{node.lineno}: {receiver}.get({node.args[0].value!r})"
                    )
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
            sl = node.slice
            if (
                isinstance(sl, ast.Constant)
                and isinstance(sl.value, str)
                and sl.value in _PRINCIPAL_FIELDS
            ):
                receiver = _receiver_name(node.value)
                if receiver and "principal" in receiver.lower():
                    offenders.append(
                        f"L{node.lineno}: {receiver}[{sl.value!r}]"
                    )
            self.generic_visit(node)

    def _receiver_name(node: ast.AST) -> str:
        """Best-effort readable name for the expression the access is on."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{_receiver_name(node.value)}.{node.attr}"
        return ""

    Visitor().visit(tree)
    assert not offenders, (
        "Dict-style access on a Principal-like object found. Use attribute "
        "access (getattr(principal, 'role', '')) instead — dict access "
        "silently raised AttributeError inside except-pass blocks once:\n  "
        + "\n  ".join(offenders)
    )
