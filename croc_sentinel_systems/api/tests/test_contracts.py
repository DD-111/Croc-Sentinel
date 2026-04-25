"""
Static-analysis contract tests for the api/ package.

Goal: catch regressions of the bugs we already hit once, without booting the
full FastAPI app (which would need DB / Redis / MQTT / JWT secrets).

Covered contracts
-----------------
* `_CSRF_EXEMPT_PREFIXES` — every entry must cover at least one real route,
  OR be a reserved static-file mount we document inline. Prevents the class of
  bug where the exempt list drifted from the SPA's actual auth paths (see
  tests/README.md).

* `_RESERVED_PREFIXES` — must enumerate every top-level FastAPI router mount
  so `DASHBOARD_PATH` can never shadow an API root. Lives in ``config.py``
  since the Phase-2 modularization split.

* `Principal` access — no `.get("role"/"sub"/"username"/"zones")` and no
  `["role"/"sub"/"username"/"zones"]` indexing on the result of
  `decode_jwt(...)` / `require_principal(...)`. That was exactly the
  `AttributeError` that silently broke factory JWT auth.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
APP_PY = API_DIR / "app.py"
CONFIG_PY = API_DIR / "config.py"


# --------------------------------------------------------------------------- #
# Loading / parsing
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def app_source() -> str:
    return APP_PY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def app_tree(app_source: str) -> ast.Module:
    return ast.parse(app_source, filename=str(APP_PY))


@pytest.fixture(scope="module")
def config_tree() -> ast.Module:
    return ast.parse(CONFIG_PY.read_text(encoding="utf-8"), filename=str(CONFIG_PY))


# --------------------------------------------------------------------------- #
# Extractors
# --------------------------------------------------------------------------- #
def _extract_tuple_of_str(tree: ast.Module, name: str) -> tuple[str, ...] | None:
    """Find `NAME: ... = (...)` or `NAME = (...)` at module top level.

    Returns ``None`` when the tuple is not present in this tree (so the caller
    can fall back to scanning sibling modules).
    """
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
    return None


def _require_tuple_of_str(*trees_and_names: tuple[ast.Module, str], symbol: str) -> tuple[str, ...]:
    """Search several (tree, label) pairs and return the first tuple found.

    Used because some constants (e.g. ``_RESERVED_PREFIXES``) moved from
    ``app.py`` to ``config.py`` during modularization. Either location is
    accepted, but at least one must hold the canonical definition.
    """
    seen_in: list[str] = []
    for tree, label in trees_and_names:
        seen_in.append(label)
        result = _extract_tuple_of_str(tree, symbol)
        if result is not None:
            return result
    raise AssertionError(
        f"tuple `{symbol}` not found at module level in any of: {seen_in}"
    )


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


def _all_route_paths() -> set[str]:
    """Union of routes declared anywhere in the api package.

    Phase-7 onward, we extracted dozens of routes from ``app.py`` into
    ``routers/<topic>.py`` modules that all use ``@router.<verb>(...)``.
    Every CSRF-prefix / route check needs to look at the whole picture
    or we'll get false-positive "orphan" reports for any route that
    moved out of app.py.
    """
    out: set[str] = set()
    out |= _route_paths(ast.parse(APP_PY.read_text(encoding="utf-8")))
    routers_dir = API_DIR / "routers"
    if routers_dir.is_dir():
        for path in sorted(routers_dir.glob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue
            out |= _route_paths(tree)
    return out


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
    exempt = _require_tuple_of_str(
        (app_tree, "app.py"),
        symbol="_CSRF_EXEMPT_PREFIXES",
    )
    assert exempt, "_CSRF_EXEMPT_PREFIXES must not be empty"

    routes = _all_route_paths()
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


def test_reserved_prefixes_cover_known_mounts(
    app_tree: ast.Module, config_tree: ast.Module
) -> None:
    # Phase-2 modularization moved _RESERVED_PREFIXES from app.py into
    # config.py; we accept either location so the guard keeps working
    # while individual call sites still spell `_RESERVED_PREFIXES` the
    # same way.
    reserved = set(
        _require_tuple_of_str(
            (config_tree, "config.py"),
            (app_tree, "app.py"),
            symbol="_RESERVED_PREFIXES",
        )
    )
    missing = _EXPECTED_RESERVED - reserved
    assert not missing, (
        "DASHBOARD_PATH guard (_RESERVED_PREFIXES) is missing known mounts: "
        f"{sorted(missing)}. Add them so operators can't set DASHBOARD_PATH "
        "to shadow these routers."
    )


_PRINCIPAL_FIELDS = frozenset({"role", "sub", "username", "zones"})

# Functions that always return a Principal (dataclass, NOT a dict). Any local
# variable bound to a call of one of these is treated as Principal-typed for
# dict-access linting. Keep this list in sync with security.py / app.py.
_PRINCIPAL_RETURNING_CALLS = frozenset(
    {
        "decode_jwt",
        "principal_for_username",
        "principal_from_legacy_bearer",
        "_telegram_bound_principal",
        "require_principal",
    }
)


def _receiver_name(node: ast.AST) -> str:
    """Best-effort readable name for an attribute-access chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_receiver_name(node.value)}.{node.attr}"
    return ""


def _annotation_mentions_principal(ann: ast.AST | None) -> bool:
    """Return True if the annotation references the `Principal` name anywhere."""
    if ann is None:
        return False
    for sub in ast.walk(ann):
        if isinstance(sub, ast.Name) and sub.id == "Principal":
            return True
    return False


def _principal_var_names(tree: ast.Module) -> set[str]:
    """All identifiers that are *certainly* a Principal at runtime.

    Sources:
      • Names containing "principal" (case-insensitive) — covers the common
        convention in app.py.
      • Function parameters annotated `principal: Principal` /
        `Optional[Principal]`.
      • LHS of assignments whose RHS is a call to a known Principal-returning
        function (decode_jwt, principal_for_username, …).

    We only collect *names*, not full attribute chains — conservatively
    matching anywhere in the module is good enough for a regression guard.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        # Function-parameter annotations.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in (
                *node.args.args,
                *node.args.posonlyargs,
                *node.args.kwonlyargs,
            ):
                if _annotation_mentions_principal(arg.annotation):
                    out.add(arg.arg)
        # Assigning the result of decode_jwt(...) etc.
        targets: list[ast.AST] = []
        rhs: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            rhs = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            rhs = node.value
        if rhs is None:
            continue
        if not isinstance(rhs, ast.Call):
            continue
        fname = ""
        if isinstance(rhs.func, ast.Name):
            fname = rhs.func.id
        elif isinstance(rhs.func, ast.Attribute):
            fname = rhs.func.attr
        if fname not in _PRINCIPAL_RETURNING_CALLS:
            continue
        for tgt in targets:
            if isinstance(tgt, ast.Name):
                out.add(tgt.id)
    # Convention-based fallback (anything called *principal*).
    for sub in ast.walk(tree):
        if isinstance(sub, ast.Name) and "principal" in sub.id.lower():
            out.add(sub.id)
    return out


def _scan_principal_dict_access(source: str, filename: str) -> list[str]:
    """Return offending lines from one Python source string.

    A line offends when something we believe is a Principal is accessed via
    `obj.get("role")` / `obj["role"]` for any of _PRINCIPAL_FIELDS.
    """
    tree = ast.parse(source, filename=filename)
    suspects = _principal_var_names(tree)
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
                head = receiver.split(".", 1)[0] if receiver else ""
                if head and head in suspects:
                    offenders.append(
                        f"{filename}:L{node.lineno}: "
                        f"{receiver}.get({node.args[0].value!r})"
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
                head = receiver.split(".", 1)[0] if receiver else ""
                if head and head in suspects:
                    offenders.append(
                        f"{filename}:L{node.lineno}: "
                        f"{receiver}[{sl.value!r}]"
                    )
            self.generic_visit(node)

    Visitor().visit(tree)
    return offenders


def test_no_dict_access_on_principal_role_fields(app_source: str) -> None:
    """
    Catch regressions of the factory-auth bug across every Python file in the
    API package, not just app.py:

        principal = decode_jwt(token)
        principal.get("role")   # raises AttributeError → silently dies
        principal["role"]       # same

    Names treated as Principal:
      • Anything containing "principal" (case-insensitive).
      • Parameters typed `Principal` / `Optional[Principal]`.
      • Variables bound to the return of decode_jwt / principal_for_username /
        principal_from_legacy_bearer / _telegram_bound_principal /
        require_principal.

    We scan every .py file under croc_sentinel_systems/api/ except this test
    module itself (which contains the bug pattern as documentation).
    """
    api_dir = APP_PY.parent
    tests_dir = Path(__file__).resolve().parent
    offenders: list[str] = []
    for path in sorted(api_dir.rglob("*.py")):
        # Skip ourselves (we *intentionally* show the bad pattern in a
        # comment / string for documentation).
        if path.resolve() == Path(__file__).resolve():
            continue
        # Skip test sources — they purposely exercise misuse.
        if path.is_relative_to(tests_dir):
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(api_dir)
        offenders.extend(_scan_principal_dict_access(src, str(rel)))
    assert not offenders, (
        "Dict-style access on a Principal-like object found. Use attribute "
        "access (e.g. principal.role, getattr(principal, 'role', '')) "
        "instead — dict access silently raised AttributeError inside "
        "except-pass blocks once:\n  " + "\n  ".join(offenders)
    )
