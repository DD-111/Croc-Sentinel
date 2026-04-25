"""
Phase 90 contract: frontend canonicalGroupKey MUST mirror backend
``helpers._sibling_group_norm`` exactly.

Context
-------
The MQTT alarm fan-out resolves "siblings" by case-folded
``notification_group``: if device A is in "Warehouse A" and device B is
in "warehouse a", the panic-button on A also triggers B (server-side).

Pre-Phase-90 the dashboard's ``canonicalGroupKey`` did NOT case-fold,
which meant the operator saw two phantom group cards for the same
sibling-cluster — pressing "Alarm ON" on one of them would only
visually update half of the devices even though the server triggered
both. This test guards against that drift recurring.

We do NOT load the JS engine. We extract canonicalGroupKey + the
helper text from ``00-state.shell.js`` and assert the contract:
  * canonicalGroupKey result must be lower-case
  * canonicalGroupKey must call displayGroupName + a lowercasing function
  * displayGroupName must NOT lowercase
  * helpers._sibling_group_norm must casefold (Python side)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parent.parent
STATE_SHELL_JS = API_DIR / "dashboard" / "src" / "shell" / "00-state.shell.js"
HELPERS_PY = API_DIR / "helpers.py"


@pytest.fixture(scope="module")
def state_shell_src() -> str:
    return STATE_SHELL_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def helpers_src() -> str:
    return HELPERS_PY.read_text(encoding="utf-8")


def _extract_function(src: str, name: str) -> str:
    """Extract the body of `function NAME(...) { ... }` from JS source.
    Returns the brace-delimited body content (without outer braces)."""
    pattern = rf"function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{"
    m = re.search(pattern, src)
    if not m:
        raise AssertionError(f"function {name}() not found in JS source")
    depth = 1
    i = m.end()
    while i < len(src) and depth > 0:
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[m.end():i]
        i += 1
    raise AssertionError(f"unterminated function body for {name}()")


def test_canonical_group_key_calls_lowercase(state_shell_src: str) -> None:
    """canonicalGroupKey MUST case-fold so it matches the backend's
    ``_sibling_group_norm`` casefold step. ``toLocaleLowerCase`` is the
    JS-side equivalent of Python's ``str.casefold`` for ASCII / Latin-1
    group names (most groups). Plain ``toLowerCase`` is acceptable as a
    fallback."""
    body = _extract_function(state_shell_src, "canonicalGroupKey")
    assert "toLocaleLowerCase" in body or "toLowerCase" in body, (
        "canonicalGroupKey() must lowercase its result so the dashboard "
        "deduplicates groups the same way the MQTT fan-out does. "
        "Without this, e.g. 'Warehouse A' and 'warehouse a' render as "
        "two separate cards even though the backend treats them as one "
        "sibling cluster."
    )


def test_display_group_name_preserves_case(state_shell_src: str) -> None:
    """displayGroupName MUST NOT lowercase — it's used for human-readable
    titles in cards / breadcrumbs / edit-form prefills, where the user's
    original casing should be preserved."""
    body = _extract_function(state_shell_src, "displayGroupName")
    assert "toLocaleLowerCase" not in body, (
        "displayGroupName() must not case-fold; that is the job of "
        "canonicalGroupKey(). Card titles should show the case the user "
        "originally typed (e.g. 'Warehouse A' not 'warehouse a')."
    )
    assert "toLowerCase" not in body, (
        "displayGroupName() must not lowercase; preserve user-typed casing."
    )


def test_canonical_group_key_uses_display_group_name(state_shell_src: str) -> None:
    """Implementation discipline: canonicalGroupKey should derive its
    NFC + whitespace-collapse step from displayGroupName so the two
    helpers cannot drift apart on whitespace handling."""
    body = _extract_function(state_shell_src, "canonicalGroupKey")
    assert "displayGroupName" in body, (
        "canonicalGroupKey() should call displayGroupName() so the trim/"
        "NFC/whitespace behavior is shared between the matching key and "
        "the display string."
    )


def test_backend_sibling_group_norm_casefolds(helpers_src: str) -> None:
    """The backend half of the contract: _sibling_group_norm MUST
    casefold so it matches the (now case-folded) frontend
    canonicalGroupKey. If this regresses, the frontend would over-merge
    or the backend would under-merge — either creates the phantom-cards
    bug we just fixed."""
    fn_match = re.search(
        r"def\s+_sibling_group_norm\s*\([^)]*\)[^:]*:\s*(?:\"\"\".*?\"\"\")?(.+?)(?=\n\S|\Z)",
        helpers_src,
        flags=re.DOTALL,
    )
    assert fn_match, "_sibling_group_norm not found in helpers.py"
    body = fn_match.group(1)
    assert "casefold" in body, (
        "_sibling_group_norm must call .casefold() — its job is to be "
        "the case-insensitive sibling-match key the dashboard mirrors."
    )


def test_state_shell_does_not_use_plain_toLowerCase_for_groups(state_shell_src: str) -> None:
    """The whole module should funnel group-key normalization through
    canonicalGroupKey. A bare .toLowerCase() on a notification_group
    string elsewhere would silently bypass the NFC + whitespace fixes."""
    bad_pattern = re.compile(
        r"\b(notification_group|d\.notification_group)\b[^;\n]*\.toLowerCase\(\)",
    )
    matches = bad_pattern.findall(state_shell_src)
    assert not matches, (
        "Found ad-hoc .toLowerCase() on notification_group inside "
        "00-state.shell.js — use canonicalGroupKey() so NFC + whitespace "
        "normalization is applied too. Matches: %r" % matches
    )
