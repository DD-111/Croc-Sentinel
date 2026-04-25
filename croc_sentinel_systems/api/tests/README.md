# api/tests

Static-analysis contract tests for `app.py`.

These tests purposefully **do not import `app.py`**. They parse the source with
`ast` and walk decorators / assignments instead, so they stay fast (<200 ms)
and don't need the full runtime stack (DB, MQTT, Redis, JWT secrets, …).

## Why they exist

Each test guards against a real production bug we already hit once:

- `test_csrf_exempt_prefixes_match_real_routes`
  Every prefix in `_CSRF_EXEMPT_PREFIXES` **must** cover at least one real
  FastAPI route. The list used to carry `/auth/register`, `/auth/forgot-password`,
  `/auth/account-activate`, `/auth/resend-activation` — none of which the SPA
  actually calls — while the real paths (`/auth/signup/...`, `/auth/forgot/...`,
  `/auth/activate`, `/auth/code/resend`) were **not** exempt. A stale session
  cookie plus a write request hit a 403 `csrf_invalid`.

- `test_reserved_prefixes_include_mounted_routers`
  The guard that prevents `DASHBOARD_PATH` from shadowing API routers must
  list every top-level mount (`/api`, `/events`, `/ota`, `/factory`, …). If
  a new router is added and the operator sets `DASHBOARD_PATH=/foo` where
  `/foo` is the new router root, the SPA silently shadows the API.

- `test_principal_access_uses_attributes_not_dict`
  `decode_jwt()` returns a `Principal` dataclass, not a dict. A single
  `principal.get("role")` call compiled fine but raised `AttributeError`
  inside `except Exception: pass`, silently disabling JWT auth for the
  factory endpoint. This test fails the build if anyone writes
  `<name>.get("role"|"sub"|"username"|"zones")` or `<name>["role"|...]`
  near a `decode_jwt` / `require_principal` result.

## Running

```bash
python -m pytest croc_sentinel_systems/api/tests -q
```

Runs in <300 ms on a cold shell. CI can wire it alongside the frontend's
`npm run verify`.
