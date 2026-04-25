"""UI / SPA-mount redirect router (Phase-33 modularization).

The reverse-proxy / SPA "front door" — six tiny redirect endpoints that
funnel every legacy URL into the canonical dashboard mount point
(``DASHBOARD_PATH``). The actual SPA static files are served by a
mounted ``StaticFiles`` instance set up in app.py at startup; this
router only handles the *redirect-to-mount* shape.

Routes
------
  GET /                      -> 302 → {DASHBOARD_PATH}/
  GET /ui                    -> 301 → {DASHBOARD_PATH}/
  GET /ui/                   -> 301 → {DASHBOARD_PATH}/
  GET /dashboard             -> 301 → {DASHBOARD_PATH}/
  GET /dashboard/            -> 301 → {DASHBOARD_PATH}/
  GET /ui/{path:path}        -> 301 → {DASHBOARD_PATH}/{path}

All endpoints are ``include_in_schema=False`` so they don't pollute
OpenAPI; ``/`` uses 302 (temporary) so we can move the SPA without
poisoning browser caches, while the legacy ``/ui*`` and ``/dashboard*``
shapes use 301 (permanent) — those are settled.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from config import DASHBOARD_PATH


router = APIRouter(tags=["ui-mounts"])


@router.get("/", include_in_schema=False)
def _root_redirect() -> RedirectResponse:
    return RedirectResponse(url=DASHBOARD_PATH + "/", status_code=302)


@router.get("/ui", include_in_schema=False)
@router.get("/ui/", include_in_schema=False)
@router.get("/dashboard", include_in_schema=False)
@router.get("/dashboard/", include_in_schema=False)
def _legacy_ui_redirect() -> RedirectResponse:
    return RedirectResponse(url=DASHBOARD_PATH + "/", status_code=301)


@router.get("/ui/{path:path}", include_in_schema=False)
def _legacy_ui_deep_redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=f"{DASHBOARD_PATH}/{path}", status_code=301)


__all__ = [
    "router",
    "_root_redirect",
    "_legacy_ui_redirect",
    "_legacy_ui_deep_redirect",
]
