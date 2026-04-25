"""Route modules extracted from ``app.py``.

Each submodule exports a single ``router`` (``fastapi.APIRouter``) plus its
own request/response models and route-local helpers. ``app.py`` wires them
into the main FastAPI app via ``app.include_router(router)``.

The split is by URL prefix / domain (factory, audit, …) rather than by HTTP
verb. New domains should add a new module here; do not pile unrelated
endpoints into an existing one.
"""
