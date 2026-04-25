# Nginx Reverse Proxy Playbook (Croc Sentinel)

This file is for deployments using **Nginx as the main public reverse proxy**.
It complements OTA-only config in `nginx/default.conf.template` (which serves `/fw/` only).

## Why this is needed

- The dashboard uses `croc-api-base=/api` in `api/dashboard/index.html`.
- Backend routes are rooted at `/auth`, `/events`, `/devices`, etc. (no `/api` prefix).
- Therefore Nginx must proxy `/api/*` to backend **with prefix stripping**.

Without this, you will keep seeing "configured but still broken":
- `/api/auth/login` -> 404 (backend receives `/api/auth/login` instead of `/auth/login`)
- SSE/WS unstable or disconnected through proxy buffering/timeouts

## Use this template

- Source: `nginx/reverse_proxy_api.conf.template`
- Upstream expected: `http://api:8088`

Core routes implemented:
- `/console` and `/console/*` -> API static mount
- `/api/*` -> API root with strip-prefix (`proxy_pass http://api:8088/;`)
- `/api/events/stream` -> SSE optimized path
- `/api/events/ws` -> WebSocket optimized path
- `/` -> redirect to `/console/`

## Smoke + Debug

Run static smoke check:

```bash
python croc_sentinel_systems/scripts/nginx-smoke-check.py
```

Expected:

```text
OK: nginx reverse proxy template smoke checks passed
```

Then validate runtime (on server):

1) `GET /console/` returns dashboard HTML  
2) `POST /api/auth/login` reaches backend and returns auth response  
3) `GET /api/events/stream` remains open (SSE)  
4) `GET /api/events/ws` performs WebSocket upgrade (101)

## Non-goals

- Does not replace OTA nginx config (`nginx/default.conf.template`)
- Does not force Traefik; this is for direct Nginx front-door setups

