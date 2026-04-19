# Nginx: Dashboard under a subpath, API at site root

Use this when the SPA is served at a path such as `https://esasecure.com:8088/Croc_Sentinel_systems/` while REST and factory APIs stay at the **origin root** (`/auth/...`, `/devices/...`, `/factory/...`). The dashboard [`apiBase()`](../api/dashboard/assets/app.js) uses `location.origin`, so fetches go to `https://esasecure.com:8088/auth/login` etc. — correct for this layout.

**完整步骤（Docker + 宿主机 Nginx + 端口 + 验收）** → 见 **[SERVER_DEPLOY_SUBPATH.md](./SERVER_DEPLOY_SUBPATH.md)**。

## Static UI (subpath)

- Map `location /Croc_Sentinel_systems/` to the directory containing `index.html` and `assets/`.
- Use `try_files` so client-side hash routes work (`#/overview` is not sent to the server, but direct loads of nested paths may need `index.html` fallback).

## API (root)

Proxy at least these prefixes to your FastAPI/Uvicorn upstream (adjust `proxy_pass` if your app listens elsewhere):

| Prefix | Purpose |
|--------|---------|
| `/auth` | Login, JWT, signup |
| `/devices` | Device CRUD, commands |
| `/commands` | Broadcast |
| `/provision` | Bootstrap / claim |
| `/dashboard` | Dashboard JSON APIs |
| `/admin` | Admin, OTA, SMTP |
| `/health` | Health check |
| `/logs` | Message logs |
| `/audit` | Audit stream |
| `/factory` | Factory device registry (`X-Factory-Token`) |
| `/alerts` | Siren / alerts |
| `/ota` | OTA firmware listing |

Also include **`/activity`** and **`/events`** (and SSE **`/events/stream`** — disable `proxy_buffering` for that path; see full deploy doc).

## 端口注意（常见错误）

若宿主机 Nginx 监听 **8088**，则 Docker 的 **`api` 不能再占用主机 `0.0.0.0:8088`**，否则冲突。请把 API 绑定到 **回环 + 其他端口**（例如 `127.0.0.1:18088:8088`），Nginx `proxy_pass` 指向 `http://127.0.0.1:18088`。可复制仓库内 **[`docker-compose.override.example.yml`](../docker-compose.override.example.yml)** 为 `docker-compose.override.yml`。

## 静态目录推荐（`root` + 子文件夹）

把 `api/dashboard/` 同步到 **`/var/www/html/Croc_Sentinel_systems/`**（内含 `index.html` 与 `assets/`），Nginx 使用：

```nginx
root /var/www/html;
location /Croc_Sentinel_systems/ {
    try_files $uri $uri/ /Croc_Sentinel_systems/index.html;
}
```

完整 `server` 块、TLS、`/events/stream` 与反代列表见 **[SERVER_DEPLOY_SUBPATH.md](./SERVER_DEPLOY_SUBPATH.md)**。

## Factory desktop app (`tools/factory_pack`)

Set in `croc_sentinel_systems/.env` (or the app’s “API root” field):

```env
FACTORY_UI_API_BASE=https://esasecure.com:8088
```

No trailing slash, **no** `/Croc_Sentinel_systems` — factory endpoints are `/factory/ping` and `/factory/devices`.

## Related

- Server-side mount path when **not** using Nginx for static files: `DASHBOARD_PATH` in `.env` (see main [README.md](../README.md)).
