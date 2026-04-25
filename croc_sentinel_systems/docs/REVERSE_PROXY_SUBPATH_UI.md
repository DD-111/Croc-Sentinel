# 子路径控制台 + API 反代（Traefik 或任意网关）

`index.html` 中 **`croc-api-base` / `croc-dashboard-base`** 与 [`app.js`](../api/dashboard/assets/app.js)（由 `dashboard/src/` 构建）中的 `apiBase()` 共同决定：浏览器请求是 **`https://域名/根路径/...` 还是 `https://域名/api/...`**，控制台静态页在 **`/console`（可改 `DASHBOARD_PATH`）** 或你配置的子路径。

- **`croc-api-base="/api"`** 时，REST 与 **WebSocket**（`/api/events/ws`）、**SSE**（`/api/events/stream`）都带 `/api` 前缀 —— 网关需 **`StripPrefix("/api")`** 再反代到 Uvicorn（后端路由仍是根上的 `/auth`、`/events/...`）。
- **留空或不使用 `/api` 前缀** 时，与下列「**API 在站点根**」一致，无需 StripPrefix；`FACTORY_UI_API_BASE` 为浏览器能打开的 **同 scheme+host+port 根**（如 `https://x.com:443` 无尾斜杠）。

**完整生产步骤（Docker Compose + Traefik + 验收）** → **[SERVER_DEPLOY_SUBPATH.md](./SERVER_DEPLOY_SUBPATH.md)**。

| Prefix（后端**实际**路径，Strip 后） | 用途 |
|--------|------|
| `/auth` | 登录、JWT、注册 |
| `/devices` | 设备与命令 |
| `/commands` | 广播 |
| `/provision` | 认领等 |
| `/dashboard` | 仪表盘 JSON |
| `/admin` | 管理、OTA、SMTP |
| `/health` | 健康检查 |
| `/logs`、`/audit` | 日志与审计 |
| `/factory` | 出厂登记（`X-Factory-Token`） |
| `/alerts`、`/ota`、`/activity`、`/events` | 对应功能 |
| `/events/stream` | SSE 长连接 |
| `/events/ws` | WebSocket（`Upgrade` 由 Traefik 默认转发，勿关 `EVENT_WS_ENABLED` 作为首选项） |

**实时能力：** 优先在 **`StripPrefix` 下** 放行 **`/api/events/ws` → `/events/ws`** 与 **`/api/events/stream` → `/events/stream`**（若 API 在根，则为 `/events/ws`、`/events/stream`）。`EVENT_WS_ENABLED=0` 仅作代理**确实无法**做 WS 时的最后手段。

**端口与 Compose：** 若 **Traefik** 已占用 **80/443**，`api` 的 `ports` 不要与 Traefik 冲突；可映射 **`127.0.0.1:18999:8088`**，由 Traefik 在 Docker 网络中访问 `http://api:8088`（**推荐**用 **同一 `docker network` + 服务名**），比绕宿主机回环更稳。

## Factory 桌面端（`tools/factory_pack`）

```env
# 与浏览器访问的公网基址一致。布局 A（croc-api-base=/api）时「基址」要含 /api，无尾斜杠：
FACTORY_UI_API_BASE=https://你的域名/api
# 布局 B（API 在站点根、无 /api 前缀）：
# FACTORY_UI_API_BASE=https://你的域名:端口
```

Factory 走 **`/factory/*`** 相对该 base，例如 `https://你的域名/api/factory/ping` 或 `https://你的域名:18999/factory/ping`（以后者为准，与「API 在根、直连 compose 口」时一致）。

## 与仅由 API 提供静态（不设独立静态服务器）

`.env` 中 **`DASHBOARD_PATH=/console`**（默认）时，Uvicorn 会挂载 `api/dashboard/`，**Traefik 只需**把 `Host` + 路径 反代到 `api:8088`，**不必**再配一层独立静态容器。

## Related

- 主 [README.md](../README.md) — `DASHBOARD_PATH` 与 `docker-compose`。
- [SERVER_DEPLOY_SUBPATH.md](./SERVER_DEPLOY_SUBPATH.md) — Traefik 分步、StripPrefix、WS 验收。
