# 生产部署：Docker 栈 + Traefik（子路径控制台 / 可选 `/api` 前缀）

在 **VPS** 上运行 **Mosquitto + API + OTA 文件服务（`ota-nginx` 容器，固件 /fw，见 `docker-compose.yml`）**；**对外只使用 Traefik 占 80/443**，**不要再叠一层宿主机 Nginx** 去抢同一对端口。控制台可由 **Uvicorn 挂载** `DASHBOARD_PATH`（默认可为 `/console`）直接提供，无需再配独立静态网盘。

**English:** Bring up the Docker stack, then route **all browser traffic** through **Traefik** to the `api` service. Use **`StripPrefix("/api")` only** when the SPA’s `croc-api-base` meta is **`/api`** (see [REVERSE_PROXY_SUBPATH_UI.md](./REVERSE_PROXY_SUBPATH_UI.md)).

---

## 0. 架构与端口

| 组件 | 说明 |
|------|------|
| **Traefik** | 监听 `80/443`（或你启用的 `entrypoints`），TLS 可在这里终止 |
| **api** | 在 Compose 内 **`http://api:8088`** 访问（推荐）；宿主机可 **`127.0.0.1:18999:8088`** 做调试 `curl` |
| **Mosquitto** | 设备连 Broker（如 8883），与浏览器入口无关 |
| **ota-nginx** | 容器内 9231，**固件**路径 `/fw/…`；公网可让 Traefik 只反代 443 → `9231` 或经 `OTA_PUBLIC_BASE_URL` |

`HEAD` 探针失败时，`.env` 中 **`OTA_VERIFY_BASE_URL=http://ota-nginx:9231`** 可让 API 在 Docker 网内直达 `ota-nginx`（与宿主机 FQDN 是否可达无关）。

---

## 1. 与 Traefik 的关系（不冲突的用法）

- **只保留 Traefik 作为边缘网关**：`api` 不要和 Traefik 抢 `0.0.0.0:80` / `:443`。
- **同一条 `docker` 网络**里：`traefik` 与 `api` 互联，**router 指向 `http://api:8088`**（不要用「宿主机 18999」做唯一入口，除非 Traefik 在宿主机进程内且只能访问本机口）。
- **WebSocket**（`/events/ws` 或 带 `/api` 时 `/api/events/ws`）由 Traefik **默认可升级** 转发；若失败，再查 **StripPrefix、规则优先级、读超时**。
- **SSE**（`/events/stream`）：若经代理**缓冲**导致不吐字，可为该 `service` 加 **`loadBalancer.responseForwarding.flushInterval: "0ms"`** 或 `10ms`（以你 Traefik 大版本为准），并拉长 `transport`/`respondingTimeouts`（见官方文档）。

**不要用 `EVENT_WS_ENABLED=0` 作为第一步排障**；先修路由与 `StripPrefix`。

---

## 2. 准备代码与 `.env`

```bash
cd /opt   # 或你的目录
git clone <你的仓库> croc_sentinel
cd croc_sentinel/croc_sentinel_systems
cp .env.example .env
# 按 README 填写密钥、MQTT、OTA、JWT 等
```

---

## 3. API 端口不冲突

默认 `ports: "18999:8088"` 表示 **本机 18999 → 容器 8088**；**Traefik 不绑定 18999**。仅当你**没有**让 Traefik 在 Docker 内访问 `api:8088` 时，才在 Traefik `file` provider 里写 `http://172.17.0.1:18999` 等。

`docker compose up -d` 后本机自测（端口以你 `compose` 为准）：

```bash
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18999/health
# 预期 200
```

---

## 4. 布局 A — SPA 使用 `croc-api-base="/api"`（推荐，与 `index.html` 默认一致）

`index.html` 已含 `meta name="croc-api-base" content="/api"`。浏览器会请求例如 **`/api/auth/...`、WSS `wss://你的域名/api/events/ws`**。后端 Uvicorn **仍注册在** `/auth/...`与 `/events/...`（**无**全局 `/api` 前缀），因此 **Traefik 上必须对 API 使用 StripPrefix**：

- **规则**：`Host(你的域名) && PathPrefix("/api")`
- **中间件**：`stripprefix.prefixes="/api"`
- **Service**：`http://api:8088`（同一 `docker network`）

**Docker labels 示例**（`api` 与 `traefik` 同网络；键名以你实际 Traefik 版本为例）：

```yaml
# 在 docker-compose 的 api: 下追加（域名与 certresolver 自己替换）
labels:
  - "traefik.enable=true"
  - "traefik.docker.network=你的_stack_net"   # traefik 与 api 的公共网
  - "traefik.http.routers.croc.rule=Host(`example.com`) && PathPrefix(`/api`)"
  - "traefik.http.routers.croc.entrypoints=websecure"
  - "traefik.http.routers.croc.tls=true"
  - "traefik.http.routers.croc.tls.certresolver=letsencrypt"
  - "traefik.http.routers.croc.middlewares=croc-api-stripprefix@docker"
  - "traefik.http.middlewares.croc-api-stripprefix.stripprefix.prefixes=/api"
  - "traefik.http.services.croc.loadbalancer.server.port=8088"
  - "traefik.http.services.croc.loadbalancer.passHostHeader=true"
```

**同一路由还要覆盖控制台静态**：若用 **`DASHBOARD_PATH=/console`**, 浏览器在 **`/console`**, 不经过 `/api`；为 **`PathPrefix("/console")`** 增加 **第二个 router**（**无** StripPrefix，同一 `api:8088`），`rule=Host() && PathPrefix("/console")`，`priority` 可高于泛 `/` 站。

`FACTORY_UI_API_BASE`：

```env
FACTORY_UI_API_BASE=https://example.com/api
```

---

## 5. 布局 B — API 在站点根（无 `/api`）

1. 构建前把 `api/dashboard/index.html` 的 **`croc-api-base` 改为 `""`** 或 `"/"`（或你模板里不注入 `/api`），使 `apiBase() === location.origin`。
2. **Traefik** 上 **`PathPrefix` rule** 覆盖 `auth, devices, health, events, ...`** 的父路径，或 `Host` + 高优先级 直连 **`http://api:8088`** 服务。
3. **不配置** `StripPrefix`。

`FACTORY_UI_API_BASE`：

```env
FACTORY_UI_API_BASE=https://example.com:443
```

无尾斜杠、无路径 `/Croc_Sentinel_systems` 作为 API 前缀（那是旧文档里的静态子路径用名）。

---

## 6. 验证清单

| 项 | 操作 |
|----|------|
| API 直连 | `curl` `http://127.0.0.1:18999/health` → 200 |
| 经域名的 API | `curl` `https://example.com/api/health`（布局 A）→ 200 |
| WebSocket | 浏览器 **Network → WS** → `…/api/events/ws` 或 `…/events/ws`（布局 B）→ **101** |
| SSE | **EventStream** 中 `/api/events/stream` 或 `/events/stream` 保持打开 |

---

## 7. 故障排查

- **404 且用 `/api`**：StripPrefix 是否未生效、或**规则**未命中（中间件没挂上）。
- **WebSocket 失败**：`EVENT_WS_ENABLED=1`；在 Traefik dashboard 中看 router 与 middleware 顺序；**Cloudflare** 需开 **WebSocket**。
- **502**：`api` 是否在同网络、**8088** 对 Traefik 可达？`docker compose ps`、`logs api`。
- 固件下载 403/404：`OTA_TOKEN` 与 `ota-nginx` 的查询参数规则、**[SECURITY.md](../../SECURITY.md)** 一致（仓库根目录）。

---

## 8. 相关文档

- [REVERSE_PROXY_SUBPATH_UI.md](./REVERSE_PROXY_SUBPATH_UI.md) — 前缀与 Factory 基址
- [README.md](../README.md) — 日常运维
- [API_REFERENCE.md](./API_REFERENCE.md) — 端点列表

---

## Appendix — English checklist

1. Copy `.env` and fill secrets; `docker compose up -d --build`.  
2. **Traefik only on 80/443**; route **`http://api:8088`** (same network).  
3. If `croc-api-base` is **`/api`**, add **`StripPrefix /api`**.  
4. Verify **HTTP `/health`**, then **WSS 101** on the events path.  
5. Do not disable `EVENT_WS_ENABLED` before fixing the route.
