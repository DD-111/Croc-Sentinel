# 生产部署：Docker 栈 + 宿主机 Nginx（子路径 UI / 根路径 API）

本文说明在 **Ubuntu VPS** 上：先起 **Mosquitto + API + OTA Nginx（Docker）**，再用 **宿主机 Nginx** 对外提供 `https://你的域名:端口/Croc_Sentinel_systems/` 静态控制台，并把 `/auth`、`/devices`、`/factory` 等反代到本机上的 **FastAPI**。

**English summary:** Bring up the Docker stack first, bind the API **only on loopback** with a non-conflicting host port, then put host Nginx in front for TLS + static SPA under `/Croc_Sentinel_systems/` and `proxy_pass` for API prefixes at the site root.

---

## 0. 架构与端口（必读）

| 服务 | 典型对外 | 说明 |
|------|-----------|------|
| **宿主机 Nginx** | `443` 或 `8088` | 浏览器只访问这里；TLS 可在此终止 |
| **API（容器）** | **`127.0.0.1:18088` → 容器 8088** | 不要与 Nginx 监听同一主机端口；见下文 `docker-compose.override.yml` |
| **Mosquitto** | `8883`（TLS） | ESP32 连 Broker，与控制台端口无关 |
| **OTA 文件 Nginx（容器）** | `9231`（宿主机 **`127.0.0.1:9231`**） | `/fw/*.bin?token=`；对外由宿主机 **443** 反代到 `9231` |

控制台 SPA 使用 `location.origin` 调 API，因此 **API 必须在同一 Origin 的根路径**（例如 `https://esasecure.com:8088/auth/...`），静态页在 **`/Croc_Sentinel_systems/`** 子路径即可。

---

## 1. 服务器准备

- Ubuntu 22.04/24.04 LTS，已安装 Docker + Compose（见主 [README.md](../README.md) §1.1）。
- 域名解析到本机（若用 TLS）。
- 防火墙放行：`443`/`8088`（你选的对公端口）、`8883`（MQTT）。OTA 推荐只走 **443** 反代到本机 **9231**，不必对公网放行 **9231**。

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx   # 若要用 Let's Encrypt
```

---

## 2. 获取代码与 `.env`

```bash
cd /opt   # 或你的部署目录
sudo git clone <你的仓库> croc_sentinel_systems
cd croc_sentinel_systems/croc_sentinel_systems   # 与 docker-compose.yml 同级
cp .env.example .env
sudo nano .env
```

按 [README.md](../README.md) §1.2 填写：`MQTT_*`、`BOOTSTRAP_*`、`CMD_AUTH_KEY`、`BOOTSTRAP_BIND_KEY`、`OTA_TOKEN`、`JWT_SECRET`、`QR_SIGN_SECRET`、`FACTORY_API_TOKEN` 等，并与固件 `config.h` **一致**。

生产建议：

- `FACTORY_UI_API_BASE=https://你的域名:对外端口`（无尾斜杠，**无** `/Croc_Sentinel_systems`）
- 出厂登记就绪后：`ENFORCE_FACTORY_REGISTRATION=1`

---

## 3. Mosquitto 密码与证书

见主 README **§1.3、§1.4.1**：生成 `mosquitto/passwd`，将 `certs/ca.crt`、`server.crt`、`server.key` 放入 `certs/`。

---

## 4. API 仅监听本机（避免与宿主机 Nginx 抢端口）

默认 `docker-compose.yml` 为 `"8088:8088"`，若宿主机 Nginx 也要占用 **8088**，会冲突。推荐增加 **`docker-compose.override.yml`**（同目录，Compose 会自动合并）：

```yaml
# docker-compose.override.yml — API 只绑定回环，宿主机 Nginx 占用公网 8088/443
services:
  api:
    ports:
      - "127.0.0.1:18088:8088"
```

然后：

```bash
docker compose build api --no-cache
docker compose up -d
docker compose ps
curl -sS http://127.0.0.1:18088/health
```

确认 `curl` 走 **18088** 成功后再配 Nginx 反代到 `http://127.0.0.1:18088`。

---

## 5. 部署静态控制台文件

将仓库内 SPA 拷贝到宿主机目录（与 Nginx `root` 一致）。以下假定使用 **`root` + 子目录**（比 `alias` + `try_files` 更不易踩坑）：

```bash
sudo mkdir -p /var/www/html/Croc_Sentinel_systems
sudo rsync -a --delete ./api/dashboard/ /var/www/html/Croc_Sentinel_systems/
sudo chown -R root:root /var/www/html/Croc_Sentinel_systems
```

以后每次更新前端：**重新 `rsync`**，或 CI 同步同一目录。

> 若静态仍完全由 **API 容器** 提供（不设子路径 Nginx），只需把 `DASHBOARD_PATH` 设为例如 `/console`，不必拷贝静态文件；本文针对 **「子路径 UI + 根路径 API」** 的宿主机 Nginx 方案。

---

## 6. 宿主机 Nginx：`server` 示例

将 `YOUR_DOMAIN`、`listen`、证书路径、`upstream_api` 换成你的环境。

**反代前缀**需覆盖当前 FastAPI 路由（含 `activity`、`events` 与 SSE）：

`auth|devices|commands|provision|dashboard|admin|health|logs|audit|factory|alerts|ota|activity|events`

```nginx
# /etc/nginx/sites-available/croc_sentinel.conf

upstream croc_api {
    server 127.0.0.1:18088;
    keepalive 32;
}

server {
    listen 8088 ssl http2;
    server_name esasecure.com;

    ssl_certificate     /etc/letsencrypt/live/esasecure.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/esasecure.com/privkey.pem;
    # 若暂未上 TLS，可改为 listen 8088; 并删掉两行 ssl_

    root /var/www/html;

    # 可选：根 URL 跳到控制台
    location = / {
        return 302 /Croc_Sentinel_systems/;
    }

    # 静态 SPA（hash 路由：主要请求 index.html 与 assets/*）
    location /Croc_Sentinel_systems/ {
        try_files $uri $uri/ /Croc_Sentinel_systems/index.html;
    }

    # Event Center SSE：关闭缓冲，避免长连接被截断
    location ^~ /events/stream {
        proxy_pass http://croc_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 86400s;
    }

    # 其余 API
    location ~ ^/(auth|devices|commands|provision|dashboard|admin|health|logs|audit|factory|alerts|ota|activity|events)(/|$) {
        proxy_pass http://croc_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
```

启用站点并重载：

```bash
sudo ln -sf /etc/nginx/sites-available/croc_sentinel.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**证书：** 若使用 Let's Encrypt：

```bash
sudo certbot --nginx -d esasecure.com
```

（把 `server_name`、证书路径与 `certbot` 域名对齐。）

---

## 7. 更新 API 代码或前端资源后

在 **`docker-compose.yml` 所在目录**：

```bash
git pull
docker compose build api --no-cache
docker compose up -d api
```

若静态由宿主机 Nginx 提供：

```bash
sudo rsync -a --delete ./api/dashboard/ /var/www/html/Croc_Sentinel_systems/
```

浏览器对控制台 **强刷**（Ctrl+F5），避免缓存旧 `app.js`。

---

## 8. 验收清单

| 检查项 | 命令或操作 |
|--------|------------|
| API 健康 | `curl -sS http://127.0.0.1:18088/health` |
| 经 Nginx 健康 | `curl -sSk https://esasecure.com:8088/health` |
| 静态页 | 浏览器打开 `https://esasecure.com:8088/Croc_Sentinel_systems/` |
| 登录 | 打开登录页，确认请求发往 `.../auth/login`（同源根路径） |
| 出厂工具 | `.env` 中 `FACTORY_UI_API_BASE` 与浏览器 **同 scheme+host+port**，`curl`/工厂 GUI 调 `/factory/ping` |

---

## 9. 故障排查

- **`502 Bad Gateway`**：`proxy_pass` 端口是否指向 **override 后的 18088**？容器是否 `Up`？`docker compose logs api`。
- **静态 404 / 白屏**：`root` 下是否存在 `Croc_Sentinel_systems/index.html` 与 `Croc_Sentinel_systems/assets/*`？`try_files` 最后一项是否为 **`/Croc_Sentinel_systems/index.html`**（带前缀）。
- **登录后 API 404**：Nginx 的 `location` 正则是否漏掉前缀（例如 `events`、`activity`）？
- **SSE 不更新**：是否为 `/events/stream` 配置了 **`proxy_buffering off`** 与较长 **`proxy_read_timeout`**？

---

## 10. 相关文档

- [NGINX_SUBPATH_UI.md](./NGINX_SUBPATH_UI.md) — 设计说明与 API 前缀表（简版）
- [README.md](../README.md) — Docker、Mosquitto、OTA 目录、日常运维
- [API_REFERENCE.md](./API_REFERENCE.md) — HTTP 端点清单

---

## Appendix — English checklist

1. Configure `.env` and TLS certs; run `docker compose up -d --build`.  
2. Add **`docker-compose.override.yml`** so **`api` publishes `127.0.0.1:18088:8088`**.  
3. **`rsync` dashboard** to `/var/www/html/Croc_Sentinel_systems/`.  
4. Install **host Nginx**: static `location /Croc_Sentinel_systems/`, `proxy_pass` API prefixes to **`127.0.0.1:18088`**, special case **`/events/stream`**.  
5. **`nginx -t`** && **`systemctl reload nginx`**; verify **`/health`** and SPA login.
