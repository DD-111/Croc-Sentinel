# Croc Sentinel API 参考

> 范围：`croc_sentinel_systems/api/app.py` 中导出的所有 HTTP 端点（不含挂载的
> 静态前端）。 编号列出，便于前端 / 第三方对接时快速索引。

## 约定

- **Base URL**: VPS 上 `uvicorn` 或 `gunicorn` 监听的地址。默认 `:8000`。
- **认证头**：除标注 `公开` 的端点外，全部需要
  `Authorization: Bearer <jwt>` 或 `Authorization: Bearer <API_TOKEN>`
  （后者等价于 superadmin）。
- **角色层级**：`superadmin > admin > user`。表格中的 `最低角色`
  表示服务端会 `assert_min_role` 的值。
- **JSON**：请求体一律 `application/json`，响应 `application/json`。
- **时间**：所有 `*_at` / `probe_ts` 均为 UTC ISO-8601（带 `+00:00`）。

---

## 1. 身份 & 注册 (`/auth/*`)

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 1 | POST | `/auth/signup/start` | 公开 | 公开管理员注册第一步：申请 OTP |
| 2 | POST | `/auth/signup/verify` | 公开 | 校验 OTP；创建 `pending` 或 `awaiting_approval` admin |
| 3 | POST | `/auth/activate` | 公开 | admin 创建的 user 使用 OTP 激活账号 |
| 4 | POST | `/auth/code/resend` | 公开 | 重发 OTP（带冷却时间） |
| 5 | GET  | `/auth/signup/pending` | superadmin | 列出待审批 admin |
| 6 | POST | `/auth/signup/approve/{username}` | superadmin | 通过 admin 审批 |
| 7 | POST | `/auth/signup/reject/{username}` | superadmin | 拒绝 admin 审批 |
| 8 | POST | `/auth/login` | 公开 | 用户名 / 密码换 JWT（含登录限流 & 状态检查） |
| 9 | GET  | `/auth/me` | user | 返回当前主体信息 |
| 10 | GET | `/auth/admins` | admin | 列出 admin 用户 |
| 11 | GET | `/auth/users` | admin | 列出 user（admin 只看自己下属） |
| 12 | POST | `/auth/users` | admin | 新建 user；**禁止** 创建 superadmin |
| 13 | DELETE | `/auth/users/{username}` | admin | 删除 user |
| 14 | GET | `/auth/users/{username}/policy` | admin | 读用户 RBAC 策略 |
| 15 | PUT | `/auth/users/{username}/policy` | admin | 写用户 RBAC 策略 |

**离线忘记密码（RSA 公钥在服务器、私钥仅在运维离线机）**

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 15a | GET | `/auth/forgot/enabled` | 公开 | `{enabled: bool}` 是否已配置 `PASSWORD_RECOVERY_PUBLIC_KEY_*` |
| 15b | POST | `/auth/forgot/start` | 公开 | body `{username}` → `{recovery_blob_hex, ttl_seconds, blob_byte_len}`；`recovery_blob_hex` 为纯十六进制，**字符数 = 2×blob_byte_len**（RSA-2048 + 默认 PAD 时约 **1602**）；按 IP 限流 |
| 15c | POST | `/auth/forgot/complete` | 公开 | body `{username, recovery_plain, password, password_confirm}`；`recovery_plain` 为离线脚本解密后的一行 JSON |

表 `password_reset_tokens`：`jti, username, secret_hash, created_at, expires_at_ts, used, request_ip, used_at`。  
表 `forgot_password_attempts`：按 IP 滑动窗口限流。

## 2. 设备上线 / 出厂 (`/provision/*`, `/factory/*`)

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 16 | POST | `/provision/challenge/request` | 公开 | 设备端挑战请求（enforce 模式下走硬件证书） |
| 17 | POST | `/provision/challenge/verify` | 公开 | 挑战响应验证 |
| 18 | GET  | `/provision/pending` | admin | 列出"已连线但未认领"的设备 |
| 19 | POST | `/provision/claim` | admin | admin 认领 pending 设备，颁发永久 MQTT 凭据 |
| 20 | POST | `/provision/identify` | admin | 根据序列号 / 二维码查询设备状态（未注册/可认领/已认领/出厂禁用） |
| 20b | GET | `/factory/ping` | superadmin **或** `X-Factory-Token` | 工厂脚本连通性探测（不写库） |
| 21 | POST | `/factory/devices` | superadmin **或** `X-Factory-Token` | 出厂批量录入 (serial, mac, qr) |
| 22 | GET  | `/factory/devices` | superadmin | 列出 factory 清单 |
| 23 | POST | `/factory/devices/{serial}/block` | superadmin | 封禁序列号（不可再被认领） |

## 3. 设备吊销 & 查询 (`/devices/*`)

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 24 | GET | `/devices` | user | 按 tenant 过滤的设备清单 |
| 25 | GET | `/devices/{device_id}` | user | 单台设备详情 |
| 26 | GET | `/devices/{device_id}/messages` | user | 最近 MQTT 消息（ack/事件/状态/心跳） |
| 27 | GET | `/devices/revoked` | admin | 已吊销设备列表 |
| 28 | POST | `/devices/{device_id}/revoke` | admin | 吊销设备 |
| 29 | POST | `/devices/{device_id}/unrevoke` | admin | 取消吊销 |

## 4. 命令 & 警报 (`/commands/*`, `/alerts*`, `/alarms*`)

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 30 | POST | `/devices/{device_id}/commands` | user（需 `can_send_command`） | 下发任意 MQTT 命令 |
| 31 | POST | `/devices/{device_id}/alert/on` | user（需 `can_alert`） | 打开警报（siren_on） |
| 32 | POST | `/devices/{device_id}/alert/off` | user（需 `can_alert`） | 关闭警报 |
| 33 | POST | `/alerts` | user（需 `can_alert`） | 批量触发警报（tenant 内） |
| 34 | POST | `/devices/{device_id}/self-test` | user | 触发设备 self_test |
| 35 | POST | `/devices/{device_id}/schedule-reboot` | admin | 预约重启 |
| 36 | GET | `/devices/{device_id}/scheduled-jobs` | admin | 查看该设备计划任务 |
| 37 | POST | `/commands/broadcast` | admin | 对 tenant 内设备批量下发 |
| 38 | GET | `/alarms` | user | 警报历史（tenant 过滤） |
| 39 | GET | `/alarms/summary` | user | 警报摘要 / 聚合统计 |

## 5. SMTP 通知 & 收件人

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 40 | GET | `/admin/alert-recipients` | admin | 列出该 admin 的邮件接收人 |
| 41 | POST | `/admin/alert-recipients` | admin | 新增接收人 |
| 42 | PATCH | `/admin/alert-recipients/{rid}` | admin | 修改 |
| 43 | DELETE | `/admin/alert-recipients/{rid}` | admin | 删除 |
| 44 | GET | `/admin/smtp/status` | admin | SMTP 状态 / 队列深度 |
| 45 | POST | `/admin/smtp/test` | admin | 发送测试邮件 |

## 6. OTA（新：活动流程）

全流程：superadmin 发起活动 → 每个 admin 自己看到 → admin 接受 → 服务端
HEAD 校验 URL → 推送 OTA 命令 → 设备 `ota.result` 回传 → 任一失败自动回滚到
升级前版本。

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 46 | GET | `/ota/firmwares` | superadmin | 读取 `OTA_FIRMWARE_DIR` 下的 .bin 列表 |
| 47 | POST | `/ota/broadcast` | superadmin | **旧** 一把梭下发（保留兼容） |
| 48 | POST | `/ota/campaigns` | superadmin | 创建新活动（`target_admins=["*"]` 全部 admin） |
| 48b | POST | `/ota/campaigns/from-upload` | superadmin | `multipart/form-data`：上传 `.bin` 到 `OTA_FIRMWARE_DIR`、用 `OTA_PUBLIC_BASE_URL` 拼 URL、**HEAD 校验** 后建活动（与 48 同表） |
| 49 | GET | `/ota/campaigns` | admin | 列出与我相关的活动 |
| 50 | GET | `/ota/campaigns/{campaign_id}` | admin | 活动详情（含设备级进度） |
| 51 | POST | `/ota/campaigns/{campaign_id}/accept` | admin | 接受 → 验证 URL → 推送到本 admin 全部设备 |
| 52 | POST | `/ota/campaigns/{campaign_id}/decline` | admin | 拒绝此次升级 |
| 53 | POST | `/ota/campaigns/{campaign_id}/rollback` | admin | 手动回滚（admin 仅自己，superadmin 可全员） |

## 7. 系统 / 运维

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 54 | GET | `/health` | 公开 | 健康检查（MQTT + DB） |
| 55 | GET | `/dashboard/overview` | user | 仪表盘聚合数据 |
| 56 | GET | `/audit` | admin | 审计事件流 |
| 57 | GET | `/logs/messages` | admin | 原始 MQTT 消息（按设备 / 主题过滤） |
| 58 | GET | `/logs/file` | superadmin | API 进程日志 |
| 59 | GET | `/admin/presence-probes` | admin | 12h 无信号 ping 探测记录（admin 仅见自己） |
| 60 | GET | `/admin/backup/export` | superadmin | 导出备份 |
| 61 | POST | `/admin/backup/import` | superadmin | 恢复备份 |

## 8. 事件中心 `/events/*`（实时日志）

> **已实现**。统一把 audit / alarm / ota / presence / provision / device / auth /
> system 八类事件收进 `events` 表，同时通过 SSE 实时广播。
> `/subscribe/webhooks` 仍是占位，未实现。

| # | 方法 | 路径 | 最低角色 | 说明 |
|---|------|------|----------|------|
| 62 | GET | `/events` | user | 历史分页查询，`min_level` / `category` / `device_id` / `q` / `since_id` / `limit` |
| 63 | GET | `/events/stream` | user | **SSE 长连接**，增量推送事件；`?token=` 支持 EventSource |
| 64 | GET | `/events/categories` | user | 返回合法的 `levels` 和 `categories` 列表 |
| 65 | GET | `/events/export.csv` | user | 下载 CSV（`Authorization` Bearer；筛选参数同 `/events`，`limit` 默认 5000、最大 20000） |
| 66 | GET | `/events/stats/by-device` | user | `hours`（默认 168）+ `limit`；按 `device_id` 聚合事件条数 |

### 可见性（服务端自动按角色过滤）

- **superadmin**：全系统事件
- **admin**：`owner_admin == self` 或 `actor == self` 或 `target == self`
- **user**：上级 admin 租户内，且与自己相关 或 `level ∈ {warn, error, critical}`

### SSE 协议

```
GET /events/stream?min_level=warn&category=alarm&backlog=100&token=<jwt>
```

- 每条事件 SSE 格式：`id: <rowid>` / `event: <event_type>` / `data: <json>`。
- 服务端每 `EVENT_SSE_KEEPALIVE_SECONDS` 秒发送 `: keepalive` 注释，防止
  反向代理（Nginx / Cloudflare）掐断空闲连接。
- 客户端慢 → 服务端队列满 → 丢弃最老事件并在 `keepalive` 行里带
  `dropped=N`，客户端可在 UI 上提示。
- 断线重连：浏览器的 `EventSource` 自动带上 `Last-Event-ID`；当前版本
  **不保证**重连后完全补齐（只补当前 ring buffer 内的），需要全量可再
  调一次 `GET /events?since_id=<last>`。

### 事件命名约定（event_type）

| category | 示例 event_type | 级别 |
|----------|----------------|------|
| `alarm` | `alarm.trigger` | warn |
| `ota` | `ota.device.result` / `audit.ota.campaign.accept` | info / warn / error |
| `presence` | `presence.probe.sent` / `presence.probe.acked` | warn / info |
| `provision` | `provision.bootstrap_register` / `audit.device.claim` | info |
| `device` | `device.heartbeat` / `device.status` / `device.ack` / `device.event.*` | debug / warn |
| `auth` | `auth.login.rate_limited` / `audit.auth.login.ok` | info / warn / error |
| `audit` | `audit.<原 action>` | info / warn |
| `system` | `stream.hello` | info |

### 资源占用

- 按默认 retention（`debug 3d / info 14d / warn 30d / error 90d / critical 365d`），一个
  中等规模部署（1k 设备、每台每天 ~100 事件）在 SQLite 里约占
  **2–4 GB**，远低于 100 GB NVMe 预算。
- 内存：ring buffer 2000 条 × 500 B ≈ 1 MB；每路 SSE 客户端 ≈ 250 KB；128
  并发最坏 32 MB。

## 9. 预留：`/subscribe/webhooks`（尚未实现）

用于后端推送到外部 URL（Slack、企业微信机器人、PagerDuty）。当前未实现，
如果需要，只需订阅 `/events/stream` 并按 category 分发即可。

## 10. 约定 & 错误码

| HTTP | 含义 |
|------|------|
| 200  | OK |
| 400  | 参数不合法 |
| 401  | 缺 Authorization / JWT 过期 |
| 403  | 角色不足 / 不是你名下的资源 |
| 404  | 资源不存在 |
| 409  | 冲突（如重复注册） |
| 429  | 速率限制（登录失败 / 注册尝试） |
| 502  | 下游失败（MQTT 推送失败、SMTP 发送失败） |

所有错误体均为 `{"detail": "<短说明>"}`，前端用 `toast(err.message)` 展示即可。

## 11. MQTT Topic 对照（设备侧 ↔ API 侧）

| 方向 | Topic | 说明 |
|------|-------|------|
| 上 | `sentinel/<id>/heartbeat` | 事件触发心跳（含 `reason`） |
| 上 | `sentinel/<id>/status`    | 连接/吞吐/电压 |
| 上 | `sentinel/<id>/event`     | `alarm.trigger`, etc. |
| 上 | `sentinel/<id>/ack`       | 命令 ack + `ota.result` |
| 上 | `sentinel/bootstrap/register` | 出厂首次上线登记 |
| 下 | `sentinel/<id>/cmd`       | 服务端 → 设备命令（含 `ping`、`siren_on`、`ota(campaign_id,url,fw)`） |
| 下 | `sentinel/bootstrap/<mac>/assign` | 给设备下发永久凭据 |
