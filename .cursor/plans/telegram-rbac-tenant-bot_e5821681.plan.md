---
name: telegram-rbac-tenant-bot
overview: Implement a shared Telegram bot with per-chat tenant scoping, fine-grained Telegram capabilities managed by superadmin, and per-admin bot onboarding with superadmin global visibility.
todos:
  - id: binding-model
    content: Add telegram chat binding storage and resolve Principal from chat_id in webhook flow.
    status: pending
  - id: command-targeting
    content: Implement single/many/all command parsing and execution via existing guarded command path.
    status: pending
  - id: telegram-capabilities
    content: Add tg_* capability switches and enforce per-command authorization.
    status: pending
  - id: admin-management-api-ui
    content: Expose superadmin management endpoints and dashboard controls for bindings and Telegram permissions.
    status: pending
  - id: safety-controls
    content: Add confirmation token for broad actions, per-chat rate limit, and complete audit entries.
    status: pending
  - id: tenant-routing-validation
    content: Validate tenant isolation for admin/user and global visibility for superadmin across logs/devices/commands.
    status: pending
isProject: false
---

# Telegram 多租户权限化方案

## 目标
- 支持 Telegram 指令对 **单设备** / **多设备** / **全设备** 操作（如 siren on/off、single test、all test）。
- superadmin 可给 admin/user 下发细粒度 Telegram 能力开关。
- 每个 admin 可绑定自己的 Telegram chat，仅看到/操作自己范围设备。
- superadmin 可接收全局告警与全局查询结果。

## 设计原则
- 使用 **一个共享 Bot**（你已选择），通过 `chat_id -> 平台账号` 映射实现隔离。
- 所有 Telegram 命令走现有 API 权限体系，不绕过 `require_capability`、owner/zone 校验。
- 能力开关与 Dashboard 用户策略对齐，避免双重权限系统冲突。

## 数据与权限模型
- 在 [E:/Croc Sentinel/croc_sentinel_systems/api/app.py](E:/Croc Sentinel/croc_sentinel_systems/api/app.py) 的 DB 初始化区新增：
  - `telegram_chat_bindings(chat_id, username, role_snapshot, enabled, created_at, updated_at)`
  - `telegram_chat_subscriptions(chat_id, mode, owner_scope)`（可合并到 bindings）
- 在现有 `role_policies` / user policy 基础上新增 Telegram 细粒度字段（建议）：
  - `tg_view_logs`
  - `tg_view_devices`
  - `tg_siren_on`
  - `tg_siren_off`
  - `tg_test_single`
  - `tg_test_bulk`
- superadmin 通过现有用户策略接口（或新增 Telegram 专用接口）下发上述权限。

## 命令能力（含单设备/多设备）
- 查询类：
  - `devices [N]`
  - `logs [N]`
  - `device <id> status`
- 控制类：
  - `siren on <device_id> [duration_ms]`
  - `siren on many <id1,id2,...> [duration_ms]`
  - `siren on all [duration_ms]`
  - `siren off <device_id|many|all>`
  - `test <device_id>`
  - `test many <id1,id2,...>`
  - `test all`
- 解析与执行统一在 webhook handler 内，最终调用现有：
  - `resolve_target_devices(...)`
  - `publish_command(...)`
  - `/devices/{id}/self-test` 等现有受控链路。

## 多租户隔离逻辑
- webhook 收到 `chat_id` 后：
  1. 查 `telegram_chat_bindings` 得到绑定用户。
  2. 构造对应 `Principal`（admin/user/superadmin）。
  3. 用该 Principal 走现有 owner+zone 过滤与 capability 校验。
- admin/user：仅返回自己可见设备/日志。
- superadmin：允许 `all` 视角。

## superadmin 管理能力
- 在 [E:/Croc Sentinel/croc_sentinel_systems/api/app.py](E:/Croc Sentinel/croc_sentinel_systems/api/app.py) 新增管理接口：
  - 绑定管理：`/admin/telegram/bindings`（list/add/disable/remove）
  - 权限管理：沿用 `/auth/users/{username}/policy` 或新增 `/admin/telegram/policy/{username}`
- 在 [E:/Croc Sentinel/croc_sentinel_systems/api/dashboard/assets/app.js](E:/Croc Sentinel/croc_sentinel_systems/api/dashboard/assets/app.js) 的 admin 页增加 Telegram 权限开关区。

## 消息路由与订阅
- 告警推送：
  - admin 仅收到其 owner_scope 设备告警。
  - superadmin 可额外订阅全局告警。
- 命令回复：
  - 默认仅回复发起命令的 chat。
  - 关键操作（如 all siren on）记录审计并可抄送 superadmin 审计 chat（可选）。

## 安全与风控
- 保留并强制：`TELEGRAM_COMMAND_SECRET` + `TELEGRAM_COMMAND_CHAT_IDS`（白名单）。
- 新增命令风控：
  - `all` 操作需要二次确认（`confirm <token>`）
  - 速率限制（每 chat 每分钟命令数）
  - 审计日志包含：chat_id、username、target_count、cmd、结果。

## 关键文件改动清单
- 后端核心：
  - [E:/Croc Sentinel/croc_sentinel_systems/api/app.py](E:/Croc Sentinel/croc_sentinel_systems/api/app.py)
  - [E:/Croc Sentinel/croc_sentinel_systems/api/security.py](E:/Croc Sentinel/croc_sentinel_systems/api/security.py)
  - [E:/Croc Sentinel/croc_sentinel_systems/api/telegram_notify.py](E:/Croc Sentinel/croc_sentinel_systems/api/telegram_notify.py)
- 配置：
  - [E:/Croc Sentinel/croc_sentinel_systems/.env.example](E:/Croc Sentinel/croc_sentinel_systems/.env.example)
- 管理 UI：
  - [E:/Croc Sentinel/croc_sentinel_systems/api/dashboard/assets/app.js](E:/Croc Sentinel/croc_sentinel_systems/api/dashboard/assets/app.js)
  - [E:/Croc Sentinel/croc_sentinel_systems/api/dashboard/assets/app.css](E:/Croc Sentinel/croc_sentinel_systems/api/dashboard/assets/app.css)

## 实施顺序（最短可用路径）
1. 先做 `chat_id -> username` 绑定表与 webhook Principal 注入。
2. 做单设备/多设备/all 指令解析与权限校验。
3. 增加 Telegram 细粒度 capability 字段与 superadmin 下发能力。
4. 再补 Dashboard 管理界面与二次确认/限流。

## 验收标准
- admin chat 发 `devices/logs` 只能看到自己设备。
- admin chat 对非自己设备执行 `siren/test` 返回 forbidden。
- superadmin chat 可执行全局查询与全局命令（受确认机制保护）。
- user 若无 `tg_*` capability，对应命令被拒绝且有审计日志。