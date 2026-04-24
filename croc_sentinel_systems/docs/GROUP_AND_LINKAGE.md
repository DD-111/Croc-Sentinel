# 设备组与联动（notification_group）使用说明

本文说明：**Dashboard 里「组」如何配置**、**兄弟机（sibling）在服务端如何判定与下发**、**已经实现什么**、以及**做不到什么**。技术实现以数据库 `device_state.notification_group` + `device_ownership.owner_admin` 为真源；固件**不保存**组名字符串。

---

## 1. 核心概念

| 概念 | 说明 |
| --- | --- |
| **组名（组键）** | 设备 **「Notification group」** → `device_state.notification_group`。用于「谁和谁是兄弟」以及组卡展示。 |
| **真源在云端** | 组名只存在于 **API / 数据库**；固件**没有**该字段的 NVS 或编译期业务组名。改组名在 **Console** 或 **`PATCH /devices/{id}/profile`**。 |
| **按租户（owner）** | 兄弟机列表只包含 **`device_ownership.owner_admin` 与源设备相同** 的设备；**不会**跨 admin / 跨租户 fan-out。 |
| **无 owner（历史未认领池）** | 仅与「同样无 `device_ownership` 行、未 revoke」的设备之间按组名规则联动；**不会**误入已认领租户的设备。 |
| **Zone** | 在「同 owner + 同组（归一化匹配）」基础上，若事件里 `source_zone` **不是** `all` / `*`，则只选 **`device_state.zone` 与该 zone 完全相同** 的兄弟机。源为 `all`/`*` 时不按 zone 过滤。 |

---

## 2. 兄弟机机制（服务端，真实代码路径）

### 2.1 何时会算「兄弟」？

仅在设备经 MQTT 上报 **`event` 且 `type == alarm.trigger`** 时，由 API 内 **`_fan_out_alarm`** 处理（异步线程，避免阻塞 MQTT 入站）。

### 2.2 兄弟列表怎么来？（`_tenant_siblings`）

1. 读取源设备的 **`owner_admin`**（`device_ownership`）及 **`notification_group`**、事件里的 **`source_zone`**。  
2. 对源设备的组名做 **`_sibling_group_norm`**：**trim → Unicode NFC → 折叠连续空白 → casefold（大小写不敏感）**。若归一化后为空 → **兄弟列表为空**（不联动其它机）。  
3. 在库中查询候选设备：  
   - **有 owner**：`JOIN device_ownership`，`owner_admin` 相同，`revoked_devices` 无记录，且 **`notification_group` 经 trim 非空**。  
   - **无 owner**：仅 `device_ownership` 为空的未认领设备，且未 revoke，组名非空。  
4. 可选 **zone 过滤**：`source_zone` 存在且不是 `all`/`*` 时，`device_state.zone` 必须与其一致。  
5. 对每条候选的 `notification_group` 再做 **`_sibling_group_norm`**，与源的 norm **相等** 才计入兄弟。  
6. **去掉源设备自身**（报警路径上 `include_source` 对遥控/静音/暂停/恐慌均为 false）。  
7. **去重**；按 **`device_id` 字典序** 排序后取前 **`ALARM_FANOUT_MAX_TARGETS`**（默认 **200**，环境变量 `ALARM_FANOUT_MAX_TARGETS`）台，顺序稳定、便于复现与分批策略。实际命中数 **`eligible_total`**、是否触顶 **`fanout_capped`** 写入审计 `alarm.fanout` 与 **`GET /devices/{id}/siblings-preview`**。
8. **重复事件抑制**：同一设备在短时间内重复上报同一 `alarm.trigger`（优先 `nonce`，回退 `ts+trigger_kind+source_zone`）会被抑制，避免 QoS1 重投导致兄弟重复鸣响；窗口由 **`ALARM_EVENT_DEDUP_WINDOW_SEC`**（默认 8 秒）控制。  

### 2.3 兄弟收到什么 MQTT？（`_fan_out_alarm`）

在 **`should_fanout == true`** 时，对兄弟逐台 **`publish_command`**（失败会 **sleep 0.4s 后仅对失败 id 重试一次**）。下发前对目标 **`device_id` 集合单次批量** 解析 MQTT **`cmd_key`**（`provisioned_credentials`），避免每台兄弟各打一次数据库。

| `trigger_kind`（固件上报） | 策略门控 | 下发命令 | 时长参数 |
| --- | --- | --- | --- |
| `remote_silent_button` | `remote_silent_link_enabled` | `alarm_signal` `{ kind: "silent" }` | — |
| `remote_pause_button` | `remote_loud_link_enabled` | `siren_off` | — |
| `panic_button` | `panic_link_enabled` | `siren_on` | **`panic_fanout_duration_ms`**（默认 **300000**，即 5 分钟，可调 `DEFAULT_PANIC_FANOUT_MS`） |
| `remote_button` / `remote_loud_button` / `network` / `group_link` 等 loud 类 | `remote_loud_link_enabled` | `siren_on` | **`remote_loud_duration_ms`**（默认 **180000**，即 3 分钟，链到 `ALARM_FANOUT_DURATION_MS` / `DEFAULT_REMOTE_FANOUT_MS`） |

**源设备本机**：恐慌时由 **固件本机 GPIO / 本地警笛** 负责（文档与代码注释一致）；服务端 **只给兄弟** 发 MQTT，**不发回源设备**（上述路径 `include_source = false`）。  
**说明**：策略里的 **`panic_local_siren`** 在库中保存，供控制台与设备侧约定；**`_fan_out_alarm` 不会**在服务器上代替固件「关/开本机警笛」——本机行为以固件为准。

**未覆盖在表里的 `trigger_kind`**：若不在 fan-out 集合内，则 **`should_fanout` 为 false**，兄弟 **不会** 收到本条事件的联动命令（仍可能记 alarm 行、邮件等，视实现而定）。

### 2.4 策略从哪里来？（与组名「归一化」一致）

- **联动开关与时长** 来自 **`_trigger_policy_for(owner_admin, scope_group)`**。  
- **`scope_group` 现在统一按 `_sibling_group_norm` 归一化后做 SQL 等值匹配**（与兄弟匹配同一套：`trim → NFC → 折叠空白 → casefold`）。  
- 写入端（`PUT /devices/{id}/trigger-policy`）也会把 `scope_group` **以归一化形态存盘**，`UPSERT` 键为 `(owner_admin, 归一化 scope_group)`；因此「`Warehouse` / `warehouse` / `  warehouse  `」这类历史写法 **会自动落入同一条策略行**，不会再分叉。  
- **启动时自动迁移**：`init_db` 扫描 `trigger_policies`，把对同一 `owner_admin` 归一化相同的多行合并（`updated_at` 最新的保留，其余删除），并把 `scope_group` 改写为归一化键。迁移幂等，日志里失败也不会阻塞启动。

策略字段（设备详情 → Trigger policy，**属主租户可写**；纯 share 用户只读说明）包括：`panic_local_siren`、`panic_link_enabled`、`panic_fanout_duration_ms`、`remote_silent_link_enabled`、`remote_loud_link_enabled`、`remote_loud_duration_ms`、`fanout_exclude_self` 等。

---

## 3. 已经做到什么（能力清单）

| 能力 | 说明 |
| --- | --- |
| **云端统一组名** | 列表、详情、组卡与 fan-out 使用的组名均来自 **`device_state.notification_group`**。 |
| **兄弟机 fan-out** | 满足：**非空组（归一化后）**、**同 owner**、**zone 规则**、**未 revoke**、**策略允许**、**在台数上限内**；对兄弟发 **MQTT cmd**（见上表）。 |
| **组名归一化匹配** | 减少因空格、大小写、NFC 形态不一致导致「明明一组却不联动」。 |
| **空组不 fan-out** | 源组名归一化后为空 → **无兄弟目标**。 |
| **MQTT 发布失败自恢复** | 首轮失败设备 id 会 **再试发布一次**（间隔约 0.4s）。 |
| **默认时长** | 远程 loud 类兄弟 **`siren_on` 默认 180s×10=3min**；恐慌兄弟 **默认 5min**（可用环境变量与策略覆盖）。 |
| **审计与事件** | `alarm.trigger` / `alarm.fanout` 等便于排查。 |
| **Console 组卡** | 与 `GET /devices` 同步；组卡上的批量鸣笛等走 **`/alerts` 或组 apply**，与「设备事件触发的兄弟 fan-out」是 **不同路径**（后者依赖固件上报 `alarm.trigger`）。 |

---

## 4. 不能做到 / 限制与注意（避免误解）

| 项 | 说明 |
| --- | --- |
| **固件不能「烧录组名」当业务真源** | 兄弟关系由 **云端库表** 决定；固件只上报事件与 zone。 |
| **离线 / 未连 MQTT**（新版行为） | 服务端 **已补发**：每次 `publish_command` 都落库到 `cmd_queue`；兄弟机离线时该行保持 `pending`。设备恢复后有 **两条补发路径**：① 服务端在收到第一个 `heartbeat/status` 时若与上次 `updated_at` 间隔 ≥ `CROC_CMD_QUEUE_REPLAY_GAP_S`（默认 60s）会把 pending 行 **重投** MQTT；② 固件在 MQTT 持续掉线 ≥ `COMMAND_HTTP_FALLBACK_ARM_MS`（默认 120s）时启动 **HTTP 备用拉取**（`POST /device/commands/pending`，见 §7）。TTL 为 `CROC_CMD_QUEUE_TTL_S`（默认 24h），过期或已 ACK 的行会在后台清理。 |
| **超过上限** | 同一事件最多 **`ALARM_FANOUT_MAX_TARGETS`** 台兄弟（默认 **200**，`.env`）；超出部分**不会**在本轮 fan-out 中下发，超大组需**分批触发**或**提高上限**（运维权衡）。 |
| **调度命令超时** | 与兄弟 fan-out **并列**的运维语义：服务端 **`presence_probes`** 里已发出、仍为 `sent` 的探测，若 **8 分钟内**无设备侧可被核销的流量（任意 `ack` / `status` / `heartbeat` / `event`），则 **标记 `timeout`**，避免长期占坑；**`scheduled_commands`** 中超过计划执行时间 **8 分钟**仍为 `pending` 的行 **标记 `failed`**。默认 **`PRESENCE_PROBE_ACK_TIMEOUT_SEC`** / **`SCHEDULED_CMD_STALE_PENDING_SEC`** = **480**。 |
| **跨租户** | **绝不**向其它 `owner_admin` 的设备发兄弟联动命令。 |
| **共享设备（ACL）** | 被 share 的设备仍属 **原 owner** 的 `notification_group`；**策略**仅 **属主** 可改。兄弟 fan-out **仍按 owner + 组** 计算，与「谁能点 Dashboard」是两条权限线。 |
| ~~**策略键与归一化不一致**~~ | *已修复*：`scope_group` 读/写都走 `_sibling_group_norm`，兄弟匹配与策略键对齐；启动时一次性迁移合并旧的分裂行。参见 §2.4。 |
| **Dashboard 组卡「Alarm ON」** | 多为 **`/alerts` 或组 apply** 直接对所选 `device_id` 发 MQTT，**不是**走「某台先报 `alarm.trigger` 再兄弟 fan-out」那条链。 |
| **Delay 配置语义** | `delay_seconds` 仅保留为网页配置字段（用于可视化与策略档案）；实际组卡 apply 按**立即下发**执行，不再在服务端排队延迟执行。 |
| **Superadmin 组卡 owner 混选** | 允许 superadmin 跨 owner 自由编排组卡；组卡统计按当前设备 `owner_admin + notification_group` 真实切片显示。admin / user 仅可见和操作自己租户设备（严格数据隔离，不透传跨租户 ACL 视图）。 |
| **仅改浏览器本地** | 组卡展示用 `localStorage` 可丢；**数据库组名不变**。 |

---

## 4.1 Auto-Reconcile（cmd_key mismatch 自愈）

- **Detect key mismatch**：当设备 `ack` 报文出现 `ok=false` 且 `detail` 为 `bad key` / `device cmd_key unset`（等）时，服务端自动入队 reconcile。  
- **Auto trigger re-claim**：调度器执行 reconcile 时，会给该设备生成新 `mqtt_username` / `mqtt_password` / `cmd_key`，并复用当前 `pending_claims.claim_nonce` 重新发布 `bootstrap.assign`。  
- **Auto clear stale pending_claims**：定时清理长时间未刷新的 `pending_claims`（默认 24h，`PENDING_CLAIM_STALE_SECONDS`）。  
- **Auto rebind device**：按 `mac_nocolon` 对齐 `pending_claims.proposed_device_id` 到当前 `provisioned_credentials.device_id`，避免 pending 与已注册 ID 漂移。  

---

## 5. 与《白话总览》的边界

`OVERVIEW_CN.md` 里「按一下全响」是概括。**实际上**：兄弟是否响取决于 **组名（归一化）+ owner + zone + 策略 + 在线 + 上限**，且 **恐慌时本机由固件、兄弟由 MQTT**。

---

## 6. 固件侧排查：像「兄弟机失效」时是否怪固件？

**结论先说**：兄弟名单与策略在 **API + 数据库** 里算；固件**不负责**「谁和谁是兄弟」。固件只负责在按键/逻辑满足时，往 **`…/{deviceId}/event`** 发一条 JSON，且 **`type` 必须为 `alarm.trigger`**。若这条消息**没到服务器**或**字段与库不一致**，现象会像「兄弟机全没了」。

对照仓库 **`Croc Sentinel.ino`** 里 **`publishAlarmEvent`**（约 1467 行起）与 **`handleTriggerInput`**（约 2363 行起），可按下面逐项排除：

| 现象 / 怀疑 | 固件或链路上可能原因 | 建议 |
| --- | --- | --- |
| **串口有 `[trigger] …` 但兄弟不响** | 云端 **组名为空 / owner 不同 / zone 不一致 / 策略关** 等（不是固件算兄弟）。 | 看 API 事件 `alarm.fanout`、`device_state.notification_group`、各机 **zone** 与 Dashboard 是否一致。 |
| **串口有 `alarm JSON serialize truncated; not sent`** | **`StaticJsonDocument<320>` + `buf[320]`** 序列化失败，**整条 `alarm.trigger` 未发出**。 | 缩短 `deviceId`/`deviceZone` 异常过长不现实时，需改固件增大 buffer / `StaticJsonDocument`。 |
| **`alarm.trigger queued (MQTT offline or publish failed)`** | **`publishRaw`** 在 **未连接** 或 **`mqttClient.publish` 失败** 时入 **离线队列**；若长期发不出去，**服务器永远收不到**，兄弟不会 fan-out。 | 查 MQTT 连接、TLS、broker 配额；重连后看离线队列是否刷出（`flushOfflineQueue` 每次最多 3 条）。 |
| **本机有反应、兄弟始终没有** | 本机 GPIO 与 **MQTT 上报** 是两条路径（恐慌先 `activateSiren` 再 `publishAlarmEvent`）。 | 确认 **event 主题** 上是否有 `alarm.trigger`（broker 抓包 / API 日志）。 |
| **`trigger_kind` 不对** | 固件里写死为 `panic_button` / `remote_loud_button` / `remote_silent_button` / `remote_pause_button`；若 GPIO 接错或防抖逻辑误触，会发**别类**事件，策略可能关掉该路径。 | 对照按键接线；看 API 里 `triggered_by` 与 `trigger_policies`。 |
| **Zone 导致「只有本区不响别区」** | 固件把 **`deviceZone`** 写入 **`source_zone`**；API 在 `source_zone` **不是** `all` / `*` 时，要求 **`device_state.zone` 与 `source_zone` 字符串完全一致**（**区分大小写**）。 | 全厂用 **`all`**（默认 `DEVICE_ZONE`）或保证 **Dashboard 里 zone 与设备 NVS `zone` 同一拼写**。 |
| **连按没第二次** | **`alarmInCooldown()`**：距上次 **`publishAlarmEvent` 结束** 不足 **`ALARM_COOLDOWN_MS`**（如 `config.h.example` 里 5000ms）会 **不再发** MQTT（恐慌/大声在冷却内直接不触发上报）。 | 串口看是否在冷却内；调大间隔或确认是否为预期防抖。 |

**不是固件 bug 的常见根因**：`notification_group` **只在云端**维护——固件注释已写明；若 Console 里组名为空，**API 侧兄弟列表为空**，与烧录的 OTA 版本无关。

---

## 7. 持久化命令队列 + 非抢占 HTTP 备用通道

> **目标**：兄弟机 fan-out 时如果某台恰好掉线，**不再永远错过**这次指令；设备上线后会 **主动补发**。MQTT 仍是 **唯一的主通道**，HTTP 只在 MQTT 掉线足够久之后才 **辅助** 被动拉取，**不会抢 MQTT**。

### 7.1 数据源：`cmd_queue` 表（服务端）

- **何时落库**：每次 `publish_command`（包括兄弟 fan-out、组卡 apply、控制台单机命令、调度器到期触发）成功调用 paho publish 后，同步 `INSERT OR REPLACE` 一行到 `cmd_queue`，主键 `cmd_id` = MQTT /cmd 负载里的 `cmd_id`。
- **字段要点**：`device_id` / `cmd` / `params_json` / `target_id` / `proto` / `cmd_key`（与 MQTT 负载里的 `key` 同值）、`created_at` / `expires_at` / `delivered_via`（初始 `mqtt`，HTTP 拉取时追加记录）、`acked_at` / `ack_ok` / `ack_detail`。
- **TTL**：默认 24h（`CROC_CMD_QUEUE_TTL_S`）。已 ACK 行过老也会一并清理，保持表小。
- **不入队的动词**：高频瞬时指令（如 `presence_probe`）通过 `_CMD_QUEUE_SKIP_VERBS` 列表跳过，避免表膨胀。
- **清理节奏**：挂在既有 `scheduled_commands` worker tick 里（`_cmd_queue_cleanup_expired`），不新增线程。

### 7.2 ACK 统一销账（任何通道都行）

- MQTT `ack` 主题上的 JSON 若带 `cmd_id`，MQTT 入站 worker 直接调 `_cmd_queue_mark_acked(cmd_id, ok, detail)`。
- HTTP 备用通道的设备 ACK 走 `POST /device/commands/ack`，同一个函数销账。
- 未匹配到 `cmd_id` 的 ACK 不会报错（旧负载、raw publish 等绕过队列的路径仍然工作）。

### 7.3 服务端 → 设备的两条补发路径

1. **上线瞬时 MQTT replay**（`_maybe_replay_queue_on_reconnect`）：  
   - 触发点：`_dispatch_mqtt_payload` 收到 `heartbeat/status` 且上一条 `device_state.updated_at` 距今 ≥ `CROC_CMD_QUEUE_REPLAY_GAP_S`（默认 60s）。  
   - 行为：读取该设备的 pending cmd（最多 16 条），每条按 **正常 `publish_command`（`persist=False`）** 重发 MQTT；`cmd_id` 保持不变，设备端按 cmd_id 幂等处理。  
   - 限速：每设备 15s 去抖，不会在 heartbeat 抖动时连刷。
2. **设备 HTTP 拉取**（仅在 MQTT 久掉时启用，见 §7.4）：作为 1) 的兜底，防止 MQTT 层迟迟不恢复导致命令永远无法到达。

### 7.4 固件 HTTP 备用拉取（`Croc Sentinel.ino`）

- **入口**：`pullDeviceCommandsHttp`，被主 loop 里的新块调用。  
- **启动条件（AND 全部满足）**：  
  - `DEVICE_SYNC_HTTP_ENABLED = 1`；  
  - 设备已 provision 且 `netIf->connected()`；  
  - `mqttClient.connected() == false`；  
  - `s_mqttLastDownAtMs != 0` 且 `now - s_mqttLastDownAtMs ≥ COMMAND_HTTP_FALLBACK_ARM_MS`（默认 120s）。  
- **关闭条件**：只要 `mqttClient.connected() == true`，下一个 loop 立即停止拉取 —— **不与 MQTT 并行抢下发**。
- **轮询节奏**：`COMMAND_HTTP_FALLBACK_POLL_MS`（默认 30s），每次最多 `COMMAND_HTTP_FALLBACK_MAX_PER_POLL`（默认 4）条，`DEVICE_SYNC_HTTP_QUICK_TIMEOUT_MS`（≈4.5s）超时。
- **负载复用**：服务端 `POST /device/commands/pending` 直接返回与 MQTT `/cmd` **完全同构** 的帧（`proto / key / target_id / cmd / params / cmd_id`）；固件把它原样塞进 `handleCmdFromBody`，走 **同一套** `proto` 校验、`key` 校验、`target_id` 匹配和 `executeCommand` —— 鉴权语义零分叉。
- **ACK**：每条处理完立刻调 `postDeviceCommandAckHttp(cmd_id, true, "http_backup_delivered")`，销账服务端队列行。若此时 MQTT 恰好回线，`executeCommand` 本身也会 publishAck，服务端双通道收到同一个 `cmd_id` 的 ACK 是幂等的（`_cmd_queue_mark_acked` 有 `acked_at IS NULL` 保护）。

### 7.5 鉴权（两个通道都用同一把钥匙）

- `POST /device/commands/pending` 与 `POST /device/commands/ack` 要求 **(`device_id` + `mac_nocolon` + 16-hex `cmd_key`)** 三元组匹配 `provisioned_credentials`。
- 这把 `cmd_key` 就是固件签 MQTT `/cmd` 用的那把 —— 即使设备 NVS 里的 key 与服务器库不同步（旧状态），HTTP 通道也会 `403`，不会成为「侧门」。

### 7.6 观测点

- 日志：`cmd_queue replay: device=... gap=...s pending=N`；`[cmd-pull] delivered=N`；`[cmd-pull] HTTP status=...`。  
- 审计：`audit_events` 里 `alarm.fanout` 的 `targets` 维持不变；新加 `trigger.policy.save.detail.group_key` 方便排查策略归一化问题。  
- 表直查：`SELECT * FROM cmd_queue WHERE device_id=? AND acked_at IS NULL` 即可看到 pending 队列；ACK 后 `acked_at` 填值、`ack_ok` 为 1/0。

---

## 8. English summary (current behaviour)

- **Sibling set** = same **`owner_admin`**, not revoked, **non-empty** `notification_group`, optional **exact zone** match unless event zone is `all`/`*`, then **normalized group equality** (`NFC`, collapsed whitespace, **casefold**). **Source device excluded** on alarm fan-out paths. **Cap** = `ALARM_FANOUT_MAX_TARGETS` (default **200**); targets are **sorted by `device_id`** before capping; audit / `siblings-preview` expose **`eligible_total`** and **`fanout_capped`**. **One DB round-trip** batches **`cmd_key`** for all fan-out targets.  
- **Commands**: silent → `alarm_signal`; pause → `siren_off`; loud-like & panic → `siren_on` with **`remote_loud_duration_ms`** or **`panic_fanout_duration_ms`** respectively; **gated** by `trigger_policies` flags. **One retry** after publish failures.  
- **Policy row key** now uses the **same** `_sibling_group_norm` as sibling matching (`trim + NFC + collapse WS + casefold`). `init_db` collapses any pre-existing case/whitespace variants into one row on startup, so historical `Warehouse` vs `warehouse` rows no longer produce split policies.  
- **Offline delivery**: every `publish_command` is persisted to `cmd_queue`. When the device is seen again (heartbeat/status gap ≥ `CROC_CMD_QUEUE_REPLAY_GAP_S`) the server replays its unacked rows over MQTT. Firmware also pulls `POST /device/commands/pending` over HTTP once `mqttClient.connected() == false` for `COMMAND_HTTP_FALLBACK_ARM_MS` (default 120s) — the pull loop disarms the instant MQTT is back up, so it never competes with the primary channel. Either channel can settle the row via `_cmd_queue_mark_acked`.  
- **Does not**: cross-tenant fan-out, firmware-stored group name, or unlimited targets.  
- **Stale command hygiene** (scheduler): `presence_probes.outcome=sent` older than **`PRESENCE_PROBE_ACK_TIMEOUT_SEC`** (default **480s**) → **`timeout`**; `scheduled_commands` still **`pending`** with `execute_at_ts` older than **`SCHEDULED_CMD_STALE_PENDING_SEC`** → **`failed`**. This is **not** per-sibling MQTT ack tracking for `siren_on` fan-out (fire-and-forget + broker QoS1 only).  
- **Firmware checklist** (see §6): **`alarm.trigger` must reach the broker**; watch **JSON serialize / MQTT publish / cooldown**; **`source_zone`** must match DB **`zone`** when not using `all`/`*`.

---

*Document version: aligned with `croc_sentinel_systems/api/app.py` and `Croc Sentinel.ino` (`publishAlarmEvent`, `handleTriggerInput`). See also `OVERVIEW_CN.md` and `API_REFERENCE.md`.*
