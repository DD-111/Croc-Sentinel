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

### 2.4 策略从哪里来？（与组名「归一化」的关系）

- **联动开关与时长** 来自 **`_trigger_policy_for(owner_admin, scope_group)`**。  
- 其中 **`scope_group` = 源设备 `notification_group` 的 `.strip()`，与数据库 `trigger_policies.scope_group` 做 SQL 等值匹配**。  
- **重要**：兄弟机 **匹配**用了归一化（大小写/空白/NFC），但 **策略行键仍是「strip 后的原始字符串」**。若两台机分别写成 `Warehouse` 与 `warehouse`，它们 **会互为兄弟** 并 fan-out，但 **可能对应两条策略行**；若只保存了一条，另一台会用 **默认策略**（全 true + 默认时长）。**建议租户内统一同一逻辑组的字符串写法**，并在设备页 **Trigger policy** 里按该组保存一次策略。

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
| **离线 / 未连 MQTT** | 服务端仍会 **选中**该兄弟，但 **离线机收不到** 当次命令；与所有云端下行一致。 |
| **超过上限** | 同一事件最多 **`ALARM_FANOUT_MAX_TARGETS`** 台兄弟（默认 **200**，`.env`）；超出部分**不会**在本轮 fan-out 中下发，超大组需**分批触发**或**提高上限**（运维权衡）。 |
| **调度命令超时** | 与兄弟 fan-out **并列**的运维语义：服务端 **`presence_probes`** 里已发出、仍为 `sent` 的探测，若 **8 分钟内**无设备侧可被核销的流量（任意 `ack` / `status` / `heartbeat` / `event`），则 **标记 `timeout`**，避免长期占坑；**`scheduled_commands`** 中超过计划执行时间 **8 分钟**仍为 `pending` 的行 **标记 `failed`**。默认 **`PRESENCE_PROBE_ACK_TIMEOUT_SEC`** / **`SCHEDULED_CMD_STALE_PENDING_SEC`** = **480**。 |
| **跨租户** | **绝不**向其它 `owner_admin` 的设备发兄弟联动命令。 |
| **共享设备（ACL）** | 被 share 的设备仍属 **原 owner** 的 `notification_group`；**策略**仅 **属主** 可改。兄弟 fan-out **仍按 owner + 组** 计算，与「谁能点 Dashboard」是两条权限线。 |
| **策略键与归一化不一致** | 兄弟可因归一化合并；**策略**按 **原始 strip 字符串** 键控——请 **统一组名字符串** 或接受默认策略。 |
| **Dashboard 组卡「Alarm ON」** | 多为 **`/alerts` 或组 apply** 直接对所选 `device_id` 发 MQTT，**不是**走「某台先报 `alarm.trigger` 再兄弟 fan-out」那条链。 |
| **Superadmin 组卡 owner 混选** | 现实现为**单卡单 owner bucket**：一个组卡内不允许混选多个 `owner_admin`（含 unassigned），否则会被拒绝保存，避免“同组多卡重叠统计”。 |
| **仅改浏览器本地** | 组卡展示用 `localStorage` 可丢；**数据库组名不变**。 |

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

## 7. English summary (current behaviour)

- **Sibling set** = same **`owner_admin`**, not revoked, **non-empty** `notification_group`, optional **exact zone** match unless event zone is `all`/`*`, then **normalized group equality** (`NFC`, collapsed whitespace, **casefold**). **Source device excluded** on alarm fan-out paths. **Cap** = `ALARM_FANOUT_MAX_TARGETS` (default **200**); targets are **sorted by `device_id`** before capping; audit / `siblings-preview` expose **`eligible_total`** and **`fanout_capped`**. **One DB round-trip** batches **`cmd_key`** for all fan-out targets.  
- **Commands**: silent → `alarm_signal`; pause → `siren_off`; loud-like & panic → `siren_on` with **`remote_loud_duration_ms`** or **`panic_fanout_duration_ms`** respectively; **gated** by `trigger_policies` flags. **One retry** after publish failures.  
- **Policy row key** = **exact** `notification_group.strip()` per device owner — **not** the same normalization as sibling matching; **keep one canonical spelling** per logical group to avoid split policies.  
- **Does not**: cross-tenant fan-out, offline delivery, firmware-stored group name, or unlimited targets.  
- **Stale command hygiene** (scheduler): `presence_probes.outcome=sent` older than **`PRESENCE_PROBE_ACK_TIMEOUT_SEC`** (default **480s**) → **`timeout`**; `scheduled_commands` still **`pending`** with `execute_at_ts` older than **`SCHEDULED_CMD_STALE_PENDING_SEC`** → **`failed`**. This is **not** per-sibling MQTT ack tracking for `siren_on` fan-out (fire-and-forget + broker QoS1 only).  
- **Firmware checklist** (see §6): **`alarm.trigger` must reach the broker**; watch **JSON serialize / MQTT publish / cooldown**; **`source_zone`** must match DB **`zone`** when not using `all`/`*`.

---

*Document version: aligned with `croc_sentinel_systems/api/app.py` and `Croc Sentinel.ino` (`publishAlarmEvent`, `handleTriggerInput`). See also `OVERVIEW_CN.md` and `API_REFERENCE.md`.*
