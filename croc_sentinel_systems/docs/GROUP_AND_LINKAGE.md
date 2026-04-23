# 设备组与联动（notification_group）使用说明

本文说明：**Dashboard 里「组」如何配置**、**报警/兄弟机联动如何工作**、**已经实现什么**、以及**做不到什么**。技术实现以服务端 `device_state.notification_group` 为唯一真源；固件**不保存**组名字符串。

---

## 1. 核心概念

| 概念 | 说明 |
| --- | --- |
| **组名（组键）** | 即设备上的 **「Notification group」** 字段，对应数据库 `device_state.notification_group`。同一字符串 = 同一逻辑组。 |
| **真源在云端** | 组名只存在于 **API / 数据库**；设备固件**没有**该字段的 NVS 或编译期配置。改组名、换组、删组都在 **Console** 或 **API** 完成。 |
| **按租户** | 设备归属 `device_ownership.owner_admin`；兄弟机与 fan-out **不会**跨 admin。 |
| **与 Zone 的关系** | 报警 fan-out 在「同 owner + 同组名」基础上，还受 **设备 Zone** 约束（与固件上报的 `source_zone` 等一致；Zone 为 `all` / `*` 时按策略放宽）。 |

---

## 2. 怎么使用（操作路径）

1. **给设备设组名**  
   - 打开 **All devices** → 点进某台设备；在 **Save profile** 中填写 **Notification group**（或 Overview **组卡 → Edit** 里勾选设备并保存）。  
   - 保存会调用 `PATCH /devices/{id}/profile`，写入数据库。

2. **Overview「组卡」**  
   - 组卡上的设备列表与 **All devices 里 `notification_group` 一致**；本地 `localStorage` 会随 `GET /devices` 结果自动对齐（含定时刷新、改设备/删机后的缓存刷新）。

3. **空组 = 不跟别的设备联动**  
   - 将某台的 **Notification group 清空** 并保存后，该台在服务端为「无组」：  
   - **不会**再参与**同组兄弟机**的 MQTT 命令 fan-out（见下文「已做到什么」）。  
   - 本地 GPIO 行为（如本机蜂鸣/恐慌）仍由**固件与接线**决定，与「是否填了组名」独立。

4. **换机主 / 重新认领**  
   - 新认领或管理类转移后，服务端会对历史 `device_state` 做清理或隔离，避免上一手租户的组名/标签遗留在新手账号下（以当前 API 实现为准）。

5. **固件端**  
   - 无需在 `config.h` 里配组名；`DEVICE_ZONE` 等仍按现有文档配置。  
   - 设备通过 MQTT 上报告警等事件；**谁和谁是兄弟**由 **API 读库**后决定。

---

## 3. 已经做到什么

| 能力 | 说明 |
| --- | --- |
| **云端统一组名** | 所有组关系以 `device_state.notification_group` 为准；列表、详情、组卡与 fan-out 一致。 |
| **同组兄弟机 fan-out** | 在**非空组名**且 policy 允许时，由 API 对**同 owner、同组、同 zone 规则下**的其它设备下发 `siren_on` / `alarm_signal` 等（具体以 `trigger_policy` 与 `trigger_kind` 为准）。 |
| **空组不 fan-out** | 源设备组名为空时，**不再**把同 Zone 下其它（含无组/他组）设备误当兄弟机整批下发（服务端 `_tenant_siblings` 对空组返回无目标）。 |
| **Console 与列表同步** | 组卡元数据会随 `/devices` 更新；改 profile、删机、revoke 等会触发设备列表缓存失效并排队同步组卡元数据。 |
| **审计与事件** | Profile 变更等会写事件流；便于排查组名前后变化。 |
| **按登录用户区分的本地组卡** | 组卡扩展信息使用 `localStorage` 中按 **用户名** 分 key 存储；不同账号不共用。 |

---

## 4. 不能做到 / 限制与注意

| 项 | 说明 |
| --- | --- |
| **固件里不能「直接选组」** | 组名**不能**在烧录时写死为业务含义；必须在 Dashboard/API 配。 |
| **组名不是全局唯一** | 组名字符串按**租户 + 设备记录**使用；不要依赖「全世界唯一组名」。跨租户隔离由 **owner** 与 API 授权保证。 |
| **大小写与全角** | 组名按**字符串**匹配；`A` 与 `a` 是不同组。请统一命名习惯。 |
| **无组设备之间不通过「空组」互联动** | 空组**不会**被当成「所有无组设备一个大组」来 fan-out；需要联动请显式设**相同非空**组名。 |
| **离线设备** | 服务端仍会计算 fan-out 目标，但**未在线设备**收不到 MQTT；与任何云端指令一致。 |
| **仅改本地浏览器** | 清浏览器数据会丢组卡**展示用**的本地元数据，但**不会**改数据库；重新登录后从 `/devices` 会再同步。 |
| **共享设备** | 被 share 的组/设备，编辑权限以 API 与 UI 限制为准（如共享组只读等）；与「同 owner 同组」 fan-out 是两条线。 |

---

## 5. 与《白话总览》的边界

`OVERVIEW_CN.md` 里「按一下某台 → 同 admin 名下全响」是**便于理解的概括**。**实际上**：是否响、响哪些台，还受 **notification_group、Zone、策略（静音/外放/恐慌）以及设备在线** 等约束。细节以本文与 `API` / `app.py` 中 alarm fan-out 逻辑为准。

---

## 6. English summary

- **Group membership** is **`device_state.notification_group` only**; firmware does **not** store the group name.  
- **Use** the device **Profile** or **group card editor** in the Console; save calls the profile API.  
- **Empty group** means **no sibling fan-out** from the server for that device (no cross-device linkage via the group path).  
- **What works**: tenant-scoped siblings, DB as source of truth, dashboard group cards kept in sync with `GET /devices`, policies for silent/loud/panic paths.  
- **What it does *not* do**: compile-time group in firmware, “all ungrouped devices mesh together” without explicit names, or cross-tenant group sharing.

---

*Document version: matches Console + API behaviour around `notification_group` and group-card sync. For deployment, also see `OVERVIEW_CN.md` and `API_REFERENCE.md`.*
