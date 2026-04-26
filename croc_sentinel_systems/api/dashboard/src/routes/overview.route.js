/**
 * Route: #/overview — Dashboard overview / hero KPIs / recent activity.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("overview", async (view, _args, routeSeq) => {
  setCrumb("Overview");
  const groupScope = (state.me && state.me.username) ? state.me.username : "anon";
  const GROUP_API_CAPS_LS_KEY = `croc.group.api.caps.v2.${groupScope}`;
  const loadGroupApiCaps = () => {
    try {
      const raw = localStorage.getItem(GROUP_API_CAPS_LS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return {
        settings: obj && obj.settings === false ? false : true,
        apply: obj && obj.apply === false ? false : true,
        delete: obj && obj.delete === false ? false : true,
        prefix: (obj && (obj.prefix === "/api" || obj.prefix === "")) ? obj.prefix : "",
      };
    } catch {
      return { settings: true, apply: true, delete: true, prefix: "" };
    }
  };
  const saveGroupApiCaps = (caps) => {
    localStorage.setItem(GROUP_API_CAPS_LS_KEY, JSON.stringify({
      settings: !!(caps && caps.settings),
      apply: !!(caps && caps.apply),
      delete: !!(caps && caps.delete),
      prefix: (caps && caps.prefix === "/api") ? "/api" : "",
    }));
  };
  const groupApiCaps = loadGroupApiCaps();
  const tryGroupApiCall = async (suffix, opts) => {
    const lastErrs = [];
    const prefixes = groupApiCaps.prefix === "/api" ? ["/api", ""] : ["", "/api"];
    for (const px of prefixes) {
      try {
        const r = await api(`${px}/group-cards${suffix}`, opts);
        if (groupApiCaps.prefix !== px) {
          groupApiCaps.prefix = px;
          saveGroupApiCaps(groupApiCaps);
        }
        return r;
      } catch (e) {
        const msg = String((e && e.message) || e || "");
        lastErrs.push(e);
        if (msg.includes("404") || msg.includes("405") || msg.includes("501")) continue;
        throw e;
      }
    }
    throw lastErrs[lastErrs.length - 1] || new Error("group route unavailable");
  };
  const loadGroupSettingsCompat = async () => {
    if (!groupApiCaps.settings) return { items: [] };
    try {
      return await tryGroupApiCall("/settings", { timeoutMs: 12000, retries: 1 });
    } catch (e) {
      const msg = String((e && e.message) || e || "");
      if (msg.includes("404") || msg.includes("405") || msg.includes("501")) {
        groupApiCaps.settings = false;
        saveGroupApiCaps(groupApiCaps);
        return { items: [] };
      }
      throw e;
    }
  };
  const fetchOverviewAndDevices = async () => {
    let bestOv = null;
    let bestList = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const [ovR, liR] = await Promise.allSettled([
        api("/dashboard/overview", { timeoutMs: 22000, retries: 3 }),
        api("/devices", { timeoutMs: 22000, retries: 3 }),
      ]);
      if (ovR.status === "fulfilled" && ovR.value) bestOv = ovR.value;
      if (liR.status === "fulfilled" && liR.value) bestList = liR.value;
      if (bestOv && bestList) return { ov: bestOv, list: bestList };
      if (attempt === 0) await _sleep(500);
    }
    return { ov: bestOv, list: bestList };
  };
  const [ovListRes, grpSetRes] = await Promise.allSettled([
    fetchOverviewAndDevices(),
    loadGroupSettingsCompat(),
  ]);
  let ov = (ovListRes.status === "fulfilled" && ovListRes.value && ovListRes.value.ov) ? ovListRes.value.ov : null;
  let list = (ovListRes.status === "fulfilled" && ovListRes.value && ovListRes.value.list) ? ovListRes.value.list : null;
  if (!ov || !list) {
    const cached = state.overviewCache;
    if (cached && cached.ov && cached.list) {
      ov = ov || cached.ov;
      list = list || cached.list;
      toast("Showing last known data — server is slow or offline; will retry on refresh.", "warn");
    }
  }
  if (!ov) ov = { mqtt_connected: false };
  if (!list) list = { items: [] };
  state.overviewCache = { ov, list, ts: Date.now() };
  const groupSettingsItems = (grpSetRes.status === "fulfilled" && grpSetRes.value && Array.isArray(grpSetRes.value.items))
    ? grpSetRes.value.items
    : [];
  let devices = list.items || [];
  let byId = new Map(devices.map((d) => [String(d.device_id), d]));

  const GROUP_META_LS_KEY = `croc.group.meta.v2.${groupScope}`;
  const GROUP_SETTINGS_LS_KEY = `croc.group.settings.v1.${groupScope}`;
  const loadGroupMeta = () => {
    try {
      const raw = localStorage.getItem(GROUP_META_LS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return (obj && typeof obj === "object") ? obj : {};
    } catch { return {}; }
  };
  const saveGroupMeta = (obj) => localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(obj || {}));
  const loadLocalGroupSettings = () => {
    try {
      const raw = localStorage.getItem(GROUP_SETTINGS_LS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return (obj && typeof obj === "object") ? obj : {};
    } catch { return {}; }
  };
  const saveLocalGroupSettings = (obj) => localStorage.setItem(GROUP_SETTINGS_LS_KEY, JSON.stringify(obj || {}));
  const groupDelayTimers = new Map();
  const localGroupSettings = loadLocalGroupSettings();
  const groupSettingsMap = new Map();
  for (const [k, v] of Object.entries(localGroupSettings)) groupSettingsMap.set(String(k), v || {});
  for (const x of groupSettingsItems) {
    const mk = groupCardMetaKey(
      x.group_key,
      state.me && state.me.role === "superadmin" ? x.owner_admin : "",
    );
    if (mk) groupSettingsMap.set(mk, x);
  }
  const meta = loadGroupMeta();
  syncGroupMetaWithDevices(meta, devices);
  saveGroupMeta(meta);

  let selectedGroup = "";
  const hh = state.health || {};
  const httpOk = !!(hh.ok ?? true);
  const mqConnected = !!(hh.mqtt_connected ?? ov.mqtt_connected);
  const mqQDepth = Number(hh.mqtt_ingest_queue_depth || 0);
  const mqDropped = Number(hh.mqtt_ingest_dropped || 0);
  const totalDevices = Number(ov.total_devices != null ? ov.total_devices : devices.length);
  const onlineDevices = Number((ov.presence && ov.presence.online != null) ? ov.presence.online : devices.filter(isOnline).length);
  const offlineDevices = Math.max(0, totalDevices - onlineDevices);
  const txBps = Number((ov.throughput && ov.throughput.tx_bps_total) || 0);
  const rxBps = Number((ov.throughput && ov.throughput.rx_bps_total) || 0);
  const bps = (v) => {
    v = Number(v || 0);
    if (v < 1024) return `${v.toFixed(0)} B/s`;
    if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
    return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
  };
  const mqStatus = !mqConnected ? "Disconnected" : (mqDropped > 0 || mqQDepth >= 300 ? "Warning" : "Healthy");
  const mqClass = !mqConnected ? "revoked" : (mqStatus === "Warning" ? "offline" : "online");
  let lastOverviewHeaderSig = "";
  const patchOverviewHeader = (vals) => {
    const sig = JSON.stringify(vals || {});
    if (sig === lastOverviewHeaderSig) return;
    lastOverviewHeaderSig = sig;
    const setTxt = (id, v) => {
      const el = $(`#${id}`, view);
      if (el && el.textContent !== String(v)) el.textContent = String(v);
    };
    setTxt("ovServerV", vals.server);
    setTxt("ovDevicesV", vals.devices);
    setTxt("ovOnlineV", vals.online);
    setTxt("ovOfflineV", vals.offline);
    setTxt("ovTxV", vals.tx);
    setTxt("ovRxV", vals.rx);
    setTxt("ovMqttQueue", vals.queue);
    setTxt("ovMqttDropped", vals.dropped);
    const risk = $("#ovMqttRisk", view);
    if (risk) {
      if (risk.textContent !== String(vals.risk)) risk.textContent = String(vals.risk);
      const want = `badge ${vals.riskClass}`;
      if (risk.className !== want) risk.className = want;
    }
  };

  const isSuper = !!(state.me && state.me.role === "superadmin");
  const serverHeadline = () => {
    if (isSuper) {
      return `${httpOk ? "HTTP OK" : "HTTP DOWN"} · ${mqConnected ? "MQTT UP" : "MQTT DOWN"}`;
    }
    return httpOk && mqConnected ? "Status ok" : "Status down";
  };

  mountView(view, `
    <header class="page-head">
      <h2>Overview</h2>
    </header>
    <section class="stats">
      <div class="stat"><div class="k">Server</div><div class="v" id="ovServerV">—</div><div class="sub">HTTP + MQTT realtime</div></div>
      <div class="stat"><div class="k">Devices</div><div class="v" id="ovDevicesV">—</div><div class="sub">total in scope</div></div>
      <div class="stat"><div class="k">Online</div><div class="v" id="ovOnlineV">—</div><div class="sub">active now</div></div>
      <div class="stat"><div class="k">Offline</div><div class="v" id="ovOfflineV">—</div><div class="sub">inactive now</div></div>
      <div class="stat"><div class="k">TX</div><div class="v" id="ovTxV">—</div><div class="sub">aggregate uplink</div></div>
      <div class="stat"><div class="k">RX</div><div class="v" id="ovRxV">—</div><div class="sub">aggregate downlink</div></div>
    </section>
    <section class="card card--groups">
      <div class="row">
        <h3 style="margin:0">MQTT risk</h3>
        <span class="badge ${mqClass}" id="ovMqttRisk">${mqStatus}</span>
      </div>
      <div class="divider"></div>
      <div class="muted">queue=<span class="mono" id="ovMqttQueue">0</span> · dropped=<span class="mono" id="ovMqttDropped">0</span></div>
    </section>
    <section class="card">
      <div class="row">
        <h2 style="margin:0">Group cards</h2>
        <button class="btn sm secondary right" id="grpNew">New group</button>
      </div>
      ${state.me && state.me.role === "superadmin" ? `
      <div class="row" style="flex-wrap:wrap;gap:10px;align-items:flex-end;margin:10px 0 4px">
        <label class="field" style="margin:0;min-width:220px;flex:1">
          <span>Filter by owner / 按租户筛选组卡</span>
          <input type="search" id="ovOwnerFilter" list="ovOwnerDatalist" placeholder="username substring…" autocomplete="off" />
          <datalist id="ovOwnerDatalist"></datalist>
        </label>
        <button type="button" class="btn sm secondary btn-tap" id="ovOwnerClear">Clear</button>
      </div>
      <p class="muted" style="margin:0 0 8px;font-size:12px">One card per tenant group. <span class="mono">__unowned__</span> means no owner.</p>
      ` : ""}
      <div id="groupCards" class="device-grid"></div>
      ${state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users"))) ? `
      <details class="share-fold" id="grpShareFold">
        <summary class="share-fold__summary">
          <span>Global sharing</span>
        </summary>
        <div class="share-global-panel">
          <div class="share-global-head">
            <div class="share-global-toolbar">
              <button class="btn sm secondary btn-tap" type="button" id="grpShareRefresh">Refresh</button>
              <button class="btn sm btn-tap" type="button" id="grpShareOpen">New grant</button>
            </div>
          </div>
          <p class="muted" style="margin:0 0 6px;font-size:12px">Shared users get per-device access only; group cards and trigger policy stay tenant-local.</p>
          <div id="shareGrantsTableWrap" class="share-grants-table mini" style="margin-top:10px">
            <p class="muted" style="margin:0;padding:8px 0">Loading shares…</p>
          </div>
        </div>
      </details>` : ""}
    </section>
    <div id="shareModal" class="grp-modal" style="display:none">
      <div class="grp-modal-card" style="max-width:760px;width:min(760px,96vw)">
        <h3 style="margin:0 0 8px" id="shareModalTitle">Share devices / group</h3>
        <p class="muted" id="shareTargetHint" style="margin:0 0 10px">Select devices, users, and permissions.</p>
        <p class="muted" id="shareEditNote" style="margin:0 0 8px;display:none"></p>
        <div class="row" style="gap:10px;align-items:flex-start;flex-wrap:wrap">
          <div style="flex:1;min-width:280px">
            <div class="row" style="justify-content:space-between;align-items:center">
              <strong>Devices</strong>
              <label class="muted"><input type="checkbox" id="shareSelAllDevices" /> Select all</label>
            </div>
            <div id="shareDeviceList" class="grp-pick-list grp-pick-list--devices" style="max-height:280px;overflow:auto"></div>
          </div>
          <div style="flex:1;min-width:280px">
            <div class="row" style="justify-content:space-between;align-items:center">
              <strong>Users</strong>
              <label class="muted"><input type="checkbox" id="shareSelAllUsers" /> Select all</label>
            </div>
            <div id="shareUserList" class="grp-pick-list" style="max-height:260px;overflow:auto"></div>
          </div>
        </div>
        <div class="row" style="margin-top:10px;gap:14px">
          <label><input type="checkbox" id="sharePermView" checked /> can_view</label>
          <label><input type="checkbox" id="sharePermOperate" /> can_operate</label>
        </div>
        <p class="muted" id="shareBatchStat" style="min-height:1.2em;margin:8px 0 0"></p>
        <div class="row" style="justify-content:flex-end;gap:8px;margin-top:10px">
          <button class="btn sm secondary" id="shareModalCancel" type="button">Cancel</button>
          <button class="btn sm" id="shareModalApply" type="button">Apply sharing</button>
        </div>
      </div>
    </div>
    <div id="grpSetModal" class="grp-modal" style="display:none">
      <div class="grp-modal-card">
        <h3 style="margin:0 0 8px">Group trigger settings</h3>
        <p class="muted" id="gsKeyLabel" style="margin:0 0 10px"></p>
        <p class="muted" style="margin:0 0 10px;font-size:12px;line-height:1.45" lang="zh">延迟为 0 表示立即鸣响；鸣响时长以分钟计（与单机远程警报复位策略一致）。<br/><span lang="en">Delay 0 = immediate siren. Duration is in minutes (same idea as remote siren length).</span></p>
        <label class="field"><span>Siren duration (minutes)</span><input id="gsDurMin" type="number" min="0.5" max="5" step="0.5" /></label>
        <label class="field field--spaced"><span>Delay before siren (seconds)</span><input id="gsDelay" type="number" min="0" max="3600" step="1" /></label>
        <label class="field field--spaced field--toggle">
          <span class="row field--toggle__row" style="margin:0;align-items:flex-start;gap:10px">
            <input id="gsReboot" type="checkbox" />
            <span class="field--toggle__text">Reboot + self-check this group after trigger</span>
          </span>
        </label>
        <div class="row" style="justify-content:flex-end;gap:8px;margin-top:10px">
          <button class="btn sm secondary" id="gsCancel" type="button">Cancel</button>
          <button class="btn sm secondary" id="gsApply" type="button">Apply now</button>
          <button class="btn sm" id="gsSave" type="button">Save</button>
        </div>
      </div>
    </div>
    <div id="grpModal" class="grp-modal" style="display:none">
      <div class="grp-modal-card grp-modal-card--edit">
        <header class="grp-modal__head">
          <h3 class="grp-modal__title">编辑组卡 / Edit group card</h3>
          <p class="grp-modal__lede muted">填写组标识与展示信息，勾选要出现在此卡上的设备。需要说明时请向管理员索取文档。<br/><span lang="en">Set the group identifier and display fields, then pick devices for this card. Ask your administrator for documentation if needed.</span></p>
        </header>
        <div class="grp-modal__fields">
          <label class="field"><span>Group key</span><input id="gmKey" placeholder="e.g. Warehouse-A" autocomplete="off"/></label>
          <p class="muted grp-modal__key-hint" style="margin:-2px 0 10px;font-size:11px;line-height:1.45">保存时会自动整理首尾空格与连续空格（Unicode NFC）。<strong>大小写仍区分</strong>；与「设备详情 → Notification group」不一致时会出现多张组卡。<br/><span lang="en">Spaces are normalized on save; <strong>case still matters</strong>. Must match each device&rsquo;s Notification group or you will see multiple cards.</span></p>
          <label class="field"><span>Display name</span><input id="gmName" autocomplete="off"/></label>
          <label class="field"><span>Owner name</span><input id="gmOwner" autocomplete="name"/></label>
          <label class="field"><span>Phone</span><input id="gmPhone" inputmode="tel" autocomplete="tel"/></label>
          <label class="field"><span>Email</span><input id="gmEmail" type="email" autocomplete="email"/></label>
          <div class="field field--devices">
            <span>Devices in this group</span>
            <div id="gmDevices" class="grp-pick-list grp-pick-list--devices" role="group" aria-label="Devices in group"></div>
          </div>
        </div>
        <div class="row grp-modal__actions" style="justify-content:flex-end;gap:8px;margin-top:12px">
          <button class="btn sm secondary" id="gmCancel" type="button">Cancel</button>
          <button class="btn sm" id="gmSave" type="button">Save</button>
        </div>
      </div>
    </div>`);
  patchOverviewHeader({
    server: serverHeadline(),
    devices: totalDevices,
    online: onlineDevices,
    offline: offlineDevices,
    tx: bps(txBps),
    rx: bps(rxBps),
    queue: mqQDepth,
    dropped: mqDropped,
    risk: mqStatus,
    riskClass: mqClass,
  });

  const groupCardsEl = $("#groupCards", view);
  const grpModalEl = $("#grpModal", view);
  const grpSetModalEl = $("#grpSetModal", view);
  const shareModalEl = $("#shareModal", view);
  if (!groupCardsEl || !grpModalEl || !grpSetModalEl) return;

  const repopOvOwnerDatalist = () => {
    const dl = $("#ovOwnerDatalist", view);
    if (!dl || !(state.me && state.me.role === "superadmin")) return;
    const owners = [...new Set(devices.map((d) => String(d.owner_admin || "").trim()).filter(Boolean))].sort();
    setChildMarkup(dl, owners.map((o) => `<option value="${escapeHtml(o)}"></option>`).join(""));
  };

  const groupDeviceRow = (d, { checked, disabled } = {}) => {
    const did = String(d && d.device_id != null ? d.device_id : "").trim();
    if (!did) return "";
    const name0 = d && d.display_label != null && String(d.display_label).trim();
    const name = name0 || did;
    const ck = checked ? " checked" : "";
    const di = disabled ? " disabled" : "";
    return (
      `<label class="grp-pick-item grp-pick-item--device">` +
      `<input type="checkbox" class="grp-pick-chk" value="${escapeHtml(did)}"${ck}${di} />` +
      `<span class="grp-pick-text">` +
      `<span class="grp-pick-name">${escapeHtml(name)}</span>` +
      `<span class="grp-pick-id mono" title="Device ID / 序列号">${escapeHtml(did)}</span>` +
      `</span></label>`
    );
  };

  let editingGroup = "";
  let ownerFilterQ = "";
  const devicesForGroups = () => {
    if (!(state.me && state.me.role === "superadmin")) return devices;
    const q = ownerFilterQ.trim().toLowerCase();
    if (!q) return devices;
    return devices.filter((d) => String(d.owner_admin || "").toLowerCase().includes(q));
  };
  const groupDeviceIdsFromList = (g, tenantOwner) => {
    const key = canonicalGroupKey(g);
    if (!key) return [];
    const t = String(tenantOwner || "").trim();
    const isSuper = state.me && state.me.role === "superadmin";
    const out = [];
    for (const d of devices) {
      if (!d || canonicalGroupKey(d.notification_group) !== key) continue;
      if (isSuper) {
        const o = String(d.owner_admin || "").trim();
        if (t === "") {
          if (o) continue;
        } else if (o !== t) {
          continue;
        }
      } else if (t && String(d.owner_admin || "").trim() !== t) {
        continue;
      }
      const did = String(d.device_id || "").trim();
      if (did) out.push(did);
    }
    return out;
  };
  const collectGroupSlots = () => buildGroupSlotsFromDeviceList(devicesForGroups());
  const groupDeviceIdsFromSlot = (slot) => {
    const ids = groupDeviceIdsFromList(slot.groupKey, slot.tenantOwner);
    return ids.filter((x) => byId.has(String(x)));
  };
  const groupSharedBySlot = (slot) => {
    const rows = groupDeviceIdsFromSlot(slot).map((id) => byId.get(String(id))).filter(Boolean);
    const sharedFrom = new Set(rows.map((d) => String(d.shared_by || "")).filter(Boolean));
    return Array.from(sharedFrom);
  };
  const groupSharedByNotificationKey = (gk) => {
    const key = canonicalGroupKey(gk);
    if (!key) return [];
    const rows = devices.filter((d) => canonicalGroupKey(d.notification_group) === key);
    const sharedFrom = new Set(rows.map((d) => String(d.shared_by || "")).filter(Boolean));
    return Array.from(sharedFrom);
  };
  /** Grantees that already have an active ACL row on every device in `deviceIds` (batch modal locks these). */
  const granteesFullyCoveringDevices = (deviceIds, shareItems) => {
    const ids = (Array.isArray(deviceIds) ? deviceIds : []).map((x) => String(x || "").trim()).filter(Boolean);
    const n = ids.length;
    if (!n || !Array.isArray(shareItems)) return new Set();
    const dset = new Set(ids);
    const counts = new Map();
    for (const it of shareItems) {
      if (it && it.revoked_at) continue;
      const did = String((it && it.device_id) || "").trim();
      if (!dset.has(did)) continue;
      const g = String((it && it.grantee_username) || "").trim();
      if (!g) continue;
      counts.set(g, (counts.get(g) || 0) + 1);
    }
    const out = new Set();
    for (const [g, c] of counts) {
      if (c >= n) out.add(g);
    }
    return out;
  };
  /** Badge: device-level ACL only — distinguish full card vs partial shared devices (grantee view). */
  const shareScopeBadgesHtml = (rows) => {
    const list = Array.isArray(rows) ? rows.filter(Boolean) : [];
    const n = list.length;
    if (!n) return "";
    const sharedRows = list.filter((d) => d && d.is_shared);
    const sn = sharedRows.length;
    if (sn === 0) return "";
    if (sn === n) {
      const owners = [...new Set(sharedRows.map((d) => String(d.shared_by || "").trim()).filter(Boolean))];
      const o = owners.length === 1 ? owners[0] : owners.join(", ");
      return `<span class="badge accent" title="Device-level ACL: every device on this card is shared to you (same notification group)">ACL: full group · ${escapeHtml(o || "?")}</span>`;
    }
    return `<span class="badge partial" title="Device-level ACL: only some devices on this card are shared">ACL: partial devices (${sn}/${n})</span>`;
  };
  const buildGroupCardHtml = (slot) => {
    const g = slot.groupKey;
    const ids = groupDeviceIdsFromSlot(slot);
    const rows = ids.map((id) => byId.get(String(id))).filter(Boolean);
    const total = rows.length;
    const on = rows.filter((d) => isOnline(d)).length;
    const off = Math.max(0, total - on);
    const m = meta[slot.metaKey] || {};
    const gs = groupSettingsMap.get(slot.metaKey) || {
      trigger_mode: "continuous",
      trigger_duration_ms: DEFAULT_REMOTE_SIREN_MS,
      delay_seconds: 0,
      reboot_self_check: false,
    };
    const isSharedGroup = groupSharedBySlot(slot).length > 0;
    const scopeShareHtml = shareScopeBadgesHtml(rows);
    const dsec = Number(gs.delay_seconds || 0);
    const modeLabel = dsec > 0 ? `immediate (delay cfg: ${dsec}s)` : "immediate";
    const shareBtn = state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users")))
      ? `<button class="group-del-ico js-share-group" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" title="Share devices in this card (device ACL only — not group secrets)">⇪</button>`
      : "";
    const unassignedSuper = state.me && state.me.role === "superadmin" && !slot.tenantOwner;
    const hasCorner = !!(slot.tenantOwner || shareBtn || unassignedSuper);
    const ownerPill = slot.tenantOwner
      ? `<span class="card-owner-tag" title="Owning admin / 所属租户">${escapeHtml(slot.tenantOwner)}</span>`
      : (unassignedSuper ? `<span class="card-owner-tag" title="No owner_admin on devices in this card">Unassigned</span>` : "");
    const cornerHtml = hasCorner
      ? `<div class="device-card__corner-tr" role="group" aria-label="Tenant">${ownerPill}${shareBtn}</div>`
      : "";
    return `<article class="device-card js-group-card ${hasCorner ? "js-group-card--has-corner " : ""}${selectedGroup === slot.metaKey ? "is-selected" : ""}" data-meta-key="${escapeHtml(slot.metaKey)}" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" style="cursor:pointer;position:relative">
      ${cornerHtml}
      <h3><div class="device-primary-name">${escapeHtml(m.display_name || g)}</div><div class="device-id-sub mono">${escapeHtml(g)}</div></h3>
      <div class="meta" style="margin-bottom:8px">
        Trigger: <span class="mono">${escapeHtml(modeLabel)}</span> ·
        Duration: <span class="mono">${escapeHtml(String(Math.round((Number(gs.trigger_duration_ms) || DEFAULT_REMOTE_SIREN_MS) / 60000 * 10) / 10))} min</span> ·
        Reboot+self-check: <span class="mono">${gs.reboot_self_check ? "yes" : "no"}</span>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;align-items:center">
        <span class="badge neutral">total ${total}</span>
        <span class="badge online">online ${on}</span>
        <span class="badge offline">offline ${off}</span>
        ${scopeShareHtml}
      </div>
      <div class="meta">Owner: ${escapeHtml(m.owner_name || "—")} · ${escapeHtml(m.phone || "—")} · ${escapeHtml(m.email || "—")}</div>
      <div class="group-card-actions">
        <div class="group-card-actions__alarms">
          <button class="btn sm danger js-alert-on" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button">Alarm ON</button>
          <button class="btn sm secondary js-alert-off" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button">Alarm OFF</button>
        </div>
        <div class="group-card-actions__manage">
          <button class="btn sm secondary js-group-settings" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" ${isSharedGroup ? "disabled title=\"Shared group follows owner settings\"" : ""}>Settings</button>
          <button class="btn sm secondary js-edit-group" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" ${isSharedGroup ? "disabled title=\"Shared group: device membership is read-only\"" : ""}>Edit</button>
          <button class="btn sm danger js-del-group" data-group="${escapeHtml(g)}" data-owner="${escapeHtml(slot.tenantOwner)}" data-meta-key="${escapeHtml(slot.metaKey)}" type="button" ${isSharedGroup ? "disabled title=\"Shared group cannot be deleted\"" : "title=\"Delete group\""}>Delete</button>
        </div>
      </div>
    </article>`;
  };
  const renderGroups = () => {
    const slots = collectGroupSlots();
    if (slots.length === 0) {
      setChildMarkup(groupCardsEl, `<p class="muted">No groups yet.</p>`);
      return;
    }
    const existing = new Map(
      $$(".js-group-card", groupCardsEl).map((el) => [String(el.getAttribute("data-meta-key") || el.getAttribute("data-group") || ""), el]),
    );
    const frag = document.createDocumentFragment();
    for (const slot of slots) {
      const html = buildGroupCardHtml(slot);
      let node = existing.get(slot.metaKey) || null;
      if (!node || node.outerHTML !== html) {
        const sub = parseHtmlToFragment(html.trim());
        node = sub.firstElementChild;
      }
      if (node) frag.appendChild(node);
    }
    groupCardsEl.replaceChildren(frag);
  };
  const editingSettingsSlot = { metaKey: "", groupKey: "", tenantOwner: "" };
  const readSlotFromBtn = (btn) => {
    const card = btn && btn.closest ? btn.closest(".js-group-card") : null;
    const metaKey = String((btn && btn.dataset && btn.dataset.metaKey) || (card && card.getAttribute("data-meta-key")) || "");
    const groupKey = String((btn && btn.dataset && btn.dataset.group) || (card && card.getAttribute("data-group")) || "");
    const tenantOwner = String((btn && btn.dataset && btn.dataset.owner) || (card && card.getAttribute("data-owner")) || "");
    return { metaKey, groupKey, tenantOwner };
  };
  const openSettingsModal = (slot) => {
    editingSettingsSlot.metaKey = slot.metaKey || "";
    editingSettingsSlot.groupKey = slot.groupKey || "";
    editingSettingsSlot.tenantOwner = slot.tenantOwner || "";
    if (!editingSettingsSlot.metaKey) return;
    const gs = groupSettingsMap.get(editingSettingsSlot.metaKey) || {
      trigger_mode: "continuous",
      trigger_duration_ms: DEFAULT_REMOTE_SIREN_MS,
      delay_seconds: 0,
      reboot_self_check: false,
    };
    const label = editingSettingsSlot.tenantOwner
      ? `Group: ${editingSettingsSlot.groupKey} · admin: ${editingSettingsSlot.tenantOwner}`
      : `Group: ${editingSettingsSlot.groupKey}`;
    $("#gsKeyLabel", view).textContent = label;
    const durMin = Math.max(0.5, Math.min(5, (Number(gs.trigger_duration_ms) || DEFAULT_REMOTE_SIREN_MS) / 60000));
    const gdm = $("#gsDurMin", view);
    if (gdm) gdm.value = String(Math.round(durMin * 10) / 10);
    $("#gsDelay", view).value = String(Number(gs.delay_seconds || 0));
    $("#gsReboot", view).checked = !!gs.reboot_self_check;
    grpSetModalEl.style.display = "flex";
  };
  const closeSettingsModal = () => { grpSetModalEl.style.display = "none"; };
  const collectSettingsPayload = () => {
    const durMinEl = $("#gsDurMin", view);
    const durMin = parseFloat((durMinEl && durMinEl.value) || "3", 10);
    const delay = parseInt($("#gsDelay", view).value, 10);
    const reboot = !!$("#gsReboot", view).checked;
    if (!Number.isFinite(durMin) || durMin < 0.5 || durMin > 5) {
      throw new Error("Siren duration must be 0.5–5 minutes");
    }
    if (!Number.isFinite(delay) || delay < 0 || delay > 3600) {
      throw new Error("Delay seconds must be 0-3600");
    }
    const duration = Math.round(durMin * 60000);
    return {
      trigger_mode: delay > 0 ? "delay" : "continuous",
      trigger_duration_ms: duration,
      delay_seconds: delay,
      reboot_self_check: reboot,
    };
  };
  const persistSettingsLocal = (metaKey, payload) => {
    const all = loadLocalGroupSettings();
    all[metaKey] = Object.assign({}, payload || {});
    saveLocalGroupSettings(all);
  };
  const saveGroupSettingsCompat = async (groupKey, tenantOwner, payload) => {
    const mk = groupCardMetaKey(groupKey, tenantOwner);
    const path = groupApiSuffixWithOwner(`/${encodeURIComponent(groupKey)}/settings`, tenantOwner);
    const body = Object.assign({}, payload || {});
    if (state.me && state.me.role === "superadmin" && String(tenantOwner || "").trim()) {
      body.owner_admin = String(tenantOwner).trim();
    }
    if (!groupApiCaps.settings) {
      persistSettingsLocal(mk, body);
      return body;
    }
    try {
      return await tryGroupApiCall(path, {
        method: "PUT",
        body,
      });
    } catch (e) {
      const msg = String((e && e.message) || e || "");
      if (msg.includes("404") || msg.includes("405") || msg.includes("501")) {
        groupApiCaps.settings = false;
        saveGroupApiCaps(groupApiCaps);
        persistSettingsLocal(mk, body);
        return body;
      }
      throw e;
    }
  };
  const applyGroupSettingsFallback = async (groupKey, tenantOwner, payload) => {
    const slot = { metaKey: groupCardMetaKey(groupKey, tenantOwner), groupKey, tenantOwner: tenantOwner || "" };
    const ids = groupDeviceIdsFromSlot(slot);
    if (!ids.length) throw new Error("No devices in this group");
    if (!can("can_alert")) throw new Error("No can_alert capability");
    const durationMs = Number(payload.trigger_duration_ms || DEFAULT_REMOTE_SIREN_MS);
    const timerKey = slot.metaKey;
    const prevTimer = groupDelayTimers.get(timerKey);
    if (prevTimer) {
      clearTimeout(prevTimer);
      groupDelayTimers.delete(timerKey);
    }
    await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
    let rebootJobs = 0;
    let selfTests = 0;
    if (payload.reboot_self_check) {
      if (!can("can_send_command")) throw new Error("Reboot+self-check needs can_send_command");
      for (const did of ids) {
        await api(`/devices/${encodeURIComponent(did)}/self-test`, { method: "POST" });
        selfTests += 1;
        await api(`/devices/${encodeURIComponent(did)}/commands`, {
          method: "POST",
          body: { cmd: "reboot", params: {} },
        });
        rebootJobs += 1;
      }
    }
    return { ok: true, fallback: true, device_count: ids.length, self_tests: selfTests, reboot_jobs: rebootJobs };
  };
  $("#gsCancel", view).addEventListener("click", closeSettingsModal);
  $("#gsSave", view).addEventListener("click", async () => {
    try {
      if (!editingSettingsSlot.metaKey) throw new Error("No group selected");
      const payload = collectSettingsPayload();
      const r = await saveGroupSettingsCompat(
        editingSettingsSlot.groupKey,
        editingSettingsSlot.tenantOwner,
        payload,
      );
      groupSettingsMap.set(editingSettingsSlot.metaKey, r || payload);
      renderGroups();
      closeSettingsModal();
      toast("Group settings saved", "ok");
    } catch (e) {
      toast(e.message || e, "err");
    }
  });
  $("#gsApply", view).addEventListener("click", async () => {
    try {
      if (!editingSettingsSlot.metaKey) throw new Error("No group selected");
      const payload = collectSettingsPayload();
      await saveGroupSettingsCompat(
        editingSettingsSlot.groupKey,
        editingSettingsSlot.tenantOwner,
        payload,
      );
      groupSettingsMap.set(editingSettingsSlot.metaKey, payload);
      const r = await runGroupApplyOnAction({
        groupKey: editingSettingsSlot.groupKey,
        ownerAdmin: editingSettingsSlot.tenantOwner,
        payload,
        apiCaps: groupApiCaps,
        saveApiCaps: saveGroupApiCaps,
        tryApplyRoute: (gk, oa) => tryGroupApiCall(
          groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}/apply`, oa),
          { method: "POST" },
        ),
        applyFallback: applyGroupSettingsFallback,
      });
      renderGroups();
      closeSettingsModal();
      toast(`Applied to ${Number(r.device_count || 0)} devices${r && r.fallback ? " (fallback mode)" : ""}`, "ok");
    } catch (e) {
      toast(e.message || e, "err");
    }
  });
  const clearGroupByDevicePatch = async (groupKey, tenantOwner) => {
    const slot = { metaKey: groupCardMetaKey(groupKey, tenantOwner), groupKey, tenantOwner: tenantOwner || "" };
    const ids = groupDeviceIdsFromSlot(slot);
    if (!ids.length) return { ok: true, changed: 0 };
    let changed = 0;
    for (const id of ids) {
      await api(`/devices/${encodeURIComponent(id)}/profile`, {
        method: "PATCH",
        body: { notification_group: "" },
      });
      changed += 1;
    }
    return { ok: true, changed };
  };
  const deleteGroupCard = async (groupKey, tenantOwner) => runGroupDeleteAction({
    groupKey,
    ownerAdmin: tenantOwner,
    apiCaps: groupApiCaps,
    saveApiCaps: saveGroupApiCaps,
    tryDeletePostRoute: (gk, oa) => tryGroupApiCall(
      groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}/delete`, oa),
      { method: "POST" },
    ),
    tryDeleteRoute: (gk, oa) => tryGroupApiCall(
      groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}`, oa),
      { method: "DELETE" },
    ),
    clearFallback: clearGroupByDevicePatch,
  });
  const openGroupModal = (metaKey) => {
    editingGroup = metaKey || "";
    const parsed = parseGroupMetaKey(editingGroup);
    const gk = parsed.groupKey || "";
    const m = meta[editingGroup] || { display_name: gk || "", owner_name: "", phone: "", email: "", device_ids: [] };
    const slot = { metaKey: editingGroup, groupKey: gk, tenantOwner: parsed.tenantOwner };
    $("#gmKey", view).value = canonicalGroupKey(gk) || "";
    $("#gmName", view).value = m.display_name || "";
    $("#gmOwner", view).value = m.owner_name || "";
    $("#gmPhone", view).value = m.phone || "";
    $("#gmEmail", view).value = m.email || "";
    const sel = new Set((m.device_ids || []).map(String));
    const pick = $("#gmDevices", view);
    const isSharedGroup = groupSharedBySlot(slot).length > 0;
    if (pick) {
      setChildMarkup(
        pick,
        devices
          .map((d) => groupDeviceRow(d, { checked: sel.has(String(d.device_id)), disabled: isSharedGroup }))
          .filter(Boolean)
          .join(""),
      );
      if (isSharedGroup) {
        prependChildMarkup(
          pick,
          `<p class="grp-pick-hint muted" style="margin:0 0 8px">Shared group: 成员只读。 · Device membership is read-only.</p>`,
        );
      }
    }
    grpModalEl.style.display = "flex";
  };
  const closeGroupModal = () => { grpModalEl.style.display = "none"; };
  let sharePrefillGroup = "";
  let sharePrefillOwner = "";
  let shareModalUsersCache = [];
  let shareModalEditSpec = null;
  let overviewShareItems = [];
  let shareDevChangeBound = false;

  const refreshOverviewShareItemsSilently = async () => {
    if (!(state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users"))))) return;
    try {
      const r = await api("/admin/shares?limit=2000", { timeoutMs: 12000 });
      overviewShareItems = Array.isArray(r.items) ? r.items.filter((x) => x && !x.revoked_at) : [];
    } catch (_) { /* keep previous cache */ }
  };

  const loadOverviewShareGrants = async () => {
    const wrap = $("#shareGrantsTableWrap", view);
    if (!wrap) return;
    if (!(state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users"))))) return;
    setChildMarkup(wrap, `<p class="muted" style="margin:0;padding:8px 0">Loading…</p>`);
    try {
      const r = await api("/admin/shares?limit=2000", { timeoutMs: 22000 });
      overviewShareItems = Array.isArray(r.items) ? r.items.filter((x) => x && !x.revoked_at) : [];
      const rows = [...overviewShareItems].sort((a, b) => {
        const c = String(a.device_id || "").localeCompare(String(b.device_id || ""));
        return c !== 0 ? c : String(a.grantee_username || "").localeCompare(String(b.grantee_username || ""));
      });
      if (!rows.length) {
        setChildMarkup(wrap, `<p class="muted" style="margin:0;padding:8px 0">No active shares in your scope.</p>`);
        return;
      }
      const body = rows.map((it) => {
        const did = escapeHtml(String(it.device_id || ""));
        const gu = escapeHtml(String(it.grantee_username || ""));
        const v = it.can_view ? "✓" : "—";
        const o = it.can_operate ? "✓" : "—";
        return `<tr data-device-id="${did}" data-grantee="${gu}">
          <td class="mono">${did}</td>
          <td class="mono">${gu}</td>
          <td>${v}</td>
          <td>${o}</td>
          <td style="white-space:nowrap">
            <button type="button" class="btn sm secondary js-share-grant-edit">Edit</button>
            <button type="button" class="btn sm danger js-share-grant-revoke">Revoke</button>
          </td>
        </tr>`;
      }).join("");
      setChildMarkup(wrap, `<div class="table-wrap"><table class="t"><thead><tr><th>Device</th><th>Grantee</th><th>View</th><th>Operate</th><th>Actions</th></tr></thead><tbody>${body}</tbody></table></div>`);
    } catch (e) {
      setChildMarkup(wrap, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  };

  const renderShareUserPickList = () => {
    const userListEl = $("#shareUserList", view);
    if (!userListEl) return;
    const preserve = new Map();
    $$("input[type='checkbox']", userListEl).forEach((inp) => {
      const v = String(inp.value || "").trim();
      if (!inp.disabled && v) preserve.set(v, !!inp.checked);
    });
    if (!shareModalUsersCache.length) {
      setChildMarkup(userListEl, `<p class="muted">No eligible users.</p>`);
      return;
    }
    const selIds = $$("#shareDeviceList input[type='checkbox']", view)
      .filter((x) => x.checked && !x.disabled)
      .map((x) => String(x.value || "").trim())
      .filter(Boolean);
    const locked = granteesFullyCoveringDevices(selIds, overviewShareItems);
    const eg = shareModalEditSpec;
    const editUser = eg ? String(eg.grantee_username || "").trim() : "";
    setChildMarkup(
      userListEl,
      shareModalUsersCache.map((x) => {
        const u = String(x.username || "").trim();
        const uname = escapeHtml(u);
        const role = escapeHtml(x.role || "user");
        const isEditUser = !!(eg && editUser && u === editUser);
        const isLocked = !isEditUser && selIds.length > 0 && locked.has(u);
        const checked = isEditUser ? true : !!preserve.get(u);
        const dis = isLocked || isEditUser ? "disabled" : "";
        const lockNote = isLocked ? ` <span class="muted" title="Already has ACL on every selected device">(already shared)</span>` : "";
        const cls = isLocked ? "grp-pick-item is-grant-locked" : "grp-pick-item";
        return `<label class="${cls}"><input type="checkbox" value="${uname}" ${checked ? "checked" : ""} ${dis}/> <span>${uname} <span class="mono">(${role})</span>${lockNote}</span></label>`;
      }).join("") || `<p class="muted">No active admin/user accounts.</p>`,
    );
  };

  const openShareModal = async (prefillGroup, prefillOwner, editSpec) => {
    if (!shareModalEl) return;
    shareModalEditSpec = editSpec && typeof editSpec === "object" ? editSpec : null;
    const editDid = shareModalEditSpec ? String(shareModalEditSpec.device_id || "").trim() : "";
    sharePrefillGroup = String(prefillGroup || "").trim();
    sharePrefillOwner = String(prefillOwner || "").trim();
    const devListEl = $("#shareDeviceList", view);
    const userListEl = $("#shareUserList", view);
    const hintEl = $("#shareTargetHint", view);
    const statEl = $("#shareBatchStat", view);
    const titleEl = $("#shareModalTitle", view);
    const noteEl = $("#shareEditNote", view);
    if (!devListEl || !userListEl || !hintEl || !statEl) return;
    statEl.textContent = "";
    if (titleEl) titleEl.textContent = shareModalEditSpec ? "Edit device share" : "Share devices / group";
    if (noteEl) {
      if (shareModalEditSpec) {
        noteEl.style.display = "block";
        noteEl.textContent = `Device ${editDid} · grantee ${String(shareModalEditSpec.grantee_username || "")} — adjust permissions and apply.`;
      } else {
        noteEl.style.display = "none";
        noteEl.textContent = "";
      }
    }
    if (shareModalEditSpec) {
      hintEl.textContent = "Permissions apply to this device–user pair (UPSERT). Group/fleet semantics stay with the owning tenant.";
      const pv = $("#sharePermView", view);
      const po = $("#sharePermOperate", view);
      if (pv) pv.checked = !!shareModalEditSpec.can_view;
      if (po) po.checked = !!shareModalEditSpec.can_operate;
    } else {
      hintEl.textContent = sharePrefillGroup
        ? `Prefilling devices in “${sharePrefillGroup}” — still device-level ACL only (not a “group share”).`
        : "Select devices and users. Grants are per-device; recipients never inherit your group keys or group-card settings. Users already fully covered on the current device selection are locked — use Edit in the table.";
      const pv = $("#sharePermView", view);
      const po = $("#sharePermOperate", view);
      if (pv) pv.checked = true;
      if (po) po.checked = false;
    }
    const picked = new Set(
      sharePrefillGroup && !shareModalEditSpec
        ? groupDeviceIdsFromList(sharePrefillGroup, sharePrefillOwner).map(String)
        : [],
    );
    if (shareModalEditSpec) {
      const row = devices.find((d) => String(d.device_id) === editDid);
      setChildMarkup(
        devListEl,
        row
          ? groupDeviceRow(row, { checked: true, disabled: true })
          : `<label class="grp-pick-item grp-pick-item--device">` +
            `<input type="checkbox" class="grp-pick-chk" value="${escapeHtml(editDid)}" checked disabled />` +
            `<span class="grp-pick-text">` +
            `<span class="grp-pick-name">${escapeHtml(editDid)}</span>` +
            `<span class="grp-pick-id mono">${escapeHtml(editDid)}</span></span></label>`,
      );
    } else {
      setChildMarkup(
        devListEl,
        devices
          .filter((d) => !d.is_shared)
          .map((d) => groupDeviceRow(d, { checked: picked.has(String(d.device_id)), disabled: false }))
          .filter(Boolean)
          .join("") || `<p class="muted">No own devices available.</p>`,
      );
    }
    if (!shareDevChangeBound) {
      shareDevChangeBound = true;
      devListEl.addEventListener("change", () => {
        if (shareModalEl && shareModalEl.style.display === "flex" && !shareModalEditSpec) renderShareUserPickList();
      });
    }
    await refreshOverviewShareItemsSilently();
    setChildMarkup(userListEl, `<p class="muted">Loading users…</p>`);
    try {
      const u = await api("/auth/users", { timeoutMs: 16000 });
      shareModalUsersCache = (u.items || []).filter((x) => {
        const role = String(x.role || "");
        const st = String(x.status || "active");
        if (!(st === "active" || st === "")) return false;
        if (state.me && state.me.role === "admin") return role === "user";
        return role === "admin" || role === "user";
      });
      renderShareUserPickList();
    } catch (e) {
      shareModalUsersCache = [];
      setChildMarkup(userListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
    const allDev = $("#shareSelAllDevices", view);
    const allUsr = $("#shareSelAllUsers", view);
    if (allDev) {
      allDev.checked = false;
      allDev.disabled = !!shareModalEditSpec;
      allDev.onchange = () => {
        $$("#shareDeviceList input[type='checkbox']:not([disabled])", view).forEach((x) => { x.checked = !!allDev.checked; });
        if (!shareModalEditSpec) renderShareUserPickList();
      };
    }
    if (allUsr) {
      allUsr.checked = false;
      allUsr.onchange = () => {
        $$("#shareUserList input[type='checkbox']:not([disabled])", view).forEach((x) => { x.checked = !!allUsr.checked; });
      };
    }
    shareModalEl.style.display = "flex";
  };
  const closeShareModal = () => {
    if (shareModalEl) shareModalEl.style.display = "none";
    shareModalEditSpec = null;
    const allDev = $("#shareSelAllDevices", view);
    if (allDev) allDev.disabled = false;
    const titleEl = $("#shareModalTitle", view);
    if (titleEl) titleEl.textContent = "Share devices / group";
    const noteEl = $("#shareEditNote", view);
    if (noteEl) { noteEl.style.display = "none"; noteEl.textContent = ""; }
  };
  $("#grpNew", view).addEventListener("click", () => openGroupModal(""));
  $("#gmCancel", view).addEventListener("click", closeGroupModal);
  const grpShareOpenBtn = $("#grpShareOpen", view);
  if (grpShareOpenBtn) grpShareOpenBtn.addEventListener("click", () => openShareModal("", "", null));
  const grpShareRefreshBtn = $("#grpShareRefresh", view);
  if (grpShareRefreshBtn) grpShareRefreshBtn.addEventListener("click", () => loadOverviewShareGrants());
  const shareGrantsWrap = $("#shareGrantsTableWrap", view);
  if (shareGrantsWrap) {
    shareGrantsWrap.addEventListener("click", async (ev) => {
      const btn = ev.target.closest("button");
      if (!btn) return;
      const tr = btn.closest("tr");
      if (!tr) return;
      const device_id = tr.getAttribute("data-device-id") || "";
      const grantee_username = tr.getAttribute("data-grantee") || "";
      if (!device_id || !grantee_username) return;
      const row = overviewShareItems.find((x) => String(x.device_id) === device_id && String(x.grantee_username) === grantee_username);
      if (btn.classList.contains("js-share-grant-edit")) {
        openShareModal("", "", row ? {
          device_id: row.device_id,
          grantee_username: row.grantee_username,
          can_view: !!Number(row.can_view),
          can_operate: !!Number(row.can_operate),
        } : {
          device_id,
          grantee_username,
          can_view: true,
          can_operate: false,
        });
        return;
      }
      if (btn.classList.contains("js-share-grant-revoke")) {
        if (!confirm(`Revoke share for ${grantee_username} on ${device_id}?`)) return;
        try {
          await api(`/admin/devices/${encodeURIComponent(device_id)}/share/${encodeURIComponent(grantee_username)}`, { method: "DELETE" });
          toast("Share revoked", "ok");
          await loadOverviewShareGrants();
          await refreshOverviewShareItemsSilently();
          try { bustDeviceListCaches(); } catch (_) {}
        } catch (e) { toast(e.message || e, "err"); }
      }
    });
  }
  const shareCancelBtn = $("#shareModalCancel", view);
  if (shareCancelBtn) shareCancelBtn.addEventListener("click", closeShareModal);
  const shareApplyBtn = $("#shareModalApply", view);
  if (shareApplyBtn) {
    shareApplyBtn.addEventListener("click", async () => {
      const statEl = $("#shareBatchStat", view);
      const deviceIds = $$("#shareDeviceList input[type='checkbox']", view).filter((x) => x.checked).map((x) => String(x.value || "").trim()).filter(Boolean);
      const usernames = $$("#shareUserList input[type='checkbox']", view).filter((x) => x.checked).map((x) => String(x.value || "").trim()).filter(Boolean);
      const canView = !!$("#sharePermView", view)?.checked;
      const canOperate = !!$("#sharePermOperate", view)?.checked;
      if (!deviceIds.length) { toast("Select at least one device", "err"); return; }
      if (!usernames.length) { toast("Select at least one user", "err"); return; }
      if (!canView && !canOperate) { toast("Select at least one permission", "err"); return; }
      const total = deviceIds.length * usernames.length;
      if (statEl) statEl.textContent = `Applying ${total} share grants…`;
      const res = await grantShareMatrix(
        deviceIds,
        usernames,
        { can_view: canView, can_operate: canOperate },
        (p) => { if (statEl) statEl.textContent = `Applied ${p.idx}/${p.total} · ok ${p.ok} · failed ${p.fail}`; },
      );
      const ok = Number(res.ok || 0);
      const fail = Number(res.fail || 0);
      if (fail === 0) {
        toast(`Sharing applied (${ok}/${total})`, "ok");
        closeShareModal();
        loadOverviewShareGrants();
        try { bustDeviceListCaches(); } catch (_) {}
      } else {
        toast(`Sharing done with failures (${ok} ok, ${fail} failed)`, "warn");
        loadOverviewShareGrants();
      }
    });
  }
  $("#gmSave", view).addEventListener("click", async () => {
    const key = canonicalGroupKey($("#gmKey", view).value || "");
    if (!key) { toast("Group key required", "err"); return; }
    const oldMetaKey = String(editingGroup || "").trim();
    const oldParsed = parseGroupMetaKey(oldMetaKey);
    const oldEntry = oldMetaKey && Object.prototype.hasOwnProperty.call(meta, oldMetaKey) ? meta[oldMetaKey] : null;
    const display_name = String($("#gmName", view).value || "").trim();
    const owner_name = String($("#gmOwner", view).value || "").trim();
    const phone = String($("#gmPhone", view).value || "").trim();
    const email = String($("#gmEmail", view).value || "").trim();
    const picks = Array.from($$("#gmDevices input[type='checkbox']", view)).filter((x) => x.checked).map((x) => String(x.value || "").trim());
    let tenantForMeta = oldParsed.tenantOwner || "";
    if (state.me && state.me.role === "superadmin") {
      for (const id of picks) {
        const dev = byId.get(String(id));
        const o = dev && String(dev.owner_admin || "").trim();
        if (o) { tenantForMeta = o; break; }
      }
    }
    const newMetaKey = groupCardMetaKey(key, tenantForMeta);
    if (groupSharedByNotificationKey(key).length > 0) {
      const keepIds = (oldEntry && Array.isArray(oldEntry.device_ids)) ? oldEntry.device_ids.map((x) => String(x)) : [];
      if (oldMetaKey && oldMetaKey !== newMetaKey && meta[oldMetaKey]) delete meta[oldMetaKey];
      meta[newMetaKey] = { display_name, owner_name, phone, email, device_ids: keepIds };
      saveGroupMeta(meta);
      try { bustDeviceListCaches(); } catch (_) {}
      closeGroupModal();
      renderGroups();
      toast("Group card updated (shared group — device list is owner-managed)", "ok");
      return;
    }
    const previousDeviceIds = oldMetaKey ? groupDeviceIdsFromList(oldParsed.groupKey, oldParsed.tenantOwner) : [];
    if (picks.length > 0) {
      try {
        for (const id of picks) {
          await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: key } });
        }
        const nextSet = new Set(picks);
        for (const id of previousDeviceIds) {
          if (!nextSet.has(id)) {
            await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: "" } });
          }
        }
      } catch (e) {
        toast(e.message || e, "err");
        return;
      }
    } else {
      for (const id of previousDeviceIds) {
        try {
          await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: "" } });
        } catch (e) {
          toast(e.message || e, "err");
          return;
        }
      }
    }
    if (oldMetaKey && oldMetaKey !== newMetaKey && meta[oldMetaKey]) delete meta[oldMetaKey];
    meta[newMetaKey] = { display_name, owner_name, phone, email, device_ids: picks };
    saveGroupMeta(meta);
    try { bustDeviceListCaches(); } catch (_) {}
    closeGroupModal();
    renderGroups();
    toast("Group saved — device notification groups synced for sibling alarm fan-out", "ok");
  });
  groupCardsEl.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button");
    if (btn) {
      const slot = readSlotFromBtn(btn);
      const g = slot.groupKey;
      if (!g) return;
      if (btn.classList.contains("js-edit-group")) {
        openGroupModal(slot.metaKey);
        return;
      }
      if (btn.classList.contains("js-group-settings")) {
        openSettingsModal(slot);
        return;
      }
      if (btn.classList.contains("js-share-group")) {
        if (!(state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users"))))) {
          toast("No sharing permission", "err"); return;
        }
        openShareModal(g, slot.tenantOwner, null);
        return;
      }
      if (btn.classList.contains("js-del-group")) {
        if (groupSharedBySlot(slot).length > 0) { toast("Shared group cannot be deleted", "err"); return; }
        if (!confirm(`Delete group card "${g}"?`)) return;
        try {
          await deleteGroupCard(g, slot.tenantOwner);
          if (slot.metaKey && meta[slot.metaKey]) delete meta[slot.metaKey];
          saveGroupMeta(meta);
          renderGroups();
          toast("Group deleted", "ok");
        } catch (e) {
          toast(e.message || e, "err");
        }
        return;
      }
      if (!can("can_alert")) { toast("No can_alert capability", "err"); return; }
      const ids = groupDeviceIdsFromSlot(slot);
      if (ids.length === 0) { toast("No devices in this group", "warn"); return; }
      const action = btn.classList.contains("js-alert-on") ? "on" : "off";
      if (!confirm(`${action === "on" ? "Open" : "Close"} alarm for ${ids.length} devices in ${g}?`)) return;
      try {
        if (action === "on") {
          const payload = groupTriggerPayloadFromSettings(groupSettingsMap.get(slot.metaKey) || {});
          await runGroupApplyOnAction({
            groupKey: g,
            ownerAdmin: slot.tenantOwner,
            payload,
            apiCaps: groupApiCaps,
            saveApiCaps: saveGroupApiCaps,
            tryApplyRoute: (gk, oa) => tryGroupApiCall(
              groupApiSuffixWithOwner(`/${encodeURIComponent(gk)}/apply`, oa),
              { method: "POST" },
            ),
            applyFallback: applyGroupSettingsFallback,
          });
        } else {
          const prevTimer = groupDelayTimers.get(slot.metaKey);
          if (prevTimer) {
            clearTimeout(prevTimer);
            groupDelayTimers.delete(slot.metaKey);
          }
          await api("/alerts", { method: "POST", body: { action, duration_ms: DEFAULT_REMOTE_SIREN_MS, device_ids: ids } });
        }
        toast(`${action === "on" ? "Alarm ON" : "Alarm OFF"} · ${ids.length}`, "ok");
      } catch (e) {
        toast(e.message || e, "err");
      }
      return;
    }
    const card = ev.target.closest(".js-group-card");
    if (!card) return;
    const g = card.dataset.group || "";
    if (!g) return;
    const ow = String(card.getAttribute("data-owner") || "").trim();
    location.hash = `#/group/${encodeURIComponent(g)}${ow ? `?owner=${encodeURIComponent(ow)}` : ""}`;
  });
  const OVERVIEW_LIVE_MS = 7500;
  const refreshOverviewLive = async () => {
    if (!isRouteCurrent(routeSeq)) return;
    try {
      bustApiGetCachedPrefix("/dashboard/overview");
      bustApiGetCachedPrefix("/devices");
      const [ovN, listN] = await Promise.all([
        api("/dashboard/overview", { timeoutMs: 20000, retries: 2 }),
        api("/devices", { timeoutMs: 20000, retries: 2 }),
      ]);
      if (!isRouteCurrent(routeSeq)) return;
      ov = ovN || ov;
      list = listN || list;
      state.overviewCache = { ov, list, ts: Date.now() };
      devices = Array.isArray(list.items) ? list.items.slice() : [];
      byId = new Map(devices.map((d) => [String(d.device_id), d]));
      const hh = state.health || {};
      const httpOk = !!(hh.ok ?? true);
      const mqConnected = !!(hh.mqtt_connected ?? ov.mqtt_connected);
      const mqQDepth = Number(hh.mqtt_ingest_queue_depth || 0);
      const mqDropped = Number(hh.mqtt_ingest_dropped || 0);
      const totalDevices = Number(ov.total_devices != null ? ov.total_devices : devices.length);
      const onlineDevices = Number((ov.presence && ov.presence.online != null) ? ov.presence.online : devices.filter(isOnline).length);
      const offlineDevices = Math.max(0, totalDevices - onlineDevices);
      const txBps = Number((ov.throughput && ov.throughput.tx_bps_total) || 0);
      const rxBps = Number((ov.throughput && ov.throughput.rx_bps_total) || 0);
      const bps = (v) => {
        v = Number(v || 0);
        if (v < 1024) return `${v.toFixed(0)} B/s`;
        if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
        return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
      };
      const mqStatus = !mqConnected ? "Disconnected" : (mqDropped > 0 || mqQDepth >= 300 ? "Warning" : "Healthy");
      const mqClass = !mqConnected ? "revoked" : (mqStatus === "Warning" ? "offline" : "online");
      const serverHeadlineLive = isSuper
        ? `${httpOk ? "HTTP OK" : "HTTP DOWN"} · ${mqConnected ? "MQTT UP" : "MQTT DOWN"}`
        : (httpOk && mqConnected ? "Status ok" : "Status down");
      patchOverviewHeader({
        server: serverHeadlineLive,
        devices: totalDevices,
        online: onlineDevices,
        offline: offlineDevices,
        tx: bps(txBps),
        rx: bps(rxBps),
        queue: mqQDepth,
        dropped: mqDropped,
        risk: mqStatus,
        riskClass: mqClass,
      });
      syncGroupMetaWithDevices(meta, devices);
      saveGroupMeta(meta);
      repopOvOwnerDatalist();
      renderGroups();
    } catch (_) {}
  };
  scheduleRouteTicker(routeSeq, "overview-live", refreshOverviewLive, OVERVIEW_LIVE_MS);
  const ovOwnerInp = $("#ovOwnerFilter", view);
  const ovOwnerClr = $("#ovOwnerClear", view);
  if (ovOwnerInp && state.me && state.me.role === "superadmin") {
    repopOvOwnerDatalist();
    const onOwnerFilt = () => {
      ownerFilterQ = String(ovOwnerInp.value || "");
      renderGroups();
    };
    ovOwnerInp.addEventListener("input", onOwnerFilt);
    ovOwnerInp.addEventListener("change", onOwnerFilt);
    if (ovOwnerClr) {
      ovOwnerClr.addEventListener("click", () => {
        ovOwnerInp.value = "";
        ownerFilterQ = "";
        renderGroups();
      });
    }
  }
  renderGroups();
  if (state.me && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users")))) {
    loadOverviewShareGrants();
  }
});
