/**
 * Route: #/devices — All devices grid + per-row actions.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("devices", async (view, args, routeSeq) => {
  const id = decodeURIComponent(args[0] || "");
  if (!id) {
    setCrumb("All devices");
    let allItems = [];
    const hintById = new Map();
    const selectedIds = new Set();
    const filteredItems = () => {
      const inp = $("#allDevFilter", view);
      const q = inp ? String(inp.value || "").trim().toLowerCase() : "";
      return allItems.filter((d) => {
        if (!q) return true;
        const did = String(d.device_id || "").toLowerCase();
        const nm = String(d.display_label || "").toLowerCase();
        const grp = String(d.notification_group || "").toLowerCase();
        const zn = String(d.zone || "").toLowerCase();
        return did.includes(q) || nm.includes(q) || grp.includes(q) || zn.includes(q);
      });
    };
    const bulkBarState = () => {
      const c = selectedIds.size;
      const stat = $("#bulkSelStat", view);
      const grpBtn = $("#bulkApplyGroup", view);
      const zoBtn = $("#bulkApplyZone", view);
      const zcBtn = $("#bulkClearZone", view);
      const selVisBtn = $("#bulkSelectVisible", view);
      const clrBtn = $("#bulkClearSel", view);
      const totalVisible = filteredItems().length;
      if (stat) stat.textContent = `${c} selected · ${totalVisible} visible`;
      const disable = c === 0;
      if (grpBtn) grpBtn.disabled = disable;
      if (zoBtn) zoBtn.disabled = disable;
      if (zcBtn) zcBtn.disabled = disable;
      if (clrBtn) clrBtn.disabled = disable;
      if (selVisBtn) selVisBtn.disabled = totalVisible === 0;
    };
    const deviceListCard = (d) => {
      const on = isOnline(d);
      const did = String(d.device_id || "");
      const checked = selectedIds.has(did);
      const hasLabel = !!(d.display_label && String(d.display_label).trim());
      const titleHtml = hasLabel
        ? `<div class="device-card__title-row">` +
          `<span class="device-primary-name device-card__title-name">${escapeHtml(String(d.display_label).trim())}</span>` +
          `<span class="device-card__sn mono" title="${escapeHtml(did)}">${escapeHtml(did)}</span>` +
          `</div>`
        : `<div class="device-card__title-row device-card__title-row--mono">` +
          `<span class="device-primary-name mono device-card__sn" title="${escapeHtml(did)}">${escapeHtml(did || "unknown")}</span>` +
          `</div>`;
      const letter = escapeHtml((d.display_label || d.device_id || "?").slice(0, 1).toUpperCase());
      const spLine = d.status_preview && d.status_preview.line ? escapeHtml(String(d.status_preview.line)) : "—";
      const showOwnerTag = !!(d.owner_admin && state.me && (state.me.role === "superadmin" || d.is_shared));
      const scopeLead =
        d.is_shared && d.shared_by
          ? `<span class="device-card__meta-k">Shared</span><span class="device-card__meta-scope">${escapeHtml(String(d.shared_by))}</span><span class="device-card__meta-sep" aria-hidden="true"> · </span>`
          : "";
      const needFw = !!(d.firmware_hint && d.firmware_hint.update_available && firmwareHintStillValid(d.fw, d.firmware_hint));
      const fwBlock = d.fw
        ? `<div class="device-card__firmware">` +
          `<span class="device-fw-inline" role="group" aria-label="Firmware">` +
          `<span class="chip device-fw-chip" title="Reported firmware">v${escapeHtml(d.fw)}</span>` +
          (needFw
            ? `<span class="device-fw-pill" title="Newer build on server / 服务器上有较新版本">Update / 有更新</span>` +
              `<button type="button" class="btn sm secondary fw-hint-cta fw-hint-cta--sm js-fw-hint" data-did="${escapeHtml(did)}" title="View update details / 查看更新" aria-label="Firmware update">更新</button>`
            : "") +
          `</span></div>`
        : "";
      const listCorner = `<div class="device-card__corner-tr device-card__corner-tr--list-bulk" role="group" aria-label="Selection">` +
        (showOwnerTag ? `<span class="card-owner-tag" title="Owning admin / 租户">${escapeHtml(String(d.owner_admin))}</span>` : "") +
        `<label class="device-card__pick-wrap muted">` +
        `<input type="checkbox" class="bulk-dev-pick" data-device-id="${escapeHtml(did)}" ${checked ? "checked" : ""} />` +
        `<span>Pick</span></label></div>`;
      return `<div class="device-card device-card--row-thumb${showOwnerTag ? " device-card--row-thumb--wide-pad" : ""}" style="position:relative">` +
        listCorner +
        `<a href="#/devices/${encodeURIComponent(d.device_id)}" style="display:flex;gap:10px;text-decoration:none;color:inherit;flex:1;min-width:0">` +
        `<div class="device-thumb device-thumb--list" aria-hidden="true">${letter}</div>` +
        `<div class="device-card--row-body">` +
        `<h3 class="device-card__h3">${titleHtml}</h3>` +
        `<div class="device-card__status">` +
        `<div class="device-card__pills">` +
        `<span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>` +
        (d.zone ? `<span class="chip device-zone-chip">${escapeHtml(d.zone)}</span>` : "") +
        (d.is_shared ? `<span class="badge accent" title="shared device">shared</span>` : "") +
        `</div>` +
        `${fwBlock}` +
        `</div>` +
        `<div class="device-card__meta-compact meta">` +
        `<div class="device-card__meta-row"><span class="device-card__meta-k">Live</span><span class="device-card__meta-v">${spLine}</span></div>` +
        `<div class="device-card__meta-row">${scopeLead}<span class="device-card__meta-k">Updated</span><span class="device-card__meta-v">${escapeHtml(fmtRel(d.updated_at))}</span></div>` +
        `</div>` +
        `</div></a></div>`;
    };
    const applyFilter = () => {
      const items = filteredItems();
      const grid = $("#allDevicesGrid", view);
      if (!grid) return;
      try {
        grid.classList.remove("device-grid--skeleton");
        grid.removeAttribute("aria-busy");
      } catch (_) {}
      if (allItems.length === 0) {
        setChildMarkup(grid, `<p class="muted" style="padding:8px 0">No devices in your scope.</p>`);
        bulkBarState();
        return;
      }
      setChildMarkup(
        grid,
        items.length === 0
          ? `<p class="muted" style="padding:8px 0">No matches.</p>`
          : items.map(deviceListCard).join(""),
      );
      bulkBarState();
    };
    const runBulkProfile = async (payload) => {
      if (!selectedIds.size) { toast("Select at least one device", "err"); return; }
      const ids = Array.from(selectedIds.values());
      const r = await api("/devices/bulk/profile", {
        method: "POST",
        body: Object.assign({ device_ids: ids }, payload || {}),
      });
      bustDeviceListCaches();
      toast(`Bulk done · ${Number(r.count || ids.length)} devices`, "ok");
      await loadDevicesAndHints();
    };
    const mergeFirmwareHintsObject = (raw) => {
      const o = raw && typeof raw === "object" ? raw : {};
      hintById.clear();
      for (const k of Object.keys(o)) hintById.set(k, o[k]);
      for (const it of allItems) {
        const k = String(it.device_id);
        const h = o[k];
        it.firmware_hint = h && h.update_available && firmwareHintStillValid(it.fw, h) ? h : null;
      }
    };
    const loadDevicesAndHints = async () => {
      if (!isRouteCurrent(routeSeq)) return;
      let r;
      try {
        r = await api("/devices", { timeoutMs: 20000, retries: 2 });
      } catch (e) {
        if (isRouteCurrent(routeSeq)) toast(String(e && e.message) || "Failed to load devices", "err");
        return;
      }
      if (!isRouteCurrent(routeSeq)) return;
      allItems = Array.isArray(r.items) ? r.items : [];
      for (const did of Array.from(selectedIds)) {
        if (!allItems.some((x) => String(x.device_id) === did)) selectedIds.delete(did);
      }
      for (const it of allItems) {
        it.firmware_hint = null;
      }
      applyFilter();
      try {
        const hintRes = await api("/devices/firmware-hints", { timeoutMs: 25000, retries: 0 });
        if (!isRouteCurrent(routeSeq)) return;
        mergeFirmwareHintsObject((hintRes && hintRes.hints) || {});
      } catch (_) {
        /* list already visible; hints are optional */
      }
      if (isRouteCurrent(routeSeq)) applyFilter();
    };
    mountView(view, `
      <header class="page-head">
        <h2>All devices</h2>
        <p class="muted">Thumbnails and quick status. Multi-select for production bulk updates.</p>
      </header>
      <div class="card" style="margin:0 0 12px">
        <div class="inline-form" style="margin-top:4px">
          <label class="field" style="max-width:min(100%, 360px)">
            <span>Filter</span>
            <input type="search" id="allDevFilter" placeholder="id / name / group / zone" autocomplete="off" />
          </label>
        </div>
        <div class="action-bar" style="margin-top:12px">
          <span class="chip" id="bulkSelStat">0 selected · 0 visible</span>
          <button class="btn sm secondary" id="bulkSelectVisible" type="button">Select visible</button>
          <button class="btn sm secondary" id="bulkClearSel" type="button" disabled>Clear selection</button>
          <details class="toolbar-collapse" style="min-width:260px;flex:1 1 420px">
            <summary>Bulk actions</summary>
            <div class="inline-form" style="margin-top:2px">
              <label class="field">
                <span>Bulk group</span>
                <input id="bulkGroupValue" maxlength="80" placeholder="empty = clear group" />
              </label>
              <button class="btn sm" id="bulkApplyGroup" type="button" disabled>Apply group</button>
              <label class="field">
                <span>Zone override</span>
                <input id="bulkZoneValue" maxlength="31" placeholder="e.g. all / Zone-A" />
              </label>
              <div class="row" style="gap:8px;justify-content:flex-end;flex-wrap:wrap">
                <button class="btn sm" id="bulkApplyZone" type="button" disabled>Apply zone</button>
                <button class="btn sm secondary" id="bulkClearZone" type="button" disabled>Clear zone override</button>
              </div>
            </div>
          </details>
        </div>
      </div>
      <div id="allDevicesGrid" class="device-grid device-grid--skeleton" aria-busy="true">
        ${[1, 2, 3, 4, 5, 6].map(() => `<div class="device-card device-card--skeleton" role="presentation"><div class="device-card--skeleton__thumb"></div><div class="device-card--skeleton__body"><div class="device-card--skeleton__line device-card--skeleton__line--w80"></div><div class="device-card--skeleton__line device-card--skeleton__line--w40"></div><div class="device-card--skeleton__line device-card--skeleton__line--w90"></div></div></div>`).join("")}
      </div>
    `);
    const f = $("#allDevFilter", view);
    if (f) f.addEventListener("input", () => { applyFilter(); });
    const grid = $("#allDevicesGrid", view);
    if (grid) {
      grid.addEventListener("change", (ev) => {
        const el = ev.target;
        if (!(el instanceof HTMLInputElement)) return;
        if (!el.classList.contains("bulk-dev-pick")) return;
        const did = String(el.dataset.deviceId || "").trim();
        if (!did) return;
        if (el.checked) selectedIds.add(did);
        else selectedIds.delete(did);
        bulkBarState();
      });
    }
    const selVis = $("#bulkSelectVisible", view);
    if (selVis) {
      selVis.addEventListener("click", () => {
        for (const d of filteredItems()) {
          const did = String(d.device_id || "").trim();
          if (did) selectedIds.add(did);
        }
        applyFilter();
      });
    }
    const clrSel = $("#bulkClearSel", view);
    if (clrSel) {
      clrSel.addEventListener("click", () => {
        selectedIds.clear();
        applyFilter();
      });
    }
    const grpBtn = $("#bulkApplyGroup", view);
    if (grpBtn) {
      grpBtn.addEventListener("click", async () => {
        const rawG = String($("#bulkGroupValue", view)?.value || "").trim();
        const grpVal = rawG ? canonicalGroupKey(rawG) : "";
        const promptTxt = grpVal
          ? `Apply group "${grpVal}" to ${selectedIds.size} selected device(s)?`
          : `Clear group for ${selectedIds.size} selected device(s)?`;
        if (!confirm(promptTxt)) return;
        try {
          await runBulkProfile({ set_notification_group: true, notification_group: grpVal });
        } catch (e) { toast(e.message || e, "err"); }
      });
    }
    const zoneBtn = $("#bulkApplyZone", view);
    if (zoneBtn) {
      zoneBtn.addEventListener("click", async () => {
        const z = String($("#bulkZoneValue", view)?.value || "").trim();
        if (!z) { toast("Enter zone value", "err"); return; }
        if (!confirm(`Apply zone override "${z}" to ${selectedIds.size} selected device(s)?`)) return;
        try {
          await runBulkProfile({ set_zone_override: true, zone_override: z });
        } catch (e) { toast(e.message || e, "err"); }
      });
    }
    const clrZoneBtn = $("#bulkClearZone", view);
    if (clrZoneBtn) {
      clrZoneBtn.addEventListener("click", async () => {
        if (!confirm(`Clear zone override for ${selectedIds.size} selected device(s)?`)) return;
        try {
          await runBulkProfile({ clear_zone_override: true });
        } catch (e) { toast(e.message || e, "err"); }
      });
    }
    view.addEventListener("click", (ev) => {
      const t = ev.target && ev.target.closest && ev.target.closest(".js-fw-hint");
      if (!t) return;
      ev.preventDefault();
      ev.stopPropagation();
      const did0 = t.getAttribute("data-did");
      const h = did0 && hintById.get(did0);
      const row = did0 ? allItems.find((x) => String(x.device_id) === String(did0)) : null;
      if (h) {
        openGlobalFwHintDialog(h, {
          currentFw: row && row.fw != null ? String(row.fw) : "",
          deviceId: String(did0 || ""),
          canOperateThisDevice: undefined,
        });
      }
    });
    requestAnimationFrame(() => {
      setTimeout(() => { void loadDevicesAndHints(); }, 0);
    });
    scheduleRouteTicker(routeSeq, "devices-list-live", loadDevicesAndHints, 22000);
    return;
  }
  const isSuperViewer = !!(state.me && state.me.role === "superadmin");

  let d = await api(`/devices/${encodeURIComponent(id)}`);
  const canOperateThisDevice = !!(d.can_operate ?? (state.me && (state.me.role === "superadmin" || state.me.role === "admin")));
  window.__devicePollLocks = window.__devicePollLocks || new Map();
  const runPollDedup = (key, worker) => {
    const k = String(key || "");
    if (!k) return worker();
    const locks = window.__devicePollLocks;
    if (locks.has(k)) return locks.get(k);
    const p = (async () => {
      try {
        return await worker();
      } finally {
        if (locks.get(k) === p) locks.delete(k);
      }
    })();
    locks.set(k, p);
    return p;
  };
  setCrumb(d.display_label ? `Device · ${d.display_label}` : `Device · ${id}`);
  const bps = (v) => {
    v = Number(v || 0);
    if (v < 1024) return v.toFixed(0) + " B/s";
    if (v < 1024 * 1024) return (v / 1024).toFixed(1) + " KB/s";
    return (v / 1024 / 1024).toFixed(2) + " MB/s";
  };
  const reasonEn = {
    none: "OK",
    power_low: "Power low",
    network_lost: "Network lost",
    signal_weak: "Weak signal",
  };
  const deviceLiveModel = (dev) => {
    const on = isOnline(dev);
    const s = dev.last_status_json || {};
    const reason = s.disconnect_reason || (on ? "none" : "network_lost");
    const outV = (s.vbat == null || s.vbat < 0) ? "—" : `${Number(s.vbat).toFixed(2)} V`;
    const rssi = (s.rssi == null || s.rssi === -127) ? "—" : `${s.rssi} dBm`;
    const netT = String(s.net_type || dev.net_type || "");
    const wifiSsidDd = netT === "wifi"
      ? ((s.wifi_ssid != null && String(s.wifi_ssid).length > 0)
        ? escapeHtml(String(s.wifi_ssid))
        : `<span class="muted">Not associated</span>`)
      : `<span class="muted">N/A (${escapeHtml(netT || "—")})</span>`;
    const wifiChDd = (netT === "wifi" && s.wifi_channel != null && Number(s.wifi_channel) > 0)
      ? escapeHtml(String(s.wifi_channel))
      : "—";
    return { on, s, reason, outV, rssi, wifiSsidDd, wifiChDd };
  };
  const dm = deviceLiveModel(d);
  const rawCommandDrawer = (state.me && state.me.role === "superadmin") ? `
    <details class="card device-drawer">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Raw command</span>
        <span class="device-drawer__hint muted">Superadmin · manual MQTT cmd</span>
      </summary>
      <div class="device-drawer__body">
        <label class="field"><span>cmd</span><input id="cmdName" placeholder="get_info / ota" ${can("can_send_command") ? "" : "disabled"} /></label>
        <label class="field" style="margin-top:8px"><span>params (JSON)</span><textarea id="cmdParams" placeholder='{"key":"value"}' ${can("can_send_command") ? "" : "disabled"}></textarea></label>
        <div class="row" style="margin-top:8px;justify-content:flex-end">
          <button class="btn" id="sendCmd" ${can("can_send_command") ? "" : "disabled"}>Send</button>
        </div>
      </div>
    </details>` : "";
  const canUseSharePanel = !!(
    state.me
    && (state.me.role === "superadmin" || (state.me.role === "admin" && can("can_manage_users")))
    && (!d.is_shared || state.me.role === "superadmin")
  );
  const sharePanel = canUseSharePanel ? `
    <details class="card device-drawer" id="sharePanel">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Sharing</span>
        <span class="device-drawer__hint muted">Grant / revoke · expand</span>
      </summary>
      <div class="device-drawer__body">
        <div class="row" style="justify-content:flex-end;margin-bottom:8px">
          <button class="btn secondary btn-tap sm" type="button" id="shareRefresh">Refresh</button>
        </div>
        <p class="muted" style="margin:0 0 10px">Grant or revoke per-account access (admin: your users only).</p>
        <div class="inline-form" style="margin-top:4px">
          <label class="field grow"><span>Grantee username</span>
            <input id="shareUser" placeholder="admin_x or user_x" />
          </label>
          <label class="field"><span>View</span>
            <input id="shareCanView" type="checkbox" checked />
          </label>
          <label class="field"><span>Operate</span>
            <input id="shareCanOperate" type="checkbox" />
          </label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn btn-tap" id="shareGrant">Grant / Update</button>
          </div>
        </div>
        <div id="shareList" style="margin-top:12px"></div>
      </div>
    </details>
  ` : "";
  const renderMsgFeed = (items) => {
    const msgItems = Array.isArray(items) ? items : [];
    if (msgItems.length === 0) return `<p class="muted audit-empty">No messages.</p>`;
    return `<div class="audit-feed">${msgItems.map((m) => {
      const plRows = messagePayloadRows(m.payload || {});
      const extra = plRows.length
        ? `<div class="audit-extra">${plRows.map((row) =>
            `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`,
        ).join("")}</div>`
        : "";
      return `<article class="audit-item">
        <div class="audit-item-top">
          <div class="audit-time">
            <span class="audit-ts mono">${escapeHtml(fmtTs(m.ts_received))}</span>
            <span class="muted audit-rel">${escapeHtml(fmtRel(m.ts_received))}</span>
          </div>
          <span class="chip">${escapeHtml(m.channel || "—")}</span>
        </div>
        ${extra}
      </article>`;
    }).join("")}</div>`;
  };
  const mqttMsgPanel = isSuperViewer ? `
    <div class="card">
      <details id="mqttMsgDetails">
        <summary style="cursor:pointer;font-weight:600">MQTT debug messages (latest 25)</summary>
        <p class="muted" style="margin:8px 0 0">Debug-only raw device uplink snapshots. Hidden by default to keep the page clean.</p>
        <div class="divider"></div>
        <div class="audit-feed-wrap" id="devMsgsList"><p class="muted">Expand to load…</p></div>
      </details>
    </div>` : "";
  mountView(view, `
    <nav class="device-page-back-nav" aria-label="Device navigation">
      <a href="#/devices" class="btn secondary sm btn-tap device-page-back">← Back</a>
    </nav>
    <div class="card device-focus-layout">
      <div class="device-focus-left">
        <div class="row" style="align-items:flex-start;flex-wrap:wrap;gap:10px">
          <div class="device-page-head" style="flex:1;min-width:0">
            <div class="device-primary-name">${escapeHtml(d.display_label || id)}</div>
            ${d.display_label ? `<div class="device-id-sub mono">${escapeHtml(id)}</div>` : ""}
          </div>
          <span class="badge ${dm.on ? "online" : "offline"}" id="devOnlineBadge">${dm.on ? "online" : "offline"}</span>
          <span class="chip" id="devReasonChip">${escapeHtml(reasonEn[dm.reason] || dm.reason)}</span>
          ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
        </div>
        <div class="device-hero-card">
          <div class="device-thumb">${escapeHtml((d.display_label || id || "?").slice(0, 1).toUpperCase())}</div>
          <div class="device-hero-meta">
            <div class="device-hero-line device-hero-line--fw">
              <span class="muted">Firmware</span>
              <div class="device-hero-fw">
                <span class="mono" id="devFwVer">${escapeHtml(d.fw || "—")}</span>
                <span class="device-fw-state" id="devFwStatus" aria-live="polite">—</span>
                <button type="button" class="btn sm secondary fw-hint-cta" id="devFwHintBtn" style="display:${(d.firmware_hint && d.firmware_hint.update_available && firmwareHintStillValid(d.fw, d.firmware_hint)) ? "inline-flex" : "none"}" title="New firmware on server / 服务器有新固件">更新</button>
              </div>
            </div>
            <div class="device-hero-line"><span class="muted">Platform</span><span class="mono">${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}</span></div>
            <div class="device-hero-line"><span class="muted">Network</span><span class="mono" id="devNetRow">${escapeHtml(d.net_type || "—")} · ${escapeHtml(dm.s.ip || "—")}</span></div>
            <div class="device-hero-line"><span class="muted">Wi‑Fi</span><span id="devWifiSsid">${dm.wifiSsidDd}</span></div>
            <div class="device-hero-line"><span class="muted">Output V</span><span class="mono" id="devOutV">${escapeHtml(dm.outV)}</span></div>
            <div class="device-hero-line"><span class="muted">Tx / Rx</span><span class="mono" id="devTxRx">${escapeHtml(bps(dm.s.tx_bps))} / ${escapeHtml(bps(dm.s.rx_bps))}</span></div>
            <div class="device-hero-line"><span class="muted">RSSI</span><span class="mono" id="devRssi">${escapeHtml(dm.rssi)}</span></div>
            <div class="device-hero-line"><span class="muted">Wi‑Fi CH</span><span class="mono" id="devWifiCh">${dm.wifiChDd}</span></div>
            <div class="device-hero-line"><span class="muted">Uptime</span><span class="mono" id="devUptime">${escapeHtml((dm.s.uptime_s ? `${Math.floor(dm.s.uptime_s / 3600)}h ${Math.floor((dm.s.uptime_s % 3600) / 60)}m` : "—"))}</span></div>
            <div class="device-hero-line"><span class="muted">Heap</span><span class="mono" id="devHeap">${escapeHtml(dm.s.free_heap ? `${dm.s.free_heap} B (min ${dm.s.min_free_heap || "?"} B)` : "—")}</span></div>
            <div class="device-hero-line"><span class="muted">Disconnect</span><span class="mono" id="devDisconnect">${escapeHtml(dm.reason)}</span></div>
            <div class="device-hero-line"><span class="muted">Updated</span><span id="devUpdated">${escapeHtml(fmtTs(d.updated_at))} (${escapeHtml(fmtRel(d.updated_at))})</span></div>
          </div>
        </div>
      </div>
      <aside class="device-focus-right">
        <div class="card" style="margin:0">
          <h3 style="margin:0 0 8px">Ownership</h3>
          <p class="muted" style="margin:0 0 8px">Current account binding for this device.</p>
          <div class="device-owner-kv">
            <div><span class="muted">Account</span><span class="mono">${escapeHtml(d.owner_admin || d.shared_by || "—")}</span></div>
            <div><span class="muted">Email</span><span class="mono">${escapeHtml(d.owner_email || "—")}</span></div>
            <div><span class="muted">Shared</span><span class="mono">${d.is_shared ? `yes · by ${escapeHtml(d.shared_by || "?")}` : "no"}</span></div>
          </div>
        </div>
        <div class="card" style="margin:12px 0 0">
          <h3 style="margin:0 0 8px;font-size:13px;color:var(--text-muted)">Notifications</h3>
          ${d.is_shared ? `<p class="muted" style="margin:0 0 8px">Device share is <strong>device-scoped</strong> only. You cannot see or edit the owner&rsquo;s notification group; use your own tenant group cards or single-device actions.</p>` : ""}
          <div class="row" style="gap:10px;align-items:flex-end;flex-wrap:wrap">
            <label class="field grow"><span>Display name</span>
              <input id="dispLabel" value="${escapeHtml(d.display_label || "")}" maxlength="80" />
            </label>
            <label class="field grow"><span>Notification group</span>
              <input id="notifGroup" value="${escapeHtml(d.notification_group || "")}" maxlength="80" placeholder="e.g. Warehouse A" ${d.is_shared ? "disabled title=\"Owner tenant only\"" : ""} />
            </label>
            <button class="btn secondary btn-tap" type="button" id="saveProfile">Save</button>
          </div>
        </div>
      </aside>
    </div>

    <div class="split device-quick-split">
      <div class="card">
        <h3>Quick actions</h3>
        ${d.is_shared ? `<p class="muted" style="margin:0 0 8px">Shared by <span class="mono">${escapeHtml(d.shared_by || "?")}</span>. Delete/Revoke actions are disabled for shared devices.</p>` : ""}
        <div class="row">
          <button class="btn" id="alertOn" ${can("can_alert") ? "" : "disabled"}>Siren ON</button>
          <button class="btn secondary" id="alertOff" ${can("can_alert") ? "" : "disabled"}>Siren OFF</button>
          <button class="btn secondary" id="selfTest" ${can("can_send_command") && canOperateThisDevice ? "" : "disabled"}>Self-test</button>
        </div>
        <div class="row" style="margin-top:10px">
          <input id="rebootDelay" placeholder="Delay seconds (e.g. 30)" style="max-width:200px" />
          <button class="btn secondary" id="doReboot" ${can("can_send_command") && canOperateThisDevice ? "" : "disabled"}>Schedule reboot</button>
        </div>
        <div class="row" style="margin-top:14px">
          <button class="btn secondary" id="unrevoke" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Unrevoke</button>
        </div>
      </div>
    </div>
    ${sharePanel}

    <details class="card device-drawer" id="wifiCtlCard">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Wi‑Fi (device)</span>
        <span class="device-drawer__hint muted">Provision · NVS · expand</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0 0 10px">Credentials are written to device NVS, then the board reboots. Optional <strong>follow‑up commands</strong> are stored in NVS and run <strong>in order</strong> after Wi‑Fi + MQTT reconnect — no second dashboard click (safe cmds only: get_info, ping, self_test, set_param).</p>
        ${can("can_send_command") && canOperateThisDevice ? `
        <div class="inline-form" style="margin-top:4px">
          <label class="field grow"><span>New SSID</span><input id="wifiNewSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz network name" /></label>
          <label class="field grow"><span>Password</span><input id="wifiNewPass" type="password" maxlength="64" autocomplete="new-password" placeholder="empty if open network" /></label>
          <div class="field" style="margin-top:10px">
            <span>After reconnect (stored on device, sequential)</span>
            <div class="row" style="gap:14px;flex-wrap:wrap;margin-top:6px">
              <label><input type="checkbox" id="wifiChainGetInfo" checked /> <span class="mono">get_info</span> (status)</label>
              <label><input type="checkbox" id="wifiChainPing" checked /> <span class="mono">ping</span></label>
              <label><input type="checkbox" id="wifiChainSelfTest" /> <span class="mono">self_test</span></label>
            </div>
          </div>
          <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:8px">
            <button class="btn btn-tap" type="button" id="wifiApplyBtn">Start provision task</button>
          </div>
        </div>
        <div style="margin-top:8px">
          <progress id="wifiTaskProgress" value="0" max="100" style="width:100%;height:12px"></progress>
        </div>
        <p class="muted" id="wifiScanStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span> and <strong>operate</strong> access on this device (tenant owner, admin, or shared grant with Operate).</p>`}
      </div>
    </details>

    <details class="card danger-zone danger-zone--compact device-drawer">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Danger zone</span>
        <span class="device-drawer__hint muted">Unbind &amp; reset</span>
      </summary>
      <div class="device-drawer__body danger-zone-body">
        <p class="muted danger-zone-compact-lead">Removes this device from your tenant and sends <span class="mono">unclaim_reset</span> when online. Re-add from Activate.</p>
        <div class="danger-zone-single-action">
          <button class="btn danger sm danger-zone-unbind-btn" type="button" id="deleteReset" ${can("can_send_command") && !d.is_shared ? "" : "disabled"}>Unbind &amp; reset</button>
        </div>
      </div>
    </details>

    ${d.is_shared ? `
    <details class="card device-drawer" id="triggerPolicyCard">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Trigger policy</span>
        <span class="device-drawer__hint muted">Owner tenant only</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0">Sibling / group trigger policy is managed by the <strong>owning tenant</strong> only. Device share does not expose group policy.</p>
      </div>
    </details>` : `
    <details class="card device-drawer" id="triggerPolicyCard">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Trigger policy</span>
        <span class="device-drawer__hint muted">Server · group scope · expand</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0 0 10px">Scope: owner account + group <span class="mono">${escapeHtml(d.notification_group || "(default)")}</span>. Siblings = same tenant + same <span class="mono">notification_group</span> (server normalizes spacing/case). Remote #1 = silent; #2 = loud to siblings; panic = local + optional sibling siren.</p>
        ${can("can_send_command") && canOperateThisDevice ? `
        <div class="inline-form" style="margin-top:4px;gap:12px;flex-wrap:wrap;align-items:flex-end">
          <label class="field"><span>Panic local</span><input type="checkbox" id="tpPanicLocal" title="Sound on device that pressed panic" /></label>
          <label class="field"><span>Panic → siblings</span><input type="checkbox" id="tpPanicLink" title="MQTT siren to same-group devices" /></label>
          <label class="field"><span>Remote silent link</span><input type="checkbox" id="tpSilentLink" /></label>
          <label class="field"><span>Remote loud link</span><input type="checkbox" id="tpLoudLink" /></label>
          <label class="field"><span>Exclude self</span><input type="checkbox" id="tpExcludeSelf" /></label>
          <label class="field"><span>Loud (min)</span><input id="tpLoudMin" type="number" min="0.5" max="5" step="0.5" value="3" title="Remote / #2 sibling siren length" /></label>
          <label class="field"><span>Panic sibling (min)</span><input id="tpPanicMin" type="number" min="0.5" max="10" step="0.5" value="5" title="Panic MQTT sibling siren length" /></label>
          <div class="row wide" style="justify-content:flex-end;flex-basis:100%">
            <button class="btn secondary btn-tap" type="button" id="tpRefresh">Refresh</button>
            <button class="btn btn-tap" type="button" id="tpSave">Save</button>
          </div>
        </div>
        <p class="muted" id="tpStatus" style="margin-top:8px;min-height:1.3em"></p>` : `<p class="muted">Requires <span class="mono">can_send_command</span> and <strong>operate</strong> access on this device.</p>`}
      </div>
    </details>`}

    ${rawCommandDrawer}

    ${mqttMsgPanel}`);
  const patchDeviceLive = (dev) => {
    const m = deviceLiveModel(dev);
    const onlineBadge = $("#devOnlineBadge", view);
    if (onlineBadge) {
      onlineBadge.textContent = m.on ? "online" : "offline";
      onlineBadge.className = `badge ${m.on ? "online" : "offline"}`;
    }
    const reasonChip = $("#devReasonChip", view);
    if (reasonChip) reasonChip.textContent = String(reasonEn[m.reason] || m.reason);
    const setText = (idSel, txt) => { const el = $(idSel, view); if (el) el.textContent = String(txt); };
    const setHtml = (idSel, txt) => { const el = $(idSel, view); if (el) setChildMarkup(el, String(txt)); };
    setText("#devNetRow", `${dev.net_type || "—"} · ${m.s.ip || "—"}`);
    setHtml("#devWifiSsid", m.wifiSsidDd);
    setHtml("#devWifiCh", m.wifiChDd);
    setText("#devRssi", m.rssi);
    setText("#devOutV", m.outV);
    setText("#devTxRx", `${bps(m.s.tx_bps)} / ${bps(m.s.rx_bps)}`);
    setText("#devDisconnect", m.reason);
    setText("#devUptime", m.s.uptime_s ? `${Math.floor(m.s.uptime_s / 3600)}h ${Math.floor((m.s.uptime_s % 3600) / 60)}m` : "—");
    setText("#devHeap", m.s.free_heap ? `${m.s.free_heap} B (min ${m.s.min_free_heap || "?"} B)` : "—");
    setText("#devUpdated", `${fmtTs(dev.updated_at)} (${fmtRel(dev.updated_at)})`);
    syncDevicePageFirmwareHint(view, dev, id);
  };
  patchDeviceLive(d);
  scheduleRouteTicker(routeSeq, `device-live-${id}`, async () => {
    if (!isRouteCurrent(routeSeq)) return;
    const latest = await apiGetCached(`/devices/${encodeURIComponent(id)}`, { timeoutMs: 16000 }, 5000);
    if (!isRouteCurrent(routeSeq) || !latest) return;
    d = latest;
    patchDeviceLive(latest);
  }, 12000);
  if (isSuperViewer) {
    const det = $("#mqttMsgDetails", view);
    const box = $("#devMsgsList", view);
    let loaded = false;
    const loadDebugMsgs = async () => {
      if (loaded || !box) return;
      loaded = true;
      setChildMarkup(box, `<p class="muted">Loading…</p>`);
      try {
        const msgs = await api(`/devices/${encodeURIComponent(id)}/messages?limit=25`, { timeoutMs: 16000 });
        setChildMarkup(box, renderMsgFeed(msgs.items || []));
      } catch (e) {
        setChildMarkup(box, `<p class="badge offline">${escapeHtml(e.message || e)}</p>`);
      }
    };
    if (det) {
      det.addEventListener("toggle", () => {
        if (det.open) loadDebugMsgs();
      });
    }
  }

  $("#saveProfile").addEventListener("click", async () => {
    try {
      const body = { display_label: ($("#dispLabel").value || "").trim() };
      if (!d.is_shared) {
        body.notification_group = canonicalGroupKey(($("#notifGroup") && $("#notifGroup").value) || "");
      }
      await api(`/devices/${encodeURIComponent(id)}/profile`, {
        method: "PATCH",
        body,
      });
      if (!d.is_shared) {
        reconcileGroupMetaForDevice(id, body.notification_group || "", d.owner_admin);
      }
      toast("Saved", "ok");
    } catch (e) { toast(e.message || e, "err"); }
  });

  const withDev = (fn) => async () => {
    try { await fn(); toast("Sent", "ok"); }
    catch (e) { toast(e.message || e, "err"); }
  };

  $("#alertOn").addEventListener("click", withDev(() =>
    api(`/devices/${encodeURIComponent(id)}/alert/on?duration_ms=${DEFAULT_REMOTE_SIREN_MS}`, { method: "POST" })));
  $("#alertOff").addEventListener("click", withDev(() =>
    api(`/devices/${encodeURIComponent(id)}/alert/off`, { method: "POST" })));
  $("#selfTest").addEventListener("click", withDev(() =>
    api(`/devices/${encodeURIComponent(id)}/self-test`, { method: "POST" })));
  $("#doReboot").addEventListener("click", withDev(() => {
    const v = parseInt($("#rebootDelay").value, 10);
    if (!Number.isFinite(v) || v < 5) throw new Error("delay must be >= 5 seconds");
    return api(`/devices/${encodeURIComponent(id)}/schedule-reboot`, { method: "POST", body: { delay_s: v } });
  }));
  $("#unrevoke").addEventListener("click", withDev(async () => {
    await api(`/devices/${encodeURIComponent(id)}/unrevoke`, { method: "POST" });
    bustDeviceListCaches();
  }));
  const deleteResetBtn = $("#deleteReset", view);
  if (deleteResetBtn) {
    deleteResetBtn.addEventListener("click", async () => {
      if (!confirm("Delete this device from current account records? You can re-add and reconfigure later.")) return;
      const typed = String(prompt(`Type device ID to confirm delete/reset:\n${id}`) || "").trim();
      if (typed.toUpperCase() !== String(id).toUpperCase()) { toast("Confirmation mismatch", "err"); return; }
      try {
        const dr = await api(`/devices/${encodeURIComponent(id)}/delete-reset`, {
          method: "POST",
          body: { confirm_text: typed },
        });
        removeDeviceIdFromAllGroupMeta(id);
        bustDeviceListCaches();
        const sentNv = dr && (dr.nvs_purge_sent === true);
        const ackNv = dr && (dr.nvs_purge_acked === true);
        toast(
          `Device removed from account.${ackNv ? " Device confirmed unclaim_reset (WiFi+claim cleared, rebooting)." : (sentNv ? " Command was dispatched but device ack not confirmed before unlink." : " Command dispatch failed/offline.")} Re-add from Activate.`,
          ackNv ? "ok" : "err",
        );
        location.hash = "#/devices";
      } catch (e) { toast(e.message || e, "err"); }
    });
  }
  const sendCmdBtn = $("#sendCmd");
  if (sendCmdBtn) {
    sendCmdBtn.addEventListener("click", async () => {
      const name = ($("#cmdName").value || "").trim();
      if (!name) { toast("Enter cmd", "err"); return; }
      let params = {};
      const raw = ($("#cmdParams").value || "").trim();
      if (raw) {
        try { params = JSON.parse(raw); } catch { toast("Invalid JSON in params", "err"); return; }
      }
      try {
        await api(`/devices/${encodeURIComponent(id)}/commands`, { method: "POST", body: { cmd: name, params } });
        toast("Command sent", "ok");
      } catch (e) { toast(e.message || e, "err"); }
    });
  }

  const wifiApplyBtn = $("#wifiApplyBtn");
  try {
    const rawPf = sessionStorage.getItem("croc.deviceWifiPrefill.v1");
    if (rawPf) {
      const pf = JSON.parse(rawPf);
      const match = pf && String(pf.device_id || "").toUpperCase() === String(id).toUpperCase();
      if (match && pf.ssid) {
        const wS = $("#wifiNewSsid", view);
        const wP = $("#wifiNewPass", view);
        const card = $("#wifiCtlCard", view);
        if (wS) wS.value = String(pf.ssid);
        if (wP) wP.value = String(pf.password || "");
        sessionStorage.removeItem("croc.deviceWifiPrefill.v1");
        if (card) card.open = true;
        toast("Prefilled Wi‑Fi from Activate page — start provision below when the device is online.", "ok");
      }
    }
  } catch (_) {}
  const wifiTaskProgress = $("#wifiTaskProgress");
  const setWifiProgress = (n) => {
    if (!wifiTaskProgress) return;
    const v = Math.max(0, Math.min(100, Number(n || 0)));
    wifiTaskProgress.value = v;
  };
  const pollWifiTask = async (taskId) => runPollDedup(`wifi-task:${id}:${String(taskId || "")}`, async () => {
    const st = $("#wifiScanStatus");
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      try {
        const t = await api(`/devices/${encodeURIComponent(id)}/provision/wifi-task/${encodeURIComponent(taskId)}`, { timeoutMs: 16000 });
        setWifiProgress(t.progress || 0);
        if (st) st.textContent = String(t.message || t.status || "");
        if (t.status === "success") {
          toast("Provision success", "ok");
          return;
        }
        if (t.status === "failed") {
          toast(t.message || "Provision failed", "err");
          return;
        }
      } catch (e) {
        if (st) st.textContent = String(e.message || e);
      }
    }
    if (st) st.textContent = "Timed out waiting task result";
    toast("Provision task timeout", "err");
  });
  if (wifiApplyBtn) {
    wifiApplyBtn.addEventListener("click", async () => {
      const ssid = ($("#wifiNewSsid", view).value || "").trim();
      const password = ($("#wifiNewPass", view).value || "");
      const st = $("#wifiScanStatus", view);
      if (!ssid) { toast("Enter SSID", "err"); return; }
      if (!confirm("Save Wi‑Fi on device and reboot? You may lose contact until it joins the new network.")) return;
      try {
        wifiApplyBtn.disabled = true;
        setWifiProgress(10);
        if (st) st.textContent = "Creating provision task…";
        const chain = [];
        const cGi = $("#wifiChainGetInfo", view);
        const cPi = $("#wifiChainPing", view);
        const cSt = $("#wifiChainSelfTest", view);
        if (cGi && cGi.checked) chain.push({ cmd: "get_info", params: {} });
        if (cPi && cPi.checked) chain.push({ cmd: "ping", params: {} });
        if (cSt && cSt.checked) chain.push({ cmd: "self_test", params: {} });
        const body = { ssid, password };
        if (chain.length) body.chain = chain;
        const r = await api(`/devices/${encodeURIComponent(id)}/provision/wifi-task`, {
          method: "POST",
          body,
        });
        setWifiProgress(r.progress || 35);
        if (st) st.textContent = `Task ${r.task_id} running…`;
        await pollWifiTask(r.task_id);
      } catch (e) { toast(e.message || e, "err"); if (st) st.textContent = String(e.message || e); }
      finally { wifiApplyBtn.disabled = false; }
    });
  }
  const tpPanicLocal = $("#tpPanicLocal");
  const tpPanicLink = $("#tpPanicLink");
  const tpSilentLink = $("#tpSilentLink");
  const tpLoudLink = $("#tpLoudLink");
  const tpExcludeSelf = $("#tpExcludeSelf");
  const tpLoudMin = $("#tpLoudMin");
  const tpPanicMin = $("#tpPanicMin");
  const tpStatus = $("#tpStatus");
  const loadTriggerPolicy = async () => {
    if (!tpPanicLocal || !tpPanicLink || !tpSilentLink || !tpLoudLink || !tpExcludeSelf || !tpLoudMin || !tpPanicMin) return;
    try {
      if (tpStatus) tpStatus.textContent = "Loading policy…";
      const r = await api(`/devices/${encodeURIComponent(id)}/trigger-policy`, { timeoutMs: 16000 });
      const p = r.policy || {};
      tpPanicLocal.checked = !!p.panic_local_siren;
      if (tpPanicLink) tpPanicLink.checked = p.panic_link_enabled !== false;
      tpSilentLink.checked = !!p.remote_silent_link_enabled;
      tpLoudLink.checked = !!p.remote_loud_link_enabled;
      tpExcludeSelf.checked = !!p.fanout_exclude_self;
      const loudMs = Number(p.remote_loud_duration_ms || DEFAULT_REMOTE_SIREN_MS);
      const panicMs = Number(p.panic_fanout_duration_ms || DEFAULT_PANIC_FANOUT_MS);
      tpLoudMin.value = String(Math.round(Math.max(0.5, Math.min(5, loudMs / 60000)) * 10) / 10);
      tpPanicMin.value = String(Math.round(Math.max(0.5, Math.min(10, panicMs / 60000)) * 10) / 10);
      if (tpStatus) tpStatus.textContent = `Loaded for group ${r.scope_group || "(default)"}`;
    } catch (e) {
      if (tpStatus) tpStatus.textContent = String(e.message || e);
    }
  };
  const tpRefresh = $("#tpRefresh");
  if (tpRefresh) tpRefresh.addEventListener("click", () => loadTriggerPolicy());
  const tpSave = $("#tpSave");
  if (tpSave) {
    tpSave.addEventListener("click", async () => {
      try {
        const lm = parseFloat((tpLoudMin && tpLoudMin.value) || "3", 10);
        const pm = parseFloat((tpPanicMin && tpPanicMin.value) || "5", 10);
        if (!Number.isFinite(lm) || lm < 0.5 || lm > 5) throw new Error("Loud duration must be 0.5–5 minutes");
        if (!Number.isFinite(pm) || pm < 0.5 || pm > 10) throw new Error("Panic sibling duration must be 0.5–10 minutes");
        const remote_loud_duration_ms = Math.round(lm * 60000);
        const panic_fanout_duration_ms = Math.round(pm * 60000);
        if (tpStatus) tpStatus.textContent = "Saving policy…";
        await api(`/devices/${encodeURIComponent(id)}/trigger-policy`, {
          method: "PUT",
          body: {
            panic_local_siren: !!(tpPanicLocal && tpPanicLocal.checked),
            panic_link_enabled: !!(tpPanicLink && tpPanicLink.checked),
            remote_silent_link_enabled: !!(tpSilentLink && tpSilentLink.checked),
            remote_loud_link_enabled: !!(tpLoudLink && tpLoudLink.checked),
            fanout_exclude_self: !!(tpExcludeSelf && tpExcludeSelf.checked),
            remote_loud_duration_ms,
            panic_fanout_duration_ms,
          },
        });
        if (tpStatus) tpStatus.textContent = "Policy saved";
        toast("Trigger policy saved", "ok");
      } catch (e) {
        if (tpStatus) tpStatus.textContent = String(e.message || e);
        toast(e.message || e, "err");
      }
    });
    loadTriggerPolicy();
  }

  const shareListEl = $("#shareList");
  const renderShares = async () => {
    if (!shareListEl) return;
    setChildMarkup(shareListEl, `<p class="muted">Loading shares…</p>`);
    try {
      const r = await api(`/admin/devices/${encodeURIComponent(id)}/shares`, { timeoutMs: 16000 });
      const items = r.items || [];
      setChildMarkup(
        shareListEl,
        `
        <div class="table-wrap"><table class="t">
          <thead><tr><th>User</th><th>Role</th><th>View</th><th>Operate</th><th>Granted by</th><th>Granted at</th><th>Status</th><th></th></tr></thead>
          <tbody>${
            items.length === 0
              ? `<tr><td colspan="8" class="muted">No shares</td></tr>`
              : items.map((it) => `
                <tr>
                  <td class="mono">${escapeHtml(it.grantee_username || "")}</td>
                  <td>${escapeHtml(it.grantee_role || "—")}</td>
                  <td>${it.can_view ? "yes" : "no"}</td>
                  <td>${it.can_operate ? "yes" : "no"}</td>
                  <td class="mono">${escapeHtml(it.granted_by || "")}</td>
                  <td>${escapeHtml(fmtTs(it.granted_at))}</td>
                  <td>${it.revoked_at ? `<span class="badge offline">revoked</span>` : `<span class="badge online">active</span>`}</td>
                  <td>${it.revoked_at ? "" : `<button class="btn ghost shareRevokeBtn" data-user="${escapeHtml(it.grantee_username || "")}">Revoke</button>`}</td>
                </tr>
              `).join("")
          }</tbody>
        </table></div>
      `,
      );
      $$(".shareRevokeBtn", shareListEl).forEach((btn) => {
        btn.addEventListener("click", async () => {
          const u = btn.getAttribute("data-user") || "";
          if (!u) return;
          if (!confirm(`Revoke share for ${u}?`)) return;
          try {
            await api(`/admin/devices/${encodeURIComponent(id)}/share/${encodeURIComponent(u)}`, { method: "DELETE" });
            toast("Share revoked", "ok");
            await renderShares();
          } catch (e) { toast(e.message || e, "err"); }
        });
      });
    } catch (e) {
      setChildMarkup(shareListEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  };
  const shareGrantBtn = $("#shareGrant");
  if (shareGrantBtn) {
    shareGrantBtn.addEventListener("click", async () => {
      const grantee = ($("#shareUser").value || "").trim();
      const canView = !!$("#shareCanView").checked;
      const canOperate = !!$("#shareCanOperate").checked;
      if (!grantee) { toast("Enter grantee username", "err"); return; }
      if (!canView && !canOperate) { toast("Select view and/or operate", "err"); return; }
      try {
        await api(`/admin/devices/${encodeURIComponent(id)}/share`, {
          method: "POST",
          body: { grantee_username: grantee, can_view: canView, can_operate: canOperate },
        });
        toast("Share granted", "ok");
        await renderShares();
      } catch (e) { toast(e.message || e, "err"); }
    });
  }
  const shareRefreshBtn = $("#shareRefresh");
  if (shareRefreshBtn) {
    shareRefreshBtn.addEventListener("click", () => renderShares());
    renderShares();
  }
});
