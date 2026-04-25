/**
 * Route: #/group — Single group/site detail (deep link only).
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("group", async (view, args, routeSeq) => {
  // Two-key strategy (Phase 90): the URL carries whatever casing the
  // user typed/clicked — preserve that for display, but match devices
  // case-insensitively via the canonical key so siblings collide the
  // same way the backend's _sibling_group_norm does. Without this, a
  // route like "/group/Warehouse%20A" would not match a device whose
  // notification_group is "warehouse a", even though they're siblings
  // server-side.
  const rawArg = decodeURIComponent(args[0] || "");
  const g = canonicalGroupKey(rawArg);
  if (!g) { location.hash = "#/overview"; return; }
  const displayFromUrl = displayGroupName(rawArg);
  const tenantOwner = String((window.__routeQuery && window.__routeQuery.get("owner")) || "").trim();
  const metaKey = groupCardMetaKey(g, tenantOwner);
  const groupScope = (state.me && state.me.username) ? state.me.username : "anon";
  const GROUP_META_LS_KEY = `croc.group.meta.v2.${groupScope}`;
  const GROUP_SETTINGS_LS_KEY = `croc.group.settings.v1.${groupScope}`;
  const GROUP_API_CAPS_LS_KEY = `croc.group.api.caps.v2.${groupScope}`;
  const loadGroupMeta = () => {
    try {
      const raw = localStorage.getItem(GROUP_META_LS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return (obj && typeof obj === "object") ? obj : {};
    } catch { return {}; }
  };
  const loadGroupSettings = () => {
    try {
      const raw = localStorage.getItem(GROUP_SETTINGS_LS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return (obj && typeof obj === "object") ? obj : {};
    } catch { return {}; }
  };
  const loadGroupApiCaps = () => {
    try {
      const raw = localStorage.getItem(GROUP_API_CAPS_LS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return {
        apply: obj && obj.apply === false ? false : true,
        delete: obj && obj.delete === false ? false : true,
      };
    } catch { return { apply: true, delete: true }; }
  };
  const saveGroupApiCaps = (caps) => localStorage.setItem(GROUP_API_CAPS_LS_KEY, JSON.stringify({
    apply: !!(caps && caps.apply),
    delete: !!(caps && caps.delete),
  }));
  window.__groupDelayTimers = window.__groupDelayTimers || new Map();
  const meta = loadGroupMeta();
  const gsMap = loadGroupSettings();
  const groupApiCaps = loadGroupApiCaps();
  // Show *something* immediately on cold loads — /devices may take seconds.
  // Display priority: stored display_name > URL-supplied case > folded key.
  const coldName = (meta[metaKey] || meta[g] || {}).display_name || displayFromUrl || g;
  setCrumb(`Group · ${coldName}`);
  mountView(view, `
    <section class="card">
      <div class="row" style="align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <h2 style="margin:0">${escapeHtml(coldName)}</h2>
        <a href="#/overview" class="btn ghost right">← Back</a>
      </div>
      <p class="muted" style="margin-top:10px">Loading group…</p>
    </section>`);
  if (!isRouteCurrent(routeSeq)) return;
  const [listRes] = await Promise.allSettled([apiGetCached("/devices", { timeoutMs: 16000 }, 3000)]);
  if (!isRouteCurrent(routeSeq)) return;
  let list = (listRes.status === "fulfilled" && listRes.value) ? listRes.value : { items: [] };
  syncGroupMetaWithDevices(meta, list.items || []);
  try { localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta)); } catch (_) {}
  const gm = meta[metaKey] || meta[g] || { display_name: displayFromUrl || g, owner_name: "", phone: "", email: "", device_ids: [] };
  const rowsByGroup = () => (list.items || []).filter((d) => {
    if (canonicalGroupKey(d.notification_group) !== g) return false;
    if (state.me && state.me.role === "superadmin" && tenantOwner) {
      return String(d.owner_admin || "").trim() === tenantOwner;
    }
    return true;
  });
  let rows = rowsByGroup();
  let ids = rows.map((d) => String(d.device_id || "")).filter(Boolean);
  const isSharedGroup = rows.some((d) => !!d.is_shared);
  const online = rows.filter((d) => isOnline(d)).length;
  const offline = Math.max(0, rows.length - online);
  setCrumb(`Group · ${gm.display_name || g}`);
  mountView(view, `
    <section class="card">
      <div class="row" style="align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <h2 style="margin:0;flex:1;min-width:0">${escapeHtml(gm.display_name || g)}</h2>
        <div class="row" style="gap:8px;align-items:center;flex-shrink:0;margin-left:auto">
          ${tenantOwner ? `<span class="card-owner-tag" title="Owning admin / 所属租户">${escapeHtml(tenantOwner)}</span>` : ""}
          <a href="#/overview" class="btn ghost right">← Back</a>
        </div>
      </div>
      <div class="divider"></div>
      <div class="row" style="gap:6px;flex-wrap:wrap">
        <span class="badge neutral">total <span id="grpTotal">${rows.length}</span></span>
        <span class="badge online">online <span id="grpOnline">${online}</span></span>
        <span class="badge offline">offline <span id="grpOffline">${offline}</span></span>
        <span class="chip">${escapeHtml(g)}</span>
      </div>
      <p class="muted" style="margin-top:8px">Owner: ${escapeHtml(gm.owner_name || "—")} · ${escapeHtml(gm.phone || "—")} · ${escapeHtml(gm.email || "—")}</p>
      <div class="row" style="margin-top:8px;gap:8px;justify-content:flex-end">
        <button class="btn sm danger" id="grpAlarmOn" ${can("can_alert") ? "" : "disabled"}>Alarm ON</button>
        <button class="btn sm secondary" id="grpAlarmOff" ${can("can_alert") ? "" : "disabled"}>Alarm OFF</button>
      </div>
    </section>
    <section class="card">
      <h3 style="margin:0">Devices</h3>
      <div class="divider"></div>
      <div class="device-grid" id="groupPageDevices"></div>
    </section>
    <details class="card danger-zone device-drawer">
      <summary class="device-drawer__summary">
        <span class="device-drawer__title">Danger zone</span>
        <span class="device-drawer__hint muted">Delete group · expand</span>
      </summary>
      <div class="device-drawer__body">
        <p class="muted" style="margin:0 0 10px">Delete group will clear notification_group from all devices in this group.</p>
        <div class="row" style="justify-content:flex-end">
          <button class="btn danger btn-tap" id="grpDelete" ${isSharedGroup ? "disabled title=\"Shared group cannot be deleted\"" : ""}>Delete group</button>
        </div>
      </div>
    </details>
  `);
  const devGrid = $("#groupPageDevices", view);
  const renderGroupDevices = () => {
    if (!devGrid) return;
    setChildMarkup(
      devGrid,
      rows.length ? rows.map((d) => {
        const on = isOnline(d);
        const primary = escapeHtml(d.display_label || d.device_id || "unknown");
        const subId = d.display_label ? `<div class="device-id-sub mono">${escapeHtml(d.device_id || "")}</div>` : "";
        return `<a class="device-card" href="#/devices/${encodeURIComponent(d.device_id)}" style="text-decoration:none;color:inherit">
        <h3><div class="device-primary-name">${primary}</div>${subId}</h3>
        <div><span class="badge ${on ? "online" : "offline"}">${on ? "online" : "offline"}</span>
          ${d.zone ? `<span class="chip">${escapeHtml(d.zone)}</span>` : ""}
          ${d.fw ? `<span class="chip">v${escapeHtml(d.fw)}</span>` : ""}
          ${d.is_shared ? `<span class="badge accent" title="shared device">sharing by ${escapeHtml(d.shared_by || "?")}</span>` : ""}
        </div>
        <div class="meta">Platform: ${escapeHtml(maskPlatform(`${d.chip_target || ""}/${d.board_profile || ""}`))}<br/>Manufacturer: ESA Sibu</div>
      </a>`;
      }).join("") : `<p class="muted">No devices in this group.</p>`,
    );
    const onNow = rows.filter((d) => isOnline(d)).length;
    const offNow = Math.max(0, rows.length - onNow);
    const tEl = $("#grpTotal", view);
    const oEl = $("#grpOnline", view);
    const fEl = $("#grpOffline", view);
    if (tEl) tEl.textContent = String(rows.length);
    if (oEl) oEl.textContent = String(onNow);
    if (fEl) fEl.textContent = String(offNow);
  };
  renderGroupDevices();
  const clearGroupByDevicePatchCompat = async () => {
    let changed = 0;
    for (const id of ids) {
      await api(`/devices/${encodeURIComponent(id)}/profile`, { method: "PATCH", body: { notification_group: "" } });
      changed += 1;
    }
    return { ok: true, changed };
  };
  const withOwnerQuery = (path, ownerO) => {
    const q = groupApiQueryOwner(ownerO);
    if (!q) return path;
    const join = path.includes("?") ? "&" : "?";
    return `${path}${join}${q}`;
  };
  const deleteGroupCardCompat = async (groupKey, ownerO) => runGroupDeleteAction({
    groupKey,
    ownerAdmin: ownerO,
    apiCaps: groupApiCaps,
    saveApiCaps: saveGroupApiCaps,
    tryDeletePostRoute: async (gk, oa) => {
      const p = withOwnerQuery(`/group-cards/${encodeURIComponent(gk)}/delete`, oa);
      try { return await api(p, { method: "POST" }); } catch (e) {
        if (!isGroupRouteMissingError(e)) throw e;
      }
      return await api(withOwnerQuery(`/api/group-cards/${encodeURIComponent(gk)}/delete`, oa), { method: "POST" });
    },
    tryDeleteRoute: async (gk, oa) => {
      const p = withOwnerQuery(`/group-cards/${encodeURIComponent(gk)}`, oa);
      try { return await api(p, { method: "DELETE" }); } catch (e) {
        if (!isGroupRouteMissingError(e)) throw e;
      }
      return await api(withOwnerQuery(`/api/group-cards/${encodeURIComponent(gk)}`, oa), { method: "DELETE" });
    },
    clearFallback: clearGroupByDevicePatchCompat,
  });
  const applyGroupSettingsFallbackCompat = async (_groupKey, _ownerO, payload) => {
    const durationMs = Number(payload.trigger_duration_ms || DEFAULT_REMOTE_SIREN_MS);
    const tkey = metaKey;
    const prev = window.__groupDelayTimers.get(tkey);
    if (prev) {
      clearTimeout(prev);
      window.__groupDelayTimers.delete(tkey);
    }
    await api("/alerts", { method: "POST", body: { action: "on", duration_ms: durationMs, device_ids: ids } });
    return { ok: true, fallback: true, device_count: ids.length };
  };
  const tryApplyRouteCompat = async (groupKey, ownerO) => {
    const p = withOwnerQuery(`/group-cards/${encodeURIComponent(groupKey)}/apply`, ownerO);
    try { return await api(p, { method: "POST" }); } catch (e) {
      if (!isGroupRouteMissingError(e)) throw e;
    }
    return await api(withOwnerQuery(`/api/group-cards/${encodeURIComponent(groupKey)}/apply`, ownerO), { method: "POST" });
  };
  const sendAlert = async (action) => {
    if (!can("can_alert")) { toast("No can_alert capability", "err"); return; }
    if (ids.length === 0) { toast("No devices in this group", "warn"); return; }
    if (!confirm(`${action === "on" ? "Open" : "Close"} alarm for ${ids.length} devices in ${g}?`)) return;
    if (action === "on") {
      const payload = groupTriggerPayloadFromSettings(gsMap[metaKey] || gsMap[g] || {});
      await runGroupApplyOnAction({
        groupKey: g,
        ownerAdmin: tenantOwner,
        payload,
        apiCaps: groupApiCaps,
        saveApiCaps: saveGroupApiCaps,
        tryApplyRoute: tryApplyRouteCompat,
        applyFallback: applyGroupSettingsFallbackCompat,
      });
    } else {
      const prev = window.__groupDelayTimers.get(metaKey);
      if (prev) {
        clearTimeout(prev);
        window.__groupDelayTimers.delete(metaKey);
      }
      await api("/alerts", { method: "POST", body: { action: "off", duration_ms: DEFAULT_REMOTE_SIREN_MS, device_ids: ids } });
    }
    toast(`${action === "on" ? "Alarm ON" : "Alarm OFF"} · ${ids.length}`, "ok");
  };
  const alarmOnBtn = $("#grpAlarmOn", view);
  const alarmOffBtn = $("#grpAlarmOff", view);
  const delGroupBtn = $("#grpDelete", view);
  if (alarmOnBtn) alarmOnBtn.addEventListener("click", () => sendAlert("on"));
  if (alarmOffBtn) alarmOffBtn.addEventListener("click", () => sendAlert("off"));
  if (delGroupBtn) {
    delGroupBtn.addEventListener("click", async () => {
      if (isSharedGroup) { toast("Shared group cannot be deleted", "err"); return; }
      if (!confirm(`Delete group card "${g}"?`)) return;
      try {
        await deleteGroupCardCompat(g, tenantOwner);
        if (meta[metaKey]) delete meta[metaKey];
        else if (meta[g]) delete meta[g];
        localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta));
        toast("Group deleted", "ok");
        location.hash = "#/overview";
      } catch (e) {
        toast(e.message || e, "err");
      }
    });
  }
  const refreshGroupLive = async () => {
    if (!isRouteCurrent(routeSeq)) return;
    const latest = await apiGetCached("/devices", { timeoutMs: 16000 }, 2000);
    if (!isRouteCurrent(routeSeq)) return;
    list = latest || { items: [] };
    syncGroupMetaWithDevices(meta, list.items || []);
    try { localStorage.setItem(GROUP_META_LS_KEY, JSON.stringify(meta)); } catch (_) {}
    rows = rowsByGroup();
    ids = rows.map((d) => String(d.device_id || "")).filter(Boolean);
    renderGroupDevices();
  };
  scheduleRouteTicker(routeSeq, `group-live-${g}`, refreshGroupLive, 10000);
});
