/**
 * Route: #/site — Tenant site overview (superadmin).
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("site", async (view, _args, routeSeq) => {
  setCrumb("Site · owners & groups / 站点");
  if (!(state.me && state.me.role === "superadmin")) {
    mountView(view, `<div class="card"><p class="muted">Superadmin only.</p></div>`);
    return;
  }
  let ownerQ = String((window.__routeQuery && window.__routeQuery.get("owner")) || "").trim();
  let allDevs = [];
  try {
    const r = await api("/devices", { timeoutMs: 20000 });
    if (!isRouteCurrent(routeSeq)) return;
    allDevs = Array.isArray(r.items) ? r.items.slice() : [];
  } catch (e) {
    if (!isRouteCurrent(routeSeq)) return;
    mountView(view, `<div class="card"><p class="badge offline">${escapeHtml(e.message || e)}</p></div>`);
    return;
  }
  const applyFilter = (list, q) => {
    const s = String(q || "").trim().toLowerCase();
    if (!s) return list;
    return list.filter((d) => String(d.owner_admin || "").toLowerCase().includes(s));
  };
  const filtered = () => applyFilter(allDevs, ownerQ);
  const ownersU = [...new Set(allDevs.map((d) => String(d.owner_admin || "").trim()).filter(Boolean))].sort();
  const fd = filtered();
  const slots = buildGroupSlotsFromDeviceList(fd);
  const rows = fd.map((d) => {
    const on = isOnline(d);
    const did = encodeURIComponent(d.device_id);
    return `<tr><td class="mono"><a href="#/devices/${did}">${escapeHtml(d.device_id)}</a></td><td class="mono">${escapeHtml(d.owner_admin || "—")}</td><td>${escapeHtml(d.notification_group || "—")}</td><td>${escapeHtml(d.zone || "")}</td><td><span class="badge ${on ? "online" : "offline"}">${on ? "on" : "off"}</span></td></tr>`;
  }).join("");
  const grpRows = slots.map((s) => {
    const owq = s.tenantOwner ? `?owner=${encodeURIComponent(s.tenantOwner)}` : "";
    return `<tr><td class="mono"><a href="#/group/${encodeURIComponent(s.groupKey)}${owq}">${escapeHtml(s.groupKey)}</a></td><td class="mono">${escapeHtml(s.tenantOwner || "—")}</td><td class="mono muted">${escapeHtml(s.metaKey)}</td></tr>`;
  }).join("");
  mountView(view, `
    <section class="card">
      <h2 class="ui-section-title" style="margin:0">Site / 站点</h2>
      <p class="muted" style="margin:8px 0 0">Search <strong>owner admin</strong> username (substring). Lists devices and <strong>notification groups</strong> under that filter — same slot keys as Overview group cards.</p>
      <div class="inline-form" style="margin-top:12px;flex-wrap:wrap;gap:10px;align-items:flex-end">
        <label class="field grow"><span>Owner contains</span>
          <input type="search" id="siteOwnerQ" value="${escapeHtml(ownerQ)}" placeholder="e.g. dan" list="siteOwnerDl" autocomplete="off" />
          <datalist id="siteOwnerDl">${ownersU.map((o) => `<option value="${escapeHtml(o)}"></option>`).join("")}</datalist>
        </label>
        <button type="button" class="btn sm secondary btn-tap" id="siteOwnerClear">Clear</button>
        <button type="button" class="btn btn-tap" id="siteOwnerApply">Apply</button>
      </div>
    </section>
    <section class="card">
      <h3 style="margin:0 0 8px">Owners in fleet (${ownersU.length})</h3>
      <p class="muted" style="margin:0;font-size:12px">Unique <span class="mono">owner_admin</span> from API. Click a chip to filter.</p>
      <div class="row" style="gap:6px;flex-wrap:wrap;margin-top:10px">
        ${ownersU.map((o) => `<button type="button" class="chip js-site-owner-chip" data-o="${escapeHtml(o)}" style="cursor:pointer">${escapeHtml(o)}</button>`).join("")}
      </div>
    </section>
    <section class="card">
      <h3 style="margin:0 0 8px">Devices (${fd.length})</h3>
      <div class="table-wrap"><table class="t">
        <thead><tr><th>Device</th><th>Owner</th><th>Notification group</th><th>Zone</th><th>Presence</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="muted">No devices match.</td></tr>`}</tbody>
      </table></div>
    </section>
    <section class="card">
      <h3 style="margin:0 0 8px">Groups (${slots.length})</h3>
      <div class="table-wrap"><table class="t">
        <thead><tr><th>Group key</th><th>Tenant (slot)</th><th>Card meta-key</th></tr></thead>
        <tbody>${grpRows || `<tr><td colspan="3" class="muted">No groups in filter.</td></tr>`}</tbody>
      </table></div>
    </section>
  `);
  $("#siteOwnerApply", view).addEventListener("click", () => {
    ownerQ = String($("#siteOwnerQ", view)?.value || "").trim();
    location.hash = ownerQ ? `#/site?owner=${encodeURIComponent(ownerQ)}` : "#/site";
  });
  $("#siteOwnerClear", view).addEventListener("click", () => { location.hash = "#/site"; });
  $("#siteOwnerQ", view).addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); $("#siteOwnerApply", view).click(); }
  });
  $$(".js-site-owner-chip", view).forEach((btn) => {
    btn.addEventListener("click", () => {
      const o = btn.getAttribute("data-o") || "";
      location.hash = o ? `#/site?owner=${encodeURIComponent(o)}` : "#/site";
    });
  });
});
