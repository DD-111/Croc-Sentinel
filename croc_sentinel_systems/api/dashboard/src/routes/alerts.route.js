/**
 * Route: #/alerts — bulk siren control (sends siren_on/siren_off via MQTT).
 *
 * Build: concatenated by `scripts/build-dashboard.mjs`. Shares scope with
 * console.raw.js — see `account-activate.route.js` for the convention.
 *
 * Backend contracts:
 *   - GET  /devices           → /devices/{id}/state per row (cached 4s)
 *   - POST /alerts            → bulk siren fan-out
 * Both verified by `tests/test_spa_api_contract.py`.
 */

registerRoute("alerts", async (view) => {
  setCrumb("Siren");
  const enabled = can("can_alert");

  // Render the chrome immediately so users on slow networks see the page
  // (instead of blanking on the /devices fetch). Targets and the Run button
  // hydrate once /devices resolves.
  mountView(view, `
    <div class="card">
      <h2>Bulk siren</h2>
      ${enabled ? "" : `<p class="badge revoked">No can_alert — ask admin (Policies).</p>`}
      <p id="alertsLoadMsg" class="muted" aria-live="polite">Loading device list…</p>
      <div class="inline-form inline-form--bulk-siren" style="margin-top:12px">
        <label class="field"><span>Action</span>
          <select id="action"><option value="on">ON</option><option value="off">OFF</option></select>
        </label>
        <label class="field"><span>Duration (ms)</span>
          <input id="dur" type="number" value="${DEFAULT_REMOTE_SIREN_MS}" min="500" max="300000" step="1000" />
        </label>
        <label class="field wide"><span>Targets (empty = all visible)</span>
          <select id="targets" multiple size="6" disabled></select>
        </label>
        <div class="row wide" style="justify-content:flex-end">
          <button class="btn danger" id="fire" disabled>Run</button>
        </div>
      </div>
    </div>`);

  const sel = $("#targets");
  const fireBtn = $("#fire");
  const loadMsg = $("#alertsLoadMsg");

  let list;
  try {
    list = await apiGetCached("/devices", { timeoutMs: 16000 }, 4000);
    if (loadMsg) loadMsg.remove();
  } catch (e) {
    const detail = String((e && e.message) || e || "load failed");
    if (loadMsg) {
      loadMsg.className = "badge offline";
      loadMsg.textContent = `Device list fallback: ${detail}`;
    }
    list = { items: [] };
  }
  const devices = list.items || [];

  setChildMarkup(sel, devices.map((d) => {
    const lab = d.display_label ? `${escapeHtml(d.display_label)}` : escapeHtml(d.device_id);
    const serial = d.display_label ? ` · ${escapeHtml(d.device_id)}` : "";
    const grp = d.notification_group ? `[${escapeHtml(d.notification_group)}] ` : "";
    const z = d.zone ? ` · ${escapeHtml(d.zone)}` : "";
    return `<option value="${escapeHtml(d.device_id)}">${grp}${lab}${serial}${z}</option>`;
  }).join(""));
  sel.disabled = false;
  if (enabled) fireBtn.disabled = false;

  fireBtn.addEventListener("click", async () => {
    const action = $("#action").value;
    const dur = parseInt($("#dur").value, 10) || DEFAULT_REMOTE_SIREN_MS;
    const ids = Array.from(sel.selectedOptions).map((o) => o.value);
    if (action === "on" && !confirm(`Siren ON for ${ids.length === 0 ? "ALL visible devices" : ids.length + " device(s)"}?`)) return;
    try {
      const r = await api("/alerts", { method: "POST", body: { action, duration_ms: dur, device_ids: ids } });
      toast(`${action === "on" ? "ON" : "OFF"} → ${r.sent_count} device(s)`, "ok");
    } catch (e) { toast(e.message || e, "err"); }
  });
});
