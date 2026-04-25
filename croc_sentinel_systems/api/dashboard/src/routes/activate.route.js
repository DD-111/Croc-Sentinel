/**
 * Route: #/activate — Admin: activate/claim a device into the tenant.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("activate", async (view) => {
  setCrumb("Activate device");
  if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`); return; }
  const canClaim = can("can_claim_device");

  mountView(view, `
    <div class="activate-shell">
      <section class="card activate-hero">
        <p class="activate-kicker">Field · Claim</p>
        <h2 class="activate-title">Claim device</h2>
        <p class="muted activate-lead">
          A serial appears as <strong>claimable</strong> only after the unit is <strong>powered and has contacted the server</strong>. Optionally save a <strong>target Wi‑Fi</strong> here (stored in this browser only); after claim we pre-fill the device page Wi‑Fi form for MQTT provisioning when online.
        </p>
        <ol class="activate-steps">
          <li><span class="n">1</span>Optional: save target Wi‑Fi (recommended)</li>
          <li><span class="n">2</span>Enter sticker serial or paste full <span class="mono">CROC|…</span></li>
          <li><span class="n">3</span>Identify → if claimable, confirm and complete claim</li>
        </ol>
        ${canClaim ? "" : `<p class="badge revoked" style="margin-top:12px">Your account lacks <span class="mono">can_claim_device</span>; ask an administrator.</p>`}
      </section>

      <section class="card activate-main">
        <div class="activate-wifi-row">
          <button type="button" class="btn secondary btn-tap" style="width:100%" id="activateWifiOpenBtn">① Target Wi‑Fi (SSID / password)</button>
          <p class="muted activate-wifi-status" id="activateWifiStatus"></p>
        </div>
        <div class="inline-form activate-serial-block">
          <label class="field wide"><span>② Serial or full QR line (CROC|…)</span>
            <input id="idn_input" class="activate-serial-input" placeholder="SN-… or paste full CROC|… line" autocomplete="off"/>
          </label>
          <div class="row wide activate-actions">
            <button class="btn btn-tap activate-id-btn" id="idn_go" ${canClaim ? "" : "disabled"}>③ Identify</button>
          </div>
        </div>
        <div id="idnResult" class="activate-result"></div>
      </section>

      <dialog id="activateWifiDialog" class="activate-wifi-dlg">
        <form class="activate-wifi-dlg__inner" onsubmit="return false">
          <h3 class="activate-wifi-dlg__title">Target Wi‑Fi</h3>
          <p class="muted activate-wifi-dlg__lead">
            If the device has <strong>never been online</strong>, the server cannot push Wi‑Fi to it directly. SSID/password here are saved only in <strong>this browser</strong>; after claim, paste them into the device page for MQTT delivery. Leave password empty on open networks.
          </p>
          <label class="field wide"><span>SSID</span>
            <input type="text" id="activateDlgSsid" maxlength="32" autocomplete="off" placeholder="2.4 GHz network name" />
          </label>
          <label class="field wide"><span>Password</span>
            <input type="password" id="activateDlgPass" maxlength="64" autocomplete="new-password" placeholder="Empty if open network" />
          </label>
          <label class="field" style="margin-bottom:0"><span></span>
            <span><input type="checkbox" id="activateDlgShowPass" /> Show password</span>
          </label>
          <div class="activate-wifi-dlg__actions">
            <button type="button" class="btn ghost" id="activateWifiDlgClose">Close</button>
            <button type="button" class="btn" id="activateWifiDlgSave">Save to this browser</button>
            <button type="button" class="btn secondary" id="activateWifiDlgClear">Clear draft</button>
          </div>
        </form>
      </dialog>

      <section class="card activate-pending-card">
        <div class="row between" style="flex-wrap:wrap;gap:8px;align-items:center">
          <h3 style="margin:0">Recently reported (pending claim)</h3>
          <span class="muted" style="font-size:13px">MQTT <span class="mono">bootstrap.register</span></span>
          <button class="btn secondary btn-tap" id="reload">Refresh</button>
        </div>
        <div class="divider"></div>
        <div id="pendList"></div>
      </section>
    </div>`);

  const ACTIVATE_WIFI_STORE = "croc.activateWifiDraft.v1";
  const DEVICE_WIFI_PREFILL_KEY = "croc.deviceWifiPrefill.v1";
  const readWifiDraft = () => {
    try {
      const raw = sessionStorage.getItem(ACTIVATE_WIFI_STORE);
      const o = raw ? JSON.parse(raw) : null;
      if (o && typeof o.ssid === "string" && o.ssid.trim()) {
        return { ssid: o.ssid.trim(), password: typeof o.password === "string" ? o.password : "" };
      }
    } catch (_) {}
    return null;
  };
  const refreshWifiBanner = () => {
    const el = $("#activateWifiStatus", view);
    const d = readWifiDraft();
    if (!el) return;
    el.textContent = d
      ? `Saved target Wi‑Fi “${d.ssid}”. After claim we open the device page with Wi‑Fi (device) prefilled (requires device online to push).`
      : "Optionally save the Wi‑Fi you plan to use (this browser only), or skip and fill it later on the device page.";
  };
  const dlgWifi = $("#activateWifiDialog", view);
  const openActivateWifiDialog = () => {
    const d = readWifiDraft();
    const s = $("#activateDlgSsid", view);
    const p = $("#activateDlgPass", view);
    if (s) s.value = d ? d.ssid : "";
    if (p) p.value = d ? d.password : "";
    if (dlgWifi && typeof dlgWifi.showModal === "function") dlgWifi.showModal();
  };
  const closeActivateWifiDialog = () => {
    if (dlgWifi && typeof dlgWifi.close === "function") dlgWifi.close();
  };

  const wifiOpenBtn = $("#activateWifiOpenBtn", view);
  if (wifiOpenBtn) wifiOpenBtn.addEventListener("click", openActivateWifiDialog);
  const wifiSaveBtn = $("#activateWifiDlgSave", view);
  if (wifiSaveBtn) {
    wifiSaveBtn.addEventListener("click", () => {
      const ssid = ($("#activateDlgSsid", view).value || "").trim();
      const password = $("#activateDlgPass", view).value || "";
      if (!ssid) { toast("Enter Wi‑Fi name (SSID)", "err"); return; }
      sessionStorage.setItem(ACTIVATE_WIFI_STORE, JSON.stringify({ ssid, password }));
      refreshWifiBanner();
      closeActivateWifiDialog();
      toast("Saved (this browser only)", "ok");
    });
  }
  const wifiClrDlg = $("#activateWifiDlgClear", view);
  if (wifiClrDlg) {
    wifiClrDlg.addEventListener("click", () => {
      sessionStorage.removeItem(ACTIVATE_WIFI_STORE);
      refreshWifiBanner();
      closeActivateWifiDialog();
      toast("Wi‑Fi draft cleared", "ok");
    });
  }
  const wifiClsDlg = $("#activateWifiDlgClose", view);
  if (wifiClsDlg) wifiClsDlg.addEventListener("click", closeActivateWifiDialog);
  const showPassEl = $("#activateDlgShowPass", view);
  if (showPassEl) {
    showPassEl.addEventListener("change", () => {
      const p = $("#activateDlgPass", view);
      if (p) p.type = showPassEl.checked ? "text" : "password";
    });
  }
  refreshWifiBanner();

  const resultBox = $("#idnResult");
  const drawBadge = (kind, label) =>
    `<span class="badge ${kind === "ok" ? "online" : (kind === "err" ? "offline" : "")}">${escapeHtml(label)}</span>`;

  const showClaimForm = (serial, mac, qr) => {
    const draft = readWifiDraft();
    const draftNote = draft
      ? `<p class="muted" style="margin:0 0 12px">Saved target Wi‑Fi <span class="mono">${escapeHtml(draft.ssid)}</span> — after claim we jump to the device page with Wi‑Fi (device) prefilled.</p>`
      : "";
    appendChildMarkup(
      resultBox,
      `
      <div class="card" style="margin-top:10px">
        <h4 style="margin-top:0">Confirm claim</h4>
        ${draftNote}
        <div class="inline-form">
          <label class="field"><span>device_id (usually serial)</span><input id="c_id" value="${escapeHtml(serial)}"/></label>
          <label class="field"><span>mac_nocolon</span><input id="c_mac" value="${escapeHtml(mac)}"/></label>
          <label class="field"><span>zone</span><input id="c_zone" value="all"/></label>
          <label class="field wide"><span>qr_code (optional)</span><input id="c_qr" value="${escapeHtml(qr || "")}"/></label>
          <div class="row wide" style="justify-content:flex-end">
            <button class="btn btn-tap" id="c_submit">Confirm claim</button>
          </div>
        </div>
      </div>`,
    );
    $("#c_submit").addEventListener("click", async () => {
      const body = {
        mac_nocolon: ($("#c_mac").value || "").trim().toUpperCase(),
        device_id: ($("#c_id").value || "").trim().toUpperCase(),
        zone: ($("#c_zone").value || "all").trim(),
      };
      const q = ($("#c_qr").value || "").trim();
      if (q) body.qr_code = q;
      const preWifi = readWifiDraft();
      try {
        await api("/provision/claim", { method: "POST", body });
        const did = String(body.device_id || "").toUpperCase();
        if (preWifi && preWifi.ssid) {
          sessionStorage.setItem(
            DEVICE_WIFI_PREFILL_KEY,
            JSON.stringify({ device_id: did, ssid: preWifi.ssid, password: preWifi.password || "" }),
          );
        }
        sessionStorage.removeItem(ACTIVATE_WIFI_STORE);
        refreshWifiBanner();
        toast("Claim completed", "ok");
        location.hash = `#/devices/${encodeURIComponent(did)}`;
      } catch (e) { toast(e.message || e, "err"); }
    });
  };

  $("#idn_go").addEventListener("click", async () => {
    setChildMarkup(resultBox, `<p class="muted">Identifying…</p>`);
    const raw = ($("#idn_input").value || "").trim();
    if (!raw) { setChildMarkup(resultBox, `<p class="muted">Enter serial or QR payload</p>`); return; }
    const body = raw.startsWith("CROC|") ? { qr_code: raw } : { serial: raw.toUpperCase() };
    try {
      const r = await api("/provision/identify", { method: "POST", body });
      const kv = (k, v) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(v)}</dd>`;
      switch (r.status) {
        case "ready":
          setChildMarkup(
            resultBox,
            `${drawBadge("ok", "Ready to claim")}
            <dl class="kv">${kv("Serial", r.serial)}${kv("MAC", r.mac_nocolon)}${kv("Firmware", r.fw || "—")}${kv("Last seen", r.last_seen_at ? fmtTs(r.last_seen_at) : "—")}</dl>
            <p>${escapeHtml(r.message)}</p>`,
          );
          showClaimForm(r.serial, r.mac_nocolon, raw.startsWith("CROC|") ? raw : "");
          break;
        case "already_registered":
          const canSeeOwner = !!(state.me && state.me.role === "superadmin");
          const ownerKv = canSeeOwner ? kv("Owner admin", r.owner_admin || "—") : "";
          const byYou = !!r.by_you;
          setChildMarkup(
            resultBox,
            `${drawBadge("err", byYou ? "Already yours" : "Already registered")}
            <dl class="kv">${kv("Serial", r.serial)}${kv("device_id", r.device_id)}${ownerKv}${kv("Claimed at", r.claimed_at ? fmtTs(r.claimed_at) : "—")}</dl>
            <p class="muted">${escapeHtml(r.message)}</p>
            ${byYou ? `<a class="btn secondary" href="#/devices/${encodeURIComponent(r.device_id)}">Open device</a>` : ""}`,
          );
          break;
        case "offline": {
          const dw = readWifiDraft();
          const draftNote = dw
            ? `<p class="muted" style="margin-top:10px">Saved Wi‑Fi on this machine: <strong>${escapeHtml(dw.ssid)}</strong>. After the unit is online and claimed, push credentials from the device page.</p>`
            : "";
          setChildMarkup(
            resultBox,
            `${drawBadge("", "Waiting for device")}
            <dl class="kv">${kv("Serial", r.serial)}${r.mac_hint ? kv("Factory MAC", r.mac_hint) : ""}</dl>
            <p>${escapeHtml(r.message)}</p>
            ${draftNote}
            <div class="activate-offline-actions">
              <button type="button" class="btn secondary btn-tap" id="activateOfflineWifiBtn">Edit target Wi‑Fi</button>
              <button type="button" class="btn btn-tap" id="idn_retry_offline">Powered & online — retry identify</button>
            </div>`,
          );
          break;
        }
        case "blocked":
          setChildMarkup(resultBox, `${drawBadge("err", "Factory blocked")}<p>${escapeHtml(r.message)}</p>`);
          break;
        case "unknown_serial":
          setChildMarkup(resultBox, `${drawBadge("err", "Unknown serial")}<p>${escapeHtml(r.message)}</p>`);
          break;
        default:
          setChildMarkup(resultBox, `<p class="muted">Unknown status: ${escapeHtml(r.status)}</p>`);
      }
    } catch (e) { setChildMarkup(resultBox, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`); }
  });

  view.addEventListener("click", (ev) => {
    if (ev.target.closest("#activateOfflineWifiBtn")) {
      openActivateWifiDialog();
      return;
    }
    if (ev.target.closest("#idn_retry_offline")) {
      const go = $("#idn_go", view);
      if (go) go.click();
    }
  });

  $("#reload").addEventListener("click", () => renderRoute());

  try {
    const rq = window.__routeQuery || new URLSearchParams("");
    const pre = (rq.get("q") || rq.get("serial") || "").trim();
    if (pre) {
      const el = $("#idn_input");
      if (el) el.value = pre;
    }
  } catch (_) {}

  let pendingErr = "";
  const data = await apiOr("/provision/pending", (e) => {
    pendingErr = String((e && e.message) || e || "load failed");
    return { items: [] };
  }, { timeoutMs: 16000 });
  const items = data.items || [];
  const pendListEl = view.querySelector("#pendList");
  if (!pendListEl) return;
  setChildMarkup(
    pendListEl,
    `
    <div class="table-wrap"><table class="t">
      <thead><tr><th>MAC</th><th>Serial / proposed ID</th><th>QR</th><th>Firmware</th><th>Last seen</th></tr></thead>
      <tbody>${items.length === 0 ? `<tr><td colspan="5" class="muted">${pendingErr ? "Load failed (retry with Refresh)." : "None"}</td></tr>` :
        items.map((p) => `<tr>
          <td class="mono">${escapeHtml(p.mac_nocolon || p.mac || "")}</td>
          <td class="mono">${escapeHtml(p.proposed_device_id || "—")}</td>
          <td class="mono">${escapeHtml(p.qr_code || "—")}</td>
          <td>${escapeHtml(p.fw || "—")}</td>
          <td>${escapeHtml(fmtTs(p.last_seen_at))}</td>
        </tr>`).join("")}</tbody>
    </table></div>`,
  );
});
