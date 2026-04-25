/**
 * Route: #/ota — OTA & firmware (superadmin staging + tenant-side upgrade hint).
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("ota", async (view, _args, routeSeq) => {
  await __renderOtaFirmwareRoute(view, routeSeq);
});

async function __renderOtaFirmwareRoute(view, routeSeq) {
  setCrumb("OTA (ops)");
  const me = state.me || { username: "", role: "user" };
  const isSuper = me.role === "superadmin";

  if (!isSuper) {
    mountView(view, `
      <div class="card">
        <h2 class="ui-section-title" style="margin:0">OTA & firmware</h2>
        <p class="muted" style="margin:8px 0 0">租户侧 <strong>不</strong>再使用 Admin OTA 控制台。请在 <a href="#/devices">全部设备</a> 与设备详情查看版本旁的 <strong>↑ + 红点</strong>（有可用新固件时）。OTA 上传与 campaign 仅 <strong>superadmin</strong> 在侧栏「OTA (ops)」操作。</p>
        <p class="muted" style="margin:8px 0 0">There is <strong>no</strong> admin OTA console in this product. Use <a href="#/devices">All devices</a> and device detail for the <strong>↑ + red dot</strong> when an upgrade is available. Staging and campaigns are <strong>superadmin</strong> only (sidebar <strong>OTA (ops)</strong>).</p>
      </div>`);
    return;
  }

  const helpCard = `
    <div class="card ota-help-card">
      <h2 class="ui-section-title" style="margin:0">OTA & firmware · 使用说明</h2>
      <div class="ota-help__cols">
        <div>
          <h3 class="ota-help__h">中文</h3>
          <ul class="muted ota-help__ul">
            <li><strong>全员（含 admin）</strong>：只看 <a href="#/devices">全部设备</a> / 设备详情上的 <strong>↑ + 红点</strong> 与说明弹窗；不在此页对 campaign 做 Accept。</li>
            <li><strong>检测</strong>：服务器比较 <code>OTA_FIRMWARE_DIR</code> 中的 <code>.bin</code> 与设备 <code>fw</code>；需 <code>OTA_PUBLIC_BASE_URL</code> 才能在弹窗中给出下载 URL。</li>
            <li><strong>文件</strong>：推荐 <code>croc-版本号-8位hex.bin</code>；同名 <code>.txt</code> / <code>.md</code> 为 release notes。</li>
            <li><strong>Superadmin</strong>：在本页下方上传 / 从已存文件建 campaign（若仍使用后端 campaign 流，由 API 或其它流程让各租户设备拉取；控制台不再给 admin 提供 OTA 入口）。</li>
          </ul>
        </div>
        <div>
          <h3 class="ota-help__h">English</h3>
          <ul class="muted ota-help__ul">
            <li><strong>Everyone (including admin)</strong>: use <a href="#/devices">All devices</a> / device detail <strong>↑ + red dot</strong> + notes dialog only — <strong>no</strong> tenant OTA Accept UI here.</li>
            <li><strong>Detection</strong>: server compares <code>.bin</code> in <code>OTA_FIRMWARE_DIR</code> vs device <code>fw</code>; set <code>OTA_PUBLIC_BASE_URL</code> for URLs in the dialog.</li>
            <li><strong>Files</strong>: prefer <code>croc-SEMVER-random8.bin</code>; sidecar <code>.txt</code>/<code>.md</code> for notes.</li>
            <li><strong>Superadmin</strong>: upload / create-from-stored below. Campaign APIs may still exist server-side; this dashboard does not expose an admin OTA workflow.</li>
          </ul>
        </div>
      </div>
      <p class="muted" style="margin:12px 0 0">Fleet: <a href="#/devices">All devices</a></p>
    </div>`;

  const superCard = `
    <div class="card">
      <h2 class="ui-section-title">Superadmin · Upload & campaign</h2>
      <p class="muted" style="margin:0 0 8px">Upload stages a <code>.bin</code> under <code>OTA_FIRMWARE_DIR</code> (upload password <code>OTA_UPLOAD_PASSWORD</code>). The API keeps at most <strong id="otaMaxBinsLbl">10</strong> <code>.bin</code> files and deletes the <strong>oldest by file mtime</strong> (and sidecars) when over limit — same rule as <code>POST /ota/firmware/upload</code>. The list below is <strong>fetched from this server</strong> (<code>GET /ota/firmwares</code>); click <strong>Refresh list</strong> after upload or if you copied files in by hand.</p>
      <div class="inline-form">
        <label class="field wide"><span>Upload password *</span><input type="password" id="otaStUploadPwd" autocomplete="off" placeholder="Server OTA_UPLOAD_PASSWORD" /></label>
        <label class="field"><span>Firmware file (.bin)</span><input type="file" id="otaStFile" accept=".bin,application/octet-stream" /></label>
        <label class="field"><span>Version label *</span><input id="otaStFw" placeholder="6.6.8" maxlength="40" /></label>
        <div class="row wide" style="justify-content:flex-end">
          <button type="button" class="btn btn-tap" id="otaStBtn">Upload & verify</button>
        </div>
      </div>
      <p class="muted" id="otaRetentionInfo" style="margin-top:8px;min-height:1.2em"></p>
      <p class="muted" id="otaStResult" style="margin-top:4px;min-height:1.2em"></p>
      <div class="divider"></div>
      <h3 style="margin:0 0 6px">Publish from server-staged firmware / 使用服务器上的固件</h3>
      <p class="muted" style="margin:0 0 8px;font-size:12.5px">The dropdown is populated by <strong>pulling the current directory listing from the API</strong> (not from your PC). Pick a <code>.bin</code> already on the server, then create a campaign. <strong>Version</strong> is resolved on the server (<code>.version</code> sidecar or filename) — not hand-typed; it should match that build&rsquo;s <code>FW_VERSION</code>.</p>
      <div class="row wide" style="align-items:flex-end;flex-wrap:wrap;gap:10px;margin-bottom:6px">
        <label class="field wide" style="flex:1;min-width:220px;margin:0"><span>Firmware on server *</span><select id="otaFromSel"><option value="">Loading…</option></select></label>
        <button type="button" class="btn secondary btn-tap sm" id="otaFwListRefresh">Refresh list</button>
      </div>
      <label class="field wide"><span>Version (from server, read-only)</span><input type="text" id="otaFromResolvedVer" class="mono" readonly tabindex="-1" value="—" style="background:var(--bg-muted);cursor:default" aria-live="polite" /></label>
      <label class="field wide"><span>Notes</span><input id="otaFromNotes" maxlength="500" /></label>
      <label class="checkbox"><input type="checkbox" id="otaFromAllAd" checked /><span>Target all admins</span></label>
      <label class="field wide"><span>Or comma-separated admin usernames</span><input id="otaFromAdmTxt" placeholder="admin-a, admin-b (when not targeting all)" /></label>
      <div class="row wide" style="justify-content:flex-end;margin-top:10px">
        <button type="button" class="btn btn-tap" id="otaFromBtn">Create campaign</button>
      </div>
    </div>`;

  mountView(view, helpCard + superCard);

  const otaSyncFromStoredVersion = () => {
    const sel = $("#otaFromSel", view);
    const ro = $("#otaFromResolvedVer", view);
    if (!ro) return;
    if (!sel || !sel.value) {
      ro.value = "—";
      return;
    }
    const i = Number(sel.selectedIndex);
    const opt = sel.options[i];
    const raw = opt && opt.getAttribute("data-fw-version");
    const v = (raw && String(raw).trim()) || "";
    ro.value = v || "—";
  };

  const refreshFirmwareSelect = async () => {
    if (!isSuper) return;
    const sel = $("#otaFromSel", view);
    if (!sel) return;
    try {
      const r = await api("/ota/firmwares", { timeoutMs: 20000 });
      if (!isRouteCurrent(routeSeq)) return;
      const items = r.items || [];
      const ret = r.retention;
      const mx = $("#otaMaxBinsLbl", view);
      if (mx && ret && ret.max_bins != null) mx.textContent = String(ret.max_bins);
      const inf = $("#otaRetentionInfo", view);
      if (inf) {
        inf.textContent = ret
          ? `Server directory: ${ret.stored_count || 0} / max ${ret.max_bins} .bin files (oldest mtime removed when over limit). Upload password: ${ret.upload_password_configured ? "configured" : "not set on server"}.`
          : "";
      }
      const fmtM = (ts) => {
        const t = Number(ts);
        if (!Number.isFinite(t) || t <= 0) return "";
        try {
          const d = new Date(t * 1000);
          return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
        } catch {
          return "";
        }
      };
      sel.innerHTML = items.length
        ? items.map((it) => {
          const vRaw = (it.fw_version && String(it.fw_version).trim()) || "";
          const dv = vRaw ? escapeHtml(vRaw) : "";
          const fv = vRaw
            ? ` · v${escapeHtml(vRaw)}`
            : "";
          const mt = fmtM(it.mtime);
          const mtS = mt ? ` · ${escapeHtml(mt)}` : "";
          return `<option value="${escapeHtml(it.name)}" data-fw-version="${dv}">${escapeHtml(it.name)}${fv} (${Math.round(Number(it.size || 0) / 1024)} KB${mtS})</option>`;
        }).join("")
        : "<option value=\"\">(no .bin in folder)</option>";
      otaSyncFromStoredVersion();
      sel.onchange = otaSyncFromStoredVersion;
    } catch (e) {
      const inf = $("#otaRetentionInfo", view);
      if (inf) inf.textContent = "";
      sel.innerHTML = `<option value="">${escapeHtml(e.message || "list failed")}</option>`;
      otaSyncFromStoredVersion();
      sel.onchange = otaSyncFromStoredVersion;
    }
  };

  await refreshFirmwareSelect();
  const otaFwListRefresh = $("#otaFwListRefresh", view);
  if (otaFwListRefresh) {
    otaFwListRefresh.addEventListener("click", async () => {
      otaFwListRefresh.disabled = true;
      try {
        await refreshFirmwareSelect();
        toast("Firmware list refreshed from server", "ok");
      } catch (_) {}
      finally { otaFwListRefresh.disabled = false; }
    });
  }
  const stBtn = $("#otaStBtn", view);
  if (stBtn) {
    stBtn.addEventListener("click", async () => {
      const inp = $("#otaStFile", view);
      const f = inp && inp.files && inp.files[0];
      const fw = String($("#otaStFw", view)?.value || "").trim();
      const upw = String($("#otaStUploadPwd", view)?.value || "");
      if (!f || !fw) { toast("Choose file and version label", "err"); return; }
      if (!upw) { toast("Enter the upload password (set OTA_UPLOAD_PASSWORD on the server).", "err"); return; }
      if (!confirm("Upload firmware to server (HEAD check against public /fw/ URL)?")) return;
      try {
        const fd = new FormData();
        fd.append("file", f);
        fd.append("fw_version", fw);
        fd.append("upload_password", upw);
        const r = await api("/ota/firmware/upload", { method: "POST", body: fd, timeoutMs: 180000 });
        if (!isRouteCurrent(routeSeq)) return;
        const resEl = $("#otaStResult", view);
        if (resEl) resEl.textContent = `Stored ${r.stored_as || ""} · head_ok=${r.head_ok} · ${r.verify || ""}`;
        toast("Upload finished", r.head_ok ? "ok" : "err");
        if (inp) inp.value = "";
        refreshFirmwareSelect();
      } catch (e) { toast(e.message || e, "err"); }
    });
  }
  const fromBtn = $("#otaFromBtn", view);
  if (fromBtn) {
    fromBtn.addEventListener("click", async () => {
      const fn = String($("#otaFromSel", view)?.value || "").trim();
      const notes = String($("#otaFromNotes", view)?.value || "").trim();
      const allCh = $("#otaFromAllAd", view);
      const rawAdm = String($("#otaFromAdmTxt", view)?.value || "").trim();
      const target_admins = (allCh && allCh.checked) ? ["*"] : (rawAdm ? rawAdm.split(/[\s,;]+/).filter(Boolean) : ["*"]);
      if (!fn) { toast("Select a firmware package from the list", "err"); return; }
      if (!confirm("Create OTA campaign from this stored file? The campaign version will be taken from the server (staged .version / filename), not the UI.")) return;
      try {
        const out = await api("/ota/campaigns/from-stored", {
          method: "POST",
          body: { filename: fn, notes: notes || undefined, target_admins },
        });
        toast(
          (out && out.fw_version) ? `Campaign created · v${out.fw_version}` : "Campaign created",
          "ok",
        );
        try { bustDeviceListCaches(); } catch (_) {}
      } catch (e) { toast(e.message || e, "err"); }
    });
  }
}


function renderPolicyPanel(username, p) {
  const row = (k, label, locked) => `
    <label class="checkbox"><input type="checkbox" data-k="${k}" ${p[k] ? "checked" : ""} ${locked ? "disabled" : ""}/><span>${escapeHtml(label)}</span></label>`;
  return `
    <div class="stack">
      <p class="muted" style="margin:0">Capabilities for <strong>${escapeHtml(username)}</strong> (user role).</p>
      <div class="row">
        ${row("can_alert", "Alarms (device + bulk + cancel)")}
        ${row("can_send_command", "Send device commands")}
        ${row("can_claim_device", "Claim / provision devices")}
        ${row("can_manage_users", "Manage users (N/A for user role)", true)}
        ${row("can_backup_restore", "Backup / restore (N/A for user role)", true)}
      </div>
      <div class="row" style="justify-content:flex-end">
        <button class="btn js-save" type="button">Save</button>
      </div>
    </div>`;
}
