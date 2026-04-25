/**
 * Route: #/admin — Admin & users console (list, role edit, pending signups).
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("admin", async (view) => {
  setCrumb("Admin");
  if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`); return; }
  const isSuper = state.me.role === "superadmin";
  let admins = [];
  if (isSuper) {
    try { admins = (await api("/auth/admins", { timeoutMs: 16000 })).items || []; } catch { admins = []; }
  }

  mountView(view, `
    <div class="card">
      <h2>Users</h2>
      <p class="muted">${isSuper
        ? "Superadmin: create admin/user, assign manager_admin and policies."
        : "Admin: manage users under you and toggle their capabilities."}</p>
      <p class="muted" style="margin-top:8px">Registration and reset codes are sent via your configured mail channel on server <span class="mono">.env</span>. Telegram alerts need <span class="mono">TELEGRAM_BOT_TOKEN</span> and <span class="mono">TELEGRAM_CHAT_IDS</span>; restart the API after changing those. Status: top bar pills (from <span class="mono">/health</span>).</p>
      <div class="row right-end" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
        <button class="btn btn-tap" id="showCreate" type="button">New user</button>
        <button class="btn secondary btn-tap" id="reloadUsers" type="button">Refresh</button>
      </div>
      <div class="divider"></div>
      <div id="userTable"></div>
    </div>

    ${isSuper ? `<div class="card">
      <h3>Global sharing</h3>
      <p class="muted">Search all share grants, create/update a grant, or revoke directly.</p>
      <div class="inline-form">
        <label class="field"><span>Device ID</span><input id="gs_device" placeholder="SN-..." /></label>
        <label class="field"><span>Grantee</span><input id="gs_user" placeholder="admin_x / user_x" /></label>
        <label class="field"><span>View</span><input id="gs_view" type="checkbox" checked /></label>
        <label class="field"><span>Operate</span><input id="gs_operate" type="checkbox" /></label>
        <div class="row wide" style="justify-content:flex-end;gap:8px;flex-wrap:wrap">
          <button class="btn btn-tap" id="gs_grant" type="button">Grant / Update</button>
          <button class="btn secondary btn-tap" id="gs_query" type="button">Query</button>
          <label class="field" style="margin:0"><span>Include revoked</span><input id="gs_inc_rev" type="checkbox" /></label>
        </div>
      </div>
      <div id="gsList" style="margin-top:10px"></div>
    </div>` : ""}

    <div class="card" id="createPanel" style="display:none">
      <h3>New user</h3>
      <div class="inline-form">
        <label class="field"><span>Username</span><input id="u_name" autocomplete="off" /></label>
        <label class="field"><span>Password (min 8)</span><input id="u_pass" type="password" autocomplete="new-password" /></label>
        <label class="field"><span>Role</span><select id="u_role">
          ${isSuper
            ? `<option value="user">user</option><option value="admin">admin</option>`
            : `<option value="user">user</option>`}
        </select></label>
        <label class="field" id="u_mgr_wrap" ${isSuper ? "" : 'style="display:none"'}>
          <span>Manager admin</span>
          <select id="u_mgr">${admins.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join("")}</select>
        </label>
        <label class="field"><span>Email (required)</span><input id="u_email" type="email" autocomplete="off"/></label>
        <label class="field"><span>Tenant (optional)</span><input id="u_tenant" /></label>
        <div class="row wide" style="justify-content:flex-end;flex-wrap:wrap;gap:10px">
          <button class="btn ghost btn-tap" id="u_cancel" type="button">Cancel</button>
          <button class="btn btn-tap" id="u_submit" type="button">Create & send activation email</button>
        </div>
        <p class="muted" style="margin:8px 0 0">
          New users start as <span class="mono">pending</span>. They must finish
          <a href="#/account-activate">Activate account</a> with the email code before sign-in.
        </p>
      </div>
    </div>

    ${isSuper ? `<div class="card">
      <h3>Pending admin signups</h3>
      <p class="muted">Public registration + email verified; awaiting your approval.</p>
      <div id="pendAdmins"></div>
    </div>` : ""}

    <div class="card">
      <h3>Alert email recipients</h3>
      <p class="muted">Inbox list for alarm emails when mail channel is configured on the server.</p>
      <div id="smtpStatus" class="row" style="gap:6px"></div>
      <div class="divider"></div>
      <div class="inline-form">
        <label class="field wide"><span>Email</span><input id="r_email" type="email" autocomplete="off" placeholder="you@company.com"/></label>
        <label class="field"><span>Label</span><input id="r_label" autocomplete="off" placeholder="on-call"/></label>
        <div class="row wide" style="justify-content:flex-end">
          <button class="btn" id="r_add">Add</button>
          <button class="btn ghost" id="r_test">Send test mail</button>
        </div>
      </div>
      <div id="recipientList" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <h3>Telegram</h3>
      <p class="muted">Forwards <span class="mono">emit_event</span> from server env (<span class="mono">TELEGRAM_BOT_TOKEN</span>, <span class="mono">TELEGRAM_CHAT_IDS</span>). Test does not use the queue.</p>
      <div id="tgStatus" class="row" style="gap:6px;flex-wrap:wrap"></div>
      <div class="row" style="margin-top:10px">
        <button class="btn secondary" id="tgTest" type="button">Send test to all chats</button>
      </div>
      <div class="divider"></div>
      <h4 style="margin:0 0 8px">Command chat binding</h4>
      <p class="muted" style="margin:0 0 8px">User sends <span class="mono">/start</span> to bot, copies <span class="mono">chat_id</span>, then binds here. No password in Telegram.</p>
      <div class="inline-form">
        <label class="field"><span>chat_id</span><input id="tgBindChatId" placeholder="e.g. 2082431201 or -100xxxx" /></label>
        <label class="field"><span>Enabled</span><input id="tgBindEnabled" type="checkbox" checked /></label>
        <div class="row wide" style="justify-content:flex-end">
          <button class="btn" id="tgBindSelf" type="button">Bind this chat</button>
          <button class="btn secondary" id="tgReloadBindings" type="button">Refresh bindings</button>
        </div>
      </div>
      <div id="tgBindings" style="margin-top:10px"></div>
    </div>

    ${isSuper ? `<div class="card">
      <h3>Database backup / restore</h3>
      <p class="muted">Uses <span class="mono">/admin/backup/export</span> and <span class="mono">/admin/backup/import</span>: full SQLite encrypted to <span class="mono">.enc</span>. Import writes <span class="mono">*.restored</span> — follow ops runbook to swap files.</p>
      <label class="field" style="max-width:420px">
        <span>Encryption key <span class="muted">X-Backup-Encryption-Key</span></span>
        <input id="bk_key" type="password" autocomplete="off" />
      </label>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="bk_export">Export .enc</button>
        <input type="file" id="bk_file" accept=".enc,application/octet-stream" />
        <button class="btn secondary" id="bk_import">Upload & decrypt</button>
      </div>
    </div>` : ""}`);

  const $v = (sel) => $(sel, view);

  // users
  const loadUsers = async () => {
    try {
      const d = await api("/auth/users", { timeoutMs: 16000 });
      const users = d.items || [];
      const userTableEl = $v("#userTable");
      if (!userTableEl) return;
      setChildMarkup(
        userTableEl,
        users.length === 0
          ? `<p class="muted">No users.</p>`
          : `<div class="table-wrap"><table class="t">
            <thead><tr><th>User</th><th>Role</th><th>manager</th><th>tenant</th><th>Created</th><th></th></tr></thead>
            <tbody>${users.map((u) => {
              const isUser = u.role === "user";
              const isAdminRow = u.role === "admin";
              const self = u.username === (state.me && state.me.username);
              const closeTenantBtn = isSuper && isAdminRow && !self
                ? `<button type="button" class="btn sm danger js-close-admin" data-u="${escapeHtml(u.username)}">Close tenant</button>`
                : "";
              return `<tr>
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td><span class="chip">${escapeHtml(u.role)}</span></td>
                <td class="mono">${escapeHtml(u.manager_admin || "—")}</td>
                <td class="mono">${escapeHtml(u.tenant || "—")}</td>
                <td>${escapeHtml(fmtTs(u.created_at))}</td>
                <td>
                  <div class="table-actions">
                    <details class="toolbar-collapse">
                      <summary>Actions</summary>
                      <div class="table-actions">
                        ${isUser ? `<button type="button" class="btn sm secondary js-pol" data-u="${escapeHtml(u.username)}">Policy</button>` : ""}
                        ${closeTenantBtn}
                        ${self ? "" : (isAdminRow ? "" : `<button type="button" class="btn sm danger js-del" data-u="${escapeHtml(u.username)}">Delete</button>`)}
                      </div>
                    </details>
                  </div>
                </td>
              </tr><tr class="sub" style="display:none" data-pol-row="${escapeHtml(u.username)}"><td colspan="6"></td></tr>`;
            }).join("")}</tbody></table></div>`,
      );
    } catch (e) {
      const userTableEl = $v("#userTable");
      if (userTableEl) setChildMarkup(userTableEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  };

  const loadGlobalShares = async () => {
    if (!isSuper) return;
    const listEl = $v("#gsList");
    if (!listEl) return;
    const qs = new URLSearchParams();
    const device = ($v("#gs_device").value || "").trim();
    const user = ($v("#gs_user").value || "").trim();
    if (device) qs.set("device_id", device);
    if (user) qs.set("grantee_username", user);
    if ($v("#gs_inc_rev") && $v("#gs_inc_rev").checked) qs.set("include_revoked", "true");
    qs.set("limit", "500");
    setChildMarkup(listEl, `<p class="muted">Loading shares…</p>`);
    try {
      const d = await api("/admin/shares?" + qs.toString(), { timeoutMs: 16000 });
      const items = d.items || [];
      setChildMarkup(
        listEl,
        items.length === 0
          ? `<p class="muted">No matching shares.</p>`
          : `<div class="table-wrap"><table class="t">
            <thead><tr><th>Device</th><th>Owner</th><th>Grantee</th><th>Role</th><th>View</th><th>Operate</th><th>Granted by</th><th>Status</th><th></th></tr></thead>
            <tbody>${items.map((it) => `
              <tr>
                <td class="mono">${escapeHtml(it.device_id || "")}</td>
                <td class="mono">${escapeHtml(it.owner_admin || "—")}</td>
                <td class="mono">${escapeHtml(it.grantee_username || "")}</td>
                <td>${escapeHtml(it.grantee_role || "—")}</td>
                <td>${it.can_view ? "yes" : "no"}</td>
                <td>${it.can_operate ? "yes" : "no"}</td>
                <td class="mono">${escapeHtml(it.granted_by || "")}</td>
                <td>${it.revoked_at ? `<span class="badge offline">revoked</span>` : `<span class="badge online">active</span>`}</td>
                <td><div class="table-actions">${it.revoked_at ? "" : `<button class="btn sm danger js-gs-revoke" data-device="${escapeHtml(it.device_id || "")}" data-user="${escapeHtml(it.grantee_username || "")}">Revoke</button>`}</div></td>
              </tr>`).join("")}</tbody></table></div>`,
      );
    } catch (e) {
      setChildMarkup(listEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  };

  $v("#reloadUsers").addEventListener("click", loadUsers);
  $v("#showCreate").addEventListener("click", () => {
    $v("#createPanel").style.display = "";
    $v("#createPanel").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $v("#u_cancel").addEventListener("click", () => { $v("#createPanel").style.display = "none"; });
  $v("#u_submit").addEventListener("click", async () => {
    const body = {
      username: $v("#u_name").value.trim(),
      password: $v("#u_pass").value,
      role: $v("#u_role").value,
    };
    if (!body.username || !body.password) { toast("Username and password required", "err"); return; }
    const email = $v("#u_email").value.trim();
    if (!email) { toast("Email required for activation", "err"); return; }
    body.email = email;
    const tenant = $v("#u_tenant").value.trim(); if (tenant) body.tenant = tenant;
    if (isSuper && body.role === "user") body.manager_admin = $v("#u_mgr").value;
    try {
      const resp = await api("/auth/users", { method: "POST", body });
      toast(`Created: ${resp.message || "activation email sent"}`, "ok");
      $v("#createPanel").style.display = "none";
      $v("#u_name").value = ""; $v("#u_pass").value = ""; $v("#u_tenant").value = "";
      $v("#u_email").value = "";
      loadUsers();
    } catch (e) { toast(e.message || e, "err"); }
  });

  if (isSuper) {
    $v("#gs_query").addEventListener("click", loadGlobalShares);
    $v("#gs_grant").addEventListener("click", async () => {
      const device = ($v("#gs_device").value || "").trim();
      const user = ($v("#gs_user").value || "").trim();
      const canView = !!$v("#gs_view").checked;
      const canOperate = !!$v("#gs_operate").checked;
      if (!device || !user) { toast("Device ID and grantee required", "err"); return; }
      if (!canView && !canOperate) { toast("Select view and/or operate", "err"); return; }
      try {
        await api(`/admin/devices/${encodeURIComponent(device)}/share`, {
          method: "POST",
          body: { grantee_username: user, can_view: canView, can_operate: canOperate },
        });
        toast("Share updated", "ok");
        loadGlobalShares();
      } catch (e) { toast(e.message || e, "err"); }
    });
    $v("#gsList").addEventListener("click", async (ev) => {
      const btn = ev.target.closest(".js-gs-revoke");
      if (!btn) return;
      const device = btn.dataset.device || "";
      const user = btn.dataset.user || "";
      if (!device || !user) return;
      if (!confirm(`Revoke ${user} from ${device}?`)) return;
      try {
        await api(`/admin/devices/${encodeURIComponent(device)}/share/${encodeURIComponent(user)}`, { method: "DELETE" });
        toast("Share revoked", "ok");
        loadGlobalShares();
      } catch (e) { toast(e.message || e, "err"); }
    });
    loadGlobalShares();
  }

  const openPolicy = async (username, trRow) => {
    const cell = trRow.querySelector("td");
    setChildMarkup(cell, `<span class="muted">Loading…</span>`);
    trRow.style.display = "";
    try {
        const p = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { timeoutMs: 16000 });
      setChildMarkup(cell, renderPolicyPanel(username, p));
      cell.querySelector(".js-save").addEventListener("click", async () => {
        const body = {};
        cell.querySelectorAll("input[type=checkbox][data-k]").forEach((i) => body[i.dataset.k] = !!i.checked);
        try {
          const r = await api(`/auth/users/${encodeURIComponent(username)}/policy`, { method: "PUT", body });
          toast(`Policy updated for ${username}`, "ok");
          setChildMarkup(cell, renderPolicyPanel(username, r.policy || r));
          cell.querySelector(".js-save").addEventListener("click", () => openPolicy(username, trRow));
        } catch (e) { toast(e.message || e, "err"); }
      });
    } catch (e) { setChildMarkup(cell, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`); }
  };

  $v("#userTable").addEventListener("click", async (ev) => {
    const t = ev.target.closest("button");
    if (!t) return;
    const u = t.dataset.u;
    if (t.classList.contains("js-del")) {
      if (!confirm(`Delete user ${u}?`)) return;
      try { await api(`/auth/users/${encodeURIComponent(u)}`, { method: "DELETE" }); toast("Deleted", "ok"); loadUsers(); }
      catch (e) { toast(e.message || e, "err"); }
    }
    if (t.classList.contains("js-pol")) {
      const row = view.querySelector(`tr[data-pol-row="${CSS.escape(u)}"]`);
      if (!row) return;
      if (row.style.display === "") { row.style.display = "none"; return; }
      openPolicy(u, row);
    }
    if (t.classList.contains("js-close-admin")) {
      if (!isSuper) return;
      if (!u) return;
      if (!confirm(
        `Close admin tenant "${u}"?\n\n` +
          "· Devices: factory-unclaim all, OR transfer to another admin in the next prompt.\n" +
          "· All subordinate users under this admin will be deleted.\n" +
          "· That username and email are released for new signups."
      )) return;
      const transfer = window.prompt(
        "Optional: target admin username to receive ALL this admin’s devices (leave empty to unclaim every device):"
      );
      if (transfer === null) return;
      const transferTo = String(transfer).trim() || null;
      const confirmText = window.prompt("Type exactly: CLOSE TENANT");
      if (confirmText === null) return;
      if (String(confirmText).trim() !== "CLOSE TENANT") {
        toast("Confirmation must be exactly: CLOSE TENANT", "err");
        return;
      }
      try {
        const r = await api(`/auth/admins/${encodeURIComponent(u)}/close`, {
          method: "POST",
          body: { confirm_text: "CLOSE TENANT", transfer_devices_to: transferTo },
        });
        toast(
          `Tenant closed — unclaimed ${Number(r.devices_unclaimed || 0)}, transferred ${Number(r.devices_transferred || 0)}, removed ${Number(r.subordinate_users_deleted || 0)} user(s).`,
          "ok",
        );
        loadUsers();
      } catch (e) { toast(e.message || e, "err"); }
    }
  });

  // backup
  if (isSuper) {
    $v("#bk_export").addEventListener("click", async () => {
      const key = ($v("#bk_key").value || "").trim();
      if (!key) { toast("Enter backup encryption key", "err"); return; }
      const btn = $v("#bk_export");
      const orig = btn ? btn.textContent : "";
      if (btn) { btn.disabled = true; btn.textContent = "Exporting…"; }
      try {
        const _h = { "X-Backup-Encryption-Key": key };
        const _tb = getToken();
        if (_tb) _h.Authorization = "Bearer " + _tb;
        // Backup files can be large; allow up to 5 minutes before aborting.
        const r = await fetchWithDeadline(apiBase() + "/admin/backup/export", {
          method: "GET",
          credentials: "include",
          headers: _h,
        }, 300000);
        if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
        const blob = new Blob([await r.arrayBuffer()], { type: "application/octet-stream" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob); a.download = "sentinel-backup.enc"; a.click();
        URL.revokeObjectURL(a.href);
        toast("Downloaded", "ok");
      } catch (e) { toast(e.message || e, "err"); }
      finally { if (btn) { btn.disabled = false; btn.textContent = orig || "Export"; } }
    });
    $v("#bk_import").addEventListener("click", async () => {
      const key = ($v("#bk_key").value || "").trim();
      const f = $v("#bk_file").files[0];
      if (!key || !f) { toast("Pick a file and enter the encryption key", "err"); return; }
      const fd = new FormData(); fd.append("file", f, f.name || "sentinel-backup.enc");
      const btn = $v("#bk_import");
      const orig = btn ? btn.textContent : "";
      if (btn) { btn.disabled = true; btn.textContent = "Importing…"; }
      try {
        const _hi = { "X-Backup-Encryption-Key": key };
        const _ti = getToken();
        if (_ti) _hi.Authorization = "Bearer " + _ti;
        else {
          // Cookie session: backup is a write op → must echo CSRF token.
          let _ctok = getCsrfToken();
          if (!_ctok) _ctok = await refreshCsrfToken();
          if (_ctok) _hi[CSRF_HEADER_NAME] = _ctok;
        }
        const r = await fetchWithDeadline(apiBase() + "/admin/backup/import", {
          method: "POST",
          credentials: "include",
          headers: _hi,
          body: fd,
        }, 300000);
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(`${r.status} ${j.detail || ""}`);
        toast("Written: " + (j.written_path || "done"), "ok");
      } catch (e) { toast(e.message || e, "err"); }
      finally { if (btn) { btn.disabled = false; btn.textContent = orig || "Import"; } }
    });
  }

  // SMTP status + recipients
  const loadSmtpStatus = async () => {
    try {
      const s = await api("/admin/smtp/status", { timeoutMs: 16000 });
      const smtpEl = $v("#smtpStatus");
      if (!smtpEl) return;
      const okBadge = s.enabled
        ? `<span class="badge online">Mail on</span>`
        : `<span class="badge offline">Mail off</span>`;
      const last = s.last_error ? `<span class="chip" title="last error">${escapeHtml(s.last_error)}</span>` : "";
      setChildMarkup(
        smtpEl,
        `${okBadge}
        <span class="chip">host: ${escapeHtml(s.host || "—")}:${escapeHtml(String(s.port || "—"))}</span>
        <span class="chip">mode: ${escapeHtml(s.mode || "—")}</span>
        <span class="chip">from: ${escapeHtml(s.sender || "—")}</span>
        <span class="chip">sent: ${s.sent_count || 0}</span>
        <span class="chip">failed: ${s.failed_count || 0}</span>
        <span class="chip">queue: ${s.queue_size ?? 0}/${s.queue_max ?? ""}</span>${last}`,
      );
    } catch (e) {
      const smtpEl = $v("#smtpStatus");
      if (!smtpEl) return;
      setChildMarkup(smtpEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
    }
  };
  const loadRecipients = async () => {
    try {
      const d = await api("/admin/alert-recipients", { timeoutMs: 16000 });
      const items = d.items || [];
      const listEl = $v("#recipientList");
      if (!listEl) return;
      setChildMarkup(
        listEl,
        items.length === 0
          ? `<p class="muted">No recipients yet.</p>`
          : `<div class="table-wrap"><table class="t">
            <thead><tr><th>Email</th><th>Label</th><th>Enabled</th><th>Tenant</th><th></th></tr></thead>
            <tbody>${items.map((r) => `
              <tr>
                <td class="mono">${escapeHtml(r.email)}</td>
                <td>${escapeHtml(r.label || "—")}</td>
                <td>${r.enabled ? `<span class="badge online">On</span>` : `<span class="badge offline">Off</span>`}</td>
                <td class="mono">${escapeHtml(r.owner_admin || "")}</td>
                <td><div class="table-actions">
                  <button class="btn sm secondary js-rtoggle" data-id="${r.id}" data-en="${r.enabled ? 1 : 0}">${r.enabled ? "Disable" : "Enable"}</button>
                  <button class="btn sm danger js-rdel" data-id="${r.id}">Delete</button>
                </div></td>
              </tr>`).join("")}</tbody></table></div>`,
      );
    } catch (e) {
      const listEl = $v("#recipientList");
      if (!listEl) return;
      setChildMarkup(listEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
    }
  };
  $v("#r_add").addEventListener("click", async () => {
    const email = ($v("#r_email").value || "").trim();
    const label = ($v("#r_label").value || "").trim();
    if (!email) { toast("Enter email", "err"); return; }
    try {
      await api("/admin/alert-recipients", { method: "POST", body: { email, label } });
      $v("#r_email").value = ""; $v("#r_label").value = "";
      toast("Added", "ok");
      loadRecipients();
    } catch (e) { toast(e.message || e, "err"); }
  });
  $v("#r_test").addEventListener("click", async () => {
    const email = ($v("#r_email").value || "").trim();
    if (!email) { toast("Enter recipient email first", "err"); return; }
    try {
      await api("/admin/smtp/test", { method: "POST", body: { to: email } });
      toast("Mail test sent", "ok");
      loadSmtpStatus();
    } catch (e) { toast(e.message || e, "err"); }
  });
  const loadTgStatus = async () => {
    try {
      const t = await api("/admin/telegram/status", { timeoutMs: 16000 });
      const tgEl = $v("#tgStatus");
      if (!tgEl) return;
      const badge = t.enabled
        ? `<span class="badge online">enabled</span>`
        : `<span class="badge offline">disabled</span>`;
      const wk = t.worker_running ? "yes" : "no";
      const th = t.token_hint ? `<span class="chip mono" title="Token prefix/suffix only">${escapeHtml(t.token_hint)}</span>` : "";
      const modErr = t.status_module_error
        ? `<p class="badge revoked" style="margin-top:8px">Telegram module failed — see <span class="mono">last_error</span> and API logs.</p>`
        : "";
      const le = (t.last_error || "").trim()
        ? `<p class="muted" style="margin-top:8px;word-break:break-word"><strong>Last error:</strong> ${escapeHtml(t.last_error)}</p>`
        : "";
      setChildMarkup(
        tgEl,
        `${badge}
        ${th}
        <span class="chip">worker: ${wk}</span>
        <span class="chip">chats: ${t.chats ?? 0}</span>
        <span class="chip">min_level: ${escapeHtml(t.min_level || "")}</span>
        <span class="chip">queue: ${t.queue_size ?? 0}</span>${modErr}${le}`,
      );
    } catch (e) {
      const tgEl = $v("#tgStatus");
      if (!tgEl) return;
      setChildMarkup(tgEl, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
    }
  };
  const loadTgBindings = async () => {
    const el = $v("#tgBindings");
    if (!el) return;
    setChildMarkup(el, `<p class="muted">Loading bindings…</p>`);
    try {
      const d = await api("/admin/telegram/bindings", { timeoutMs: 16000 });
      const items = d.items || [];
      setChildMarkup(
        el,
        items.length === 0
          ? `<p class="muted">No bindings yet.</p>`
          : `<div class="table-wrap"><table class="t">
            <thead><tr><th>chat_id</th><th>username</th><th>enabled</th><th>updated</th><th></th></tr></thead>
            <tbody>${items.map((it) => `
              <tr>
                <td class="mono">${escapeHtml(it.chat_id || "")}</td>
                <td>${escapeHtml(it.username || "")}</td>
                <td>${it.enabled ? `<span class="badge online">on</span>` : `<span class="badge offline">off</span>`}</td>
                <td>${escapeHtml(fmtTs(it.updated_at || it.created_at))}</td>
                <td><div class="table-actions"><button class="btn sm danger js-tg-unbind" data-chat="${escapeHtml(String(it.chat_id || ""))}">Unbind</button></div></td>
              </tr>`).join("")}</tbody></table></div>`,
      );
    } catch (e) {
      setChildMarkup(el, `<span class="badge revoked">${escapeHtml(e.message || e)}</span>`);
    }
  };
  $v("#tgTest").addEventListener("click", async () => {
    try {
      const r = await api("/admin/telegram/test", { method: "POST", body: { text: "Croc Sentinel UI test" } });
      toast(r.detail || "ok", "ok");
      loadTgStatus();
    } catch (e) { toast(e.message || e, "err"); }
  });
  $v("#tgBindSelf").addEventListener("click", async () => {
    const chat_id = ($v("#tgBindChatId").value || "").trim();
    const enabled = !!$v("#tgBindEnabled").checked;
    if (!chat_id) { toast("Enter chat_id", "err"); return; }
    try {
      await api("/admin/telegram/bind-self", { method: "POST", body: { chat_id, enabled } });
      toast("Chat bound", "ok");
      loadTgBindings();
    } catch (e) { toast(e.message || e, "err"); }
  });
  $v("#tgReloadBindings").addEventListener("click", loadTgBindings);
  $v("#tgBindings").addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".js-tg-unbind");
    if (!btn) return;
    const chat = btn.dataset.chat || "";
    if (!chat) return;
    if (!confirm(`Unbind chat ${chat}?`)) return;
    try {
      await api(`/admin/telegram/bindings/${encodeURIComponent(chat)}`, { method: "DELETE" });
      toast("Unbound", "ok");
      loadTgBindings();
    } catch (e) { toast(e.message || e, "err"); }
  });
  $v("#recipientList").addEventListener("click", async (ev) => {
    const b = ev.target.closest("button"); if (!b) return;
    const id = b.dataset.id;
    if (b.classList.contains("js-rdel")) {
      if (!confirm("Remove this recipient?")) return;
      try { await api(`/admin/alert-recipients/${id}`, { method: "DELETE" }); toast("Removed", "ok"); loadRecipients(); }
      catch (e) { toast(e.message || e, "err"); }
    }
    if (b.classList.contains("js-rtoggle")) {
      const en = b.dataset.en === "1" ? 0 : 1;
      try { await api(`/admin/alert-recipients/${id}`, { method: "PATCH", body: { enabled: !!en } }); loadRecipients(); }
      catch (e) { toast(e.message || e, "err"); }
    }
  });
  loadSmtpStatus();
  loadRecipients();
  loadTgStatus();
  loadTgBindings();

  // Pending admin signups (superadmin approval queue)
  const loadPendAdmins = async () => {
    if (!isSuper) return;
    try {
      const d = await api("/auth/signup/pending", { timeoutMs: 16000 });
      const items = d.items || [];
      const pendEl = $v("#pendAdmins");
      if (!pendEl) return;
      setChildMarkup(
        pendEl,
        items.length === 0
          ? `<p class="muted">No pending signups.</p>`
          : `<div class="table-wrap"><table class="t">
            <thead><tr><th>Username</th><th>Email</th><th>Submitted</th><th>Email OK</th><th></th></tr></thead>
            <tbody>${items.map((u) => `<tr>
              <td><strong>${escapeHtml(u.username)}</strong></td>
              <td class="mono">${escapeHtml(u.email || "—")}</td>
              <td>${escapeHtml(fmtTs(u.created_at))}</td>
              <td>${u.email_verified_at ? "✓" : "—"}</td>
              <td>
                <button class="btn sm js-ok" data-u="${escapeHtml(u.username)}">Approve</button>
                <button class="btn sm danger js-reject" data-u="${escapeHtml(u.username)}">Reject</button>
              </td>
            </tr>`).join("")}</tbody></table></div>`,
      );
    } catch (e) {
      const pendEl = $v("#pendAdmins");
      if (!pendEl) return;
      setChildMarkup(pendEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  };
  if (isSuper) {
    $v("#pendAdmins").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      const u = b.dataset.u;
      if (b.classList.contains("js-ok")) {
        try { await api(`/auth/signup/approve/${encodeURIComponent(u)}`, { method: "POST" }); toast("Approved", "ok"); loadPendAdmins(); loadUsers(); }
        catch (e) { toast(e.message || e, "err"); }
      } else if (b.classList.contains("js-reject")) {
        if (!confirm(`Reject and delete signup for ${u}?`)) return;
        try { await api(`/auth/signup/reject/${encodeURIComponent(u)}`, { method: "POST" }); toast("Rejected", "ok"); loadPendAdmins(); }
        catch (e) { toast(e.message || e, "err"); }
      }
    });
    loadPendAdmins();
  }

  loadUsers();
});
