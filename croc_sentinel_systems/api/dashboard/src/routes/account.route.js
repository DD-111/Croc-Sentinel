/**
 * Route: #/account — Logged-in user account & sessions panel.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("account", async (view) => {
  setCrumb("Account");
  if (!hasRole("user")) { mountView(view, `<div class="card"><p class="muted">Sign in required.</p></div>`); return; }
  const me = state.me || { username: "", role: "" };
  const avStored = String(me.avatar_url || "").trim();
  const uname0 = (String(me.username || "?").trim() || "?")[0].toUpperCase();
  const roleNorm = String(me.role || "").trim().toLowerCase();
  const deleteSection = (() => {
    if (roleNorm === "superadmin") {
      return `
    <div class="card">
      <h3>Delete account</h3>
      <p class="muted">Superadmin accounts cannot be removed through this console (API blocks self-deletion).</p>
    </div>`;
    }
    if (roleNorm === "admin") {
      return `
    <details class="card danger-zone">
      <summary style="cursor:pointer;font-weight:700">Danger zone · Close tenant</summary>
      <div style="margin-top:10px">
      <h3>Close tenant account</h3>
      <p class="muted" style="margin:0 0 10px">If you close this admin tenant:</p>
      <ul class="muted" style="margin:0 0 12px;padding-left:1.25em;line-height:1.55">
        <li><strong>Devices</strong> you own are <strong>factory-unclaimed</strong> (dashboard records removed; devices return to unregistered / reclaimable state).</li>
        <li><strong>Subordinate users</strong> created under your account are <strong>deleted</strong>.</li>
        <li>Your <strong>username</strong> and <strong>email</strong> become available for new registration.</li>
      </ul>
      <label class="checkbox" style="margin-bottom:12px;display:flex;gap:8px;align-items:flex-start">
        <input id="accAckTenant" type="checkbox" />
        <span>I understand all devices under this tenant will be released and sub-users removed.</span>
      </label>
      <p class="muted">Type <span class="mono">DELETE</span> and your password to confirm.</p>
      <label class="field"><span>Current password</span><input id="accDelPw" type="password" autocomplete="current-password"/></label>
      <label class="field field--spaced"><span>Type DELETE</span><input id="accDelText" placeholder="DELETE"/></label>
      <div class="row" style="justify-content:flex-end;margin-top:10px">
        <button class="btn danger" id="accDeleteSelf">Close tenant permanently</button>
      </div>
      </div>
    </details>`;
    }
    return `
    <details class="card danger-zone">
      <summary style="cursor:pointer;font-weight:700">Danger zone · Delete account</summary>
      <div style="margin-top:10px">
      <h3>Delete account</h3>
      <p class="muted">This action is irreversible. Type <span class="mono">DELETE</span> and confirm your password.</p>
      <label class="field"><span>Current password</span><input id="accDelPw" type="password" autocomplete="current-password"/></label>
      <label class="field field--spaced"><span>Type DELETE</span><input id="accDelText" placeholder="DELETE"/></label>
      <div class="row" style="justify-content:flex-end;margin-top:10px">
        <button class="btn danger" id="accDeleteSelf">Delete my account</button>
      </div>
      </div>
    </details>`;
  })();
  const previewInner = avStored
    ? `<img src="${escapeHtml(avStored)}" alt="" width="48" height="48" loading="lazy" decoding="async" referrerpolicy="no-referrer" />`
    : `<span class="account-avatar-fallback" aria-hidden="true">${escapeHtml(uname0)}</span>`;
  mountView(view, `
    <div class="card">
      <h2>My account</h2>
      <p class="muted">User: <span class="mono">${escapeHtml(me.username)}</span> · Role: <span class="mono">${escapeHtml(me.role)}</span></p>
    </div>
    <div class="card">
      <h3>Profile picture</h3>
      <p class="muted" style="margin:0 0 10px">Use an <strong>https</strong> image link you control (square works best). Shown in the left sidebar. If the image cannot load, your initial is used.</p>
      <div class="row" style="align-items:flex-end;flex-wrap:wrap;gap:12px">
        <label class="field" style="flex:1;min-width:200px;max-width:100%"><span>Image URL</span>
          <input id="accAvatarUrl" type="url" inputmode="url" placeholder="https://…" value="${escapeHtml(avStored)}" autocomplete="off" />
        </label>
        <div class="account-avatar-preview" id="accAvatarPreview" aria-hidden="true">${previewInner}</div>
      </div>
      <div class="row" style="justify-content:flex-end;margin-top:10px;gap:8px;flex-wrap:wrap">
        <button class="btn secondary" type="button" id="accAvatarClear">Use initial only</button>
        <button class="btn" type="button" id="accAvatarSave">Save</button>
      </div>
    </div>
    <div class="card">
      <h3>Change password</h3>
      <label class="field"><span>Current password</span><input id="acc_old" type="password" autocomplete="current-password"/></label>
      <label class="field field--spaced"><span>New password</span><input id="acc_new1" type="password" autocomplete="new-password"/></label>
      <label class="field field--spaced"><span>Confirm new password</span><input id="acc_new2" type="password" autocomplete="new-password"/></label>
      <div class="row" style="justify-content:flex-end;margin-top:10px">
        <button class="btn" id="accChangePw">Update password</button>
      </div>
    </div>
    ${deleteSection}
  `);
  const accPre = $("#accAvatarPreview", view);
  const accUrl = $("#accAvatarUrl", view);
  const setAccPreview = () => {
    if (!accPre) return;
    const v = (accUrl && accUrl.value ? accUrl.value : "").trim();
    if (!v) {
      setChildMarkup(accPre, `<span class="account-avatar-fallback" aria-hidden="true">${escapeHtml(uname0)}</span>`);
      return;
    }
    setChildMarkup(
      accPre,
      `<img src="${escapeHtml(v)}" alt="" width="48" height="48" loading="lazy" decoding="async" referrerpolicy="no-referrer" />`,
    );
    const g = accPre.querySelector("img");
    if (g) {
      g.addEventListener(
        "error",
        () => {
          setChildMarkup(
            accPre,
            `<span class="account-avatar-fallback account-avatar-fallback--err" title="Image failed to load" aria-hidden="true">${escapeHtml(uname0)}</span>`,
          );
        },
        { once: true },
      );
    }
  };
  if (accUrl) {
    accUrl.addEventListener("input", () => setAccPreview());
    accUrl.addEventListener("change", () => setAccPreview());
  }
  $("#accAvatarClear", view).addEventListener("click", () => {
    if (accUrl) accUrl.value = "";
    setAccPreview();
  });
  $("#accAvatarSave", view).addEventListener("click", async () => {
    const v = (accUrl && accUrl.value ? accUrl.value : "").trim();
    try {
      const r = await api("/auth/me/profile", { method: "PATCH", body: { avatar_url: v } });
      if (state.me) state.me.avatar_url = r && r.avatar_url != null ? r.avatar_url : v;
      renderAuthState();
      toast(v ? "Profile picture saved" : "Using initial letter", "ok");
    } catch (e) {
      toast(e.message || e, "err");
    }
  });
  const accChangePwBtn = $("#accChangePw", view);
  if (accChangePwBtn) {
    accChangePwBtn.addEventListener("click", async () => {
    try {
      await api("/auth/me/password", {
        method: "PATCH",
        body: {
          current_password: ($("#acc_old", view).value || ""),
          new_password: ($("#acc_new1", view).value || ""),
          new_password_confirm: ($("#acc_new2", view).value || ""),
        },
      });
      toast("Password updated — please sign in again.", "ok");
      setToken("");
      state.me = null;
      clearHealthPollTimer();
      renderAuthState();
      location.hash = "#/login";
    } catch (e) { toast(e.message || e, "err"); }
    });
  }
  const accDeleteSelfBtn = $("#accDeleteSelf", view);
  if (accDeleteSelfBtn) {
    accDeleteSelfBtn.addEventListener("click", async () => {
    if (roleNorm === "superadmin") return;
    const msg = roleNorm === "admin"
      ? "Close this admin tenant permanently? All owned devices will be factory-unclaimed and sub-users deleted."
      : "Delete your account permanently?";
    if (!confirm(msg)) return;
    if (roleNorm === "admin") {
      const ack = $("#accAckTenant", view);
      if (!ack || !ack.checked) {
        toast("Confirm the checklist: devices will be released and sub-users removed.", "err");
        return;
      }
    }
    try {
      const body = {
        password: ($("#accDelPw", view).value || ""),
        confirm_text: ($("#accDelText", view).value || "").trim(),
        acknowledge_admin_tenant_closure: roleNorm === "admin",
      };
      await api("/auth/me/delete", { method: "POST", body });
      toast(roleNorm === "admin" ? "Tenant closed" : "Account deleted", "ok");
      setToken("");
      state.me = null;
      clearHealthPollTimer();
      location.hash = "#/login";
      renderAuthState();
    } catch (e) { toast(e.message || e, "err"); }
    });
  }
});
