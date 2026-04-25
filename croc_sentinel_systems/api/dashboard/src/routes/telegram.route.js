/**
 * Route: #/telegram — Telegram bot link/unlink + test message.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("telegram", async (view) => {
  setCrumb("Telegram");
  if (!hasRole("user")) { mountView(view, `<div class="card"><p class="muted">Sign in required.</p></div>`); return; }
  mountView(view, `
    <div class="ui-shell telegram-shell">
    <div class="card">
      <div class="ui-section-head">
        <div>
          <h2 class="ui-section-title">Telegram connect</h2>
          <p class="ui-section-sub">No password in Telegram. Generate link, open chat, send <span class="mono">/start</span>, done.</p>
        </div>
        <div class="ui-section-actions">
          <button class="btn" id="tgGenLink">Generate connect link</button>
          <button class="btn secondary" id="tgReloadMine">Refresh bindings</button>
        </div>
      </div>
      <div id="tgLinkBox" style="margin-top:10px"></div>
    </div>
    <div class="card">
      <div class="ui-section-head">
        <div>
          <h3 class="ui-section-title">My chat bindings</h3>
          <p class="ui-section-sub">Enable, disable, or unbind your own Telegram chats.</p>
        </div>
      </div>
      <div id="tgMineList"></div>
    </div>
    <div class="card">
      <div class="ui-section-head">
        <div>
          <h3 class="ui-section-title">Manual bind (fallback)</h3>
          <p class="ui-section-sub">If deep link cannot open Telegram, use <span class="mono">/start</span> to get chat_id, then bind manually.</p>
        </div>
      </div>
      <div class="inline-form">
        <label class="field"><span>chat_id</span><input id="tgManualChatId" placeholder="e.g. 2082431201 or -100xxxx" /></label>
        <label class="field"><span>Enabled</span><input id="tgManualEnabled" type="checkbox" checked /></label>
        <div class="row wide" style="justify-content:flex-end"><button class="btn" id="tgManualBind">Bind manually</button></div>
      </div>
    </div>
    </div>
  `);
  const mineEl = $("#tgMineList", view);
  const linkEl = $("#tgLinkBox", view);
  const loadMine = async () => {
    if (!mineEl) return;
    setChildMarkup(mineEl, `<p class="muted">Loading…</p>`);
    try {
      const d = await api("/admin/telegram/bindings", { timeoutMs: 16000 });
      const items = d.items || [];
      setChildMarkup(
        mineEl,
        items.length === 0
          ? `<p class="muted">No bindings yet.</p>`
          : `<div class="table-wrap"><table class="t">
            <thead><tr><th>chat_id</th><th>enabled</th><th>updated</th><th></th><th></th></tr></thead>
            <tbody>${items.map((it) => `
              <tr>
                <td class="mono">${escapeHtml(it.chat_id || "")}</td>
                <td>${it.enabled ? `<span class="badge online">on</span>` : `<span class="badge offline">off</span>`}</td>
                <td>${escapeHtml(fmtTs(it.updated_at || it.created_at))}</td>
                <td><button class="btn sm secondary js-tg-toggle" data-chat="${escapeHtml(String(it.chat_id || ""))}" data-en="${it.enabled ? "1" : "0"}">${it.enabled ? "Disable" : "Enable"}</button></td>
                <td><button class="btn sm danger js-tg-unbind" data-chat="${escapeHtml(String(it.chat_id || ""))}">Unbind</button></td>
              </tr>`).join("")}</tbody>
          </table></div>`,
      );
    } catch (e) {
      setChildMarkup(mineEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  };
  $("#tgGenLink", view).addEventListener("click", async () => {
    if (!linkEl) return;
    try {
      const r = await api("/telegram/link-token", { method: "POST", body: { enabled_on_bind: true } });
      const deep = r.deep_link || "";
      const openChat = r.open_chat_url || "";
      const payload = r.start_payload || "";
      setChildMarkup(
        linkEl,
        deep
          ? `<div class="ui-status-strip">
             <div class="ui-status-item"><div class="k">Step 1</div><div class="v"><a class="btn" href="${escapeHtml(openChat || deep)}" target="_blank" rel="noopener">Open bot chat</a></div></div>
             <div class="ui-status-item"><div class="k">Step 2</div><div class="v"><a class="btn secondary" href="${escapeHtml(deep)}" target="_blank" rel="noopener">Run one-click bind</a></div></div>
           </div>
           <p class="muted mono" style="margin-top:8px">${escapeHtml(deep)}</p>`
          : `<p class="muted">Set <span class="mono">TELEGRAM_BOT_USERNAME</span> on server, then retry.<br/>Fallback: send <span class="mono">/start ${escapeHtml(payload)}</span> in your bot chat.</p>`,
      );
    } catch (e) {
      setChildMarkup(linkEl, `<p class="badge revoked">${escapeHtml(e.message || e)}</p>`);
    }
  });
  $("#tgManualBind", view).addEventListener("click", async () => {
    const chatId = ($("#tgManualChatId", view).value || "").trim();
    const enabled = !!$("#tgManualEnabled", view).checked;
    if (!chatId) { toast("Enter chat_id", "err"); return; }
    try {
      await api("/admin/telegram/bind-self", { method: "POST", body: { chat_id: chatId, enabled } });
      toast("Bound", "ok");
      loadMine();
    } catch (e) { toast(e.message || e, "err"); }
  });
  $("#tgReloadMine", view).addEventListener("click", loadMine);
  mineEl.addEventListener("click", async (ev) => {
    const tgl = ev.target.closest(".js-tg-toggle");
    if (tgl) {
      const chat = tgl.dataset.chat || "";
      const enabled = !(tgl.dataset.en === "1");
      try {
        await api(`/admin/telegram/bindings/${encodeURIComponent(chat)}/enabled?enabled=${enabled ? "true" : "false"}`, { method: "PATCH" });
        toast(enabled ? "Enabled" : "Disabled", "ok");
        loadMine();
      } catch (e) { toast(e.message || e, "err"); }
      return;
    }
    const del = ev.target.closest(".js-tg-unbind");
    if (del) {
      const chat = del.dataset.chat || "";
      if (!chat) return;
      if (!confirm(`Unbind chat ${chat}?`)) return;
      try {
        await api(`/admin/telegram/bindings/${encodeURIComponent(chat)}`, { method: "DELETE" });
        toast("Unbound", "ok");
        loadMine();
      } catch (e) { toast(e.message || e, "err"); }
    }
  });
  loadMine();
});
