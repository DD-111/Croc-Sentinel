/**
 * Route: #/events — Live events stream (SSE) + filters.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("events", async (view, _args) => {
  const navTok = state.routeSeq;
  setCrumb("Events");
  const me = state.me || { username: "", role: "" };
  const isSuper = me.role === "superadmin";
  const scopeLabel = isSuper ? "System-wide" : (me.role === "admin" ? "Your tenant" : "Your account");

  mountView(view, `
    <div class="ui-shell card audit-page" style="margin:0">
      <div class="row between" style="flex-wrap:wrap;gap:10px">
        <div>
          <h2 class="ui-section-title" style="margin:0">Event center</h2>
          <p class="muted" style="margin:4px 0 0">Visibility: ${scopeLabel}.</p>
        </div>
        <div class="row" style="gap:8px;align-items:center">
          <span id="evLive" class="badge offline" title="Live stream">Offline</span>
          <button class="btn sm secondary" id="evPause">Pause</button>
          <button class="btn sm secondary" id="evClear">Clear</button>
        </div>
      </div>
      <div class="divider"></div>
      <div class="inline-form" style="margin-bottom:10px">
        <label class="field"><span>Min level</span>
          <select id="evLevel">
            <option value="">All</option>
            <option value="debug">debug+</option>
            <option value="info" selected>info+</option>
            <option value="warn">warn+</option>
            <option value="error">error+</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label class="field"><span>Category</span>
          <select id="evCategory">
            <option value="">All</option>
            <option value="alarm">alarm</option>
            <option value="ota">ota</option>
            <option value="presence">presence</option>
            <option value="provision">provision</option>
            <option value="device">device</option>
            <option value="auth">auth</option>
            <option value="audit">audit</option>
            <option value="system">system</option>
          </select>
        </label>
        <label class="field"><span>Device ID</span><input id="evDevice" placeholder="SN-… or id" /></label>
        <label class="field wide"><span>Search</span><input id="evQ" placeholder="summary / actor / event_type" /></label>
        <div class="row wide action-bar" style="justify-content:flex-end;gap:8px;flex-wrap:wrap">
          <button class="btn sm" id="evApply">Apply & reload</button>
          <details class="toolbar-collapse" style="min-width:160px">
            <summary>More tools</summary>
            <div class="table-actions">
              <button class="btn sm secondary" id="evStats">By device (7d)</button>
              <button class="btn sm secondary" id="evCsv">Export CSV</button>
              <button class="btn sm secondary" id="evReload">Last 200</button>
            </div>
          </details>
        </div>
      </div>
    </div>
    <div id="evStatsBox" class="card" style="margin-top:12px;display:none">
      <h3 style="margin:0 0 8px">Events per device (7 days)</h3>
      <div id="evStatsInner" class="muted">—</div>
    </div>
    <div class="ui-shell card audit-page" style="margin-top:12px">
      <div id="evList" class="audit-feed-wrap muted">Connecting…</div>
    </div>`);

  let paused = false;
  let buffer = [];  // newest first
  const BUFFER_MAX = 180;
  const RENDER_LIMIT = 150;
  let evRenderTimer = 0;
  let evReconnectBackoffMs = 800;

  function badgeClass(lvl) {
    return ({
      debug: "neutral", info: "accent", warn: "partial",
      error: "failed", critical: "revoked",
    })[lvl] || "neutral";
  }
  function catClass(cat) {
    return ({
      alarm: "failed", ota: "accent", presence: "partial",
      provision: "accent", device: "neutral", auth: "partial",
      audit: "neutral", system: "neutral",
    })[cat] || "neutral";
  }
  function rowHtml(e) {
    const primary = (e.summary && String(e.summary).trim()) || (e.event_type || "—");
    const tsShort = fmtTs(e.ts_malaysia || e.ts);
    const typeDiffers = e.event_type && String(e.event_type) !== String(primary);
    const extras = eventDetailDedupedRows(
      (e.detail && typeof e.detail === "object" && !Array.isArray(e.detail)) ? e.detail : {},
      e,
    );
    const devLink = e.device_id
      ? `<a class="mono audit-target" href="#/devices/${encodeURIComponent(e.device_id)}">${escapeHtml(e.device_id)}</a>`
      : "";
    const targetStr = (e.target && e.target !== e.device_id) ? String(e.target) : "";
    const typeTag = typeDiffers
      ? ` · <span class="mono" style="font-size:12px;opacity:0.88">${escapeHtml(e.event_type)}</span>`
      : "";
    const extraBlock = extras.length
      ? `<div class="audit-extra">${extras.map((row) =>
          `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`,
      ).join("")}</div>`
      : "";
    return `<details class="audit-item audit-item--foldable" data-level="${escapeHtml(e.level || "")}">
      <summary class="audit-item__fold-sum">
      <div class="audit-item-top">
        <div class="audit-time">
          <span class="audit-ts mono">${escapeHtml(tsShort)}</span>
          <span class="muted audit-rel">${escapeHtml(fmtRel(e.ts))}</span>
        </div>
        <span class="badge ${badgeClass(e.level)}">${escapeHtml(e.level || "")}</span>
        <span class="badge ${catClass(e.category)}">${escapeHtml(e.category || "")}</span>
      </div>
      <div class="audit-item-line audit-item__fold-primary" style="font-weight:600;margin-top:8px">${escapeHtml(primary)}${typeTag}</div>
      </summary>
      <div class="audit-item__fold-body">
      <div class="audit-item-line" style="font-size:12.5px;flex-wrap:wrap">
        <span class="audit-actor">${e.actor ? escapeHtml(e.actor) : "—"}</span>
        ${targetStr ? ` <span class="audit-arrow">→</span> <span class="mono audit-target">${escapeHtml(targetStr)}</span>` : ""}
        ${devLink ? ` · ${devLink}` : ""}
        ${e.owner_admin ? ` <span class="chip" title="owner_admin">@${escapeHtml(e.owner_admin)}</span>` : ""}
      </div>
      ${extraBlock}
      </div>
    </details>`;
  }
  function flushEvRender() {
    evRenderTimer = 0;
    const listEl = document.getElementById("evList");
    if (!listEl) return;
    if (buffer.length === 0) {
      setHtmlIfChanged(listEl, `<p class="muted audit-empty">No events.</p>`);
      return;
    }
    const visible = buffer.slice(0, RENDER_LIMIT);
    setHtmlIfChanged(listEl, `<div class="audit-feed">${visible.map(rowHtml).join("")}</div>`);
  }
  function scheduleEvRender() {
    if (evRenderTimer) return;
    evRenderTimer = setTimeout(flushEvRender, 120);
  }
  function pushEvent(ev) {
    if (paused) return;
    let row = ev;
    try {
      if (ev && ev.detail != null && typeof ev.detail === "object") {
        const sj = JSON.stringify(ev.detail);
        if (sj.length > 12000) {
          row = Object.assign({}, ev, {
            detail: { _truncated: true, _approx_bytes: sj.length },
          });
        }
      }
    } catch (_) {}
    buffer.unshift(row);
    if (buffer.length > BUFFER_MAX) buffer.length = BUFFER_MAX;
    scheduleEvRender();
  }
  function currentFilters() {
    const p = new URLSearchParams();
    const lvl = $("#evLevel").value.trim(); if (lvl) p.set("min_level", lvl);
    const cat = $("#evCategory").value.trim(); if (cat) p.set("category", cat);
    const dev = $("#evDevice").value.trim(); if (dev) p.set("device_id", dev);
    const q = $("#evQ").value.trim(); if (q) p.set("q", q);
    return p;
  }

  async function loadHistory() {
    try {
      if (!isRouteCurrent(navTok)) return;
      const p = currentFilters(); p.set("limit", "200");
      const r = await api("/events?" + p.toString(), { timeoutMs: 16000 });
      if (!isRouteCurrent(navTok)) return;
      buffer = (r.items || []).slice();
      if (buffer.length > BUFFER_MAX) buffer = buffer.slice(0, BUFFER_MAX);
      if (evRenderTimer) { clearTimeout(evRenderTimer); evRenderTimer = 0; }
      flushEvRender();
    } catch (e) {
      if (!isRouteCurrent(navTok)) return;
      const listEl = document.getElementById("evList");
      if (listEl) mountView(listEl, hx`<p class="badge offline">${e.message || e}</p>`);
      toast(e.message || e, "err");
    }
  }

  function closeStream() {
    if (window.__evReconnectTimer) {
      try { clearTimeout(window.__evReconnectTimer); } catch (_) {}
      window.__evReconnectTimer = 0;
    }
    if (window.__evSSE) {
      try { window.__evSSE.close(); } catch (_) {}
      window.__evSSE = null;
    }
    if (window.__evFetchAbort) {
      try { window.__evFetchAbort.abort(); } catch (_) {}
      window.__evFetchAbort = null;
    }
    const live = $("#evLive");
    if (live) { live.textContent = "Offline"; live.className = "badge offline"; }
  }
  /**
   * Live events: use fetch() + ReadableStream instead of EventSource so we can send
   * Authorization (JWT never appears in URL query — fewer proxy/logging issues).
   * Server still emits ping keepalives for buffered proxies.
   */
  function openStream() {
    if (!isRouteCurrent(navTok)) return;
    closeStream();
    const p = currentFilters();
    const slack = Math.max(0, BUFFER_MAX - buffer.length);
    p.set("backlog", String(Math.min(100, slack)));
    const qs = p.toString();
    const tok = getToken();
    const ac = new AbortController();
    window.__evFetchAbort = ac;
    const shim = {
      readyState: EventSource.CONNECTING,
      close() {
        try { ac.abort(); } catch (_) {}
        window.__evFetchAbort = null;
        this.readyState = EventSource.CLOSED;
      },
    };
    window.__evSSE = shim;

    const scheduleReconnect = () => {
      if (!isRouteCurrent(navTok) || paused || window.__evReconnectTimer) return;
      const wait = evReconnectBackoffMs + Math.floor(Math.random() * 480);
      window.__evReconnectTimer = setTimeout(() => {
        window.__evReconnectTimer = 0;
        if (!isRouteCurrent(navTok) || paused) return;
        openStream();
      }, wait);
      evReconnectBackoffMs = Math.min(8000, Math.floor(evReconnectBackoffMs * 1.5));
    };

    const run = async () => {
      const url = apiBase() + "/events/stream" + (qs ? "?" + qs : "");
      const hdrs = {
        Accept: "text/event-stream",
        "Cache-Control": "no-store",
      };
      if (tok) hdrs.Authorization = "Bearer " + tok;
      try {
        const r = await fetch(url, {
          method: "GET",
          credentials: "include",
          headers: hdrs,
          signal: ac.signal,
        });
        if (!isRouteCurrent(navTok)) return;
        if (!r.ok) {
          const errText = await r.text().catch(() => "");
          throw new Error(errText || String(r.status));
        }
        if (!r.body || typeof r.body.getReader !== "function") {
          throw new Error("Event stream unsupported in this browser");
        }
        evReconnectBackoffMs = 800;
        shim.readyState = EventSource.OPEN;
        const liveOn = $("#evLive");
        if (liveOn) {
          liveOn.textContent = "Live";
          liveOn.className = "badge online";
          liveOn.title = "Live stream connected";
        }
        await pumpSseBody(r.body.getReader(), ac.signal, (kind, payload) => {
          if (kind === "ping") return;
          if (!isRouteCurrent(navTok)) return;
          try {
            const ev = JSON.parse(payload);
            if (ev.event_type === "stream.hello") return;
            pushEvent(ev);
          } catch (_) {}
        });
        if (ac.signal.aborted || !isRouteCurrent(navTok)) return;
        shim.readyState = EventSource.CLOSED;
        if (!paused && isRouteCurrent(navTok)) {
          evReconnectBackoffMs = 800;
          const live = $("#evLive");
          if (live) {
            live.textContent = "Reconnecting…";
            live.className = "badge offline";
          }
          scheduleReconnect();
        }
      } catch (e) {
        if (e && e.name === "AbortError") return;
        if (!isRouteCurrent(navTok)) return;
        shim.readyState = EventSource.CLOSED;
        const live = $("#evLive");
        if (live && isRouteCurrent(navTok)) {
          live.textContent = "Reconnecting…";
          live.className = "badge offline";
        }
        if (!paused && isRouteCurrent(navTok)) scheduleReconnect();
      }
    };
    void run();
  }

  $("#evPause").addEventListener("click", () => {
    paused = !paused;
    $("#evPause").textContent = paused ? "Resume" : "Pause";
  });
  $("#evClear").addEventListener("click", () => {
    buffer = [];
    if (evRenderTimer) { clearTimeout(evRenderTimer); evRenderTimer = 0; }
    flushEvRender();
  });
  $("#evApply").addEventListener("click", () => { loadHistory().then(openStream); });
  $("#evReload").addEventListener("click", loadHistory);
  $("#evStats").addEventListener("click", async () => {
    try {
      if (!isRouteCurrent(navTok)) return;
      const r = await api("/events/stats/by-device?hours=168&limit=200", { timeoutMs: 16000 });
      const items = r.items || [];
      const evStatsBoxEl = $("#evStatsBox", view);
      const evStatsInnerEl = $("#evStatsInner", view);
      if (!evStatsBoxEl || !evStatsInnerEl || !isRouteCurrent(navTok)) return;
      evStatsBoxEl.style.display = "block";
      if (items.length === 0) {
        setChildMarkup(evStatsInnerEl, "<p class='muted'>No rows with device_id.</p>");
        return;
      }
      setChildMarkup(
        evStatsInnerEl,
        `<div class="table-wrap"><table class="t"><thead><tr><th>Device</th><th>Count</th></tr></thead><tbody>${
          items.map((x) => `<tr><td class="mono">${escapeHtml(x.device_id)}</td><td>${x.count}</td></tr>`).join("")
        }</tbody></table></div>`,
      );
    } catch (e) { toast(e.message || e, "err"); }
  });
  $("#evCsv").addEventListener("click", async () => {
    try {
      const p = currentFilters();
      p.set("limit", "8000");
      const url = apiBase() + "/events/export.csv?" + p.toString();
      const _ex = {};
      const _t = getToken();
      if (_t) _ex.Authorization = "Bearer " + _t;
      const r = await fetch(url, { credentials: "include", headers: _ex });
      if (!r.ok) {
        const t = await r.text();
        throw new Error(t || r.statusText);
      }
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "croc_sentinel_events.csv";
      a.click();
      URL.revokeObjectURL(a.href);
      toast("CSV downloaded", "ok");
    } catch (e) { toast(e.message || e, "err"); }
  });

  await loadHistory();
  openStream();
  window.__eventsStreamResume = () => {
    if (paused) return;
    if (!isRouteCurrent(navTok)) return;
    openStream();
  };
});
