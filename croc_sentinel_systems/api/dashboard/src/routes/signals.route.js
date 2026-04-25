/**
 * Route: #/signals — Signal log — device alarms + dashboard/API remote siren.
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

// Unified: device alarms + dashboard/API remote siren (who / what / when / where / fan-out)
async function renderSignalsPage(view, _args, routeSeq) {
  setCrumb("Signals");
  mountView(view, `
    <div class="card">
      <div class="row" style="flex-wrap:wrap;align-items:flex-end;gap:12px">
        <div style="flex:1;min-width:200px">
          <h2 style="margin:0">Signal log</h2>
          <p class="muted" style="margin:6px 0 0">Device alarms and dashboard/API siren events. Group comes from device notification settings.</p>
        </div>
        <label class="field" style="max-width:140px;margin:0"><span>Hours</span><input id="sig_hours" type="number" value="168" min="1" max="720"/></label>
        <button class="btn secondary btn-tap" id="sig_reload">Refresh</button>
      </div>
      <div class="divider"></div>
      <div class="stats" id="sigSummary"></div>
      <div class="divider"></div>
      <div id="sigList"><p class="muted">Loading…</p></div>
    </div>`);
  const reload = async () => {
    const hours = parseInt($("#sig_hours").value, 10) || 168;
    const qs = new URLSearchParams({ limit: "200", since_hours: String(hours) });
    try {
      if (!isRouteCurrent(routeSeq)) return;
      const [d, sumR] = await Promise.all([
        api("/activity/signals?" + qs.toString(), { timeoutMs: 24000 }),
        api("/alarms/summary", { timeoutMs: 16000 }).catch(() => ({ last_24h: 0, last_7d: 0, top_sources_7d: [] })),
      ]);
      if (!isRouteCurrent(routeSeq)) return;
      const sigSummaryEl = $("#sigSummary", view);
      const sigListEl = $("#sigList", view);
      if (!sigSummaryEl || !sigListEl) return;
      setHtmlIfChanged(sigSummaryEl, [
        ["Alarms 24h", sumR.last_24h || 0, "device-side alarm rows"],
        ["Alarms 7d", sumR.last_7d || 0, "same scope"],
        ["Top source 7d", (sumR.top_sources_7d || []).slice(0, 1).map((x) => `${x.source_id} × ${x.c}`).join("") || "—", "by count"],
      ].map(([k, v, s]) => `<div class="stat"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div><div class="sub">${escapeHtml(s)}</div></div>`).join(""));
      const items = d.items || [];
      const whoLbl = (w) => ({
        remote_button: "GPIO / local button",
        network: "MQTT / network",
        api: "API / automation",
      }[w] || w);
      setHtmlIfChanged(sigListEl, items.length === 0
        ? `<p class="muted audit-empty">No rows in this window.</p>`
        : `<div class="audit-feed">${items.map((a) => {
          const dev = a.device_id === "*" ? "(bulk)" : a.device_id;
          const link = a.device_id && a.device_id !== "*"
            ? `<a class="mono audit-target" href="#/devices/${encodeURIComponent(a.device_id)}">${escapeHtml(dev)}</a>`
            : escapeHtml(dev);
          const em = a.email_sent ? "queued" : (a.email_detail || "—");
          const fo = a.kind && a.kind.startsWith("bulk") ? String(a.fanout_count || 0) : String(a.fanout_count ?? "—");
          const whoS = a.kind === "device_alarm" ? whoLbl(a.who) : (a.who || "—");
          const tShort = fmtTs(a.ts);
          return `<article class="audit-item">
            <div class="audit-item-top">
              <div class="audit-time">
                <span class="audit-ts mono">${escapeHtml(tShort)}</span>
                <span class="muted audit-rel">${escapeHtml(fmtRel(a.ts))}</span>
              </div>
              <span class="chip">${escapeHtml(a.what || a.kind || "")}</span>
              <span class="chip">${escapeHtml(a.zone || "all")}</span>
            </div>
            <div class="audit-item-line" style="flex-wrap:wrap;align-items:center;gap:6px">
              <span class="mono">${link}</span>
              <span class="chip">${escapeHtml(a.display_label || "—")}</span>
              <span class="chip">${escapeHtml(a.notification_group || "—")}</span>
            </div>
            <div class="audit-item-line muted" style="font-size:12.5px">Who: ${escapeHtml(String(whoS))} · Fan-out: ${escapeHtml(fo)} · Email: ${escapeHtml(em)}</div>
          </article>`;
        }).join("")}</div>`);
    } catch (e) {
      if (!isRouteCurrent(routeSeq)) return;
      toast(e.message || e, "err");
    }
  };
  $("#sig_reload").addEventListener("click", reload);
  reload();
  scheduleRouteTicker(routeSeq, "signals-live-reload", reload, 10000);
}
registerRoute("signals", renderSignalsPage);
