/**
 * Route: #/audit — Audit log viewer (per-tenant).
 *
 * Build: split out of src/console.raw.js and concatenated as raw text by
 * scripts/build-dashboard.mjs after the monolith body. Shares scope with
 * helpers like $, mountView, api, registerRoute, state, toast, can, setCrumb
 * (defined in console.raw.js and the lib/ modules spliced at the top).
 */

registerRoute("audit", async (view, _args, routeSeq) => {
  setCrumb("Audit");
  if (!hasRole("admin")) { mountView(view, `<div class="card"><p class="muted">Admins only.</p></div>`); return; }
  mountView(view, `
    <div class="ui-shell card audit-page">
      <div class="ui-section-head">
        <div>
          <h2 class="ui-section-title">Audit</h2>
          <p class="ui-section-sub">Who did what, when — extra fields only when they add information beyond actor / target.</p>
        </div>
        <div class="ui-section-actions audit-filters">
          <label class="field compact"><span>Actor</span><input id="f_actor" type="search" autocomplete="off" placeholder="username" /></label>
          <label class="field compact"><span>Action</span><input id="f_action" type="search" autocomplete="off" placeholder="prefix e.g. provision" /></label>
          <label class="field compact"><span>Target</span><input id="f_target" type="search" autocomplete="off" placeholder="device or user" /></label>
          <button class="btn secondary btn-tap" id="f_reload" type="button">Apply</button>
        </div>
      </div>
      <div class="ui-status-strip" id="auditStrip">
        <span class="ui-status-item"><strong id="auditCount">—</strong> entries</span>
        <span class="ui-status-item muted">Newest first · max 200</span>
      </div>
      <div class="divider"></div>
      <div id="auditList" class="audit-feed-wrap"><p class="muted">Loading…</p></div>
    </div>`);

  const reload = async () => {
    const qs = new URLSearchParams();
    const elA = $("#f_actor", view);
    const elAc = $("#f_action", view);
    const elT = $("#f_target", view);
    const a = (elA && elA.value ? String(elA.value) : "").trim();
    const ac = (elAc && elAc.value ? String(elAc.value) : "").trim();
    const t = (elT && elT.value ? String(elT.value) : "").trim();
    if (a) qs.set("actor", a);
    if (ac) qs.set("action", ac);
    if (t) qs.set("target", t);
    qs.set("limit", "200");
    let d;
    try {
      d = await api("/audit?" + qs.toString(), { timeoutMs: 24000 });
    } catch (e) {
      toast(e.message || e, "err");
      return;
    }
    if (!isRouteCurrent(routeSeq)) return;
    const items = d.items || [];
    const auditListEl = $("#auditList", view);
    const countEl = $("#auditCount", view);
    if (!auditListEl) return;
    if (countEl) setTextIfChanged(countEl, String(items.length));

    if (items.length === 0) {
      setHtmlIfChanged(auditListEl, `<p class="muted audit-empty">No matching entries.</p>`);
      return;
    }

    setHtmlIfChanged(auditListEl, `<div class="audit-feed">${items.map((e) => {
      const actor = e.actor || "";
      const tgt = e.target || "";
      const action = e.action || "";
      const extras = auditDetailDedupedRows(e.detail || {}, actor, tgt);
      const extrasHtml = extras.length
        ? `<div class="audit-extra">${extras.map((row) =>
            `<div class="audit-extra-row"><span class="audit-k">${escapeHtml(row.k)}</span><span class="audit-v mono">${escapeHtml(row.v)}</span></div>`,
          ).join("")}</div>`
        : "";
      const tgtHtml = tgt
        ? `<span class="audit-target mono" title="target">${escapeHtml(tgt)}</span>`
        : `<span class="muted">—</span>`;
      return `
        <article class="audit-item">
          <div class="audit-item-top">
            <div class="audit-time">
              <span class="audit-ts">${escapeHtml(fmtTs(e.created_at))}</span>
              <span class="muted audit-rel">${escapeHtml(fmtRel(e.created_at))}</span>
            </div>
            <span class="audit-action-chip ${auditChipClass(action)}" title="${escapeHtml(action)}">${escapeHtml(action)}</span>
          </div>
          <div class="audit-item-line">
            <span class="audit-actor">${escapeHtml(actor)}</span>
            <span class="audit-arrow" aria-hidden="true">→</span>
            ${tgtHtml}
          </div>
          ${extrasHtml}
        </article>`;
    }).join("")}</div>`);
  };

  const onFilterKey = (ev) => {
    if (ev.key === "Enter") reload();
  };
  $("#f_reload", view).addEventListener("click", reload);
  const fa = $("#f_actor", view);
  const fac = $("#f_action", view);
  const ft = $("#f_target", view);
  if (fa) fa.addEventListener("keydown", onFilterKey);
  if (fac) fac.addEventListener("keydown", onFilterKey);
  if (ft) ft.addEventListener("keydown", onFilterKey);
  reload();
  scheduleRouteTicker(routeSeq, "audit-live-reload", reload, 12000);
});
