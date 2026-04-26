/**
 * App chrome: who-am-I card, sidebar nav, health pills, MQTT dot, theme
 * toggle, mobile drawer + desktop rail collapse logic.
 *
 * Concatenated as raw text by scripts/build-dashboard.mjs after
 * 10-api.shell.js. Layout reads state directly (state.me, state.health,
 * state.mqttConnected) and writes to the live DOM via setHtmlIfChanged /
 * setChildMarkup from src/lib/dom.js (HEADER import).
 */
// ------------------------------------------------------------------ layout
function renderAuthState() {
  if (!state.me) clearHealthPollTimer();
  document.body.dataset.auth = state.me ? "ok" : "none";
  const who = $("#who");
  if (state.me) {
    const u = String(state.me.username || "").trim() || "—";
    const role = String(state.me.role || "").trim() || "—";
    const zt = (state.me.zones || []).map((z) => String(z)).filter(Boolean).join(", ") || "—";
    const initial = (u[0] || "?").toUpperCase();
    const av = String(state.me.avatar_url || "").trim();
    const avatarEl = av
      ? `<div class="who-card__avatar who-card__avatar--photo" aria-hidden="true"><img src="${escapeHtml(av)}" alt="" width="40" height="40" loading="lazy" decoding="async" referrerpolicy="no-referrer" /></div>`
      : `<div class="who-card__avatar" aria-hidden="true">${escapeHtml(initial)}</div>`;
    setChildMarkup(
      who,
      `<div class="who-card" title="${escapeHtml(u)}">` +
        avatarEl +
        `<div class="who-card__body">` +
          `<div class="who-card__name">${escapeHtml(u)}</div>` +
          `<div class="who-card__meta">` +
          `<span class="who-card__role">${escapeHtml(role)}</span>` +
          `<span class="who-card__zones" title="${escapeHtml(zt)}">${escapeHtml(zt)}</span>` +
          `</div>` +
        `</div>` +
      `</div>`,
    );
    const im = who && who.querySelector(".who-card__avatar--photo img");
    if (im) {
      im.addEventListener(
        "error",
        function onAvErr() {
          im.removeEventListener("error", onAvErr);
          const w = im.closest(".who-card__avatar");
          if (w) {
            w.classList.remove("who-card__avatar--photo");
            w.textContent = initial;
          }
        },
        { once: true },
      );
    }
    if (who) {
      who.className = "who who--authed";
      who.setAttribute("role", "group");
      who.setAttribute("aria-label", "Account");
    }
  } else {
    if (who) {
      who.className = "who who--guest";
      who.textContent = "Signed out";
      who.removeAttribute("role");
      who.removeAttribute("aria-label");
      who.removeAttribute("title");
    }
  }
  renderNav();
  renderHealthPills();
  try { applySidebarRail(); } catch (_) {}
}

function renderNav() {
  const nav = $("#nav");
  if (!nav) return;
  if (!state.me) { setHtmlIfChanged(nav, ""); return; }
  const hash = location.hash || "#/overview";
  const hashNoQuery = hash.split("?")[0];
  const coreParts = [];
  for (const g of NAV_GROUPS) {
    const items = g.items.filter((n) => hasRole(n.min));
    if (items.length === 0) continue;
    coreParts.push(`<div class="nav-section">${escapeHtml(g.title)}</div>`);
    for (const n of items) {
      const active = (n.path === "#/devices"
        // Highlight "All devices" on both the list and any device detail
        // (#/devices/:id) so mobile users keep their place in the nav.
        ? (hashNoQuery === "#/devices" || hashNoQuery.startsWith("#/devices/"))
        : n.path === "#/site"
          ? hashNoQuery === "#/site"
          : hash.startsWith(n.path))
        ? ` aria-current="page"`
        : "";
      coreParts.push(
        `<a href="${n.path}"${active} title="${escapeHtml(n.label)}"><span class="nav-ico" aria-hidden="true">${n.ico}</span><span class="nav-label">${escapeHtml(n.label)}</span></a>`,
      );
    }
  }
  setHtmlIfChanged(nav, `<div class="nav-core">${coreParts.join("")}</div>`);
}

function renderHealthPills() {
  const el = $("#healthPills");
  if (!el) return;
  if (!state.me || !state.health) {
    setHtmlIfChanged(el, "");
    return;
  }
  const sm = state.health.smtp || {};
  const tg = state.health.telegram || {};
  const mailOk = !!sm.configured && !!sm.worker_running;
  const tgOn = !!tg.enabled;
  const tgOk = tgOn && !!tg.worker_running;
  const tgErr = String(tg.last_error || "").trim();
  const mqConn = !!state.health.mqtt_connected;
  const mqQ = Number(state.health.mqtt_ingest_queue_depth || 0);
  const mqDrop = Number(state.health.mqtt_ingest_dropped || 0);
  const mqLastUp = String(state.health.mqtt_last_connect_at || "");
  const mqLastDown = String(state.health.mqtt_last_disconnect_at || "");
  const mqLastReason = String(state.health.mqtt_last_disconnect_reason || "");
  const mailTitle = sm.configured
    ? (mailOk ? "Mail worker running — verification email can be sent" : "Mail channel configured but worker not running — check API logs")
    : "Mail channel not configured on server";
  const tgTitle = tgOn
    ? (tgOk
      ? (tgErr ? `Telegram worker up — last API error: ${tgErr}` : "Telegram worker running — events at min_level+ are queued")
      : "Telegram enabled but worker not running — check API logs")
    : "Telegram disabled — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS (numeric chat id; start a chat with the bot first)";
  const mqttTitle = mqConn
    ? (mqDrop > 0
      ? `MQTT connected, but ingest dropped ${mqDrop} message(s); queue depth=${mqQ}. last_up=${mqLastUp ? fmtTs(mqLastUp) : "—"}`
      : `MQTT connected; ingest queue depth=${mqQ}. last_up=${mqLastUp ? fmtTs(mqLastUp) : "—"}`)
    : `MQTT disconnected — check broker/TLS/network. last_down=${mqLastDown ? fmtTs(mqLastDown) : "—"} reason=${mqLastReason || "—"}`;
  setHtmlIfChanged(el, `
    <span class="health-pill ${mqConn ? (mqDrop > 0 ? "warn" : "ok") : "off"}" title="${escapeHtml(mqttTitle)}">MQTT</span>
    <span class="health-pill ${mailOk ? "ok" : sm.configured ? "warn" : "off"}" title="${escapeHtml(mailTitle)}">MAIL</span>
    <span class="health-pill ${tgOk ? "ok" : tgOn ? "warn" : "off"}" title="${escapeHtml(tgTitle)}">TG</span>`);
}

function renderMqttDot() {
  const dot = $("#mqttDot");
  if (!dot) return;
  dot.className = "dot-status " + (state.mqttConnected ? "ok" : "bad");
  dot.title = state.mqttConnected ? "MQTT up" : "MQTT down";
}

function setCrumb(text) { const el = $("#crumb"); if (el) el.textContent = text; }

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem(LS.theme, t);
}

function initTheme() {
  const saved = localStorage.getItem(LS.theme);
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  setTheme(saved || (prefersDark ? "dark" : "light"));
}

function toggleNav(open) {
  if (open == null) open = document.body.dataset.nav !== "open";
  document.body.dataset.nav = open ? "open" : "";
  // Keep backdrop visibility in sync with nav state across desktop/mobile.
  const bd = document.getElementById("sidebarBackdrop");
  if (!bd) return;
  const mobile = !!(window.matchMedia && window.matchMedia("(max-width: 900px)").matches);
  const show = !!open && mobile;
  if (show) {
    bd.removeAttribute("hidden");
    bd.style.display = "";
  } else {
    bd.setAttribute("hidden", "");
    bd.style.display = "none";
  }
}

function applySidebarRail() {
  const m = window.matchMedia && window.matchMedia("(min-width: 901px)");
  if (!m || !m.matches) {
    try { document.body.removeAttribute("data-sidebar"); } catch (_) {}
  } else {
    try {
      const c = localStorage.getItem(LS.sidebarCollapsed) === "1";
      if (c) document.body.setAttribute("data-sidebar", "collapsed");
      else document.body.removeAttribute("data-sidebar");
    } catch (_) {
      try { document.body.removeAttribute("data-sidebar"); } catch (_) {}
    }
  }
  const btn = document.getElementById("sidebarRailToggle");
  if (btn) {
    const isCol = document.body.getAttribute("data-sidebar") === "collapsed";
    btn.setAttribute("aria-label", isCol ? "Expand sidebar" : "Collapse sidebar");
    btn.setAttribute("aria-expanded", isCol ? "false" : "true");
    btn.setAttribute("title", isCol ? "Expand sidebar" : "Collapse sidebar");
    const svgL = "<svg class=\"sidebar-rail-toggle__icon\" viewBox=\"0 0 24 24\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M15 6l-6 6 6 6\"/></svg>";
    const svgR = "<svg class=\"sidebar-rail-toggle__icon\" viewBox=\"0 0 24 24\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M9 6l6 6-6 6\"/></svg>";
    btn.innerHTML = isCol ? svgR : svgL;
  }
}

function toggleSidebarRail() {
  if (!window.matchMedia("(min-width: 901px)").matches) return;
  const cur = localStorage.getItem(LS.sidebarCollapsed) === "1";
  try { localStorage.setItem(LS.sidebarCollapsed, cur ? "0" : "1"); } catch (_) {}
  applySidebarRail();
}

/** Collapse drawer when viewport is desktop width (e.g. rotate phone / resize). */
function syncNavForViewport() {
  try {
    if (window.matchMedia && window.matchMedia("(min-width: 901px)").matches) toggleNav(false);
  } catch (_) {}
  try { applySidebarRail(); } catch (_) {}
}
