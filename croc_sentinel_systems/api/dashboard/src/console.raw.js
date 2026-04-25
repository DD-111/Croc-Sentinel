/* Croc Sentinel Console - SPA
 * Markup safety: escapeHtml(str) or hx`...${str}...` for any API/user text; mountView(el, html) for route shells (DOMParser + replaceChildren, no innerHTML).
 * Live stream: Events use fetch()+stream+Authorization (not EventSource URL+?token=) for reverse-proxy reliability. */
(function () {
  "use strict";

  // LS / OFFLINE_MS / DEFAULT_REMOTE_SIREN_MS / DEFAULT_PANIC_FANOUT_MS /
  // NAV_GROUPS / ROLE_WEIGHT / one-time JWT migration → src/lib/constants.js.

  // authSiteFooterHtml / authAsideHtml → src/lib/auth-chrome.js
  // (imported by build-dashboard.mjs HEADER).

  // state object + group-meta storage + lifecycle timers (route redirect /
  // health poll / events live badge) → src/shell/00-state.shell.js.

  // ------------------------------------------------------------------ utils
  // $ / $$ → src/lib/dom.js.

  // apiBase / fetchWithDeadline / _sleep / _isTransientFetchError /
  // _isRetryableHttpStatus / DEFAULT_API_TIMEOUT_MS / ROUTE_RENDER_TIMEOUT_MS
  // → src/lib/api.js (imported by build-dashboard.mjs HEADER).

  function getToken() { return localStorage.getItem(LS.token) || ""; }
  function setToken(t) {
    t ? localStorage.setItem(LS.token, t) : localStorage.removeItem(LS.token);
    if (!t) {
      _groupMetaSyncChain = Promise.resolve();
    }
  }

  // ------------------------------------------------------------------ csrf
  // CSRF_COOKIE_NAME / CSRF_HEADER_NAME / _readCsrfCookie / getCsrfToken /
  // setCsrfToken / refreshCsrfToken / _isCsrfRejection → src/lib/csrf.js.
  // _isWriteMethod (HTTP method classifier) → src/lib/api.js.

  // escapeHtml / parseHtmlToFragment / setChildMarkup / prependChildMarkup /
  // appendChildMarkup / setHtmlIfChanged / setTextIfChanged / hx / mountView
  // → src/lib/dom.js.

  // parseSseFields / SSE_PARSE_BUF_MAX / pumpSseBody → src/lib/sse.js.

  // MY_TZ / MY_OFFSET_HINT / fmtTs / fmtRel / maskPlatform / auditActionPrefix /
  // auditDetailDedupedRows / eventDetailDedupedRows / messagePayloadRows /
  // auditChipClass → src/lib/format.js.

  function roleWeight(r) { return ROLE_WEIGHT[r] || 0; }
  function hasRole(min) { return state.me && roleWeight(state.me.role) >= roleWeight(min); }
  function can(cap) { return !!(state.me && state.me.policy && state.me.policy[cap]); }
  function isOnline(d) {
    if (typeof d.is_online === "boolean") return d.is_online;
    return Date.now() - Date.parse(d.updated_at || 0) < OFFLINE_MS;
  }

  function toast(msg, kind) {
    const el = $("#toast");
    if (!el) return;
    el.textContent = String(msg);
    el.className = "toast show " + (kind || "");
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.className = "toast"; }, 3200);
  }

  // api / apiOr / apiGetCached / FW hint dialog / login / loadMe / loadHealth
  // and the group apply/delete + share matrix helpers →
  // src/shell/10-api.shell.js.

  // renderAuthState / renderNav / renderHealthPills / renderMqttDot /
  // setCrumb / setTheme / initTheme / toggleNav / applySidebarRail /
  // toggleSidebarRail / syncNavForViewport → src/shell/20-layout.shell.js.

  // registerRoute / renderRoute / clearRouteTickers / scheduleRouteTicker /
  // hashchange listener → src/shell/30-router.shell.js.

  // ------------------------------------------------------------------ pages
  //
  // Auth pages have been peeled off into src/routes/*.route.js (concatenated
  // back into this same scope by scripts/build-dashboard.mjs):
  //   • login.route.js              (#/login)
  //   • forgot-password.route.js    (#/forgot-password)
  //   • register.route.js           (#/register)
  //   • account-activate.route.js   (#/account-activate)
  //
  // Adding more routes? Drop a `<id>.route.js` in src/routes/ that calls
  // `registerRoute("<id>", async (view, args, routeSeq) => {...})` at the top
  // level — do NOT use ES `import`/`export`, the file is concatenated as raw
  // text so it shares scope with this monolith. See src/README.md.

  // route "account" extracted to src/routes/account.route.js

  // Overview
  // route "overview" extracted to src/routes/overview.route.js

  // route "site" extracted to src/routes/site.route.js

  // route "group" extracted to src/routes/group.route.js

  // Device list (no id) + device detail
  // route "devices" extracted to src/routes/devices.route.js

  // Bulk siren — extracted to src/routes/alerts.route.js.

  // Activate
  // route "activate" extracted to src/routes/activate.route.js

  // Event Center — global live + historical log stream
  // NOTE: Active stream lives on window.__evSSE (fetch shim); renderRoute closes it on navigation.
  // navTok: capture state.routeSeq up front so nested async (loadHistory, openStream) always see a
  // defined token even if a minifier / bad edit drops the 3rd handler param (avoids "routeSeq is not defined").
  // route "events" extracted to src/routes/events.route.js

  // Telegram self-service (user/admin/superadmin)
  // route "telegram" extracted to src/routes/telegram.route.js

  // Audit
  // route "audit" extracted to src/routes/audit.route.js

  // Admin
  // route "admin" extracted to src/routes/admin.route.js

  // route "signals" extracted to src/routes/signals.route.js

  // route "ota" extracted to src/routes/ota.route.js

  // ------------------------------------------------------------------ boot
  async function boot() {
    initTheme();

    $("#menuBtn").addEventListener("click", () => toggleNav());
    $("#sidebarBackdrop").addEventListener("click", () => toggleNav(false));
    const railT = document.getElementById("sidebarRailToggle");
    if (railT) railT.addEventListener("click", () => toggleSidebarRail());
    window.addEventListener("resize", syncNavForViewport);
    window.addEventListener("orientationchange", syncNavForViewport);
    $("#themeBtn").addEventListener("click", () => {
      setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    $("#logoutBtn").addEventListener("click", async () => {
      try {
        await fetchWithDeadline(apiBase() + "/auth/logout", { method: "POST" }, 12000);
      } catch (_) {}
      setToken("");
      state.me = null;
      clearHealthPollTimer();
      location.hash = "#/login";
      renderAuthState();
    });
    $("#refreshBtn").addEventListener("click", () => renderRoute());

    document.addEventListener("click", (ev) => {
      const b = ev.target.closest(".btn-tap");
      if (!b || b.disabled) return;
      try {
        if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        if (typeof navigator !== "undefined" && navigator.vibrate) navigator.vibrate(10);
      } catch (_) {}
    }, true);

    await loadMe();
    syncNavForViewport();
    try { applySidebarRail(); } catch (_) {}
    if (!location.hash) location.hash = state.me ? "#/overview" : "#/login";
    else renderRoute();
    await loadHealth().catch(() => {});
    window.addEventListener("online", () => {
      loadHealth().catch(() => {});
      tickHealthIfVisible();
      if (typeof window.__eventsStreamResume === "function") {
        try {
          if (!window.__evSSE || window.__evSSE.readyState === EventSource.CLOSED) {
            window.__eventsStreamResume();
          } else {
            syncEventsLiveBadge();
          }
        } catch (_) {}
      }
    });
    document.addEventListener("visibilitychange", () => {
      document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
      if (document.visibilityState === "hidden") {
        /* Keep SSE open through tab switches — closing forced reconnect storms through proxies. */
        const live = document.getElementById("evLive");
        if (live && window.__evSSE && window.__evSSE.readyState === EventSource.OPEN) {
          live.textContent = "Background";
          live.className = "badge neutral";
          live.title = "Stream stays connected in background";
        }
        return;
      }
      tickHealthIfVisible();
      syncEventsLiveBadge();
      if (typeof window.__eventsStreamResume === "function") {
        try {
          if (!window.__evSSE || window.__evSSE.readyState === EventSource.CLOSED) {
            window.__eventsStreamResume();
          }
        } catch (_) {}
      }
    });
    document.documentElement.classList.toggle("tab-hidden", document.visibilityState === "hidden");
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
