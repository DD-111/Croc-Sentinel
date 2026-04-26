/**
 * Hash router + per-route ticker registry. Owns the `routes` registry that
 * src/routes/*.route.js populates via registerRoute(id, handler) at load
 * time, plus the renderRoute() pipeline (auth gating, view-loading skeleton,
 * timeout race, post-render nav refresh). Listens on hashchange.
 *
 * Concatenated AFTER state/api/layout but BEFORE the route files, so the
 * registry is empty at concat-time but every routes/*.route.js sees
 * registerRoute() in scope when its top-level call runs.
 */
// ------------------------------------------------------------------ router
const routes = {};

function registerRoute(id, handler) { routes[id] = handler; }
function isRouteCurrent(seq) { return seq === state.routeSeq; }
function clearRouteTickers() {
  const ticks = window.__routeTickers;
  if (!ticks) return;
  for (const t of ticks.values()) {
    try { clearTimeout(t); } catch (_) {}
  }
  ticks.clear();
}
function scheduleRouteTicker(routeSeq, key, fn, intervalMs) {
  window.__routeTickers = window.__routeTickers || new Map();
  const ticks = window.__routeTickers;
  const k = String(key || "");
  let running = false;
  const run = async () => {
    if (!isRouteCurrent(routeSeq)) return;
    if (document.visibilityState !== "visible") {
      const tid = setTimeout(run, intervalMs);
      ticks.set(k, tid);
      return;
    }
    if (running) {
      const tid = setTimeout(run, intervalMs);
      ticks.set(k, tid);
      return;
    }
    running = true;
    try { await fn(); } catch (_) {}
    running = false;
    if (!isRouteCurrent(routeSeq)) return;
    const tid = setTimeout(run, intervalMs);
    ticks.set(k, tid);
  };
  const old = ticks.get(k);
  if (old) { try { clearTimeout(old); } catch (_) {} }
  const first = setTimeout(run, intervalMs);
  ticks.set(k, first);
}

async function renderRoute() {
  const view = $("#view");
  // #region agent log
  fetch('http://127.0.0.1:7580/ingest/13cc4f55-c163-4556-b72d-19f8aaadec22',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'ba8b41'},body:JSON.stringify({sessionId:'ba8b41',runId:'r1',hypothesisId:'B,E',location:'30-router.shell.js:renderRoute-entry',message:'renderRoute entry',data:{hash:location.hash,viewExists:!!view,bodyClass:document.body&&document.body.className||'',bodyDataLayout:document.body&&document.body.dataset.layout||'',hasToken:!!(typeof getToken==='function'?getToken():null),hasMe:!!(typeof state!=='undefined'&&state&&state.me)},timestamp:Date.now()})}).catch(()=>{});
  // #endregion
  if (!view) return;
  let hashFull = location.hash || "#/overview";
  let routeQuery = new URLSearchParams("");
  const qm = hashFull.indexOf("?");
  if (qm >= 0) {
    try {
      routeQuery = new URLSearchParams(hashFull.slice(qm + 1));
    } catch (_) {}
    hashFull = hashFull.slice(0, qm);
  }
  window.__routeQuery = routeQuery;
  const [_, rawId, ...rest] = hashFull.split("/");
  const id = rawId || "overview";
  const args = rest;
  const routeSeq = ++state.routeSeq;

  clearRouteRedirectTimer();
  if (overviewFilterDebounce) {
    clearTimeout(overviewFilterDebounce);
    overviewFilterDebounce = null;
  }
  if (window.__pendingEvListRaf) {
    try { cancelAnimationFrame(window.__pendingEvListRaf); } catch (_) {}
    window.__pendingEvListRaf = 0;
  }
  clearRouteTickers();
  if (window.__fpCooldownTimer) {
    // Forgot-password resend countdown is a setInterval (clearTimeout won't
    // touch it), so clear it here when the user navigates mid-cooldown.
    try { clearInterval(window.__fpCooldownTimer); } catch (_) {}
    window.__fpCooldownTimer = 0;
  }
  if (window.__evReconnectTimer) {
    try { clearTimeout(window.__evReconnectTimer); } catch (_) {}
    window.__evReconnectTimer = 0;
  }
  if (window.__evFetchAbort) {
    try { window.__evFetchAbort.abort(); } catch (_) {}
    window.__evFetchAbort = null;
  }
  window.__eventsStreamResume = null;
  toggleNav(false);
  if (window.__evSSE) { try { window.__evSSE.close(); } catch {} window.__evSSE = null; }

  // Public-route ids and alias mapping come from src/routes/manifest.js
  // (the bundle splice rewrites these references so non-bundled local runs
  // still see the legacy literal sets). Edit the manifest, not this file.
  const publicRoutes = PUBLIC_ROUTE_IDS;
  if (!state.me && !publicRoutes.has(id)) {
    location.hash = "#/login";
    return;
  }
  if (state.me && publicRoutes.has(id)) {
    location.hash = "#/overview";
    return;
  }
  const aliasHash = "#/" + id;
  const routeId = ROUTE_ALIASES[aliasHash] || id;
  const isAuthRoute = publicRoutes.has(routeId);
  document.body.dataset.layout = isAuthRoute ? "auth" : "app";
  // Keep an explicit class for auth-shell CSS guards and legacy selectors.
  document.body.classList.toggle("auth-route-active", isAuthRoute);
  // Runtime hard guard: enforce auth/app chrome visibility directly so
  // late-loaded styles or specificity collisions cannot re-show app chrome.
  try {
    const topbar = document.querySelector(".topbar");
    const sidebar = document.querySelector(".sidebar");
    const sidebarBackdrop = document.querySelector(".sidebar-backdrop");
    for (const el of [topbar, sidebar]) {
      if (!el) continue;
      if (isAuthRoute) {
        el.setAttribute("hidden", "");
        el.style.display = "none";
      } else {
        el.removeAttribute("hidden");
        el.style.display = "";
      }
    }
    if (sidebarBackdrop) {
      if (isAuthRoute) {
        sidebarBackdrop.setAttribute("hidden", "");
        sidebarBackdrop.style.display = "none";
      } else {
        // Backdrop should only appear when mobile nav is opened.
        const navOpen = document.body.dataset.nav === "open";
        if (navOpen) {
          sidebarBackdrop.removeAttribute("hidden");
          sidebarBackdrop.style.display = "";
        } else {
          sidebarBackdrop.setAttribute("hidden", "");
          sidebarBackdrop.style.display = "none";
        }
      }
    }
  } catch (_) {}
  try { applySidebarRail(); } catch (_) {}
  const handler = routes[routeId] || routes["overview"];
  // #region agent log
  try {
    var _tb = document.querySelector('.topbar');
    var _sb = document.querySelector('.sidebar');
    var _au = document.querySelector('.auth-surface');
    fetch('http://127.0.0.1:7580/ingest/13cc4f55-c163-4556-b72d-19f8aaadec22',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'ba8b41'},body:JSON.stringify({sessionId:'ba8b41',runId:'r1',hypothesisId:'B,D,E',location:'30-router.shell.js:hard-guard-done',message:'after hard-guard, before handler',data:{routeId:routeId,isAuthRoute:isAuthRoute,handlerKnown:routeId in routes,handlerKey:(routes[routeId]?routeId:'(fallback overview)'),bodyDataLayout:document.body.dataset.layout,bodyClass:document.body.className,topbarDisplay:_tb?getComputedStyle(_tb).display:'none(missing)',sidebarDisplay:_sb?getComputedStyle(_sb).display:'none(missing)',hasAuthSurface:!!_au,viewChildCount:view.children.length},timestamp:Date.now()})}).catch(()=>{});
  } catch(_) {}
  // #endregion
  try {
    mountView(view, `<div class="route-loading card" aria-busy="true" role="status">
      <span class="sr-only">Loading page</span>
      <div class="route-loading__head"></div>
      <div class="route-loading__lines">
        <span class="route-loading__bar route-loading__bar--90"></span>
        <span class="route-loading__bar route-loading__bar--72"></span>
        <span class="route-loading__bar route-loading__bar--84"></span>
      </div>
    </div>`);
    const swap = async () => {
      await handler(view, args, routeSeq);
    };
    // Do not wrap `swap()` in `document.startViewTransition`: handlers often await
    // network I/O before finishing; the View Transition API then hits a DOM-update
    // timeout and rejects. (Also avoids races where a later route replaces #view while
    // an older handler is still awaiting.)
    await Promise.race([
      swap(),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("Page render timed out. Please retry.")), ROUTE_RENDER_TIMEOUT_MS);
      }),
    ]);
    renderNav();
    renderHealthPills();
    // #region agent log
    try {
      var _au2 = document.querySelector('.auth-surface');
      var _card = document.querySelector('[data-auth-card]');
      var _form = document.getElementById('loginForm');
      fetch('http://127.0.0.1:7580/ingest/13cc4f55-c163-4556-b72d-19f8aaadec22',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'ba8b41'},body:JSON.stringify({sessionId:'ba8b41',runId:'r1',hypothesisId:'B,C,D',location:'30-router.shell.js:handler-done',message:'after handler success',data:{routeId:routeId,viewChildCount:view.children.length,viewFirstChildClass:(view.firstElementChild&&view.firstElementChild.className||''),authSurfaceFound:!!_au2,authCardFound:!!_card,authCardDisplay:_card?getComputedStyle(_card).display:'(none)',authCardRect:_card?(function(r){return{w:Math.round(r.width),h:Math.round(r.height)};})(_card.getBoundingClientRect()):null,loginFormFound:!!_form},timestamp:Date.now()})}).catch(()=>{});
    } catch(_) {}
    // #endregion
  } catch (e) {
    // #region agent log
    fetch('http://127.0.0.1:7580/ingest/13cc4f55-c163-4556-b72d-19f8aaadec22',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'ba8b41'},body:JSON.stringify({sessionId:'ba8b41',runId:'r1',hypothesisId:'B',location:'30-router.shell.js:handler-catch',message:'handler threw',data:{routeId:routeId,error:String(e&&e.message||e),stack:String(e&&e.stack||'').slice(0,400)},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
    mountView(view, hx`<div class="card"><h2>Load failed</h2><p class="muted">${e.message || e}</p></div>`);
  }
}

window.addEventListener("hashchange", renderRoute);
