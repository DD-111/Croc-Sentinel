/**
 * Route: #/account-activate — admin-issued account activation flow.
 *
 * Build mechanism: this file is *not* an ES module. It's read as raw text by
 * `scripts/build-dashboard.mjs` and concatenated after the spliced
 * `console.raw.js` body, so it shares scope with the monolith and can call
 * `registerRoute`, `mountView`, `setCrumb`, `apiBase`, `$`, etc. directly.
 * Do NOT add `import` or `export` here — esbuild would treat it as a separate
 * module and lose the shared scope.
 *
 * Smoke + tests:
 *   - `scripts/smoke-routes.mjs` confirms `registerRoute("account-activate")`
 *     still appears in the bundle and matches the route manifest.
 *   - `tests/test_spa_api_contract.py` confirms `/auth/activate` and
 *     `/auth/code/resend` still hit a real FastAPI route.
 */

registerRoute("account-activate", async (view) => {
  setCrumb("Activate account");
  document.body.dataset.auth = "none";
  mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("activate")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner">
      <div class="auth-card auth-card--panel auth-card--wide" data-auth-card>
        <header class="auth-card__head">
          <h1 class="auth-card__title">Activate account</h1>
          <p class="auth-card__lead">Use the code from your invitation email</p>
        </header>
        <div class="auth-card__body">
          <p class="auth-card__note muted">An administrator created your user. Enter your <strong>username</strong> and the <strong>email code</strong> below.</p>
          <label class="field"><span>Username</span><input id="a_user" autocomplete="username" placeholder="Your username"/></label>
          <label class="field field--spaced"><span>Email code</span><input id="a_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code" placeholder="From email"/></label>
          <div class="auth-card__submit">
            <button class="btn btn-tap btn-block" type="button" id="a_submit">Activate</button>
            <button class="btn secondary btn-tap btn-block" type="button" id="a_resend">Resend code</button>
            <a class="auth-link auth-link--center" href="#/login">Back to sign in</a>
          </div>
          <p class="auth-card__msg muted" id="a_msg" aria-live="polite"></p>
        </div>
      </div>
      ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
  const msg = $("#a_msg");
  $("#a_submit").addEventListener("click", async () => {
    const body = {
      username: $("#a_user").value.trim(),
      email_code: $("#a_email_code").value.trim(),
    };
    msg.textContent = "";
    try {
      const r = await fetch(apiBase() + "/auth/activate", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `${r.status}`);
      setChildMarkup(msg, `<span class="badge online">Activated</span> Redirecting to sign in…`);
      scheduleRouteRedirect(1500, "#/login");
    } catch (e) { msg.textContent = String(e.message || e); }
  });
  $("#a_resend").addEventListener("click", async () => {
    msg.textContent = "";
    const username = $("#a_user").value.trim();
    if (!username) { msg.textContent = "Enter username first"; return; }
    try {
      const r = await fetch(apiBase() + "/auth/code/resend", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, channel: "email", purpose: "activate" }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `${r.status}`);
      msg.textContent = "Resend requested — check inbox and spam.";
    } catch (e) { msg.textContent = String(e.message || e); }
  });
});
