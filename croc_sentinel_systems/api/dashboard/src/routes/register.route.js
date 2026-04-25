/**
 * Route: #/register — public admin signup (start → email-code → verify).
 *
 * Build: concatenated by `scripts/build-dashboard.mjs`. Shares scope with
 * console.raw.js — see `account-activate.route.js` for the convention.
 *
 * Backend contracts:
 *   - POST /auth/signup/start    → request OTP
 *   - POST /auth/signup/verify   → finish signup
 *   - POST /auth/code/resend     → re-issue OTP (purpose=signup)
 * Verified by `tests/test_spa_api_contract.py`.
 */

registerRoute("register", async (view) => {
  setCrumb("Register admin");
  document.body.dataset.auth = "none";
  const cleanSignupMessage = (raw) => {
    const s = String(raw || "").trim();
    if (!s) return "Request failed. Please try again.";
    const l = s.toLowerCase();
    if (l.includes("already exists")) return "Username or email already exists.";
    if (l.includes("invalid") && l.includes("email")) return "Email format is invalid.";
    if (l.includes("networkerror") || l.includes("failed to fetch")) return "Network error. Please check server/API.";
    return s.replace(/^error:\s*/i, "");
  };
  mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("register")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner">
      <div class="auth-card auth-card--panel auth-card--wide" data-auth-card>
        <header class="auth-card__head">
          <h1 class="auth-card__title">Create admin</h1>
          <p class="auth-card__lead">Email verification, then sign in.</p>
        </header>
        <div class="auth-card__body">
          <p class="auth-card__note muted">After verification, you can sign in immediately.</p>
          <ol class="auth-steps" aria-label="Steps">
            <li id="r_step_ind1" class="is-active"><span class="auth-steps__n">1</span><span class="auth-steps__t">Your details</span></li>
            <li id="r_step_ind2"><span class="auth-steps__n">2</span><span class="auth-steps__t">Email code</span></li>
          </ol>
          <div id="rStep1">
            <label class="field"><span>Username</span><input id="r_user" autocomplete="username" placeholder="2–64 chars, letters · digits · ._-"/></label>
            <label class="field field--spaced"><span>Password</span><input id="r_pass" type="password" autocomplete="new-password" placeholder="At least 8 characters"/></label>
            <label class="field field--spaced"><span>Email</span><input id="r_email" type="email" autocomplete="email" placeholder="you@company.com"/></label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="button" id="r_start">Send verification code</button>
              <a class="auth-link auth-link--center" href="#/login">Already have an account</a>
            </div>
            <p class="auth-card__msg muted" id="r_msg1" aria-live="polite"></p>
          </div>
          <div id="rStep2" style="display:none">
            <p class="auth-card__note">We sent a code to <strong class="mono" id="r_shown_email"></strong>. Check inbox and spam.</p>
            <label class="field field--spaced"><span>Verification code</span><input id="r_email_code" inputmode="numeric" maxlength="12" autocomplete="one-time-code" placeholder="6–12 digits"/></label>
            <div class="auth-card__submit">
              <button class="btn btn-tap btn-block" type="button" id="r_verify">Complete signup</button>
              <button class="btn secondary btn-tap btn-block" type="button" id="r_resend">Resend code</button>
              <button class="btn ghost btn-tap btn-block" type="button" id="r_back_step">Edit details</button>
            </div>
            <p class="auth-card__msg muted" id="r_msg2" aria-live="polite"></p>
          </div>
        </div>
      </div>
      ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
  const m1 = $("#r_msg1"), m2 = $("#r_msg2");
  $("#r_start").addEventListener("click", async () => {
    m1.textContent = "";
    const body = {
      username: $("#r_user").value.trim(),
      password: $("#r_pass").value,
      email: $("#r_email").value.trim(),
    };
    if (!body.username || !body.password || !body.email) { m1.textContent = "Username, password, and email required"; return; }
    try {
      const r = await fetch(apiBase() + "/auth/signup/start", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `${r.status}`);
      sessionStorage.setItem("croc.signup_user", body.username);
      $("#r_shown_email").textContent = body.email;
      $("#r_step_ind1").classList.remove("is-active");
      $("#r_step_ind2").classList.add("is-active");
      $("#rStep1").style.display = "none";
      $("#rStep2").style.display = "";
    } catch (e) { m1.textContent = cleanSignupMessage(e.message || e); }
  });
  $("#r_verify").addEventListener("click", async () => {
    m2.textContent = "";
    const body = {
      username: sessionStorage.getItem("croc.signup_user") || "",
      email_code: $("#r_email_code").value.trim(),
    };
    try {
      const r = await fetch(apiBase() + "/auth/signup/verify", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `${r.status}`);
      setChildMarkup(m2, `<span class="badge online">OK</span> Redirecting to sign in…`);
      scheduleRouteRedirect(1500, "#/login");
    } catch (e) { m2.textContent = cleanSignupMessage(e.message || e); }
  });
  $("#r_back_step").addEventListener("click", () => {
    m2.textContent = "";
    $("#r_step_ind2").classList.remove("is-active");
    $("#r_step_ind1").classList.add("is-active");
    $("#rStep2").style.display = "none";
    $("#rStep1").style.display = "";
  });
  $("#r_resend").addEventListener("click", async () => {
    const username = sessionStorage.getItem("croc.signup_user") || "";
    if (!username) { m2.textContent = "Complete step 1 first"; return; }
    try {
      const r = await fetch(apiBase() + "/auth/code/resend", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, channel: "email", purpose: "signup" }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `${r.status}`);
      m2.textContent = "Code resent";
    } catch (e) { m2.textContent = cleanSignupMessage(e.message || e); }
  });
});
