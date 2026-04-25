/**
 * Route: #/forgot-password — username + email + SHA code reset flow.
 *
 * Build: concatenated by `scripts/build-dashboard.mjs`. Shares scope with
 * console.raw.js — see `account-activate.route.js` for the convention.
 *
 * Backend contracts (verified by `tests/test_spa_api_contract.py`):
 *   - GET  /auth/forgot/email/enabled   → feature gate (mailer configured?)
 *   - POST /auth/forgot/email/check     → username/email match check
 *   - POST /auth/forgot/email/start     → request SHA code
 *   - POST /auth/forgot/email/complete  → set new password
 *
 * Cooldown timer leak guard: any setInterval is also pinned on
 * `window.__fpCooldownTimer` so route navigation can clear it via
 * `clearRouteTickers()` in console.raw.js.
 */

registerRoute("forgot-password", async (view) => {
  setCrumb("Forgot password");
  document.body.dataset.auth = "none";
  let enabled = true;
  try {
    const r = await fetch(apiBase() + "/auth/forgot/email/enabled");
    const j = await r.json();
    enabled = !!j.enabled;
  } catch { enabled = false; }
  mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("recovery")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner auth-surface__inner--wide">
      <div class="auth-card auth-card--panel auth-card--wide auth-card--prose" data-auth-card>
        <header class="auth-card__head">
          <h1 class="auth-card__title">Account recovery</h1>
          <p class="auth-card__lead">Reset via email verification code</p>
        </header>
        <div class="auth-card__body">
        <p class="muted auth-card__prose">
          Enter your username and the same email used at registration.
          The server sends a SHA-style verification code to that email.
          Enter the code to set a new password (saved permanently on server).
        </p>
        ${enabled ? "" : `<p class="badge revoked" style="margin:10px 0">Email sender is not configured on server.</p>`}
        <div id="fpStep1">
          <label class="field"><span>Username</span><input id="fp_user" autocomplete="username" /></label>
          <label class="field field--spaced"><span>Registered email</span><input id="fp_email" autocomplete="email" /></label>
          <div class="auth-card__submit">
            <button class="btn btn-tap btn-block" type="button" id="fp_go" ${enabled ? "" : "disabled"}>Send SHA code</button>
            <a class="auth-link auth-link--center" href="#/login">Back to sign in</a>
          </div>
          <p class="auth-card__msg muted" id="fp_msg1" aria-live="polite"></p>
        </div>
        <div id="fpStep2" style="display:none">
          <label class="field"><span>SHA code (from email)</span>
            <input id="fp_sha_code" class="mono" maxlength="32" autocomplete="one-time-code" />
          </label>
          <label class="field field--spaced"><span>New password (≥8)</span><input id="fp_p1" type="password" autocomplete="new-password" /></label>
          <label class="field field--spaced"><span>Confirm password</span><input id="fp_p2" type="password" autocomplete="new-password" /></label>
          <div class="auth-card__submit">
            <button class="btn btn-tap btn-block" type="button" id="fp_done">Update password</button>
            <button class="btn secondary btn-tap btn-block" type="button" id="fp_resend">Resend SHA code</button>
            <button class="btn secondary btn-tap btn-block" type="button" id="fp_back">Back</button>
          </div>
          <p class="auth-card__msg muted" id="fp_msg2" aria-live="polite"></p>
        </div>
        </div>
      </div>
      ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
  const m1 = $("#fp_msg1"), m2 = $("#fp_msg2");
  let fpCooldown = 0;
  let fpCooldownTimer = 0;
  const fpGoBtn = $("#fp_go");
  const fpResendBtn = $("#fp_resend");
  const applyFpCooldownUi = () => {
    const left = Math.max(0, Number(fpCooldown || 0));
    if (fpGoBtn) {
      fpGoBtn.disabled = !enabled || left > 0;
      fpGoBtn.textContent = left > 0 ? `Resend in ${left}s` : "Send SHA code";
    }
    if (fpResendBtn) {
      fpResendBtn.disabled = left > 0;
      fpResendBtn.textContent = left > 0 ? `Resend in ${left}s` : "Resend SHA code";
    }
  };
  const startFpCooldown = (seconds) => {
    fpCooldown = Math.max(0, Number(seconds || 0));
    applyFpCooldownUi();
    if (fpCooldownTimer) clearInterval(fpCooldownTimer);
    // Also kill any leftover from an earlier visit so navigating away mid-cooldown
    // and coming back doesn't double-tick the UI.
    if (window.__fpCooldownTimer) {
      try { clearInterval(window.__fpCooldownTimer); } catch (_) {}
      window.__fpCooldownTimer = 0;
    }
    if (fpCooldown <= 0) return;
    fpCooldownTimer = setInterval(() => {
      fpCooldown = Math.max(0, fpCooldown - 1);
      applyFpCooldownUi();
      if (fpCooldown <= 0) {
        clearInterval(fpCooldownTimer);
        fpCooldownTimer = 0;
        window.__fpCooldownTimer = 0;
      }
    }, 1000);
    window.__fpCooldownTimer = fpCooldownTimer;
  };
  const parseCooldownFromMessage = (msg) => {
    const m = String(msg || "").match(/wait\s+(\d+)s/i);
    return m ? Math.max(1, Number(m[1])) : 0;
  };
  const doForgotSend = async () => {
    m1.textContent = "";
    const username = $("#fp_user").value.trim();
    const email = ($("#fp_email").value || "").trim().toLowerCase();
    if (!username || !email) { m1.textContent = "Enter username and email"; return false; }
    if (fpCooldown > 0) { m1.textContent = `Please wait ${fpCooldown}s before resending.`; return false; }
    const check = await fetch(apiBase() + "/auth/forgot/email/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email }),
    });
    const cj = await check.json().catch(() => ({}));
    if (!check.ok) {
      const det = cj.detail;
      const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || check.statusText);
      throw new Error(msg);
    }
    if (!cj.matched) {
      m1.textContent = "Username and registered email do not match.";
      return false;
    }
    const preWait = Number(cj.resend_after_seconds || 0);
    if (preWait > 0) {
      startFpCooldown(preWait);
      m1.textContent = `Please wait ${preWait}s before sending again.`;
      return false;
    }
    const r = await fetch(apiBase() + "/auth/forgot/email/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      const det = d.detail;
      const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || r.statusText);
      const wait = parseCooldownFromMessage(msg);
      if (wait > 0) startFpCooldown(wait);
      throw new Error(msg);
    }
    const cd = Number(d.resend_after_seconds || 60);
    startFpCooldown(cd);
    m1.textContent = `Code sent. TTL ${(Number(d.ttl_seconds || 0) / 60).toFixed(0)} min.`;
    return true;
  };
  applyFpCooldownUi();
  $("#fp_go").addEventListener("click", async () => {
    try {
      const ok = await doForgotSend();
      if (!ok) return;
      $("#fpStep1").style.display = "none";
      $("#fpStep2").style.display = "block";
    } catch (e) { m1.textContent = String(e.message || e); }
  });
  if (fpResendBtn) {
    fpResendBtn.addEventListener("click", async () => {
      try {
        const ok = await doForgotSend();
        if (ok) m2.textContent = `Code resent. Wait ${fpCooldown}s before next resend.`;
      } catch (e) { m2.textContent = String(e.message || e); }
    });
  }
  $("#fp_back").addEventListener("click", () => {
    $("#fpStep2").style.display = "none";
    $("#fpStep1").style.display = "block";
    m2.textContent = "";
  });
  $("#fp_done").addEventListener("click", async () => {
    m2.textContent = "";
    const username = $("#fp_user").value.trim();
    const email = ($("#fp_email").value || "").trim().toLowerCase();
    const sha_code = ($("#fp_sha_code").value || "").trim().toUpperCase();
    const password = $("#fp_p1").value;
    const password_confirm = $("#fp_p2").value;
    if (!email || !sha_code || !password) { m2.textContent = "Enter email, SHA code, and password"; return; }
    if (password !== password_confirm) { m2.textContent = "Passwords do not match"; return; }
    try {
      const r = await fetch(apiBase() + "/auth/forgot/email/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, sha_code, password, password_confirm }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        const det = d.detail;
        const msg = Array.isArray(det) ? det.map((x) => x.msg || JSON.stringify(x)).join("; ") : (det || r.statusText);
        throw new Error(msg);
      }
      setChildMarkup(m2, `<span class="badge online">Password updated</span> Redirecting to sign in…`);
      toast("Password updated", "ok");
      scheduleRouteRedirect(1500, "#/login");
    } catch (e) { m2.textContent = String(e.message || e); }
  });
});
