/**
 * Route: #/login — primary sign-in form (auth shell page).
 *
 * Build: concatenated by `scripts/build-dashboard.mjs`. Shares scope with
 * console.raw.js — see `account-activate.route.js` for the convention.
 *
 * Flow: posts to login() (defined in console.raw.js — wraps /auth/login,
 * stores CSRF token + JWT/cookie session, hydrates state.me), then loads
 * /me + /health and redirects to #/overview.
 *
 * Backend contracts: covered transitively by login() / loadMe() / loadHealth()
 * which are tested via `tests/test_spa_api_contract.py`.
 */

registerRoute("login", async (view) => {
  setCrumb("Sign in");
  document.body.dataset.auth = "none";
  const cleanAuthMessage = (raw) => {
    const s = String(raw || "").trim();
    if (!s) return "Request failed. Please try again.";
    const l = s.toLowerCase();
    if (l.includes("401")) return "Username or password is incorrect.";
    if (l.includes("invalid credentials")) return "Username or password is incorrect.";
    if (l.includes("too many login attempts")) return s; /* 429: server already has seconds */
    if (l.includes("session expired")) return "Session expired. Please sign in again.";
    if (l.includes("networkerror") || l.includes("failed to fetch")) return "Network error. Please check server/API.";
    return s.replace(/^error:\s*/i, "");
  };
  mountView(view, `
    <div class="auth-surface" role="main">
      ${authAsideHtml("login")}
      <div class="auth-surface__body">
        <div class="auth-surface__inner">
          <div class="auth-card auth-card--panel auth-card--auth-main" data-auth-card>
            <header class="auth-card__head">
              <h1 class="auth-card__title">Sign in</h1>
              <p class="auth-card__lead">Use the credentials your administrator provided.</p>
            </header>
            <form class="auth-card__body" id="loginForm" autocomplete="on">
              <label class="field">
                <span>Username</span>
                <input name="username" autocomplete="username" required placeholder="e.g. dan" />
              </label>
              <label class="field field--spaced">
                <span>Password</span>
                <input name="password" type="password" autocomplete="current-password" required placeholder="••••••••" />
              </label>
              <div class="auth-card__submit">
                <button class="btn btn-tap btn-block auth-btn-primary" type="submit" id="loginSubmit">Sign in</button>
              </div>
              <p class="auth-card__msg auth-card__msg--fixed muted" id="loginMsg" aria-live="polite"></p>
              <nav class="auth-card__links auth-card__links--grid" aria-label="Other sign-in options">
                <a class="auth-link" href="#/register">Register admin</a>
                <a class="auth-link" href="#/account-activate">Activate account</a>
                <a class="auth-link" href="#/forgot-password">Forgot password</a>
              </nav>
            </form>
          </div>
          ${authSiteFooterHtml()}
        </div>
      </div>
    </div>`);
  const form = $("#loginForm", view);
  const card = view.querySelector("[data-auth-card]");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const data = new FormData(form);
    const msg = $("#loginMsg", view);
    const btn = $("#loginSubmit", view);
    const label = btn ? btn.textContent : "Sign in";
    msg.textContent = "";
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Signing in…";
    }
    try {
      await login(data.get("username"), data.get("password"));
      await loadMe();
      await loadHealth();
      location.hash = "#/overview";
    } catch (e) {
      msg.textContent = cleanAuthMessage(e.message || e);
      if (card) {
        card.classList.remove("auth-shake");
        void card.offsetWidth;
        card.classList.add("auth-shake");
        setTimeout(() => card.classList.remove("auth-shake"), 500);
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = label;
      }
    }
  });
});
