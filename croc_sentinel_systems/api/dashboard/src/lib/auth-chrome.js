/**
 * Public auth pages (login / register / forgot / activate) share two static
 * chunks of chrome: the bottom legal footer and the left "story" aside.
 * Both are pure HTML factories — no state, no DOM access, just template
 * literal output — so they live in lib/ and are imported by the bundle
 * HEADER. Route files (login/register/forgot-password/account-activate)
 * call them by name.
 */

export function authSiteFooterHtml() {
  return `
      <footer class="site-footer site-footer--auth" aria-label="Page footer">
        <div class="site-footer__row site-footer__row--auth">
          <div class="site-footer__brand site-footer__brand--company" role="group" aria-label="ESA">
            <div class="site-footer__wordmark" lang="en">ESA</div>
          </div>
          <p class="site-footer__legal">CROC AI</p>
        </div>
      </footer>`;
}

/** Public auth: left story panel + right form (v3 layout) */
export function authAsideHtml(kind) {
  const m = {
    login: {
      t: "Operations console",
      d: "Role-scoped monitoring, OTA, and device control in one place.",
      items: ["Audit-ready events", "Per-tenant device boundaries", "Real-time health"],
    },
    register: {
      t: "Admin workspace",
      d: "Email verification, then sign in to manage your fleet.",
      items: ["Isolated tenant data", "Verification + cooldown", "No shared MQTT bleed"],
    },
    recovery: {
      t: "Account recovery",
      d: "We send a one-time code to the email on file for this account.",
      items: ["Match username to email", "Code from your inbox", "Set a new password here"],
    },
    activate: {
      t: "Activate access",
      d: "An administrator created your user — confirm with the email we sent you.",
      items: ["One-time code", "Same inbox as the invite", "Then use Sign in"],
    },
  };
  const c = m[kind] || m.login;
  return `
      <aside class="auth-surface__side" aria-label="ESA">
        <div class="auth-surface__side-main">
        <div class="auth-surface__side-content">
          <div class="auth-surface__company" lang="en">
            <p class="auth-surface__company-eyebrow">Secured platform provider</p>
            <p class="auth-surface__wordmark" translate="no">ESA</p>
            <p class="auth-surface__company-line" lang="en">Private, secured operations and tenant-safe edge access — one platform.</p>
            <p class="auth-surface__product-line" translate="no"><span class="auth-surface__product-name">Croc Sentinel</span> <span class="auth-surface__product-role">fleet console</span></p>
          </div>
          <h2 class="auth-surface__headline">${c.t}</h2>
          <p class="auth-surface__lede">${c.d}</p>
          <ul class="auth-surface__bullets" role="list">
            ${c.items.map((x) => `<li>${x}</li>`).join("")}
          </ul>
        </div>
        </div>
        <div class="auth-surface__side-foot" role="group" aria-label="Partners">
          <div class="auth-surface__partner-logos">
            <img class="auth-surface__partner-logo" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="" data-partner-slot="1" loading="lazy" decoding="async" />
            <img class="auth-surface__partner-logo" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="" data-partner-slot="2" loading="lazy" decoding="async" />
            <img class="auth-surface__partner-logo" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="" data-partner-slot="3" loading="lazy" decoding="async" />
          </div>
        </div>
      </aside>`;
}
