# Operations console (single SPA)

**Do not add** parallel HTML “pages” under this folder. The fleet UI is one **hash-routed** bundle:

| File | Role |
|------|------|
| `index.html` | Shell; loads `assets/app.css` + `assets/app.js` |
| `assets/app.css` | Layout, tokens, responsive + auth marketing surface |
| `assets/app.js` | Routes, API calls, templates (all “screens” live here) |

**Typography (global):** **Source Sans 3** (body) + **Outfit** (titles / brand) + **JetBrains Mono** (code). Defined in `assets/app.css` `:root` so login and signed-in views match.

**URL on the server:** the API mounts this directory at **`DASHBOARD_PATH`** (default in `.env`: `/console`), not a fixed `/dashboard` string. Old paths like `/ui` or `/dashboard` are redirected to `DASHBOARD_PATH` when enabled in `api/app.py`.

**In-app routes** (fragment after `#`): e.g. `#/overview`, `#/alerts`, `#/activate`, `#/login` — see `registerRoute(...)` in `app.js`.

**Not the web console:** the desktop **factory** tool is `tools/factory_pack/factory_ui.py` (Tk). It is a separate app; only its “open activate link in browser” string should point at the same `DASHBOARD_PATH` as the API.
