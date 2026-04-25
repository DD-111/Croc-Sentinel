# Operations console (single SPA)

**Do not add** parallel HTML “pages” under this folder. The fleet UI is one **hash-routed** bundle:

| File | Role |
|------|------|
| `index.html` | Shell; loads `assets/app.css` + `assets/app.js` (add `?v=…` on those URLs to force browsers to pick up a new build) |
| `assets/app.css` | Entry: `@import`s layered styles under `assets/css/` |
| `assets/css/*.css` | Tokens, shell, components, main rules, redesign layer |
| `assets/app.js` | **Normally built** from `src/` via **`npm run build`**; you may hand-edit for hotfixes / merge recovery, then backport to `src/` when possible |
| `src/console.raw.js` | SPA logic source (was the monolith); spliced with `src/lib/*.js` at build time |
| `src/lib/*.js` | Shared modules: constants, DOM safety, SSE helpers, formatting |
| `package.json` | `npm run build` → `assets/app.js`; **`npm run verify`** = build + syntax check + route smoke |

**Typography (global):** **Source Sans 3** (body) + **Outfit** (titles / brand) + **JetBrains Mono** (code). Tokens live in `assets/css/00-tokens.css`.

**Developers:** from this folder, `npm install` once, then after any change to `src/console.raw.js` or `src/lib/*.js`, run **`npm run build`** before shipping (Docker copies `assets/app.js` as-is).

**URL on the server:** the API mounts this directory at **`DASHBOARD_PATH`** (default in `.env`: `/console`), not a fixed `/dashboard` string. Old paths like `/ui` or `/dashboard` are redirected to `DASHBOARD_PATH` when enabled in `api/app.py`.

**In-app routes** (fragment after `#`): e.g. `#/overview`, `#/alerts`, `#/activate`, `#/login` — see `registerRoute(...)` in **`src/console.raw.js`** (compiled into `assets/app.js`).

**Single source of truth (default):** JS under **`src/`**; CSS under **`assets/css/`** with `assets/app.css` as the `@import` entry. **`scripts/split-css.mjs`** guards against accidental re-split of the import entry; use **`node scripts/split-css.mjs --force`** (or `CROC_SPLIT_CSS_FORCE=1`) when you intentionally restored a monolithic `app.css` and need to re-partition.

**Not the web console:** the desktop **factory** tool is `tools/factory_pack/factory_ui.py` (Tk). It is a separate app; only its “open activate link in browser” string should point at the same `DASHBOARD_PATH` as the API.
