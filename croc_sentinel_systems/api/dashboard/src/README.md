# Dashboard source (`src/`)

The SPA is split across three layers, each with a different concatenation/bundle rule. Edit the layer that matches the kind of code you're touching:

| Layer | Files | Mechanism | When to use |
|---|---|---|---|
| **Lib (ESM)** | `src/lib/*.js` | `import { … }` in HEADER, real ES modules | Pure helpers — no shared state, no DOM tree refs (constants, formatters, HTTP/CSRF utilities, static HTML factories) |
| **Shell (raw concat)** | `src/shell/<NN>-<name>.shell.js` | Concatenated as raw text after the monolith body, before the route files | State-coupled glue that needs to read/write the SPA `state` object, mutate the live DOM, or call other shell pieces directly |
| **Routes (raw concat)** | `src/routes/*.route.js` | Concatenated last, after shell | One file per `registerRoute(...)` handler — the leaf of the bundle |
| **Monolith shell** | `src/console.raw.js` | IIFE wrapper + 4-helper glue + `boot()` | Boot loop, glue functions that everyone calls (`toast`, `roleWeight`, `hasRole`, `can`, `isOnline`, `getToken`, `setToken`) |

## Layer 1 — `src/lib/` (proper ES modules)

- `constants.js` — `LS`, `NAV_GROUPS`, timeouts, role weights, `PUBLIC_ROUTE_IDS`, `ROUTE_ALIASES` (re-exported from `routes/manifest.js`).
- `dom.js` — `$`, `escapeHtml`, `hx`, `mountView`, safe fragment helpers.
- `sse.js` — `parseSseFields`, `pumpSseBody`.
- `format.js` — timestamps, audit/event row helpers.
- `api.js` — `apiBase`, `fetchWithDeadline`, retry/timeout classifiers, `DEFAULT_API_TIMEOUT_MS`, `ROUTE_RENDER_TIMEOUT_MS`. Pure browser-env utilities.
- `csrf.js` — double-submit CSRF helpers (`getCsrfToken`, `refreshCsrfToken`, `_isCsrfRejection`).
- `auth-chrome.js` — `authSiteFooterHtml`, `authAsideHtml` (static HTML for login/register/forgot/activate pages).

Names with a leading `_` (e.g. `_isWriteMethod`, `_sleep`) are exported on purpose: every existing call site uses that spelling, so re-exporting under the underscore form makes lib extraction a zero-rename change. Treat them as the public surface.

## Layer 2 — `src/shell/` (raw text, shared scope)

These files are NOT ES modules. They run inside the same IIFE as `console.raw.js` and the route files, so they can read/write `state`, call `mountView`, `$`, `api`, `setHtmlIfChanged`, etc. directly. **Do not** add `import` / `export` here.

The numeric prefix forces concat order:

| File | Owns |
|---|---|
| `00-state.shell.js` | `state = { me, mqttConnected, health, overviewCache, routeSeq }`; group-meta storage helpers (`canonicalGroupKey`, `groupCardMetaKey`, `syncGroupMetaFromServer`, …); `_groupMetaSyncChain`; lifecycle timers (`routeRedirectTimer`, `healthPollTimer`, `overviewFilterDebounce`); `syncEventsLiveBadge` |
| `10-api.shell.js` | `api`, `apiOr`, `apiGetCached` + cache; group apply/delete fallbacks (`runGroupApplyOnAction`, `runGroupDeleteAction`); `grantShareMatrix`; firmware hint dialog (`openGlobalFwHintDialog`, `firmwareHintStillValid`); auth lifecycle (`login`, `loadMe`, `loadHealth`) |
| `20-layout.shell.js` | `renderAuthState`, `renderNav`, `renderHealthPills`, `renderMqttDot`, `setCrumb`, `setTheme`/`initTheme`, `toggleNav`, `applySidebarRail`/`toggleSidebarRail`, `syncNavForViewport` |
| `30-router.shell.js` | The `routes` registry, `registerRoute`, `isRouteCurrent`, `clearRouteTickers`/`scheduleRouteTicker`, `renderRoute`, the `hashchange` listener |

Function declarations in any shell file are hoisted to the top of the IIFE, so order between *functions* doesn't matter. Order between top-level `let`/`const` *does* matter — that's why `state` lives in `00-state.shell.js`.

## Layer 3 — `src/routes/` (raw text, one route per file)

- `manifest.js` — `ROUTES`, `buildNavGroups`, `PUBLIC_ROUTE_IDS`, `ROUTE_ALIASES`. Imported by `lib/constants.js`.
- `*.route.js` — one route per file. Each file runs `registerRoute("<id>", async (view, args, routeSeq) => { … })` at the top level. **Do not** add `import` / `export` here.

### Adding a new route

1. Add a row to `routes/manifest.js` (`ROUTES` array — `id`, `path`, `min`, optional `group`/`label`/`ico`/`public`).
2. Create `routes/<id>.route.js`:
   ```js
   /** Route: #/<id> — <one-line description>. */
   registerRoute("<id>", async (view, args, routeSeq) => {
     setCrumb("…");
     mountView(view, `<div class="card">…</div>`);
     // …
   });
   ```
3. Run `npm run verify` (build + `node --check` + smoke). The smoke script ensures every manifest id has a matching `registerRoute(...)` and vice versa.
4. If the route hits a new backend path, run `pytest croc_sentinel_systems/api/tests` so `test_every_spa_call_hits_a_real_backend_route` blesses the new contract.

## Build pipeline

`scripts/build-dashboard.mjs` does, in order:

1. Reads `console.raw.js` and strips the outer IIFE wrapper. (No marker-based splicing any more — duplicates have been physically removed; if anyone re-adds a duplicate name, esbuild fails with a duplicate-binding error because HEADER imports the same name.)
2. Prepends `import { … } from "./lib/<name>.js"` for every helper module.
3. Appends every `src/shell/<NN>-<name>.shell.js` (sorted, so `00-state` runs before `10-api`).
4. Appends every `src/routes/<id>.route.js` (sorted).
5. Hands the result to **esbuild**, which `import`-bundles `lib/*.js` and re-wraps the whole thing in a single IIFE → `assets/app.js`.

After edits, run **`npm run build`** (or **`npm run verify`**: build + `node --check` + smoke) before committing or shipping.

**Overrides:** you may patch `assets/app.js` directly for a hotfix, but always backport to `src/`. For CSS partition maintenance, **`node scripts/split-css.mjs --force`** bypasses the guard.
