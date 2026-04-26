# Operations console (single SPA)

> ## 改前端 UI 之前先看这里 / Where to edit (cheat sheet)
>
> **`assets/app.js` 是构建产物，改它没有用 — 每次 `npm run build` 都会被覆盖。**
> **`assets/app.js` is the build output, NEVER hand-edit it — it is overwritten by every `npm run build`.**
>
> | 想改的 UI / What you want to change | 改这个文件 / Edit this file |
> |---|---|
> | 登录页表单（输入框 / 按钮 / 文案） | `src/routes/login.route.js` |
> | 登录页旁边的 aside 推广栏 / 底部 footer 静态 HTML | `src/lib/auth-chrome.js` |
> | 登录态隐藏 topbar / sidebar 的规则 | `assets/css/01-base-shell.css`（搜 `body[data-layout="auth"]`） |
> | 登录页布局（auth-surface 居中、footer 不漂） | `assets/css/03-shell-v3.css`（搜 `auth-surface__inner`） |
> | 路由切换时把 `body.data-layout` / `auth-route-active` 打上去 | `src/shell/30-router.shell.js`（`renderRoute`） |
> | 全局按钮 `.btn` 样式 | `assets/css/02-main.css`（搜 `.btn`） |
> | 颜色 / 字号 / 间距 token | `assets/css/00-tokens.css` |
> | 任意 `#/<id>` 路由的页面内容 | `src/routes/<id>.route.js`（一个路由一个文件） |
> | 加新路由（要先在导航 / 路由表里登记） | `src/routes/manifest.js` + 新建 `src/routes/<id>.route.js` |
> | 顶层 boot loop / 事件监听 | `src/console.raw.js`（短小，仅 boot） |
> | 全局 `state` / 缓存 / 计时器 | `src/shell/00-state.shell.js` |
> | 网络层 / `api()` / `apiOr()` / `loadMe` | `src/shell/10-api.shell.js` |
> | sidebar / topbar / 主题切换的 JS 行为 | `src/shell/20-layout.shell.js` |
> | 通用工具（`getToken`、`hasRole`、`toast`、`isOnline`） | `src/shell/40-glue.shell.js` |
> | 顶层 HTML 骨架（topbar / sidebar / footer） | `index.html` |
>
> **改完必须做的两步 / After every edit, do BOTH:**
>
> ```bash
> # 1) 本地：重建前端 bundle（写 assets/app.js + sourcemap）
> cd croc_sentinel_systems/api/dashboard
> npm run build
>
> # 2) 服务器：重新打镜像并热替换（assets/app.js 是 COPY 进镜像的）
> cd croc_sentinel_systems
> docker compose build api && docker compose up -d api
> ```
>
> **看不到变化的常见 3 个原因 / "Why my change doesn't show":**
> 1. 改了 `assets/app.js`（错的） — 应该改 `src/` 然后 `npm run build`
> 2. 没重启容器 / 没重建镜像 — `docker compose build api && up -d api`
> 3. 浏览器缓存 — 强制刷新（Windows: Ctrl+Shift+R, Mac: Cmd+Shift+R），或把 `index.html` 里 `?v=NN` 递增（当前 `v=85`）
>
> **DevTools 怎么直接定位回 `src/`：**
> 构建后 `assets/app.js` 旁边会有 `app.js.map`，DevTools → Sources 面板会显示原始的 `src/routes/login.route.js` 等文件，调试时直接看源码、设断点都对得上行号。

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
