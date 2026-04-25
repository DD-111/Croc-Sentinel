/**
 * Splices modular imports into console.raw.js (IIFE monolith) and bundles to assets/app.js.
 *
 * Route splitting: any file matching `src/routes/*.route.js` is appended after
 * the spliced monolith body (and before esbuild wraps everything in an IIFE).
 * Route files are NOT ES modules — they share scope with console.raw.js so
 * they can call `registerRoute`, `mountView`, `api`, `$`, etc. directly.
 *
 * Order: HEADER imports → spliced console.raw body → routes/*.route.js (sorted).
 */
import * as esbuild from "esbuild";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const rawPath = join(root, "src", "console.raw.js");
const routesDir = join(root, "src", "routes");

const HEADER = `/* Croc Sentinel Console — bundled from dashboard/src/ (npm run build) */
"use strict";
import { LS, OFFLINE_MS, DEFAULT_REMOTE_SIREN_MS, DEFAULT_PANIC_FANOUT_MS, NAV_GROUPS, ROLE_WEIGHT, PUBLIC_ROUTE_IDS, ROUTE_ALIASES } from "./lib/constants.js";
import { $, $$, escapeHtml, hx, mountView, parseHtmlToFragment, setChildMarkup, prependChildMarkup, appendChildMarkup, setHtmlIfChanged, setTextIfChanged } from "./lib/dom.js";
import { parseSseFields, pumpSseBody, SSE_PARSE_BUF_MAX } from "./lib/sse.js";
import { fmtTs, fmtRel, maskPlatform, auditActionPrefix, auditDetailDedupedRows, eventDetailDedupedRows, messagePayloadRows, auditChipClass } from "./lib/format.js";

`;

function spliceMonolith(raw) {
  let body = raw.replace(/\r\n/g, "\n");
  body = body.replace(/\(function \(\) \{\s*\n  ["']use strict["'];\s*\n/, "");
  body = body.replace(/\n\}\)\(\);\s*$/, "");

  const cMark = "  // ------------------------------------------------------------------ const\n";
  const cStart = body.indexOf(cMark);
  const cEnd = body.indexOf("  function authSiteFooterHtml()", cStart);
  if (cStart === -1 || cEnd === -1) {
    throw new Error("build-dashboard: could not splice const block (markers missing)");
  }
  body = body.slice(0, cStart) + body.slice(cEnd);

  const r1Start = body.indexOf("  const $ = (sel, root) => (root || document).querySelector(sel);");
  const r1End = body.indexOf("  /**\n   * REST base URL.", r1Start);
  if (r1Start === -1 || r1End === -1) {
    throw new Error("build-dashboard: could not find $/$$ block or REST comment marker");
  }

  const r2Start = body.indexOf("  function escapeHtml(v) {");
  const r2End = body.indexOf("  /** Parse one SSE block", r2Start);
  if (r2Start === -1 || r2End === -1) {
    throw new Error("build-dashboard: could not find escapeHtml..mountView block or SSE marker");
  }

  const r3Start = body.indexOf("  /** Parse one SSE block");
  const r3End = body.indexOf("  /** All dashboard clocks", r3Start);
  if (r3Start === -1 || r3End === -1) {
    throw new Error("build-dashboard: could not find SSE block or MY_TZ marker");
  }

  const r4Start = body.indexOf("  /** All dashboard clocks");
  const r4End = body.indexOf("  function roleWeight(r) { return ROLE_WEIGHT[r] || 0; }", r4Start);
  if (r4Start === -1 || r4End === -1) {
    throw new Error("build-dashboard: could not find format block or roleWeight marker");
  }

  const ranges = [
    [r4Start, r4End],
    [r3Start, r3End],
    [r2Start, r2End],
    [r1Start, r1End],
  ].sort((a, b) => b[0] - a[0]);

  for (const [s, e] of ranges) {
    body = body.slice(0, s) + body.slice(e);
  }

  return HEADER + body;
}

function loadRouteFiles() {
  if (!existsSync(routesDir)) return "";
  const entries = readdirSync(routesDir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".route.js"))
    .map((e) => e.name)
    .sort();
  if (entries.length === 0) return "";
  let out = "\n// ============================================================\n";
  out += "// === Routes spliced from src/routes/*.route.js ==============\n";
  out += "// ============================================================\n";
  for (const name of entries) {
    const txt = readFileSync(join(routesDir, name), "utf8").replace(/\r\n/g, "\n");
    out += `\n// ── ${name} ─────────────────────────────────────\n` + txt + "\n";
  }
  return out;
}

const raw = readFileSync(rawPath, "utf8");
const contents = spliceMonolith(raw) + loadRouteFiles();

const result = await esbuild.build({
  stdin: {
    contents,
    resolveDir: join(root, "src"),
    sourcefile: "virtual-console.js",
    loader: "js",
  },
  bundle: true,
  outfile: join(root, "assets", "app.js"),
  platform: "browser",
  format: "iife",
  legalComments: "none",
  banner: {
    js: "/* Croc Sentinel Console — IIFE bundle; edit src/ + npm run build */",
  },
});

if (result.errors && result.errors.length) {
  console.error(result.errors);
  process.exit(1);
}

console.log("OK: wrote assets/app.js");
