/**
 * One-shot helper: physically remove every block in console.raw.js whose
 * canonical home is now src/lib/<name>.js. The build pipeline used to splice
 * these blocks out at build time (via marker-based body.indexOf rules); after
 * this script runs they are gone from disk, and the splice rules in
 * scripts/build-dashboard.mjs can be deleted in the same commit.
 *
 * Each range is replaced by a single breadcrumb comment so a future reader
 * grepping for "escapeHtml" inside console.raw.js still gets pointed at the
 * canonical lib/ file.
 *
 * Run once. Idempotent: if a marker is missing, the corresponding range is
 * skipped (assumed already deleted).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const monolithPath = join(root, "src", "console.raw.js");

// Each range: human-readable id, start marker, end marker (exclusive),
// breadcrumb comment that replaces it.
const RANGES = [
  {
    id: "const-block",
    start: "  // ------------------------------------------------------------------ const\n",
    end: "  function authSiteFooterHtml()",
    crumb:
      "  // LS / OFFLINE_MS / DEFAULT_REMOTE_SIREN_MS / DEFAULT_PANIC_FANOUT_MS /\n" +
      "  // NAV_GROUPS / ROLE_WEIGHT / one-time JWT migration → src/lib/constants.js.\n" +
      "\n",
  },
  {
    id: "dom-shorthand",
    start: "  const $ = (sel, root) => (root || document).querySelector(sel);",
    end: "  /**\n   * REST base URL.",
    // After the api block was already removed, the next line is the api
    // breadcrumb comment; we don't expect this range to match anymore.
    altEnd: "  // apiBase / fetchWithDeadline /",
    crumb:
      "  // $ / $$ → src/lib/dom.js.\n" +
      "\n",
  },
  {
    id: "dom-html-helpers",
    start: "  function escapeHtml(v) {",
    end: "  /** Parse one SSE block",
    crumb:
      "  // escapeHtml / parseHtmlToFragment / setChildMarkup / prependChildMarkup /\n" +
      "  // appendChildMarkup / setHtmlIfChanged / setTextIfChanged / hx / mountView\n" +
      "  // → src/lib/dom.js.\n" +
      "\n",
  },
  {
    id: "sse-block",
    start: "  /** Parse one SSE block",
    end: "  /** All dashboard clocks",
    crumb:
      "  // parseSseFields / SSE_PARSE_BUF_MAX / pumpSseBody → src/lib/sse.js.\n" +
      "\n",
  },
  {
    id: "format-block",
    start: "  /** All dashboard clocks",
    end: "  function roleWeight(r) { return ROLE_WEIGHT[r] || 0; }",
    crumb:
      "  // MY_TZ / MY_OFFSET_HINT / fmtTs / fmtRel / maskPlatform / auditActionPrefix /\n" +
      "  // auditDetailDedupedRows / eventDetailDedupedRows / messagePayloadRows /\n" +
      "  // auditChipClass → src/lib/format.js.\n" +
      "\n",
  },
];

let body = readFileSync(monolithPath, "utf8").replace(/\r\n/g, "\n");

// Compute every (start, end) pair against the *original* body, then apply in
// descending order of start so earlier offsets stay valid (same trick the
// build pipeline used).
const ops = [];
for (const r of RANGES) {
  const s = body.indexOf(r.start);
  let e = -1;
  if (s !== -1) e = body.indexOf(r.end, s);
  if (s !== -1 && e === -1 && r.altEnd) e = body.indexOf(r.altEnd, s);
  if (s === -1 || e === -1) {
    console.log(`SKIP ${r.id}: marker missing (start=${s}, end=${e}) — assumed already removed`);
    continue;
  }
  ops.push({ id: r.id, s, e, crumb: r.crumb, removed: e - s });
}
ops.sort((a, b) => b.s - a.s);

let totalRemoved = 0;
for (const op of ops) {
  body = body.slice(0, op.s) + op.crumb + body.slice(op.e);
  totalRemoved += op.removed;
  console.log(`OK ${op.id}: stripped ${op.removed} bytes (replaced with ${op.crumb.length}-byte breadcrumb)`);
}

writeFileSync(monolithPath, body, "utf8");
console.log(`---`);
console.log(`Total stripped: ${totalRemoved} bytes (raw); console.raw.js rewritten.`);
