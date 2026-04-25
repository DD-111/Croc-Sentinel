/**
 * Static UX audit for routes in src/console.raw.js.
 *
 * Scans each `registerRoute("id", async (view) => { ... })` block and reports:
 *   - Whether it shows a "Loading…" placeholder before the first await.
 *   - Whether it has any visible empty-state branch (`length === 0` or
 *     `items.length` checks producing a "No …" / "empty" message).
 *   - Whether it explicitly handles auth role gating (hasRole / role check).
 */
import { readFileSync } from "node:fs";

const src = readFileSync("src/console.raw.js", "utf8");

// Find each registerRoute block. Two shapes are accepted:
//   registerRoute("id", async (view, ...) => { ... })
//   registerRoute("id", funcRef);   // bound to an existing function
const blocks = [];
const reInline = /registerRoute\(\s*"([^"]+)"\s*,\s*async\s*\(([^)]*)\)\s*=>\s*\{/g;
const reRef = /registerRoute\(\s*"([^"]+)"\s*,\s*([A-Za-z_\$][\w\$]*)\s*\)/g;

let m;
while ((m = reInline.exec(src))) {
  const id = m[1];
  const startIdx = m.index;
  const bodyStart = m.index + m[0].length;
  let depth = 1;
  let i = bodyStart;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") depth--;
    i++;
  }
  const bodyEnd = i;
  const body = src.slice(bodyStart, bodyEnd - 1);
  const startLine = src.slice(0, startIdx).split("\n").length;
  const endLine = src.slice(0, bodyEnd).split("\n").length;
  blocks.push({ id, startLine, endLine, body, kind: "inline" });
}
while ((m = reRef.exec(src))) {
  const id = m[1];
  const refName = m[2];
  // Find the function definition: `function refName(...) { ... }`
  const fnRe = new RegExp(
    "(?:async\\s+)?function\\s+" + refName + "\\s*\\([^)]*\\)\\s*\\{",
    "g"
  );
  const fm = fnRe.exec(src);
  if (!fm) continue;
  const bodyStart = fm.index + fm[0].length;
  let depth = 1;
  let i = bodyStart;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") depth--;
    i++;
  }
  const bodyEnd = i;
  const body = src.slice(bodyStart, bodyEnd - 1);
  const startLine = src.slice(0, fm.index).split("\n").length;
  const endLine = src.slice(0, bodyEnd).split("\n").length;
  blocks.push({ id, startLine, endLine, body, kind: "ref:" + refName });
}
blocks.sort((a, b) => a.startLine - b.startLine);

console.log("== Route UX audit ==");
console.log("routes scanned:", blocks.length);
console.log("");

const findings = [];
for (const r of blocks) {
  const lengthLines = (r.endLine - r.startLine + 1);
  const hasLoading =
    /Loading\s*…|Loading\s*\.{3}|class="muted"[^>]*>Loading|<p class="muted">Loading/i.test(
      r.body
    );
  const hasEmpty =
    /No \w|empty|length\s*===?\s*0|\.items\.length|\.rows\.length|table-empty|empty-state/i.test(
      r.body
    );
  const hasRoleGate = /hasRole\(|state\.me\?\.role|role\s*===\s*"(superadmin|admin|user)"/.test(
    r.body
  );
  const calls = (r.body.match(/\bapi\(/g) || []).length;

  findings.push({
    id: r.id,
    L: r.startLine,
    lines: lengthLines,
    apiCalls: calls,
    hasLoading,
    hasEmpty,
    hasRoleGate,
  });
}

const fmt = (v) => (v ? "✓" : "·");
const pad = (s, n) => (String(s) + " ".repeat(n)).slice(0, n);
console.log(
  pad("ID", 22),
  pad("startL", 8),
  pad("len", 6),
  pad("api()", 6),
  pad("loading", 8),
  pad("empty", 7),
  pad("role", 5)
);
console.log("─".repeat(74));
for (const f of findings) {
  console.log(
    pad(f.id, 22),
    pad(f.L, 8),
    pad(f.lines, 6),
    pad(f.apiCalls, 6),
    pad(fmt(f.hasLoading), 8),
    pad(fmt(f.hasEmpty), 7),
    pad(fmt(f.hasRoleGate), 5)
  );
}

console.log("");
const recommendations = [];
for (const f of findings) {
  // High value: route makes API calls but has no loading UI before the await.
  if (f.apiCalls > 0 && !f.hasLoading) {
    recommendations.push(
      `[loading] ${f.id} (L${f.L}) — ${f.apiCalls} api() calls, no Loading… placeholder before the first await`
    );
  }
  // High value: route renders a table/list (>= 2 api calls) but no empty-state branch.
  if (f.apiCalls >= 2 && !f.hasEmpty) {
    recommendations.push(
      `[empty] ${f.id} (L${f.L}) — multiple api() calls, no visible "no rows / empty" branch detected`
    );
  }
}
if (recommendations.length === 0) {
  console.log("No actionable findings.");
} else {
  console.log("Recommendations:");
  for (const r of recommendations) console.log("  -", r);
}
