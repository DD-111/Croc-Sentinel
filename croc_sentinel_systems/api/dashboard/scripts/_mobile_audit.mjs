/**
 * Static mobile / touch audit. One-shot exploratory tool — not part of CI.
 * Scans the layered CSS for the most common mobile pitfalls and prints a
 * concise findings table.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = "assets/css";
const files = readdirSync(root).filter((f) => f.endsWith(".css")).sort();

const findings = [];
const note = (severity, file, line, what, detail) =>
  findings.push({ severity, file, line, what, detail });

// 1. min-height / height / line-height of buttons/inputs (look for likely
//    touch-target rules with values < 40px).
const SMALL_TARGET_RE =
  /(\.btn[^{}]*|\.icon-btn[^{}]*|button[^{}]*|input[^{}]*|select[^{}]*|\.nav-item[^{}]*|\.tag[^{}]*|\.chip[^{}]*)\s*\{[^}]*?(?:min-height|height|line-height)\s*:\s*(\d+(?:\.\d+)?)px/g;

// 2. fixed pixel widths likely to overflow narrow phones.
const HARD_WIDTH_RE = /\bwidth\s*:\s*(\d{3,})\s*px\b/g;

// 3. Missing safe-area on bottom-fixed bars.
const BOTTOM_FIXED_RE =
  /position\s*:\s*fixed[^}]*?bottom\s*:\s*0/gs;

// 4. Use of vw / 100vw which traps horizontal scrolling on iOS Safari with safe areas.
const VW_HARD_RE = /\b(?:width|min-width|max-width)\s*:\s*100vw\b/g;

// 5. Rules with `overflow-x: visible` next to `display:flex; flex-wrap:nowrap`
//    in a parent — too noisy for static; skip.

for (const f of files) {
  const path = join(root, f);
  const text = readFileSync(path, "utf8").replace(/\r\n/g, "\n");
  const lineOf = (pos) => {
    let l = 1;
    for (let i = 0; i < pos; i++) if (text[i] === "\n") l++;
    return l;
  };

  let m;
  while ((m = SMALL_TARGET_RE.exec(text))) {
    const px = Number(m[2]);
    if (px && px < 32) {
      note(
        "WARN",
        f,
        lineOf(m.index),
        "small-touch-target",
        `${m[1].trim().slice(0, 40)}… → ${px}px (recommend ≥40px)`
      );
    }
  }
  while ((m = HARD_WIDTH_RE.exec(text))) {
    const px = Number(m[1]);
    if (px >= 480) {
      note(
        "INFO",
        f,
        lineOf(m.index),
        "fixed-width",
        `width: ${px}px — phone min width is 320px`
      );
    }
  }
  while ((m = BOTTOM_FIXED_RE.exec(text))) {
    const block = m[0];
    if (!/safe-area-inset-bottom/.test(block)) {
      note(
        "WARN",
        f,
        lineOf(m.index),
        "fixed-bottom-no-safearea",
        "position:fixed; bottom:0 without env(safe-area-inset-bottom)"
      );
    }
  }
  while ((m = VW_HARD_RE.exec(text))) {
    note(
      "INFO",
      f,
      lineOf(m.index),
      "100vw",
      "100vw can overshoot the viewport on iOS — prefer 100% or 100dvw"
    );
  }
}

// Output
const grouped = findings.reduce((acc, x) => {
  acc[x.what] = (acc[x.what] || 0) + 1;
  return acc;
}, {});
console.log("== Mobile audit ==");
console.log("Files scanned:", files.join(", "));
console.log("Total findings:", findings.length);
for (const [k, v] of Object.entries(grouped)) console.log("  -", k, "×", v);
console.log("");
for (const x of findings) {
  console.log(`[${x.severity}] ${x.file}:${x.line}  ${x.what}  ${x.detail}`);
}
