/**
 * One-shot splitter: partitions assets/app.css into css/*.css and replaces app.css with @imports.
 * Run from dashboard/: node scripts/split-css.mjs
 *
 * Safety defaults refuse destructive re-runs. Override when intentional:
 *   node scripts/split-css.mjs --force
 *   CROC_SPLIT_CSS_FORCE=1 node scripts/split-css.mjs
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cssDir = join(root, "assets", "css");
mkdirSync(cssDir, { recursive: true });

const force =
  process.argv.includes("--force") ||
  process.argv.includes("-f") ||
  process.env.CROC_SPLIT_CSS_FORCE === "1";

const raw = readFileSync(join(root, "assets", "app.css"), "utf8");
const looksLikeImportEntry =
  /^@import\s/m.test(raw.trimStart()) || raw.includes("split layers");
const lineCount = raw.split("\n").length;

if (!force && (looksLikeImportEntry || lineCount < 200)) {
  if (looksLikeImportEntry) {
    console.error(
      "split-css: assets/app.css is already the @import entry. Re-splitting would corrupt CSS. Edit assets/css/*.css instead, or run with --force if you restored a monolith and accept the risk.",
    );
  } else {
    console.error(
      "split-css: app.css looks too small to be the legacy monolith; refusing. Use --force if this is intentional.",
    );
  }
  process.exit(1);
}

if (force && (looksLikeImportEntry || lineCount < 200)) {
  console.warn(
    "split-css: --force / CROC_SPLIT_CSS_FORCE: skipping safety checks. Verify line slices (77 / 900) still match your file.",
  );
}

const lines = raw.split(/\n/);

const tokens = lines.slice(0, 77).join("\n");
const baseShell = lines.slice(77, 900).join("\n");
const main = lines.slice(900).join("\n");

writeFileSync(join(cssDir, "00-tokens.css"), tokens + "\n");
writeFileSync(join(cssDir, "01-base-shell.css"), baseShell + "\n");
writeFileSync(join(cssDir, "02-main.css"), main + "\n");

const newApp = `/* Croc Sentinel console — split layers; edit css/*.css */
@import url("./css/00-tokens.css");
@import url("./css/01-base-shell.css");
@import url("./css/02-main.css");
@import url("./css/20-redesign.css");
`;

writeFileSync(join(root, "assets", "app.css"), newApp);
console.log("Split OK:", join(cssDir, "00-tokens.css"), "lines ~77 +", 900 - 77, "+", lines.length - 900);
