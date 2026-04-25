/**
 * Flat ESLint config for the dashboard.
 *
 * The dashboard ships in three flavours that need different lint contexts:
 *
 *   1. src/lib/*.js + src/routes/manifest.js
 *      Pure ES modules, imported via the build HEADER. Browser globals only.
 *
 *   2. src/shell/*.shell.js + src/routes/*.route.js + src/console.raw.js
 *      Concatenated as raw text into one IIFE by scripts/build-dashboard.mjs.
 *      They share scope — every top-level `function/const/let` in any file is
 *      visible to every other file. ESLint cannot infer that on its own, so
 *      scripts/_derive-globals.mjs walks the source tree and produces
 *      scripts/_globals.json with every cross-file name. We feed that here.
 *
 *      Because top-level decls are intentionally "exported by concat",
 *      `no-unused-vars` runs with `vars: "local"`: it only flags vars that
 *      are unused within the same scope they were declared in (function
 *      bodies, blocks). True dead globals are caught by `npm run smoke`.
 *
 *   3. scripts/*.mjs
 *      Node build/util scripts. Node globals only.
 *
 * Updating cross-file globals: run `node scripts/_derive-globals.mjs` after
 * extracting / renaming any shell / route / lib symbol, then commit the
 * regenerated _globals.json. `npm run lint` does this for you (preflight).
 */

import { readFileSync } from "node:fs";
import globals from "globals";

const _g = JSON.parse(
  readFileSync(new URL("./scripts/_globals.json", import.meta.url), "utf8"),
);

/** Cross-file globals visible to every shell / route / monolith file. */
const concatGlobals = Object.fromEntries(
  _g.concatGlobals.map((name) => [name, "writable"]),
);

const sharedRules = {
  "no-undef": "error",
  eqeqeq: ["error", "smart"],
};

const esmUnusedVars = [
  "error",
  {
    argsIgnorePattern: "^_",
    varsIgnorePattern: "^_",
    caughtErrorsIgnorePattern: "^_",
    ignoreRestSiblings: true,
  },
];

const concatUnusedVars = [
  "error",
  {
    // The whole point of shell/ + routes/*.route.js is to hand top-level decls
    // off to sibling files via shared scope, so don't flag those as unused.
    // Anything declared inside a function/block is fair game.
    vars: "local",
    varsIgnorePattern: "^_",
    args: "after-used",
    argsIgnorePattern: "^_",
    caughtErrorsIgnorePattern: "^_",
    destructuredArrayIgnorePattern: "^_",
    ignoreRestSiblings: true,
  },
];

export default [
  // Hard ignores: build output, node_modules, generated metadata.
  {
    ignores: [
      "node_modules/**",
      "assets/**",
      "scripts/_globals.json",
    ],
  },

  // Layer 1: pure ESM helpers + the canonical route manifest.
  {
    files: ["src/lib/**/*.js", "src/routes/manifest.js"],
    languageOptions: {
      sourceType: "module",
      ecmaVersion: 2024,
      globals: { ...globals.browser },
    },
    rules: {
      ...sharedRules,
      "no-unused-vars": esmUnusedVars,
    },
  },

  // Layer 2: raw-concatenated shell + route handlers + remaining monolith.
  {
    files: [
      "src/shell/**/*.js",
      "src/routes/*.route.js",
      "src/console.raw.js",
    ],
    languageOptions: {
      sourceType: "script",
      ecmaVersion: 2024,
      globals: {
        ...globals.browser,
        ...concatGlobals,
      },
    },
    rules: {
      ...sharedRules,
      "no-unused-vars": concatUnusedVars,
    },
  },

  // Layer 3: Node build / smoke / utility scripts.
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      sourceType: "module",
      ecmaVersion: 2024,
      globals: { ...globals.node },
    },
    rules: {
      ...sharedRules,
      "no-unused-vars": esmUnusedVars,
    },
  },
];
