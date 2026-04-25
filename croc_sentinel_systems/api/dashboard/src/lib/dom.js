/** DOM helpers + safe HTML mounting (no innerHTML on live nodes). */
const _lastHtmlByEl = new WeakMap();

export const $ = (sel, root) => (root || document).querySelector(sel);
export const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

export function escapeHtml(v) {
  return String(v == null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Parsed HTML fragment (no assignment to Element.innerHTML). */
export function parseHtmlToFragment(html) {
  const src = String(html ?? "");
  const frag = document.createDocumentFragment();
  if (!src.trim()) return frag;
  const doc = new DOMParser().parseFromString("<!DOCTYPE html><body>" + src + "</body>", "text/html");
  const b = doc.body;
  while (b.firstChild) frag.appendChild(b.firstChild);
  return frag;
}

export function setChildMarkup(el, html) {
  if (!el) return;
  el.replaceChildren(parseHtmlToFragment(String(html ?? "")));
}

export function prependChildMarkup(el, html) {
  if (!el) return;
  const frag = parseHtmlToFragment(html);
  const ref = el.firstChild;
  while (frag.firstChild) el.insertBefore(frag.firstChild, ref);
}

export function appendChildMarkup(el, html) {
  if (!el) return;
  el.append(parseHtmlToFragment(html));
}

export function setHtmlIfChanged(el, html) {
  if (!el) return false;
  const next = String(html == null ? "" : html);
  const prev = _lastHtmlByEl.has(el) ? _lastHtmlByEl.get(el) : null;
  if (prev === next) return false;
  el.replaceChildren(parseHtmlToFragment(next));
  _lastHtmlByEl.set(el, next);
  return true;
}

export function setTextIfChanged(el, txt) {
  if (!el) return false;
  const next = String(txt == null ? "" : txt);
  if (el.textContent === next) return false;
  el.textContent = next;
  return true;
}

/**
 * Tagged template: escapes every interpolation (use for any server/user-facing string).
 * Static HTML in template literals stays literal; only ${values} are escaped.
 */
export function hx(strings, ...values) {
  let out = "";
  for (let i = 0; i < strings.length; i++) {
    out += strings[i];
    if (i < values.length) out += escapeHtml(values[i]);
  }
  return out;
}

/** Replace a route container’s markup; caller must escape dynamic parts (escapeHtml / hx). */
export function mountView(el, html) {
  if (!el) return;
  el.replaceChildren(parseHtmlToFragment(String(html == null ? "" : html)));
}
