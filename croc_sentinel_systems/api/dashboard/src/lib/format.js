/** All dashboard clocks: Asia/Kuala_Lumpur (Malaysia, UTC+08, no DST). */
const MY_TZ = "Asia/Kuala_Lumpur";
const MY_OFFSET_HINT = "(UTC+08:00)";

export function fmtTs(v) {
  if (!v) return "—";
  const t = typeof v === "number" ? (v > 1e12 ? v : v * 1000) : Date.parse(v);
  if (!Number.isFinite(t)) return String(v);
  const d = new Date(t);
  const base = new Intl.DateTimeFormat("en-CA", {
    timeZone: MY_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d).replace(",", "");
  return `${base} ${MY_OFFSET_HINT}`;
}

export function fmtRel(v) {
  if (!v) return "—";
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return String(v);
  const diff = Date.now() - t;
  if (diff < 60_000) return "just now";
  if (diff < 3600_000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400_000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

export function maskPlatform(_raw) {
  return "e**********";
}

/** Audit log: prefix of action before first "." (for styling). */
export function auditActionPrefix(action) {
  const s = String(action || "").trim();
  const i = s.indexOf(".");
  return i > 0 ? s.slice(0, i) : (s || "other");
}

/** Strip detail fields that duplicate the row's actor/target columns. */
export function auditDetailDedupedRows(detail, actor, target) {
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) return [];
  const a = String(actor || "").trim();
  const t = String(target || "").trim();
  const rows = [];
  for (const [k, raw] of Object.entries(detail)) {
    if (raw == null || raw === "") continue;
    const str = typeof raw === "object" ? JSON.stringify(raw) : String(raw);
    if (!str.trim()) continue;
    if (str === a && /^(actor|username|user|owner|owner_admin|created_by)$/i.test(k)) continue;
    if (t && str === t && /^(target|device_id|deviceId|source_id)$/i.test(k)) continue;
    let display = str;
    if (display.length > 220) display = `${display.slice(0, 217)}…`;
    rows.push({ k, v: display });
  }
  return rows;
}

/** Event detail: skip keys that duplicate the row (actor, target, device, owner). */
export function eventDetailDedupedRows(detail, e) {
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) return [];
  const actor = String((e && e.actor) || "").trim();
  const target = String((e && e.target) || "").trim();
  const dev = String((e && e.device_id) || "").trim();
  const owner = String((e && e.owner_admin) || "").trim();
  const rows = [];
  for (const [k, raw] of Object.entries(detail)) {
    if (raw == null || raw === "") continue;
    const str = typeof raw === "object" ? JSON.stringify(raw) : String(raw);
    if (!str.trim()) continue;
    if (str === actor && /^(actor|username|user|owner_admin|created_by)$/i.test(k)) continue;
    if (target && str === target && /^(target)$/i.test(k)) continue;
    if (dev && str === dev && /^(device_id|deviceId|source_id|device)$/i.test(k)) continue;
    if (owner && str === owner && /^(owner_admin|owner)$/i.test(k)) continue;
    if (str === target && /^(target|device_id|deviceId)$/i.test(k)) continue;
    let display = str;
    if (display.length > 220) display = `${display.slice(0, 217)}…`;
    rows.push({ k, v: display });
  }
  return rows;
}

export function messagePayloadRows(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return [];
  const rows = [];
  for (const [k, raw] of Object.entries(payload)) {
    if (raw == null || raw === "") continue;
    if (String(k || "").startsWith("_")) continue;
    if (/^(ts|timestamp|nonce|seq|message_id|msg_id)$/i.test(String(k || ""))) continue;
    const str = typeof raw === "object" ? JSON.stringify(raw) : String(raw);
    if (!str.trim()) continue;
    let display = str;
    if (display.length > 200) display = `${display.slice(0, 197)}…`;
    rows.push({ k, v: display });
  }
  return rows;
}

export function auditChipClass(action) {
  const p = auditActionPrefix(action);
  const map = {
    alarm: "audit-pfx-alarm",
    provision: "audit-pfx-prov",
    factory: "audit-pfx-factory",
    telegram: "audit-pfx-tg",
    auth: "audit-pfx-auth",
    admin: "audit-pfx-admin",
    user: "audit-pfx-user",
    command: "audit-pfx-cmd",
    mqtt: "audit-pfx-sys",
    device: "audit-pfx-dev",
    ota: "audit-pfx-ota",
    bulk: "audit-pfx-cmd",
    remote: "audit-pfx-alarm",
    signal: "audit-pfx-alarm",
    schedule: "audit-pfx-sys",
    login: "audit-pfx-auth",
    signup: "audit-pfx-auth",
  };
  return map[p] || "audit-pfx-other";
}
