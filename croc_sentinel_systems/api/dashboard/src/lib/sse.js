/** Parse one SSE block (RFC 8895-style, LF / CRLF). */
export function parseSseFields(block) {
  let eventName = "message";
  const dataLines = [];
  const lines = String(block || "").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === "" || line.startsWith(":")) continue;
    const ci = line.indexOf(":");
    const field = ci === -1 ? line : line.slice(0, ci);
    let value = ci === -1 ? "" : line.slice(ci + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") eventName = value;
    else if (field === "data") dataLines.push(value);
  }
  return { event: eventName, data: dataLines.join("\n") };
}

export const SSE_PARSE_BUF_MAX = 262144;

/** Read chunked text/event-stream; invokes onFrame(type, payload) where type is "message"|"ping". */
export async function pumpSseBody(reader, signal, onFrame) {
  const dec = new TextDecoder();
  let buf = "";
  while (!signal.aborted) {
    let chunk;
    try {
      chunk = await reader.read();
    } catch (_) {
      break;
    }
    const { done, value } = chunk || {};
    if (done) break;
    buf += dec.decode(value, { stream: true });
    if (buf.length > SSE_PARSE_BUF_MAX) {
      const cut = buf.lastIndexOf("\n\n", buf.length - 65536);
      buf = cut > 0 ? buf.slice(cut + 2) : "";
    }
    for (;;) {
      const m = buf.match(/\r?\n\r?\n/);
      if (!m) break;
      const idx = m.index || 0;
      const raw = buf.slice(0, idx);
      buf = buf.slice(idx + m[0].length);
      if (!String(raw || "").trim()) continue;
      const fields = parseSseFields(raw);
      if (fields.event === "ping") onFrame("ping", fields.data);
      else onFrame("message", fields.data);
    }
  }
}
