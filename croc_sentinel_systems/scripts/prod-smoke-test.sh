#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:8088}"
API_TOKEN="${API_TOKEN:?API_TOKEN is required}"

auth_header=(-H "Authorization: Bearer ${API_TOKEN}")

echo "[1/6] health"
curl -fsS "${auth_header[@]}" "${API_BASE}/health" >/dev/null

echo "[2/6] dashboard overview"
curl -fsS "${auth_header[@]}" "${API_BASE}/dashboard/overview" >/dev/null

echo "[3/6] list devices"
devices_json="$(curl -fsS "${auth_header[@]}" "${API_BASE}/devices")"
device_id="$(python3 - <<'PY' "$devices_json"
import json,sys
d=json.loads(sys.argv[1]).get("items",[])
print(d[0]["device_id"] if d else "")
PY
)"

if [[ -n "${device_id}" ]]; then
  echo "[4/6] single-device self-test command"
  curl -fsS -X POST "${auth_header[@]}" "${API_BASE}/devices/${device_id}/self-test" >/dev/null

  echo "[5/6] single-device alert on/off"
  curl -fsS -X POST "${auth_header[@]}" "${API_BASE}/devices/${device_id}/alert/on?duration_ms=3000" >/dev/null
  curl -fsS -X POST "${auth_header[@]}" "${API_BASE}/devices/${device_id}/alert/off" >/dev/null
else
  echo "[4/6] skipped self-test (no devices yet)"
  echo "[5/6] skipped alert test (no devices yet)"
fi

echo "[6/6] logs endpoint"
curl -fsS "${auth_header[@]}" "${API_BASE}/logs/messages?limit=5" >/dev/null

echo "PASS: production smoke test completed"
