#!/usr/bin/env bash
# Copyright 2026 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Launches a local 4-role Split Moderation & Redemption TLS 1.3 topology:
#   - 3 Identity Anchors (`anchor.com`, `anchor2.com`, `anchor3.com`, satisfying
#     the >= 3 Anchor Set ring invariant)
#   - 1 Shared Split Moderator (`antifraud.com`)
#   - 2 Independent Relying-Party Origins (`shoes.com` and `socks.com`)
# and optionally starts Chromium configured with `--mole-key-commitments`.

set -euo pipefail

OUT_DIR="${OUT_DIR:-out/Default}"
CHROME_BIN="${CHROME_BIN:-${OUT_DIR}/chrome}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d -t mole_split_demo.XXXXXX)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=mole-demo.local" \
  -addext "subjectAltName=DNS:anchor.com,DNS:anchor2.com,DNS:anchor3.com,DNS:antifraud.com,DNS:shoes.com,DNS:socks.com,IP:127.0.0.1" \
  -keyout "${WORK_DIR}/key.pem" \
  -out "${WORK_DIR}/cert.pem" >/dev/null 2>&1

SPKI_HASH="$(openssl x509 -in "${WORK_DIR}/cert.pem" -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  openssl base64)"

start_anchor() {
  local origin="$1"
  local port="$2"
  local log="${WORK_DIR}/anchor_${port}.log"
  "${OUT_DIR}/mole_demo_anchor" \
    --origin "${origin}" \
    --port "${port}" \
    --epoch "demo-epoch-1" \
    --cert "${WORK_DIR}/cert.pem" \
    --key "${WORK_DIR}/key.pem" >"${log}" 2>&1 &
  PIDS+=("$!")
  for _ in $(seq 1 50); do
    if grep -q "^ANCHOR_COMMITMENT " "${log}" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "Timed out waiting for ${origin} on :${port}" >&2
  cat "${log}" >&2
  exit 1
}

start_anchor "https://anchor.com" 8441
start_anchor "https://anchor2.com" 8445
start_anchor "https://anchor3.com" 8446

AK1="$(awk '/^ANCHOR_KEY / {print $2}' "${WORK_DIR}/anchor_8441.log")"
AK2="$(awk '/^ANCHOR_KEY / {print $2}' "${WORK_DIR}/anchor_8445.log")"
AK3="$(awk '/^ANCHOR_KEY / {print $2}' "${WORK_DIR}/anchor_8446.log")"

AC1="$(sed -n 's/^ANCHOR_COMMITMENT //p' "${WORK_DIR}/anchor_8441.log")"
AC2="$(sed -n 's/^ANCHOR_COMMITMENT //p' "${WORK_DIR}/anchor_8445.log")"
AC3="$(sed -n 's/^ANCHOR_COMMITMENT //p' "${WORK_DIR}/anchor_8446.log")"

MOD_LOG="${WORK_DIR}/moderator.log"
"${OUT_DIR}/mole_demo_moderator" \
  --origin "https://antifraud.com" \
  --port 8442 \
  --policy "antifraud-v2" \
  --epoch "demo-epoch-1" \
  --anchor-keys "${AK1},${AK2},${AK3}" \
  --allowed-sites "https://shoes.com,https://socks.com" \
  --cert "${WORK_DIR}/cert.pem" \
  --key "${WORK_DIR}/key.pem" >"${MOD_LOG}" 2>&1 &
PIDS+=("$!")

for _ in $(seq 1 50); do
  if grep -q "^MODERATOR_COMMITMENT " "${MOD_LOG}" 2>/dev/null; then
    break
  fi
  sleep 0.05
done

CLEARANCE_KEY="$(awk '/^MODERATOR_CLEARANCE_KEY / {print $2}' "${MOD_LOG}")"
MOD_COMMIT="$(sed -n 's/^MODERATOR_COMMITMENT //p' "${MOD_LOG}")"

"${OUT_DIR}/mole_demo_origin" \
  --origin "https://shoes.com" \
  --port 8443 \
  --moderator "https://antifraud.com" \
  --policy "antifraud-v2" \
  --clearance-key "${CLEARANCE_KEY}" \
  --cost 1 \
  --moderator-addr "127.0.0.1:8442" \
  --reward 3 \
  --web-dir "${SCRIPT_DIR}/web/shoes" \
  --cert "${WORK_DIR}/cert.pem" \
  --key "${WORK_DIR}/key.pem" >"${WORK_DIR}/shoes.log" 2>&1 &
PIDS+=("$!")

"${OUT_DIR}/mole_demo_origin" \
  --origin "https://socks.com" \
  --port 8444 \
  --moderator "https://antifraud.com" \
  --policy "antifraud-v2" \
  --clearance-key "${CLEARANCE_KEY}" \
  --cost 1 \
  --web-dir "${SCRIPT_DIR}/web/socks" \
  --cert "${WORK_DIR}/cert.pem" \
  --key "${WORK_DIR}/key.pem" >"${WORK_DIR}/socks.log" 2>&1 &
PIDS+=("$!")

COMMITMENTS_JSON="$(printf '{"anchors":{"https://anchor.com":%s,"https://anchor2.com":%s,"https://anchor3.com":%s},"moderators":{"https://antifraud.com":%s}}' \
  "${AC1}" "${AC2}" "${AC3}" "${MOD_COMMIT}")"

echo "=== MOLE Split Moderation & Redemption Demo Running ==="
echo "  Anchors (N=3): https://anchor.com (:8441), anchor2.com (:8445), anchor3.com (:8446)"
echo "  Moderator:     https://antifraud.com (:8442)"
echo "  Origins:       https://shoes.com (:8443), https://socks.com (:8444)"

if [[ -x "${CHROME_BIN}" ]]; then
  "${CHROME_BIN}" \
    --user-data-dir="${WORK_DIR}/profile" \
    --enable-blink-features=ModeratedEndorsements \
    --mole-key-commitments="${COMMITMENTS_JSON}" \
    --ignore-certificate-errors-spki-list="${SPKI_HASH}" \
    --host-resolver-rules="MAP anchor.com 127.0.0.1:8441, MAP anchor2.com 127.0.0.1:8445, MAP anchor3.com 127.0.0.1:8446, MAP antifraud.com 127.0.0.1:8442, MAP shoes.com 127.0.0.1:8443, MAP socks.com 127.0.0.1:8444" \
    "https://anchor.com"
else
  echo "Chromium binary not found at ${CHROME_BIN}; servers running until Ctrl-C."
  wait
fi
