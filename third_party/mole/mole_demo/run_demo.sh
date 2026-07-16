#!/usr/bin/env bash
# Copyright 2026 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Runs the 4-origin MoLE demo:
#   anchor.com     (identity provider)   -> mole_demo_anchor
#   antifraud.com  (shared moderator)    -> mole_demo_moderator
#   shoes.com      (a site)              -> static page
#   socks.com      (a site)              -> static page
# ...all mapped to localhost and driven by a content_shell/chrome build with the
# ModeratedEndorsements feature. Usage:  ./run_demo.sh [out_dir]
set -euo pipefail

OUT="${1:-out/athm}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRCROOT="$(cd "$HERE/../../.." && pwd)"
cd "$SRCROOT"

ANCHOR_BIN="$OUT/mole_demo_anchor"
MOD_BIN="$OUT/mole_demo_moderator"
# content_shell (Mac .app or plain binary) or chrome.
if [[ -x "$OUT/Content Shell.app/Contents/MacOS/Content Shell" ]]; then
  BROWSER="$OUT/Content Shell.app/Contents/MacOS/Content Shell"
elif [[ -x "$OUT/content_shell" ]]; then
  BROWSER="$OUT/content_shell"
elif [[ -x "$OUT/Chromium.app/Contents/MacOS/Chromium" ]]; then
  BROWSER="$OUT/Chromium.app/Contents/MacOS/Chromium"
else
  echo "No content_shell/chrome found in $OUT. Build one first." >&2; exit 1
fi
for b in "$ANCHOR_BIN" "$MOD_BIN"; do
  [[ -x "$b" ]] || { echo "missing $b — run: autoninja -C $OUT mole_demo_anchor mole_demo_moderator" >&2; exit 1; }
done

EPOCH="demo-epoch-1"
TMP="$(mktemp -d)"
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

echo "== starting anchor.com (:8081) =="
"$ANCHOR_BIN" --port 8081 --epoch "$EPOCH" 2>"$TMP/anchor.log" & PIDS+=($!)
for _ in $(seq 1 100); do grep -q ANCHOR_KEY "$TMP/anchor.log" 2>/dev/null && break; sleep 0.05; done
ANCHOR_KEY="$(grep ANCHOR_KEY "$TMP/anchor.log" | awk '{print $2}')"
ANCHOR_COMMITMENT="$(grep ANCHOR_COMMITMENT "$TMP/anchor.log" | cut -d' ' -f2-)"
[[ -n "$ANCHOR_KEY" ]] || { echo "anchor failed to start:"; cat "$TMP/anchor.log"; exit 1; }

echo "== starting antifraud.com (:8080), accepting anchor.com =="
"$MOD_BIN" --port 8080 --anchor-key "$ANCHOR_KEY" --epoch "$EPOCH" \
  --policy antifraud-basic --initial-credits 2 --issuance-batch 4 --charge 1 \
  2>"$TMP/mod.log" & PIDS+=($!)
for _ in $(seq 1 100); do grep -q MODERATOR_COMMITMENT "$TMP/mod.log" 2>/dev/null && break; sleep 0.05; done
MOD_COMMITMENT="$(grep MODERATOR_COMMITMENT "$TMP/mod.log" | cut -d' ' -f2-)"
[[ -n "$MOD_COMMITMENT" ]] || { echo "moderator failed to start:"; cat "$TMP/mod.log"; exit 1; }

echo "== starting shoes.com (:8082) and socks.com (:8083) =="
( cd "$HERE/web/shoes" && exec python3 -m http.server 8082 ) >/dev/null 2>&1 & PIDS+=($!)
( cd "$HERE/web/socks" && exec python3 -m http.server 8083 ) >/dev/null 2>&1 & PIDS+=($!)

# The browser's key-commitment registry: enroll the two origins so enforcement
# passes (everything else is fail-closed). Keyed by serialized origin.
COMMITMENTS="{\"anchors\":{\"http://anchor.com\":$ANCHOR_COMMITMENT},\"moderators\":{\"http://antifraud.com\":$MOD_COMMITMENT}}"

# macOS: an incremental relink can break the .app's ad-hoc signature ("code has
# no resources…"), which makes macOS refuse to launch it. Re-sign defensively.
if [[ "$(uname)" == "Darwin" && "$BROWSER" == *".app/"* ]]; then
  APP_BUNDLE="${BROWSER%%.app/*}.app"
  xattr -dr com.apple.provenance "$APP_BUNDLE" 2>/dev/null || true
  codesign --force --sign - \
    "$APP_BUNDLE"/Contents/Frameworks/*.framework/Versions/Current 2>/dev/null || true
  codesign --force --sign - "$APP_BUNDLE" 2>/dev/null || true
fi

echo "== launching browser =="
echo "   Visit anchor.com -> Get endorsement, then shoes.com / socks.com -> Verify,"
echo "   and watch antifraud.com's counters (1 redemption, N unlinkable presentations)."
"$BROWSER" \
  --user-data-dir="$TMP/profile" \
  --host-resolver-rules="MAP anchor.com 127.0.0.1:8081,MAP antifraud.com 127.0.0.1:8080,MAP shoes.com 127.0.0.1:8082,MAP socks.com 127.0.0.1:8083" \
  --unsafely-treat-insecure-origin-as-secure="http://anchor.com,http://antifraud.com,http://shoes.com,http://socks.com" \
  --enable-blink-features=ModeratedEndorsements \
  --mole-key-commitments="$COMMITMENTS" \
  http://anchor.com

echo "== browser closed; shutting down servers =="
