// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Demo EC-ACT Moderator HTTPS server (`draft-jms-mole-protocols-01` §5.2, §6).
//! Usage:
//!   mole_demo_moderator --port 8080 --origin https://antifraud.com \
//!       --anchor-key <b64> --epoch demo-epoch-1 --context antifraud-basic \
//!       --balance-width 8 --initial-balance 4 --spend-amount 1 \
//!       --max-top-up 0 --refund-amount 1 --cert cert.pem --key key.pem
//! Prints `MODERATOR_COMMITMENT <json>` to stderr for `run_demo.sh`.

use mole_core::http::{b64_decode, b64_encode};
use mole_demo::{ModeratorServer, Response, serve};

const PAGE: &str = r#"<!doctype html>
<meta charset=utf-8><title>antifraud.com — the shared moderator</title>
<style>body{font:16px system-ui;max-width:44em;margin:3em auto;padding:0 1em}
pre{background:#f4f4f4;padding:1em;overflow-x:auto}b{color:#06c}</style>
<h1>🛡️ antifraud.com</h1>
<p>antifraud.com is the shared Moderator that shoes.com and socks.com both use.
Everything it observes appears below: one unlinkable EC-IHAT redemption at
<code>POST /mole/issue</code>, followed by unlinkable EC-ACT spend nullifiers on
<code>GET /gate</code>.</p>
<pre id=out>loading…</pre>
<script>
async function tick() {
  try {
    const s = await (await fetch("https://antifraud.com/stats")).json();
    let out_lines = [];
    out_lines.push("endorsement redemptions (POST /mole/issue): " + s.redemptions);
    out_lines.push("credential presentations (GET /gate):       " + s.presentations);
    out_lines.push("recovery / signoff settlements:             " + s.settlements);
    out_lines.push("");
    out_lines.push("each presentation revealed only a fresh one-time nullifier:");
    if (!s.nullifiers.length) out_lines.push("  (none yet; visit shoes.com or socks.com)");
    for (const n of s.nullifiers) out_lines.push("  " + n);
    out_lines.push("");
    out_lines.push("Each nullifier appears once and never again. antifraud.com");
    out_lines.push("cannot link two presentations together or link any of them");
    out_lines.push("back to a redemption or an anchor.com user.");
    document.getElementById("out").textContent = out_lines.join("\n");
  } catch (e) {
    document.getElementById("out").textContent = "stats unavailable: " + e;
  }
}
tick(); setInterval(tick, 1000);
</script>
"#;

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port = arg(&args, "--port", "8080");
    let origin = arg(&args, "--origin", "https://antifraud.com");
    let anchor_key_b64 = arg(&args, "--anchor-key", "");
    let epoch = arg(&args, "--epoch", "demo-epoch-1");
    let context = {
        let c = arg(&args, "--context", "");
        if c.is_empty() {
            arg(&args, "--policy", "antifraud-basic")
        } else {
            c
        }
    };
    let balance_width: u8 = arg(&args, "--balance-width", "8").parse().unwrap_or(8);
    let initial_balance: u64 = arg(&args, "--initial-balance", "4").parse().unwrap_or(4);
    let spend_amount: u64 = arg(&args, "--spend-amount", "1").parse().unwrap_or(1);
    let max_top_up: u64 = arg(&args, "--max-top-up", "0").parse().unwrap_or(0);
    let refund_amount: u64 = arg(&args, "--refund-amount", "1").parse().unwrap_or(1);
    let hold_secs: u64 = arg(&args, "--hold-secs", "0").parse().unwrap_or(0);
    let cert = arg(&args, "--cert", "");
    let key = arg(&args, "--key", "");

    let Ok(anchor_key) = b64_decode(&anchor_key_b64) else {
        eprintln!("[mole-demo-moderator] --anchor-key must be unpadded base64url");
        std::process::exit(2);
    };

    let mut moderator = match ModeratorServer::new(
        &origin,
        &anchor_key,
        epoch.as_bytes(),
        context.as_bytes(),
        balance_width,
        initial_balance,
        spend_amount,
        max_top_up,
        refund_amount,
        hold_secs,
    ) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[mole-demo-moderator] {e}");
            std::process::exit(2);
        }
    };
    eprintln!("MODERATOR_ACCEPTS_ANCHOR {}", b64_encode(&anchor_key));
    eprintln!("MODERATOR_COMMITMENT {}", moderator.commitment_json());

    let addr = format!("127.0.0.1:{port}");
    if let Err(e) = serve(&addr, &cert, &key, |request| {
        if request.path == "/" || request.path == "/index.html" {
            return Response {
                status: 200,
                headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
                body: PAGE.as_bytes().to_vec(),
            };
        }
        moderator.handle(request)
    }) {
        eprintln!("[mole-demo-moderator] fatal: {e}");
        std::process::exit(1);
    }
}
