// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The demo Moderator server. Usage:
//!   mole_demo_moderator --port 8080 --anchor-key <b64> --epoch demo-epoch-1 \
//!       --policy antifraud-basic --initial-credits 2 --issuance-batch 4 --charge 1
//! Prints `MODERATOR_COMMITMENT <json>` to stderr for the launch script.

use mole_core::http::{b64_decode, b64_encode};
use mole_demo::{serve, ModeratorServer, Response};

const PAGE: &str = r#"<!doctype html>
<meta charset=utf-8><title>antifraud.com — the shared moderator</title>
<style>body{font:16px system-ui;max-width:40em;margin:3em auto;padding:0 1em}
pre{background:#f4f4f4;padding:1em}b{color:#06c}</style>
<h1>🛡️ antifraud.com</h1>
<p>The <b>anti-fraud moderator</b> shared by shoes.com and socks.com. It redeems
one endorsement into a pool of anonymous credentials, and verifies a fresh
credential on each visit. The counters below are the whole privacy story:</p>
<pre id=out>loading…</pre>
<p><b>One redemption</b> vets you once. <b>Many presentations</b> — one per site
visit — and antifraud.com <b>cannot tell they are the same person</b>, nor can
shoes.com and socks.com link you to each other.</p>
<script>
async function tick() {
  try {
    const s = await (await fetch("https://antifraud.com/stats")).json();
    out.textContent =
      "redemptions (Redeem & Issue): " + s.redemptions + "\n" +
      "presentations (site visits):  " + s.presentations + "\n\n" +
      (s.redemptions <= 1 && s.presentations >= 2
        ? "→ " + s.presentations + " unlinkable visits from " + s.redemptions +
          " redemption. antifraud.com cannot correlate them."
        : "");
  } catch (e) { out.textContent = "stats unavailable: " + e; }
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
    let anchor_key_b64 = arg(&args, "--anchor-key", "");
    let epoch = arg(&args, "--epoch", "demo-epoch-1");
    let policy = arg(&args, "--policy", "antifraud-basic");
    let initial_credits: u64 = arg(&args, "--initial-credits", "2").parse().unwrap_or(2);
    let issuance_batch: u64 = arg(&args, "--issuance-batch", "4").parse().unwrap_or(4);
    let charge: u64 = arg(&args, "--charge", "1").parse().unwrap_or(1);
    let refund: u64 = arg(&args, "--refund", "0").parse().unwrap_or(0);
    let cert = arg(&args, "--cert", "");
    let key = arg(&args, "--key", "");

    let Ok(anchor_key) = b64_decode(&anchor_key_b64) else {
        eprintln!("[mole-demo-moderator] --anchor-key must be base64url");
        std::process::exit(2);
    };

    let mut moderator = match ModeratorServer::new(
        &anchor_key,
        epoch.as_bytes(),
        policy.as_bytes(),
        initial_credits,
        issuance_batch,
        charge,
        refund,
    ) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[mole-demo-moderator] {e}");
            std::process::exit(2);
        }
    };
    // The demo enrolls the anchor by its committed key; echo the accepted key.
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
