// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Demo Split Moderation & Redemption HTTPS server (`antifraud.com`).

use mole_core::http::{b64_decode, b64_encode};
use mole_demo::{
    Response, SplitModeratorConfig, SplitModeratorServer, serve,
};

const PAGE: &str = r#"<!doctype html>
<meta charset=utf-8><title>antifraud.com — Split Moderator</title>
<style>body{font:16px system-ui;max-width:46em;margin:3em auto;padding:0 1em}
pre{background:#f4f4f4;padding:1em;overflow-x:auto}</style>
<h1>🛡️ antifraud.com (Split Moderator)</h1>
<p>Shared Moderator serving <code>POST /mole/v1/{issue,present,settle}</code>.
Mints short-lived P-256 ECDSA <code>ClearanceToken</code>s verified locally by
<code>shoes.com</code> and <code>socks.com</code> without seeing first-party
Origin cookies or <code>Authorization: Bearer</code> tokens.</p>
<pre id=out>Loading stats…</pre>
<script>
async function tick() {
  try {
    const s = await (await fetch("/stats")).json();
    document.getElementById("out").textContent = JSON.stringify(s, null, 2);
  } catch (e) {
    document.getElementById("out").textContent = "Error: " + e;
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
    let port = arg(&args, "--port", "8442");
    let origin = arg(&args, "--origin", "https://antifraud.com");
    let anchor_keys_csv = arg(&args, "--anchor-keys", "");
    let epoch = arg(&args, "--epoch", "demo-epoch-1");
    let policy_id = arg(&args, "--policy", "antifraud-v2");
    let allowed_sites_csv = arg(&args, "--allowed-sites", "https://shoes.com,https://socks.com");
    let balance_width: u8 = arg(&args, "--balance-width", "8").parse().unwrap_or(8);
    let initial_balance: u64 = arg(&args, "--initial-balance", "8").parse().unwrap_or(8);
    let spend_amount: u64 = arg(&args, "--spend-amount", "1").parse().unwrap_or(1);
    let max_top_up: u64 = arg(&args, "--max-top-up", "2").parse().unwrap_or(2);
    let hold_ms: u64 = arg(&args, "--hold-ms", "1000").parse().unwrap_or(1000);
    let cert = arg(&args, "--cert", "");
    let key = arg(&args, "--key", "");

    let mut accepted_anchor_keys = Vec::new();
    for part in anchor_keys_csv.split(',').filter(|s| !s.trim().is_empty()) {
        let Ok(raw) = b64_decode(part.trim()) else {
            eprintln!("[mole-demo-moderator] invalid base64url anchor key");
            std::process::exit(2);
        };
        accepted_anchor_keys.push(raw);
    }
    let allowed_sites: Vec<String> = allowed_sites_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut moderator = match SplitModeratorServer::new(SplitModeratorConfig {
        origin,
        policy_id: policy_id.clone(),
        credential_context: policy_id.into_bytes(),
        accepted_anchor_keys,
        epoch: epoch.into_bytes(),
        balance_width,
        initial_balance,
        spend_amount,
        max_top_up,
        default_refund_amount: spend_amount,
        allowed_refund_amounts: vec![0, spend_amount, spend_amount + max_top_up],
        allowed_sites,
        hold_ms,
    }) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[mole-demo-moderator] {e}");
            std::process::exit(2);
        }
    };

    eprintln!(
        "MODERATOR_CLEARANCE_KEY {}",
        b64_encode(moderator.clearance_public_key())
    );
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
