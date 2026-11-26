// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Demo EC-IHAT Anchor HTTPS server (`draft-jms-mole-protocols-01` §4.4, §6).
//! Usage:
//!   mole_demo_anchor --port 8081 --origin https://anchor.com --epoch demo-epoch-1 \
//!       --cert cert.pem --key key.pem
//! Prints `ANCHOR_KEY <b64>` and `ANCHOR_COMMITMENT <json>` to stderr for
//! `run_demo.sh` to assemble `--mole-key-commitments`.

use mole_core::http::b64_encode;
use mole_demo::{AnchorServer, Response, serve};

const PAGE: &str = r#"<!doctype html>
<meta charset=utf-8><title>anchor.com — your identity provider</title>
<style>body{font:16px system-ui;max-width:40em;margin:3em auto;padding:0 1em}
button{font:inherit;padding:.5em 1em}pre{background:#f4f4f4;padding:1em;white-space:pre-wrap}
a{color:#06c}</style>
<h1>🔒 anchor.com</h1>
<p>anchor.com is an identity provider — the kind of site that already knows you
are a real, distinct person. Ask it for an endorsement batch and it issues
blind EC-IHAT endorsements to your browser over two HTTPS round-trips.</p>
<p>You are signed in here, so anchor.com endorses your browser automatically on
page load.</p>
<pre id=out>issuing your EC-IHAT endorsement batch…</pre>
<p>Then try
<a href="https://shoes.com">👟 shoes.com</a> and
<a href="https://socks.com">🧦 socks.com</a>. Both check visitors through the
same Moderator (<a href="https://antifraud.com">🛡️ antifraud.com</a>), and
neither site nor antifraud.com can link your visits to each other or to you.</p>
<script>
window.addEventListener("load", async () => {
  if (!navigator.endorsement) {
    out.textContent = "navigator.endorsement is unavailable in this browser.";
    return;
  }
  try {
    await navigator.endorsement.collect("https://anchor.com");
    out.textContent = "✓ Done. Your browser now holds a batch of unlinkable "
      + "EC-IHAT endorsements. It can redeem one for an EC-ACT anonymous "
      + "credential at Moderators without revealing your identity.";
  } catch (e) {
    out.textContent = "✗ collect() failed: " + e;
  }
});
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
    let port = arg(&args, "--port", "8081");
    let origin = arg(&args, "--origin", "https://anchor.com");
    let epoch = arg(&args, "--epoch", "demo-epoch-1");
    let cert = arg(&args, "--cert", "");
    let key = arg(&args, "--key", "");

    let mut anchor = AnchorServer::new(&origin, epoch.as_bytes());
    eprintln!("ANCHOR_KEY {}", b64_encode(&anchor.public_key()));
    eprintln!("ANCHOR_COMMITMENT {}", anchor.commitment_json());

    let addr = format!("127.0.0.1:{port}");
    if let Err(e) = serve(&addr, &cert, &key, |request| {
        if request.path == "/" || request.path == "/index.html" {
            return Response {
                status: 200,
                headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
                body: PAGE.as_bytes().to_vec(),
            };
        }
        anchor.handle(request)
    }) {
        eprintln!("[mole-demo-anchor] fatal: {e}");
        std::process::exit(1);
    }
}
