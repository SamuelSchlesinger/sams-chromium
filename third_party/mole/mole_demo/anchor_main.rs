// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Demo EC-IHAT Anchor HTTPS server (`navigator.endorsement.endorse()`).

use mole_core::http::b64_encode;
use mole_demo::{AnchorServer, Response, serve};

const PAGE: &str = r#"<!doctype html>
<meta charset=utf-8><title>anchor.com — Identity Anchor</title>
<style>body{font:16px system-ui;max-width:42em;margin:3em auto;padding:0 1em}
button{font:inherit;padding:.55em 1.1em;cursor:pointer}
pre{background:#f4f4f4;padding:1em;white-space:pre-wrap}</style>
<h1>🔒 anchor.com</h1>
<p>Click below (transient user activation) to obtain a batch of unlinkable
EC-IHAT endorsements via <code>navigator.endorsement.endorse()</code>.</p>
<p><button id=btn>Endorse Browser</button></p>
<pre id=out>Ready.</pre>
<p>Next visit <a href="https://shoes.com">👟 shoes.com</a> and
<a href="https://socks.com">🧦 socks.com</a> (moderated by
<a href="https://antifraud.com">🛡️ antifraud.com</a>).</p>
<script>
document.getElementById("btn").addEventListener("click", async () => {
  const out = document.getElementById("out");
  if (!navigator.endorsement) {
    out.textContent = "navigator.endorsement is not enabled.";
    return;
  }
  try {
    out.textContent = "Running 2-RTT EC-IHAT grant…";
    await navigator.endorsement.endorse({
      authorization: "Bearer demo-idp-session-assertion"
    });
    out.textContent = "✓ Endorsed! Unlinkable EC-IHAT endorsements stored in encrypted SQLite.";
  } catch (e) {
    out.textContent = "✗ endorse() failed: " + e;
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
    let port = arg(&args, "--port", "8441");
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
