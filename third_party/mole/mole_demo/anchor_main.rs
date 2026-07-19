// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The demo Anchor server. Usage:
//!   mole_demo_anchor --port 8081 --epoch demo-epoch-1
//! Prints `ANCHOR_KEY <b64>` and `ANCHOR_COMMITMENT <json>` to stderr for the
//! launch script to assemble the browser's key-commitment registry.

use mole_core::http::b64_encode;
use mole_demo::{serve, AnchorServer, Response};

const PAGE: &str = r#"<!doctype html>
<meta charset=utf-8><title>anchor.com — your identity provider</title>
<style>body{font:16px system-ui;max-width:40em;margin:3em auto;padding:0 1em}
button{font:inherit;padding:.5em 1em}pre{background:#f4f4f4;padding:1em;white-space:pre-wrap}
a{color:#06c}</style>
<h1>🔒 anchor.com</h1>
<p>anchor.com is an identity provider, the kind of site that already knows you
are a real, distinct person: a bank, say, or a government ID service. Ask it
for an endorsement and it hands one to your browser. You can show that
endorsement to other sites to prove you are a real person, and they still
cannot tell who you are.</p>
<p>You are signed in here, so anchor.com endorses your browser on its own,
just because you loaded this page. No button, no CAPTCHA.</p>
<pre id=out>issuing your endorsement…</pre>
<p>Then try
<a href="https://shoes.com">👟 shoes.com</a> and
<a href="https://socks.com">🧦 socks.com</a>. Both check visitors through the
same anti-fraud service, and neither one can tell it is you.</p>
<script>
window.addEventListener("load", async () => {
  if (!navigator.endorsement) {
    out.textContent = "navigator.endorsement is unavailable in this browser.";
    return;
  }
  try {
    await navigator.endorsement.collect("https://anchor.com");
    out.textContent = "✓ Done. Your browser now holds an endorsement. It can "
      + "present this at other sites, and none of them can trace it back to "
      + "you, not even anchor.com.";
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
    let epoch = arg(&args, "--epoch", "demo-epoch-1");
    let cert = arg(&args, "--cert", "");
    let key = arg(&args, "--key", "");

    let mut anchor = AnchorServer::new(epoch.as_bytes());
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
