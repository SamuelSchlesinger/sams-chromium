// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Demo Relying-Party Origin HTTPS server (`shoes.com` / `socks.com`).
//! Challenges with `401 Mole-Challenge`, verifies `Sec-Mole-Authorization`
//! P-256 ECDSA `ClearanceToken`s locally alongside `Authorization: Bearer`,
//! and emits `Mole-Info` / behavioral reward updates.

use std::path::PathBuf;
use std::sync::Arc;

use mole_core::http::b64_decode;
use mole_demo::{OriginServer, OriginServerConfig, serve, tls};

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port = arg(&args, "--port", "8443");
    let origin = arg(&args, "--origin", "https://shoes.com");
    let moderator_origin = arg(&args, "--moderator", "https://antifraud.com");
    let policy_id = arg(&args, "--policy", "antifraud-v2");
    let clearance_key_b64 = arg(&args, "--clearance-key", "");
    let cost: u64 = arg(&args, "--cost", "1").parse().unwrap_or(1);
    let mod_feedback_addr = arg(&args, "--moderator-addr", "");
    let reward: u64 = arg(&args, "--reward", "3").parse().unwrap_or(3);
    let web_dir = arg(&args, "--web-dir", "");
    let cert = arg(&args, "--cert", "");
    let key = arg(&args, "--key", "");

    let Ok(clearance_public_key) = b64_decode(&clearance_key_b64) else {
        eprintln!("[mole-demo-origin] --clearance-key must be unpadded base64url");
        std::process::exit(2);
    };

    let client_ctx = (!cert.is_empty())
        .then(|| tls::SslContext::new_client(&cert).ok().map(Arc::new))
        .flatten();
    let reward_refund_amount =
        (!mod_feedback_addr.is_empty()).then_some((mod_feedback_addr, reward));
    let web_root = (!web_dir.is_empty()).then(|| PathBuf::from(web_dir));

    let mut server = match OriginServer::new(
        OriginServerConfig {
            origin,
            moderator_origin,
            policy_id,
            clearance_public_key,
            cost,
            reward_refund_amount,
            web_root,
        },
        client_ctx,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[mole-demo-origin] {e}");
            std::process::exit(2);
        }
    };

    let addr = format!("127.0.0.1:{port}");
    if let Err(e) = serve(&addr, &cert, &key, |request| server.handle(request)) {
        eprintln!("[mole-demo-origin] fatal: {e}");
        std::process::exit(1);
    }
}
