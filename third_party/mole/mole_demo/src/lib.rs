// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! 4-Origin Split Moderation & Redemption HTTPS demo & TLS 1.3 E2E test suite.
//!
//! Implements wire-exact counterparts to `//components/moderated_endorsements`:
//! - BoringSSL TLS 1.3 server and client wrappers (`tls::SslContext`,
//!   `tls::SslStream`).
//! - `AnchorServer`: `GET /.well-known/mole-anchor` and 2-RTT `POST /mole/grant`
//!   (`GrantRequest -> GrantCommitments -> GrantChallenges -> GrantResponses`)
//!   issuing unlinkable `EC-IHAT` Endorsement batches.
//! - `SplitModeratorServer`: Split Moderation & Redemption (`GET /.well-known/mole-moderator`,
//!   `POST /mole/v1/issue` with 5-minute `(nullifier_A, idempotency_key)` replay
//!   cache and `>= 3` Anchor Set enforcement, `POST /mole/v1/present` minting
//!   P-256 ECDSA `ClearanceToken`s in both immediate `200` and deferred `202 Held`
//!   modes, `POST /mole/v1/feedback`, and `POST /mole/v1/settle` supporting both
//!   `session_handle` and 96-byte `RecoveryHandle` crash recovery).
//! - `OriginServer`: HTTPS relying-party Origin (`shoes.com`, `socks.com`) that
//!   challenges with `401 Mole-Challenge`, locally verifies `Sec-Mole-Authorization`
//!   P-256 ECDSA `ClearanceToken`s alongside `Authorization: Bearer`, emits
//!   `Mole-Info: session="...", settle-ready=?1`, and posts behavioral reward
//!   feedback to the Moderator over TLS 1.3.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bssl_crypto::{ec::P256, ecdsa};
use mole_core::act::{compute_ec_act_key_id, derive_ctx_cred};
use mole_core::config::{AnchorConfiguration, validate_https_origin};
use mole_core::http::{
    MoleAuthorization, MoleChallenge, MoleCredential, b64_encode,
    format_endorsement_response_media_type, format_www_authenticate,
    parse_endorsement_request_media_type,
};
use mole_core::messages::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, EcIhatGrantPost, GrantCommitments, GrantResponses, ProtectedRequestContext,
    RecoveryHandle, RedemptionChallenge,
};
use mole_core::split::{
    ClearanceToken, IssueRequestEnvelope, IssueResponseEnvelope, MOLE_ENVELOPE_MEDIA_TYPE,
    MoleInfo, PresentRequestEnvelope, PresentResponseEnvelope, SecMoleAuthorization,
    SettleRequestEnvelope, SettleResponseEnvelope, SplitMoleChallenge,
};
use mole_core::wire::Wire as _;
use mole_core::{
    CIPHERSUITE_P256_SHA256, EC_IHAT_CTX_RED, credential_type, endorsement_type, fill_random,
    sha256,
};
use zeroize::Zeroizing;

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn compute_split_ctx_spend(
    req_ctx: &ProtectedRequestContext,
    cost: u64,
    max_top_up: u64,
    credential_context: &[u8],
) -> Result<[u8; 32], String> {
    let rc_bytes = req_ctx.to_bytes().map_err(|e| e.to_string())?;
    let act_chal = EcActChallenge {
        spend_amount: cost,
        max_top_up,
        credential_context: credential_context.to_vec(),
        request_context: rc_bytes,
    };
    act_chal.ctx_spend().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 + BoringSSL TLS 1.3 Server & Client
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn json(status: u16, body: String) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into_bytes(),
        }
    }

    pub fn binary(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn content_type(&self) -> &str {
        self.header("Content-Type").unwrap_or("")
    }

    pub fn authorization(&self) -> &str {
        self.header("Authorization").unwrap_or("")
    }

    pub fn sec_mole_authorization(&self) -> Option<&str> {
        self.header("Sec-Mole-Authorization")
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

pub fn read_request<S: Read>(stream: &mut S) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let k = name.trim().to_string();
            let v = value.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }

    if content_length > 2 * 1024 * 1024 {
        return None;
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

pub fn write_response<W: Write>(stream: &mut W, response: &Response) {
    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status));
    out.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    out.push_str("Access-Control-Allow-Origin: *\r\n");
    out.push_str("Access-Control-Allow-Headers: *\r\n");
    for (name, value) in &response.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

pub fn read_http_response<S: Read>(stream: &mut S) -> Result<Response, String> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if reader
        .read_line(&mut status_line)
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("empty HTTP response".into());
    }
    let mut parts = status_line.split_whitespace();
    let _http_ver = parts.next().ok_or("missing HTTP version")?;
    let status: u16 = parts
        .next()
        .ok_or("missing status")?
        .parse()
        .map_err(|_| "bad status code")?;

    let mut content_length = 0usize;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let k = name.trim().to_string();
            let v = value.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

pub mod tls {
    use bssl_sys::{
        SSL, SSL_CTX, SSL_CTX_free, SSL_CTX_load_verify_locations, SSL_CTX_new,
        SSL_CTX_set_min_proto_version, SSL_CTX_set_verify, SSL_CTX_use_PrivateKey_file,
        SSL_CTX_use_certificate_chain_file, SSL_VERIFY_PEER, SSL_accept, SSL_connect, SSL_free,
        SSL_new, SSL_read, SSL_set_fd, SSL_shutdown, SSL_write, TLS_client_method,
        TLS_server_method, TLS1_3_VERSION,
    };
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_void};

    const SSL_FILETYPE_PEM: c_int = 1;

    pub struct SslContext(*mut SSL_CTX);
    // SAFETY: BoringSSL `SSL_CTX` is thread-safe after initialization for
    // spawning per-connection `SSL*` state across threads.
    unsafe impl Send for SslContext {}
    unsafe impl Sync for SslContext {}

    impl SslContext {
        pub fn new_server(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
            // SAFETY: BoringSSL `SSL_CTX` initialization with null & return checks.
            unsafe {
                let ctx = SSL_CTX_new(TLS_server_method());
                if ctx.is_null() {
                    return Err("SSL_CTX_new(server) failed".into());
                }
                SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION as u16);
                let cert = CString::new(cert_pem).map_err(|_| "bad cert path")?;
                let key = CString::new(key_pem).map_err(|_| "bad key path")?;
                if SSL_CTX_use_certificate_chain_file(ctx, cert.as_ptr()) != 1 {
                    SSL_CTX_free(ctx);
                    return Err(format!("cannot load certificate {cert_pem}"));
                }
                if SSL_CTX_use_PrivateKey_file(ctx, key.as_ptr(), SSL_FILETYPE_PEM) != 1 {
                    SSL_CTX_free(ctx);
                    return Err(format!("cannot load private key {key_pem}"));
                }
                Ok(SslContext(ctx))
            }
        }

        pub fn new_client(ca_cert_pem: &str) -> Result<Self, String> {
            // SAFETY: BoringSSL client `SSL_CTX` pinned to TLS 1.3 + `ca_cert_pem`.
            unsafe {
                let ctx = SSL_CTX_new(TLS_client_method());
                if ctx.is_null() {
                    return Err("SSL_CTX_new(client) failed".into());
                }
                SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION as u16);
                let ca = CString::new(ca_cert_pem).map_err(|_| "bad ca path")?;
                if SSL_CTX_load_verify_locations(ctx, ca.as_ptr(), std::ptr::null()) != 1 {
                    SSL_CTX_free(ctx);
                    return Err(format!("cannot load CA certificate {ca_cert_pem}"));
                }
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, None);
                Ok(SslContext(ctx))
            }
        }
    }

    impl Drop for SslContext {
        fn drop(&mut self) {
            // SAFETY: `self.0` was allocated by `SSL_CTX_new`.
            unsafe { SSL_CTX_free(self.0) };
        }
    }

    pub struct SslStream {
        ssl: *mut SSL,
        _tcp: TcpStream,
    }

    impl SslStream {
        pub fn accept(ctx: &SslContext, tcp: TcpStream) -> Result<SslStream, String> {
            // SAFETY: `ctx.0` is valid and `_tcp` outlives `ssl`.
            unsafe {
                let ssl = SSL_new(ctx.0);
                if ssl.is_null() {
                    return Err("SSL_new failed".into());
                }
                SSL_set_fd(ssl, tcp.as_raw_fd());
                if SSL_accept(ssl) != 1 {
                    SSL_free(ssl);
                    return Err("TLS 1.3 server handshake failed".into());
                }
                Ok(SslStream { ssl, _tcp: tcp })
            }
        }

        pub fn connect(ctx: &SslContext, tcp: TcpStream) -> Result<SslStream, String> {
            // SAFETY: `ctx.0` is valid and `_tcp` outlives `ssl`.
            unsafe {
                let ssl = SSL_new(ctx.0);
                if ssl.is_null() {
                    return Err("SSL_new failed".into());
                }
                SSL_set_fd(ssl, tcp.as_raw_fd());
                if SSL_connect(ssl) != 1 {
                    SSL_free(ssl);
                    return Err("TLS 1.3 client handshake failed".into());
                }
                Ok(SslStream { ssl, _tcp: tcp })
            }
        }
    }

    impl Read for SslStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // SAFETY: `buf` is valid for `buf.len()` writable bytes.
            let n =
                unsafe { SSL_read(self.ssl, buf.as_mut_ptr() as *mut c_void, buf.len() as c_int) };
            Ok(if n <= 0 { 0 } else { n as usize })
        }
    }

    impl Write for SslStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // SAFETY: `buf` is valid for `buf.len()` readable bytes.
            let n =
                unsafe { SSL_write(self.ssl, buf.as_ptr() as *const c_void, buf.len() as c_int) };
            if n <= 0 {
                Err(io::Error::other("SSL_write failed"))
            } else {
                Ok(n as usize)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for SslStream {
        fn drop(&mut self) {
            // SAFETY: `self.ssl` was allocated by `SSL_new`.
            unsafe {
                SSL_shutdown(self.ssl);
                SSL_free(self.ssl);
            }
        }
    }
}

pub fn https_request(
    client_ctx: &tls::SslContext,
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Response, String> {
    let tcp = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut ssl = tls::SslStream::connect(client_ctx, tcp)?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    ssl.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    if !body.is_empty() {
        ssl.write_all(body).map_err(|e| e.to_string())?;
    }
    ssl.flush().map_err(|e| e.to_string())?;
    read_http_response(&mut ssl)
}

pub fn serve<F: FnMut(&Request) -> Response>(
    addr: &str,
    cert_pem: &str,
    key_pem: &str,
    mut handler: F,
) -> std::io::Result<()> {
    let ctx = tls::SslContext::new_server(cert_pem, key_pem).map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(addr)?;
    eprintln!("[mole-demo] listening (TLS 1.3) on {addr}");
    for stream in listener.incoming() {
        let Ok(tcp) = stream else { continue };
        let Ok(mut ssl) = tls::SslStream::accept(&ctx, tcp) else {
            continue;
        };
        if let Some(request) = read_request(&mut ssl) {
            let response = if request.method == "OPTIONS" {
                Response::text(204, "")
            } else {
                handler(&request)
            };
            write_response(&mut ssl, &response);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Anchor Server (`EC-IHAT` 2-RTT Batch Grant)
// ---------------------------------------------------------------------------

const SESSION_TTL: Duration = Duration::from_secs(300);

fn is_mole_envelope_content_type(ct: &str) -> bool {
    let essence = ct.split(';').next().unwrap_or("").trim();
    essence.eq_ignore_ascii_case(MOLE_ENVELOPE_MEDIA_TYPE)
}

pub struct AnchorServer {
    origin: String,
    key: ec_ihat::SecretKey,
    issuance_epoch: Vec<u8>,
    open_sessions: HashMap<[u8; 32], (Instant, Vec<ec_ihat::AnchorState>)>,
    consumed_sessions: HashMap<[u8; 32], Instant>,
}

impl AnchorServer {
    pub fn new(origin: &str, epoch: &[u8]) -> AnchorServer {
        let mut seed = Zeroizing::new([0u8; 48]);
        fill_random(&mut *seed).expect("RNG succeeds");
        let key = ec_ihat::SecretKey::from_seed(&seed).expect("Anchor key derives");
        let canon_origin = validate_https_origin(origin.trim_end_matches('/'))
            .unwrap_or_else(|_| "https://anchor.com".into());
        AnchorServer {
            origin: canon_origin,
            key,
            issuance_epoch: epoch.to_vec(),
            open_sessions: HashMap::new(),
            consumed_sessions: HashMap::new(),
        }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
    }

    pub fn epoch(&self) -> &[u8] {
        &self.issuance_epoch
    }

    pub fn grant_uri(&self) -> String {
        format!("{}/mole/grant", self.origin)
    }

    pub fn configuration_json(&self) -> String {
        let cfg = AnchorConfiguration {
            grant_uri: self.grant_uri(),
            endorsement_type: endorsement_type::EC_IHAT,
            ciphersuite: CIPHERSUITE_P256_SHA256.into(),
            anchor_key: b64_encode(&self.public_key()),
            issuance_epoch: b64_encode(&self.issuance_epoch),
        };
        serde_json::to_string(&cfg).expect("AnchorConfiguration serializes")
    }

    pub fn commitment_value(&self) -> serde_json::Value {
        serde_json::json!({
            "grant-uri": self.grant_uri(),
            "keys": [b64_encode(&self.public_key())],
            "epochs": [b64_encode(&self.issuance_epoch)],
        })
    }

    pub fn commitment_json(&self) -> String {
        self.commitment_value().to_string()
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        if request.path == "/.well-known/mole-anchor" && request.method == "GET" {
            return Response::json(200, self.configuration_json());
        }
        if request.path == "/mole/grant" && request.method == "POST" {
            return self.grant(request.content_type(), &request.body);
        }
        Response::text(404, "not found\n")
    }

    fn grant(&mut self, content_type: &str, body: &[u8]) -> Response {
        match parse_endorsement_request_media_type(content_type) {
            Ok(t) if t == endorsement_type::EC_IHAT => {}
            _ => {
                return Response::text(
                    415,
                    "expected application/mole-endorsement-request; type=0002\n",
                );
            }
        }
        let Ok(post) = EcIhatGrantPost::from_bytes(body) else {
            return Response::text(400, "malformed grant message\n");
        };
        let Ok(resp_ct) = format_endorsement_response_media_type(endorsement_type::EC_IHAT) else {
            return Response::text(500, "media type error\n");
        };
        match post {
            EcIhatGrantPost::Request(req) => {
                self.open_sessions
                    .retain(|_, (created_at, _)| created_at.elapsed() <= SESSION_TTL);
                self.consumed_sessions
                    .retain(|_, created_at| created_at.elapsed() <= SESSION_TTL);
                let n = usize::from(req.count.min(64));
                let mut states = Vec::with_capacity(n);
                let mut commitments = Vec::with_capacity(n);
                for _ in 0..n {
                    let Ok((st, com)) = ec_ihat::commit(&self.issuance_epoch) else {
                        return Response::text(500, "commit error\n");
                    };
                    states.push(st);
                    commitments.push(com);
                }
                let mut session_id = [0u8; 32];
                if fill_random(&mut session_id).is_err() {
                    return Response::text(500, "rng error\n");
                }
                self.open_sessions
                    .insert(session_id, (Instant::now(), states));
                let Ok(wire) = (GrantCommitments {
                    session_id,
                    commitments,
                })
                .to_bytes() else {
                    return Response::text(500, "encode GrantCommitments failed\n");
                };
                Response::binary(200, &resp_ct, wire)
            }
            EcIhatGrantPost::Challenges(ch) => {
                if self.consumed_sessions.contains_key(&ch.session_id) {
                    return Response::text(409, "replayed session_id\n");
                }
                let Some((created_at, states)) = self.open_sessions.remove(&ch.session_id) else {
                    return Response::text(400, "unknown session_id\n");
                };
                if created_at.elapsed() > SESSION_TTL {
                    return Response::text(400, "expired session_id\n");
                }
                self.consumed_sessions.insert(ch.session_id, Instant::now());
                if states.len() != ch.challenges.len() {
                    return Response::text(400, "batch challenge count mismatch\n");
                }
                let mut responses = Vec::with_capacity(states.len());
                for (st, chal) in states.into_iter().zip(&ch.challenges) {
                    let Ok(resp) = ec_ihat::respond(&self.key, st, chal) else {
                        return Response::text(400, "respond failed\n");
                    };
                    responses.push(resp);
                }
                let Ok(wire) = (GrantResponses { responses }).to_bytes() else {
                    return Response::text(500, "encode GrantResponses failed\n");
                };
                Response::binary(200, &resp_ct, wire)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Split Moderator Server (`#188` + `#186` + `#34` + `#152`)
// ---------------------------------------------------------------------------

struct CachedIssueEntry {
    idempotency_key: [u8; 32],
    response_wire: Vec<u8>,
    created_at: Instant,
}

struct RecordedSplitSession {
    recovery_handle: RecoveryHandle,
    spend_msg_bytes: Vec<u8>,
    ctx_spend: [u8; 32],
    refund_amount: u64,
    signoff_refund_amount: u64,
    created_at: Instant,
    ready_at: Instant,
    settled_update: Option<Vec<u8>>,
}

pub struct SplitModeratorConfig {
    pub origin: String,
    pub policy_id: String,
    pub credential_context: Vec<u8>,
    pub accepted_anchor_keys: Vec<Vec<u8>>,
    pub epoch: Vec<u8>,
    pub balance_width: u8,
    pub initial_balance: u64,
    pub spend_amount: u64,
    pub max_top_up: u64,
    pub default_refund_amount: u64,
    pub allowed_refund_amounts: Vec<u64>,
    pub allowed_sites: Vec<String>,
    pub hold_ms: u64,
}

pub struct SplitModeratorServer {
    cfg: SplitModeratorConfig,
    raw_anchor_keys: Vec<[u8; 33]>,
    anchor_set: Vec<ec_ihat::PublicKey>,
    ctx_cred: Vec<u8>,
    act_params: ec_act::Params,
    act_key: ec_act::SecretKey,
    clearance_sk: ecdsa::PrivateKey<P256>,
    clearance_pk_sec1: Vec<u8>,
    ihat_nullifiers: HashSet<[u8; 32]>,
    issue_idempotency_cache: HashMap<[u8; 32], CachedIssueEntry>,
    act_nullifiers: HashSet<[u8; 32]>,
    sessions_by_handle: HashMap<String, RecordedSplitSession>,
    handle_by_recovery: HashMap<RecoveryHandle, String>,
    inline_redeem_challenges: HashMap<[u8; 32], Instant>,
    inline_act_challenges: HashMap<Vec<u8>, Instant>,
    next_session_seq: u64,
}

impl SplitModeratorServer {
    pub fn new(mut cfg: SplitModeratorConfig) -> Result<Self, String> {
        if cfg.accepted_anchor_keys.len() < 3 {
            return Err("Moderator Anchor Set must contain >= 3 Anchors".into());
        }
        if cfg.balance_width == 0 || cfg.balance_width > 16 {
            return Err("balance_width must be in 1..=16".into());
        }
        let canon_origin = validate_https_origin(cfg.origin.trim_end_matches('/'))
            .map_err(|e| format!("invalid moderator origin: {e}"))?;
        cfg.origin = canon_origin;

        let mut raw_anchor_keys = Vec::with_capacity(cfg.accepted_anchor_keys.len());
        let mut anchor_set = Vec::with_capacity(cfg.accepted_anchor_keys.len());
        for raw_ak in &cfg.accepted_anchor_keys {
            let arr: [u8; 33] = raw_ak
                .as_slice()
                .try_into()
                .map_err(|_| "anchor key must be 33 bytes".to_string())?;
            let pk = <ec_ihat::PublicKey>::from_bytes(&arr)
                .map_err(|_| "invalid SEC1 EC-IHAT anchor key".to_string())?;
            raw_anchor_keys.push(arr);
            anchor_set.push(pk);
        }

        let ctx_cred = derive_ctx_cred(&cfg.credential_context, cfg.balance_width)
            .map_err(|e| format!("derive_ctx_cred: {e}"))?;
        let act_params = ec_act::Params::new(cfg.balance_width)
            .map_err(|e| format!("ec_act::Params: {e:?}"))?;
        let mut seed = Zeroizing::new([0u8; 48]);
        fill_random(&mut *seed).map_err(|e| format!("{e}"))?;
        let act_key =
            ec_act::SecretKey::from_seed(&seed).map_err(|e| format!("ACT keygen: {e:?}"))?;

        let clearance_sk = ecdsa::PrivateKey::<P256>::generate();
        let clearance_pk_sec1 = clearance_sk.to_x962_compressed().as_ref().to_vec();

        Ok(Self {
            cfg,
            raw_anchor_keys,
            anchor_set,
            ctx_cred,
            act_params,
            act_key,
            clearance_sk,
            clearance_pk_sec1,
            ihat_nullifiers: HashSet::new(),
            issue_idempotency_cache: HashMap::new(),
            act_nullifiers: HashSet::new(),
            sessions_by_handle: HashMap::new(),
            handle_by_recovery: HashMap::new(),
            inline_redeem_challenges: HashMap::new(),
            inline_act_challenges: HashMap::new(),
            next_session_seq: 1,
        })
    }

    pub fn origin(&self) -> &str {
        &self.cfg.origin
    }

    pub fn policy_id(&self) -> &str {
        &self.cfg.policy_id
    }

    pub fn clearance_public_key(&self) -> &[u8] {
        &self.clearance_pk_sec1
    }

    pub fn credential_public_key(&self) -> Vec<u8> {
        self.act_key.public_key().to_bytes().to_vec()
    }

    pub fn key_id(&self) -> [u8; 32] {
        compute_ec_act_key_id(&self.act_key.public_key())
    }

    pub fn issue_uri(&self) -> String {
        format!("{}/mole/v1/issue", self.cfg.origin)
    }

    pub fn present_uri(&self) -> String {
        format!("{}/mole/v1/present", self.cfg.origin)
    }

    pub fn settle_uri(&self) -> String {
        format!("{}/mole/v1/settle", self.cfg.origin)
    }

    pub fn configuration_json(&self) -> String {
        let cfg = serde_json::json!({
            "issuance-uri": self.issue_uri(),
            "issue-uri": self.issue_uri(),
            "present-uri": self.present_uri(),
            "settle-uri": self.settle_uri(),
            "policy-id": self.cfg.policy_id,
            "clearance-public-key": b64_encode(&self.clearance_pk_sec1),
            "allowed-sites": self.cfg.allowed_sites,
            "endorsements": [{
                "endorsement-type": endorsement_type::EC_IHAT,
                "ciphersuite": CIPHERSUITE_P256_SHA256,
                "anchor-set": self.raw_anchor_keys.iter().map(|k| b64_encode(k)).collect::<Vec<_>>(),
                "issuance-epoch": b64_encode(&self.cfg.epoch),
            }],
            "credential-keys": [{
                "credential-type": credential_type::EC_ACT,
                "ciphersuite": CIPHERSUITE_P256_SHA256,
                "credential-key": b64_encode(&self.credential_public_key()),
                "credential-context": b64_encode(&self.cfg.credential_context),
                "balance-width": self.cfg.balance_width,
                "result-retention": 300,
            }],
        });
        serde_json::to_string(&cfg).expect("ModeratorConfiguration serializes")
    }

    pub fn commitment_value(&self) -> serde_json::Value {
        let anchors: Vec<String> = self
            .raw_anchor_keys
            .iter()
            .map(|k| b64_encode(k))
            .collect();
        serde_json::json!({
            "policies": [{
                "policy-id": self.cfg.policy_id,
                "credential-context": b64_encode(&self.cfg.credential_context),
                "credential-key": b64_encode(&self.credential_public_key()),
                "clearance-public-key": b64_encode(&self.clearance_pk_sec1),
                "balance-width": self.cfg.balance_width,
                "initial-balance": self.cfg.initial_balance,
                "spend-amount": self.cfg.spend_amount,
                "max-top-up": self.cfg.max_top_up,
                "allowed-refund-amounts": self.cfg.allowed_refund_amounts,
                "min-anchor-set-size": 3,
                "accepted-anchor-keys": anchors,
                "epochs": [b64_encode(&self.cfg.epoch)],
                "allowed-sites": self.cfg.allowed_sites,
                "issuance-uri": self.issue_uri(),
                "present-uri": self.present_uri(),
                "settle-uri": self.settle_uri(),
            }]
        })
    }

    pub fn commitment_json(&self) -> String {
        self.commitment_value().to_string()
    }

    pub fn set_hold_ms(&mut self, hold_ms: u64) {
        self.cfg.hold_ms = hold_ms;
    }

    fn sweep_expired_state(&mut self) {
        self.issue_idempotency_cache
            .retain(|_, entry| entry.created_at.elapsed() <= SESSION_TTL);
        self.sessions_by_handle
            .retain(|_, sess| sess.created_at.elapsed() <= SESSION_TTL);
        self.handle_by_recovery
            .retain(|_, handle| self.sessions_by_handle.contains_key(handle));
        self.inline_redeem_challenges
            .retain(|_, t| t.elapsed() <= SESSION_TTL);
        self.inline_act_challenges
            .retain(|_, t| t.elapsed() <= SESSION_TTL);
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/.well-known/mole-moderator") => {
                Response::json(200, self.configuration_json())
            }
            ("POST", "/mole/v1/issue") => {
                if !is_mole_envelope_content_type(request.content_type()) {
                    return Response::text(415, "expected application/mole+octet-stream\n");
                }
                self.handle_issue(&request.body)
            }
            ("POST", "/mole/v1/present") => {
                if !is_mole_envelope_content_type(request.content_type()) {
                    return Response::text(415, "expected application/mole+octet-stream\n");
                }
                self.handle_present(&request.body)
            }
            ("POST", "/mole/v1/settle") => {
                if !is_mole_envelope_content_type(request.content_type()) {
                    return Response::text(415, "expected application/mole+octet-stream\n");
                }
                self.handle_settle(&request.body)
            }
            ("POST", "/mole/v1/feedback") => self.handle_feedback(&request.body),
            ("POST", "/.well-known/mole-issuer") => self.handle_inline_issuer(request),
            ("POST", "/inline/resource") => self.handle_inline_resource(request),
            ("GET", "/stats") => self.handle_stats(),
            _ => Response::text(404, "not found\n"),
        }
    }

    fn handle_issue(&mut self, body: &[u8]) -> Response {
        let Ok(req) = IssueRequestEnvelope::from_bytes(body) else {
            return Response::text(400, "malformed IssueRequestEnvelope\n");
        };
        if req.endorsement_type != endorsement_type::EC_IHAT {
            return Response::text(400, "unsupported endorsement_type\n");
        }
        let expected_key_id = self.key_id();
        if req.policy_id != self.cfg.policy_id || req.key_id != expected_key_id {
            return Response::text(400, "policy_id or key_id mismatch\n");
        }

        let mut ctx_input = Vec::new();
        ctx_input.extend_from_slice(b"MOLE-SPLIT-ISSUE-v1|");
        ctx_input.extend_from_slice(self.cfg.origin.as_bytes());
        ctx_input.push(b'|');
        ctx_input.extend_from_slice(req.policy_id.as_bytes());
        ctx_input.push(b'|');
        ctx_input.extend_from_slice(&req.idempotency_key);
        let expected_red_ctx = sha256(&ctx_input);

        let Ok(redemption) =
            <ec_ihat::Redemption>::from_bytes(&req.ihat_redeem_proof, self.anchor_set.len())
        else {
            return Response::text(400, "malformed EC-IHAT Redemption\n");
        };

        // Check `redemption_context` binding AFTER verifying or checking idempotency:
        // Note: `nullifier` is verified cryptographically via `ec_ihat::verify_redemption`
        // over `req.redemption_context` first so forged proofs can never probe cache state!
        let challenge_dig = (RedemptionChallenge {
            redemption_context: req.redemption_context,
        })
        .digest();
        let Ok(nullifier_a) = ec_ihat::verify_redemption(
            &self.anchor_set,
            &redemption,
            &self.cfg.epoch,
            EC_IHAT_CTX_RED,
            &challenge_dig,
        ) else {
            return Response::text(403, "invalid EC-IHAT ring redemption proof\n");
        };

        // 5-minute `(nullifier_A, idempotency_key)` cache check BEFORE burning
        // `nullifier_A` so dropped HTTP responses recover cleanly!
        if let Some(cached) = self.issue_idempotency_cache.get(&nullifier_a)
            && cached.created_at.elapsed() <= Duration::from_secs(300)
        {
            if cached.idempotency_key == req.idempotency_key
                && req.redemption_context == expected_red_ctx
            {
                return Response::binary(200, MOLE_ENVELOPE_MEDIA_TYPE, cached.response_wire.clone());
            }
            return Response::text(409, "replayed EC-IHAT nullifier\n");
        }
        if req.redemption_context != expected_red_ctx {
            return Response::text(400, "mismatched redemption_context\n");
        }
        if self.ihat_nullifiers.contains(&nullifier_a) {
            return Response::text(409, "replayed EC-IHAT nullifier\n");
        }

        let Ok(act_req) = EcActIssuanceRequest::from_bytes(&self.act_params, &req.act_issue_request)
        else {
            return Response::text(400, "malformed EcActIssuanceRequest\n");
        };
        if act_req.truncated_key_id != expected_key_id[31]
            || act_req.credential_context != self.cfg.credential_context
        {
            return Response::text(400, "wrong truncated_key_id or credential_context\n");
        }
        let Ok(verified_req) = ec_act::verify_issue_request(&self.act_params, &act_req.request)
        else {
            return Response::text(400, "invalid EC-ACT IssueRequest proof\n");
        };
        let Ok(issue_resp) = ec_act::issue_response(
            &self.act_key,
            &self.ctx_cred,
            self.cfg.initial_balance,
            verified_req,
        ) else {
            return Response::text(400, "EC-ACT blind issue_response failed\n");
        };

        let Ok(resp_wire) = (IssueResponseEnvelope {
            act_issue_response: (EcActIssuanceResponse {
                response: issue_resp,
            })
            .to_bytes(),
            initial_credit: self.cfg.initial_balance,
        })
        .to_bytes() else {
            return Response::text(500, "encode IssueResponseEnvelope failed\n");
        };

        self.sweep_expired_state();
        self.ihat_nullifiers.insert(nullifier_a);
        self.issue_idempotency_cache.insert(
            nullifier_a,
            CachedIssueEntry {
                idempotency_key: req.idempotency_key,
                response_wire: resp_wire.clone(),
                created_at: Instant::now(),
            },
        );
        Response::binary(200, MOLE_ENVELOPE_MEDIA_TYPE, resp_wire)
    }

    fn handle_present(&mut self, body: &[u8]) -> Response {
        self.sweep_expired_state();
        let Ok(req) = PresentRequestEnvelope::from_bytes(body) else {
            return Response::text(400, "malformed PresentRequestEnvelope\n");
        };
        let expected_key_id = self.key_id();
        if req.policy_id != self.cfg.policy_id || req.key_id != expected_key_id {
            return Response::text(400, "policy_id or key_id mismatch\n");
        }
        if !self.cfg.allowed_sites.is_empty()
            && !self
                .cfg
                .allowed_sites
                .iter()
                .any(|s| s == "*" || s == &req.target_origin)
        {
            return Response::text(403, "target_origin not in allowed_sites\n");
        }

        let Ok(pau) = EcActPresentationAndUpdate::from_bytes(&self.act_params, &req.act_presentation)
        else {
            return Response::text(400, "malformed EcActPresentationAndUpdate\n");
        };
        if pau.key_id != expected_key_id {
            return Response::text(401, "unknown or rotated key_id\n");
        }
        if pau.spend.amount() != req.cost
            || req.cost > self.cfg.spend_amount
            || pau.spend.allowance() != req.max_top_up
            || req.max_top_up > self.cfg.max_top_up
        {
            return Response::text(400, "spend amount or max_top_up out of policy bounds\n");
        }

        let nullifier_k = pau.spend.nullifier();
        if self.act_nullifiers.contains(&nullifier_k) {
            return Response::text(409, "replayed EC-ACT spend nullifier\n");
        }

        let prc = req.protected_request_context();
        let Ok(ctx_spend) = compute_split_ctx_spend(
            &prc,
            req.cost,
            req.max_top_up,
            &self.cfg.credential_context,
        ) else {
            return Response::text(400, "invalid ProtectedRequestContext\n");
        };

        let spend_msg_bytes = pau.spend.to_bytes().to_vec();
        let rec_handle = pau.recovery_handle();
        let Ok(verified_spend) = ec_act::verify_spend(
            &self.act_params,
            &self.act_key,
            &self.ctx_cred,
            &ctx_spend,
            &pau.spend,
        ) else {
            return Response::text(403, "invalid EC-ACT spend proof\n");
        };
        self.act_nullifiers.insert(nullifier_k);

        let session_handle = format!("sess-{:08x}", self.next_session_seq);
        self.next_session_seq += 1;
        let now = now_unix_secs();

        let is_deferred = req.allow_deferred && self.cfg.hold_ms > 0;
        let mut token = ClearanceToken {
            version: ClearanceToken::VERSION,
            moderator_origin: self.cfg.origin.clone(),
            policy_id: self.cfg.policy_id.clone(),
            target_origin: req.target_origin,
            method: req.method,
            path_and_query: req.path_and_query,
            challenge_nonce: req.challenge_nonce,
            cost: req.cost,
            issued_at: now,
            expires_at: now + 120,
            session_id: if is_deferred {
                session_handle.clone()
            } else {
                String::new()
            },
            signature: [0u8; 64],
        };
        let Ok(signing_payload) = token.signing_payload() else {
            return Response::text(500, "ClearanceToken signing_payload failed\n");
        };
        let Ok(sig_arr) = self
            .clearance_sk
            .sign_p1363(&signing_payload)
            .as_slice()
            .try_into()
        else {
            return Response::text(500, "ECDSA signature length error\n");
        };
        token.signature = sig_arr;
        let Ok(token_bytes) = token.to_bytes() else {
            return Response::text(500, "ClearanceToken encode failed\n");
        };

        if is_deferred {
            let now_inst = Instant::now();
            self.handle_by_recovery
                .insert(rec_handle, session_handle.clone());
            self.sessions_by_handle.insert(
                session_handle.clone(),
                RecordedSplitSession {
                    recovery_handle: rec_handle,
                    spend_msg_bytes,
                    ctx_spend,
                    refund_amount: self.cfg.default_refund_amount,
                    signoff_refund_amount: self.cfg.spend_amount,
                    created_at: now_inst,
                    ready_at: now_inst + Duration::from_millis(self.cfg.hold_ms),
                    settled_update: None,
                },
            );
            let min_ms = self.cfg.hold_ms.min(u32::MAX as u64) as u32;
            let max_ms = self.cfg.hold_ms.saturating_add(30_000).min(u32::MAX as u64) as u32;
            let Ok(wire) = (PresentResponseEnvelope::Held {
                clearance_token: token_bytes,
                session_handle,
                min_delay_ms: min_ms,
                max_hold_ms: max_ms,
            })
            .to_bytes() else {
                return Response::text(500, "encode Held response failed\n");
            };
            return Response::binary(202, MOLE_ENVELOPE_MEDIA_TYPE, wire);
        }

        let Ok(refund) = ec_act::issue_refund(verified_spend, self.cfg.default_refund_amount)
        else {
            return Response::text(500, "EC-ACT refund failed\n");
        };
        let upd_bytes = (EcActUpdate { refund }).to_bytes();
        let now_inst = Instant::now();
        self.handle_by_recovery
            .insert(rec_handle, session_handle.clone());
        self.sessions_by_handle.insert(
            session_handle,
            RecordedSplitSession {
                recovery_handle: rec_handle,
                spend_msg_bytes,
                ctx_spend,
                refund_amount: self.cfg.default_refund_amount,
                signoff_refund_amount: self.cfg.spend_amount,
                created_at: now_inst,
                ready_at: now_inst,
                settled_update: Some(upd_bytes.clone()),
            },
        );
        let Ok(wire) = (PresentResponseEnvelope::Settled {
            clearance_token: token_bytes,
            act_refund_response: upd_bytes,
        })
        .to_bytes() else {
            return Response::text(500, "encode Settled response failed\n");
        };
        Response::binary(200, MOLE_ENVELOPE_MEDIA_TYPE, wire)
    }

    fn handle_feedback(&mut self, body: &[u8]) -> Response {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Response::text(400, "malformed JSON feedback\n");
        };
        let Some(session_id) = v.get("session").and_then(|s| s.as_str()) else {
            return Response::text(400, "missing session\n");
        };
        let Some(refund) = v.get("refund_amount").and_then(|r| r.as_u64()) else {
            return Response::text(400, "missing refund_amount\n");
        };
        if !self.cfg.allowed_refund_amounts.is_empty()
            && !self.cfg.allowed_refund_amounts.contains(&refund)
        {
            return Response::text(400, "refund_amount not in allowed_refund_amounts\n");
        }
        let Some(sess) = self.sessions_by_handle.get_mut(session_id) else {
            return Response::text(404, "unknown session\n");
        };
        sess.refund_amount = refund;
        sess.ready_at = Instant::now();
        Response::json(200, r#"{"ok":true}"#.into())
    }

    fn handle_settle(&mut self, body: &[u8]) -> Response {
        let Ok(req) = SettleRequestEnvelope::from_bytes(body) else {
            return Response::text(400, "malformed SettleRequestEnvelope\n");
        };
        let handle = if !req.session_handle.is_empty() {
            req.session_handle
        } else if let Some(rec) = req.recovery_handle {
            match self.handle_by_recovery.get(&rec) {
                Some(h) => h.clone(),
                None => return Response::text(404, "unknown recovery_handle\n"),
            }
        } else {
            return Response::text(400, "missing session_handle and recovery_handle\n");
        };

        let Some(sess) = self.sessions_by_handle.get_mut(&handle) else {
            return Response::text(404, "unknown session_handle\n");
        };
        if let Some(rec) = req.recovery_handle
            && rec != sess.recovery_handle
        {
            return Response::text(403, "recovery_handle mismatch\n");
        }

        if sess.settled_update.is_none() {
            let now_inst = Instant::now();
            if !req.is_signoff && now_inst < sess.ready_at {
                let rem_ms = sess
                    .ready_at
                    .duration_since(now_inst)
                    .as_millis()
                    .clamp(10, u32::MAX as u128) as u32;
                let Ok(wire) = (SettleResponseEnvelope::Pending {
                    retry_after_ms: rem_ms,
                })
                .to_bytes() else {
                    return Response::text(500, "encode Pending failed\n");
                };
                return Response::binary(202, MOLE_ENVELOPE_MEDIA_TYPE, wire);
            }
            let effective_refund = if req.is_signoff {
                sess.signoff_refund_amount
            } else {
                sess.refund_amount
            };
            let Ok(spend) =
                <ec_act::SpendMessage>::from_bytes(&self.act_params, &sess.spend_msg_bytes)
            else {
                return Response::text(500, "stored SpendMessage corrupted\n");
            };
            let Ok(verified_spend) = ec_act::verify_spend(
                &self.act_params,
                &self.act_key,
                &self.ctx_cred,
                &sess.ctx_spend,
                &spend,
            ) else {
                return Response::text(500, "settle verify_spend failed\n");
            };
            let Ok(refund) = ec_act::issue_refund(verified_spend, effective_refund) else {
                return Response::text(500, "settle issue_refund failed\n");
            };
            sess.settled_update = Some((EcActUpdate { refund }).to_bytes());
        }

        let act_refund_response = sess.settled_update.clone().unwrap_or_default();
        let Ok(wire) = (SettleResponseEnvelope::Settled {
            act_refund_response,
        })
        .to_bytes() else {
            return Response::text(500, "encode Settled failed\n");
        };
        Response::binary(200, MOLE_ENVELOPE_MEDIA_TYPE, wire)
    }

    fn handle_stats(&self) -> Response {
        let nullifiers: Vec<String> = self
            .act_nullifiers
            .iter()
            .map(|n| b64_encode(n))
            .collect();
        let held_count = self
            .sessions_by_handle
            .values()
            .filter(|s| s.settled_update.is_none())
            .count();
        let settled_count = self
            .sessions_by_handle
            .values()
            .filter(|s| s.settled_update.is_some())
            .count();
        let json = serde_json::json!({
            "redemptions": self.ihat_nullifiers.len(),
            "presentations": self.act_nullifiers.len(),
            "held_sessions": held_count,
            "settled_sessions": settled_count,
            "nullifiers": nullifiers,
        });
        Response::json(200, json.to_string())
    }

    // --- `-01` Inline HTTP Authentication (`WWW-Authenticate: Mole` / `Authorization: Mole` / `Mole-Credential`) ---

    fn handle_inline_resource(&mut self, request: &Request) -> Response {
        self.sweep_expired_state();
        let raw_auth = request.authorization();
        if raw_auth.is_empty() {
            let mut redeem_ctx = [0u8; 32];
            fill_random(&mut redeem_ctx).expect("RNG succeeds");
            self.inline_redeem_challenges
                .insert(redeem_ctx, Instant::now());

            let mut req_nonce = vec![0u8; 16];
            fill_random(&mut req_nonce).expect("RNG succeeds");
            let act_chal = EcActChallenge {
                spend_amount: self.cfg.spend_amount,
                max_top_up: self.cfg.max_top_up,
                credential_context: self.cfg.credential_context.clone(),
                request_context: req_nonce,
            };
            let act_chal_bytes = act_chal.to_bytes().expect("EcActChallenge encodes");
            self.inline_act_challenges
                .insert(act_chal_bytes.clone(), Instant::now());

            let www = format_www_authenticate(&[
                MoleChallenge::Credential {
                    credential_type: credential_type::EC_ACT,
                    challenge: act_chal_bytes,
                },
                MoleChallenge::Redeem {
                    endorsement_type: endorsement_type::EC_IHAT,
                    challenge: redeem_ctx,
                },
            ])
            .expect("format_www_authenticate");
            return Response {
                status: 401,
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("WWW-Authenticate".into(), www),
                ],
                body: br#"{"error":"inline_mole_required"}"#.to_vec(),
            };
        }

        let Ok(MoleAuthorization::Presentation {
            credential_type: ctype,
            presentation,
        }) = MoleAuthorization::parse(raw_auth)
        else {
            return Response::text(400, "expected Authorization: Mole presentation-0001\n");
        };
        if ctype != credential_type::EC_ACT {
            return Response::text(400, "unsupported credential_type\n");
        }
        let Ok(pau) = EcActPresentationAndUpdate::from_bytes(&self.act_params, &presentation) else {
            return Response::text(400, "malformed EcActPresentationAndUpdate\n");
        };
        if pau.key_id != self.key_id() {
            return Response::text(401, "unknown key_id\n");
        }
        let nullifier_k = pau.spend.nullifier();
        if self.act_nullifiers.contains(&nullifier_k) {
            return Response::text(409, "replayed EC-ACT spend nullifier\n");
        }

        // Match against active inline challenges.
        let mut matched: Option<(Vec<u8>, [u8; 32], ec_act::VerifiedSpend)> = None;
        for chal_bytes in self.inline_act_challenges.keys() {
            if let Ok(chal) = EcActChallenge::from_bytes(chal_bytes)
                && let Ok(ctx_spend) = chal.ctx_spend()
                && let Ok(vs) = ec_act::verify_spend(
                    &self.act_params,
                    &self.act_key,
                    &self.ctx_cred,
                    &ctx_spend,
                    &pau.spend,
                )
            {
                matched = Some((chal_bytes.clone(), ctx_spend, vs));
                break;
            }
        }
        let Some((matched_chal, ctx_spend, verified_spend)) = matched else {
            return Response::text(403, "invalid inline EC-ACT spend proof\n");
        };
        self.inline_act_challenges.remove(&matched_chal);
        self.act_nullifiers.insert(nullifier_k);

        let rec_handle = pau.recovery_handle();
        let spend_msg_bytes = pau.spend.to_bytes().to_vec();
        let session_handle = format!("inline-sess-{:08x}", self.next_session_seq);
        self.next_session_seq += 1;
        let now_inst = Instant::now();

        if self.cfg.hold_ms > 0 {
            let held_secs = self.cfg.hold_ms.div_ceil(1_000).clamp(1, 300);
            self.handle_by_recovery
                .insert(rec_handle, session_handle.clone());
            self.sessions_by_handle.insert(
                session_handle,
                RecordedSplitSession {
                    recovery_handle: rec_handle,
                    spend_msg_bytes,
                    ctx_spend,
                    refund_amount: self.cfg.default_refund_amount,
                    signoff_refund_amount: self.cfg.spend_amount,
                    created_at: now_inst,
                    ready_at: now_inst + Duration::from_millis(self.cfg.hold_ms),
                    settled_update: None,
                },
            );
            let cred_hdr = (MoleCredential::HeldForUpdate {
                credential_type: credential_type::EC_ACT,
                duration_secs: held_secs,
            })
            .to_header_value()
            .expect("HeldForUpdate formats");
            return Response {
                status: 200,
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Mole-Credential".into(), cred_hdr),
                ],
                body: br#"{"ok":true,"mode":"inline-held"}"#.to_vec(),
            };
        }

        let Ok(refund) = ec_act::issue_refund(verified_spend, self.cfg.default_refund_amount) else {
            return Response::text(500, "inline issue_refund failed\n");
        };
        let upd_bytes = (EcActUpdate { refund }).to_bytes();
        let cred_hdr = (MoleCredential::Update {
            credential_type: credential_type::EC_ACT,
            update: Some(upd_bytes),
        })
        .to_header_value()
        .expect("Update formats");
        Response {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Mole-Credential".into(), cred_hdr),
            ],
            body: br#"{"ok":true,"mode":"inline-settled"}"#.to_vec(),
        }
    }

    fn handle_inline_issuer(&mut self, request: &Request) -> Response {
        self.sweep_expired_state();
        let Ok(auth) = MoleAuthorization::parse(request.authorization()) else {
            return Response::text(400, "malformed Authorization: Mole\n");
        };
        let is_signoff = matches!(auth, MoleAuthorization::Signoff { .. });
        match auth {
            MoleAuthorization::RedeemAndIssue {
                endorsement_type: etype,
                redemption,
                credential_type: ctype,
                credential_request,
            } => {
                if etype != endorsement_type::EC_IHAT || ctype != credential_type::EC_ACT {
                    return Response::text(400, "unsupported inline type\n");
                }
                let Ok(red_proof) =
                    <ec_ihat::Redemption>::from_bytes(&redemption, self.anchor_set.len())
                else {
                    return Response::text(400, "malformed EC-IHAT Redemption\n");
                };
                let mut verified_nullifier: Option<([u8; 32], [u8; 32])> = None;
                for &chal_ctx in self.inline_redeem_challenges.keys() {
                    let dig = (RedemptionChallenge {
                        redemption_context: chal_ctx,
                    })
                    .digest();
                    if let Ok(nf) = ec_ihat::verify_redemption(
                        &self.anchor_set,
                        &red_proof,
                        &self.cfg.epoch,
                        EC_IHAT_CTX_RED,
                        &dig,
                    ) {
                        verified_nullifier = Some((chal_ctx, nf));
                        break;
                    }
                }
                let Some((matched_ctx, nullifier_a)) = verified_nullifier else {
                    return Response::text(403, "invalid inline EC-IHAT redemption\n");
                };
                if self.ihat_nullifiers.contains(&nullifier_a) {
                    return Response::text(409, "replayed EC-IHAT nullifier\n");
                }
                let Ok(act_req) =
                    EcActIssuanceRequest::from_bytes(&self.act_params, &credential_request)
                else {
                    return Response::text(400, "malformed EcActIssuanceRequest\n");
                };
                let expected_key_id = self.key_id();
                if act_req.truncated_key_id != expected_key_id[31]
                    || act_req.credential_context != self.cfg.credential_context
                {
                    return Response::text(400, "wrong key_id or credential_context\n");
                }
                let Ok(verified_req) =
                    ec_act::verify_issue_request(&self.act_params, &act_req.request)
                else {
                    return Response::text(400, "invalid EC-ACT IssueRequest\n");
                };
                let Ok(issue_resp) = ec_act::issue_response(
                    &self.act_key,
                    &self.ctx_cred,
                    self.cfg.initial_balance,
                    verified_req,
                ) else {
                    return Response::text(400, "EC-ACT issue_response failed\n");
                };
                self.inline_redeem_challenges.remove(&matched_ctx);
                self.ihat_nullifiers.insert(nullifier_a);

                let resp_bytes = (EcActIssuanceResponse {
                    response: issue_resp,
                })
                .to_bytes();
                let cred_hdr = (MoleCredential::Response {
                    credential_type: credential_type::EC_ACT,
                    response: resp_bytes,
                })
                .to_header_value()
                .expect("MoleCredential::Response formats");
                Response {
                    status: 200,
                    headers: vec![("Mole-Credential".into(), cred_hdr)],
                    body: Vec::new(),
                }
            }
            MoleAuthorization::Recovery {
                credential_type: ctype,
                recovery_handle,
            }
            | MoleAuthorization::Signoff {
                credential_type: ctype,
                recovery_handle,
            } => {
                if ctype != credential_type::EC_ACT {
                    return Response::text(400, "unsupported credential_type\n");
                }
                let Ok(rec) = RecoveryHandle::from_bytes(&recovery_handle) else {
                    return Response::text(400, "malformed RecoveryHandle\n");
                };
                let Some(handle) = self.handle_by_recovery.get(&rec).cloned() else {
                    return Response::text(404, "unknown RecoveryHandle\n");
                };
                let Some(sess) = self.sessions_by_handle.get_mut(&handle) else {
                    return Response::text(404, "unknown session\n");
                };
                if sess.settled_update.is_none() {
                    let now_inst = Instant::now();
                    if !is_signoff && now_inst < sess.ready_at {
                        let rem_secs = sess
                            .ready_at
                            .duration_since(now_inst)
                            .as_secs()
                            .clamp(1, 300);
                        let hdr = (MoleCredential::HeldForUpdate {
                            credential_type: credential_type::EC_ACT,
                            duration_secs: rem_secs,
                        })
                        .to_header_value()
                        .expect("HeldForUpdate formats");
                        return Response {
                            status: 202,
                            headers: vec![("Mole-Credential".into(), hdr)],
                            body: Vec::new(),
                        };
                    }
                    let effective_refund = if is_signoff {
                        sess.signoff_refund_amount
                    } else {
                        sess.refund_amount
                    };
                    let Ok(spend) =
                        <ec_act::SpendMessage>::from_bytes(&self.act_params, &sess.spend_msg_bytes)
                    else {
                        return Response::text(500, "corrupted spend\n");
                    };
                    let Ok(vs) = ec_act::verify_spend(
                        &self.act_params,
                        &self.act_key,
                        &self.ctx_cred,
                        &sess.ctx_spend,
                        &spend,
                    ) else {
                        return Response::text(500, "verify_spend failed\n");
                    };
                    let Ok(refund) = ec_act::issue_refund(vs, effective_refund) else {
                        return Response::text(500, "issue_refund failed\n");
                    };
                    sess.settled_update = Some((EcActUpdate { refund }).to_bytes());
                }
                let hdr = (MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: sess.settled_update.clone(),
                })
                .to_header_value()
                .expect("Update formats");
                Response {
                    status: 200,
                    headers: vec![("Mole-Credential".into(), hdr)],
                    body: Vec::new(),
                }
            }
            _ => Response::text(400, "unsupported inline operation\n"),
        }
    }
}

// ---------------------------------------------------------------------------
// Relying-Party Origin Server (`shoes.com` / `socks.com`)
// ---------------------------------------------------------------------------

pub struct OriginServerConfig {
    pub origin: String,
    pub moderator_origin: String,
    pub policy_id: String,
    pub clearance_public_key: Vec<u8>,
    pub cost: u64,
    pub reward_refund_amount: Option<(String, u64)>,
    pub web_root: Option<PathBuf>,
}

pub struct OriginServer {
    cfg: OriginServerConfig,
    clearance_pk: ecdsa::PublicKey<P256>,
    active_nonces: HashMap<Vec<u8>, Instant>,
    tls_client_ctx: Option<Arc<tls::SslContext>>,
}

impl OriginServer {
    pub fn new(
        mut cfg: OriginServerConfig,
        tls_client_ctx: Option<Arc<tls::SslContext>>,
    ) -> Result<Self, String> {
        let canon_origin = validate_https_origin(cfg.origin.trim_end_matches('/'))
            .map_err(|e| format!("invalid origin: {e}"))?;
        let canon_mod = validate_https_origin(cfg.moderator_origin.trim_end_matches('/'))
            .map_err(|e| format!("invalid moderator_origin: {e}"))?;
        cfg.origin = canon_origin;
        cfg.moderator_origin = canon_mod;

        let clearance_pk =
            ecdsa::PublicKey::<P256>::from_x962_compressed(&cfg.clearance_public_key)
                .ok_or_else(|| "invalid 33-byte SEC1 P-256 clearance_public_key".to_string())?;
        Ok(Self {
            cfg,
            clearance_pk,
            active_nonces: HashMap::new(),
            tls_client_ctx,
        })
    }

    pub fn origin(&self) -> &str {
        &self.cfg.origin
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        if request.method == "GET" && (request.path == "/" || request.path == "/index.html") {
            if let Some(root) = &self.cfg.web_root
                && let Ok(bytes) = std::fs::read(root.join("index.html"))
            {
                return Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
                    body: bytes,
                };
            }
            return Response::text(200, "MOLE Origin Server\n");
        }

        if request.method == "POST"
            && (request.path.starts_with("/api/purchase")
                || request.path.starts_with("/api/review"))
        {
            return self.handle_moderated_api(request);
        }

        Response::text(404, "not found\n")
    }

    fn handle_moderated_api(&mut self, request: &Request) -> Response {
        // Verify first-party Origin session authentication (`Authorization: Bearer ...`)
        // coexists cleanly alongside `Sec-Mole-Authorization`!
        let bearer_subject = request
            .authorization()
            .strip_prefix("Bearer ")
            .unwrap_or("anonymous")
            .to_string();

        let Some(raw_sec_mole) = request.sec_mole_authorization() else {
            self.active_nonces
                .retain(|_, t| t.elapsed() <= SESSION_TTL);
            let mut nonce = vec![0u8; 16];
            fill_random(&mut nonce).expect("RNG succeeds");
            self.active_nonces.insert(nonce.clone(), Instant::now());
            let Ok(challenge) = (SplitMoleChallenge {
                moderator: self.cfg.moderator_origin.clone(),
                policy: self.cfg.policy_id.clone(),
                cost: self.cfg.cost,
                nonce,
                max_cost: None,
                exp: None,
                sig: None,
            })
            .to_header_value() else {
                return Response::text(500, "failed to format Mole-Challenge\n");
            };
            return Response {
                status: 401,
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Mole-Challenge".into(), challenge),
                ],
                body: br#"{"error":"moderation_required"}"#.to_vec(),
            };
        };

        let Ok(sec_auth) = SecMoleAuthorization::parse(raw_sec_mole) else {
            return Response::text(400, "malformed Sec-Mole-Authorization\n");
        };
        let Ok(token) = ClearanceToken::from_bytes(&sec_auth.clearance) else {
            return Response::text(400, "malformed ClearanceToken\n");
        };
        let Ok(signing_payload) = token.signing_payload() else {
            return Response::text(400, "invalid ClearanceToken payload\n");
        };

        // 1. Verify P-256 ECDSA signature locally (`0` Origin <-> Moderator sync latency!).
        if self
            .clearance_pk
            .verify_p1363(&signing_payload, &token.signature)
            .is_err()
        {
            return Response::text(403, "invalid ClearanceToken ECDSA signature\n");
        }

        // 2. Verify request-binding fields & single-use challenge nonce!
        let now = now_unix_secs();
        if token.moderator_origin != self.cfg.moderator_origin
            || token.policy_id != self.cfg.policy_id
            || token
                .verify_claims(
                    &self.cfg.origin,
                    &request.method,
                    &request.path,
                    &token.challenge_nonce,
                    self.cfg.cost,
                    now,
                )
                .is_err()
        {
            return Response::text(403, "ClearanceToken request binding mismatch\n");
        }

        let Some(issued_at) = self.active_nonces.remove(&token.challenge_nonce) else {
            return Response::text(401, "unknown or replayed challenge nonce\n");
        };
        if issued_at.elapsed() > Duration::from_secs(120) {
            return Response::text(401, "expired challenge nonce\n");
        }

        let mut resp = Response::json(
            200,
            serde_json::json!({
                "ok": true,
                "origin": self.cfg.origin,
                "bearer_subject": bearer_subject,
                "cost_verified": token.cost,
            })
            .to_string(),
        );

        // If this presentation opened a deferred behavioral session, optionally
        // post reward feedback to Moderator and signal `Mole-Info: settle-ready=?1`.
        let session_id = sec_auth
            .session
            .or_else(|| (!token.session_id.is_empty()).then(|| token.session_id.clone()));
        if let Some(sess) = session_id {
            let mut settle_ready = false;
            if let (Some((mod_addr, reward)), Some(client_ctx)) =
                (&self.cfg.reward_refund_amount, &self.tls_client_ctx)
            {
                let feedback = serde_json::json!({
                    "session": sess,
                    "refund_amount": *reward,
                })
                .to_string();
                if let Ok(fb_res) = https_request(
                    client_ctx,
                    mod_addr,
                    "POST",
                    "/mole/v1/feedback",
                    &[("Content-Type", "application/json")],
                    feedback.as_bytes(),
                ) && fb_res.status == 200
                {
                    settle_ready = true;
                }
            }
            if let Ok(info) = (MoleInfo {
                session: Some(sess),
                settle_ready,
            })
            .to_header_value()
            {
                resp.headers.push(("Mole-Info".into(), info));
            }
        }

        resp
    }
}

// ---------------------------------------------------------------------------
// Live 4-Origin BoringSSL TLS 1.3 Socket E2E Integration Suite
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mole_core::http::parse_challenges;
    use mole_core::messages::{GrantChallenges, GrantRequest};
    use std::process::Command;
    use std::sync::Mutex;
    use std::thread;

    struct LiveTlsEndpoint {
        addr: String,
        origin: String,
    }

    fn spawn_tls_server<H>(
        cert_pem: String,
        key_pem: String,
        handler: Arc<Mutex<H>>,
    ) -> LiveTlsEndpoint
    where
        H: FnMut(&Request) -> Response + Send + 'static,
    {
        let ctx = Arc::new(
            tls::SslContext::new_server(&cert_pem, &key_pem).expect("TLS 1.3 server context"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");
        let origin = format!("https://127.0.0.1:{port}");

        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let ctx_c = Arc::clone(&ctx);
                let h_c = Arc::clone(&handler);
                thread::spawn(move || {
                    if let Ok(mut ssl) = tls::SslStream::accept(&ctx_c, stream)
                        && let Some(req) = read_request(&mut ssl)
                    {
                        let resp = h_c.lock().unwrap()(&req);
                        write_response(&mut ssl, &resp);
                    }
                });
            }
        });

        LiveTlsEndpoint { addr, origin }
    }

    fn generate_localhost_cert(dir: &std::path::Path) -> (String, String) {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1,DNS:localhost",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
            ])
            .output()
            .expect("openssl available");
        assert!(
            status.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        (
            cert.to_str().unwrap().to_string(),
            key.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn live_four_origin_tls13_split_moderation_and_redemption_e2e() {
        let tmp_dir =
            std::env::temp_dir().join(format!("mole_demo_tls13_e2e_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let (cert_pem, key_pem) = generate_localhost_cert(&tmp_dir);
        let client_tls = Arc::new(tls::SslContext::new_client(&cert_pem).unwrap());

        let epoch = b"2026-11-26".to_vec();

        // 1. Launch 3 Distinct Anchors (`N = 3 >= 3` Anchor Set ring invariant!).
        let anchor1_holder: Arc<Mutex<Option<AnchorServer>>> = Arc::new(Mutex::new(None));
        let a1_ref = Arc::clone(&anchor1_holder);
        let anchor1_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                a1_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );
        *anchor1_holder.lock().unwrap() = Some(AnchorServer::new(&anchor1_ep.origin, &epoch));
        let anchor2 = AnchorServer::new("https://anchor2.example", &epoch);
        let anchor3 = AnchorServer::new("https://anchor3.example", &epoch);

        let anchor1_pk = anchor1_holder.lock().unwrap().as_ref().unwrap().public_key();
        let ring_keys = vec![
            anchor1_pk.clone(),
            anchor2.public_key(),
            anchor3.public_key(),
        ];

        // Reject `< 3` Anchor Sets at `SplitModeratorServer::new`!
        assert!(
            SplitModeratorServer::new(SplitModeratorConfig {
                origin: "https://127.0.0.1:9442".into(),
                policy_id: "too-small".into(),
                credential_context: b"ctx".to_vec(),
                accepted_anchor_keys: vec![anchor1_pk.clone(), anchor2.public_key()],
                epoch: epoch.clone(),
                balance_width: 8,
                initial_balance: 10,
                spend_amount: 2,
                max_top_up: 3,
                default_refund_amount: 2,
                allowed_refund_amounts: vec![0, 2, 5],
                allowed_sites: vec![],
                hold_ms: 0,
            })
            .is_err()
        );

        // 2. Reserve TLS 1.3 listeners for Moderator, `shoes` Origin, and `socks` Origin.
        let mod_holder: Arc<Mutex<Option<SplitModeratorServer>>> = Arc::new(Mutex::new(None));
        let mod_ref = Arc::clone(&mod_holder);
        let mod_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                mod_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );

        let shoes_holder: Arc<Mutex<Option<OriginServer>>> = Arc::new(Mutex::new(None));
        let shoes_ref = Arc::clone(&shoes_holder);
        let shoes_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                shoes_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );

        let socks_holder: Arc<Mutex<Option<OriginServer>>> = Arc::new(Mutex::new(None));
        let socks_ref = Arc::clone(&socks_holder);
        let socks_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                socks_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );

        let cred_context = b"commerce-ctx".to_vec();
        let mod_server = SplitModeratorServer::new(SplitModeratorConfig {
            origin: mod_ep.origin.clone(),
            policy_id: "commerce-v2".into(),
            credential_context: cred_context.clone(),
            accepted_anchor_keys: ring_keys.clone(),
            epoch: epoch.clone(),
            balance_width: 8,
            initial_balance: 10,
            spend_amount: 2,
            max_top_up: 3,
            default_refund_amount: 2,
            allowed_refund_amounts: vec![0, 2, 5],
            allowed_sites: vec![shoes_ep.origin.clone(), socks_ep.origin.clone()],
            hold_ms: 0,
        })
        .unwrap();
        let clearance_pk = mod_server.clearance_public_key().to_vec();
        let mod_key_id = mod_server.key_id();
        let mod_act_pk_bytes = mod_server.credential_public_key();
        *mod_holder.lock().unwrap() = Some(mod_server);

        *shoes_holder.lock().unwrap() = Some(
            OriginServer::new(
                OriginServerConfig {
                    origin: shoes_ep.origin.clone(),
                    moderator_origin: mod_ep.origin.clone(),
                    policy_id: "commerce-v2".into(),
                    clearance_public_key: clearance_pk.clone(),
                    cost: 2,
                    reward_refund_amount: Some((mod_ep.addr.clone(), 5)),
                    web_root: None,
                },
                Some(Arc::clone(&client_tls)),
            )
            .unwrap(),
        );
        *socks_holder.lock().unwrap() = Some(
            OriginServer::new(
                OriginServerConfig {
                    origin: socks_ep.origin.clone(),
                    moderator_origin: mod_ep.origin.clone(),
                    policy_id: "commerce-v2".into(),
                    clearance_public_key: clearance_pk.clone(),
                    cost: 2,
                    reward_refund_amount: None,
                    web_root: None,
                },
                Some(Arc::clone(&client_tls)),
            )
            .unwrap(),
        );

        // Verify Moderator discovery JSON validates cleanly via `mole_core`!
        let mod_dir_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "GET",
            "/.well-known/mole-moderator",
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(mod_dir_res.status, 200);
        let parsed_mod_cfg: mole_core::config::ModeratorConfiguration =
            serde_json::from_slice(&mod_dir_res.body).unwrap();
        parsed_mod_cfg.validate_with_min_anchors(3).unwrap();

        // --- STEP A: 2-RTT `EC-IHAT` Batch Grant over TLS 1.3 at `anchor1` ---
        let dir_res = https_request(
            &client_tls,
            &anchor1_ep.addr,
            "GET",
            "/.well-known/mole-anchor",
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(dir_res.status, 200);

        let rtt1_wire = (GrantRequest { count: 2 }).to_bytes().unwrap();
        let req_ct = "application/mole-endorsement-request; type=0002";
        let rtt1_res = https_request(
            &client_tls,
            &anchor1_ep.addr,
            "POST",
            "/mole/grant",
            &[
                ("Content-Type", req_ct),
                ("Authorization", "Bearer user-idp-token"),
            ],
            &rtt1_wire,
        )
        .unwrap();
        assert_eq!(rtt1_res.status, 200);
        let com_msg = GrantCommitments::from_bytes(&rtt1_res.body).unwrap();
        assert_eq!(com_msg.commitments.len(), 2);

        let a1_pk = <ec_ihat::PublicKey>::from_bytes(&anchor1_pk.clone().try_into().unwrap())
            .unwrap();
        let mut client_states = Vec::new();
        let mut challenges = Vec::new();
        for com in &com_msg.commitments {
            let (st, ch) =
                ec_ihat::challenge(&a1_pk, &epoch, EC_IHAT_CTX_RED, com).unwrap();
            client_states.push(st);
            challenges.push(ch);
        }
        let rtt2_wire = (GrantChallenges {
            session_id: com_msg.session_id,
            challenges,
        })
        .to_bytes()
        .unwrap();
        let rtt2_res = https_request(
            &client_tls,
            &anchor1_ep.addr,
            "POST",
            "/mole/grant",
            &[("Content-Type", req_ct)],
            &rtt2_wire,
        )
        .unwrap();
        assert_eq!(rtt2_res.status, 200);
        let resp_msg = GrantResponses::from_bytes(&rtt2_res.body).unwrap();
        let mut endorsements = Vec::new();
        for (st, r) in client_states.into_iter().zip(&resp_msg.responses) {
            endorsements.push(ec_ihat::finalize(&a1_pk, st, r).unwrap());
        }
        assert_eq!(endorsements.len(), 2);

        // --- STEP B: `shoes` `401 Mole-Challenge` + Simulated Dropped `/issue` Idempotency Retry ---
        let ch_shoes = https_request(
            &client_tls,
            &shoes_ep.addr,
            "POST",
            "/api/purchase",
            &[
                ("Authorization", "Bearer shoes-jwt-alice"),
                ("Content-Type", "application/json"),
            ],
            br#"{"sku":"trail-runner"}"#,
        )
        .unwrap();
        assert_eq!(ch_shoes.status, 401);
        let parsed_ch =
            SplitMoleChallenge::parse(ch_shoes.header("Mole-Challenge").unwrap()).unwrap();
        assert_eq!(parsed_ch.moderator, mod_ep.origin);
        assert_eq!(parsed_ch.cost, 2);

        let ctx_cred = derive_ctx_cred(&cred_context, 8).unwrap();
        let act_params = ec_act::Params::new(8).unwrap();
        let mod_act_pk =
            <ec_act::PublicKey>::from_bytes(&mod_act_pk_bytes.try_into().unwrap()).unwrap();
        let ring_pks: Vec<ec_ihat::PublicKey> = ring_keys
            .iter()
            .map(|k| <ec_ihat::PublicKey>::from_bytes(&k.as_slice().try_into().unwrap()).unwrap())
            .collect();

        let build_issue_for = |endorsement: ec_ihat::Endorsement, idem: [u8; 32]| {
            let mut ctx_input = Vec::new();
            ctx_input.extend_from_slice(b"MOLE-SPLIT-ISSUE-v1|");
            ctx_input.extend_from_slice(mod_ep.origin.as_bytes());
            ctx_input.push(b'|');
            ctx_input.extend_from_slice(b"commerce-v2");
            ctx_input.push(b'|');
            ctx_input.extend_from_slice(&idem);
            let redemption_context = sha256(&ctx_input);
            let challenge_dig = (RedemptionChallenge { redemption_context }).digest();

            let proof = ec_ihat::redeem(
                &ring_pks,
                0,
                endorsement,
                &epoch,
                EC_IHAT_CTX_RED,
                &challenge_dig,
            )
            .unwrap();

            let (iss_state, iss_req_msg) = ec_act::issue_request(&act_params).unwrap();
            let act_issue_request = (EcActIssuanceRequest {
                truncated_key_id: mod_key_id[31],
                credential_context: cred_context.clone(),
                request: iss_req_msg,
            })
            .to_bytes()
            .unwrap();

            let env = IssueRequestEnvelope {
                policy_id: "commerce-v2".into(),
                key_id: mod_key_id,
                idempotency_key: idem,
                endorsement_type: endorsement_type::EC_IHAT,
                redemption_context,
                ihat_redeem_proof: proof.to_bytes(),
                act_issue_request,
            };
            (env, iss_state)
        };

        let mut e_iter = endorsements.into_iter();
        let e0 = e_iter.next().unwrap();
        let e1 = e_iter.next().unwrap();

        let mut idem1 = [0u8; 32];
        fill_random(&mut idem1).unwrap();
        let (issue_env1, iss_state1) = build_issue_for(e0, idem1);
        let issue_wire1 = issue_env1.to_bytes().unwrap();

        // Wrong `Content-Type` MUST be rejected with `415 Unsupported Media Type` (`SP-P2-4c`)!
        let wrong_ct_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/issue",
            &[("Content-Type", "application/json")],
            &issue_wire1,
        )
        .unwrap();
        assert_eq!(wrong_ct_res.status, 415);

        // First `/issue` succeeds on server (simulate client dropping response!).
        let dropped_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/issue",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &issue_wire1,
        )
        .unwrap();
        assert_eq!(dropped_res.status, 200);

        // Replay with SAME `(nullifier_A, idempotency_key)` recovers exact blind credential!
        let replayed_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/issue",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &issue_wire1,
        )
        .unwrap();
        assert_eq!(replayed_res.status, 200);
        assert_eq!(replayed_res.body, dropped_res.body);

        // Different `idempotency_key` with the same `nullifier_A` is rejected `409 Conflict`!
        let mut wrong_idem = idem1;
        wrong_idem[0] ^= 0xff;
        let mut forged_env = issue_env1.clone();
        forged_env.idempotency_key = wrong_idem;
        let conflict_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/issue",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &forged_env.to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(conflict_res.status, 409);

        let iss_resp_env1 = IssueResponseEnvelope::from_bytes(&replayed_res.body).unwrap();
        assert_eq!(iss_resp_env1.initial_credit, 10);
        let act_iss_resp1 =
            EcActIssuanceResponse::from_bytes(&act_params, &iss_resp_env1.act_issue_response)
                .unwrap();
        let cred_shoes = ec_act::finalize_issue(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            iss_state1,
            &act_iss_resp1.response,
        )
        .unwrap();
        assert_eq!(cred_shoes.balance(), 10);

        // --- STEP C: Immediate `200 Settled` Presentation + `Authorization: Bearer` Coexistence ---
        let prc_shoes1 = ProtectedRequestContext {
            target_origin: shoes_ep.origin.clone(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: parsed_ch.nonce.clone(),
            cost: 2,
            allow_deferred: false,
        };
        let ctx_spend1 = compute_split_ctx_spend(&prc_shoes1, 2, 3, &cred_context).unwrap();
        let (spend_state1, spend_msg1) =
            ec_act::prove_spend(&act_params, cred_shoes, &ctx_cred, 2, 3, &ctx_spend1).unwrap();
        let pau1 = EcActPresentationAndUpdate {
            key_id: mod_key_id,
            spend: spend_msg1,
        };
        let pres_env1 = PresentRequestEnvelope {
            policy_id: "commerce-v2".into(),
            key_id: mod_key_id,
            target_origin: shoes_ep.origin.clone(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: parsed_ch.nonce.clone(),
            cost: 2,
            max_top_up: 3,
            allow_deferred: false,
            act_presentation: pau1.to_bytes(),
        };
        let pres_res1 = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/present",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &pres_env1.to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(pres_res1.status, 200);
        let PresentResponseEnvelope::Settled {
            clearance_token: clearance1,
            act_refund_response: act_refund1,
        } = PresentResponseEnvelope::from_bytes(&pres_res1.body).unwrap()
        else {
            panic!("expected Settled");
        };
        let upd1 = EcActUpdate::from_bytes(&act_params, &act_refund1).unwrap();
        assert_eq!(upd1.refund.return_amount(), 2);
        let cred_shoes =
            ec_act::finalize_refund(&act_params, &mod_act_pk, &ctx_cred, spend_state1, &upd1.refund)
                .unwrap();
        assert_eq!(cred_shoes.balance(), 10);

        let sec_auth_hdr1 = (SecMoleAuthorization {
            clearance: clearance1,
            session: None,
        })
        .to_header_value()
        .unwrap();

        // Cross-origin replay against `socks` MUST be rejected (`403`)!
        let cross_origin_replay = https_request(
            &client_tls,
            &socks_ep.addr,
            "POST",
            "/api/purchase",
            &[
                ("Authorization", "Bearer socks-jwt-bob"),
                ("Sec-Mole-Authorization", &sec_auth_hdr1),
            ],
            br#"{}"#,
        )
        .unwrap();
        assert_eq!(cross_origin_replay.status, 403);

        // Authentic presentation to `shoes` alongside `Authorization: Bearer` succeeds (`200`)!
        let shoes_ok1 = https_request(
            &client_tls,
            &shoes_ep.addr,
            "POST",
            "/api/purchase",
            &[
                ("Authorization", "Bearer shoes-jwt-alice"),
                ("Sec-Mole-Authorization", &sec_auth_hdr1),
            ],
            br#"{"sku":"trail-runner"}"#,
        )
        .unwrap();
        assert_eq!(shoes_ok1.status, 200);
        let shoes_body1: serde_json::Value = serde_json::from_slice(&shoes_ok1.body).unwrap();
        assert_eq!(shoes_body1["bearer_subject"], "shoes-jwt-alice");

        // Replaying the consumed `Sec-Mole-Authorization` a second time on `shoes` is rejected (`401`)!
        let replay_same_origin = https_request(
            &client_tls,
            &shoes_ep.addr,
            "POST",
            "/api/purchase",
            &[
                ("Authorization", "Bearer shoes-jwt-alice"),
                ("Sec-Mole-Authorization", &sec_auth_hdr1),
            ],
            br#"{"sku":"trail-runner"}"#,
        )
        .unwrap();
        assert_eq!(replay_same_origin.status, 401);

        // --- STEP D: Deferred `202 Held` on `shoes` + Concurrent `socks` Isolation + Behavioral Top-Up `/settle` ---
        mod_holder.lock().unwrap().as_mut().unwrap().set_hold_ms(5_000);

        let ch_shoes2 = https_request(
            &client_tls,
            &shoes_ep.addr,
            "POST",
            "/api/purchase",
            &[("Authorization", "Bearer shoes-jwt-alice")],
            br#"{"sku":"marathon-pro"}"#,
        )
        .unwrap();
        assert_eq!(ch_shoes2.status, 401);
        let parsed_ch2 =
            SplitMoleChallenge::parse(ch_shoes2.header("Mole-Challenge").unwrap()).unwrap();

        let prc_shoes2 = ProtectedRequestContext {
            target_origin: shoes_ep.origin.clone(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: parsed_ch2.nonce.clone(),
            cost: 2,
            allow_deferred: true,
        };
        let ctx_spend2 = compute_split_ctx_spend(&prc_shoes2, 2, 3, &cred_context).unwrap();
        let (spend_state2, spend_msg2) =
            ec_act::prove_spend(&act_params, cred_shoes, &ctx_cred, 2, 3, &ctx_spend2).unwrap();
        let pau2 = EcActPresentationAndUpdate {
            key_id: mod_key_id,
            spend: spend_msg2,
        };
        let recovery2 = pau2.recovery_handle();
        let pres_env2 = PresentRequestEnvelope {
            policy_id: "commerce-v2".into(),
            key_id: mod_key_id,
            target_origin: shoes_ep.origin.clone(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: parsed_ch2.nonce.clone(),
            cost: 2,
            max_top_up: 3,
            allow_deferred: true,
            act_presentation: pau2.to_bytes(),
        };
        let pres_res2 = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/present",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &pres_env2.to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(pres_res2.status, 202);
        let PresentResponseEnvelope::Held {
            clearance_token: clearance2,
            session_handle: session2,
            ..
        } = PresentResponseEnvelope::from_bytes(&pres_res2.body).unwrap()
        else {
            panic!("expected Held");
        };

        // Polling `/settle` before Origin feedback returns `202 Pending`!
        let early_settle = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/settle",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(SettleRequestEnvelope {
                session_handle: session2.clone(),
                recovery_handle: Some(recovery2),
                is_signoff: false,
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(early_settle.status, 202);

        // While `shoes` is held, `socks` concurrently redeems `e1` and presents
        // WITHOUT blocking on or signing off `shoes`'s held session!
        let mut idem2 = [0u8; 32];
        fill_random(&mut idem2).unwrap();
        let (issue_env2, iss_state2) = build_issue_for(e1, idem2);
        let issue_res2 = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/issue",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &issue_env2.to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(issue_res2.status, 200);
        let iss_resp_env2 = IssueResponseEnvelope::from_bytes(&issue_res2.body).unwrap();
        let act_iss_resp2 =
            EcActIssuanceResponse::from_bytes(&act_params, &iss_resp_env2.act_issue_response)
                .unwrap();
        let cred_socks = ec_act::finalize_issue(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            iss_state2,
            &act_iss_resp2.response,
        )
        .unwrap();

        let ch_socks = https_request(
            &client_tls,
            &socks_ep.addr,
            "POST",
            "/api/purchase",
            &[("Authorization", "Bearer socks-jwt-bob")],
            br#"{"sku":"merino-crew"}"#,
        )
        .unwrap();
        assert_eq!(ch_socks.status, 401);
        let parsed_socks_ch =
            SplitMoleChallenge::parse(ch_socks.header("Mole-Challenge").unwrap()).unwrap();
        let prc_socks = ProtectedRequestContext {
            target_origin: socks_ep.origin.clone(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: parsed_socks_ch.nonce.clone(),
            cost: 2,
            allow_deferred: false,
        };
        let ctx_spend_socks = compute_split_ctx_spend(&prc_socks, 2, 3, &cred_context).unwrap();
        let (_socks_state, socks_spend) =
            ec_act::prove_spend(&act_params, cred_socks, &ctx_cred, 2, 3, &ctx_spend_socks)
                .unwrap();
        let socks_pres_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/present",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(PresentRequestEnvelope {
                policy_id: "commerce-v2".into(),
                key_id: mod_key_id,
                target_origin: socks_ep.origin.clone(),
                method: "POST".into(),
                path_and_query: "/api/purchase".into(),
                challenge_nonce: parsed_socks_ch.nonce,
                cost: 2,
                max_top_up: 3,
                allow_deferred: false,
                act_presentation: (EcActPresentationAndUpdate {
                    key_id: mod_key_id,
                    spend: socks_spend,
                })
                .to_bytes(),
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(socks_pres_res.status, 200);
        let PresentResponseEnvelope::Settled {
            clearance_token: socks_clearance,
            ..
        } = PresentResponseEnvelope::from_bytes(&socks_pres_res.body).unwrap()
        else {
            panic!("expected socks Settled");
        };
        let socks_ok = https_request(
            &client_tls,
            &socks_ep.addr,
            "POST",
            "/api/purchase",
            &[
                ("Authorization", "Bearer socks-jwt-bob"),
                (
                    "Sec-Mole-Authorization",
                    &(SecMoleAuthorization {
                        clearance: socks_clearance,
                        session: None,
                    })
                    .to_header_value()
                    .unwrap(),
                ),
            ],
            br#"{"sku":"merino-crew"}"#,
        )
        .unwrap();
        assert_eq!(socks_ok.status, 200);

        // Now `shoes` receives `clearance2`, posts behavioral reward (`refund = 5 = 2 + 3`) to
        // Moderator over TLS 1.3, and returns `Mole-Info: session="...", settle-ready=?1`!
        let shoes_ok2 = https_request(
            &client_tls,
            &shoes_ep.addr,
            "POST",
            "/api/purchase",
            &[
                ("Authorization", "Bearer shoes-jwt-alice"),
                (
                    "Sec-Mole-Authorization",
                    &(SecMoleAuthorization {
                        clearance: clearance2,
                        session: Some(session2.clone()),
                    })
                    .to_header_value()
                    .unwrap(),
                ),
            ],
            br#"{"sku":"marathon-pro"}"#,
        )
        .unwrap();
        assert_eq!(shoes_ok2.status, 200);
        let mole_info = MoleInfo::parse(shoes_ok2.header("Mole-Info").unwrap()).unwrap();
        assert_eq!(mole_info.session.as_deref(), Some(session2.as_str()));
        assert!(mole_info.settle_ready);

        // Client settles `session2` (`is_signoff = false`), AND verify crash-recovery via
        // `RecoveryHandle` alone (`session_handle = ""`) returns the identical `Settled` bytes!
        let settle_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/settle",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(SettleRequestEnvelope {
                session_handle: session2,
                recovery_handle: Some(recovery2),
                is_signoff: false,
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(settle_res.status, 200);

        let crash_recovery_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/settle",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(SettleRequestEnvelope {
                session_handle: String::new(),
                recovery_handle: Some(recovery2),
                is_signoff: false,
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(crash_recovery_res.status, 200);
        assert_eq!(crash_recovery_res.body, settle_res.body);

        let SettleResponseEnvelope::Settled {
            act_refund_response: reward_refund,
        } = SettleResponseEnvelope::from_bytes(&settle_res.body).unwrap()
        else {
            panic!("expected Settled");
        };
        let reward_upd = EcActUpdate::from_bytes(&act_params, &reward_refund).unwrap();
        assert_eq!(reward_upd.refund.return_amount(), 5);
        let cred_shoes_boosted = ec_act::finalize_refund(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            spend_state2,
            &reward_upd.refund,
        )
        .unwrap();
        assert_eq!(cred_shoes_boosted.balance(), 13);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn live_tls13_l16_wide_balance_and_early_signoff_settlement_e2e() {
        let tmp_dir =
            std::env::temp_dir().join(format!("mole_demo_tls13_l16_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let (cert_pem, key_pem) = generate_localhost_cert(&tmp_dir);
        let client_tls = Arc::new(tls::SslContext::new_client(&cert_pem).unwrap());

        let epoch = b"2026-11-26-l16".to_vec();
        let a1 = AnchorServer::new("https://a1.example", &epoch);
        let a2 = AnchorServer::new("https://a2.example", &epoch);
        let a3_holder: Arc<Mutex<Option<AnchorServer>>> = Arc::new(Mutex::new(None));
        let a3_ref = Arc::clone(&a3_holder);
        let a3_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                a3_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );
        *a3_holder.lock().unwrap() = Some(AnchorServer::new(&a3_ep.origin, &epoch));
        let a3_pk_bytes = a3_holder.lock().unwrap().as_ref().unwrap().public_key();
        let ring_keys = vec![a1.public_key(), a2.public_key(), a3_pk_bytes.clone()];

        let mod_holder: Arc<Mutex<Option<SplitModeratorServer>>> = Arc::new(Mutex::new(None));
        let mod_ref = Arc::clone(&mod_holder);
        let mod_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                mod_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );

        let cred_context = b"l16-wide-ctx".to_vec();
        let mod_server = SplitModeratorServer::new(SplitModeratorConfig {
            origin: mod_ep.origin.clone(),
            policy_id: "wide-l16".into(),
            credential_context: cred_context.clone(),
            accepted_anchor_keys: ring_keys.clone(),
            epoch: epoch.clone(),
            balance_width: 16,
            initial_balance: 1_000,
            spend_amount: 25,
            max_top_up: 50,
            default_refund_amount: 75,
            allowed_refund_amounts: vec![0, 25, 75],
            allowed_sites: vec!["*".into()],
            hold_ms: 60_000,
        })
        .unwrap();
        let mod_key_id = mod_server.key_id();
        let mod_act_pk = <ec_act::PublicKey>::from_bytes(
            &mod_server.credential_public_key().try_into().unwrap(),
        )
        .unwrap();
        *mod_holder.lock().unwrap() = Some(mod_server);

        // Grant from Anchor #3 (index 2 in ring!).
        let req_ct = "application/mole-endorsement-request; type=0002";
        let r1 = https_request(
            &client_tls,
            &a3_ep.addr,
            "POST",
            "/mole/grant",
            &[("Content-Type", req_ct)],
            &(GrantRequest { count: 1 }).to_bytes().unwrap(),
        )
        .unwrap();
        let com_msg = GrantCommitments::from_bytes(&r1.body).unwrap();
        let a3_pk =
            <ec_ihat::PublicKey>::from_bytes(&a3_pk_bytes.try_into().unwrap()).unwrap();
        let (st, ch) =
            ec_ihat::challenge(&a3_pk, &epoch, EC_IHAT_CTX_RED, &com_msg.commitments[0]).unwrap();
        let r2 = https_request(
            &client_tls,
            &a3_ep.addr,
            "POST",
            "/mole/grant",
            &[("Content-Type", req_ct)],
            &(GrantChallenges {
                session_id: com_msg.session_id,
                challenges: vec![ch],
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        let resp_msg = GrantResponses::from_bytes(&r2.body).unwrap();
        let endorsement = ec_ihat::finalize(&a3_pk, st, &resp_msg.responses[0]).unwrap();

        // Issue L=16 credential (`initial_balance = 1_000`).
        let ctx_cred = derive_ctx_cred(&cred_context, 16).unwrap();
        let act_params = ec_act::Params::new(16).unwrap();
        let mut idem = [0u8; 32];
        fill_random(&mut idem).unwrap();
        let mut ctx_input = Vec::new();
        ctx_input.extend_from_slice(b"MOLE-SPLIT-ISSUE-v1|");
        ctx_input.extend_from_slice(mod_ep.origin.as_bytes());
        ctx_input.push(b'|');
        ctx_input.extend_from_slice(b"wide-l16");
        ctx_input.push(b'|');
        ctx_input.extend_from_slice(&idem);
        let redemption_context = sha256(&ctx_input);
        let ring_pks: Vec<ec_ihat::PublicKey> = ring_keys
            .iter()
            .map(|k| <ec_ihat::PublicKey>::from_bytes(&k.as_slice().try_into().unwrap()).unwrap())
            .collect();
        let proof = ec_ihat::redeem(
            &ring_pks,
            2,
            endorsement,
            &epoch,
            EC_IHAT_CTX_RED,
            &(RedemptionChallenge { redemption_context }).digest(),
        )
        .unwrap();
        let (iss_state, iss_req_msg) = ec_act::issue_request(&act_params).unwrap();
        let iss_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/issue",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(IssueRequestEnvelope {
                policy_id: "wide-l16".into(),
                key_id: mod_key_id,
                idempotency_key: idem,
                endorsement_type: endorsement_type::EC_IHAT,
                redemption_context,
                ihat_redeem_proof: proof.to_bytes(),
                act_issue_request: (EcActIssuanceRequest {
                    truncated_key_id: mod_key_id[31],
                    credential_context: cred_context.clone(),
                    request: iss_req_msg,
                })
                .to_bytes()
                .unwrap(),
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(iss_res.status, 200);
        let iss_env = IssueResponseEnvelope::from_bytes(&iss_res.body).unwrap();
        let cred = ec_act::finalize_issue(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            iss_state,
            &EcActIssuanceResponse::from_bytes(&act_params, &iss_env.act_issue_response)
                .unwrap()
                .response,
        )
        .unwrap();
        assert_eq!(cred.balance(), 1_000);

        // Present with `allow_deferred = true` (`hold_ms = 60_000` -> `202 Held`), then
        // immediately sign off early (`is_signoff = true`) and verify baseline `spend_amount` (`25`)
        // is refunded (`1_000 - 25 + 25 = 1_000`) without waiting 60s!
        let prc = ProtectedRequestContext {
            target_origin: "https://any-shop.example".into(),
            method: "POST".into(),
            path_and_query: "/checkout".into(),
            challenge_nonce: vec![0x42; 16],
            cost: 25,
            allow_deferred: true,
        };
        let ctx_spend = compute_split_ctx_spend(&prc, 25, 50, &cred_context).unwrap();
        let (spend_state, spend_msg) =
            ec_act::prove_spend(&act_params, cred, &ctx_cred, 25, 50, &ctx_spend).unwrap();
        let pau = EcActPresentationAndUpdate {
            key_id: mod_key_id,
            spend: spend_msg,
        };
        let pres_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/present",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(PresentRequestEnvelope {
                policy_id: "wide-l16".into(),
                key_id: mod_key_id,
                target_origin: "https://any-shop.example".into(),
                method: "POST".into(),
                path_and_query: "/checkout".into(),
                challenge_nonce: vec![0x42; 16],
                cost: 25,
                max_top_up: 50,
                allow_deferred: true,
                act_presentation: pau.to_bytes(),
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(pres_res.status, 202);
        let PresentResponseEnvelope::Held { session_handle, .. } =
            PresentResponseEnvelope::from_bytes(&pres_res.body).unwrap()
        else {
            panic!("expected Held");
        };

        let signoff_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/mole/v1/settle",
            &[("Content-Type", MOLE_ENVELOPE_MEDIA_TYPE)],
            &(SettleRequestEnvelope {
                session_handle,
                recovery_handle: None,
                is_signoff: true,
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(signoff_res.status, 200);
        let SettleResponseEnvelope::Settled {
            act_refund_response,
        } = SettleResponseEnvelope::from_bytes(&signoff_res.body).unwrap()
        else {
            panic!("expected Settled");
        };
        let upd = EcActUpdate::from_bytes(&act_params, &act_refund_response).unwrap();
        assert_eq!(upd.refund.return_amount(), 25);
        let restored = ec_act::finalize_refund(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            spend_state,
            &upd.refund,
        )
        .unwrap();
        assert_eq!(restored.balance(), 1_000);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn live_tls13_inline_01_cold_redeem_present_and_deferred_settle_e2e() {
        let tmp_dir =
            std::env::temp_dir().join(format!("mole_demo_tls13_inline_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let (cert_pem, key_pem) = generate_localhost_cert(&tmp_dir);
        let client_tls = Arc::new(tls::SslContext::new_client(&cert_pem).unwrap());

        let epoch = b"2026-11-26-inline".to_vec();
        let a1_holder: Arc<Mutex<Option<AnchorServer>>> = Arc::new(Mutex::new(None));
        let a1_ref = Arc::clone(&a1_holder);
        let a1_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                a1_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );
        *a1_holder.lock().unwrap() = Some(AnchorServer::new(&a1_ep.origin, &epoch));
        let a2 = AnchorServer::new("https://inline-a2.example", &epoch);
        let a3 = AnchorServer::new("https://inline-a3.example", &epoch);
        let a1_pk_bytes = a1_holder.lock().unwrap().as_ref().unwrap().public_key();
        let ring_keys = vec![a1_pk_bytes.clone(), a2.public_key(), a3.public_key()];

        let mod_holder: Arc<Mutex<Option<SplitModeratorServer>>> = Arc::new(Mutex::new(None));
        let mod_ref = Arc::clone(&mod_holder);
        let mod_ep = spawn_tls_server(
            cert_pem.clone(),
            key_pem.clone(),
            Arc::new(Mutex::new(move |req: &Request| {
                mod_ref.lock().unwrap().as_mut().unwrap().handle(req)
            })),
        );

        let cred_context = b"inline-01-ctx".to_vec();
        let mod_server = SplitModeratorServer::new(SplitModeratorConfig {
            origin: mod_ep.origin.clone(),
            policy_id: "inline-v1".into(),
            credential_context: cred_context.clone(),
            accepted_anchor_keys: ring_keys.clone(),
            epoch: epoch.clone(),
            balance_width: 8,
            initial_balance: 10,
            spend_amount: 2,
            max_top_up: 3,
            default_refund_amount: 5,
            allowed_refund_amounts: vec![0, 2, 5],
            allowed_sites: vec![mod_ep.origin.clone()],
            hold_ms: 40,
        })
        .unwrap();
        let mod_key_id = mod_server.key_id();
        let mod_act_pk = <ec_act::PublicKey>::from_bytes(
            &mod_server.credential_public_key().try_into().unwrap(),
        )
        .unwrap();
        *mod_holder.lock().unwrap() = Some(mod_server);

        // 1. Obtain `EC-IHAT` Endorsement over TLS 1.3.
        let req_ct = "application/mole-endorsement-request; type=0002";
        let r1 = https_request(
            &client_tls,
            &a1_ep.addr,
            "POST",
            "/mole/grant",
            &[("Content-Type", req_ct)],
            &(GrantRequest { count: 1 }).to_bytes().unwrap(),
        )
        .unwrap();
        let com_msg = GrantCommitments::from_bytes(&r1.body).unwrap();
        let a1_pk =
            <ec_ihat::PublicKey>::from_bytes(&a1_pk_bytes.try_into().unwrap()).unwrap();
        let (st, ch) =
            ec_ihat::challenge(&a1_pk, &epoch, EC_IHAT_CTX_RED, &com_msg.commitments[0]).unwrap();
        let r2 = https_request(
            &client_tls,
            &a1_ep.addr,
            "POST",
            "/mole/grant",
            &[("Content-Type", req_ct)],
            &(GrantChallenges {
                session_id: com_msg.session_id,
                challenges: vec![ch],
            })
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        let resp_msg = GrantResponses::from_bytes(&r2.body).unwrap();
        let endorsement = ec_ihat::finalize(&a1_pk, st, &resp_msg.responses[0]).unwrap();

        // 2. Hit `-01` inline protected endpoint -> `401 WWW-Authenticate: Mole challenge-0001=..., redeem-0002=...`.
        let ch_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/inline/resource",
            &[],
            b"{}",
        )
        .unwrap();
        assert_eq!(ch_res.status, 401);
        let parsed_challenges =
            parse_challenges(&[ch_res.header("WWW-Authenticate").unwrap()]);
        let mut raw_act_chal = Vec::new();
        let mut redeem_chal = [0u8; 32];
        for c in parsed_challenges {
            match c {
                MoleChallenge::Credential { challenge, .. } => raw_act_chal = challenge,
                MoleChallenge::Redeem { challenge, .. } => redeem_chal = challenge,
                _ => {}
            }
        }
        assert!(!raw_act_chal.is_empty());

        // 3. Cold `-01` inline redeem (`POST /.well-known/mole-issuer` with `Authorization: Mole redeem-0002=..., credential-request-0001=...`).
        let ring_pks: Vec<ec_ihat::PublicKey> = ring_keys
            .iter()
            .map(|k| <ec_ihat::PublicKey>::from_bytes(&k.as_slice().try_into().unwrap()).unwrap())
            .collect();
        let red_dig = (RedemptionChallenge {
            redemption_context: redeem_chal,
        })
        .digest();
        let red_proof =
            ec_ihat::redeem(&ring_pks, 0, endorsement, &epoch, EC_IHAT_CTX_RED, &red_dig).unwrap();

        let act_params = ec_act::Params::new(8).unwrap();
        let ctx_cred = derive_ctx_cred(&cred_context, 8).unwrap();
        let (iss_state, iss_req_msg) = ec_act::issue_request(&act_params).unwrap();
        let cred_req_bytes = (EcActIssuanceRequest {
            truncated_key_id: mod_key_id[31],
            credential_context: cred_context.clone(),
            request: iss_req_msg,
        })
        .to_bytes()
        .unwrap();
        let redeem_auth = (MoleAuthorization::RedeemAndIssue {
            endorsement_type: endorsement_type::EC_IHAT,
            redemption: red_proof.to_bytes(),
            credential_type: credential_type::EC_ACT,
            credential_request: cred_req_bytes,
        })
        .to_header_value()
        .unwrap();

        let redeem_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/.well-known/mole-issuer",
            &[("Authorization", &redeem_auth)],
            &[],
        )
        .unwrap();
        assert_eq!(redeem_res.status, 200);
        let MoleCredential::Response { response: raw_iss_resp, .. } =
            MoleCredential::parse(redeem_res.header("Mole-Credential").unwrap()).unwrap()
        else {
            panic!("expected MoleCredential::Response");
        };
        let iss_resp = EcActIssuanceResponse::from_bytes(&act_params, &raw_iss_resp).unwrap();
        let cred = ec_act::finalize_issue(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            iss_state,
            &iss_resp.response,
        )
        .unwrap();
        assert_eq!(cred.balance(), 10);

        // 4. Inline presentation (`Authorization: Mole presentation-0001=...`) -> `200 OK` + `Mole-Credential: held-for-update-0001="1"`.
        let parsed_act_chal = EcActChallenge::from_bytes(&raw_act_chal).unwrap();
        let ctx_spend = parsed_act_chal.ctx_spend().unwrap();
        let (spend_state, spend_msg) =
            ec_act::prove_spend(&act_params, cred, &ctx_cred, 2, 3, &ctx_spend).unwrap();
        let pau = EcActPresentationAndUpdate {
            key_id: mod_key_id,
            spend: spend_msg,
        };
        let rec_handle = pau.recovery_handle();
        let pres_auth = (MoleAuthorization::Presentation {
            credential_type: credential_type::EC_ACT,
            presentation: pau.to_bytes(),
        })
        .to_header_value()
        .unwrap();

        let pres_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/inline/resource",
            &[("Authorization", &pres_auth)],
            b"{}",
        )
        .unwrap();
        assert_eq!(pres_res.status, 200);
        let MoleCredential::HeldForUpdate { duration_secs, .. } =
            MoleCredential::parse(pres_res.header("Mole-Credential").unwrap()).unwrap()
        else {
            panic!("expected HeldForUpdate");
        };
        assert_eq!(duration_secs, 1);

        // 5. Wait for hold window (`50ms`) and settle via `Authorization: Mole recovery-0001=...` -> `Mole-Credential: update-0001=...` (`balance = 13`)!
        thread::sleep(Duration::from_millis(60));
        let settle_auth = (MoleAuthorization::Recovery {
            credential_type: credential_type::EC_ACT,
            recovery_handle: rec_handle.to_bytes().unwrap(),
        })
        .to_header_value()
        .unwrap();
        let settle_res = https_request(
            &client_tls,
            &mod_ep.addr,
            "POST",
            "/.well-known/mole-issuer",
            &[("Authorization", &settle_auth)],
            &[],
        )
        .unwrap();
        assert_eq!(settle_res.status, 200);
        let MoleCredential::Update {
            update: Some(raw_upd),
            ..
        } = MoleCredential::parse(settle_res.header("Mole-Credential").unwrap()).unwrap()
        else {
            panic!("expected MoleCredential::Update");
        };
        let upd = EcActUpdate::from_bytes(&act_params, &raw_upd).unwrap();
        assert_eq!(upd.refund.return_amount(), 5);
        let boosted = ec_act::finalize_refund(
            &act_params,
            &mod_act_pk,
            &ctx_cred,
            spend_state,
            &upd.refund,
        )
        .unwrap();
        assert_eq!(boosted.balance(), 13);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
