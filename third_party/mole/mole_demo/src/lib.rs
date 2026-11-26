// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runnable MOLE HTTPS demo (`draft-jms-mole-protocols-01` and
//! `draft-jms-mole-http-transport-01`): standalone Anchor and Moderator HTTPS
//! servers built on the same BoringSSL-backed `mole_p256`, `ec_ihat`, `ec_act`,
//! and `mole_core` crates as `//components/moderated_endorsements`.
//!
//! Serves genuine TLS via BoringSSL (`bssl_sys`) so the browser runs in a true
//! HTTPS secure context (`anchor.com`, `antifraud.com`, `shoes.com`, `socks.com`).

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use mole_core::act::{compute_ec_act_key_id, derive_ctx_cred};
use mole_core::config::{
    AnchorConfiguration, EcActKeyConfig, EcIhatEndorsementConfig, ModeratorConfiguration,
    validate_https_endpoint_uri,
};
use mole_core::http::{
    MoleAuthorization, MoleChallenge, MoleCredential, b64_encode,
    format_endorsement_response_media_type, format_www_authenticate,
    parse_endorsement_request_media_type,
};
use mole_core::messages::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, EcIhatGrantPost, GrantCommitments, GrantResponses, RecoveryHandle,
};
use mole_core::wire::Wire as _;
use mole_core::{
    CIPHERSUITE_P256_SHA256, EC_IHAT_CTX_RED, credential_type, endorsement_type, fill_random,
    sha256,
};
use mole_p256::zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 + BoringSSL TLS Server
// ---------------------------------------------------------------------------

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn json(body: String) -> Response {
        Response {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into_bytes(),
        }
    }
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub content_type: String,
    pub authorization: String,
    pub body: Vec<u8>,
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
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
    let mut content_type = String::new();
    let mut authorization = String::new();
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
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            } else if name == "content-type" {
                content_type = value.to_string();
            } else if name == "authorization" {
                authorization = value.to_string();
            }
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
        content_type,
        authorization,
        body,
    })
}

pub fn write_response<W: Write>(stream: &mut W, response: &Response) {
    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status));
    out.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    out.push_str("Access-Control-Allow-Origin: *\r\n");
    out.push_str("Access-Control-Allow-Headers: *\r\n");
    out.push_str("Access-Control-Expose-Headers: *\r\n");
    for (name, value) in &response.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

pub mod tls {
    use bssl_sys::{
        SSL, SSL_CTX, SSL_CTX_free, SSL_CTX_new, SSL_CTX_use_PrivateKey_file,
        SSL_CTX_use_certificate_chain_file, SSL_accept, SSL_free, SSL_new, SSL_read, SSL_set_fd,
        SSL_shutdown, SSL_write, TLS_method,
    };
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_void};

    const SSL_FILETYPE_PEM: c_int = 1;

    pub struct SslContext(*mut SSL_CTX);

    impl SslContext {
        pub fn new(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
            // SAFETY: standard single-threaded BoringSSL `SSL_CTX` initialization
            // with null checks on every call.
            unsafe {
                let ctx = SSL_CTX_new(TLS_method());
                if ctx.is_null() {
                    return Err("SSL_CTX_new failed".into());
                }
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
    }

    impl Drop for SslContext {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live `SSL_CTX` from `SSL_CTX_new`.
            unsafe { SSL_CTX_free(self.0) };
        }
    }

    pub struct SslStream {
        ssl: *mut SSL,
        _tcp: TcpStream,
    }

    impl SslStream {
        pub fn accept(ctx: &SslContext, tcp: TcpStream) -> Result<SslStream, String> {
            // SAFETY: `ctx.0` is valid and `_tcp` keeps the underlying socket fd
            // alive for the lifetime of `ssl`.
            unsafe {
                let ssl = SSL_new(ctx.0);
                if ssl.is_null() {
                    return Err("SSL_new failed".into());
                }
                SSL_set_fd(ssl, tcp.as_raw_fd());
                if SSL_accept(ssl) != 1 {
                    SSL_free(ssl);
                    return Err("TLS handshake failed".into());
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
            // SAFETY: `self.ssl` is a live `SSL` created by `SSL_new`.
            unsafe {
                SSL_shutdown(self.ssl);
                SSL_free(self.ssl);
            }
        }
    }
}

pub fn serve<F: FnMut(&Request) -> Response>(
    addr: &str,
    cert_pem: &str,
    key_pem: &str,
    mut handler: F,
) -> std::io::Result<()> {
    let ctx = tls::SslContext::new(cert_pem, key_pem).map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(addr)?;
    eprintln!("[mole-demo] listening (HTTPS) on {addr}");
    for stream in listener.incoming() {
        let Ok(tcp) = stream else { continue };
        let Ok(mut ssl) = tls::SslStream::accept(&ctx, tcp) else {
            continue;
        };
        if let Some(request) = read_request(&mut ssl) {
            let response = if request.method == "OPTIONS" {
                Response::text(200, "")
            } else {
                handler(&request)
            };
            write_response(&mut ssl, &response);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Anchor Server (`draft-jms-mole-protocols-01` §4.4, §6)
// ---------------------------------------------------------------------------

pub struct AnchorServer {
    origin: String,
    key: ec_ihat::SecretKey,
    issuance_epoch: Vec<u8>,
    open_sessions: HashMap<[u8; 32], Vec<ec_ihat::AnchorState>>,
    consumed_sessions: HashSet<[u8; 32]>,
}

impl AnchorServer {
    pub fn new(origin: &str, epoch: &[u8]) -> AnchorServer {
        let mut seed = Zeroizing::new([0u8; 48]);
        fill_random(&mut *seed).expect("RNG succeeds");
        let key = ec_ihat::SecretKey::from_seed(&seed).expect("Anchor key derives");
        let (canon_origin, _) = validate_https_endpoint_uri(origin)
            .unwrap_or_else(|_| ("https://anchor.com".into(), "/".into()));
        AnchorServer {
            origin: canon_origin,
            key,
            issuance_epoch: epoch.to_vec(),
            open_sessions: HashMap::new(),
            consumed_sessions: HashSet::new(),
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
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

    /// JSON commitment entry for `MoleCommitmentRegistry` (`anchors[origin]`).
    pub fn commitment_json(&self) -> String {
        serde_json::json!({
            "grant-uri": self.grant_uri(),
            "keys": [b64_encode(&self.public_key())],
            "epochs": [b64_encode(&self.issuance_epoch)],
        })
        .to_string()
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        if request.path == "/.well-known/mole-anchor" && request.method == "GET" {
            return Response::json(self.configuration_json());
        }
        if request.path == "/mole/grant" && request.method == "POST" {
            return self.grant(&request.content_type, &request.body);
        }
        Response::text(404, "not found\n")
    }

    fn grant(&mut self, content_type: &str, body: &[u8]) -> Response {
        match parse_endorsement_request_media_type(content_type) {
            Ok(t) if t == endorsement_type::EC_IHAT => {}
            _ => return Response::text(415, "expected application/mole-endorsement-request; type=0002\n"),
        }
        let Ok(post) = EcIhatGrantPost::from_bytes(body) else {
            return Response::text(400, "malformed EC-IHAT grant payload\n");
        };

        let resp_bytes = match post {
            EcIhatGrantPost::Request(req) => {
                let n = usize::from(req.count.min(64));
                let mut states = Vec::with_capacity(n);
                let mut commitments = Vec::with_capacity(n);
                for _ in 0..n {
                    let Ok((st, com)) = ec_ihat::commit(&self.issuance_epoch) else {
                        return Response::text(500, "EC-IHAT commit failed\n");
                    };
                    states.push(st);
                    commitments.push(com);
                }
                let mut session_id = [0u8; 32];
                fill_random(&mut session_id).expect("RNG succeeds");
                self.open_sessions.insert(session_id, states);
                GrantCommitments {
                    session_id,
                    commitments,
                }
                .to_bytes()
                .expect("GrantCommitments encodes")
            }
            EcIhatGrantPost::Challenges(chal) => {
                if self.consumed_sessions.contains(&chal.session_id) {
                    return Response::text(400, "replayed grant session_id\n");
                }
                let Some(states) = self.open_sessions.remove(&chal.session_id) else {
                    return Response::text(400, "unknown grant session_id\n");
                };
                self.consumed_sessions.insert(chal.session_id);
                if states.len() != chal.challenges.len() {
                    return Response::text(400, "challenge count mismatch\n");
                }
                let mut responses = Vec::with_capacity(states.len());
                for (state, challenge_msg) in states.into_iter().zip(&chal.challenges) {
                    let Ok(resp) = ec_ihat::respond(&self.key, state, challenge_msg) else {
                        return Response::text(400, "EC-IHAT respond failed\n");
                    };
                    responses.push(resp);
                }
                GrantResponses { responses }
                    .to_bytes()
                    .expect("GrantResponses encodes")
            }
        };

        Response {
            status: 200,
            headers: vec![
                (
                    "Content-Type".into(),
                    format_endorsement_response_media_type(endorsement_type::EC_IHAT)
                        .expect("media type formats"),
                ),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: resp_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// Moderator Server (`draft-jms-mole-protocols-01` §5.2 & HTTP Transport `-01`)
// ---------------------------------------------------------------------------

enum RecordedDecision {
    Held {
        hold_until: u64,
        raw_spend: Vec<u8>,
    },
    Refund(Vec<u8>),
}

struct RecordedPresentation {
    presentation_sha256: [u8; 32],
    recorded_at: u64,
    decision: RecordedDecision,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub struct ModeratorServer {
    origin: String,
    credential_context: Vec<u8>,
    ctx_cred: Vec<u8>,
    accepted_anchor_keys: Vec<[u8; 33]>,
    anchor_set: Vec<ec_ihat::PublicKey>,
    issuance_epoch: Vec<u8>,
    balance_width: u8,
    initial_balance: u64,
    spend_amount: u64,
    max_top_up: u64,
    refund_amount: u64,
    hold_duration_secs: u64,
    result_retention_secs: u64,
    params: ec_act::Params,
    secret_key: ec_act::SecretKey,
    key_id: [u8; 32],
    redemption_challenge: [u8; 32],
    seen_endorsement_nullifiers: HashSet<[u8; 32]>,
    recorded_spends: HashMap<[u8; 32], RecordedPresentation>,
    pub redemptions: u64,
    pub presentations: u64,
    pub settlements: u64,
    recent_nullifiers: Vec<String>,
}

impl ModeratorServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: &str,
        accepted_anchor_key: &[u8],
        epoch: &[u8],
        credential_context: &[u8],
        balance_width: u8,
        initial_balance: u64,
        spend_amount: u64,
        max_top_up: u64,
        refund_amount: u64,
        hold_duration_secs: u64,
    ) -> Result<ModeratorServer, String> {
        let arr: [u8; 33] = accepted_anchor_key
            .try_into()
            .map_err(|_| "anchor key must be 33 bytes".to_string())?;
        let anchor_pk =
            ec_ihat::PublicKey::from_bytes(&arr).map_err(|_| "invalid anchor P-256 point")?;
        let params = ec_act::Params::new(balance_width)
            .map_err(|_| "balance-width must be in 1..=64".to_string())?;
        let ctx_cred = derive_ctx_cred(credential_context, balance_width)
            .map_err(|e| format!("invalid credential-context: {e}"))?;

        let mut seed = Zeroizing::new([0u8; 48]);
        fill_random(&mut *seed).map_err(|_| "RNG failed".to_string())?;
        let secret_key =
            ec_act::SecretKey::from_seed(&seed).map_err(|_| "Moderator keygen failed")?;
        let key_id = compute_ec_act_key_id(&secret_key.public_key());

        let mut redemption_challenge = [0u8; 32];
        fill_random(&mut redemption_challenge).map_err(|_| "RNG failed".to_string())?;
        let (canon_origin, _) = validate_https_endpoint_uri(origin)
            .unwrap_or_else(|_| ("https://antifraud.com".into(), "/".into()));

        Ok(ModeratorServer {
            origin: canon_origin,
            credential_context: credential_context.to_vec(),
            ctx_cred,
            accepted_anchor_keys: vec![arr],
            anchor_set: vec![anchor_pk],
            issuance_epoch: epoch.to_vec(),
            balance_width,
            initial_balance,
            spend_amount,
            max_top_up,
            refund_amount,
            hold_duration_secs,
            result_retention_secs: 300,
            params,
            secret_key,
            key_id,
            redemption_challenge,
            seen_endorsement_nullifiers: HashSet::new(),
            recorded_spends: HashMap::new(),
            redemptions: 0,
            presentations: 0,
            settlements: 0,
            recent_nullifiers: Vec::new(),
        })
    }

    pub fn issuance_uri(&self) -> String {
        format!("{}/mole/issue", self.origin)
    }

    fn ec_act_challenge(&self) -> EcActChallenge {
        EcActChallenge {
            spend_amount: self.spend_amount,
            max_top_up: self.max_top_up,
            credential_context: self.credential_context.clone(),
            request_context: Vec::new(),
        }
    }

    pub fn configuration_json(&self) -> String {
        let ihat = EcIhatEndorsementConfig {
            endorsement_type: endorsement_type::EC_IHAT,
            ciphersuite: CIPHERSUITE_P256_SHA256.into(),
            issuance_epoch: b64_encode(&self.issuance_epoch),
            anchor_set: self
                .accepted_anchor_keys
                .iter()
                .map(|k| b64_encode(k))
                .collect(),
        };
        let act_key = EcActKeyConfig {
            credential_type: credential_type::EC_ACT,
            credential_key: b64_encode(&self.secret_key.public_key().to_bytes()),
            ciphersuite: CIPHERSUITE_P256_SHA256.into(),
            balance_width: self.balance_width,
            credential_context: b64_encode(&self.credential_context),
            result_retention: self.result_retention_secs,
        };
        let cfg = ModeratorConfiguration {
            issuance_uri: self.issuance_uri(),
            endorsements: vec![serde_json::to_value(ihat).unwrap()],
            credential_keys: vec![serde_json::to_value(act_key).unwrap()],
        };
        serde_json::to_string(&cfg).expect("ModeratorConfiguration serializes")
    }

    /// JSON commitment entry for `MoleCommitmentRegistry` (`moderators[origin]`).
    pub fn commitment_json(&self) -> String {
        let accepted: Vec<String> = self
            .accepted_anchor_keys
            .iter()
            .map(|k| b64_encode(k))
            .collect();
        serde_json::json!({
            "policies": [{
                "credential-context": b64_encode(&self.credential_context),
                "credential-key": b64_encode(&self.secret_key.public_key().to_bytes()),
                "balance-width": self.balance_width,
                "initial-balance": self.initial_balance,
                "spend-amount": self.spend_amount,
                "max-top-up": self.max_top_up,
                "accepted-anchor-keys": accepted,
                "epochs": [b64_encode(&self.issuance_epoch)],
                "allow-no-endorsement": false,
                "issuance-uri": self.issuance_uri(),
            }]
        })
        .to_string()
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        if request.path == "/.well-known/mole-moderator" && request.method == "GET" {
            return Response::json(self.configuration_json());
        }
        if request.path == "/mole/issue" && request.method == "POST" {
            return self.handle_issue(&request.authorization);
        }
        if request.path == "/gate" {
            return self.handle_gate(&request.authorization);
        }
        if request.path == "/stats" {
            return Response::json(
                serde_json::json!({
                    "redemptions": self.redemptions,
                    "presentations": self.presentations,
                    "settlements": self.settlements,
                    "nullifiers": self.recent_nullifiers,
                })
                .to_string(),
            );
        }
        Response::text(404, "not found\n")
    }

    fn challenge_401(&self) -> Response {
        let challenges = vec![
            MoleChallenge::Credential {
                credential_type: credential_type::EC_ACT,
                challenge: self.ec_act_challenge().to_bytes().unwrap(),
            },
            MoleChallenge::Redeem {
                endorsement_type: endorsement_type::EC_IHAT,
                challenge: self.redemption_challenge,
            },
        ];
        Response {
            status: 401,
            headers: vec![
                ("Content-Type".into(), "text/plain".into()),
                (
                    "WWW-Authenticate".into(),
                    format_www_authenticate(&challenges).unwrap(),
                ),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: b"credential required\n".to_vec(),
        }
    }

    fn finalize_held(&mut self, nullifier: &[u8; 32], now: u64) -> Option<String> {
        let rec = self.recorded_spends.get(nullifier)?;
        let raw_spend = match &rec.decision {
            RecordedDecision::Held { raw_spend, .. } => raw_spend.clone(),
            RecordedDecision::Refund(bytes) => {
                return MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: Some(bytes.clone()),
                }
                .to_header_value()
                .ok();
            }
        };
        let spend_msg = ec_act::SpendMessage::from_bytes(&self.params, &raw_spend).ok()?;
        let ctx_spend = self.ec_act_challenge().ctx_spend().ok()?;
        let verified = ec_act::verify_spend(
            &self.params,
            &self.secret_key,
            &self.ctx_cred,
            &ctx_spend,
            &spend_msg,
        )
        .ok()?;
        let refund = ec_act::issue_refund(verified, self.refund_amount).ok()?;
        let bytes = EcActUpdate { refund }.to_bytes();
        let header = MoleCredential::Update {
            credential_type: credential_type::EC_ACT,
            update: Some(bytes.clone()),
        }
        .to_header_value()
        .ok()?;
        if let Some(record) = self.recorded_spends.get_mut(nullifier) {
            record.decision = RecordedDecision::Refund(bytes);
            record.recorded_at = now;
        }
        Some(header)
    }

    fn handle_issue(&mut self, authorization: &str) -> Response {
        if authorization.is_empty() {
            return self.challenge_401();
        }
        let Ok(auth) = MoleAuthorization::parse(authorization) else {
            return Response::text(400, "malformed Authorization\n");
        };
        let now = unix_now_secs();

        match auth {
            MoleAuthorization::RedeemAndIssue {
                endorsement_type: endorsement_type::EC_IHAT,
                redemption,
                credential_type: credential_type::EC_ACT,
                credential_request,
            } => {
                let Ok(iss_req) =
                    EcActIssuanceRequest::from_bytes(&self.params, &credential_request)
                else {
                    return Response::text(400, "malformed IssuanceRequest\n");
                };
                if iss_req.truncated_key_id != self.key_id[31]
                    || iss_req.credential_context != self.credential_context
                {
                    return Response::text(403, "unknown key or credential_context\n");
                }
                let Ok(verified_req) =
                    ec_act::verify_issue_request(&self.params, &iss_req.request)
                else {
                    return Response::text(403, "invalid IssueRequest proof\n");
                };
                let Ok(red) =
                    ec_ihat::Redemption::from_bytes(&redemption, self.anchor_set.len())
                else {
                    return Response::text(403, "malformed EC-IHAT Redemption\n");
                };
                let challenge_dig = sha256(&self.redemption_challenge);
                let Ok(nf) = ec_ihat::verify_redemption(
                    &self.anchor_set,
                    &red,
                    &self.issuance_epoch,
                    EC_IHAT_CTX_RED,
                    &challenge_dig,
                ) else {
                    return Response::text(403, "EC-IHAT verification failed\n");
                };
                let Ok(response) = ec_act::issue_response(
                    &self.secret_key,
                    &self.ctx_cred,
                    self.initial_balance,
                    verified_req,
                ) else {
                    return Response::text(403, "EC-ACT issue_response failed\n");
                };
                if !self.seen_endorsement_nullifiers.insert(nf) {
                    return Response::text(403, "replayed endorsement nullifier\n");
                }
                self.redemptions += 1;
                let mole_cred = MoleCredential::Response {
                    credential_type: credential_type::EC_ACT,
                    response: EcActIssuanceResponse { response }.to_bytes(),
                }
                .to_header_value()
                .unwrap();
                Response {
                    status: 200,
                    headers: vec![
                        ("Content-Type".into(), "text/plain".into()),
                        ("Mole-Credential".into(), mole_cred),
                        ("Cache-Control".into(), "no-store".into()),
                    ],
                    body: Vec::new(),
                }
            }
            MoleAuthorization::Recovery {
                credential_type: credential_type::EC_ACT,
                recovery_handle,
            } => {
                let Ok(handle) = RecoveryHandle::from_bytes(&recovery_handle) else {
                    return Response::text(400, "malformed RecoveryHandle\n");
                };
                if handle.key_id != self.key_id {
                    return Response::text(404, "not found\n");
                }
                let Some(rec) = self.recorded_spends.get(&handle.nullifier) else {
                    return Response::text(404, "not found\n");
                };
                if rec.presentation_sha256 != handle.presentation_sha256 {
                    return Response::text(404, "not found\n");
                }
                match &rec.decision {
                    RecordedDecision::Held { hold_until, .. } => {
                        if now < *hold_until {
                            return Response::text(404, "still held\n");
                        }
                        let Some(mole_cred) = self.finalize_held(&handle.nullifier, now) else {
                            return Response::text(404, "not found\n");
                        };
                        self.settlements += 1;
                        Response {
                            status: 200,
                            headers: vec![
                                ("Content-Type".into(), "text/plain".into()),
                                ("Mole-Credential".into(), mole_cred),
                                ("Cache-Control".into(), "no-store".into()),
                            ],
                            body: Vec::new(),
                        }
                    }
                    RecordedDecision::Refund(bytes) => {
                        if now.saturating_sub(rec.recorded_at) > self.result_retention_secs {
                            return Response::text(404, "expired\n");
                        }
                        let mole_cred = MoleCredential::Update {
                            credential_type: credential_type::EC_ACT,
                            update: Some(bytes.clone()),
                        }
                        .to_header_value()
                        .unwrap();
                        self.settlements += 1;
                        Response {
                            status: 200,
                            headers: vec![
                                ("Content-Type".into(), "text/plain".into()),
                                ("Mole-Credential".into(), mole_cred),
                                ("Cache-Control".into(), "no-store".into()),
                            ],
                            body: Vec::new(),
                        }
                    }
                }
            }
            MoleAuthorization::Signoff {
                credential_type: credential_type::EC_ACT,
                recovery_handle,
            } => {
                let Ok(handle) = RecoveryHandle::from_bytes(&recovery_handle) else {
                    return Response::text(400, "malformed RecoveryHandle\n");
                };
                if handle.key_id != self.key_id {
                    return Response::text(404, "not found\n");
                }
                let Some(rec) = self.recorded_spends.get(&handle.nullifier) else {
                    return Response::text(404, "not found\n");
                };
                if rec.presentation_sha256 != handle.presentation_sha256 {
                    return Response::text(404, "not found\n");
                }
                let Some(mole_cred) = self.finalize_held(&handle.nullifier, now) else {
                    return Response::text(404, "not found\n");
                };
                self.settlements += 1;
                Response {
                    status: 200,
                    headers: vec![
                        ("Content-Type".into(), "text/plain".into()),
                        ("Mole-Credential".into(), mole_cred),
                        ("Cache-Control".into(), "no-store".into()),
                    ],
                    body: Vec::new(),
                }
            }
            _ => Response::text(400, "unsupported issuance operation\n"),
        }
    }

    fn handle_gate(&mut self, authorization: &str) -> Response {
        if authorization.is_empty() {
            return self.challenge_401();
        }
        let Ok(auth) = MoleAuthorization::parse(authorization) else {
            return Response::text(400, "malformed Authorization\n");
        };
        let MoleAuthorization::Presentation {
            credential_type: ct,
            presentation,
        } = auth
        else {
            return Response::text(400, "expected presentation on /gate\n");
        };
        if ct != credential_type::EC_ACT {
            return self.challenge_401();
        }
        let Ok(pau) = EcActPresentationAndUpdate::from_bytes(&self.params, &presentation) else {
            return Response::text(403, "malformed PresentationAndUpdate\n");
        };
        if pau.key_id != self.key_id {
            return Response::text(403, "unknown key_id\n");
        };

        let now = unix_now_secs();
        let nf = pau.spend.nullifier();
        let pau_sha256 = sha256(&presentation);

        if let Some(existing) = self.recorded_spends.get(&nf) {
            if existing.presentation_sha256 != pau_sha256
                || now.saturating_sub(existing.recorded_at) > self.result_retention_secs
            {
                return Response::text(403, "conflicting or expired duplicate presentation\n");
            }
            let mole_cred = match &existing.decision {
                RecordedDecision::Held { hold_until, .. } => MoleCredential::HeldForUpdate {
                    credential_type: credential_type::EC_ACT,
                    duration_secs: hold_until.saturating_sub(now),
                },
                RecordedDecision::Refund(bytes) => MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: Some(bytes.clone()),
                },
            }
            .to_header_value()
            .unwrap();
            return Response {
                status: 409,
                headers: vec![
                    ("Content-Type".into(), "text/plain".into()),
                    ("Mole-Credential".into(), mole_cred),
                    ("Cache-Control".into(), "no-store".into()),
                ],
                body: b"duplicate presentation\n".to_vec(),
            };
        }

        if pau.spend.amount() != self.spend_amount || pau.spend.allowance() != self.max_top_up {
            return Response::text(403, "spend amounts do not match challenge\n");
        }
        let Ok(ctx_spend) = self.ec_act_challenge().ctx_spend() else {
            return Response::text(500, "challenge encode failed\n");
        };
        let Ok(verified) = ec_act::verify_spend(
            &self.params,
            &self.secret_key,
            &self.ctx_cred,
            &ctx_spend,
            &pau.spend,
        ) else {
            return Response::text(403, "EC-ACT verify_spend failed\n");
        };

        let (decision, mole_cred) = if self.hold_duration_secs > 0 {
            (
                RecordedDecision::Held {
                    hold_until: now.saturating_add(self.hold_duration_secs),
                    raw_spend: pau.spend.to_bytes(),
                },
                MoleCredential::HeldForUpdate {
                    credential_type: credential_type::EC_ACT,
                    duration_secs: self.hold_duration_secs,
                }
                .to_header_value()
                .unwrap(),
            )
        } else {
            let Ok(refund) = ec_act::issue_refund(verified, self.refund_amount) else {
                return Response::text(403, "EC-ACT issue_refund failed\n");
            };
            let bytes = EcActUpdate { refund }.to_bytes();
            (
                RecordedDecision::Refund(bytes.clone()),
                MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: Some(bytes),
                }
                .to_header_value()
                .unwrap(),
            )
        };

        self.recorded_spends.insert(
            nf,
            RecordedPresentation {
                presentation_sha256: pau_sha256,
                recorded_at: now,
                decision,
            },
        );
        self.presentations += 1;
        self.recent_nullifiers.insert(0, to_hex(&nf));
        self.recent_nullifiers.truncate(8);

        Response {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "text/plain".into()),
                ("Mole-Credential".into(), mole_cred),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: b"access granted: you are vouched for\n".to_vec(),
        }
    }
}
