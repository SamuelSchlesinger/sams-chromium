// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A runnable MoLE demo: standalone Anchor and Moderator HTTP servers built on
//! the same first-party BoringSSL crypto the browser uses
//! (`act_boring`/`ihat_boring`/`mole_core`/`sigma_boring`), so their wire
//! format is byte-compatible with `//components/moderated_endorsements` by
//! construction. The protocol logic mirrors the in-FFI `TestMoleAnchor` /
//! `TestMoleModerator`; here it speaks real HTTP/1.1 over `std::net`.
//!
//! Not production code: single-threaded, plaintext HTTP, no TLS. It exists so a
//! content_shell/chrome build can run the whole cross-site flow against local
//! `anchor.com` / `antifraud.com` servers.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use act_boring::proofs::request_context_scalar;
use act_boring::spend::{scalar_to_u128, SpendProof};
use act_boring::{
    IssuanceRequest as ActIssuanceRequestMsg, Params as ActParams, PrivateKey as ActPrivateKey,
    Scalar as ActScalar,
};
use ihat_boring::anchor::AnchorSecretKey;
use ihat_boring::wire::decode_anchor_key;
use ihat_boring::{Point as IhatKey, ProofRequest, SignatureRequest};
use mole_core::act::{key_id, BALANCE_DIGITS};
use mole_core::config::{
    AnchorDirectory, AnchorEndorsementConfig, ModeratorDirectory, ModeratorPolicy,
};
use mole_core::http::{b64_encode, MoleAuthorization, MoleChallenge, MoleCredential};
use mole_core::messages::{
    ActChallenge, ActIssuanceRequest, ActIssuanceResponse, ActPresentationAndUpdate, ActUpdate,
    CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
    CredentialUpdate, EndorsementRequest, EndorsementResponse, IhatChallenge, IhatGrantRequest,
    IhatGrantResponse, IhatPresentation, ModeratorChallenge, OptionalCredentialUpdate,
};
use mole_core::wire::Wire;
use mole_core::{challenge_digest, credential_type, endorsement_type};
use sigma_boring::fill_random;

// ---------------------------------------------------------------------------
// A minimal HTTP response, and the tiny HTTP/1.1 server loop.
// ---------------------------------------------------------------------------

/// One HTTP response: status, extra headers (name, value), and a body.
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: body.as_bytes().to_vec(),
        }
    }
    fn json(body: String) -> Response {
        Response {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into_bytes(),
        }
    }
}

/// A parsed request: method, path, the `Authorization` value, and the body.
pub struct Request {
    pub method: String,
    pub path: String,
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
        _ => "OK",
    }
}

fn read_request<S: Read>(stream: &mut S) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
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
            } else if name == "authorization" {
                authorization = value.to_string();
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(Request { method, path, authorization, body })
}

fn write_response<W: Write>(stream: &mut W, response: &Response) {
    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status));
    out.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    // Permissive CORS so the site pages can drive the servers from JS if needed.
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

// A BoringSSL TLS server: real HTTPS so the browser sees a genuine secure
// context by scheme (no --unsafely-treat-insecure-origin-as-secure). Uses the
// in-tree BoringSSL directly through bssl_sys.
mod tls {
    use bssl_sys::{
        SSL_CTX_free, SSL_CTX_new, SSL_CTX_use_PrivateKey_file,
        SSL_CTX_use_certificate_chain_file, SSL_accept, SSL_free, SSL_new, SSL_read,
        SSL_set_fd, SSL_shutdown, SSL_write, TLS_method, SSL, SSL_CTX,
    };
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_void};

    // PEM file type constant (openssl/ssl.h). bssl_sys does not re-export the
    // #define, so spell it out.
    const SSL_FILETYPE_PEM: c_int = 1;

    /// A TLS server context holding the loaded certificate and key.
    pub struct SslContext(*mut SSL_CTX);

    impl SslContext {
        pub fn new(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
            // SAFETY: standard BoringSSL server-context setup; every raw call
            // is checked, and the context is used single-threaded in serve().
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
            // SAFETY: `self.0` is a live SSL_CTX from SSL_CTX_new.
            unsafe { SSL_CTX_free(self.0) };
        }
    }

    /// One accepted TLS connection; reads/writes go through the SSL object.
    pub struct SslStream {
        ssl: *mut SSL,
        _tcp: TcpStream,
    }

    impl SslStream {
        pub fn accept(ctx: &SslContext, tcp: TcpStream) -> Result<SslStream, String> {
            // SAFETY: `ctx.0` is a live SSL_CTX; `tcp` outlives the SSL via the
            // `_tcp` field, so the fd stays valid for the SSL's lifetime.
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
            // SAFETY: `buf` is valid for `buf.len()` bytes; blocking socket, so
            // SSL_read returns >0 on data, <=0 on close/error (treated as EOF).
            let n = unsafe {
                SSL_read(self.ssl, buf.as_mut_ptr() as *mut c_void, buf.len() as c_int)
            };
            Ok(if n <= 0 { 0 } else { n as usize })
        }
    }

    impl Write for SslStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // SAFETY: `buf` is valid for `buf.len()` bytes.
            let n = unsafe {
                SSL_write(self.ssl, buf.as_ptr() as *const c_void, buf.len() as c_int)
            };
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
            // SAFETY: `self.ssl` is a live SSL from SSL_new.
            unsafe {
                SSL_shutdown(self.ssl);
                SSL_free(self.ssl);
            }
        }
    }
}

/// Serve HTTPS forever on `addr` with the given PEM cert/key, dispatching each
/// request to `handler`.
pub fn serve<F: FnMut(&Request) -> Response>(
    addr: &str,
    cert_pem: &str,
    key_pem: &str,
    mut handler: F,
) -> std::io::Result<()> {
    let ctx = tls::SslContext::new(cert_pem, key_pem)
        .map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(addr)?;
    eprintln!("[mole-demo] listening (HTTPS) on {addr}");
    for stream in listener.incoming() {
        let tcp = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut ssl = match tls::SslStream::accept(&ctx, tcp) {
            Ok(s) => s,
            Err(_) => continue,  // non-TLS probe or handshake failure
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
// The Anchor: grants IHAT endorsements (mirrors TestMoleAnchor).
// ---------------------------------------------------------------------------

pub struct AnchorServer {
    key: AnchorSecretKey,
    endorsement_context: Vec<u8>,
    sessions: HashMap<Vec<u8>, ihat_boring::anchor::AnchorNeedsProofRequest>,
}

impl AnchorServer {
    pub fn new(epoch: &[u8]) -> AnchorServer {
        AnchorServer {
            key: AnchorSecretKey::random(),
            endorsement_context: epoch.to_vec(),
            sessions: HashMap::new(),
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
    }

    pub fn directory_json(&self) -> String {
        let directory = AnchorDirectory {
            endorsement_configs: vec![AnchorEndorsementConfig {
                endorsement_type: endorsement_type::IHAT,
                public_key: b64_encode(&self.public_key()),
                endorsement_context: b64_encode(&self.endorsement_context),
                endorse_endpoint: "/mole/endorse".to_string(),
            }],
        };
        serde_json::to_string(&directory).expect("directory serializes")
    }

    /// The registry entry the browser must commit for this Anchor's origin.
    pub fn commitment_json(&self) -> String {
        format!(
            "{{\"keys\":[\"{}\"],\"epochs\":[\"{}\"]}}",
            b64_encode(&self.public_key()),
            b64_encode(&self.endorsement_context)
        )
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        if request.path == "/.well-known/mole-anchor" {
            return Response::json(self.directory_json());
        }
        if request.path == "/mole/endorse" && request.method == "POST" {
            return self.endorse(&request.body);
        }
        Response::text(404, "not found\n")
    }

    fn endorse(&mut self, body: &[u8]) -> Response {
        let Ok(request) = EndorsementRequest::from_bytes(body) else {
            return Response::text(400, "malformed EndorsementRequest\n");
        };
        if request.endorsement_type != endorsement_type::IHAT {
            return Response::text(404, "unknown endorsement type\n");
        }
        let Ok(grant) = IhatGrantRequest::from_bytes(&request.body) else {
            return Response::text(400, "malformed grant body\n");
        };
        let response_body = match grant {
            IhatGrantRequest::Step1 { signature_request } => {
                let Ok(sig_request) = SignatureRequest::from_wire(&signature_request) else {
                    return Response::text(400, "malformed SignatureRequest\n");
                };
                if sig_request.endorsement_context != self.endorsement_context {
                    return Response::text(400, "wrong endorsement context\n");
                }
                let (signature, pending) = sig_request.sign(&self.key);
                let mut session_id = vec![0u8; 16];
                fill_random(&mut session_id);
                self.sessions.insert(session_id.clone(), pending);
                IhatGrantResponse::Step1 { session_id, signature: signature.to_wire() }
            }
            IhatGrantRequest::Step2 { session_id, proof_request } => {
                let Some(pending) = self.sessions.remove(&session_id) else {
                    return Response::text(400, "unknown or spent session\n");
                };
                let Ok(proof_request) = ProofRequest::from_wire(&proof_request) else {
                    return Response::text(400, "malformed ProofRequest\n");
                };
                let proof = pending.prove(&proof_request);
                IhatGrantResponse::Step2 { proof: proof.to_wire() }
            }
        };
        let response = EndorsementResponse {
            endorsement_type: endorsement_type::IHAT,
            body: response_body.to_bytes(),
        };
        Response {
            status: 200,
            headers: vec![(
                "Content-Type".into(),
                "application/mole-endorsement-response".into(),
            )],
            body: response.to_bytes(),
        }
    }
}

// ---------------------------------------------------------------------------
// The Moderator: challenge / Redeem & Issue / Present (mirrors
// TestMoleModerator).
// ---------------------------------------------------------------------------

pub struct ModeratorServer {
    policy_context: Vec<u8>,
    accepted_anchor_keys: Vec<[u8; 33]>,
    endorsement_context: Vec<u8>,
    initial_credits: u64,
    issuance_batch: u64,
    charge: u64,
    refund: u64,
    act_domain_separator: Vec<u8>,
    accepted: Vec<IhatKey>,
    act_params: ActParams,
    act_key: ActPrivateKey,
    act_key_id: [u8; 32],
    act_ctx: ActScalar,
    seen_endorsement_nullifiers: HashSet<Vec<u8>>,
    seen_spend_nullifiers: HashSet<[u8; 32]>,
    pub redemptions: u64,
    pub presentations: u64,
    /// The spend nullifiers seen, most recent first, hex — for the demo to
    /// show what the Moderator observes: a pile of fresh one-time values it
    /// cannot link to a credential, to each other, or to a redemption.
    recent_nullifiers: Vec<String>,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl ModeratorServer {
    pub fn new(
        accepted_anchor_key: &[u8],
        epoch: &[u8],
        policy: &[u8],
        initial_credits: u64,
        issuance_batch: u64,
        charge: u64,
        refund: u64,
    ) -> Result<ModeratorServer, String> {
        let mut key = [0u8; 33];
        if accepted_anchor_key.len() != 33 {
            return Err("anchor key must be 33 bytes".into());
        }
        key.copy_from_slice(accepted_anchor_key);
        let accepted =
            vec![decode_anchor_key(&key).map_err(|_| "anchor key does not decode".to_string())?];
        let act_domain_separator = b"MoLE-demo:act:v1".to_vec();
        let act_params = ActParams::from_domain_separator(&act_domain_separator);
        let act_key = ActPrivateKey::random();
        let act_key_id = key_id(&act_key.public().to_wire());
        let act_ctx = request_context_scalar(policy, epoch);
        Ok(ModeratorServer {
            policy_context: policy.to_vec(),
            accepted_anchor_keys: vec![key],
            endorsement_context: epoch.to_vec(),
            initial_credits,
            issuance_batch,
            charge,
            refund,
            act_domain_separator,
            accepted,
            act_params,
            act_key,
            act_key_id,
            act_ctx,
            seen_endorsement_nullifiers: HashSet::new(),
            seen_spend_nullifiers: HashSet::new(),
            redemptions: 0,
            presentations: 0,
            recent_nullifiers: Vec::new(),
        })
    }

    fn moderator_challenge(&self) -> ModeratorChallenge {
        ModeratorChallenge {
            endorsement_type: endorsement_type::IHAT,
            challenge: IhatChallenge { keys: self.accepted_anchor_keys.clone() }.to_bytes(),
        }
    }

    fn credential_challenge(&self) -> CredentialChallenge {
        CredentialChallenge {
            credential_type: credential_type::ACT,
            challenge: ActChallenge {
                policy_context: self.policy_context.clone(),
                charge: self.charge,
                topup: 0,
            }
            .to_bytes(),
        }
    }

    pub fn directory_json(&self) -> String {
        let directory = ModeratorDirectory {
            policies: vec![ModeratorPolicy {
                policy_context: b64_encode(&self.policy_context),
                credential_type: credential_type::ACT,
                act_public_key: b64_encode(&self.act_key.public().to_wire()),
                act_domain_separator: b64_encode(&self.act_domain_separator),
                act_balance_digits: BALANCE_DIGITS as u64,
                initial_credits: self.initial_credits,
                issuance_batch: self.issuance_batch,
                charge: self.charge,
                endorsement_type: endorsement_type::IHAT,
                accepted_anchor_keys: self.accepted_anchor_keys.iter().map(|k| b64_encode(k)).collect(),
                endorsement_context: b64_encode(&self.endorsement_context),
            }],
        };
        serde_json::to_string(&directory).expect("directory serializes")
    }

    /// The committed policy the browser must have for this Moderator's origin.
    pub fn commitment_json(&self) -> String {
        let accepted: Vec<String> =
            self.accepted_anchor_keys.iter().map(|k| format!("\"{}\"", b64_encode(k))).collect();
        format!(
            "{{\"policies\":[{{\"policy-context\":\"{}\",\"act-public-key\":\"{}\",\
             \"act-domain-separator\":\"{}\",\"accepted-anchor-keys\":[{}],\
             \"epochs\":[\"{}\"],\"charge\":{},\"topup\":0}}]}}",
            b64_encode(&self.policy_context),
            b64_encode(&self.act_key.public().to_wire()),
            b64_encode(&self.act_domain_separator),
            accepted.join(","),
            b64_encode(&self.endorsement_context),
            self.charge,
        )
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        if request.path == "/.well-known/mole-moderator" {
            return Response::json(self.directory_json());
        }
        if request.path == "/gate" {
            return self.resource(&request.authorization);
        }
        if request.path == "/stats" {
            let nullifiers: Vec<String> =
                self.recent_nullifiers.iter().map(|n| format!("\"{n}\"")).collect();
            return Response::json(format!(
                "{{\"redemptions\":{},\"presentations\":{},\"nullifiers\":[{}]}}",
                self.redemptions,
                self.presentations,
                nullifiers.join(",")
            ));
        }
        Response::text(404, "not found\n")
    }

    fn challenge_response(&self, mole_credential: String) -> Response {
        let credential = MoleChallenge {
            challenge: self.credential_challenge().to_bytes(),
            realm: Some("moderator".into()),
        };
        let endorsement = MoleChallenge {
            challenge: self.moderator_challenge().to_bytes(),
            realm: Some("moderator".into()),
        };
        let mut headers = vec![
            ("WWW-Authenticate".into(), credential.to_header_value()),
            ("WWW-Authenticate".into(), endorsement.to_header_value()),
        ];
        if !mole_credential.is_empty() {
            headers.push(("Mole-Credential".into(), mole_credential));
        }
        Response { status: 401, headers, body: b"credential required\n".to_vec() }
    }

    fn reject(&self) -> Response {
        Response::text(403, "rejected\n")
    }

    fn resource(&mut self, authorization: &str) -> Response {
        if authorization.is_empty() {
            return self.challenge_response(String::new());
        }
        match MoleAuthorization::parse(authorization) {
            Err(_) => self.challenge_response(String::new()),
            Ok(MoleAuthorization::CredentialRequest(bytes)) => self.redeem_and_issue(&bytes),
            Ok(MoleAuthorization::Presentation(bytes)) => self.present(&bytes),
        }
    }

    fn redeem_and_issue(&mut self, bytes: &[u8]) -> Response {
        let Ok(request) = CredentialRequest::from_bytes(bytes) else {
            return self.reject();
        };
        if request.endorsement_type != endorsement_type::IHAT
            || request.credential_type != credential_type::ACT
        {
            return self.challenge_response(String::new());
        }
        let Ok(presentation) = IhatPresentation::from_bytes(&request.endorsement_presentation)
        else {
            return self.reject();
        };
        let Ok(presentation) = ihat_boring::Presentation::from_wire(&presentation.bytes) else {
            return self.reject();
        };
        let binding = challenge_digest(&self.moderator_challenge().to_bytes());
        if !presentation.verify(&self.accepted, &binding) {
            return self.reject();
        }
        if presentation.endorsement.endorsement_context != self.endorsement_context {
            return self.reject();
        }
        let Ok(issuance) = ActIssuanceRequest::from_bytes(&request.issuance_request) else {
            return self.reject();
        };
        if issuance.truncated_key_id != self.act_key_id[31] {
            return self.reject();
        }
        if issuance.requests.len() as u64 != self.issuance_batch {
            return self.reject();
        }
        let Ok(act_requests) = issuance
            .requests
            .iter()
            .map(|bytes| ActIssuanceRequestMsg::from_wire(bytes))
            .collect::<Result<Vec<_>, _>>()
        else {
            return self.reject();
        };
        let Ok(responses) = act_requests
            .iter()
            .map(|act_request| {
                self.act_key
                    .issue::<BALANCE_DIGITS>(
                        &self.act_params,
                        act_request,
                        u128::from(self.initial_credits),
                        self.act_ctx.clone(),
                    )
                    .map(|response| response.to_wire().expect("issuance response encodes"))
            })
            .collect::<Result<Vec<_>, _>>()
        else {
            return self.reject();
        };
        if !self.seen_endorsement_nullifiers.insert(presentation.endorsement.nf.clone()) {
            return self.reject();
        }
        self.redemptions += 1;
        let credential_response = CredentialResponse {
            credential_type: credential_type::ACT,
            issuance_response: ActIssuanceResponse { responses }.to_bytes(),
        };
        self.challenge_response(
            MoleCredential::Response(credential_response.to_bytes()).to_header_value(),
        )
    }

    fn present(&mut self, bytes: &[u8]) -> Response {
        let Ok(presentation) = CredentialPresentation::from_bytes(bytes) else {
            return self.reject();
        };
        if presentation.credential_type != credential_type::ACT {
            return self.challenge_response(String::new());
        }
        let Ok(pau) = ActPresentationAndUpdate::from_bytes(&presentation.presentation_and_update)
        else {
            return self.reject();
        };
        let expected_digest = challenge_digest(&self.credential_challenge().to_bytes());
        if pau.challenge_digest != expected_digest || pau.key_id != self.act_key_id {
            return self.reject();
        }
        let Ok(spend) = SpendProof::from_wire(&pau.spend_proof) else {
            return self.reject();
        };
        if scalar_to_u128(&spend.s) != Some(u128::from(self.charge))
            || scalar_to_u128(&spend.a) != Some(0)
            || !spend.ctx.ct_eq(&self.act_ctx)
        {
            return self.reject();
        }
        let Ok(refund) =
            self.act_key.refund(&self.act_params, &spend, u128::from(self.refund), BALANCE_DIGITS)
        else {
            return self.reject();
        };
        if !self.seen_spend_nullifiers.insert(spend.k.to_bytes()) {
            return self.reject();
        }
        self.presentations += 1;
        self.recent_nullifiers.insert(0, to_hex(&spend.k.to_bytes()));
        self.recent_nullifiers.truncate(8);
        let update = OptionalCredentialUpdate {
            update: Some(CredentialUpdate {
                credential_type: credential_type::ACT,
                update_response: ActUpdate { refund: refund.to_wire().expect("refund encodes") }
                    .to_bytes(),
            }),
        };
        Response {
            status: 200,
            headers: vec![(
                "Mole-Credential".into(),
                MoleCredential::Update(update.to_bytes()).to_header_value(),
            )],
            body: b"access granted: you are vouched for\n".to_vec(),
        }
    }
}
