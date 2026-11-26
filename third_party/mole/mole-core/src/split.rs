// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Split Moderation & Redemption (`internet-drafts#188`, `#186`, `#34`, `#152`):
//!
//! - **Plane 1 (Client <-> Origin RFC 9651 Structured Field Headers, `< 350 B`)**:
//!   - [`SplitMoleChallenge`] (`Mole-Challenge` response header)
//!   - [`SecMoleAuthorization`] (`Sec-Mole-Authorization` forbidden request header)
//!   - [`SecMoleGrease`] (`Sec-Mole-Grease` wire greasing header)
//!   - [`MoleInfo`] (`Mole-Info` response header)
//! - **Plane 2 (Client <-> Moderator HTTPS POST Binary Envelopes)**:
//!   - [`ClearanceToken`] (Origin-bound compact clearance token signed by Moderator)
//!   - [`IssueRequestEnvelope`] / [`IssueResponseEnvelope`] (`POST /mole/v1/issue`, with 32-byte `idempotency_key`)
//!   - [`PresentRequestEnvelope`] / [`PresentResponseEnvelope`] (`POST /mole/v1/present`)
//!   - [`SettleRequestEnvelope`] / [`SettleResponseEnvelope`] (`POST /mole/v1/settle`)

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::config::validate_https_origin;
use crate::credential_type;
use crate::http::HeaderError;
use crate::messages::{ProtectedRequestContext, RecoveryHandle};
use crate::wire::{
    Wire, WireError, get_fixed, get_opaque_bounded, get_str_v, get_u8, get_u16, get_u32, get_u64,
    put_opaque_v, put_str_v, put_u8, put_u16, put_u32, put_u64,
};
use crate::{MAX_MOLE_ENVELOPE_LEN, MAX_MOLE_HEADER_LEN};

/// Lowercase `Mole-Challenge` Origin response header name.
pub const MOLE_CHALLENGE_HEADER: &str = "mole-challenge";
/// Lowercase `Sec-Mole-Authorization` Origin forbidden request header name.
pub const SEC_MOLE_AUTHORIZATION_HEADER: &str = "sec-mole-authorization";
/// Lowercase `Sec-Mole-Grease` Origin forbidden request header name.
pub const SEC_MOLE_GREASE_HEADER: &str = "sec-mole-grease";
/// Lowercase `Mole-Info` Origin response header name.
pub const MOLE_INFO_HEADER: &str = "mole-info";
/// Media type for Split Moderator HTTPS POST envelopes.
pub const MOLE_ENVELOPE_MEDIA_TYPE: &str = "application/mole+octet-stream";

/// Domain-separation prefix for `ClearanceToken` signatures.
pub const CLEARANCE_TOKEN_DST: &[u8] = b"MOLE-CLEARANCE-TOKEN-v1";
/// Domain-separation prefix for cross-site `Mole-Challenge` delegation signatures.
pub const CHALLENGE_DELEGATION_DST: &[u8] = b"MOLE-CHALLENGE-DELEGATION-v1";

// ---------------------------------------------------------------------------
// Minimal RFC 9651 Structured Field Dictionary Parser & Serializer Helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum SfValue {
    String(String),
    Integer(u64),
    ByteSeq(Vec<u8>),
    Bool(bool),
    Token(String),
    Other,
}

fn is_sf_key_start(b: u8) -> bool {
    b.is_ascii_lowercase() || b == b'*'
}

fn is_sf_key_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'*')
}

fn is_sf_string_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

fn format_sf_string(s: &str) -> Result<String, HeaderError> {
    if !s.bytes().all(is_sf_string_printable) {
        return Err(HeaderError::MalformedParams);
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    Ok(out)
}

fn format_sf_bytes(bytes: &[u8]) -> String {
    format!(":{}:", STANDARD.encode(bytes))
}

/// Parses an RFC 9651 Dictionary (comma-separated `key=member-value` or bare boolean `key`,
/// with optional `;param-key[=bare-item]` item parameters attached to each member).
/// Rejects duplicate dictionary keys, non-printable characters, and inputs exceeding `MAX_MOLE_HEADER_LEN`.
fn parse_sf_dict(input: &str) -> Result<Vec<(String, SfValue)>, HeaderError> {
    if input.len() > MAX_MOLE_HEADER_LEN {
        return Err(HeaderError::TooLarge);
    }
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    let mut out: Vec<(String, SfValue)> = Vec::new();

    let skip_ows = |i: &mut usize| {
        while *i < bytes.len() && matches!(bytes[*i], b' ' | b'\t') {
            *i += 1;
        }
    };

    skip_ows(&mut idx);
    if idx == bytes.len() {
        return Err(HeaderError::MalformedParams);
    }

    while idx < bytes.len() {
        if !is_sf_key_start(bytes[idx]) {
            return Err(HeaderError::MalformedParams);
        }
        let key_start = idx;
        idx += 1;
        while idx < bytes.len() && is_sf_key_char(bytes[idx]) {
            idx += 1;
        }
        let key = std::str::from_utf8(&bytes[key_start..idx])
            .map_err(|_| HeaderError::MalformedParams)?
            .to_string();
        if out.iter().any(|(k, _)| k == &key) {
            return Err(HeaderError::MalformedParams);
        }

        let val = if idx < bytes.len() && bytes[idx] == b'=' {
            idx += 1;
            parse_sf_member_value(bytes, &mut idx)?
        } else {
            SfValue::Bool(true)
        };

        consume_sf_parameters(bytes, &mut idx)?;
        out.push((key, val));
        skip_ows(&mut idx);
        if idx == bytes.len() {
            break;
        }
        if bytes[idx] == b',' {
            idx += 1;
            skip_ows(&mut idx);
            if idx == bytes.len() {
                return Err(HeaderError::MalformedParams);
            }
        } else {
            return Err(HeaderError::MalformedParams);
        }
    }

    Ok(out)
}

fn consume_sf_parameters(bytes: &[u8], idx: &mut usize) -> Result<(), HeaderError> {
    while *idx < bytes.len() && bytes[*idx] == b';' {
        *idx += 1;
        while *idx < bytes.len() && bytes[*idx] == b' ' {
            *idx += 1;
        }
        if *idx >= bytes.len() || !is_sf_key_start(bytes[*idx]) {
            return Err(HeaderError::MalformedParams);
        }
        *idx += 1;
        while *idx < bytes.len() && is_sf_key_char(bytes[*idx]) {
            *idx += 1;
        }
        if *idx < bytes.len() && bytes[*idx] == b'=' {
            *idx += 1;
            let _ = parse_sf_bare_item(bytes, idx)?;
        }
    }
    Ok(())
}

fn parse_sf_member_value(bytes: &[u8], idx: &mut usize) -> Result<SfValue, HeaderError> {
    if *idx >= bytes.len() {
        return Err(HeaderError::MalformedParams);
    }
    if bytes[*idx] == b'(' {
        *idx += 1;
        loop {
            while *idx < bytes.len() && bytes[*idx] == b' ' {
                *idx += 1;
            }
            if *idx >= bytes.len() {
                return Err(HeaderError::MalformedParams);
            }
            if bytes[*idx] == b')' {
                *idx += 1;
                return Ok(SfValue::Other);
            }
            let _ = parse_sf_bare_item(bytes, idx)?;
            consume_sf_parameters(bytes, idx)?;
            if *idx < bytes.len() && !matches!(bytes[*idx], b' ' | b')') {
                return Err(HeaderError::MalformedParams);
            }
        }
    }
    parse_sf_bare_item(bytes, idx)
}

fn parse_sf_bare_item(bytes: &[u8], idx: &mut usize) -> Result<SfValue, HeaderError> {
    if *idx >= bytes.len() {
        return Err(HeaderError::MalformedParams);
    }
    match bytes[*idx] {
        b'"' => {
            *idx += 1;
            let mut s = String::new();
            while *idx < bytes.len() {
                let b = bytes[*idx];
                *idx += 1;
                if b == b'"' {
                    return Ok(SfValue::String(s));
                }
                if b == b'\\' {
                    if *idx >= bytes.len() {
                        return Err(HeaderError::MalformedParams);
                    }
                    let esc = bytes[*idx];
                    *idx += 1;
                    if esc != b'"' && esc != b'\\' {
                        return Err(HeaderError::MalformedParams);
                    }
                    s.push(esc as char);
                } else if is_sf_string_printable(b) {
                    s.push(b as char);
                } else {
                    return Err(HeaderError::MalformedParams);
                }
            }
            Err(HeaderError::MalformedParams)
        }
        b':' => {
            *idx += 1;
            let start = *idx;
            while *idx < bytes.len() && bytes[*idx] != b':' {
                let b = bytes[*idx];
                if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
                    return Err(HeaderError::InvalidBase64);
                }
                *idx += 1;
            }
            if *idx >= bytes.len() || bytes[*idx] != b':' {
                return Err(HeaderError::MalformedParams);
            }
            let raw_b64 =
                std::str::from_utf8(&bytes[start..*idx]).map_err(|_| HeaderError::InvalidBase64)?;
            *idx += 1;
            let decoded = STANDARD
                .decode(raw_b64)
                .map_err(|_| HeaderError::InvalidBase64)?;
            Ok(SfValue::ByteSeq(decoded))
        }
        b'?' => {
            *idx += 1;
            if *idx >= bytes.len() {
                return Err(HeaderError::MalformedParams);
            }
            let flag = match bytes[*idx] {
                b'1' => true,
                b'0' => false,
                _ => return Err(HeaderError::MalformedParams),
            };
            *idx += 1;
            Ok(SfValue::Bool(flag))
        }
        b'-' => {
            *idx += 1;
            let start = *idx;
            while *idx < bytes.len() && bytes[*idx].is_ascii_digit() {
                *idx += 1;
            }
            if *idx == start || *idx - start > 15 {
                return Err(HeaderError::MalformedParams);
            }
            if *idx < bytes.len() && bytes[*idx] == b'.' {
                if *idx - start > 12 {
                    return Err(HeaderError::MalformedParams);
                }
                *idx += 1;
                let frac_start = *idx;
                while *idx < bytes.len() && bytes[*idx].is_ascii_digit() {
                    *idx += 1;
                }
                if *idx == frac_start || *idx - frac_start > 3 {
                    return Err(HeaderError::MalformedParams);
                }
            }
            Ok(SfValue::Other)
        }
        b if b.is_ascii_digit() => {
            let start = *idx;
            if b == b'0'
                && *idx + 1 < bytes.len()
                && matches!(bytes[*idx + 1], b'x' | b'X')
            {
                // Hexadecimal grease token such as `0x2a2a`.
                *idx += 2;
                while *idx < bytes.len() && bytes[*idx].is_ascii_hexdigit() {
                    *idx += 1;
                }
                let tok = std::str::from_utf8(&bytes[start..*idx])
                    .map_err(|_| HeaderError::MalformedParams)?;
                return Ok(SfValue::Token(tok.to_string()));
            }
            while *idx < bytes.len() && bytes[*idx].is_ascii_digit() {
                *idx += 1;
            }
            if *idx < bytes.len() && bytes[*idx] == b'.' {
                if *idx - start > 12 {
                    return Err(HeaderError::MalformedParams);
                }
                *idx += 1;
                let frac_start = *idx;
                while *idx < bytes.len() && bytes[*idx].is_ascii_digit() {
                    *idx += 1;
                }
                if *idx == frac_start || *idx - frac_start > 3 {
                    return Err(HeaderError::MalformedParams);
                }
                return Ok(SfValue::Other);
            }
            if *idx - start > 15 {
                // RFC 9651 integers have at most 15 digits (`<= 999_999_999_999_999`).
                return Err(HeaderError::MalformedParams);
            }
            let num_str = std::str::from_utf8(&bytes[start..*idx])
                .map_err(|_| HeaderError::MalformedParams)?;
            let val = num_str
                .parse::<u64>()
                .map_err(|_| HeaderError::MalformedParams)?;
            Ok(SfValue::Integer(val))
        }
        b if b.is_ascii_alphabetic() || b == b'*' => {
            let start = *idx;
            *idx += 1;
            while *idx < bytes.len()
                && (bytes[*idx].is_ascii_alphanumeric()
                    || matches!(bytes[*idx], b'_' | b'-' | b'.' | b':' | b'*' | b'/'))
            {
                *idx += 1;
            }
            let tok = std::str::from_utf8(&bytes[start..*idx])
                .map_err(|_| HeaderError::MalformedParams)?;
            Ok(SfValue::Token(tok.to_string()))
        }
        _ => Err(HeaderError::MalformedParams),
    }
}

// ---------------------------------------------------------------------------
// Plane 1: Client <-> Origin Structured Field Headers (`< 350 B`)
// ---------------------------------------------------------------------------

/// Parsed `Mole-Challenge` Origin response header:
/// `moderator="https://...", policy="...", cost=2, nonce=:base64:, max-cost=10, exp=1800000000, sig=:base64:`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitMoleChallenge {
    /// Canonical HTTPS Moderator origin (`https://moderator.example:8442`).
    pub moderator: String,
    /// Policy identifier (`"default"` or named policy).
    pub policy: String,
    /// Required spend cost `s` for this request.
    pub cost: u64,
    /// Origin-fresh challenge nonce (`1..=128` bytes).
    pub nonce: Vec<u8>,
    /// Optional delegated maximum cost ceiling signed by the Moderator (`defaults to cost`).
    pub max_cost: Option<u64>,
    /// Optional delegation signature expiration (Unix seconds).
    pub exp: Option<u64>,
    /// Optional 64-byte Moderator delegation signature over `(target_origin, moderator, policy, max_cost, exp)`.
    pub sig: Option<Vec<u8>>,
}

impl SplitMoleChallenge {
    /// Formats as an RFC 9651 `Mole-Challenge` header value.
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        let canonical_mod =
            validate_https_origin(&self.moderator).map_err(|_| HeaderError::MalformedParams)?;
        if self.policy.is_empty() || self.policy.len() > 128 || self.nonce.is_empty() || self.nonce.len() > 128 {
            return Err(HeaderError::MalformedParams);
        }
        let mut parts = vec![
            format!("moderator={}", format_sf_string(&canonical_mod)?),
            format!("policy={}", format_sf_string(&self.policy)?),
            format!("cost={}", self.cost),
            format!("nonce={}", format_sf_bytes(&self.nonce)),
        ];
        if let Some(mc) = self.max_cost {
            parts.push(format!("max-cost={mc}"));
        }
        if let Some(exp) = self.exp {
            parts.push(format!("exp={exp}"));
        }
        if let Some(ref sig) = self.sig {
            parts.push(format!("sig={}", format_sf_bytes(sig)));
        }
        let out = parts.join(", ");
        if out.len() > MAX_MOLE_HEADER_LEN {
            return Err(HeaderError::TooLarge);
        }
        Ok(out)
    }

    /// Parses an RFC 9651 `Mole-Challenge` header value, ignoring unknown future SFV keys.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let dict = parse_sf_dict(value)?;
        let mut moderator = None;
        let mut policy = None;
        let mut cost = None;
        let mut nonce = None;
        let mut max_cost = None;
        let mut exp = None;
        let mut sig = None;

        for (k, v) in dict {
            match (k.as_str(), v) {
                ("moderator", SfValue::String(s)) => {
                    let canon = validate_https_origin(&s).map_err(|_| HeaderError::MalformedParams)?;
                    moderator = Some(canon);
                }
                ("policy", SfValue::String(s)) => {
                    if s.is_empty() || s.len() > 128 {
                        return Err(HeaderError::MalformedParams);
                    }
                    policy = Some(s);
                }
                ("cost", SfValue::Integer(n)) => cost = Some(n),
                ("nonce", SfValue::ByteSeq(b)) => {
                    if b.is_empty() || b.len() > 128 {
                        return Err(HeaderError::MalformedParams);
                    }
                    nonce = Some(b);
                }
                ("max-cost", SfValue::Integer(n)) => max_cost = Some(n),
                ("exp", SfValue::Integer(n)) => exp = Some(n),
                ("sig", SfValue::ByteSeq(b)) => {
                    if b.len() != 64 {
                        return Err(HeaderError::MalformedParams);
                    }
                    sig = Some(b);
                }
                (
                    "moderator" | "policy" | "cost" | "nonce" | "max-cost" | "exp" | "sig",
                    _,
                ) => return Err(HeaderError::MalformedParams),
                _ => {} // Unknown greased/extension keys are ignored.
            }
        }

        let challenge = Self {
            moderator: moderator.ok_or(HeaderError::MalformedParams)?,
            policy: policy.ok_or(HeaderError::MalformedParams)?,
            cost: cost.ok_or(HeaderError::MalformedParams)?,
            nonce: nonce.ok_or(HeaderError::MalformedParams)?,
            max_cost,
            exp,
            sig,
        };
        if let Some(mc) = challenge.max_cost {
            if challenge.cost > mc {
                return Err(HeaderError::MalformedParams);
            }
        }
        Ok(challenge)
    }

    /// Computes the canonical delegation signing message for cross-site Moderator authorization:
    /// `b"MOLE-CHALLENGE-DELEGATION-v1" || target_origin<V> || moderator<V> || policy<V> || u64(max_cost) || u64(exp)`.
    pub fn delegation_signing_payload(
        target_origin: &str,
        moderator_origin: &str,
        policy: &str,
        max_cost: u64,
        exp: u64,
    ) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(CHALLENGE_DELEGATION_DST);
        put_str_v(&mut out, target_origin, 256)?;
        put_str_v(&mut out, moderator_origin, 256)?;
        put_str_v(&mut out, policy, 128)?;
        put_u64(&mut out, max_cost);
        put_u64(&mut out, exp);
        Ok(out)
    }
}

/// Parsed `Sec-Mole-Authorization` Origin forbidden request header:
/// `clearance=:base64:, session="sess_..."`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecMoleAuthorization {
    /// Encoded signed [`ClearanceToken`] bytes.
    pub clearance: Vec<u8>,
    /// Optional opaque deferred-settlement session handle.
    pub session: Option<String>,
}

impl SecMoleAuthorization {
    /// Formats as an RFC 9651 `Sec-Mole-Authorization` header value.
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        if self.clearance.is_empty() || self.clearance.len() > 2048 {
            return Err(HeaderError::MalformedParams);
        }
        let mut out = format!("clearance={}", format_sf_bytes(&self.clearance));
        if let Some(ref sess) = self.session {
            if sess.is_empty() || sess.len() > 128 {
                return Err(HeaderError::MalformedParams);
            }
            out.push_str(", session=");
            out.push_str(&format_sf_string(sess)?);
        }
        if out.len() > MAX_MOLE_HEADER_LEN {
            return Err(HeaderError::TooLarge);
        }
        Ok(out)
    }

    /// Parses an RFC 9651 `Sec-Mole-Authorization` header value.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let dict = parse_sf_dict(value)?;
        let mut clearance = None;
        let mut session = None;
        for (k, v) in dict {
            match (k.as_str(), v) {
                ("clearance", SfValue::ByteSeq(b)) => {
                    if b.is_empty() || b.len() > 2048 {
                        return Err(HeaderError::MalformedParams);
                    }
                    clearance = Some(b);
                }
                ("session", SfValue::String(s)) => {
                    if s.is_empty() || s.len() > 128 {
                        return Err(HeaderError::MalformedParams);
                    }
                    session = Some(s);
                }
                ("clearance" | "session", _) => return Err(HeaderError::MalformedParams),
                _ => {}
            }
        }
        Ok(Self {
            clearance: clearance.ok_or(HeaderError::MalformedParams)?,
            session,
        })
    }
}

/// Parsed `Sec-Mole-Grease` wire-greasing header (`suite="0x2a2a"` or `suite=0x2a2a`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecMoleGrease {
    /// Reserved greased suite ID (`0x?A?A`).
    pub suite: u16,
}

impl SecMoleGrease {
    /// Formats `Sec-Mole-Grease: suite="0x2a2a"`.
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        if !credential_type::is_greased(self.suite) {
            return Err(HeaderError::InvalidTypeSuffix);
        }
        Ok(format!("suite=\"0x{:04x}\"", self.suite))
    }

    /// Parses `Sec-Mole-Grease`, validating that `suite` is a `0x?A?A` greased codepoint.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let dict = parse_sf_dict(value)?;
        let mut suite = None;
        for (k, v) in dict {
            if k == "suite" {
                let raw = match v {
                    SfValue::String(s) | SfValue::Token(s) => s,
                    _ => return Err(HeaderError::MalformedParams),
                };
                let hex = raw
                    .strip_prefix("0x")
                    .or_else(|| raw.strip_prefix("0X"))
                    .unwrap_or(&raw);
                if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(HeaderError::InvalidTypeSuffix);
                }
                let parsed =
                    u16::from_str_radix(hex, 16).map_err(|_| HeaderError::InvalidTypeSuffix)?;
                if !credential_type::is_greased(parsed) {
                    return Err(HeaderError::InvalidTypeSuffix);
                }
                suite = Some(parsed);
            }
        }
        Ok(Self {
            suite: suite.ok_or(HeaderError::MalformedParams)?,
        })
    }
}

/// Parsed `Mole-Info` Origin response header:
/// `session="sess_...", settle-ready=?1`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoleInfo {
    /// Opaque session handle echoed by Origin.
    pub session: Option<String>,
    /// Whether Origin has already reported behavioral feedback so client may settle immediately.
    pub settle_ready: bool,
}

impl MoleInfo {
    /// Formats as an RFC 9651 `Mole-Info` header value.
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        let mut parts = Vec::new();
        if let Some(ref s) = self.session {
            if s.is_empty() || s.len() > 128 {
                return Err(HeaderError::MalformedParams);
            }
            parts.push(format!("session={}", format_sf_string(s)?));
        }
        parts.push(format!(
            "settle-ready=?{}",
            if self.settle_ready { '1' } else { '0' }
        ));
        Ok(parts.join(", "))
    }

    /// Parses an RFC 9651 `Mole-Info` header value.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let dict = parse_sf_dict(value)?;
        let mut session = None;
        let mut settle_ready = false;
        for (k, v) in dict {
            match (k.as_str(), v) {
                ("session", SfValue::String(s)) => {
                    if s.is_empty() || s.len() > 128 {
                        return Err(HeaderError::MalformedParams);
                    }
                    session = Some(s);
                }
                ("settle-ready", SfValue::Bool(b)) => settle_ready = b,
                ("session" | "settle-ready", _) => return Err(HeaderError::MalformedParams),
                _ => {}
            }
        }
        Ok(Self {
            session,
            settle_ready,
        })
    }
}

// ---------------------------------------------------------------------------
// Plane 2: Origin-Bound ClearanceToken & Split Moderator POST Envelopes
// ---------------------------------------------------------------------------

/// Origin-bound Clearance Token minted by the Moderator upon verifying an EC-ACT
/// presentation (`POST /mole/v1/present`) and verified locally by the Origin in `< 0.1 ms`
/// without any Origin -> Moderator RPC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearanceToken {
    /// Wire format version (`1`).
    pub version: u8,
    /// Canonical Moderator origin (`https://moderator.example:8442`).
    pub moderator_origin: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Canonical target Origin (`https://shoes.example:8443`) — prevents cross-origin replay.
    pub target_origin: String,
    /// Uppercase HTTP method (`GET`, `POST`, ...).
    pub method: String,
    /// Request path and query (`/api/purchase`).
    pub path_and_query: String,
    /// Origin challenge nonce bound into the spend proof.
    pub challenge_nonce: Vec<u8>,
    /// Verified spend cost `s`.
    pub cost: u64,
    /// Issuance timestamp (Unix seconds).
    pub issued_at: u64,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
    /// Optional deferred session handle (empty if immediate settlement).
    pub session_id: String,
    /// Fixed-width 64-byte signature (`r || s` for P-256 ECDSA, or Ed25519 signature).
    pub signature: [u8; 64],
}

impl ClearanceToken {
    /// Current ClearanceToken version (`1`).
    pub const VERSION: u8 = 1;

    /// Deterministic domain-separated byte string signed by the Moderator's clearance key.
    pub fn signing_payload(&self) -> Result<Vec<u8>, WireError> {
        if self.version != Self::VERSION {
            return Err(WireError::Malformed("unsupported ClearanceToken version"));
        }
        if self.challenge_nonce.len() > 128 {
            return Err(WireError::OutOfRange);
        }
        let mut out = Vec::with_capacity(224);
        out.extend_from_slice(CLEARANCE_TOKEN_DST);
        put_u8(&mut out, self.version);
        put_str_v(&mut out, &self.moderator_origin, 256)?;
        put_str_v(&mut out, &self.policy_id, 128)?;
        put_str_v(&mut out, &self.target_origin, 256)?;
        put_str_v(&mut out, &self.method, 32)?;
        put_str_v(&mut out, &self.path_and_query, 512)?;
        put_opaque_v(&mut out, &self.challenge_nonce)?;
        put_u64(&mut out, self.cost);
        put_u64(&mut out, self.issued_at);
        put_u64(&mut out, self.expires_at);
        put_str_v(&mut out, &self.session_id, 128)?;
        Ok(out)
    }

    /// Verifies non-cryptographic request-binding claims at the Origin before/alongside
    /// checking `signature` against the Moderator's `clearance_public_key`.
    pub fn verify_claims(
        &self,
        expected_target_origin: &str,
        expected_method: &str,
        expected_path_and_query: &str,
        expected_nonce: &[u8],
        min_cost: u64,
        now_unix_secs: u64,
    ) -> Result<(), WireError> {
        if self.version != Self::VERSION {
            return Err(WireError::Malformed("unsupported ClearanceToken version"));
        }
        if self.target_origin != expected_target_origin {
            return Err(WireError::Malformed("ClearanceToken target_origin mismatch"));
        }
        if !self.method.eq_ignore_ascii_case(expected_method) {
            return Err(WireError::Malformed("ClearanceToken HTTP method mismatch"));
        }
        if self.path_and_query != expected_path_and_query {
            return Err(WireError::Malformed("ClearanceToken path_and_query mismatch"));
        }
        if self.challenge_nonce.as_slice() != expected_nonce {
            return Err(WireError::Malformed("ClearanceToken challenge_nonce mismatch"));
        }
        if self.cost < min_cost {
            return Err(WireError::Malformed("ClearanceToken cost insufficient"));
        }
        if self.expires_at < self.issued_at {
            return Err(WireError::Malformed(
                "ClearanceToken expires_at precedes issued_at",
            ));
        }
        if self.expires_at - self.issued_at > 300 {
            return Err(WireError::Malformed("ClearanceToken TTL exceeds 300s"));
        }
        if self.issued_at > now_unix_secs.saturating_add(60) {
            return Err(WireError::Malformed(
                "ClearanceToken issued_at exceeds 60s clock skew",
            ));
        }
        if now_unix_secs > self.expires_at {
            return Err(WireError::Malformed("ClearanceToken expired"));
        }
        Ok(())
    }
}

impl Wire for ClearanceToken {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.version != Self::VERSION || self.challenge_nonce.len() > 128 {
            return Err(WireError::OutOfRange);
        }
        put_u8(out, self.version);
        put_str_v(out, &self.moderator_origin, 256)?;
        put_str_v(out, &self.policy_id, 128)?;
        put_str_v(out, &self.target_origin, 256)?;
        put_str_v(out, &self.method, 32)?;
        put_str_v(out, &self.path_and_query, 512)?;
        put_opaque_v(out, &self.challenge_nonce)?;
        put_u64(out, self.cost);
        put_u64(out, self.issued_at);
        put_u64(out, self.expires_at);
        put_str_v(out, &self.session_id, 128)?;
        out.extend_from_slice(&self.signature);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > 2048 {
            return Err(WireError::OutOfRange);
        }
        let version = get_u8(buf)?;
        if version != Self::VERSION {
            return Err(WireError::Malformed("unsupported ClearanceToken version"));
        }
        let moderator_origin = get_str_v(buf, 256)?;
        let policy_id = get_str_v(buf, 128)?;
        let target_origin = get_str_v(buf, 256)?;
        let method = get_str_v(buf, 32)?;
        let path_and_query = get_str_v(buf, 512)?;
        let challenge_nonce = get_opaque_bounded(buf, 128)?.to_vec();
        let cost = get_u64(buf)?;
        let issued_at = get_u64(buf)?;
        let expires_at = get_u64(buf)?;
        let session_id = get_str_v(buf, 128)?;
        let signature = get_fixed::<64>(buf)?;
        Ok(Self {
            version,
            moderator_origin,
            policy_id,
            target_origin,
            method,
            path_and_query,
            challenge_nonce,
            cost,
            issued_at,
            expires_at,
            session_id,
            signature,
        })
    }
}

/// Request envelope for `POST /mole/v1/issue` (Redeem EC-IHAT Endorsement -> Issue EC-ACT Credential).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueRequestEnvelope {
    /// Policy identifier (`"default"` or named policy).
    pub policy_id: String,
    /// Full 32-byte Moderator EC-ACT `key_id`.
    pub key_id: [u8; 32],
    /// Client-chosen 32-byte idempotency key so Moderator caches blind `IssueResponse`s
    /// for 5 minutes keyed by `(nullifier_A, idempotency_key)` on dropped HTTP responses.
    pub idempotency_key: [u8; 32],
    /// Endorsement type (`0x0002` EC-IHAT or `0x0001` NoEndorsement).
    pub endorsement_type: u16,
    /// 32-byte redemption context bound into `EC-IHAT` `redeem` (`SHA-256("MOLE-SPLIT-ISSUE-v1" || ...)` or server challenge).
    pub redemption_context: [u8; 32],
    /// Encoded `ec_ihat::Redemption` bytes (empty when `endorsement_type == NO_ENDORSEMENT`).
    pub ihat_redeem_proof: Vec<u8>,
    /// Encoded `EcActIssuanceRequest` bytes.
    pub act_issue_request: Vec<u8>,
}

impl Wire for IssueRequestEnvelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_u8(out, 1); // envelope version 1
        put_str_v(out, &self.policy_id, 128)?;
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.idempotency_key);
        put_u16(out, self.endorsement_type);
        out.extend_from_slice(&self.redemption_context);
        if self.ihat_redeem_proof.len() > MAX_MOLE_ENVELOPE_LEN
            || self.act_issue_request.len() > 4096
        {
            return Err(WireError::OutOfRange);
        }
        put_opaque_v(out, &self.ihat_redeem_proof)?;
        put_opaque_v(out, &self.act_issue_request)?;
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > MAX_MOLE_ENVELOPE_LEN {
            return Err(WireError::OutOfRange);
        }
        if get_u8(buf)? != 1 {
            return Err(WireError::Malformed("unsupported IssueRequestEnvelope version"));
        }
        let policy_id = get_str_v(buf, 128)?;
        let key_id = get_fixed::<32>(buf)?;
        let idempotency_key = get_fixed::<32>(buf)?;
        let endorsement_type = get_u16(buf)?;
        let redemption_context = get_fixed::<32>(buf)?;
        let ihat_redeem_proof = get_opaque_bounded(buf, MAX_MOLE_ENVELOPE_LEN)?.to_vec();
        let act_issue_request = get_opaque_bounded(buf, 4096)?.to_vec();
        Ok(Self {
            policy_id,
            key_id,
            idempotency_key,
            endorsement_type,
            redemption_context,
            ihat_redeem_proof,
            act_issue_request,
        })
    }
}

/// Response envelope from `POST /mole/v1/issue` (`200 OK`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueResponseEnvelope {
    /// Encoded `EcActIssuanceResponse` bytes (137 bytes).
    pub act_issue_response: Vec<u8>,
    /// Issued initial credit `c` (verified cryptographically by `ec_act::issue_finalize` and pinned against `CommittedPolicy`).
    pub initial_credit: u64,
}

impl Wire for IssueResponseEnvelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_u8(out, 1);
        if self.act_issue_response.len() > 4096 {
            return Err(WireError::OutOfRange);
        }
        put_opaque_v(out, &self.act_issue_response)?;
        put_u64(out, self.initial_credit);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > 8192 {
            return Err(WireError::OutOfRange);
        }
        if get_u8(buf)? != 1 {
            return Err(WireError::Malformed("unsupported IssueResponseEnvelope version"));
        }
        let act_issue_response = get_opaque_bounded(buf, 4096)?.to_vec();
        let initial_credit = get_u64(buf)?;
        Ok(Self {
            act_issue_response,
            initial_credit,
        })
    }
}

/// Request envelope for `POST /mole/v1/present` (Spend EC-ACT -> Mint ClearanceToken).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentRequestEnvelope {
    /// Policy identifier.
    pub policy_id: String,
    /// Full 32-byte Moderator EC-ACT `key_id`.
    pub key_id: [u8; 32],
    /// Canonical target Origin (`https://shoes.example:8443`).
    pub target_origin: String,
    /// Uppercase HTTP method (`GET`, `POST`, ...).
    pub method: String,
    /// Request path and query (`/api/purchase`).
    pub path_and_query: String,
    /// Origin challenge nonce (`Mole-Challenge` `nonce`).
    pub challenge_nonce: Vec<u8>,
    /// Spend cost `s`.
    pub cost: u64,
    /// Maximum offered top-up `a`.
    pub max_top_up: u64,
    /// Whether the client allows `202 Accepted` deferred settlement (`Held`).
    pub allow_deferred: bool,
    /// Encoded `EcActPresentationAndUpdate` bytes.
    pub act_presentation: Vec<u8>,
}

impl PresentRequestEnvelope {
    /// Reconstructs the exact `ProtectedRequestContext` bound into `EcActChallenge.request_context`.
    pub fn protected_request_context(&self) -> ProtectedRequestContext {
        ProtectedRequestContext {
            target_origin: self.target_origin.clone(),
            method: self.method.clone(),
            path_and_query: self.path_and_query.clone(),
            challenge_nonce: self.challenge_nonce.clone(),
            cost: self.cost,
            allow_deferred: self.allow_deferred,
        }
    }
}

impl Wire for PresentRequestEnvelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.challenge_nonce.len() > 128 || self.act_presentation.len() > MAX_MOLE_ENVELOPE_LEN {
            return Err(WireError::OutOfRange);
        }
        put_u8(out, 1);
        put_str_v(out, &self.policy_id, 128)?;
        out.extend_from_slice(&self.key_id);
        put_str_v(out, &self.target_origin, 256)?;
        put_str_v(out, &self.method, 32)?;
        put_str_v(out, &self.path_and_query, 512)?;
        put_opaque_v(out, &self.challenge_nonce)?;
        put_u64(out, self.cost);
        put_u64(out, self.max_top_up);
        put_u8(out, u8::from(self.allow_deferred));
        put_opaque_v(out, &self.act_presentation)?;
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > MAX_MOLE_ENVELOPE_LEN {
            return Err(WireError::OutOfRange);
        }
        if get_u8(buf)? != 1 {
            return Err(WireError::Malformed("unsupported PresentRequestEnvelope version"));
        }
        let policy_id = get_str_v(buf, 128)?;
        let key_id = get_fixed::<32>(buf)?;
        let target_origin = get_str_v(buf, 256)?;
        let method = get_str_v(buf, 32)?;
        let path_and_query = get_str_v(buf, 512)?;
        let challenge_nonce = get_opaque_bounded(buf, 128)?.to_vec();
        let cost = get_u64(buf)?;
        let max_top_up = get_u64(buf)?;
        let allow_deferred = match get_u8(buf)? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Malformed("invalid allow_deferred tag")),
        };
        let act_presentation = get_opaque_bounded(buf, MAX_MOLE_ENVELOPE_LEN)?.to_vec();
        Ok(Self {
            policy_id,
            key_id,
            target_origin,
            method,
            path_and_query,
            challenge_nonce,
            cost,
            max_top_up,
            allow_deferred,
            act_presentation,
        })
    }
}

/// Response envelope from `POST /mole/v1/present` (`200 OK` `Settled` or `202 Accepted` `Held`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentResponseEnvelope {
    /// Immediate settlement (`200 OK`): returns Origin-bound `ClearanceToken` + immediate EC-ACT refund (`empty` = `NoUpdate`).
    Settled {
        clearance_token: Vec<u8>,
        act_refund_response: Vec<u8>,
    },
    /// Deferred settlement (`202 Accepted`): returns Origin-bound `ClearanceToken` + opaque `session_handle` and hold bounds.
    Held {
        clearance_token: Vec<u8>,
        session_handle: String,
        min_delay_ms: u32,
        max_hold_ms: u32,
    },
}

impl Wire for PresentResponseEnvelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_u8(out, 1);
        match self {
            Self::Settled {
                clearance_token,
                act_refund_response,
            } => {
                if clearance_token.len() > 2048 || act_refund_response.len() > 4096 {
                    return Err(WireError::OutOfRange);
                }
                put_u8(out, 0);
                put_opaque_v(out, clearance_token)?;
                put_opaque_v(out, act_refund_response)?;
            }
            Self::Held {
                clearance_token,
                session_handle,
                min_delay_ms,
                max_hold_ms,
            } => {
                if clearance_token.len() > 2048 || session_handle.is_empty() {
                    return Err(WireError::OutOfRange);
                }
                put_u8(out, 1);
                put_opaque_v(out, clearance_token)?;
                put_str_v(out, session_handle, 128)?;
                put_u32(out, *min_delay_ms);
                put_u32(out, *max_hold_ms);
            }
        }
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > 16_384 {
            return Err(WireError::OutOfRange);
        }
        if get_u8(buf)? != 1 {
            return Err(WireError::Malformed("unsupported PresentResponseEnvelope version"));
        }
        match get_u8(buf)? {
            0 => {
                let clearance_token = get_opaque_bounded(buf, 2048)?.to_vec();
                let act_refund_response = get_opaque_bounded(buf, 4096)?.to_vec();
                Ok(Self::Settled {
                    clearance_token,
                    act_refund_response,
                })
            }
            1 => {
                let clearance_token = get_opaque_bounded(buf, 2048)?.to_vec();
                let session_handle = get_str_v(buf, 128)?;
                if session_handle.is_empty() {
                    return Err(WireError::Malformed("empty Held session_handle"));
                }
                let min_delay_ms = get_u32(buf)?;
                let max_hold_ms = get_u32(buf)?;
                Ok(Self::Held {
                    clearance_token,
                    session_handle,
                    min_delay_ms,
                    max_hold_ms,
                })
            }
            _ => Err(WireError::Malformed("unknown PresentResponseEnvelope status tag")),
        }
    }
}

/// Request envelope for `POST /mole/v1/settle` (settle deferred `session_handle` or crash `recovery_handle`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettleRequestEnvelope {
    /// Opaque `session_handle` returned by `POST /mole/v1/present` (`202 Accepted`), or empty if recovering solely by `recovery_handle`.
    pub session_handle: String,
    /// Optional 96-byte `RecoveryHandle` (used for crash recovery when `POST /present` response dropped before `session_handle` arrived, or alongside `session_handle`).
    pub recovery_handle: Option<RecoveryHandle>,
    /// True if client is explicitly signing off early (`pagehide` / tab close / `navigator.endorsement.settle()`).
    pub is_signoff: bool,
}

impl Wire for SettleRequestEnvelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.session_handle.is_empty() && self.recovery_handle.is_none() {
            return Err(WireError::Malformed(
                "SettleRequestEnvelope requires session_handle or recovery_handle",
            ));
        }
        put_u8(out, 1);
        put_str_v(out, &self.session_handle, 128)?;
        match &self.recovery_handle {
            Some(rh) => {
                put_u8(out, 1);
                rh.encode(out)?;
            }
            None => put_u8(out, 0),
        }
        put_u8(out, u8::from(self.is_signoff));
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > 1024 {
            return Err(WireError::OutOfRange);
        }
        if get_u8(buf)? != 1 {
            return Err(WireError::Malformed("unsupported SettleRequestEnvelope version"));
        }
        let session_handle = get_str_v(buf, 128)?;
        let recovery_handle = match get_u8(buf)? {
            0 => None,
            1 => Some(RecoveryHandle::decode(buf)?),
            _ => return Err(WireError::Malformed("invalid recovery_handle presence tag")),
        };
        if session_handle.is_empty() && recovery_handle.is_none() {
            return Err(WireError::Malformed(
                "SettleRequestEnvelope requires session_handle or recovery_handle",
            ));
        }
        let is_signoff = match get_u8(buf)? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Malformed("invalid is_signoff boolean")),
        };
        Ok(Self {
            session_handle,
            recovery_handle,
            is_signoff,
        })
    }
}

/// Response envelope from `POST /mole/v1/settle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettleResponseEnvelope {
    /// Finalized (`200 OK`): `act_refund_response` is empty for `NoUpdate` or 137-byte `EcActUpdate`.
    Settled { act_refund_response: Vec<u8> },
    /// Hold still pending (`202 Accepted`): browser may retry after `retry_after_ms` (capped to `<= 2` retries).
    Pending { retry_after_ms: u32 },
}

impl Wire for SettleResponseEnvelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_u8(out, 1);
        match self {
            Self::Settled {
                act_refund_response,
            } => {
                if act_refund_response.len() > 4096 {
                    return Err(WireError::OutOfRange);
                }
                put_u8(out, 0);
                put_opaque_v(out, act_refund_response)?;
            }
            Self::Pending { retry_after_ms } => {
                put_u8(out, 1);
                put_u32(out, *retry_after_ms);
            }
        }
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > 8192 {
            return Err(WireError::OutOfRange);
        }
        if get_u8(buf)? != 1 {
            return Err(WireError::Malformed("unsupported SettleResponseEnvelope version"));
        }
        match get_u8(buf)? {
            0 => Ok(Self::Settled {
                act_refund_response: get_opaque_bounded(buf, 4096)?.to_vec(),
            }),
            1 => Ok(Self::Pending {
                retry_after_ms: get_u32(buf)?,
            }),
            _ => Err(WireError::Malformed("unknown SettleResponseEnvelope tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_headers_round_trip_and_fit_under_350_bytes() {
        let ch = SplitMoleChallenge {
            moderator: "https://localhost:8442".into(),
            policy: "demo-policy-v1".into(),
            cost: 1,
            nonce: vec![0x42; 16],
            max_cost: Some(4),
            exp: Some(1_900_000_000),
            sig: Some(vec![0xAB; 64]),
        };
        let hdr = ch.to_header_value().unwrap();
        assert!(hdr.len() < 350, "Mole-Challenge len = {}", hdr.len());
        assert_eq!(SplitMoleChallenge::parse(&hdr).unwrap(), ch);

        let token = ClearanceToken {
            version: ClearanceToken::VERSION,
            moderator_origin: "https://localhost:8442".into(),
            policy_id: "demo-policy-v1".into(),
            target_origin: "https://localhost:8443".into(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: vec![0x42; 16],
            cost: 1,
            issued_at: 1_899_999_900,
            expires_at: 1_900_000_020,
            session_id: "sess_9f8a7b".into(),
            signature: [0xCD; 64],
        };
        let token_bytes = token.to_bytes().unwrap();
        let auth = SecMoleAuthorization {
            clearance: token_bytes.clone(),
            session: Some("sess_9f8a7b".into()),
        };
        let auth_hdr = auth.to_header_value().unwrap();
        assert!(
            auth_hdr.len() < 350,
            "Sec-Mole-Authorization len = {}",
            auth_hdr.len()
        );
        let parsed_auth = SecMoleAuthorization::parse(&auth_hdr).unwrap();
        assert_eq!(parsed_auth, auth);
        let parsed_token = ClearanceToken::from_bytes(&parsed_auth.clearance).unwrap();
        assert_eq!(parsed_token, token);

        parsed_token
            .verify_claims(
                "https://localhost:8443",
                "post",
                "/api/purchase",
                &[0x42; 16],
                1,
                1_899_999_950,
            )
            .unwrap();
        // Cross-origin replay to socks (:8444) MUST fail!
        assert!(
            parsed_token
                .verify_claims(
                    "https://localhost:8444",
                    "POST",
                    "/api/purchase",
                    &[0x42; 16],
                    1,
                    1_899_999_950,
                )
                .is_err()
        );

        let grease = SecMoleGrease { suite: 0x2A2A };
        let grease_hdr = grease.to_header_value().unwrap();
        assert_eq!(SecMoleGrease::parse(&grease_hdr).unwrap(), grease);
        assert!(SecMoleGrease::parse("suite=\"0x0001\"").is_err());

        let info = MoleInfo {
            session: Some("sess_9f8a7b".into()),
            settle_ready: true,
        };
        let info_hdr = info.to_header_value().unwrap();
        assert_eq!(MoleInfo::parse(&info_hdr).unwrap(), info);

        // RFC 9651 `;` item parameters on multiple members + greased negative/decimal/inner-list keys!
        let parameterized = "moderator=\"https://localhost:8442\";v=1;q=0.9, policy=\"demo-policy-v1\";v=1, cost=1;tier=fast, nonce=:QkJCQkJCQkJCQkJCQkJCQg==:, grease-neg=-42, grease-dec=1.25, grease-list=(\"a\";p=1 2 ?0)";
        let parsed_param_ch = SplitMoleChallenge::parse(parameterized).unwrap();
        assert_eq!(parsed_param_ch.moderator, "https://localhost:8442");
        assert_eq!(parsed_param_ch.policy, "demo-policy-v1");
        assert_eq!(parsed_param_ch.cost, 1);

        // Future `issued_at` (> now + 60s), `expires_at < issued_at`, and TTL > 300s MUST fail!
        let mut future_tok = token.clone();
        future_tok.issued_at = 1_900_000_100;
        future_tok.expires_at = 1_900_000_200;
        assert!(
            future_tok
                .verify_claims(
                    "https://localhost:8443",
                    "POST",
                    "/api/purchase",
                    &[0x42; 16],
                    1,
                    1_899_999_950,
                )
                .is_err()
        );
        let mut long_ttl_tok = token.clone();
        long_ttl_tok.expires_at = long_ttl_tok.issued_at + 301;
        assert!(
            long_ttl_tok
                .verify_claims(
                    "https://localhost:8443",
                    "POST",
                    "/api/purchase",
                    &[0x42; 16],
                    1,
                    1_899_999_950,
                )
                .is_err()
        );
    }

    #[test]
    fn split_envelopes_round_trip_and_enforce_header_cap() {
        let oversized = format!("moderator=\"https://a.example\", policy=\"{}\"", "x".repeat(5000));
        assert_eq!(SplitMoleChallenge::parse(&oversized), Err(HeaderError::TooLarge));

        let issue_req = IssueRequestEnvelope {
            policy_id: "p1".into(),
            key_id: [0x11; 32],
            idempotency_key: [0x22; 32],
            endorsement_type: 2,
            redemption_context: [0x33; 32],
            ihat_redeem_proof: vec![0x44; 512],
            act_issue_request: vec![0x55; 140],
        };
        assert_eq!(
            IssueRequestEnvelope::from_bytes(&issue_req.to_bytes().unwrap()).unwrap(),
            issue_req
        );

        let pres_req = PresentRequestEnvelope {
            policy_id: "p1".into(),
            key_id: [0x11; 32],
            target_origin: "https://shoes.example".into(),
            method: "POST".into(),
            path_and_query: "/api/purchase".into(),
            challenge_nonce: vec![0x77; 16],
            cost: 1,
            max_top_up: 2,
            allow_deferred: true,
            act_presentation: vec![0x88; 1900],
        };
        assert_eq!(
            PresentRequestEnvelope::from_bytes(&pres_req.to_bytes().unwrap()).unwrap(),
            pres_req
        );

        let held = PresentResponseEnvelope::Held {
            clearance_token: vec![0x99; 180],
            session_handle: "sess_123".into(),
            min_delay_ms: 2000,
            max_hold_ms: 60_000,
        };
        assert_eq!(
            PresentResponseEnvelope::from_bytes(&held.to_bytes().unwrap()).unwrap(),
            held
        );

        let settle_req = SettleRequestEnvelope {
            session_handle: "sess_123".into(),
            recovery_handle: Some(RecoveryHandle {
                key_id: [1; 32],
                nullifier: [2; 32],
                presentation_sha256: [3; 32],
            }),
            is_signoff: true,
        };
        assert_eq!(
            SettleRequestEnvelope::from_bytes(&settle_req.to_bytes().unwrap()).unwrap(),
            settle_req
        );
    }
}
