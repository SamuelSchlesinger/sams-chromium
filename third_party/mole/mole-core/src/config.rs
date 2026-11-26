// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Anchor and Moderator JSON configuration schemas (`draft-jms-mole-protocols-01` §6
//! plus backward-compatible Split Moderation & Redemption extensions):
//! - `/.well-known/mole-anchor` -> [`AnchorConfiguration`]
//! - `/.well-known/mole-moderator` -> [`ModeratorConfiguration`]

use core::fmt;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::act::{compute_ec_act_key_id, derive_ctx_cred, truncated_key_id};
use crate::http::b64_decode;
use crate::{
    CIPHERSUITE_P256_SHA256, MAX_ANCHOR_SET_LEN, MAX_BROWSER_BALANCE_WIDTH,
    MAX_CREDENTIAL_CONTEXT_LEN, MIN_ANCHOR_SET_LEN, credential_type, endorsement_type,
};

/// Well-known discovery path for an Anchor.
pub const ANCHOR_DIRECTORY_PATH: &str = "/.well-known/mole-anchor";
/// Well-known discovery path for a Moderator.
pub const MODERATOR_DIRECTORY_PATH: &str = "/.well-known/mole-moderator";

/// Error validating a MOLE Anchor or Moderator configuration document.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfigError {
    /// Malformed JSON syntax or field types.
    MalformedJson(String),
    /// Invalid endpoint URI (`grant-uri`, `issuance-uri`, `present-uri`, `settle-uri`).
    InvalidUri(&'static str),
    /// Invalid or unsupported configuration field.
    InvalidField(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson(msg) => write!(f, "malformed configuration JSON: {msg}"),
            Self::InvalidUri(msg) => write!(f, "invalid HTTPS endpoint URI: {msg}"),
            Self::InvalidField(msg) => write!(f, "invalid configuration: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Validates an absolute `https://` URI with a non-empty host, no userinfo, and
/// no fragment (`draft-jms-mole-protocols-01` §6), returning `(canonical_origin, path_and_query)`.
pub fn validate_https_endpoint_uri(uri: &str) -> Result<(String, String), ConfigError> {
    if uri.is_empty() || uri.len() > 2048 {
        return Err(ConfigError::InvalidUri("URI length out of range"));
    }
    if uri.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
        return Err(ConfigError::InvalidUri("URI contains whitespace or control bytes"));
    }
    if uri.contains('#') {
        return Err(ConfigError::InvalidUri("URI must not contain a fragment"));
    }
    let rest = if let Some(r) = uri.strip_prefix("https://") {
        r
    } else if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case("https://") {
        &uri[8..]
    } else {
        return Err(ConfigError::InvalidUri("URI must use the https scheme"));
    };

    let (authority, path_and_query) = match rest.find(['/', '?']) {
        Some(idx) => {
            let tail = &rest[idx..];
            if tail.starts_with('?') {
                (&rest[..idx], format!("/{tail}"))
            } else {
                (&rest[..idx], tail.to_string())
            }
        }
        None => (rest, "/".to_string()),
    };

    if authority.is_empty() {
        return Err(ConfigError::InvalidUri("URI missing host"));
    }
    if authority.contains('@') {
        return Err(ConfigError::InvalidUri("URI must not contain userinfo"));
    }
    if authority.contains('\\') || path_and_query.contains('\\') {
        return Err(ConfigError::InvalidUri(
            "URI must not contain backslash characters",
        ));
    }

    let (host, port_opt) = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or(ConfigError::InvalidUri("unclosed IPv6 literal"))?;
        let ipv6_body = &authority[1..close];
        if ipv6_body.is_empty()
            || !ipv6_body.contains(':')
            || !ipv6_body
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        {
            return Err(ConfigError::InvalidUri("invalid IPv6 host literal"));
        }
        let host_part = &authority[..=close];
        let after = &authority[close + 1..];
        let port = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            Some(parse_port(p)?)
        } else {
            return Err(ConfigError::InvalidUri("invalid authority after IPv6 host"));
        };
        (host_part.to_ascii_lowercase(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.is_empty() || h.contains(':') {
            return Err(ConfigError::InvalidUri("invalid host or port"));
        }
        validate_reg_name_or_ipv4(h)?;
        (h.to_ascii_lowercase(), Some(parse_port(p)?))
    } else {
        validate_reg_name_or_ipv4(authority)?;
        (authority.to_ascii_lowercase(), None)
    };

    if host.is_empty() {
        return Err(ConfigError::InvalidUri("URI missing host"));
    }

    let origin = match port_opt {
        Some(443) | None => format!("https://{host}"),
        Some(port) => format!("https://{host}:{port}"),
    };
    Ok((origin, path_and_query))
}

fn validate_reg_name_or_ipv4(host: &str) -> Result<(), ConfigError> {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return Err(ConfigError::InvalidUri("invalid host syntax"));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ConfigError::InvalidUri("invalid DNS/IPv4 host label"));
        }
    }
    Ok(())
}

/// Validates and canonicalizes an HTTPS origin string (`https://host[:port]`).
pub fn validate_https_origin(raw: &str) -> Result<String, ConfigError> {
    let (origin, path_and_query) = validate_https_endpoint_uri(raw)?;
    if path_and_query != "/" {
        return Err(ConfigError::InvalidUri("origin must not include a path or query"));
    }
    Ok(origin)
}

fn parse_port(s: &str) -> Result<u16, ConfigError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigError::InvalidUri("invalid port"));
    }
    let port: u16 = s
        .parse()
        .map_err(|_| ConfigError::InvalidUri("port out of range"))?;
    if port == 0 {
        return Err(ConfigError::InvalidUri("port must be non-zero"));
    }
    Ok(port)
}

/// Anchor configuration JSON (`draft-jms-mole-protocols-01` §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorConfiguration {
    /// Absolute HTTPS grant endpoint URI.
    #[serde(rename = "grant-uri")]
    pub grant_uri: String,
    /// Endorsement type (`2` for EC-IHAT).
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
    /// Ciphersuite (`"P256-SHA256"`).
    pub ciphersuite: String,
    /// Unpadded base64url `SerializeElement(pkA)`.
    #[serde(rename = "anchor-key")]
    pub anchor_key: String,
    /// Unpadded base64url issuance context `ctx_iss`.
    #[serde(rename = "issuance-epoch")]
    pub issuance_epoch: String,
}

/// Validated EC-IHAT Anchor configuration.
#[derive(Clone, Debug)]
pub struct ValidatedAnchorConfig {
    /// Canonical origin of `grant-uri` (`https://host[:port]`).
    pub origin: String,
    /// Full validated `grant-uri`.
    pub grant_uri: String,
    /// Path (and query, if any) of `grant-uri`.
    pub grant_path: String,
    /// Decoded 33-byte SEC1 public key bytes.
    pub anchor_key_bytes: [u8; 33],
    /// Decoded `ec_ihat::PublicKey`.
    pub public_key: ec_ihat::PublicKey,
    /// Decoded `issuance-epoch` (`ctx_iss`).
    pub issuance_epoch: Vec<u8>,
}

impl AnchorConfiguration {
    /// Validates URI rules, ciphersuite, epoch length, and EC-IHAT `pkA`.
    pub fn validate_ec_ihat(&self) -> Result<ValidatedAnchorConfig, ConfigError> {
        let (origin, grant_path) = validate_https_endpoint_uri(&self.grant_uri)?;
        if self.endorsement_type != endorsement_type::EC_IHAT {
            return Err(ConfigError::InvalidField("unsupported anchor endorsement-type"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(ConfigError::InvalidField("unsupported EC-IHAT ciphersuite"));
        }
        let raw_key = b64_decode(&self.anchor_key)
            .map_err(|_| ConfigError::InvalidField("anchor-key is not canonical base64url"))?;
        let anchor_key_bytes: [u8; 33] = raw_key
            .try_into()
            .map_err(|_| ConfigError::InvalidField("anchor-key must be 33 bytes"))?;
        let public_key = ec_ihat::PublicKey::from_bytes(&anchor_key_bytes)
            .map_err(|_| ConfigError::InvalidField("anchor-key is not a valid P-256 point"))?;
        let issuance_epoch = b64_decode(&self.issuance_epoch)
            .map_err(|_| ConfigError::InvalidField("issuance-epoch is not canonical base64url"))?;
        if issuance_epoch.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(ConfigError::InvalidField("issuance-epoch exceeds 256 bytes"));
        }
        Ok(ValidatedAnchorConfig {
            origin,
            grant_uri: self.grant_uri.clone(),
            grant_path,
            anchor_key_bytes,
            public_key,
            issuance_epoch,
        })
    }
}

/// Clearance verification public key advertised by a Split Moderator:
/// either a 33-byte SEC1 compressed P-256 ECDSA public key or a 32-byte Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClearancePublicKey {
    /// 33-byte SEC1 compressed P-256 ECDSA public key (`0x02`/`0x03 || X`).
    P256Ecdsa([u8; 33]),
    /// 32-byte Ed25519 public key.
    Ed25519([u8; 32]),
}

impl ClearancePublicKey {
    /// Decodes from raw public key bytes (`33` bytes for P-256 SEC1, `32` bytes for Ed25519).
    pub fn from_bytes(raw: &[u8]) -> Result<Self, ConfigError> {
        match raw.len() {
            33 => {
                let arr: [u8; 33] = raw.try_into().unwrap();
                // Validate point lies on NIST P-256 and is non-identity.
                let _ = <ec_act::PublicKey>::from_bytes(&arr).map_err(|_| {
                    ConfigError::InvalidField("clearance-public-key is not a valid P-256 point")
                })?;
                Ok(Self::P256Ecdsa(arr))
            }
            32 => {
                let arr: [u8; 32] = raw.try_into().unwrap();
                if arr == [0u8; 32] {
                    return Err(ConfigError::InvalidField("clearance-public-key cannot be all-zero"));
                }
                Ok(Self::Ed25519(arr))
            }
            _ => Err(ConfigError::InvalidField(
                "clearance-public-key must be 33 bytes (P-256 SEC1) or 32 bytes (Ed25519)",
            )),
        }
    }

    /// Returns the raw byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::P256Ecdsa(b) => b,
            Self::Ed25519(b) => b,
        }
    }
}

/// Site authorization policy declared by a Split Moderator (`allowed-sites`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedSites {
    /// Open CDN/edge Moderator (`allowed-sites = ["*"]`).
    Any,
    /// Explicit set of authorized canonical HTTPS origins (`https://shoes.example:8443`).
    Origins(Vec<String>),
}

impl AllowedSites {
    /// Checks whether `target_origin` (canonical `https://host[:port]`) is authorized.
    pub fn allows(&self, target_origin: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Origins(list) => list.iter().any(|o| o == target_origin),
        }
    }
}

/// Moderator configuration JSON (`draft-jms-mole-protocols-01` §6 + Split extensions).
/// Backward-compatible with `-01` inline Moderator configs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeratorConfiguration {
    /// Absolute HTTPS Redeem & Issue endpoint URI (`-01` spelling).
    #[serde(rename = "issuance-uri", default)]
    pub issuance_uri: String,
    /// Optional Split `POST /mole/v1/issue` URI (defaults to `issuance-uri` when omitted).
    #[serde(rename = "issue-uri", default, skip_serializing_if = "Option::is_none")]
    pub issue_uri: Option<String>,
    /// Optional Split `POST /mole/v1/present` URI.
    #[serde(rename = "present-uri", default, skip_serializing_if = "Option::is_none")]
    pub present_uri: Option<String>,
    /// Optional Split `POST /mole/v1/settle` URI (falls back to `issue_uri`/`issuance_uri` when omitted).
    #[serde(rename = "settle-uri", default, skip_serializing_if = "Option::is_none")]
    pub settle_uri: Option<String>,
    /// Optional policy identifier (`policy-id`, defaults to `"default"`).
    #[serde(rename = "policy-id", default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Optional unpadded base64url clearance verification public key (33B P-256 SEC1 or 32B Ed25519).
    #[serde(
        rename = "clearance-public-key",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub clearance_public_key: Option<String>,
    /// Optional list of allowed target Origins (`["*"]` or `["https://shoes.example", ...]`).
    #[serde(rename = "allowed-sites", default, skip_serializing_if = "Option::is_none")]
    pub allowed_sites: Option<Vec<String>>,
    /// Optional top-level range proof bit-width hint (`L=8` or `L=16`).
    #[serde(rename = "range-bits-l", default, skip_serializing_if = "Option::is_none")]
    pub range_bits_l: Option<u8>,
    /// Accepted endorsement entries (`[+ $endorsement]`).
    pub endorsements: Vec<serde_json::Value>,
    /// Active credential-key entries (`[+ $credential-key]`).
    #[serde(rename = "credential-keys")]
    pub credential_keys: Vec<serde_json::Value>,
}

/// Typed EC-IHAT entry in `ModeratorConfiguration.endorsements`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcIhatEndorsementConfig {
    /// Must be `2` (`EC-IHAT`).
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
    /// Must be `"P256-SHA256"`.
    pub ciphersuite: String,
    /// Unpadded base64url `ctx_iss`.
    #[serde(rename = "issuance-epoch")]
    pub issuance_epoch: String,
    /// Ordered unpadded base64url `SerializeElement(pkA)` entries (`<= MAX_ANCHOR_SET_LEN`).
    #[serde(rename = "anchor-set")]
    pub anchor_set: Vec<String>,
}

/// Validated EC-IHAT Anchor Set entry in a Moderator configuration.
#[derive(Clone, Debug)]
pub struct ValidatedEcIhatSet {
    /// Shared issuance epoch `ctx_iss`.
    pub issuance_epoch: Vec<u8>,
    /// Ordered 33-byte SEC1 Anchor public keys.
    pub raw_keys: Vec<[u8; 33]>,
    /// Ordered decoded `ec_ihat::PublicKey` values.
    pub anchor_set: Vec<ec_ihat::PublicKey>,
}

impl EcIhatEndorsementConfig {
    /// Validates and decodes an EC-IHAT endorsement config entry with `min_anchors`
    /// (`1` for low-level wire parsing, `MIN_ANCHOR_SET_LEN = 3` for browser policy).
    pub fn validate_with_min(&self, min_anchors: usize) -> Result<ValidatedEcIhatSet, ConfigError> {
        if self.endorsement_type != endorsement_type::EC_IHAT {
            return Err(ConfigError::InvalidField("expected endorsement-type 2"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(ConfigError::InvalidField("unsupported EC-IHAT ciphersuite"));
        }
        let issuance_epoch = b64_decode(&self.issuance_epoch)
            .map_err(|_| ConfigError::InvalidField("issuance-epoch is not canonical base64url"))?;
        if issuance_epoch.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(ConfigError::InvalidField("issuance-epoch exceeds 256 bytes"));
        }
        let floor = min_anchors.max(1);
        if self.anchor_set.len() < floor || self.anchor_set.len() > MAX_ANCHOR_SET_LEN {
            return Err(ConfigError::InvalidField("anchor-set length out of allowed bounds"));
        }
        let mut seen = HashSet::with_capacity(self.anchor_set.len());
        let mut raw_keys = Vec::with_capacity(self.anchor_set.len());
        let mut anchor_set = Vec::with_capacity(self.anchor_set.len());
        for entry in &self.anchor_set {
            let decoded = b64_decode(entry).map_err(|_| {
                ConfigError::InvalidField("anchor-set key is not canonical base64url")
            })?;
            let arr: [u8; 33] = decoded
                .try_into()
                .map_err(|_| ConfigError::InvalidField("anchor-set key must be 33 bytes"))?;
            if !seen.insert(arr) {
                return Err(ConfigError::InvalidField(
                    "anchor-set must not contain duplicate keys",
                ));
            }
            let pk = ec_ihat::PublicKey::from_bytes(&arr)
                .map_err(|_| ConfigError::InvalidField("invalid P-256 point in anchor-set"))?;
            raw_keys.push(arr);
            anchor_set.push(pk);
        }
        Ok(ValidatedEcIhatSet {
            issuance_epoch,
            raw_keys,
            anchor_set,
        })
    }

    /// Validates an EC-IHAT endorsement config entry (`1..=MAX_ANCHOR_SET_LEN`).
    pub fn validate(&self) -> Result<ValidatedEcIhatSet, ConfigError> {
        self.validate_with_min(1)
    }
}

/// Typed EC-ACT entry in `ModeratorConfiguration.credential-keys`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcActKeyConfig {
    /// Must be `1` (`EC-ACT`).
    #[serde(rename = "credential-type")]
    pub credential_type: u16,
    /// Unpadded base64url `SerializeElement(pkM)`.
    #[serde(rename = "credential-key")]
    pub credential_key: String,
    /// Must be `"P256-SHA256"`.
    pub ciphersuite: String,
    /// Balance width `L` (`1..=16`, supporting `L=8` and `L=16`).
    #[serde(rename = "balance-width", alias = "range-bits-l")]
    pub balance_width: u8,
    /// Unpadded base64url `credential_context` (`<= MAX_CREDENTIAL_CONTEXT_LEN`).
    #[serde(rename = "credential-context")]
    pub credential_context: String,
    /// Result retention window in seconds.
    #[serde(rename = "result-retention")]
    pub result_retention: u64,
}

/// Validated EC-ACT key entry with derived identifiers.
#[derive(Clone, Debug)]
pub struct ValidatedEcActKey {
    /// Raw 33-byte SEC1 `pkM`.
    pub public_key_bytes: [u8; 33],
    /// Decoded `ec_act::PublicKey`.
    pub public_key: ec_act::PublicKey,
    /// `SHA-256(SerializeElement(pkM))`.
    pub key_id: [u8; 32],
    /// `key_id[31]`.
    pub truncated_key_id: u8,
    /// Balance width `L` (`1..=16`).
    pub balance_width: u8,
    /// Decoded `credential_context`.
    pub credential_context: Vec<u8>,
    /// `credential_context || I2OSP(L, 1)`.
    pub ctx_cred: Vec<u8>,
    /// Result retention window in seconds.
    pub result_retention: u64,
}

impl EcActKeyConfig {
    /// Validates and decodes an EC-ACT credential-key entry.
    pub fn validate(&self) -> Result<ValidatedEcActKey, ConfigError> {
        if self.credential_type != credential_type::EC_ACT {
            return Err(ConfigError::InvalidField("expected credential-type 1"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(ConfigError::InvalidField("unsupported EC-ACT ciphersuite"));
        }
        if self.balance_width == 0 || self.balance_width > MAX_BROWSER_BALANCE_WIDTH {
            return Err(ConfigError::InvalidField(
                "balance-width (range-bits-l) must be in 1..=16",
            ));
        }
        let raw_pk = b64_decode(&self.credential_key)
            .map_err(|_| ConfigError::InvalidField("credential-key is not canonical base64url"))?;
        let public_key_bytes: [u8; 33] = raw_pk
            .try_into()
            .map_err(|_| ConfigError::InvalidField("credential-key must be 33 bytes"))?;
        let public_key = ec_act::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| ConfigError::InvalidField("credential-key is not a valid P-256 point"))?;
        let credential_context = b64_decode(&self.credential_context).map_err(|_| {
            ConfigError::InvalidField("credential-context is not canonical base64url")
        })?;
        if credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(ConfigError::InvalidField(
                "credential-context exceeds 256 bytes",
            ));
        }
        let ctx_cred = derive_ctx_cred(&credential_context, self.balance_width)
            .map_err(|_| ConfigError::InvalidField("balance-width must be in 1..=16"))?;
        let key_id = compute_ec_act_key_id(&public_key);
        let truncated_key_id = truncated_key_id(&key_id);
        Ok(ValidatedEcActKey {
            public_key_bytes,
            public_key,
            key_id,
            truncated_key_id,
            balance_width: self.balance_width,
            credential_context,
            ctx_cred,
            result_retention: self.result_retention,
        })
    }
}

/// Validated Moderator configuration supporting both `-01` inline and Split Moderation & Redemption.
#[derive(Clone, Debug)]
pub struct ValidatedModeratorConfig {
    /// Policy identifier (`"default"` if omitted).
    pub policy_id: String,
    /// Canonical origin of `issue_uri` / `issuance_uri`.
    pub issuance_origin: String,
    /// Full validated `issuance-uri` / `issue-uri`.
    pub issuance_uri: String,
    /// Path (and query) of `issuance_uri`.
    pub issuance_path: String,
    /// Validated Split `present-uri` (if configured) and its path.
    pub present_uri: Option<(String, String)>,
    /// Validated `settle-uri` (defaults to `issuance_uri` for `-01` compatibility) and its path.
    pub settle_uri: (String, String),
    /// Optional Split `ClearancePublicKey`.
    pub clearance_public_key: Option<ClearancePublicKey>,
    /// Optional Split `AllowedSites` list.
    pub allowed_sites: Option<AllowedSites>,
    /// Whether `endorsement-type = 1` (`NoEndorsement`) is offered.
    pub allows_no_endorsement: bool,
    /// Validated EC-IHAT Anchor Set entries.
    pub ec_ihat_sets: Vec<ValidatedEcIhatSet>,
    /// Validated EC-ACT credential keys.
    pub ec_act_keys: Vec<ValidatedEcActKey>,
}

impl ModeratorConfiguration {
    /// Validates the Moderator configuration with an explicit minimum Anchor Set size
    /// (`1` for generic protocol parsing, `MIN_ANCHOR_SET_LEN = 3` for browser enforcement).
    pub fn validate_with_min_anchors(
        &self,
        min_anchors: usize,
    ) -> Result<ValidatedModeratorConfig, ConfigError> {
        let effective_issue_uri = self
            .issue_uri
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.issuance_uri);
        if effective_issue_uri.is_empty() {
            return Err(ConfigError::InvalidUri("missing issuance-uri / issue-uri"));
        }
        let (issuance_origin, issuance_path) = validate_https_endpoint_uri(effective_issue_uri)?;

        if !self.issuance_uri.is_empty() && self.issue_uri.is_some() {
            let (legacy_origin, _) = validate_https_endpoint_uri(&self.issuance_uri)?;
            if legacy_origin != issuance_origin {
                return Err(ConfigError::InvalidUri(
                    "issuance-uri and issue-uri must share the Moderator origin",
                ));
            }
        }

        let present_uri = if let Some(ref raw_present) = self.present_uri {
            let (p_origin, p_path) = validate_https_endpoint_uri(raw_present)?;
            if p_origin != issuance_origin {
                return Err(ConfigError::InvalidUri(
                    "present-uri must share the Moderator origin",
                ));
            }
            Some((raw_present.clone(), p_path))
        } else {
            None
        };

        let settle_uri = if let Some(ref raw_settle) = self.settle_uri {
            let (s_origin, s_path) = validate_https_endpoint_uri(raw_settle)?;
            if s_origin != issuance_origin {
                return Err(ConfigError::InvalidUri(
                    "settle-uri must share the Moderator origin",
                ));
            }
            (raw_settle.clone(), s_path)
        } else {
            (effective_issue_uri.to_string(), issuance_path.clone())
        };

        let policy_id = self
            .policy_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        if policy_id.is_empty()
            || policy_id.len() > 128
            || policy_id.bytes().any(|b| b.is_ascii_control())
        {
            return Err(ConfigError::InvalidField("invalid policy-id"));
        }

        let clearance_public_key = match &self.clearance_public_key {
            Some(b64) => {
                let raw = b64_decode(b64).map_err(|_| {
                    ConfigError::InvalidField("clearance-public-key is not canonical base64url")
                })?;
                Some(ClearancePublicKey::from_bytes(&raw)?)
            }
            None => None,
        };

        if present_uri.is_some() && clearance_public_key.is_none() {
            return Err(ConfigError::InvalidField(
                "Split Moderator with present-uri requires clearance-public-key",
            ));
        }

        let allowed_sites = match &self.allowed_sites {
            None => None,
            Some(entries) => {
                if entries.is_empty() || entries.len() > 256 {
                    return Err(ConfigError::InvalidField("allowed-sites length out of range"));
                }
                if entries.len() == 1 && entries[0] == "*" {
                    Some(AllowedSites::Any)
                } else {
                    let mut canonical = Vec::with_capacity(entries.len());
                    for entry in entries {
                        canonical.push(validate_https_origin(entry)?);
                    }
                    Some(AllowedSites::Origins(canonical))
                }
            }
        };

        if let Some(l) = self.range_bits_l {
            if l == 0 || l > MAX_BROWSER_BALANCE_WIDTH {
                return Err(ConfigError::InvalidField("range-bits-l must be in 1..=16"));
            }
        }

        if self.endorsements.is_empty() || self.credential_keys.is_empty() {
            return Err(ConfigError::InvalidField(
                "endorsements and credential-keys must be non-empty",
            ));
        }

        let mut allows_no_endorsement = false;
        let mut ec_ihat_sets = Vec::new();
        for entry in &self.endorsements {
            let Some(et) = entry.get("endorsement-type").and_then(|v| v.as_u64()) else {
                return Err(ConfigError::InvalidField(
                    "endorsement entry missing uint endorsement-type",
                ));
            };
            let et = u16::try_from(et)
                .map_err(|_| ConfigError::InvalidField("endorsement-type out of u16 range"))?;
            match et {
                0 => return Err(ConfigError::InvalidField("endorsement-type 0 is reserved")),
                endorsement_type::NO_ENDORSEMENT => allows_no_endorsement = true,
                endorsement_type::EC_IHAT => {
                    let typed: EcIhatEndorsementConfig = serde_json::from_value(entry.clone())
                        .map_err(|e| ConfigError::MalformedJson(e.to_string()))?;
                    ec_ihat_sets.push(typed.validate_with_min(min_anchors)?);
                }
                _ => {}
            }
        }

        let mut ec_act_keys = Vec::new();
        let mut trunc_ids = HashSet::new();
        for entry in &self.credential_keys {
            let Some(ct) = entry.get("credential-type").and_then(|v| v.as_u64()) else {
                return Err(ConfigError::InvalidField(
                    "credential-key entry missing uint credential-type",
                ));
            };
            let ct = u16::try_from(ct)
                .map_err(|_| ConfigError::InvalidField("credential-type out of u16 range"))?;
            match ct {
                0 => return Err(ConfigError::InvalidField("credential-type 0 is reserved")),
                credential_type::EC_ACT => {
                    let typed: EcActKeyConfig = serde_json::from_value(entry.clone())
                        .map_err(|e| ConfigError::MalformedJson(e.to_string()))?;
                    let validated = typed.validate()?;
                    if let Some(l) = self.range_bits_l {
                        if validated.balance_width != l {
                            return Err(ConfigError::InvalidField(
                                "range-bits-l disagrees with credential-key balance-width",
                            ));
                        }
                    }
                    if !trunc_ids.insert(validated.truncated_key_id) {
                        return Err(ConfigError::InvalidField(
                            "active EC-ACT keys must not share truncated_key_id",
                        ));
                    }
                    ec_act_keys.push(validated);
                }
                _ => {}
            }
        }

        Ok(ValidatedModeratorConfig {
            policy_id,
            issuance_origin,
            issuance_uri: effective_issue_uri.to_string(),
            issuance_path,
            present_uri,
            settle_uri,
            clearance_public_key,
            allowed_sites,
            allows_no_endorsement,
            ec_ihat_sets,
            ec_act_keys,
        })
    }

    /// Validates generic protocol configuration (`1..=64` anchors).
    pub fn validate(&self) -> Result<ValidatedModeratorConfig, ConfigError> {
        self.validate_with_min_anchors(1)
    }

    /// Validates under strict browser privacy policy (`MIN_ANCHOR_SET_LEN = 3`..=`64` anchors).
    pub fn validate_browser_policy(&self) -> Result<ValidatedModeratorConfig, ConfigError> {
        self.validate_with_min_anchors(MIN_ANCHOR_SET_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fill_random;
    use crate::http::b64_encode;

    #[test]
    fn https_uri_validation_enforces_spec_rules() {
        assert_eq!(
            validate_https_endpoint_uri("https://Moderator.Example:443/mole/issue").unwrap(),
            ("https://moderator.example".into(), "/mole/issue".into())
        );
        assert_eq!(
            validate_https_endpoint_uri("https://antifraud.com:8080/mole/issue").unwrap(),
            ("https://antifraud.com:8080".into(), "/mole/issue".into())
        );
        assert!(validate_https_endpoint_uri("http://antifraud.com/mole/issue").is_err());
        assert!(validate_https_endpoint_uri("https://user@antifraud.com/mole/issue").is_err());
        assert!(validate_https_endpoint_uri("https://antifraud.com/mole/issue#frag").is_err());
        assert!(validate_https_endpoint_uri("https://a.com\\b.com/mole/issue").is_err());
        assert!(validate_https_endpoint_uri("https://antifraud.com/mole\\issue").is_err());
        assert!(validate_https_endpoint_uri("https://bad_host.com/mole/issue").is_err());
        assert!(validate_https_endpoint_uri("https://[not-ipv6]/mole/issue").is_err());
        assert_eq!(
            validate_https_endpoint_uri("https://[::1]:8443/mole/issue").unwrap(),
            ("https://[::1]:8443".into(), "/mole/issue".into())
        );
    }

    #[test]
    fn anchor_and_moderator_configs_validate_split_and_browser_min_anchors() {
        let mut keys = Vec::new();
        for _ in 0..3 {
            let mut seed = [0u8; 48];
            fill_random(&mut seed).unwrap();
            let sk: ec_ihat::SecretKey = ec_ihat::SecretKey::from_seed(&seed).unwrap();
            keys.push(b64_encode(&sk.public_key().to_bytes()));
        }
        let mut seed_m = [0u8; 48];
        fill_random(&mut seed_m).unwrap();
        let sk_m: ec_act::SecretKey = ec_act::SecretKey::from_seed(&seed_m).unwrap();

        let anchor_cfg = AnchorConfiguration {
            grant_uri: "https://anchor.com/mole/grant".into(),
            endorsement_type: 2,
            ciphersuite: "P256-SHA256".into(),
            anchor_key: keys[0].clone(),
            issuance_epoch: b64_encode(b"2026-11"),
        };
        assert_eq!(anchor_cfg.validate_ec_ihat().unwrap().origin, "https://anchor.com");

        // 2 anchors passes generic validate(1) if needed, but FAILS validate_browser_policy() (< 3).
        let mod_2_anchors = serde_json::json!({
            "issuance-uri": "https://antifraud.com/mole/v1/issue",
            "present-uri": "https://antifraud.com/mole/v1/present",
            "settle-uri": "https://antifraud.com/mole/v1/settle",
            "policy-id": "policy-2026",
            "range-bits-l": 16,
            "clearance-public-key": b64_encode(&sk_m.public_key().to_bytes()),
            "allowed-sites": ["https://shoes.example:8443", "https://socks.example:8444"],
            "endorsements": [{
                "endorsement-type": 2,
                "ciphersuite": "P256-SHA256",
                "issuance-epoch": b64_encode(b"2026-11"),
                "anchor-set": [keys[0].clone(), keys[1].clone()]
            }],
            "credential-keys": [{
                "credential-type": 1,
                "credential-key": b64_encode(&sk_m.public_key().to_bytes()),
                "ciphersuite": "P256-SHA256",
                "balance-width": 16,
                "credential-context": b64_encode(b"moderator-v1"),
                "result-retention": 300
            }]
        });
        let cfg2: ModeratorConfiguration = serde_json::from_value(mod_2_anchors).unwrap();
        assert!(cfg2.validate_browser_policy().is_err());

        // 3 anchors passes validate_browser_policy() cleanly.
        let mut mod_3 = serde_json::to_value(&cfg2).unwrap();
        mod_3["endorsements"][0]["anchor-set"] = serde_json::json!(keys);
        let cfg3: ModeratorConfiguration = serde_json::from_value(mod_3).unwrap();
        let vm = cfg3.validate_browser_policy().unwrap();
        assert_eq!(vm.policy_id, "policy-2026");
        assert_eq!(vm.ec_act_keys[0].balance_width, 16);
        assert_eq!(vm.ec_ihat_sets[0].anchor_set.len(), 3);
        assert!(vm.allowed_sites.as_ref().unwrap().allows("https://shoes.example:8443"));
        assert!(!vm.allowed_sites.as_ref().unwrap().allows("https://evil.example"));
    }
}
