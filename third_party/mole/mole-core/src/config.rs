// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Anchor and Moderator JSON configuration schemas (`draft-jms-mole-protocols-01` §6):
//! - `/.well-known/mole-anchor` -> [`AnchorConfiguration`]
//! - `/.well-known/mole-moderator` -> [`ModeratorConfiguration`]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::act::{compute_ec_act_key_id, derive_ctx_cred, truncated_key_id};
use crate::http::b64_decode;
use crate::{
    CIPHERSUITE_P256_SHA256, MAX_CREDENTIAL_CONTEXT_LEN, credential_type, endorsement_type,
};

/// Well-known discovery path for an Anchor.
pub const ANCHOR_DIRECTORY_PATH: &str = "/.well-known/mole-anchor";
/// Well-known discovery path for a Moderator.
pub const MODERATOR_DIRECTORY_PATH: &str = "/.well-known/mole-moderator";

/// Error validating a MOLE Anchor or Moderator configuration document.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ConfigError {
    /// Malformed JSON syntax or field types.
    #[error("malformed configuration JSON: {0}")]
    MalformedJson(String),
    /// Invalid endpoint URI (`grant-uri` or `issuance-uri`).
    #[error("invalid HTTPS endpoint URI: {0}")]
    InvalidUri(&'static str),
    /// Invalid or unsupported configuration field.
    #[error("invalid configuration: {0}")]
    InvalidField(&'static str),
}

/// Validates an absolute `https://` URI with a non-empty host, no userinfo, and
/// no fragment (`draft-jms-mole-protocols-01` §6), returning `(canonical_origin, path_and_query)`.
pub fn validate_https_endpoint_uri(uri: &str) -> Result<(String, String), ConfigError> {
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

    // Normalize host lowercase and strip default HTTPS port `:443` so canonical
    // origin matches `url::Origin::Serialize()` ("https://host" or "https://host:port").
    let (host, port_opt) = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or(ConfigError::InvalidUri("unclosed IPv6 literal"))?;
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
        (h.to_ascii_lowercase(), Some(parse_port(p)?))
    } else {
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

/// Anchor configuration JSON (`draft-jms-mole-protocols-01` §6):
/// ```json
/// {
///   "grant-uri": "https://anchor.example/mole/grant",
///   "endorsement-type": 2,
///   "ciphersuite": "P256-SHA256",
///   "anchor-key": "...",
///   "issuance-epoch": "..."
/// }
/// ```
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
        if issuance_epoch.len() > usize::from(u16::MAX) {
            return Err(ConfigError::InvalidField("issuance-epoch exceeds 65535 bytes"));
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

/// Moderator configuration JSON (`draft-jms-mole-protocols-01` §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeratorConfiguration {
    /// Absolute HTTPS Redeem & Issue endpoint URI.
    #[serde(rename = "issuance-uri")]
    pub issuance_uri: String,
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
    /// Ordered unpadded base64url `SerializeElement(pkA)` entries.
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
    /// Validates and decodes an EC-IHAT endorsement config entry.
    pub fn validate(&self) -> Result<ValidatedEcIhatSet, ConfigError> {
        if self.endorsement_type != endorsement_type::EC_IHAT {
            return Err(ConfigError::InvalidField("expected endorsement-type 2"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(ConfigError::InvalidField("unsupported EC-IHAT ciphersuite"));
        }
        let issuance_epoch = b64_decode(&self.issuance_epoch)
            .map_err(|_| ConfigError::InvalidField("issuance-epoch is not canonical base64url"))?;
        if issuance_epoch.len() > usize::from(u16::MAX) {
            return Err(ConfigError::InvalidField("issuance-epoch exceeds 65535 bytes"));
        }
        if self.anchor_set.is_empty() || self.anchor_set.len() > usize::from(u16::MAX) {
            return Err(ConfigError::InvalidField("anchor-set length out of range"));
        }
        let mut seen = HashSet::with_capacity(self.anchor_set.len());
        let mut raw_keys = Vec::with_capacity(self.anchor_set.len());
        let mut anchor_set = Vec::with_capacity(self.anchor_set.len());
        for entry in &self.anchor_set {
            let decoded = b64_decode(entry)
                .map_err(|_| ConfigError::InvalidField("anchor-set key is not canonical base64url"))?;
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
}

/// Typed No-Endorsement entry (`endorsement-type = 1`) in `ModeratorConfiguration.endorsements`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoEndorsementConfig {
    /// Must be `1`.
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
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
    /// Balance width `L` (`1..=64`).
    #[serde(rename = "balance-width")]
    pub balance_width: u8,
    /// Unpadded base64url `credential_context` (`<= 65534` bytes).
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
    /// Balance width `L`.
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
                "credential-context exceeds 65534 bytes",
            ));
        }
        let ctx_cred = derive_ctx_cred(&credential_context, self.balance_width)
            .map_err(|_| ConfigError::InvalidField("balance-width must be in 1..=64"))?;
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

/// Validated Moderator configuration (`draft-jms-mole-protocols-01` §6).
#[derive(Clone, Debug)]
pub struct ValidatedModeratorConfig {
    /// Canonical origin of `issuance-uri`.
    pub issuance_origin: String,
    /// Full validated `issuance-uri`.
    pub issuance_uri: String,
    /// Path (and query) of `issuance-uri`.
    pub issuance_path: String,
    /// Whether `endorsement-type = 1` (`NoEndorsement`) is offered.
    pub allows_no_endorsement: bool,
    /// Validated EC-IHAT Anchor Set entries.
    pub ec_ihat_sets: Vec<ValidatedEcIhatSet>,
    /// Validated EC-ACT credential keys.
    pub ec_act_keys: Vec<ValidatedEcActKey>,
}

impl ModeratorConfiguration {
    /// Validates `issuance-uri`, skips unknown protocol types per §6, and
    /// validates all recognized EC-IHAT (`0x0002`), NoEndorsement (`0x0001`),
    /// and EC-ACT (`0x0001`) entries, enforcing unique `truncated_key_id` across
    /// active EC-ACT keys (`draft-jms-mole-protocols-01` §5.2.1).
    pub fn validate(&self) -> Result<ValidatedModeratorConfig, ConfigError> {
        let (issuance_origin, issuance_path) = validate_https_endpoint_uri(&self.issuance_uri)?;
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
                    ec_ihat_sets.push(typed.validate()?);
                }
                _ => {} // Unknown endorsement types are skipped per §6.
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
                    if !trunc_ids.insert(validated.truncated_key_id) {
                        return Err(ConfigError::InvalidField(
                            "active EC-ACT keys must not share truncated_key_id",
                        ));
                    }
                    ec_act_keys.push(validated);
                }
                _ => {} // Unknown credential types are skipped per §6.
            }
        }

        Ok(ValidatedModeratorConfig {
            issuance_origin,
            issuance_uri: self.issuance_uri.clone(),
            issuance_path,
            allows_no_endorsement,
            ec_ihat_sets,
            ec_act_keys,
        })
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
    }

    #[test]
    fn anchor_and_moderator_configs_validate_and_skip_unknown_types() {
        let mut seed_a = [0u8; 48];
        let mut seed_m = [0u8; 48];
        fill_random(&mut seed_a).unwrap();
        fill_random(&mut seed_m).unwrap();
        let sk_a: ec_ihat::SecretKey = ec_ihat::SecretKey::from_seed(&seed_a).unwrap();
        let sk_m: ec_act::SecretKey = ec_act::SecretKey::from_seed(&seed_m).unwrap();

        let anchor_cfg = AnchorConfiguration {
            grant_uri: "https://anchor.com/mole/grant".into(),
            endorsement_type: 2,
            ciphersuite: "P256-SHA256".into(),
            anchor_key: b64_encode(&sk_a.public_key().to_bytes()),
            issuance_epoch: b64_encode(b"2026-11"),
        };
        let va = anchor_cfg.validate_ec_ihat().unwrap();
        assert_eq!(va.origin, "https://anchor.com");
        assert_eq!(va.grant_path, "/mole/grant");

        let mod_json = serde_json::json!({
            "issuance-uri": "https://antifraud.com/mole/issue",
            "endorsements": [
                {
                    "endorsement-type": 2,
                    "ciphersuite": "P256-SHA256",
                    "issuance-epoch": b64_encode(b"2026-11"),
                    "anchor-set": [b64_encode(&sk_a.public_key().to_bytes())]
                },
                {
                    "endorsement-type": 999,
                    "future-field": "ignored"
                }
            ],
            "credential-keys": [
                {
                    "credential-type": 1,
                    "credential-key": b64_encode(&sk_m.public_key().to_bytes()),
                    "ciphersuite": "P256-SHA256",
                    "balance-width": 8,
                    "credential-context": b64_encode(b"moderator-v1"),
                    "result-retention": 300
                },
                {
                    "credential-type": 2,
                    "token-type": 2
                }
            ]
        });
        let mod_cfg: ModeratorConfiguration = serde_json::from_value(mod_json).unwrap();
        let vm = mod_cfg.validate().unwrap();
        assert_eq!(vm.ec_ihat_sets.len(), 1);
        assert_eq!(vm.ec_act_keys.len(), 1);
        assert_eq!(vm.ec_act_keys[0].balance_width, 8);
    }
}
