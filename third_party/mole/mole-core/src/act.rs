// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! EC-ACT credential protocol glue (`draft-jms-mole-protocols-01` §5.2):
//! key identifiers, `ctx_cred` derivation, and 96-byte recovery/signoff handles.

use crate::wire::WireError;
use crate::{MAX_BROWSER_BALANCE_WIDTH, MAX_CREDENTIAL_CONTEXT_LEN, sha256};

/// Default EC-ACT balance width `L = 8` (`[0, 2^8) = [0, 256)`).
pub const DEFAULT_BALANCE_WIDTH: u8 = 8;

/// Recommended wider EC-ACT balance width `L = 16` (`[0, 2^16) = [0, 65536)`).
pub const WIDE_BALANCE_WIDTH: u8 = 16;

/// Computes `key_id = SHA-256(SerializeElement(pkM))` (`draft-jms-mole-protocols-01` §5.2.1).
pub fn key_id(pk_m_bytes: &[u8; 33]) -> [u8; 32] {
    sha256(pk_m_bytes)
}

/// Computes `key_id` directly from an [`ec_act::PublicKey`].
pub fn compute_ec_act_key_id(pk_m: &ec_act::PublicKey) -> [u8; 32] {
    key_id(&pk_m.to_bytes())
}

/// Returns `truncated_key_id`, the last byte of `key_id` (`draft-jms-mole-protocols-01` §5.2.1).
pub fn truncated_key_id(key_id_bytes: &[u8; 32]) -> u8 {
    key_id_bytes[31]
}

/// Derives `ctx_cred = credential_context || I2OSP(L, 1)` (`draft-jms-mole-protocols-01` §5.2.1).
/// Enforces `credential_context.len() <= MAX_CREDENTIAL_CONTEXT_LEN` (`256`) and
/// `1 <= balance_width <= MAX_BROWSER_BALANCE_WIDTH` (`16`).
pub fn derive_ctx_cred(
    credential_context: &[u8],
    balance_width: u8,
) -> Result<Vec<u8>, WireError> {
    if credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
        return Err(WireError::OutOfRange);
    }
    if balance_width == 0 || balance_width > MAX_BROWSER_BALANCE_WIDTH {
        return Err(WireError::OutOfRange);
    }
    let mut out = Vec::with_capacity(credential_context.len() + 1);
    out.extend_from_slice(credential_context);
    out.push(balance_width);
    Ok(out)
}

/// Computes the 96-byte EC-ACT recovery / signoff handle (`draft-jms-mole-protocols-01` §5.2.5):
/// `key_id || SerializeScalar(spend.k) || SHA-256(PresentationAndUpdate)`.
pub fn compute_recovery_handle(
    key_id_bytes: &[u8; 32],
    nullifier_k: &[u8; 32],
    presentation_and_update_bytes: &[u8],
) -> [u8; 96] {
    let digest = sha256(presentation_and_update_bytes);
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(key_id_bytes);
    out[32..64].copy_from_slice(nullifier_k);
    out[64..96].copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_has_no_nonstandard_dst_and_truncates_to_last_byte() {
        let pk = [0x02u8; 33];
        let kid = key_id(&pk);
        assert_eq!(kid, sha256(&pk));
        assert_eq!(truncated_key_id(&kid), kid[31]);
    }

    #[test]
    fn ctx_cred_supports_l8_and_l16_and_enforces_bounds() {
        let ctx8 = derive_ctx_cred(b"moderator-v1", 8).unwrap();
        assert_eq!(ctx8, b"moderator-v1\x08");
        let ctx16 = derive_ctx_cred(b"moderator-v1", 16).unwrap();
        assert_eq!(ctx16, b"moderator-v1\x10");
        assert!(derive_ctx_cred(b"x", 0).is_err());
        assert!(derive_ctx_cred(b"x", 17).is_err());
        assert!(derive_ctx_cred(&vec![0u8; MAX_CREDENTIAL_CONTEXT_LEN + 1], 8).is_err());
    }
}
