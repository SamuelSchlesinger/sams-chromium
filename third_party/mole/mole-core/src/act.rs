//! Glue for the ACT credential mapping (credential type 0x0001): the balance
//! digit count and the ACT key identifiers.
//!
//! The shared request-context scalar (bound to every credit token so
//! presentations don't link back to Redeem & Issue) is a P-256 value derived
//! in `act_boring::proofs::request_context_scalar`; the browser runtime uses
//! that directly, so no ristretto version lives here.

/// The ACT balance digit count D this instantiation runs at: balances lie in
/// [0, 3^8) = [0, 6561). Proof sizes are determined by D, so it is fixed
/// policy-wide and published in the Moderator directory as
/// `act-balance-digits`.
pub const BALANCE_DIGITS: usize = 8;

/// The key identifier of an ACT public key: SHA-256 over its 32-byte
/// encoding. Carried in full in `PresentationAndUpdate` and truncated to its
/// final byte in `IssuanceRequest`, following the Privacy Pass convention.
pub fn key_id(public_key_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"MoLE-ACT:key-id:v1");
    hasher.update(public_key_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The truncated key identifier: the final byte of [`key_id`].
pub fn truncated_key_id(public_key_bytes: &[u8]) -> u8 {
    key_id(public_key_bytes)[31]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_truncation_is_last_byte() {
        let pk = [7u8; 32];
        assert_eq!(truncated_key_id(&pk), key_id(&pk)[31]);
    }
}
