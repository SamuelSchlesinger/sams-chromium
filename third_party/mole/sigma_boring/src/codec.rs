// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The sigma-protocol Fiat-Shamir transcript framing, reproducing
//! sigma-proofs / spongefish byte-for-byte for the `sigma-proofs_Shake128_P256`
//! suite: the 64-byte padded protocol identifier, the nested-SHAKE128 session
//! derivation, `public_message`/`prover_message` absorption, and the wide
//! (64-byte -> mod n) challenge derivation.

use crate::{Scalar, Transcript, SCALAR_BYTES};

/// Pad a protocol identifier to the fixed 64-byte field.
pub fn pad_identifier(identifier: &[u8]) -> [u8; 64] {
    assert!(identifier.len() <= 64, "identifier must fit in 64 bytes");
    let mut padded = [0u8; 64];
    padded[..identifier.len()].copy_from_slice(identifier);
    padded
}

/// A transcript seeded from a 64-byte protocol identifier: a fresh SHAKE128
/// absorbing a 168-byte block whose prefix is the identifier (spongefish's
/// `StdHash::from_protocol_id`).
pub fn from_protocol_id(protocol_id: &[u8; 64]) -> Transcript {
    let mut transcript = Transcript::default();
    let mut initial_block = [0u8; 168];
    initial_block[..64].copy_from_slice(protocol_id);
    transcript.absorb(&initial_block);
    transcript
}

/// The session identifier: `[0u8; 32] || SHAKE128(id-tag-block || session)[..32]`
/// (sigma-proofs `derive_session_id`).
pub fn derive_session_id(session: &[u8]) -> [u8; 64] {
    let mut transcript =
        from_protocol_id(&pad_identifier(b"fiat-shamir/session-id"));
    transcript.absorb(session);
    let mut session_id = [0u8; 64];
    transcript.squeeze(&mut session_id[32..]);
    session_id
}

/// Initialize a prover/verifier transcript for a suite: seed from the protocol
/// identifier, then absorb the session and the instance (public messages).
pub fn init_transcript(
    protocol_identifier: &[u8],
    session: &[u8],
    instance: &[u8],
) -> Transcript {
    let mut transcript = from_protocol_id(&pad_identifier(protocol_identifier));
    transcript.absorb(&derive_session_id(session));
    transcript.absorb(instance);
    transcript
}

/// Derive a challenge scalar: squeeze 64 bytes and reduce mod the group order.
pub fn challenge_scalar(transcript: &mut Transcript) -> Scalar {
    let mut wide = [0u8; 2 * SCALAR_BYTES];
    transcript.squeeze(&mut wide);
    Scalar::from_wide_bytes_reduced(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Point;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Golden spec vector from sigma-proofs
    // tests/spec/testdata/sigma-proofs_Shake128_P256.json (discrete_logarithm):
    // Statement = header(20) || G(33) || P(33); Batchable Proof = R(33) || z(32).
    // A byte-exact codec must recompute a challenge c for which the Schnorr
    // verification equation z*G == R + c*P holds.
    const CIPHERSUITE: &[u8] = b"sigma-proofs_Shake128_P256";
    const SESSION_HEX: &str = "64697363726574655f6c6f6761726974686d";
    const STATEMENT_HEX: &str = "0100000001000000010000000000000000000000036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29602d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f6325336";
    const BATCHABLE_HEX: &str = "031af107806a9d4f14c569d5a255904f682a7e1cc289ca70f5306d690609bf8f7231ffdce808d01c2ee9354c49c3dcbe6361cce35b81c304abd3a813909ec3c16a";

    #[test]
    fn discrete_log_spec_vector_verifies() {
        let session = unhex(SESSION_HEX);
        let statement = unhex(STATEMENT_HEX);
        let batchable = unhex(BATCHABLE_HEX);

        // Statement layout: 20-byte header, then two compressed points.
        let g_bytes: [u8; 33] = statement[20..53].try_into().unwrap();
        let p_bytes: [u8; 33] = statement[53..86].try_into().unwrap();
        let generator = Point::from_bytes(&g_bytes).expect("generator decodes");
        let public = Point::from_bytes(&p_bytes).expect("public point decodes");

        // Batchable proof: commitment R (33) then response z (32).
        let r_bytes: [u8; 33] = batchable[0..33].try_into().unwrap();
        let z_bytes: [u8; 32] = batchable[33..65].try_into().unwrap();
        let commitment = Point::from_bytes(&r_bytes).expect("commitment decodes");
        let response = Scalar::from_bytes_reduced(&z_bytes);

        // Reconstruct the transcript and derive the challenge exactly as the
        // prover did: seed, absorb session + instance, absorb commitment.
        let mut transcript = init_transcript(CIPHERSUITE, &session, &statement);
        transcript.absorb(&commitment.to_bytes());
        let challenge = challenge_scalar(&mut transcript);

        // Schnorr verification for P = x*G: z*G == R + c*P.
        let lhs = generator.mul(&response);
        let rhs = commitment.add(&public.mul(&challenge));
        assert!(
            lhs.eq(&rhs),
            "spec-vector Schnorr equation failed: codec not byte-exact"
        );
    }

    #[test]
    fn generator_matches_statement() {
        // The statement's first point is the standard P-256 generator, so
        // G*1 from BoringSSL must equal it — a sanity check on our decode.
        let statement = unhex(STATEMENT_HEX);
        let g_bytes: [u8; 33] = statement[20..53].try_into().unwrap();
        let one = {
            let mut b = [0u8; 32];
            b[31] = 1;
            Scalar::from_bytes_reduced(&b)
        };
        assert_eq!(Point::mul_generator(&one).to_bytes(), g_bytes);
    }
}
