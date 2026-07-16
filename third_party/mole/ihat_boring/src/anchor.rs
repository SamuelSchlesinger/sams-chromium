// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The IHAT Anchor (issuer) on `sigma_boring`/BoringSSL, ported from `ihat-rs`
//! `anchor.rs`. This is the signing half: the long-term key and the two-step
//! signing state machine (`sign` → `prove`). With this, `ihat_boring` carries
//! the whole IHAT protocol — anchor, client, and verifier — a complete drop-in
//! for the vendored `ihat` crate.
//!
//! The Anchor never sees the unblinded nullifier `Y`, the rerandomised
//! statement, or the untwisted challenge — only the blinded `Y'` and the
//! twisted `e'`. Per-issuance randomness (`a', b', t'`) is sampled internally
//! from BoringSSL's RNG; it must be fresh per issuance (reuse leaks the key).

use crate::client::random_nonzero_scalar;
use crate::messages::{Proof, ProofRequest, Signature, SignatureRequest};
use sigma_boring::{Point, Scalar};

/// An Anchor's long-term secret key `x`.
pub struct AnchorSecretKey {
    sk: Scalar,
}

impl AnchorSecretKey {
    /// Sample a fresh Anchor secret key.
    pub fn random() -> Self {
        AnchorSecretKey { sk: random_nonzero_scalar() }
    }

    /// The Anchor's public key `X = x·G`.
    pub fn public_key(&self) -> Point {
        Point::generator().mul(&self.sk)
    }
}

/// Anchor state after signing, awaiting the client's [`ProofRequest`].
pub struct AnchorNeedsProofRequest {
    sk: Scalar,
    ap: Scalar,
    bp: Scalar,
    tp: Scalar,
}

impl SignatureRequest {
    /// **Sign** (Anchor → Client): the keyed value `Z' = x·Y'`, the commitment
    /// `C' = a'·G + b'·H`, and the proof's first messages `T₁' = t'·Y'`,
    /// `T₂' = t'·G`. Returns the [`Signature`] and the awaiting state.
    pub fn sign(&self, key: &AnchorSecretKey) -> (Signature, AnchorNeedsProofRequest) {
        let ap = random_nonzero_scalar();
        let bp = Scalar::random();
        let tp = Scalar::random();
        let g = Point::generator();
        let h = crate::hash::pedersen_generator(&self.endorsement_context);

        let signature = Signature {
            zp: self.yp.mul(&key.sk),
            cp: g.mul(&ap).add(&h.mul(&bp)),
            t1p: self.yp.mul(&tp),
            t2p: g.mul(&tp),
        };
        (
            signature,
            AnchorNeedsProofRequest { sk: key.sk.clone(), ap, bp, tp },
        )
    }
}

impl AnchorNeedsProofRequest {
    /// **Prove** (Anchor → Client): `r' = t' + e'·a'·x`, opening `a'`, `b'`.
    pub fn prove(&self, req: &ProofRequest) -> Proof {
        Proof {
            rp: self.tp.add(&req.e_prime.mul(&self.ap).mul(&self.sk)),
            ap: self.ap.clone(),
            bp: self.bp.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientNeedsSignature;

    #[test]
    fn full_ported_issuance_and_redemption() {
        // Pure `ihat_boring` end to end — anchor signs, client issues, client
        // shows, verifier verifies — all on BoringSSL, no reference crate. Proves
        // the ported anchor completes the protocol with the (reference-verified)
        // ported client and verifier.
        for n in [1usize, 3] {
            for real in 0..n {
                let anchors: Vec<AnchorSecretKey> =
                    (0..n).map(|_| AnchorSecretKey::random()).collect();
                let accepted: Vec<Point> = anchors.iter().map(|k| k.public_key()).collect();
                let issuer = &anchors[real];

                let (sig_req, client) =
                    ClientNeedsSignature::request(b"nf".to_vec(), b"epoch".to_vec());
                let (signature, anchor) = sig_req.sign(issuer);
                let (proof_req, client) = client.request_proof(issuer.public_key(), signature);
                let proof = anchor.prove(&proof_req);
                let issued = client.finalize(proof).expect("honest issuance succeeds");

                let binding = b"ctx-binding";
                let presentation = issued.show(&accepted, real, binding);
                assert!(presentation.verify(&accepted, binding), "n={n} real={real}");
                // A different binding must fail.
                assert!(!presentation.verify(&accepted, b"other-binding"));
            }
        }
    }
}
