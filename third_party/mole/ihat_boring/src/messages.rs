// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The IHAT redemption message types on `sigma_boring`, ported from `ihat-rs`
//! `messages.rs` / `verifier.rs`. This is the *verifier* half: the endorsement
//! and its Chaum–Pedersen DLEQ check, plus the `Presentation` and its single
//! acceptance decision (DLEQ well-formedness AND the accepted-set OR-proof).
//! The prover (client/anchor issuance) is not ported here — the reference
//! `ihat-rs` drives issuance in the differential test.

use crate::hash::{fiat_shamir, hash_nullifier, pedersen_generator};
use crate::orproof::OrProof;
use sigma_boring::{Point, Scalar};

/// Client → Anchor: the blinded nullifier hash `Y' = v·Y` and the endorsement
/// context. Field layout matches `ihat-rs`'s `SignatureRequest`.
pub struct SignatureRequest {
    /// Blinded nullifier hash `Y'`.
    pub yp: Point,
    /// Endorsement context (e.g. an epoch).
    pub endorsement_context: Vec<u8>,
}

/// Anchor → Client: keyed value, commitment, and two nonce commitments.
pub struct Signature {
    /// `Z' = x·Y'`.
    pub zp: Point,
    /// `C' = a'·G + b'·H`.
    pub cp: Point,
    /// `T₁' = t'·Y'`.
    pub t1p: Point,
    /// `T₂' = t'·G`.
    pub t2p: Point,
}

/// Client → Anchor: the twisted Fiat–Shamir challenge `e' = ε·α⁻¹·γ·e`.
pub struct ProofRequest {
    /// The twisted challenge.
    pub e_prime: Scalar,
}

/// Anchor → Client: the twisted response and the opened factors.
pub struct Proof {
    /// `r' = t' + e'·a'·x`.
    pub rp: Scalar,
    /// `a'`.
    pub ap: Scalar,
    /// `b'`.
    pub bp: Scalar,
}

/// A publicly-verifiable endorsement on the rerandomised statement
/// `(X_hat, Z_hat)`. Field layout and semantics match `ihat-rs`'s
/// `Endorsement`.
pub struct Endorsement {
    /// `X_hat = γ·X`.
    pub x_hat: Point,
    /// `Z_hat = γ·x·Y`.
    pub z_hat: Point,
    /// The issuance nullifier.
    pub nf: Vec<u8>,
    /// Fiat–Shamir challenge.
    pub e: Scalar,
    /// Committed factor.
    pub a: Scalar,
    /// Pedersen opening.
    pub b: Scalar,
    /// Response.
    pub r: Scalar,
    /// Endorsement context (e.g. an epoch), bound into `e`.
    pub endorsement_context: Vec<u8>,
}

impl Endorsement {
    /// Check the endorsement's Chaum–Pedersen DLEQ proof: the `a ≠ 0`,
    /// `X_hat, Z_hat ≠ 0`, and `Y ≠ 0` guards, then the Fiat–Shamir check
    /// (recompute `T₁ = r·Y − ea·Z_hat`, `T₂ = r·G − ea·X_hat`,
    /// `C = a·G + b·H`, with `H = H(context)`, and require `e` to match).
    ///
    /// Not acceptance on its own — it only says `(G, X_hat, Y, Z_hat)` is a
    /// well-formed DH tuple; binding `X_hat` to an accepted anchor is the
    /// OR-proof's job (see [`Presentation::verify`]). Ported byte-for-byte from
    /// `ihat-rs` `Endorsement::dleq_valid` (`pp.g` is the P-256 generator).
    pub fn dleq_valid(&self) -> bool {
        if self.a.is_zero() {
            return false;
        }
        if self.x_hat.is_identity() || self.z_hat.is_identity() {
            return false;
        }
        let y = hash_nullifier(&self.nf);
        if y.is_identity() {
            return false;
        }
        let g = Point::generator();
        let ea = self.e.mul(&self.a);
        // T₁ = r·Y − ea·Z_hat, T₂ = r·G − ea·X_hat (subtraction via negate).
        let t1 = y.mul(&self.r).add(&self.z_hat.mul(&ea).negate());
        let t2 = g.mul(&self.r).add(&self.x_hat.mul(&ea).negate());
        let h = pedersen_generator(&self.endorsement_context);
        let c = g.mul(&self.a).add(&h.mul(&self.b));
        self.e.ct_eq(&fiat_shamir(
            &self.x_hat,
            &y,
            &self.z_hat,
            &t1,
            &t2,
            &c,
            &self.endorsement_context,
        ))
    }
}

/// A redemption presentation: the endorsement plus the accepted-set OR-proof.
pub struct Presentation {
    /// The endorsement.
    pub endorsement: Endorsement,
    /// `1`-of-`n` OR-proof that `X_hat` is a `γ`-scaling of an accepted key.
    pub or_proof: OrProof,
}

impl Presentation {
    /// The single acceptance decision (the Verifier / Moderator verb): accept
    /// iff the endorsement's DLEQ proof is well-formed AND the OR-proof binds
    /// `X_hat` to some key in `accepted`, under the exact `binding` the prover
    /// used. `accepted` are the anchor public keys as group elements.
    pub fn verify(&self, accepted: &[Point], binding: &[u8]) -> bool {
        self.endorsement.dleq_valid()
            && self
                .or_proof
                .verify(accepted, &self.endorsement.x_hat, binding)
    }
}
