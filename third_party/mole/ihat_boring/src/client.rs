// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The IHAT Client (prover) on `sigma_boring`, ported from `ihat-rs`
//! `client.rs`. This is the half the browser runs: the oblivious-issuance state
//! machine (`request` → `request_proof` → `finalize` → [`IssuedEndorsement`])
//! and the redemption verb [`IssuedEndorsement::show`], which wraps the
//! already-ported OR-proof prover.
//!
//! Unlike the reference, per-issuance randomness is sampled internally from
//! BoringSSL's RNG (`Scalar::random`), so the verbs take no RNG argument — the
//! shape the FFI wants. Anchor public keys are carried as plain group elements.

use crate::hash::{fiat_shamir, hash_nullifier, pedersen_generator};
use crate::messages::{
    Endorsement, Presentation, Proof, ProofRequest, Signature, SignatureRequest,
};
use crate::orproof::OrProof;
use sigma_boring::{Point, Scalar};

/// A uniform nonzero scalar (`ℤ_p^*`), for the invertible blinders. Retries with
/// probability `2⁻²⁵⁶`; the reject is the only data-dependent branch and leaks
/// nothing about the value.
pub(crate) fn random_nonzero_scalar() -> Scalar {
    loop {
        let s = Scalar::random();
        if !s.is_zero() {
            return s;
        }
    }
}

/// Per-issuance Client randomness (`v, α, ε ∈ ℤ_p^*`, `γ, β, ρ ∈ ℤ_p`). Must be
/// fresh per issuance; reuse breaks the blinding.
struct ClientRandomness {
    v: Scalar,
    gamma: Scalar,
    alpha: Scalar,
    beta: Scalar,
    epsilon: Scalar,
    rho: Scalar,
}

impl ClientRandomness {
    fn random() -> Self {
        ClientRandomness {
            v: random_nonzero_scalar(),
            gamma: random_nonzero_scalar(),
            alpha: random_nonzero_scalar(),
            beta: Scalar::random(),
            epsilon: random_nonzero_scalar(),
            rho: Scalar::random(),
        }
    }
}

/// Client state after sending the [`SignatureRequest`]; consumed by
/// [`ClientNeedsSignature::request_proof`] when the [`Signature`] arrives.
pub struct ClientNeedsSignature {
    nf: Vec<u8>,
    endorsement_context: Vec<u8>,
    y: Point,
    yp: Point,
    randomness: ClientRandomness,
}

/// Client state after sending the [`ProofRequest`]; consumed by
/// [`ClientNeedsProof::finalize`] when the [`Proof`] arrives.
pub struct ClientNeedsProof {
    pre: ClientNeedsSignature,
    x: Point,
    sig: Signature,
    x_hat: Point,
    z_hat: Point,
    e: Scalar,
    ep: Scalar,
}

/// The terminal issuance state: the finished [`Endorsement`] plus the
/// rerandomiser `γ` (the redemption OR witness). Only the endorsement crosses
/// the wire; `γ` stays with the Client until [`show`](Self::show).
pub struct IssuedEndorsement {
    /// The endorsement.
    pub endorsement: Endorsement,
    pub(crate) gamma: Scalar,
}

impl ClientNeedsSignature {
    /// **Request** (Client → Anchor): blind the hashed nullifier, `Y' = v·Y`.
    /// Returns the [`SignatureRequest`] to send and the awaiting state.
    pub fn request(nf: Vec<u8>, endorsement_context: Vec<u8>) -> (SignatureRequest, Self) {
        let randomness = ClientRandomness::random();
        let y = hash_nullifier(&nf);
        let yp = y.mul(&randomness.v);
        (
            SignatureRequest {
                yp: yp.clone(),
                endorsement_context: endorsement_context.clone(),
            },
            ClientNeedsSignature {
                nf,
                endorsement_context,
                y,
                yp,
                randomness,
            },
        )
    }

    /// **Request proof** (Client → Anchor): recover `Z_hat`, form the
    /// rerandomised proof's first messages, and send the twisted challenge
    /// `e' = ε·α⁻¹·γ·e`. `x` is the Anchor's public key.
    pub fn request_proof(
        self,
        x: Point,
        sig: Signature,
    ) -> (ProofRequest, ClientNeedsProof) {
        let cr = &self.randomness;
        let g = Point::generator();
        let v_inv = cr.v.invert().expect("v is nonzero");
        let alpha_inv = cr.alpha.invert().expect("alpha is nonzero");
        let eps_inv = cr.epsilon.invert().expect("epsilon is nonzero");

        let h = pedersen_generator(&self.endorsement_context);
        let x_hat = x.mul(&cr.gamma);
        let z_hat = sig.zp.mul(&cr.gamma.mul(&v_inv));
        // C = cp·α⁻¹ − β·H.
        let c = sig.cp.mul(&alpha_inv).add(&h.mul(&cr.beta).negate());
        // T₁ = (t1p − ρ·Y')·(ε⁻¹·v⁻¹), T₂ = (t2p − ρ·G)·ε⁻¹.
        let t1 = sig
            .t1p
            .add(&self.yp.mul(&cr.rho).negate())
            .mul(&eps_inv.mul(&v_inv));
        let t2 = sig.t2p.add(&g.mul(&cr.rho).negate()).mul(&eps_inv);
        let e = fiat_shamir(&x_hat, &self.y, &z_hat, &t1, &t2, &c, &self.endorsement_context);
        let ep = cr.epsilon.mul(&alpha_inv).mul(&cr.gamma).mul(&e);

        (
            ProofRequest { e_prime: ep.clone() },
            ClientNeedsProof {
                pre: self,
                x,
                sig,
                x_hat,
                z_hat,
                e,
                ep,
            },
        )
    }
}

impl ClientNeedsProof {
    /// **Finalize** (Client, local): validate the Anchor's [`Proof`] (`a'`
    /// nonzero, the Pedersen opening, and the two DLEQ response checks), then
    /// unblind to the [`Endorsement`]. Returns `None` if validation fails.
    ///
    /// The four checks are combined without short-circuiting and the single
    /// branch is on the (public) accept/reject result — validating the Anchor's
    /// proof reveals nothing secret, but this keeps the structure faithful to
    /// the reference.
    pub fn finalize(self, proof: Proof) -> Option<IssuedEndorsement> {
        let cr = &self.pre.randomness;
        let g = Point::generator();
        let ea = self.ep.mul(&proof.ap);
        let h = pedersen_generator(&self.pre.endorsement_context);

        let ap_nonzero = !proof.ap.is_zero();
        // cp == a'·G + b'·H.
        let pedersen_ok = self.sig.cp.eq(&g.mul(&proof.ap).add(&h.mul(&proof.bp)));
        // r'·Y' == ea·Z' + T₁'.
        let dleq_y = self
            .pre
            .yp
            .mul(&proof.rp)
            .eq(&self.sig.zp.mul(&ea).add(&self.sig.t1p));
        // r'·G == ea·X + T₂'.
        let dleq_g = g
            .mul(&proof.rp)
            .eq(&self.x.mul(&ea).add(&self.sig.t2p));
        if !(ap_nonzero & pedersen_ok & dleq_y & dleq_g) {
            return None;
        }

        let alpha_inv = cr.alpha.invert().expect("alpha is nonzero");
        let eps_inv = cr.epsilon.invert().expect("epsilon is nonzero");
        Some(IssuedEndorsement {
            endorsement: Endorsement {
                x_hat: self.x_hat,
                z_hat: self.z_hat,
                nf: self.pre.nf,
                e: self.e,
                a: alpha_inv.mul(&proof.ap),
                b: alpha_inv.mul(&proof.bp).sub(&cr.beta),
                r: eps_inv.mul(&proof.rp.sub(&cr.rho)),
                endorsement_context: self.pre.endorsement_context,
            },
            gamma: cr.gamma.clone(),
        })
    }
}

impl IssuedEndorsement {
    /// **Show** (Client → Verifier): build a [`Presentation`]. `accepted` is the
    /// Verifier's accepted anchor-key set and `true_index` the secret position
    /// of the issuing anchor within it (so `x_hat == γ·accepted[true_index]`).
    /// `binding` scopes the presentation into the OR-proof's Fiat–Shamir
    /// challenge.
    ///
    /// # Panics
    /// If `true_index >= accepted.len()` or `accepted` is empty.
    pub fn show(self, accepted: &[Point], true_index: usize, binding: &[u8]) -> Presentation {
        let or_proof = OrProof::prove(
            accepted,
            &self.endorsement.x_hat,
            true_index,
            &self.gamma,
            binding,
        );
        Presentation {
            endorsement: self.endorsement,
            or_proof,
        }
    }
}
