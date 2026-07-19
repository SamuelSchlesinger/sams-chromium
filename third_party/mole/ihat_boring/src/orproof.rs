// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The redemption OR-proof, ported from `ihat-rs` `orproof.rs` onto
//! `sigma_boring::bssl`. A 1-of-n CDS OR over the Schnorr relation `X = w·B`.

use crate::hash::fiat_shamir_or;
use sigma_boring::{Point, Scalar};
use subtle::{Choice, ConstantTimeEq};

/// A Schnorr transcript for `X = w·B`: commitment `t`, sub-challenge `c`,
/// response `s`.
#[derive(Clone)]
pub struct Transcript {
    pub t: Point,
    pub c: Scalar,
    pub s: Scalar,
}

/// Verifier for `X = w·B`: `s·B == t + c·X`.
fn verify_branch(b: &Point, x: &Point, tr: &Transcript) -> bool {
    b.mul(&tr.s).eq(&tr.t.add(&x.mul(&tr.c)))
}

/// A 1-of-n OR proof: one transcript per accepted key.
#[derive(Clone)]
pub struct OrProof {
    pub transcripts: Vec<Transcript>,
}

impl OrProof {
    /// Prove `X = γ·B[true_index]` for a hidden `true_index`, simulating the
    /// decoy branches (CDS). Constant-time in the secret `true_index`: the real
    /// base is recovered by a branchless select and every branch does identical
    /// work.
    pub fn prove(
        accepted: &[Point],
        x: &Point,
        true_index: usize,
        witness: &Scalar,
        binding: &[u8],
    ) -> OrProof {
        let n = accepted.len();
        assert!(n > 0, "accepted set must be non-empty");
        assert!(true_index < n, "true branch out of range");

        let cdec: Vec<Scalar> = (0..n).map(|_| Scalar::random()).collect();
        let sdec: Vec<Scalar> = (0..n).map(|_| Scalar::random()).collect();
        let k = Scalar::random();
        // Constant-time "is this the real branch?" flag (compared as u64), so
        // no control flow or select depends on the secret true_index.
        let is_real: Vec<Choice> =
            (0..n).map(|l| (l as u64).ct_eq(&(true_index as u64))).collect();

        // Recover, without indexing by the secret, the real base B_{j*}, Σ cdec,
        // and cdec[j*].
        let mut b_real = Point::identity();
        let mut total = Scalar::zero();
        let mut cdec_real = Scalar::zero();
        for l in 0..n {
            b_real = Point::conditional_select(&b_real, &accepted[l], is_real[l]);
            total = total.add(&cdec[l]);
            cdec_real = Scalar::conditional_select(&cdec_real, &cdec[l], is_real[l]);
        }
        let honest_t = b_real.mul(&k);

        // Each branch: simulated commitment sₗ·Bₗ − cₗ·X, honest_t selected in
        // at the real branch. (s·B − c·X computed as s·B + X·(−c).)
        let commitments: Vec<Point> = (0..n)
            .map(|l| {
                let sim_t = accepted[l].mul(&sdec[l]).add(&x.mul(&cdec[l].negate()));
                Point::conditional_select(&sim_t, &honest_t, is_real[l])
            })
            .collect();

        let c = fiat_shamir_or(accepted, x, &commitments, binding);
        let c_real = c.sub(&total.sub(&cdec_real)); // c − Σ_{l≠j*} cdec[l]
        let s_real = k.add(&c_real.mul(witness));

        let transcripts = (0..n)
            .map(|l| Transcript {
                t: commitments[l].clone(),
                c: Scalar::conditional_select(&cdec[l], &c_real, is_real[l]),
                s: Scalar::conditional_select(&sdec[l], &s_real, is_real[l]),
            })
            .collect();

        OrProof { transcripts }
    }

    /// Verify: recompute the master challenge, check the sub-challenges sum to
    /// it, and every branch verifies. Rejects the identity statement and any
    /// identity anchor key.
    pub fn verify(&self, accepted: &[Point], x: &Point, binding: &[u8]) -> bool {
        if self.transcripts.len() != accepted.len() || accepted.is_empty() {
            return false;
        }
        if x.is_identity() || accepted.iter().any(|b| b.is_identity()) {
            return false;
        }
        let commitments: Vec<Point> = self.transcripts.iter().map(|tr| tr.t.clone()).collect();
        let c = fiat_shamir_or(accepted, x, &commitments, binding);

        let mut sum = Scalar::zero();
        for tr in &self.transcripts {
            sum = sum.add(&tr.c);
        }

        sum.ct_eq(&c)
            && accepted
                .iter()
                .zip(&self.transcripts)
                .all(|(b, tr)| verify_branch(b, x, tr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A set of n accepted anchor keys B_l = b_l·G and a rerandomised key
    // X = γ·B[real], with witness γ.
    fn setup(n: usize, real: usize) -> (Vec<Point>, Point, Scalar) {
        let accepted: Vec<Point> = (0..n)
            .map(|l| Point::mul_generator(&Scalar::from_u64((l as u64) + 3)))
            .collect();
        let gamma = Scalar::from_u64(0x9e3779b9);
        let x = accepted[real].mul(&gamma);
        (accepted, x, gamma)
    }

    #[test]
    fn or_proof_roundtrips_for_each_real_branch() {
        for n in [1usize, 2, 5] {
            for real in 0..n {
                let (accepted, x, gamma) = setup(n, real);
                let proof = OrProof::prove(&accepted, &x, real, &gamma, b"ctx-binding");
                assert!(
                    proof.verify(&accepted, &x, b"ctx-binding"),
                    "n={n} real={real} must verify"
                );
            }
        }
    }

    #[test]
    fn wrong_binding_rejected() {
        let (accepted, x, gamma) = setup(3, 1);
        let proof = OrProof::prove(&accepted, &x, 1, &gamma, b"binding-a");
        assert!(!proof.verify(&accepted, &x, b"binding-b"));
    }

    #[test]
    fn wrong_statement_rejected() {
        let (accepted, x, gamma) = setup(3, 1);
        let proof = OrProof::prove(&accepted, &x, 1, &gamma, b"ctx");
        // A different X_hat (not γ·B for the proven branch) must fail.
        let x2 = x.add(&Point::generator());
        assert!(!proof.verify(&accepted, &x2, b"ctx"));
    }

    #[test]
    fn identity_statement_rejected() {
        let (accepted, _, _) = setup(3, 0);
        let proof = OrProof::prove(&accepted, &accepted[0], 0, &Scalar::from_u64(1), b"c");
        assert!(!proof.verify(&accepted, &Point::identity(), b"c"));
    }
}
