// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The ACT base-3 range proof over `sigma_boring`/BoringSSL: a proof that a
//! Pedersen commitment `V = v·H1 + r·H3` opens to a value `v ∈ [0, 3^d)`,
//! without revealing `v`. This is the core novel machinery of ACT's spend
//! (which carries two of these, for the post-spend and topped-up balances);
//! porting it standalone establishes the ternary-digit relation on BoringSSL.
//!
//! Ported from the `spend_statement` range-proof equations in
//! `anonymous-credit-tokens`. For each base-3 digit `d[j]` of `v`:
//! - `Com[j] = d[j]·H1 + s[j]·H3` (digit commitment)
//! - `T[j] + Com[j] = d[j]·Com[j] + rho[j]·H3` (so `T[j]=(d[j]-1)·Com[j]+rho[j]·H3`)
//! - `2·T[j] = d[j]·T[j] + w[j]·H3` (the H1 coefficient is
//!   `d[j]·(d[j]-1)·(2-d[j])`, which vanishes iff `d[j] ∈ {0,1,2}`)
//! plus two consistency equations sharing the value witness `v`:
//! - `V = v·H1 + r·H3`
//! - `Com_total = v·H1 + Σ_j s[j]·(3^j·H3)`, where `Com_total = Σ_j 3^j·Com[j]`.
//!
//! Where the reference scales element *variables* by the public `3^j`, this
//! pre-scales the generator (`3^j·H3` is a fixed public point), since
//! `sigma_boring::RelationBuilder` terms are `scalar_var · public_point`.

use crate::params::Params;
use crate::proofs::{act_protocol_id, session};
use sigma_boring::linear_relation::{LinearRelation, RelationBuilder};
use sigma_boring::{Point, Scalar};

/// The powers `[3^0, 3^1, …, 3^(d-1)]` as scalars. `d <= 80` keeps `3^j` within
/// `u128`.
pub fn pow3_scalars(d: usize) -> Vec<Scalar> {
    (0..d)
        .map(|j| Scalar::from_be_bytes_mod_order(&3u128.pow(j as u32).to_be_bytes()))
        .collect()
}

/// The `d` base-3 digits of `v` (little-endian: index `j` weights `3^j`), each
/// in `{0, 1, 2}`. Digits above `3^d` are dropped, so an out-of-range `v` yields
/// digits that sum to `v mod 3^d` — which fails the consistency equation.
pub fn trits_of(v: u128, d: usize) -> Vec<Scalar> {
    (0..d)
        .map(|j| {
            let digit = (v / 3u128.pow(j as u32)) % 3;
            Scalar::from_u64(digit as u64)
        })
        .collect()
}

/// A base-3 range proof: the per-digit commitments and the compact sigma proof.
/// The committed value `V` is supplied separately to the verifier.
pub struct RangeProof {
    /// Digit commitments `Com[j] = d[j]·H1 + s[j]·H3`.
    pub com: Vec<Point>,
    /// Auxiliary commitments `T[j]`.
    pub t: Vec<Point>,
    /// The compact sigma proof.
    pub pok: Vec<u8>,
}

/// Build the range-proof relation and its canonical statement, shared by prover
/// and verifier. `v_commitment` is `V`; `com`/`t` are the per-digit commitments.
fn range_statement(
    params: &Params,
    v_commitment: &Point,
    com: &[Point],
    t: &[Point],
) -> (LinearRelation, Vec<u8>) {
    let d = com.len();
    let pow3 = pow3_scalars(d);
    let h1 = &params.h1;
    let h3 = &params.h3;

    // Com_total = Σ_j 3^j·Com[j].
    let mut com_total = Point::identity();
    for j in 0..d {
        com_total = com_total.add(&com[j].mul(&pow3[j]));
    }

    let mut b = RelationBuilder::default();
    // Scalars, in witness order: v, r, then d[], s[], rho[], w[].
    let v_id = b.scalar();
    let r_id = b.scalar();
    let d_ids: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let s_ids: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let rho_ids: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let w_ids: Vec<usize> = (0..d).map(|_| b.scalar()).collect();

    // Reusable generator elements.
    let h1_id = b.element(h1.clone());
    let h3_id = b.element(h3.clone());
    let p3h3_ids: Vec<usize> = (0..d).map(|j| b.element(h3.mul(&pow3[j]))).collect();
    let com_ids: Vec<usize> = (0..d).map(|j| b.element(com[j].clone())).collect();
    let t_ids: Vec<usize> = (0..d).map(|j| b.element(t[j].clone())).collect();

    // V = v·H1 + r·H3.
    b.constrain(v_commitment.clone(), &[(v_id, h1_id), (r_id, h3_id)]);

    // Com_total = v·H1 + Σ_j s[j]·(3^j·H3).
    let mut total_terms = vec![(v_id, h1_id)];
    for j in 0..d {
        total_terms.push((s_ids[j], p3h3_ids[j]));
    }
    b.constrain(com_total, &total_terms);

    // Per-digit ternary equations.
    for j in 0..d {
        b.constrain(com[j].clone(), &[(d_ids[j], h1_id), (s_ids[j], h3_id)]);
        let tc = t[j].add(&com[j]); // T[j] + Com[j]
        b.constrain(tc, &[(d_ids[j], com_ids[j]), (rho_ids[j], h3_id)]);
        let t2 = t[j].add(&t[j]); // 2·T[j]
        b.constrain(t2, &[(d_ids[j], t_ids[j]), (w_ids[j], h3_id)]);
    }

    b.build()
}

fn range_session(params: &Params) -> Vec<u8> {
    session(params, b"range", &[])
}

/// Prove that `V = v·H1 + r·H3` opens to `v ∈ [0, 3^d)`. Returns `V` and the
/// proof. Blinders are drawn from BoringSSL's RNG.
pub fn prove_range(params: &Params, v: u128, r: Scalar, d: usize) -> (Point, RangeProof) {
    let digits = trits_of(v, d);
    let one = Scalar::one();
    let two = Scalar::from_u64(2);
    let h1 = &params.h1;
    let h3 = &params.h3;

    let mut s_com = Vec::with_capacity(d);
    let mut rho = Vec::with_capacity(d);
    let mut com = Vec::with_capacity(d);
    let mut t = Vec::with_capacity(d);
    let mut w = Vec::with_capacity(d);
    for j in 0..d {
        let s_j = Scalar::random();
        let rho_j = Scalar::random();
        let com_j = h1.mul(&digits[j]).add(&h3.mul(&s_j));
        // T[j] = (d[j]-1)·Com[j] + rho[j]·H3.
        let t_j = com_j.mul(&digits[j].sub(&one)).add(&h3.mul(&rho_j));
        // w[j] = (2 - d[j])·((d[j]-1)·s[j] + rho[j]).
        let w_j = two
            .sub(&digits[j])
            .mul(&digits[j].sub(&one).mul(&s_j).add(&rho_j));
        s_com.push(s_j);
        rho.push(rho_j);
        com.push(com_j);
        t.push(t_j);
        w.push(w_j);
    }

    let v_scalar = Scalar::from_be_bytes_mod_order(&v.to_be_bytes());
    let v_commitment = h1.mul(&v_scalar).add(&h3.mul(&r));

    let (relation, statement) = range_statement(params, &v_commitment, &com, &t);

    // Witness order matches range_statement's scalar allocation.
    let mut witness = Vec::with_capacity(2 + 4 * d);
    witness.push(v_scalar);
    witness.push(r);
    witness.extend(digits);
    witness.extend(s_com);
    witness.extend(rho);
    witness.extend(w);

    let pok =
        relation.prove_compact(&witness, &act_protocol_id(), &range_session(params), &statement);
    (v_commitment, RangeProof { com, t, pok })
}

/// Verify a base-3 range proof for the committed value `v_commitment`.
pub fn verify_range(
    params: &Params,
    v_commitment: &Point,
    proof: &RangeProof,
    d: usize,
) -> bool {
    if proof.com.len() != d || proof.t.len() != d {
        return false;
    }
    let (relation, statement) = range_statement(params, v_commitment, &proof.com, &proof.t);
    relation
        .verify_compact(&act_protocol_id(), &range_session(params), &statement, &proof.pok)
        .unwrap_or(false)
}
