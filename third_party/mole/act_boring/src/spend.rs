// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! ACT spend on `sigma_boring`/BoringSSL, ported from
//! `anonymous-credit-tokens`. A spend proves, in zero knowledge, that the
//! client holds a valid credit token whose balance covers the spend
//! (`c - s ∈ [0, 3^d)`) and leaves room for the declared top-up
//! (`c + a ∈ [0, 3^d)`), and reveals a nullifier to prevent double-spending.
//!
//! The proof is a single sigma protocol of `6d + 5` equations over `8d + 7`
//! witnesses: two BBS signature-validity equations, two base-3 range proofs
//! (the [`crate::range`] machinery, inlined here so both share the balance
//! witness `c`), a nullifier-commitment opening, and two consistency equations
//! binding `v1 = c - s` and `v2 = c + a` to the digit decompositions.
//!
//! This ports `prove_spend` (client) and the spend-proof verification embedded
//! in the reference's `refund` (issuer). Refund issuance (the new-balance BBS
//! signature) is the next increment.

use crate::issuance::{CreditToken, Error, PrivateKey, PublicKey};
use crate::params::Params;
use crate::proofs::{act_protocol_id, dleq, session};
use crate::range::{pow3_scalars, trits_of};
use sigma_boring::linear_relation::{LinearRelation, RelationBuilder};
use sigma_boring::{Point, Scalar};

/// Decode a scalar's canonical encoding as a `u128`, or `None` if it does not
/// fit (the top 16 bytes are nonzero). Used to validate public spend amounts.
pub fn scalar_to_u128(s: &Scalar) -> Option<u128> {
    let bytes = s.to_bytes(); // 32-byte big-endian
    if bytes[..16].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&bytes[16..]);
    Some(u128::from_be_bytes(low))
}

fn scalar_from_u128(v: u128) -> Scalar {
    Scalar::from_be_bytes_mod_order(&v.to_be_bytes())
}

/// A spend proof: public amounts and nullifier, the randomized signature, both
/// range-proof digit/aux commitments, the new-token nullifier commitment, and
/// the compact sigma proof.
pub struct SpendProof {
    /// Nullifier of the spent token.
    pub k: Scalar,
    /// Public spend amount.
    pub s: Scalar,
    /// Public top-up amount.
    pub a: Scalar,
    /// Request context.
    pub ctx: Scalar,
    /// Blinded signature component `A'`.
    pub a_prime: Point,
    /// Blinded token component `B_bar`.
    pub b_bar: Point,
    /// Digit commitments for `v1 = c - s`.
    pub com1: Vec<Point>,
    /// Auxiliary commitments for the first range proof.
    pub t1: Vec<Point>,
    /// Digit commitments for `v2 = c + a`.
    pub com2: Vec<Point>,
    /// Auxiliary commitments for the second range proof.
    pub t2: Vec<Point>,
    /// New-token nullifier commitment `K_n = k*·H2 + rn·H3`.
    pub k_n: Point,
    /// The compact sigma proof.
    pub pok: Vec<u8>,
}

/// Client state kept after a spend, to build the new token once the issuer's
/// refund arrives.
pub struct PreRefund {
    pub(crate) k: Scalar,
    pub(crate) r: Scalar,
    pub(crate) v: Scalar,
    pub(crate) ctx: Scalar,
}

/// The issuer's refund response: a BBS-style signature on the new balance and a
/// DLEQ proof of correct issuance.
pub struct Refund {
    /// Signature component `A*`.
    pub a: Point,
    /// Signature scalar `e*`.
    pub e: Scalar,
    /// The issuer-chosen return amount added to the post-spend balance.
    pub t: Scalar,
    /// Compact DLEQ proof of correct refund issuance.
    pub pok: Vec<u8>,
}

/// Build the spend relation and its canonical statement, shared by prover and
/// verifier. `a_bar = A'·x` is supplied (the prover derives it from the
/// randomizers, the verifier from its secret key).
#[allow(clippy::too_many_arguments)]
fn spend_statement(
    params: &Params,
    k: &Scalar,
    s: &Scalar,
    a: &Scalar,
    ctx: &Scalar,
    a_prime: &Point,
    b_bar: &Point,
    a_bar: &Point,
    com1: &[Point],
    t1: &[Point],
    com2: &[Point],
    t2: &[Point],
    k_n: &Point,
) -> (LinearRelation, Vec<u8>) {
    let d = com1.len();
    let pow3 = pow3_scalars(d);
    let g = Point::generator();
    let (h1, h2, h3, h4) = (&params.h1, &params.h2, &params.h3, &params.h4);

    // Public derived points.
    let neg_a_prime = a_prime.negate();
    let neg_h1 = h1.negate();
    let neg_h3 = h3.negate();
    let h1_prime = g.add(&h2.mul(k)).add(&h4.mul(ctx)); // G + k·H2 + ctx·H4
    let com_total1 = {
        let mut acc = h1.mul(s); // s·H1 + Σ 3^j·Com1[j]
        for j in 0..d {
            acc = acc.add(&com1[j].mul(&pow3[j]));
        }
        acc
    };
    let com_total2 = {
        let mut acc = h1.mul(&a.negate()); // (-a)·H1 + Σ 3^j·Com2[j]
        for j in 0..d {
            acc = acc.add(&com2[j].mul(&pow3[j]));
        }
        acc
    };

    let mut b = RelationBuilder::default();
    // Scalars, in witness order.
    let e_id = b.scalar();
    let r2_id = b.scalar();
    let r3_id = b.scalar();
    let c_id = b.scalar();
    let r_id = b.scalar();
    let d1: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let s1: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let rho1: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let w1: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let d2: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let s2: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let rho2: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let w2: Vec<usize> = (0..d).map(|_| b.scalar()).collect();
    let kstar_id = b.scalar();
    let rn_id = b.scalar();

    // Term elements.
    let neg_ap_id = b.element(neg_a_prime);
    let bbar_id = b.element(b_bar.clone());
    let neg_h1_id = b.element(neg_h1);
    let neg_h3_id = b.element(neg_h3);
    let h1_id = b.element(h1.clone());
    let h2_id = b.element(h2.clone());
    let h3_id = b.element(h3.clone());
    let p3h3: Vec<usize> = (0..d).map(|j| b.element(h3.mul(&pow3[j]))).collect();
    let com1_id: Vec<usize> = (0..d).map(|j| b.element(com1[j].clone())).collect();
    let t1_id: Vec<usize> = (0..d).map(|j| b.element(t1[j].clone())).collect();
    let com2_id: Vec<usize> = (0..d).map(|j| b.element(com2[j].clone())).collect();
    let t2_id: Vec<usize> = (0..d).map(|j| b.element(t2[j].clone())).collect();

    // Eq 1: A_bar = e·(-A') + r2·B_bar.
    b.constrain(a_bar.clone(), &[(e_id, neg_ap_id), (r2_id, bbar_id)]);
    // Eq 2: H1' = r3·B_bar + c·(-H1) + r·(-H3).
    b.constrain(h1_prime, &[(r3_id, bbar_id), (c_id, neg_h1_id), (r_id, neg_h3_id)]);

    // Range proof over v1 = c - s.
    for j in 0..d {
        b.constrain(com1[j].clone(), &[(d1[j], h1_id), (s1[j], h3_id)]);
        b.constrain(t1[j].add(&com1[j]), &[(d1[j], com1_id[j]), (rho1[j], h3_id)]);
        b.constrain(t1[j].add(&t1[j]), &[(d1[j], t1_id[j]), (w1[j], h3_id)]);
    }
    // Range proof over v2 = c + a.
    for j in 0..d {
        b.constrain(com2[j].clone(), &[(d2[j], h1_id), (s2[j], h3_id)]);
        b.constrain(t2[j].add(&com2[j]), &[(d2[j], com2_id[j]), (rho2[j], h3_id)]);
        b.constrain(t2[j].add(&t2[j]), &[(d2[j], t2_id[j]), (w2[j], h3_id)]);
    }
    // Nullifier commitment: K_n = k*·H2 + rn·H3.
    b.constrain(k_n.clone(), &[(kstar_id, h2_id), (rn_id, h3_id)]);
    // Consistency: Com_total1 = c·H1 + Σ s1[j]·(3^j·H3) (so v1 = c - s).
    let mut c1 = vec![(c_id, h1_id)];
    for j in 0..d {
        c1.push((s1[j], p3h3[j]));
    }
    b.constrain(com_total1, &c1);
    // Consistency: Com_total2 = c·H1 + Σ s2[j]·(3^j·H3) (so v2 = c + a).
    let mut c2 = vec![(c_id, h1_id)];
    for j in 0..d {
        c2.push((s2[j], p3h3[j]));
    }
    b.constrain(com_total2, &c2);

    b.build()
}

fn spend_session(params: &Params, sp_k: &Scalar, s: &Scalar, a: &Scalar, ctx: &Scalar) -> Vec<u8> {
    session(params, b"spend", &[sp_k, s, a, ctx])
}

/// Per-decomposition digit and auxiliary commitments and the zero-constraint
/// witnesses, for a value's base-3 digits.
struct Decomposition {
    s_com: Vec<Scalar>,
    rho: Vec<Scalar>,
    com: Vec<Point>,
    t: Vec<Point>,
    w: Vec<Scalar>,
}

fn commit_digits(params: &Params, digits: &[Scalar]) -> Decomposition {
    let one = Scalar::one();
    let two = Scalar::from_u64(2);
    let (h1, h3) = (&params.h1, &params.h3);
    let d = digits.len();
    let mut out = Decomposition {
        s_com: Vec::with_capacity(d),
        rho: Vec::with_capacity(d),
        com: Vec::with_capacity(d),
        t: Vec::with_capacity(d),
        w: Vec::with_capacity(d),
    };
    for dj in digits {
        let s_j = Scalar::random();
        let rho_j = Scalar::random();
        let com_j = h1.mul(dj).add(&h3.mul(&s_j));
        // T[j] = (d[j]-1)·Com[j] + rho[j]·H3.
        let t_j = com_j.mul(&dj.sub(&one)).add(&h3.mul(&rho_j));
        // w[j] = (2 - d[j])·((d[j]-1)·s[j] + rho[j]).
        let w_j = two.sub(dj).mul(&dj.sub(&one).mul(&s_j).add(&rho_j));
        out.s_com.push(s_j);
        out.rho.push(rho_j);
        out.com.push(com_j);
        out.t.push(t_j);
        out.w.push(w_j);
    }
    out
}

/// **Prove spend** (Client): spend `s` credits from `token`, declaring top-up
/// `a`, with `d` base-3 digits. Returns the spend proof and the refund state.
pub fn prove_spend(
    token: &CreditToken,
    params: &Params,
    s: u128,
    a: u128,
    d: usize,
) -> Result<(SpendProof, PreRefund), Error> {
    let max_credits = 3u128.pow(d as u32) - 1;
    if s > max_credits || a > max_credits {
        return Err(Error::InvalidAmount);
    }
    let c = scalar_to_u128(&token.c).ok_or(Error::InvalidAmount)?;
    let v1 = c.checked_sub(s).ok_or(Error::InvalidAmount)?;
    let v2 = c.checked_add(a).ok_or(Error::InvalidAmount)?;
    if v2 > max_credits {
        return Err(Error::InvalidAmount);
    }
    let digits1 = trits_of(v1, d);
    let digits2 = trits_of(v2, d);
    let pow3 = pow3_scalars(d);

    let (h1, h2, h3, h4) = (&params.h1, &params.h2, &params.h3, &params.h4);
    let s_scalar = scalar_from_u128(s);
    let a_scalar = scalar_from_u128(a);

    // Randomize the BBS signature.
    let r1 = Scalar::random();
    let r2 = Scalar::random();
    let b_pt = Point::generator()
        .add(&h1.mul(&token.c))
        .add(&h2.mul(&token.k))
        .add(&h3.mul(&token.r))
        .add(&h4.mul(&token.ctx));
    let a_prime = token.a.mul(&r1.mul(&r2));
    let b_bar = b_pt.mul(&r1);
    let r3 = r1.invert().expect("r1 is nonzero (negligible failure)");
    // A_bar = r2·B_bar - e·A'.
    let a_bar = b_bar.mul(&r2).add(&a_prime.mul(&token.e).negate());

    let dec1 = commit_digits(params, &digits1);
    let dec2 = commit_digits(params, &digits2);

    // New-token nullifier commitment.
    let k_star = Scalar::random();
    let rn = Scalar::random();
    let k_n = h2.mul(&k_star).add(&h3.mul(&rn));

    let (relation, statement) = spend_statement(
        params, &token.k, &s_scalar, &a_scalar, &token.ctx, &a_prime, &b_bar, &a_bar, &dec1.com,
        &dec1.t, &dec2.com, &dec2.t, &k_n,
    );

    let mut witness = Vec::with_capacity(8 * d + 7);
    witness.push(token.e.clone());
    witness.push(r2);
    witness.push(r3);
    witness.push(token.c.clone());
    witness.push(token.r.clone());
    witness.extend(digits1.iter().cloned());
    witness.extend(dec1.s_com.iter().cloned());
    witness.extend(dec1.rho.iter().cloned());
    witness.extend(dec1.w.iter().cloned());
    witness.extend(digits2.iter().cloned());
    witness.extend(dec2.s_com.iter().cloned());
    witness.extend(dec2.rho.iter().cloned());
    witness.extend(dec2.w.iter().cloned());
    witness.push(k_star.clone());
    witness.push(rn.clone());

    let sess = spend_session(params, &token.k, &s_scalar, &a_scalar, &token.ctx);
    let pok = relation.prove_compact(&witness, &act_protocol_id(), &sess, &statement);

    // Refund state: K' = K_n + Σ 3^j·Com1[j] opens to (v1, r_star).
    let mut r_star = rn;
    for j in 0..d {
        r_star = r_star.add(&dec1.s_com[j].mul(&pow3[j]));
    }
    let prerefund = PreRefund {
        k: k_star,
        r: r_star,
        v: scalar_from_u128(v1),
        ctx: token.ctx.clone(),
    };

    Ok((
        SpendProof {
            k: token.k.clone(),
            s: s_scalar,
            a: a_scalar,
            ctx: token.ctx.clone(),
            a_prime,
            b_bar,
            com1: dec1.com,
            t1: dec1.t,
            com2: dec2.com,
            t2: dec2.t,
            k_n,
            pok,
        },
        prerefund,
    ))
}

impl PrivateKey {
    /// **Verify spend** (Issuer): validate the public amounts and the spend
    /// proof against this issuer's key. `d` is the base-3 digit count.
    pub fn verify_spend(&self, params: &Params, sp: &SpendProof, d: usize) -> bool {
        if sp.a_prime.is_identity() {
            return false;
        }
        let (s, a) = match (scalar_to_u128(&sp.s), scalar_to_u128(&sp.a)) {
            (Some(s), Some(a)) => (s, a),
            _ => return false,
        };
        let max_credits = 3u128.pow(d as u32) - 1;
        if s > max_credits || a > max_credits {
            return false;
        }
        if sp.com1.len() != d || sp.t1.len() != d || sp.com2.len() != d || sp.t2.len() != d {
            return false;
        }

        // A_bar = A'·x (only the issuer can form this).
        let a_bar = sp.a_prime.mul(self.secret());
        let (relation, statement) = spend_statement(
            params, &sp.k, &sp.s, &sp.a, &sp.ctx, &sp.a_prime, &sp.b_bar, &a_bar, &sp.com1,
            &sp.t1, &sp.com2, &sp.t2, &sp.k_n,
        );
        let sess = spend_session(params, &sp.k, &sp.s, &sp.a, &sp.ctx);
        relation
            .verify_compact(&act_protocol_id(), &sess, &statement, &sp.pok)
            .unwrap_or(false)
    }

    /// **Refund** (Issuer): verify the spend proof, then issue a refund for the
    /// post-spend balance `v1 = c - s`, homomorphically adding the return amount
    /// `t ∈ [0, s + a]`. The client turns this into a new token with balance
    /// `c - s + t`. `d` is the base-3 digit count.
    pub fn refund(
        &self,
        params: &Params,
        sp: &SpendProof,
        t: u128,
        d: usize,
    ) -> Result<Refund, Error> {
        if !self.verify_spend(params, sp, d) {
            return Err(Error::InvalidSpendProof);
        }
        let s = scalar_to_u128(&sp.s).ok_or(Error::InvalidAmount)?;
        let a = scalar_to_u128(&sp.a).ok_or(Error::InvalidAmount)?;
        if t > s + a {
            return Err(Error::InvalidRefundAmount);
        }
        let t_scalar = scalar_from_u128(t);

        let g = Point::generator();
        let (h1, h4) = (&params.h1, &params.h4);
        // K' = K_n + Σ 3^j·Com1[j]: commits to v1 = c - s and the new nullifier.
        let k_prime = k_prime_commitment(sp, d);

        let e_star = Scalar::random();
        let exp = e_star.add(self.secret());
        let x_a_star = g
            .add(&k_prime)
            .add(&h1.mul(&t_scalar))
            .add(&h4.mul(&sp.ctx));
        let a_star = x_a_star.mul(&exp.invert().expect("e* + x nonzero (negligible)"));
        let x_g = g.mul(&exp);

        let (relation, statement) = dleq(a_star.clone(), g.clone(), x_a_star, x_g);
        let sess = session(params, b"refund", &[&e_star, &t_scalar, &sp.ctx]);
        let pok = relation.prove_compact(&[exp], &act_protocol_id(), &sess, &statement);

        Ok(Refund { a: a_star, e: e_star, t: t_scalar, pok })
    }
}

/// `K' = K_n + Σ_j 3^j·Com1[j]`: the commitment to the post-spend balance and
/// the new-token nullifier, reconstructed by both issuer and client.
fn k_prime_commitment(sp: &SpendProof, d: usize) -> Point {
    let pow3 = pow3_scalars(d);
    let mut acc = sp.k_n.clone();
    for j in 0..d {
        acc = acc.add(&sp.com1[j].mul(&pow3[j]));
    }
    acc
}

impl PreRefund {
    /// **Finalize refund** (Client): verify the issuer's DLEQ proof and, if
    /// valid, build the new [`CreditToken`] with balance `v1 + t`. Reconstructs
    /// against the context bound in this state, so pairing with a mismatched
    /// spend proof or refund fails rather than minting an unspendable token.
    pub fn to_credit_token(
        &self,
        params: &Params,
        sp: &SpendProof,
        refund: &Refund,
        public: &PublicKey,
    ) -> Result<CreditToken, Error> {
        let t = scalar_to_u128(&refund.t).ok_or(Error::InvalidAmount)?;
        let s = scalar_to_u128(&sp.s).ok_or(Error::InvalidAmount)?;
        let a = scalar_to_u128(&sp.a).ok_or(Error::InvalidAmount)?;
        if t > s + a {
            return Err(Error::InvalidRefundAmount);
        }
        let v = scalar_to_u128(&self.v).ok_or(Error::InvalidAmount)?;
        let d = sp.com1.len();
        let max_credits = 3u128.pow(d as u32) - 1;
        match v.checked_add(t) {
            Some(vt) if vt <= max_credits => {}
            _ => return Err(Error::InvalidRefundAmount),
        }

        let g = Point::generator();
        let (h1, h4) = (&params.h1, &params.h4);
        let k_prime = k_prime_commitment(sp, d);
        let x_a = g
            .add(&k_prime)
            .add(&h1.mul(&refund.t))
            .add(&h4.mul(&self.ctx));
        let x_g = g.mul(&refund.e).add(&public.w);

        let (relation, statement) = dleq(refund.a.clone(), g.clone(), x_a, x_g);
        let sess = session(params, b"refund", &[&refund.e, &refund.t, &self.ctx]);
        match relation.verify_compact(&act_protocol_id(), &sess, &statement, &refund.pok) {
            Ok(true) => {}
            _ => return Err(Error::InvalidRefundProof),
        }

        Ok(CreditToken {
            a: refund.a.clone(),
            e: refund.e.clone(),
            k: self.k.clone(),
            r: self.r.clone(),
            c: self.v.add(&refund.t), // new balance v1 + t
            ctx: self.ctx.clone(),
        })
    }
}
