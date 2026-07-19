// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! ACT(P-256) issuance: the two-message exchange that turns a client's blinded
//! commitment into a `CreditToken` carrying `c` credits, ported from
//! `anonymous-credit-tokens` onto `sigma_boring`/BoringSSL. The client proves a
//! Pedersen PoK over its commitment; the issuer replies with a BBS-style
//! signature and a DLEQ proof of correct issuance; the client verifies and
//! unblinds. Randomness is drawn internally from BoringSSL's RNG.
//!
//! Secret-zeroization (the reference's `ZeroizeOnDrop`) is deferred — a
//! hardening pass for the full port, tracked with the EC_SCALAR work.

use crate::params::Params;
use crate::proofs::{act_protocol_id, dleq, pedersen, session};
use sigma_boring::{Point, Scalar};

/// An ACT protocol error.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The client's issuance-request proof did not verify.
    InvalidIssuanceRequestProof,
    /// The issuer's issuance-response proof did not verify.
    InvalidIssuanceResponseProof,
    /// The requested credit amount exceeds `3^D - 1`.
    AmountTooBig,
    /// A spend/top-up amount is out of range, or the balance can't cover it.
    InvalidAmount,
    /// The client's spend proof did not verify.
    InvalidSpendProof,
    /// The issuer's return amount `t` exceeds `s + a`, or the new balance would
    /// overflow the ceiling.
    InvalidRefundAmount,
    /// The issuer's refund proof did not verify.
    InvalidRefundProof,
}

/// The issuer's public key `W = x·G`.
#[derive(Clone)]
pub struct PublicKey {
    /// The public point.
    pub w: Point,
}

/// The issuer's private key.
pub struct PrivateKey {
    x: Scalar,
    public: PublicKey,
}

impl PrivateKey {
    /// A fresh random issuer key.
    pub fn random() -> Self {
        let x = Scalar::random();
        let w = Point::generator().mul(&x);
        PrivateKey { x, public: PublicKey { w } }
    }

    /// The corresponding public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The issuer secret scalar `x`. Crate-internal: used by spend/refund
    /// verification to form `A_bar = A'·x`.
    pub(crate) fn secret(&self) -> &Scalar {
        &self.x
    }
}

/// Client issuance state: the blinding factor `r` and token identifier `k`.
pub struct PreIssuance {
    r: Scalar,
    k: Scalar,
}

/// Client → Issuer: the commitment `big_K = k·H2 + r·H3` and a Pedersen PoK of
/// `(k, r)`.
pub struct IssuanceRequest {
    /// Commitment to the client's identifier and blinding factor.
    pub big_k: Point,
    /// Compact proof of knowledge of `(k, r)`.
    pub pok: Vec<u8>,
}

/// Issuer → Client: the BBS-style signature `(A, e)` on `c`, and a DLEQ proof of
/// correct issuance.
pub struct IssuanceResponse {
    /// Signature component `A`.
    pub a: Point,
    /// Signature scalar `e`.
    pub e: Scalar,
    /// Issued credit amount.
    pub c: Scalar,
    /// Compact DLEQ proof of correct issuance.
    pub pok: Vec<u8>,
}

/// A finished credit token: the client's spendable credential. All fields are
/// the BBS-signature and blinding state the (not-yet-ported) spend operation
/// consumes; only `c` is read so far, hence the allow.
#[allow(dead_code)]
pub struct CreditToken {
    pub(crate) a: Point,
    pub(crate) e: Scalar,
    pub(crate) k: Scalar,
    pub(crate) r: Scalar,
    pub(crate) c: Scalar,
    pub(crate) ctx: Scalar,
}

impl CreditToken {
    /// The token's credit balance.
    pub fn credits(&self) -> &Scalar {
        &self.c
    }
}

impl PreIssuance {
    /// Fresh client issuance state.
    pub fn random() -> Self {
        PreIssuance { r: Scalar::random(), k: Scalar::random() }
    }

    /// **Request** (Client → Issuer): commit `big_K = k·H2 + r·H3` and prove
    /// knowledge of `(k, r)`.
    pub fn request(&self, params: &Params) -> IssuanceRequest {
        let big_k = params.h2.mul(&self.k).add(&params.h3.mul(&self.r));
        let (relation, statement) =
            pedersen(params.h2.clone(), params.h3.clone(), big_k.clone());
        let sess = session(params, b"request", &[]);
        let pok = relation.prove_compact(
            &[self.k.clone(), self.r.clone()],
            &act_protocol_id(),
            &sess,
            &statement,
        );
        IssuanceRequest { big_k, pok }
    }

    /// **Finalize** (Client, local): verify the issuer's DLEQ proof and, if
    /// valid, unblind into a [`CreditToken`] bound to `ctx`.
    pub fn to_credit_token(
        &self,
        params: &Params,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
        ctx: Scalar,
    ) -> Result<CreditToken, Error> {
        let g = Point::generator();
        // X_A = G + c·H1 + ctx·H4 + big_K ; X_G = e·G + W.
        let x_a = g
            .add(&params.h1.mul(&response.c))
            .add(&params.h4.mul(&ctx))
            .add(&request.big_k);
        let x_g = g.mul(&response.e).add(&public.w);

        let (relation, statement) =
            dleq(response.a.clone(), g.clone(), x_a, x_g);
        let sess = session(params, b"respond", &[&response.c, &ctx]);
        match relation.verify_compact(&act_protocol_id(), &sess, &statement, &response.pok) {
            Ok(true) => {}
            _ => return Err(Error::InvalidIssuanceResponseProof),
        }

        Ok(CreditToken {
            a: response.a.clone(),
            e: response.e.clone(),
            k: self.k.clone(),
            r: self.r.clone(),
            c: response.c.clone(),
            ctx,
        })
    }
}

impl PrivateKey {
    /// **Issue** (Issuer): verify the client's request PoK, then sign `c`
    /// credits into a BBS-style `(A, e)` and prove correct issuance via DLEQ.
    /// `D` is the base-3 digit count bounding credits to `[0, 3^D)`.
    pub fn issue<const D: usize>(
        &self,
        params: &Params,
        request: &IssuanceRequest,
        c: u128,
        ctx: Scalar,
    ) -> Result<IssuanceResponse, Error> {
        assert!(D >= 1 && D <= 80, "D must be in 1..=80");
        let max_credits = 3u128.pow(D as u32) - 1;
        if c > max_credits {
            return Err(Error::AmountTooBig);
        }
        let c = Scalar::from_be_bytes_mod_order(&c.to_be_bytes());

        // Verify the client's Pedersen PoK on big_K.
        let (relation, statement) =
            pedersen(params.h2.clone(), params.h3.clone(), request.big_k.clone());
        let sess = session(params, b"request", &[]);
        match relation.verify_compact(&act_protocol_id(), &sess, &statement, &request.pok) {
            Ok(true) => {}
            _ => return Err(Error::InvalidIssuanceRequestProof),
        }

        // BBS-style signature: A = (G + c·H1 + ctx·H4 + big_K)·(e+x)⁻¹.
        let g = Point::generator();
        let e = Scalar::random();
        let exp = e.add(&self.x);
        let x_a = g
            .add(&params.h1.mul(&c))
            .add(&params.h4.mul(&ctx))
            .add(&request.big_k);
        let a = x_a.mul(&exp.invert().expect("e + x is nonzero (negligible failure)"));
        let x_g = g.mul(&exp);

        // DLEQ proof: X_A = exp·A and X_G = exp·G.
        let (relation, statement) = dleq(a.clone(), g.clone(), x_a, x_g);
        let sess = session(params, b"respond", &[&c, &ctx]);
        let pok = relation.prove_compact(&[exp], &act_protocol_id(), &sess, &statement);

        Ok(IssuanceResponse { a, e, c, pok })
    }
}
