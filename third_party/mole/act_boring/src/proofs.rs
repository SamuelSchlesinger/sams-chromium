// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The ACT proofs of knowledge, expressed over `sigma_boring`'s
//! `RelationBuilder` (P-256/BoringSSL). Ported from `anonymous-credit-tokens`'s
//! `proofs` module — the same Pedersen and Chaum–Pedersen (DLEQ) relations,
//! built via the canonical linear-relation encoding rather than the
//! ristretto255 `sigma_proofs::LinearRelation`.

use crate::params::Params;
use sigma_boring::linear_relation::{LinearRelation, RelationBuilder};
use sigma_boring::{Point, Scalar};

/// The ACT(P-256, SHAKE128) Fiat–Shamir protocol identifier, zero-padded to the
/// 64 bytes the transform requires. The P-256 analogue of the reference's
/// ristretto255 label; ACT defines its own since the Fiat–Shamir draft
/// standardizes no ciphersuite here.
pub fn act_protocol_id() -> [u8; 64] {
    const LABEL: &[u8] = b"ACT-v1_SchnorrProof_Shake128_P256";
    let mut id = [0u8; 64];
    id[..LABEL.len()].copy_from_slice(LABEL);
    id
}

/// The shared ACT(P-256) request-context scalar for a policy, derived from the
/// policy context and epoch. Deterministic and injective (both fields
/// length-prefixed), so every client and the issuer agree on it under the same
/// policy — the P-256 analogue of mole-core's ristretto `request_context_scalar`
/// (a distinct suite, so a distinct value; both sides here use this one).
pub fn request_context_scalar(policy_context: &[u8], epoch: &[u8]) -> Scalar {
    const DST: &[u8] = b"MoLE-ACT-P256:request-context:v1";
    let pc_len = (policy_context.len() as u64).to_be_bytes();
    let ep_len = (epoch.len() as u64).to_be_bytes();
    Scalar::hash_to_scalar(DST, &[&pc_len, policy_context, &ep_len, epoch])
}

/// Build a session identifier from the domain separator, a label, and
/// protocol-bound scalars — the reference's `session`, with P-256 scalars
/// encoded as fixed 32-byte big-endian.
pub fn session(params: &Params, label: &[u8], scalars: &[&Scalar]) -> Vec<u8> {
    let mut out = params.domain_separator().to_vec();
    out.extend_from_slice(label);
    for s in scalars {
        out.extend_from_slice(&s.to_bytes());
    }
    out
}

/// `Pedersen(P, Q, R) = PoK{ (k0, k1) : R = k0·P + k1·Q }`. Returns the
/// relation and its canonical statement label; the witness order is `[k0, k1]`.
pub fn pedersen(p: Point, q: Point, r: Point) -> (LinearRelation, Vec<u8>) {
    let mut b = RelationBuilder::default();
    let k0 = b.scalar();
    let k1 = b.scalar();
    let p_var = b.element(p);
    let q_var = b.element(q);
    b.constrain(r, &[(k0, p_var), (k1, q_var)]);
    b.build()
}

/// `DLEQ(P, Q, X, Y) = PoK{ k : X = k·P, Y = k·Q }`. Returns the relation and
/// its canonical statement label; the witness is `[k]`.
pub fn dleq(p: Point, q: Point, x: Point, y: Point) -> (LinearRelation, Vec<u8>) {
    let mut b = RelationBuilder::default();
    let k = b.scalar();
    let p_var = b.element(p);
    let q_var = b.element(q);
    b.constrain(x, &[(k, p_var)]);
    b.constrain(y, &[(k, q_var)]);
    b.build()
}
