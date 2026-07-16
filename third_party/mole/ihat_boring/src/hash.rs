// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The IHAT domain-separated hashes on `sigma_boring`, ported from `ihat-rs`
//! `hash.rs`. Points are hashed to the curve via RFC 9380
//! `P256_XMD:SHA-256_SSWU_RO_`; scalars via RFC 9380 hash-to-field, both over
//! Chromium's BoringSSL (differential-tested against the `p256` crate in
//! `sigma_boring`). Every transcript is length-prefixed so the encoding is
//! injective, matching the reference byte-for-byte.

use sigma_boring::{Point, Scalar};

/// `H₁`: nullifier bytes → group element (the issuance input `Y`).
const DST_H1: &[u8] = b"MOLE-IHAT-P256:H1-nullifier-to-group:v1";
/// `H`: endorsement-context bytes → the context-bound Pedersen generator.
const DST_H: &[u8] = b"MOLE-IHAT-P256:pedersen-generator-H:v1";
/// The issuance (GetEnd) Fiat–Shamir challenge domain.
const DST_FS: &[u8] = b"MOLE-IHAT-P256:fiat-shamir-getend:v1";
/// The redemption OR-proof Fiat–Shamir challenge domain.
const DST_OR: &[u8] = b"MOLE-IHAT-P256:fiat-shamir-or-proof:v1";

/// `Y = H₁(nf)`: hash the nullifier to a group element.
pub(crate) fn hash_nullifier(nf: &[u8]) -> Point {
    Point::hash_to_curve(nf, DST_H1)
}

/// `H = H(endorsement_context)`: the context-bound Pedersen generator.
pub(crate) fn pedersen_generator(endorsement_context: &[u8]) -> Point {
    Point::hash_to_curve(endorsement_context, DST_H)
}

/// The issuance Fiat–Shamir challenge `e = H_FS(X_hat, Y, Z_hat, T₁, T₂, C,
/// ctx)`. Six fixed-width points in order, then the length-prefixed context.
pub(crate) fn fiat_shamir(
    x_hat: &Point,
    y: &Point,
    z_hat: &Point,
    t1: &Point,
    t2: &Point,
    c: &Point,
    endorsement_context: &[u8],
) -> Scalar {
    let pts = [
        x_hat.to_bytes(),
        y.to_bytes(),
        z_hat.to_bytes(),
        t1.to_bytes(),
        t2.to_bytes(),
        c.to_bytes(),
    ];
    let ctx_len = (endorsement_context.len() as u64).to_le_bytes();
    let mut refs: Vec<&[u8]> = pts.iter().map(|p| p.as_slice()).collect();
    refs.push(&ctx_len);
    refs.push(endorsement_context);
    Scalar::hash_to_scalar(DST_FS, &refs)
}

/// The redemption OR-proof Fiat–Shamir challenge, hashing the accepted anchor
/// keys, the rerandomised key `X_hat`, the OR commitments, and the caller
/// `binding`. Each variable-count group and the binding are length-prefixed
/// (u64-LE), so the transcript is injective. Matches `ihat-rs`
/// `hash::fiat_shamir_or`.
pub(crate) fn fiat_shamir_or(
    accepted: &[Point],
    x_hat: &Point,
    commitments: &[Point],
    binding: &[u8],
) -> Scalar {
    let n_acc = (accepted.len() as u64).to_le_bytes();
    let n_com = (commitments.len() as u64).to_le_bytes();
    let acc: Vec<[u8; 33]> = accepted.iter().map(|p| p.to_bytes()).collect();
    let com: Vec<[u8; 33]> = commitments.iter().map(|p| p.to_bytes()).collect();
    let xh = x_hat.to_bytes();
    let binding_len = (binding.len() as u64).to_le_bytes();

    let mut refs: Vec<&[u8]> = Vec::with_capacity(acc.len() + com.len() + 5);
    refs.push(&n_acc);
    refs.extend(acc.iter().map(|p| p.as_slice()));
    refs.push(&xh);
    refs.push(&n_com);
    refs.extend(com.iter().map(|p| p.as_slice()));
    refs.push(&binding_len);
    refs.push(binding);
    Scalar::hash_to_scalar(DST_OR, &refs)
}
