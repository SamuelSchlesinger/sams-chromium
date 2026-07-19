// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! ACT(P-256, SHAKE128) public parameters: the generator basis and the
//! Fiat–Shamir framing, ported from `anonymous-credit-tokens` (which is over
//! ristretto255) onto `sigma_boring`/BoringSSL P-256. BoringSSL exposes P-256
//! but not ristretto255, so ACT on BoringSSL is a *new* ciphersuite — a P-256
//! instantiation of the same scheme, not a byte-for-byte reproduction. Its
//! generators, protocol identifier, and session encoding are defined here.

use sigma_boring::{Point, POINT_BYTES};

/// System parameters: four independent generators `H1..H4` with no known
/// discrete-log relations, derived deterministically from a domain separator.
/// (`H1` binds credit values, `H2` nullifiers, `H3` blinders, `H4` the request
/// context — the same roles as the reference.)
#[derive(Clone)]
pub struct Params {
    domain_separator: Vec<u8>,
    /// Credit-value generator.
    pub h1: Point,
    /// Nullifier generator.
    pub h2: Point,
    /// Blinding-factor generator.
    pub h3: Point,
    /// Request-context generator.
    pub h4: Point,
}

impl Params {
    /// Derive parameters from a raw domain separator — the ACT(P-256)
    /// `SetGenerators`. `H1..H4` come from independent RFC 9380 hash-to-curve
    /// evaluations (`P256_XMD:SHA-256_SSWU_RO_`), re-derived with an incremented
    /// counter in the (cryptographically unreachable) event that any two — or
    /// any and the base point — collide. The structure mirrors the reference so
    /// the P-256 suite is a faithful re-instantiation.
    ///
    /// # Panics
    /// If `domain_separator` is empty (the spec forbids it).
    pub fn from_domain_separator(domain_separator: &[u8]) -> Self {
        assert!(
            !domain_separator.is_empty(),
            "domain separator must be non-empty"
        );
        let dst = [b"HashToGroup-".as_slice(), domain_separator].concat();
        let g0 = Point::generator();
        let mut h = [
            Point::generator(),
            Point::generator(),
            Point::generator(),
            Point::generator(),
        ];
        let mut counter: u32 = 0;
        loop {
            // Distinct iff the base point and the four candidates have five
            // distinct compressed encodings.
            let mut encodings: Vec<[u8; POINT_BYTES]> =
                Vec::with_capacity(5);
            encodings.push(g0.to_bytes());
            for p in h.iter() {
                encodings.push(p.to_bytes());
            }
            encodings.sort_unstable();
            encodings.dedup();
            if encodings.len() == 5 {
                break;
            }
            assert!(counter <= 255, "generator derivation failed");
            let ctr = [counter as u8];
            h[0] = Point::hash_to_curve(
                &[b"GenH1".as_slice(), &ctr, domain_separator].concat(),
                &dst,
            );
            h[1] = Point::hash_to_curve(
                &[b"GenH2".as_slice(), &ctr, domain_separator].concat(),
                &dst,
            );
            h[2] = Point::hash_to_curve(
                &[b"GenH3".as_slice(), &ctr, domain_separator].concat(),
                &dst,
            );
            h[3] = Point::hash_to_curve(
                &[b"GenH4".as_slice(), &ctr, domain_separator].concat(),
                &dst,
            );
            counter += 1;
        }

        Params {
            domain_separator: domain_separator.to_vec(),
            h1: h[0].clone(),
            h2: h[1].clone(),
            h3: h[2].clone(),
            h4: h[3].clone(),
        }
    }

    /// The domain separator these parameters were derived from.
    pub fn domain_separator(&self) -> &[u8] {
        &self.domain_separator
    }
}
