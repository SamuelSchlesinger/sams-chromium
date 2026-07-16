// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `ihat_boring`: the IHAT (issuer-hiding anonymous tokens) protocol over
//! Chromium's in-tree BoringSSL, via [`sigma_boring::bssl`]. This is the
//! first-party port of `ihat-rs` off the `p256`/`elliptic-curve` crate stack.
//!
//! This module ports the redemption OR-proof (`orproof.rs` upstream): a
//! Cramer-Damgård-Schoenmakers 1-of-n OR over the Schnorr relation
//! `X = w·B`, proving the rerandomised anchor key `X_hat` is a scalar multiple
//! of *some* accepted anchor key without revealing which — MoLE's
//! issuer-hiding endorsement. The transcript encoding matches `ihat-rs`
//! byte-for-byte so the ported client and the reference verifier interoperate.

pub mod anchor;
pub mod client;
pub(crate) mod hash;
pub mod messages;
pub mod orproof;
pub mod wire;

pub use anchor::{AnchorNeedsProofRequest, AnchorSecretKey};
pub use client::{ClientNeedsProof, ClientNeedsSignature, IssuedEndorsement};
pub use messages::{
    Endorsement, Presentation, Proof, ProofRequest, Signature, SignatureRequest,
};
pub use orproof::{OrProof, Transcript};
pub use sigma_boring::{Point, Scalar};
pub use wire::WireError;

#[cfg(test)]
mod interop_tests;
