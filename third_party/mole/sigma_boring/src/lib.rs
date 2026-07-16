// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `sigma_boring`: the MoLE sigma-protocol primitives over Chromium's in-tree
//! BoringSSL. The first landed layer is P-256 group and scalar arithmetic
//! (see [`bssl`]); the duplex-sponge Fiat-Shamir codec and the
//! LinearRelation / Schnorr / composition layers build on top of it, replacing
//! the vendored `sigma-proofs` + `curve25519-dalek` stack.

pub mod bssl;
pub mod codec;
pub mod composition;
pub mod keccak;
pub mod linear_relation;
pub mod shake;

pub use bssl::{fill_random, sha256, Point, Scalar, POINT_BYTES, SCALAR_BYTES};
pub use keccak::keccak_f1600;
pub use shake::Transcript;
