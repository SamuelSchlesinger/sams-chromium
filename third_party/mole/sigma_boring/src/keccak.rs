// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The Keccak-f1600 permutation, exposed from BoringSSL's internal
//! implementation through the `MOLE_keccak_f1600` shim
//! (`//third_party/boringssl:mole_crypto_shim`). spongefish's duplex sponge
//! runs the *raw* permutation (not SHAKE-with-padding), so the MoLE
//! Fiat-Shamir codec needs the bare permutation to stay byte-compatible with
//! the sigma-protocols reference.

unsafe extern "C" {
    // Applies Keccak-f1600 in place to a 25-word (1600-bit) state.
    fn MOLE_keccak_f1600(state: *mut u64);
}

/// Apply the Keccak-f1600 permutation in place to the 25-word state.
pub fn keccak_f1600(state: &mut [u64; 25]) {
    // SAFETY: `MOLE_keccak_f1600` reads and writes exactly 25 words through the
    // pointer; `state` is a valid, uniquely-borrowed 25-word array.
    unsafe { MOLE_keccak_f1600(state.as_mut_ptr()) };
}
