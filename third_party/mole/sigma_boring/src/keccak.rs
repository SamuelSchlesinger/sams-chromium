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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_keccak_crate_permutation() {
        // Byte-for-byte parity with the `keccak` crate spongefish uses.
        for seed in 0u64..8 {
            let mut ours = [0u64; 25];
            for (i, w) in ours.iter_mut().enumerate() {
                *w = seed
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(i as u64);
            }
            let mut theirs = ours;
            keccak_f1600(&mut ours);
            keccak::Keccak::new().with_f1600(|f| f(&mut theirs));
            assert_eq!(ours, theirs, "seed {seed}");
        }
    }

    #[test]
    fn all_zero_state_matches() {
        let mut ours = [0u64; 25];
        let mut theirs = [0u64; 25];
        keccak_f1600(&mut ours);
        keccak::Keccak::new().with_f1600(|f| f(&mut theirs));
        assert_eq!(ours, theirs);
        // A permutation of the all-zero state is not the identity.
        assert_ne!(ours, [0u64; 25]);
    }
}
