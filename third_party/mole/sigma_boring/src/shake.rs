// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! SHAKE128 over BoringSSL's Keccak-f1600 permutation ([`crate::keccak_f1600`])
//! and the reset-on-absorb XOF transcript wrapper the sigma-protocol
//! Fiat-Shamir codec uses. This reproduces spongefish's
//! `XOF<sha3::Shake128>` (its `StdHash`) byte-for-byte so transcripts stay
//! compatible with the sigma-protocols reference.
//!
//! SHAKE128 is standard FIPS-202: rate 168 bytes, XOR absorb, domain
//! separation `0x1F` with `pad10*1`. The permutation is BoringSSL's; the
//! byte<->word mapping is little-endian (Chromium targets are LE).

use crate::keccak_f1600;

const RATE: usize = 168;
const WIDTH: usize = 200;

/// The incremental SHAKE128 absorb state (cloneable, always absorbing).
#[derive(Clone)]
struct Shake128 {
    state: [u8; WIDTH],
    pos: usize,
}

/// A SHAKE128 squeeze reader, produced by finalizing an absorb state.
struct Shake128Reader {
    state: [u8; WIDTH],
    pos: usize,
}

fn permute(state: &mut [u8; WIDTH]) {
    let mut words = [0u64; 25];
    for (word, chunk) in words.iter_mut().zip(state.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    keccak_f1600(&mut words);
    for (word, chunk) in words.iter().zip(state.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

impl Shake128 {
    fn new() -> Self {
        Shake128 { state: [0u8; WIDTH], pos: 0 }
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.state[self.pos] ^= byte;
            self.pos += 1;
            if self.pos == RATE {
                permute(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Finalize (SHAKE domain separation + pad10*1) into a squeeze reader,
    /// leaving `self` untouched so it can keep absorbing.
    fn finalize_xof(&self) -> Shake128Reader {
        let mut state = self.state;
        state[self.pos] ^= 0x1F;
        state[RATE - 1] ^= 0x80;
        permute(&mut state);
        Shake128Reader { state, pos: 0 }
    }
}

impl Shake128Reader {
    fn read(&mut self, out: &mut [u8]) {
        for byte in out {
            if self.pos == RATE {
                permute(&mut self.state);
                self.pos = 0;
            }
            *byte = self.state[self.pos];
            self.pos += 1;
        }
    }
}

/// SHA3-256 over BoringSSL's Keccak-f1600: rate 136 bytes, domain separation
/// `0x06`, 32-byte digest. Used for the composed-relation protocol identifier.
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    const SHA3_RATE: usize = 136;
    let mut state = [0u8; WIDTH];
    let mut pos = 0usize;
    for &byte in input {
        state[pos] ^= byte;
        pos += 1;
        if pos == SHA3_RATE {
            permute(&mut state);
            pos = 0;
        }
    }
    // pad10*1 with the SHA-3 domain separator 0x06.
    state[pos] ^= 0x06;
    state[SHA3_RATE - 1] ^= 0x80;
    permute(&mut state);
    let mut out = [0u8; 32];
    out.copy_from_slice(&state[..32]);
    out
}

/// The Fiat-Shamir transcript sponge: SHAKE128 as an extensible-output
/// function with spongefish's `XOF` wrapper semantics — an absorb invalidates
/// the current squeeze stream and appends to the message; a squeeze reads the
/// XOF of the message absorbed so far, continuing across consecutive squeezes.
#[derive(Clone)]
pub struct Transcript {
    hasher: Shake128,
    // `None` while absorbing; `Some` while squeezing. Cleared on absorb.
    reader_state: Option<[u8; WIDTH]>,
    reader_pos: usize,
}

impl Default for Transcript {
    fn default() -> Self {
        Transcript {
            hasher: Shake128::new(),
            reader_state: None,
            reader_pos: 0,
        }
    }
}

impl Transcript {
    /// Absorb `input` into the transcript.
    pub fn absorb(&mut self, input: &[u8]) {
        self.reader_state = None;
        self.hasher.update(input);
    }

    /// Squeeze `output.len()` bytes of challenge material.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        if self.reader_state.is_none() {
            let reader = self.hasher.finalize_xof();
            self.reader_state = Some(reader.state);
            self.reader_pos = reader.pos;
        }
        let mut reader = Shake128Reader {
            state: self.reader_state.unwrap(),
            pos: self.reader_pos,
        };
        reader.read(output);
        self.reader_state = Some(reader.state);
        self.reader_pos = reader.pos;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spongefish::DuplexSpongeInterface;

    type Ref = spongefish::instantiations::Shake128;

    // Drive our transcript and spongefish's Shake128 identically; compare.
    fn check(ops: &[(bool, usize)]) {
        let mut ours = Transcript::default();
        let mut theirs = Ref::default();
        let mut counter = 0u8;
        for &(is_absorb, len) in ops {
            if is_absorb {
                let data: Vec<u8> = (0..len)
                    .map(|i| {
                        counter = counter.wrapping_add(1);
                        counter ^ (i as u8)
                    })
                    .collect();
                ours.absorb(&data);
                theirs.absorb(&data);
            } else {
                let mut a = vec![0u8; len];
                let mut b = vec![0u8; len];
                ours.squeeze(&mut a);
                theirs.squeeze(&mut b);
                assert_eq!(a, b, "squeeze mismatch at len {len}");
            }
        }
    }

    #[test]
    fn raw_shake128_matches_reference_xof() {
        // Our SHAKE128 must match a bare finalize+read (no wrapper).
        let mut h = Shake128::new();
        h.update(b"the quick brown fox");
        let mut reader = h.finalize_xof();
        let mut ours = [0u8; 96];
        reader.read(&mut ours);

        let mut theirs = Ref::default();
        theirs.absorb(b"the quick brown fox");
        let mut ref_out = [0u8; 96];
        theirs.squeeze(&mut ref_out);
        assert_eq!(ours, ref_out);
    }

    #[test]
    fn single_absorb_squeeze_matches() {
        check(&[(true, 20), (false, 64)]);
    }

    #[test]
    fn absorb_spanning_rate_matches() {
        check(&[(true, RATE), (false, 32)]);
        check(&[(true, RATE + 5), (false, 200)]);
        check(&[(true, 400), (false, 64)]);
    }

    #[test]
    fn squeeze_spanning_rate_matches() {
        check(&[(true, 3), (false, 500)]);
    }

    #[test]
    fn interleaved_absorb_squeeze_matches() {
        check(&[
            (true, 7),
            (false, 40),
            (true, 169),
            (false, 5),
            (true, 1),
            (false, 200),
            (true, 333),
            (false, 168),
            (false, 40),
        ]);
    }

    #[test]
    fn empty_message_squeeze_matches() {
        check(&[(false, 64)]);
    }
}
