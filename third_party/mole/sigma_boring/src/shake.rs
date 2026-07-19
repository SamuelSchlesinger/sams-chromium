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
