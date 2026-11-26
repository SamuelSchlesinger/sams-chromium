// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! FIPS 202 SHAKE128 extensible-output function (`Keccak[256](M || 1111, d)`).
//!
//! Used exclusively by the Sigma Fiat-Shamir transcript over public statement
//! instances and commitments (`src/sigma.rs`), avoiding any external `shake`
//! crate or internal BoringSSL C++ Keccak shim on Chromium revisions prior to
//! BoringSSL exporting `EVP_shake128`.

use mole_p256::zeroize::Zeroize;

const RATE: usize = 168;
const DOMAIN_SHAKE: u8 = 0x1f;

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        let mut cur = state[1];
        for (&pi, &rho) in PI.iter().zip(&RHO) {
            let next = state[pi];
            state[pi] = cur.rotate_left(rho);
            cur = next;
        }

        for y in 0..5 {
            let row = [
                state[5 * y],
                state[5 * y + 1],
                state[5 * y + 2],
                state[5 * y + 3],
                state[5 * y + 4],
            ];
            for x in 0..5 {
                state[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        state[0] ^= rc;
    }
}

fn xor_block(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (word, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        *word ^= u64::from_le_bytes(bytes);
    }
}

fn extract_block(state: &[u64; 25], block: &mut [u8; RATE]) {
    for (word, chunk) in state.iter().zip(block.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

/// Absorbs all `inputs` in order into SHAKE128 and squeezes `out.len()` bytes.
pub(crate) fn hash(inputs: &[&[u8]], out: &mut [u8]) {
    let mut state = [0u64; 25];
    let mut buf = [0u8; RATE];
    let mut pos = 0usize;

    for input in inputs {
        let mut slice = *input;
        while !slice.is_empty() {
            let take = (RATE - pos).min(slice.len());
            buf[pos..pos + take].copy_from_slice(&slice[..take]);
            pos += take;
            slice = &slice[take..];
            if pos == RATE {
                xor_block(&mut state, &buf);
                keccak_f1600(&mut state);
                buf.fill(0);
                pos = 0;
            }
        }
    }

    buf[pos] ^= DOMAIN_SHAKE;
    buf[RATE - 1] ^= 0x80;
    xor_block(&mut state, &buf);
    keccak_f1600(&mut state);

    let mut remaining = out;
    while !remaining.is_empty() {
        extract_block(&state, &mut buf);
        let take = RATE.min(remaining.len());
        remaining[..take].copy_from_slice(&buf[..take]);
        remaining = &mut remaining[take..];
        if !remaining.is_empty() {
            keccak_f1600(&mut state);
        }
    }

    state.zeroize();
    buf.zeroize();
}
