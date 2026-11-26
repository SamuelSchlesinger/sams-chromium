// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Shared MOLE protocol machinery implementing `draft-jms-mole-protocols-01`
//! and `draft-jms-mole-http-transport-01`:
//!
//! * [`wire`] — TLS 1.3 presentation-language primitives with minimal RFC 9000
//!   QUIC `<V>` variable-length integer length prefixes.
//! * [`messages`] — direct (unwrapped) binary protocol messages for batched
//!   EC-IHAT grants (`0x0002`), 32-byte `RedemptionChallenge`s (`0x0001` &
//!   `0x0002`), and EC-ACT issuance, presentation, update, and 96-byte
//!   recovery/signoff handles (`0x0001`).
//! * [`http`] — the `Mole` HTTP authentication scheme (`WWW-Authenticate`,
//!   `Authorization`, `Mole-Credential`) and grant media types with `-XXXX`
//!   hexadecimal protocol suffixes.
//! * [`config`] — JSON Anchor and Moderator configuration schemas per Section 6
//!   of `draft-jms-mole-protocols-01`.
//! * [`act`] — EC-ACT key identifiers (`SHA-256(SerializeElement(pkM))`),
//!   `ctx_cred` derivation (`credential_context || I2OSP(L, 1)`), and recovery
//!   handle computation.

pub mod act;
pub mod config;
pub mod http;
pub mod messages;
pub mod wire;

use mole_p256::backend::Sha256 as _;

/// Fixed cryptographic redemption context for EC-IHAT (`draft-jms-mole-protocols-01` §4.4.1).
pub const EC_IHAT_CTX_RED: &[u8] = b"MOLE-EC-IHAT-ctx_red-v1";

/// Ciphersuite identifier shared by EC-IHAT and EC-ACT over P-256.
pub const CIPHERSUITE_P256_SHA256: &str = "P256-SHA256";

/// Maximum byte length of an EC-ACT `credential_context` (`2^16 - 2`), leaving
/// one byte for `I2OSP(L, 1)` in `ctx_cred` (`draft-jms-mole-protocols-01` §5.2.1).
pub const MAX_CREDENTIAL_CONTEXT_LEN: usize = 65_534;

/// MOLE endorsement type values (`draft-jms-mole-protocols-01` §8.1).
pub mod endorsement_type {
    /// Reserved; MUST NOT appear on the wire.
    pub const RESERVED: u16 = 0x0000;
    /// No Endorsement Required (`0x0001`).
    pub const NO_ENDORSEMENT: u16 = 0x0001;
    /// EC-IHAT (`0x0002`).
    pub const EC_IHAT: u16 = 0x0002;
    /// Longfellow ZK (`0x0003`, not implemented here).
    pub const LONGFELLOW: u16 = 0x0003;
}

/// MOLE credential type values (`draft-jms-mole-protocols-01` §8.2).
pub mod credential_type {
    /// Reserved; MUST NOT appear on the wire.
    pub const RESERVED: u16 = 0x0000;
    /// EC-ACT (`0x0001`).
    pub const EC_ACT: u16 = 0x0001;
    /// Privacy Pass with a Reverse Flow (`0x0002`, not implemented here).
    pub const PRIVACY_PASS_REVERSE: u16 = 0x0002;

    /// Reserved greased credential type values (`0x?A?A`, §8.2.3).
    pub const GREASED: [u16; 16] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
        0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ];

    /// Returns whether `value` is one of the reserved `0x?A?A` greased values.
    /// Recipients MUST NOT special-case these; this helper is for senders/tests.
    pub fn is_greased(value: u16) -> bool {
        (value & 0x0F0F) == 0x0A0A
    }
}

/// Computes SHA-256 using the active `ec_ihat::DefaultBackend`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <ec_ihat::DefaultBackend as mole_p256::backend::Backend>::Sha256::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// Fills `buf` with cryptographically secure random bytes from `DefaultBackend`.
pub fn fill_random(buf: &mut [u8]) -> Result<(), mole_p256::Error> {
    <ec_ihat::DefaultBackend as mole_p256::backend::Backend>::random_bytes(buf)
}

/// Computes `SHA-256(challenge_octets)` over raw decoded challenge bytes
/// (`draft-jms-mole-protocols-01` §§4.1, 5.2.3.1).
pub fn challenge_digest(challenge_octets: &[u8]) -> [u8; 32] {
    sha256(challenge_octets)
}
