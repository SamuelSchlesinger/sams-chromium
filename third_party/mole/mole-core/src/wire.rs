// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! TLS 1.3 presentation-language primitives (`draft-jms-mole-protocols-01` §2):
//! minimal-length RFC 9000 §16 QUIC variable-length integers (`<V>`), fixed-size
//! arrays, and network-byte-order integer helpers.

use thiserror::Error;

/// Error encoding or decoding a MOLE binary payload.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum WireError {
    /// Input ended before a complete value was read.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// Trailing bytes remained after decoding a complete value.
    #[error("trailing bytes after value")]
    TrailingBytes,
    /// A QUIC variable-length integer was not minimally encoded.
    #[error("non-minimal variable-length integer")]
    NonMinimalVarint,
    /// Value exceeded the permitted length or range.
    #[error("value out of range for its encoding")]
    OutOfRange,
    /// Structural or cryptographic malformation.
    #[error("malformed value: {0}")]
    Malformed(&'static str),
}

/// Canonical byte encoding for context-free MOLE binary structures.
pub trait Wire: Sized {
    /// Appends canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError>;

    /// Decodes one value from the front of `buf`, advancing it.
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError>;

    /// Encodes into a newly allocated vector.
    fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decodes from `bytes`, rejecting trailing bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut cursor = bytes;
        let value = Self::decode(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// Splits `n` bytes off the front of `buf`, advancing it.
pub fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    let (head, tail) = buf.split_at_checked(n).ok_or(WireError::UnexpectedEof)?;
    *buf = tail;
    Ok(head)
}

/// Reads a fixed-size `[u8; N]` array from `buf`.
pub fn get_fixed<const N: usize>(buf: &mut &[u8]) -> Result<[u8; N], WireError> {
    let slice = take(buf, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn get_u8(buf: &mut &[u8]) -> Result<u8, WireError> {
    Ok(take(buf, 1)?[0])
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn get_u16(buf: &mut &[u8]) -> Result<u16, WireError> {
    let raw = get_fixed::<2>(buf)?;
    Ok(u16::from_be_bytes(raw))
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn get_u64(buf: &mut &[u8]) -> Result<u64, WireError> {
    let raw = get_fixed::<8>(buf)?;
    Ok(u64::from_be_bytes(raw))
}

/// Maximum value representable in a QUIC variable-length integer (`2^62 - 1`).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Encodes `v` in minimal RFC 9000 §16 QUIC variable-length integer form.
pub fn put_varint(out: &mut Vec<u8>, v: u64) -> Result<(), WireError> {
    if v > VARINT_MAX {
        return Err(WireError::OutOfRange);
    }
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
    Ok(())
}

/// Decodes a minimal RFC 9000 §16 QUIC variable-length integer, rejecting
/// non-shortest encodings (`draft-jms-mole-protocols-01` §2).
pub fn get_varint(buf: &mut &[u8]) -> Result<u64, WireError> {
    let first = get_u8(buf)?;
    let size = 1usize << (first >> 6);
    let rest = take(buf, size - 1)?;
    let mut v = u64::from(first & 0x3F);
    for &b in rest {
        v = (v << 8) | u64::from(b);
    }
    let min_val = match size {
        1 => 0,
        2 => 1 << 6,
        4 => 1 << 14,
        8 => 1 << 30,
        _ => unreachable!(),
    };
    if v < min_val {
        return Err(WireError::NonMinimalVarint);
    }
    Ok(v)
}

/// Encodes `opaque x<V>` (QUIC varint byte-length prefix followed by `bytes`).
pub fn put_opaque_v(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let len = u64::try_from(bytes.len()).map_err(|_| WireError::OutOfRange)?;
    put_varint(out, len)?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Decodes `opaque x<V>` as a borrowed slice.
pub fn get_opaque_slice<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], WireError> {
    let len = get_varint(buf)?;
    let len = usize::try_from(len).map_err(|_| WireError::OutOfRange)?;
    take(buf, len)
}

/// Decodes `opaque x<V>` into an owned `Vec<u8>`.
pub fn get_opaque_v(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    Ok(get_opaque_slice(buf)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_and_rejects_non_minimal() {
        for v in [0, 1, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, VARINT_MAX] {
            let mut enc = Vec::new();
            put_varint(&mut enc, v).unwrap();
            let mut cur = enc.as_slice();
            assert_eq!(get_varint(&mut cur).unwrap(), v);
            assert!(cur.is_empty());
        }
        // 2-byte encoding of 5 (< 64) must fail.
        let mut non_minimal: &[u8] = &[0x40, 0x05];
        assert_eq!(get_varint(&mut non_minimal), Err(WireError::NonMinimalVarint));
        // 4-byte encoding of 100 (< 16384) must fail.
        let mut non_minimal4: &[u8] = &[0x80, 0x00, 0x00, 0x64];
        assert_eq!(get_varint(&mut non_minimal4), Err(WireError::NonMinimalVarint));
    }
}
