// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Canonical wire encoding for the ACT(P-256) message types, so the FFI and
//! network can carry them. This is the P-256 ciphersuite's own format (33-byte
//! SEC1 points, 32-byte big-endian canonical scalars, `u16`-length-prefixed
//! variable fields) — not byte-compatible with the ristretto255 reference,
//! which is a different suite. Every attacker-supplied count is bounded against
//! the remaining buffer before allocating, and scalars must be canonical.

use crate::issuance::{CreditToken, IssuanceRequest, IssuanceResponse, PublicKey};
use crate::spend::{Refund, SpendProof};
use sigma_boring::{Point, Scalar, POINT_BYTES, SCALAR_BYTES};

/// An error encoding or decoding the ACT wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The input ended before a complete value was read.
    UnexpectedEof,
    /// Bytes remained after a complete value was decoded.
    TrailingBytes,
    /// A point was not a valid SEC1-compressed P-256 group element.
    InvalidPoint,
    /// A scalar was not canonical (`0 <= x < n`).
    InvalidScalar,
    /// A length-prefixed field exceeded its `2^16 - 1` bound while encoding.
    Overflow,
}

// -- encoders --

fn put_point(out: &mut Vec<u8>, p: &Point) {
    out.extend_from_slice(&p.to_bytes());
}

fn put_scalar(out: &mut Vec<u8>, s: &Scalar) {
    out.extend_from_slice(&s.to_bytes());
}

fn put_varbytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let len = u16::try_from(bytes.len()).map_err(|_| WireError::Overflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_point_vec(out: &mut Vec<u8>, points: &[Point]) -> Result<(), WireError> {
    let n = u16::try_from(points.len()).map_err(|_| WireError::Overflow)?;
    out.extend_from_slice(&n.to_be_bytes());
    for p in points {
        put_point(out, p);
    }
    Ok(())
}

// -- decoders --

/// A byte cursor with bounds-checked reads.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<usize, WireError> {
        let raw = self.take(2)?;
        Ok(u16::from_be_bytes([raw[0], raw[1]]) as usize)
    }
    fn point(&mut self) -> Result<Point, WireError> {
        let raw = self.take(POINT_BYTES)?;
        Point::from_bytes(&raw.try_into().unwrap()).ok_or(WireError::InvalidPoint)
    }
    fn scalar(&mut self) -> Result<Scalar, WireError> {
        let raw = self.take(SCALAR_BYTES)?;
        Scalar::from_canonical_bytes(&raw.try_into().unwrap()).ok_or(WireError::InvalidScalar)
    }
    fn varbytes(&mut self) -> Result<Vec<u8>, WireError> {
        let len = self.u16()?;
        Ok(self.take(len)?.to_vec())
    }
    fn point_vec(&mut self) -> Result<Vec<Point>, WireError> {
        let n = self.u16()?;
        // Each point is POINT_BYTES on the wire; reject an impossible count
        // before allocating.
        if n > self.remaining() / POINT_BYTES {
            return Err(WireError::UnexpectedEof);
        }
        let mut points = Vec::with_capacity(n);
        for _ in 0..n {
            points.push(self.point()?);
        }
        Ok(points)
    }
    fn finish(self) -> Result<(), WireError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

impl IssuanceRequest {
    /// The canonical wire encoding: `big_K || pok`.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        put_point(&mut out, &self.big_k);
        put_varbytes(&mut out, &self.pok)?;
        Ok(out)
    }
    /// Decode from the canonical wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(bytes);
        let big_k = c.point()?;
        let pok = c.varbytes()?;
        c.finish()?;
        Ok(IssuanceRequest { big_k, pok })
    }
}

impl IssuanceResponse {
    /// The canonical wire encoding: `A || e || c || pok`.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        put_point(&mut out, &self.a);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.c);
        put_varbytes(&mut out, &self.pok)?;
        Ok(out)
    }
    /// Decode from the canonical wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(bytes);
        let a = c.point()?;
        let e = c.scalar()?;
        let credits = c.scalar()?;
        let pok = c.varbytes()?;
        c.finish()?;
        Ok(IssuanceResponse { a, e, c: credits, pok })
    }
}

impl SpendProof {
    /// The canonical wire encoding.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        put_scalar(&mut out, &self.k);
        put_scalar(&mut out, &self.s);
        put_scalar(&mut out, &self.a);
        put_scalar(&mut out, &self.ctx);
        put_point(&mut out, &self.a_prime);
        put_point(&mut out, &self.b_bar);
        put_point_vec(&mut out, &self.com1)?;
        put_point_vec(&mut out, &self.t1)?;
        put_point_vec(&mut out, &self.com2)?;
        put_point_vec(&mut out, &self.t2)?;
        put_point(&mut out, &self.k_n);
        put_varbytes(&mut out, &self.pok)?;
        Ok(out)
    }
    /// Decode from the canonical wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(bytes);
        let k = c.scalar()?;
        let s = c.scalar()?;
        let a = c.scalar()?;
        let ctx = c.scalar()?;
        let a_prime = c.point()?;
        let b_bar = c.point()?;
        let com1 = c.point_vec()?;
        let t1 = c.point_vec()?;
        let com2 = c.point_vec()?;
        let t2 = c.point_vec()?;
        let k_n = c.point()?;
        let pok = c.varbytes()?;
        c.finish()?;
        Ok(SpendProof {
            k,
            s,
            a,
            ctx,
            a_prime,
            b_bar,
            com1,
            t1,
            com2,
            t2,
            k_n,
            pok,
        })
    }
}

impl Refund {
    /// The canonical wire encoding: `A* || e* || t || pok`.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        put_point(&mut out, &self.a);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.t);
        put_varbytes(&mut out, &self.pok)?;
        Ok(out)
    }
    /// Decode from the canonical wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(bytes);
        let a = c.point()?;
        let e = c.scalar()?;
        let t = c.scalar()?;
        let pok = c.varbytes()?;
        c.finish()?;
        Ok(Refund { a, e, t, pok })
    }
}

impl PublicKey {
    /// The canonical wire encoding: the single point `W`.
    pub fn to_wire(&self) -> Vec<u8> {
        self.w.to_bytes().to_vec()
    }
    /// Decode from the canonical wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(bytes);
        let w = c.point()?;
        c.finish()?;
        Ok(PublicKey { w })
    }
}

impl CreditToken {
    /// The canonical wire encoding of the client's token: `A || e || k || r ||
    /// c || ctx`. For local pool persistence — never sent to the issuer.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_point(&mut out, &self.a);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.k);
        put_scalar(&mut out, &self.r);
        put_scalar(&mut out, &self.c);
        put_scalar(&mut out, &self.ctx);
        out
    }
    /// Decode from the canonical wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(bytes);
        let a = c.point()?;
        let e = c.scalar()?;
        let k = c.scalar()?;
        let r = c.scalar()?;
        let credits = c.scalar()?;
        let ctx = c.scalar()?;
        c.finish()?;
        Ok(CreditToken { a, e, k, r, c: credits, ctx })
    }
}
