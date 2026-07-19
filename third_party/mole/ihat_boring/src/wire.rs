// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Decoding of the IHAT redemption wire format onto `sigma_boring` types,
//! matching `ihat-rs`'s `wire.rs` (the TLS 1.3 presentation-language encoding
//! over NIST P-256) byte-for-byte, so a `Presentation` produced by the
//! reference implementation parses here identically.
//!
//! Only the *verifier*-side decode path is ported: `Endorsement`, the OR-proof
//! `Transcript`s, and the `Presentation` that wraps them. Points are 33-byte
//! SEC1-compressed; scalars are 32-byte big-endian and required canonical
//! (`< n`); variable-length fields carry a `u16` big-endian length prefix, so
//! every count is inherently bounded to `2^16 - 1` (no unbounded allocation).

use crate::client::IssuedEndorsement;
use crate::messages::{
    Endorsement, Presentation, Proof, ProofRequest, Signature, SignatureRequest,
};
use crate::orproof::{OrProof, Transcript};
use sigma_boring::{Point, Scalar, POINT_BYTES, SCALAR_BYTES};

/// An error encoding or decoding the IHAT wire format. Mirrors `ihat-rs`'s
/// `WireError`.
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
    /// A length-prefixed field exceeded its `2^16 - 1` byte bound while encoding.
    Overflow,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

// -- encoders (the messages the ported client produces) --

fn put_point(out: &mut Vec<u8>, p: &Point) {
    out.extend_from_slice(&p.to_bytes()); // 33-byte SEC1 compressed
}

fn put_scalar(out: &mut Vec<u8>, s: &Scalar) {
    out.extend_from_slice(&s.to_bytes()); // 32-byte big-endian
}

fn put_varbytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let len = u16::try_from(bytes.len()).map_err(|_| WireError::Overflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

impl SignatureRequest {
    /// The canonical IHAT wire encoding.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        put_point(&mut out, &self.yp);
        put_varbytes(&mut out, &self.endorsement_context)?;
        Ok(out)
    }
}

impl ProofRequest {
    /// The canonical IHAT wire encoding.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        put_scalar(&mut out, &self.e_prime);
        Ok(out)
    }
}

fn encode_endorsement(out: &mut Vec<u8>, e: &Endorsement) -> Result<(), WireError> {
    put_point(out, &e.x_hat);
    put_point(out, &e.z_hat);
    put_varbytes(out, &e.nf)?;
    put_scalar(out, &e.e);
    put_scalar(out, &e.a);
    put_scalar(out, &e.b);
    put_scalar(out, &e.r);
    put_varbytes(out, &e.endorsement_context)
}

fn encode_or_proof(out: &mut Vec<u8>, p: &OrProof) -> Result<(), WireError> {
    let mut body = Vec::new();
    for tr in &p.transcripts {
        put_point(&mut body, &tr.t);
        put_scalar(&mut body, &tr.c);
        put_scalar(&mut body, &tr.s);
    }
    let len = u16::try_from(body.len()).map_err(|_| WireError::Overflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(())
}

impl Presentation {
    /// The canonical IHAT wire encoding (endorsement followed by OR-proof).
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        encode_endorsement(&mut out, &self.endorsement)?;
        encode_or_proof(&mut out, &self.or_proof)?;
        Ok(out)
    }
}

/// Split `n` bytes off the front of `buf`, advancing it.
fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if buf.len() < n {
        return Err(WireError::UnexpectedEof);
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

fn get_u16(buf: &mut &[u8]) -> Result<u16, WireError> {
    let raw = take(buf, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn get_point(buf: &mut &[u8]) -> Result<Point, WireError> {
    let raw = take(buf, POINT_BYTES)?;
    Point::from_bytes(&raw.try_into().unwrap()).ok_or(WireError::InvalidPoint)
}

fn get_scalar(buf: &mut &[u8]) -> Result<Scalar, WireError> {
    let raw = take(buf, SCALAR_BYTES)?;
    // Canonical decode (reject `>= n`), matching the reference's `from_repr`.
    Scalar::from_canonical_bytes(&raw.try_into().unwrap()).ok_or(WireError::InvalidScalar)
}

fn get_varbytes(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = usize::from(get_u16(buf)?);
    Ok(take(buf, len)?.to_vec())
}

/// Decode one `Endorsement` from the front of `buf`.
fn decode_endorsement(buf: &mut &[u8]) -> Result<Endorsement, WireError> {
    Ok(Endorsement {
        x_hat: get_point(buf)?,
        z_hat: get_point(buf)?,
        nf: get_varbytes(buf)?,
        e: get_scalar(buf)?,
        a: get_scalar(buf)?,
        b: get_scalar(buf)?,
        r: get_scalar(buf)?,
        endorsement_context: get_varbytes(buf)?,
    })
}

/// Decode one OR-proof `Transcript` (`t || c || s`).
fn decode_transcript(buf: &mut &[u8]) -> Result<Transcript, WireError> {
    Ok(Transcript {
        t: get_point(buf)?,
        c: get_scalar(buf)?,
        s: get_scalar(buf)?,
    })
}

/// Decode the OR-proof: a `u16` body length, then `Transcript`s until the body
/// is consumed. The body length bounds the transcript count.
fn decode_or_proof(buf: &mut &[u8]) -> Result<OrProof, WireError> {
    let len = usize::from(get_u16(buf)?);
    let mut body = take(buf, len)?;
    let mut transcripts = Vec::new();
    while !body.is_empty() {
        transcripts.push(decode_transcript(&mut body)?);
    }
    Ok(OrProof { transcripts })
}

impl Presentation {
    /// Parse a `Presentation` (endorsement followed by OR-proof) from its
    /// canonical IHAT wire encoding, erroring on trailing bytes.
    pub fn from_wire(bytes: &[u8]) -> Result<Presentation, WireError> {
        let mut cursor = bytes;
        let endorsement = decode_endorsement(&mut cursor)?;
        let or_proof = decode_or_proof(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(WireError::TrailingBytes);
        }
        Ok(Presentation { endorsement, or_proof })
    }
}

/// Decode a bare anchor public key (a single 33-byte SEC1 point), the
/// `AnchorPublicKey` wire form.
pub fn decode_anchor_key(bytes: &[u8]) -> Result<Point, WireError> {
    let mut cursor = bytes;
    let key = get_point(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(key)
}

/// Require the whole slice to be consumed by `decode`.
fn decode_all<T>(
    bytes: &[u8],
    decode: impl FnOnce(&mut &[u8]) -> Result<T, WireError>,
) -> Result<T, WireError> {
    let mut cursor = bytes;
    let value = decode(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(value)
}

impl IssuedEndorsement {
    /// Serialize the finished endorsement *and* its redemption witness `gamma`,
    /// for local persistence of the client's endorsement store (`endorsement ||
    /// gamma`). This carries a secret (`gamma`) and is never sent to a
    /// counterparty — only the `Presentation` (which does not reveal `gamma`)
    /// crosses the wire.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        encode_endorsement(&mut out, &self.endorsement)?;
        put_scalar(&mut out, &self.gamma);
        Ok(out)
    }

    /// Decode an [`IssuedEndorsement`] from [`to_wire`](Self::to_wire).
    pub fn from_wire(bytes: &[u8]) -> Result<IssuedEndorsement, WireError> {
        let mut cursor = bytes;
        let endorsement = decode_endorsement(&mut cursor)?;
        let gamma = get_scalar(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(WireError::TrailingBytes);
        }
        Ok(IssuedEndorsement { endorsement, gamma })
    }
}

impl SignatureRequest {
    /// Decode a client `SignatureRequest` (the anchor's read side).
    pub fn from_wire(bytes: &[u8]) -> Result<SignatureRequest, WireError> {
        decode_all(bytes, |buf| {
            Ok(SignatureRequest {
                yp: get_point(buf)?,
                endorsement_context: get_varbytes(buf)?,
            })
        })
    }
}

impl ProofRequest {
    /// Decode a client `ProofRequest` (the anchor's read side).
    pub fn from_wire(bytes: &[u8]) -> Result<ProofRequest, WireError> {
        decode_all(bytes, |buf| Ok(ProofRequest { e_prime: get_scalar(buf)? }))
    }
}

impl Signature {
    /// The canonical wire encoding (the anchor's write side): four points.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_point(&mut out, &self.zp);
        put_point(&mut out, &self.cp);
        put_point(&mut out, &self.t1p);
        put_point(&mut out, &self.t2p);
        out
    }

    /// Decode an anchor `Signature` (four points) from its wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Signature, WireError> {
        decode_all(bytes, |buf| {
            Ok(Signature {
                zp: get_point(buf)?,
                cp: get_point(buf)?,
                t1p: get_point(buf)?,
                t2p: get_point(buf)?,
            })
        })
    }
}

impl Proof {
    /// The canonical wire encoding (the anchor's write side): three scalars.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_scalar(&mut out, &self.rp);
        put_scalar(&mut out, &self.ap);
        put_scalar(&mut out, &self.bp);
        out
    }

    /// Decode an anchor `Proof` (three scalars) from its wire encoding.
    pub fn from_wire(bytes: &[u8]) -> Result<Proof, WireError> {
        decode_all(bytes, |buf| {
            Ok(Proof {
                rp: get_scalar(buf)?,
                ap: get_scalar(buf)?,
                bp: get_scalar(buf)?,
            })
        })
    }
}
