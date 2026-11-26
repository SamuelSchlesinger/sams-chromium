//! The network messages of the draft: the three issuance messages and the
//! redemption.
//!
//! Decoding checks lengths, canonical encodings (which excludes the identity
//! element), minimal length prefixes, and that a redemption's vectors match
//! the depth of the Anchor Set's tree. Every other check is the protocol
//! algorithms'.

use alloc::vec::Vec;

use mole_p256::encoding::Reader;

use crate::Error;
use crate::backend::{Backend, POINT_LENGTH, SCALAR_LENGTH, Scalar};
use crate::commitment::depth;
use crate::encoding::{ReaderExt, SIGNATURE_LENGTH, length_prefix, put_signature, put_vector};
use crate::protocol::{ChallengeMessage, CommitMessage, Redemption, ResponseMessage, point_bytes};

/// Length of an encoded commitment.
const COMMIT_LENGTH: usize = 2 * POINT_LENGTH;

/// Length of an encoded response.
const RESPONSE_LENGTH: usize = 3 * SCALAR_LENGTH;

impl<B: Backend> CommitMessage<B> {
    /// The encoded length: `2 * Ne`.
    pub const LENGTH: usize = COMMIT_LENGTH;

    /// Encodes as `Element A || Element C`.
    pub fn to_bytes(&self) -> [u8; COMMIT_LENGTH] {
        let mut out = [0u8; COMMIT_LENGTH];
        out[..POINT_LENGTH].copy_from_slice(&point_bytes(&self.a));
        out[POINT_LENGTH..].copy_from_slice(&point_bytes(&self.c));
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            a: reader.point::<B>()?,
            c: reader.point::<B>()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: Backend> ChallengeMessage<B> {
    /// The encoded length: `Ns`.
    pub const LENGTH: usize = SCALAR_LENGTH;

    /// Encodes as `Scalar challenge`.
    pub fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.challenge.to_bytes()
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            challenge: reader.scalar::<B>()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: Backend> ResponseMessage<B> {
    /// The encoded length: `3 * Ns`.
    pub const LENGTH: usize = RESPONSE_LENGTH;

    /// Encodes as `Scalar s || Scalar y || Scalar t`.
    pub fn to_bytes(&self) -> [u8; RESPONSE_LENGTH] {
        let mut out = [0u8; RESPONSE_LENGTH];
        for (chunk, scalar) in out
            .chunks_exact_mut(SCALAR_LENGTH)
            .zip([&self.s, &self.y, &self.t])
        {
            chunk.copy_from_slice(&scalar.to_bytes());
        }
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            s: reader.scalar::<B>()?,
            y: reader.scalar::<B>()?,
            t: reader.scalar::<B>()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: Backend> Redemption<B> {
    /// The encoded length of a redemption against an Anchor Set of `n`
    /// keys.
    pub fn encoded_len(n: usize) -> usize {
        let q = depth(n);
        POINT_LENGTH
            + SIGNATURE_LENGTH
            + 2 * SCALAR_LENGTH
            + length_prefix(q * POINT_LENGTH).len()
            + q * POINT_LENGTH
            + length_prefix(q * SCALAR_LENGTH).len()
            + q * SCALAR_LENGTH
    }

    /// Encodes as `Element rerandomized_key || Endorsement shown ||
    /// Scalar proof_challenge || Scalar response ||
    /// Element commitment_keys<V> || Scalar openings<V>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let q = self.commitment_keys.len();
        let mut out = Vec::with_capacity(
            POINT_LENGTH
                + SIGNATURE_LENGTH
                + 2 * SCALAR_LENGTH
                + 16
                + q * POINT_LENGTH
                + self.openings.len() * SCALAR_LENGTH,
        );
        out.extend_from_slice(&point_bytes(&self.x_hat));
        put_signature(&mut out, &self.shown);
        out.extend_from_slice(&self.proof_challenge.to_bytes());
        out.extend_from_slice(&self.response.to_bytes());
        let keys: Vec<u8> = self.commitment_keys.iter().flat_map(point_bytes).collect();
        put_vector(&mut out, &keys);
        let openings: Vec<u8> = self
            .openings
            .iter()
            .flat_map(|opening| opening.to_bytes())
            .collect();
        put_vector(&mut out, &openings);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`] for an Anchor Set of `n`
    /// keys, requiring `Depth(n)` commitment keys and openings.
    pub fn from_bytes(bytes: &[u8], n: usize) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let x_hat = reader.point::<B>()?;
        let shown = reader.signature::<B>()?;
        let proof_challenge = reader.scalar::<B>()?;
        let response = reader.scalar::<B>()?;
        let keys = reader.vector()?;
        let openings = reader.vector()?;
        reader.finish()?;

        let q = depth(n);
        if keys.len() != q * POINT_LENGTH || openings.len() != q * SCALAR_LENGTH {
            return Err(Error::Deserialize);
        }
        let mut keys = Reader::new(keys);
        let mut openings = Reader::new(openings);
        let commitment_keys = keys.points::<B>(q)?;
        let openings = (0..q)
            .map(|_| openings.scalar::<B>())
            .collect::<Result<_, _>>()?;
        Ok(Self {
            x_hat,
            shown: (*shown).clone(),
            proof_challenge,
            response,
            commitment_keys,
            openings,
        })
    }
}
