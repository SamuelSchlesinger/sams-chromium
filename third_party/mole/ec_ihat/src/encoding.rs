//! IHAT's canonical-coding helpers for wire and storage encodings, over the
//! [`Reader`] that `mole-p256` shares with ACT: `CtOption` handling,
//! variable-length vectors, and the signature that an Endorsement stores and
//! a redemption shows.

use alloc::vec::Vec;

use mole_p256::encoding::Reader;
use subtle::CtOption;
use mole_p256::zeroize::Zeroizing;

use crate::backend::{Backend, SCALAR_LENGTH, Scalar};
use crate::protocol::Signature;
use crate::{Error, NULLIFIER_LENGTH};

/// Checks that a `CtOption` holds a value, mapping absence to `error`.
pub(crate) fn require<T, E>(value: CtOption<T>, error: E) -> Result<T, E> {
    value.into_option().ok_or(error)
}

/// Length of an encoded signature with its nullifier.
pub(crate) const SIGNATURE_LENGTH: usize = 4 * SCALAR_LENGTH + NULLIFIER_LENGTH;

/// The fields that only IHAT's encodings hold.
pub(crate) trait ReaderExt<'a> {
    /// A variable-length integer, rejecting any encoding that is not the
    /// shortest.
    fn length(&mut self) -> Result<usize, Error>;

    /// An `opaque value<V>`.
    fn vector(&mut self) -> Result<&'a [u8], Error>;

    /// A `Signature`, held in a `Zeroizing` so that a decoding failure
    /// wipes the fields read so far.
    fn signature<B: Backend>(&mut self) -> Result<Zeroizing<Signature<B>>, Error>;
}

impl<'a> ReaderExt<'a> for Reader<'a> {
    fn length(&mut self) -> Result<usize, Error> {
        let first = self.take(1)?[0];
        let size = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(size - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        if size > 1 && value < 1 << (8 * (size / 2) - 2) {
            return Err(Error::Deserialize);
        }
        usize::try_from(value).map_err(|_| Error::Deserialize)
    }

    fn vector(&mut self) -> Result<&'a [u8], Error> {
        let length = self.length()?;
        Ok(self.take(length)?)
    }

    fn signature<B: Backend>(&mut self) -> Result<Zeroizing<Signature<B>>, Error> {
        let mut signature = Zeroizing::new(Signature {
            c: B::Scalar::default(),
            s: B::Scalar::default(),
            y: B::Scalar::default(),
            t: B::Scalar::default(),
            nf: [0; NULLIFIER_LENGTH],
        });
        signature.c = self.scalar::<B>()?;
        signature.s = self.scalar::<B>()?;
        signature.y = self.scalar::<B>()?;
        signature.t = self.scalar::<B>()?;
        signature.nf = *self.array()?;
        Ok(signature)
    }
}

/// The minimum-size variable-length integer encoding of `value`, which is
/// below `2^62`.
pub(crate) fn length_prefix(value: usize) -> Vec<u8> {
    let value = value as u64;
    debug_assert!(value < 1 << 62);
    if value < 1 << 6 {
        alloc::vec![value as u8]
    } else if value < 1 << 14 {
        (value as u16 | 0x4000).to_be_bytes().to_vec()
    } else if value < 1 << 30 {
        (value as u32 | 0x8000_0000).to_be_bytes().to_vec()
    } else {
        (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
    }
}

/// Decodes a variable-length integer that is all of `bytes`.
#[cfg(test)]
pub(crate) fn length_for_tests(bytes: &[u8]) -> Result<usize, Error> {
    let mut reader = Reader::new(bytes);
    let length = reader.length()?;
    reader.finish()?;
    Ok(length)
}

/// Appends `opaque value<V>`.
pub(crate) fn put_vector(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&length_prefix(value.len()));
    out.extend_from_slice(value);
}

/// Appends `Scalar c || Scalar s || Scalar y || Scalar t || opaque nf[Nn]`.
pub(crate) fn put_signature<B: Backend>(out: &mut Vec<u8>, signature: &Signature<B>) {
    for scalar in [&signature.c, &signature.s, &signature.y, &signature.t] {
        out.extend_from_slice(Zeroizing::new(scalar.to_bytes()).as_ref());
    }
    out.extend_from_slice(&signature.nf);
}
