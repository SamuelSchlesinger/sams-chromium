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

//! ACT's canonical-decoding helpers for wire and storage encodings, over the
//! [`Reader`] that `mole-p256` shares with IHAT.

use mole_p256::encoding::Reader;

use crate::Error;
use crate::backend::{Backend, BackendFixedBaseExt, SCALAR_LENGTH, Scalar};
use crate::hash::require;
use crate::protocol::Params;

/// Length of an encoded `uint64` amount.
pub(crate) const AMOUNT_LENGTH: usize = 8;

/// The fields that only ACT's encodings hold.
pub(crate) trait ReaderExt<'a> {
    /// A `uint64` amount, checked against the balance width of `params`.
    fn amount<B: BackendFixedBaseExt>(&mut self, params: &Params<B>) -> Result<u64, Error>;

    /// A compact NARG string for `witnesses` scalars, with every scalar
    /// checked to be canonical.
    fn proof<B: Backend>(&mut self, witnesses: usize) -> Result<&'a [u8], Error>;
}

impl<'a> ReaderExt<'a> for Reader<'a> {
    fn amount<B: BackendFixedBaseExt>(&mut self, params: &Params<B>) -> Result<u64, Error> {
        let value = u64::from_be_bytes(*self.array()?);
        params.check_amount(value)?;
        Ok(value)
    }

    fn proof<B: Backend>(&mut self, witnesses: usize) -> Result<&'a [u8], Error> {
        let proof = self.take((witnesses + 1) * SCALAR_LENGTH)?;
        for chunk in proof.chunks_exact(SCALAR_LENGTH) {
            let bytes: &[u8; SCALAR_LENGTH] = chunk.try_into().map_err(|_| Error::Deserialize)?;
            require(B::Scalar::from_bytes(bytes), Error::Deserialize)?;
        }
        Ok(proof)
    }
}

pub(crate) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Deserialize)
}
