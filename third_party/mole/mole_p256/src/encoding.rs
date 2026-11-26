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

//! Canonical decoding of byte strings, shared by the wire and storage
//! encodings of IHAT and ACT.
//!
//! A [`Reader`] only parses. Whether its input is an attacker-controlled
//! message or local secret state is the caller's to know, and so is every
//! check beyond lengths and canonical encodings.

use alloc::vec::Vec;

use crate::Error;
use crate::backend::{Backend, Point, Scalar};

/// A cursor over a byte string, which each read advances.
///
/// Every failure is [`Error::Deserialize`].
pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// The next `length` bytes.
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::Deserialize)?;
        let slice = self.data.get(self.offset..end).ok_or(Error::Deserialize)?;
        self.offset = end;
        Ok(slice)
    }

    /// The next `N` bytes.
    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Deserialize)
    }

    /// A group element in its canonical encoding, which excludes the
    /// identity.
    pub fn point<B: Backend>(&mut self) -> Result<B::Point, Error> {
        B::Point::from_bytes(self.array()?)
            .into_option()
            .ok_or(Error::Deserialize)
    }

    /// `count` group elements, each as [`Self::point`] reads it.
    pub fn points<B: Backend>(&mut self, count: usize) -> Result<Vec<B::Point>, Error> {
        (0..count).map(|_| self.point::<B>()).collect()
    }

    /// A scalar in its canonical encoding, below the group order.
    pub fn scalar<B: Backend>(&mut self) -> Result<B::Scalar, Error> {
        B::Scalar::from_bytes(self.array()?)
            .into_option()
            .ok_or(Error::Deserialize)
    }

    /// Checks that every byte was read.
    pub fn finish(self) -> Result<(), Error> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(Error::Deserialize)
        }
    }
}
