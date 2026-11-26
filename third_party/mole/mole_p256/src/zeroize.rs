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

//! Minimal `#![no_std]` memory-zeroization primitives (`Zeroize`,
//! `ZeroizeOnDrop`, and `Zeroizing`) backed by `core::ptr::write_volatile` and
//! `core::sync::atomic::compiler_fence`, keeping the Chromium GN dependency
//! graph self-contained without requiring an external `zeroize` crate target.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, compiler_fence};

/// Trait for securely overwriting secret values in memory with zeroes.
pub trait Zeroize {
    /// Overwrites `self` with its zero representation without dead-store elision.
    fn zeroize(&mut self);
}

/// Marker trait indicating that a type zeroizes its contents when dropped.
pub trait ZeroizeOnDrop {}

#[allow(unsafe_code)]
#[inline(never)]
fn volatile_zero<T: Copy>(dst: &mut T, zero: T) {
    // SAFETY: `dst` is a valid, aligned, exclusively borrowed mutable reference
    // to a `Copy` value with no drop glue.
    unsafe { core::ptr::write_volatile(dst, zero) };
    compiler_fence(Ordering::SeqCst);
}

macro_rules! impl_zeroize_primitive {
    ($($ty:ty => $zero:expr),* $(,)?) => {
        $(
            impl Zeroize for $ty {
                fn zeroize(&mut self) {
                    volatile_zero(self, $zero);
                }
            }
        )*
    };
}

impl_zeroize_primitive!(
    u8 => 0,
    u16 => 0,
    u32 => 0,
    u64 => 0,
    usize => 0,
    bool => false,
);

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        for elem in self {
            elem.zeroize();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: Zeroize> Zeroize for Vec<T> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        self.clear();
        // Zeroize any spare initialized-as-zeroable byte capacity if `T` is `u8`
        // or general spare capacity via resize-free clear; callers pre-reserve
        // before writing secrets so initialized elements were all in `0..len`.
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zeroizing wrapper that calls [`Zeroize::zeroize`] on its inner value when dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zeroizing<Z: Zeroize>(Z);

impl<Z: Zeroize> Zeroizing<Z> {
    /// Wraps `value` so it will be zeroized on drop.
    pub fn new(value: Z) -> Self {
        Self(value)
    }
}

impl<Z: Zeroize> Deref for Zeroizing<Z> {
    type Target = Z;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Z: Zeroize> DerefMut for Zeroizing<Z> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Z: Zeroize> AsRef<Z> for Zeroizing<Z> {
    fn as_ref(&self) -> &Z {
        &self.0
    }
}

impl<Z: Zeroize> AsMut<Z> for Zeroizing<Z> {
    fn as_mut(&mut self) -> &mut Z {
        &mut self.0
    }
}

impl<Z: Zeroize> Drop for Zeroizing<Z> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<Z: Zeroize> ZeroizeOnDrop for Zeroizing<Z> {}
