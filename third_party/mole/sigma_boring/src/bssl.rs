// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! P-256 group and scalar arithmetic backed by Chromium's in-tree BoringSSL,
//! reached through the raw `bssl_sys` FFI. This is the primitive layer the
//! sigma-protocol implementation is built on; it replaces the
//! `curve25519-dalek` / `p256` / `elliptic-curve` crate stack with the one
//! elliptic-curve implementation already shipping in the browser.
//!
//! Scalars are field elements mod the P-256 group order `n`. This first cut
//! carries them as `BIGNUM`s and uses the public `BN_mod_*` API; a later
//! hardening step swaps secret-scalar arithmetic onto the constant-time
//! `EC_SCALAR` path through an exposure shim (see BORINGSSL-PRUNE-PLAN.md).
//!
//! Every `unsafe` block below is a direct BoringSSL C call whose contract is
//! documented inline. Pointers returned by `*_new` are owned and freed in
//! `Drop`; `EC_GROUP_new_by_curve_name` returns a static built-in group that
//! must not be freed.

#![allow(non_upper_case_globals)]

use core::ptr;
use subtle::Choice;

// P-256 named-curve NID (openssl/nid.h: NID_X9_62_prime256v1).
const NID_P256: i32 = 415;
use bssl_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED;

/// The size in bytes of a P-256 scalar / field element.
pub const SCALAR_BYTES: usize = 32;
/// The size in bytes of a compressed P-256 point (0x02/0x03 || x).
pub const POINT_BYTES: usize = 33;

/// The immutable per-thread P-256 context: the built-in group, its order, and
/// a `BN_CTX` scratch. BoringSSL objects are not `Sync`, so this is
/// thread-local rather than a global.
struct Group {
    group: *mut bssl_sys::EC_GROUP,
    order: *const bssl_sys::BIGNUM,
    ctx: *mut bssl_sys::BN_CTX,
}

impl Group {
    fn new() -> Self {
        // SAFETY: NID_P256 is a valid built-in curve; the returned EC_GROUP is
        // a static singleton (must not be freed). BN_CTX_new allocates scratch
        // owned by this Group.
        unsafe {
            let group = bssl_sys::EC_GROUP_new_by_curve_name(NID_P256);
            assert!(!group.is_null(), "P-256 group unavailable");
            let order = bssl_sys::EC_GROUP_get0_order(group);
            assert!(!order.is_null(), "P-256 order unavailable");
            let ctx = bssl_sys::BN_CTX_new();
            assert!(!ctx.is_null(), "BN_CTX allocation failed");
            Group { group, order, ctx }
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        // SAFETY: `ctx` was allocated in `new`; `group` is a static singleton
        // and is intentionally not freed.
        unsafe {
            bssl_sys::BN_CTX_free(self.ctx);
        }
    }
}

thread_local! {
    static GROUP: Group = Group::new();
}

fn with_group<R>(f: impl FnOnce(&Group) -> R) -> R {
    GROUP.with(f)
}

// ---------------------------------------------------------------------------
// Scalar: an integer mod the P-256 group order.
// ---------------------------------------------------------------------------

/// A P-256 scalar (mod the group order `n`).
pub struct Scalar(*mut bssl_sys::BIGNUM);

impl Scalar {
    fn from_raw() -> Self {
        // SAFETY: BN_new allocates a fresh BIGNUM owned by this Scalar.
        let p = unsafe { bssl_sys::BN_new() };
        assert!(!p.is_null(), "BN allocation failed");
        Scalar(p)
    }

    /// The scalar zero.
    pub fn zero() -> Self {
        let s = Scalar::from_raw();
        // SAFETY: BN_zero sets the BIGNUM to 0; `s.0` is a valid owned BIGNUM.
        unsafe { bssl_sys::BN_zero(s.0) };
        s
    }

    /// The scalar one.
    pub fn one() -> Self {
        Scalar::from_u64(1)
    }

    /// The scalar equal to `value` (mod n).
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; SCALAR_BYTES];
        bytes[SCALAR_BYTES - 8..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_bytes_reduced(&bytes)
    }

    /// A uniformly random scalar in `[0, n)`.
    pub fn random() -> Self {
        let s = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: BN_rand_range_ex draws from BoringSSL's default RNG into
            // the owned BIGNUM, bounded by the group order.
            let ok = unsafe { bssl_sys::BN_rand_range_ex(s.0, 1, g.order) };
            assert_eq!(ok, 1, "BN_rand_range_ex failed");
        });
        s
    }

    /// Decode a scalar from 32 big-endian bytes, requiring a *canonical*
    /// encoding (`< n`); returns `None` otherwise. Used for scalars taken off
    /// the wire (proof responses and challenges): reducing a non-canonical
    /// encoding instead (see [`from_bytes_reduced`]) would make proofs
    /// malleable and diverge from the reference, which rejects `>= n`.
    pub fn from_canonical_bytes(bytes: &[u8; SCALAR_BYTES]) -> Option<Self> {
        let s = Scalar::from_raw();
        let in_range = with_group(|g| {
            // SAFETY: BN_bin2bn parses into the owned BIGNUM; BN_cmp compares it
            // against the group order.
            unsafe {
                let r = bssl_sys::BN_bin2bn(bytes.as_ptr(), SCALAR_BYTES, s.0);
                assert!(!r.is_null(), "BN_bin2bn failed");
                bssl_sys::BN_cmp(s.0, g.order) < 0
            }
        });
        in_range.then_some(s)
    }

    /// Decode a scalar from 32 big-endian bytes, reduced mod `n`.
    pub fn from_bytes_reduced(bytes: &[u8; SCALAR_BYTES]) -> Self {
        let s = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: BN_bin2bn parses `bytes` into the owned BIGNUM; BN_nnmod
            // reduces it into [0, n) using the group order and scratch ctx.
            unsafe {
                let r =
                    bssl_sys::BN_bin2bn(bytes.as_ptr(), SCALAR_BYTES, s.0);
                assert!(!r.is_null(), "BN_bin2bn failed");
                let ok = bssl_sys::BN_nnmod(s.0, s.0, g.order, g.ctx);
                assert_eq!(ok, 1, "BN_nnmod failed");
            }
        });
        s
    }

    /// Decode a scalar from an arbitrary-length big-endian byte string,
    /// reduced mod `n`.
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let s = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: BN_bin2bn parses the bytes into the owned BIGNUM; BN_nnmod
            // reduces mod the order.
            unsafe {
                let r = bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), s.0);
                assert!(!r.is_null(), "BN_bin2bn failed");
                let ok = bssl_sys::BN_nnmod(s.0, s.0, g.order, g.ctx);
                assert_eq!(ok, 1, "BN_nnmod failed");
            }
        });
        s
    }

    /// Hash `msgs` (concatenated) to a scalar under domain-separation tag
    /// `dst`, uniformly, via RFC 9380 hash-to-field (`expand_message_xmd` over
    /// SHA-256, `L = 48` bytes for P-256, then reduction mod the order).
    pub fn hash_to_scalar(dst: &[u8], msgs: &[&[u8]]) -> Self {
        const L: usize = 48;
        let uniform = expand_message_xmd(msgs, dst, L);
        Scalar::from_be_bytes_mod_order(&uniform)
    }

    /// Decode a scalar from 64 big-endian bytes, reduced mod `n` (wide
    /// reduction). Matches the sigma-protocols challenge derivation: the
    /// 64-byte squeezed value taken mod the group order.
    pub fn from_wide_bytes_reduced(bytes: &[u8; 2 * SCALAR_BYTES]) -> Self {
        let s = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: BN_bin2bn parses the 64 big-endian bytes into the owned
            // BIGNUM; BN_nnmod reduces mod the group order into [0, n).
            unsafe {
                let r = bssl_sys::BN_bin2bn(bytes.as_ptr(), 2 * SCALAR_BYTES, s.0);
                assert!(!r.is_null(), "BN_bin2bn failed");
                let ok = bssl_sys::BN_nnmod(s.0, s.0, g.order, g.ctx);
                assert_eq!(ok, 1, "BN_nnmod failed");
            }
        });
        s
    }

    /// Encode to 32 big-endian bytes (fixed width).
    pub fn to_bytes(&self) -> [u8; SCALAR_BYTES] {
        let mut out = [0u8; SCALAR_BYTES];
        // SAFETY: BN_bn2bin_padded writes exactly SCALAR_BYTES from the owned
        // BIGNUM; it fails only if the value exceeds the width, impossible for
        // a value reduced mod the 256-bit order.
        let ok =
            unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), SCALAR_BYTES, self.0) };
        assert_eq!(ok, 1, "BN_bn2bin_padded failed");
        out
    }

    /// `self + other mod n`.
    pub fn add(&self, other: &Scalar) -> Scalar {
        let r = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: operands are reduced mod n (invariant of Scalar), the
            // precondition of BN_mod_add_quick; all pointers are owned/valid.
            let ok = unsafe {
                bssl_sys::BN_mod_add_quick(r.0, self.0, other.0, g.order)
            };
            assert_eq!(ok, 1, "BN_mod_add_quick failed");
        });
        r
    }

    /// `self - other mod n`.
    pub fn sub(&self, other: &Scalar) -> Scalar {
        let r = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: operands reduced mod n; BN_mod_sub_quick precondition met.
            let ok = unsafe {
                bssl_sys::BN_mod_sub_quick(r.0, self.0, other.0, g.order)
            };
            assert_eq!(ok, 1, "BN_mod_sub_quick failed");
        });
        r
    }

    /// `self * other mod n`.
    pub fn mul(&self, other: &Scalar) -> Scalar {
        let r = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: BN_mod_mul reduces the product mod the order using scratch
            // ctx; all pointers owned/valid.
            let ok = unsafe {
                bssl_sys::BN_mod_mul(r.0, self.0, other.0, g.order, g.ctx)
            };
            assert_eq!(ok, 1, "BN_mod_mul failed");
        });
        r
    }

    /// `-self mod n`.
    pub fn negate(&self) -> Scalar {
        Scalar::zero().sub(self)
    }

    /// `self^-1 mod n`; returns `None` for zero.
    pub fn invert(&self) -> Option<Scalar> {
        if self.is_zero() {
            return None;
        }
        let r = Scalar::from_raw();
        with_group(|g| {
            // SAFETY: BN_mod_inverse writes the inverse into the owned BIGNUM;
            // non-null return signals success for the nonzero operand.
            let out = unsafe {
                bssl_sys::BN_mod_inverse(r.0, self.0, g.order, g.ctx)
            };
            assert!(!out.is_null(), "BN_mod_inverse failed");
        });
        Some(r)
    }

    /// Constant-time select: returns `b` if `choice`, else `a`. The choice is
    /// consumed by a branchless byte-wise mask over the fixed 32-byte encoding,
    /// so the *selection* itself reveals nothing about `choice` via control
    /// flow. Residual: reconstructing the chosen value through `BIGNUM`
    /// (`BN_bin2bn`) is variable-time in that value's leading-zero profile; the
    /// EC_SCALAR hardening step (see the module header) removes this by carrying
    /// scalars in a fixed-width representation.
    pub fn conditional_select(a: &Scalar, b: &Scalar, choice: Choice) -> Scalar {
        let a_bytes = a.to_bytes();
        let b_bytes = b.to_bytes();
        let mask = 0u8.wrapping_sub(choice.unwrap_u8());
        let mut out = [0u8; SCALAR_BYTES];
        for i in 0..SCALAR_BYTES {
            out[i] = (a_bytes[i] & !mask) | (b_bytes[i] & mask);
        }
        Scalar::from_bytes_reduced(&out)
    }

    /// Whether this scalar is zero.
    pub fn is_zero(&self) -> bool {
        // SAFETY: BN_is_zero reads the owned BIGNUM.
        unsafe { bssl_sys::BN_is_zero(self.0) == 1 }
    }

    /// Constant-time equality. Compares the fixed-width 32-byte encodings with
    /// `subtle::ConstantTimeEq` (constant-time because the width is fixed),
    /// rather than the variable-time `BN_cmp`, so it is safe on secret scalars.
    pub fn ct_eq(&self, other: &Scalar) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.to_bytes().ct_eq(&other.to_bytes()))
    }
}

impl Clone for Scalar {
    fn clone(&self) -> Self {
        // SAFETY: BN_dup allocates a copy owned by the new Scalar.
        let p = unsafe { bssl_sys::BN_dup(self.0) };
        assert!(!p.is_null(), "BN_dup failed");
        Scalar(p)
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by BN_new/BN_dup; free it once.
        unsafe { bssl_sys::BN_free(self.0) };
    }
}

// ---------------------------------------------------------------------------
// RFC 9380 expand_message_xmd over BoringSSL SHA-256.
// ---------------------------------------------------------------------------

/// One-shot SHA-256 via BoringSSL.
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: SHA256 writes 32 bytes to `out` and reads `input.len()` from
    // `input`; both buffers are valid for those spans.
    unsafe {
        bssl_sys::SHA256(input.as_ptr(), input.len(), out.as_mut_ptr());
    }
    out
}

/// RFC 9380 `expand_message_xmd` with SHA-256 (b_in_bytes=32, s_in_bytes=64):
/// produce `len_in_bytes` uniform bytes from the concatenated `msgs` and DST.
fn expand_message_xmd(msgs: &[&[u8]], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32;
    const S_IN_BYTES: usize = 64;
    assert!(dst.len() <= 255, "DST too long");
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(ell <= 255, "expand_message_xmd length too large");

    // DST_prime = DST || I2OSP(len(DST), 1).
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // b_0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime).
    let mut b0_input = vec![0u8; S_IN_BYTES];
    for m in msgs {
        b0_input.extend_from_slice(m);
    }
    b0_input.extend_from_slice(&(len_in_bytes as u16).to_be_bytes());
    b0_input.push(0);
    b0_input.extend_from_slice(&dst_prime);
    let b0 = sha256(&b0_input);

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime).
    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    let mut prev = {
        let mut input = Vec::with_capacity(32 + 1 + dst_prime.len());
        input.extend_from_slice(&b0);
        input.push(1);
        input.extend_from_slice(&dst_prime);
        sha256(&input)
    };
    out.extend_from_slice(&prev);

    // b_i = H((b_0 XOR b_{i-1}) || I2OSP(i, 1) || DST_prime).
    for i in 2..=ell {
        let mut input = Vec::with_capacity(32 + 1 + dst_prime.len());
        for j in 0..32 {
            input.push(b0[j] ^ prev[j]);
        }
        input.push(i as u8);
        input.extend_from_slice(&dst_prime);
        prev = sha256(&input);
        out.extend_from_slice(&prev);
    }

    out.truncate(len_in_bytes);
    out
}

// ---------------------------------------------------------------------------
// Point: an element of the P-256 group.
// ---------------------------------------------------------------------------

/// A P-256 curve point.
pub struct Point(*mut bssl_sys::EC_POINT);

impl Point {
    fn from_raw() -> Self {
        with_group(|g| {
            // SAFETY: EC_POINT_new allocates a point in the built-in group,
            // owned by this Point.
            let p = unsafe { bssl_sys::EC_POINT_new(g.group) };
            assert!(!p.is_null(), "EC_POINT allocation failed");
            Point(p)
        })
    }

    /// The standard P-256 base point `G`.
    pub fn generator() -> Self {
        let mut one = [0u8; SCALAR_BYTES];
        one[SCALAR_BYTES - 1] = 1;
        Point::mul_generator(&Scalar::from_bytes_reduced(&one))
    }

    /// The identity (point at infinity).
    pub fn identity() -> Self {
        let p = Point::from_raw();
        with_group(|g| {
            // SAFETY: sets the owned point to the group identity.
            let ok = unsafe {
                bssl_sys::EC_POINT_set_to_infinity(g.group, p.0)
            };
            assert_eq!(ok, 1, "EC_POINT_set_to_infinity failed");
        });
        p
    }

    /// `generator * k`.
    pub fn mul_generator(k: &Scalar) -> Self {
        let r = Point::from_raw();
        with_group(|g| {
            // SAFETY: EC_POINT_mul with (n=k, q=NULL, m=NULL) computes G*k.
            let ok = unsafe {
                bssl_sys::EC_POINT_mul(
                    g.group, r.0, k.0, ptr::null(), ptr::null(), g.ctx,
                )
            };
            assert_eq!(ok, 1, "EC_POINT_mul (generator) failed");
        });
        r
    }

    /// `self * k`.
    pub fn mul(&self, k: &Scalar) -> Self {
        let r = Point::from_raw();
        with_group(|g| {
            // SAFETY: EC_POINT_mul with (n=NULL, q=self, m=k) computes self*k.
            let ok = unsafe {
                bssl_sys::EC_POINT_mul(
                    g.group, r.0, ptr::null(), self.0, k.0, g.ctx,
                )
            };
            assert_eq!(ok, 1, "EC_POINT_mul (point) failed");
        });
        r
    }

    /// `self + other`.
    pub fn add(&self, other: &Point) -> Self {
        let r = Point::from_raw();
        with_group(|g| {
            // SAFETY: EC_POINT_add sums two owned points in the group.
            let ok = unsafe {
                bssl_sys::EC_POINT_add(g.group, r.0, self.0, other.0, g.ctx)
            };
            assert_eq!(ok, 1, "EC_POINT_add failed");
        });
        r
    }

    /// `-self` (the inverse point).
    pub fn negate(&self) -> Point {
        let r = self.clone();
        with_group(|g| {
            // SAFETY: EC_POINT_invert negates the owned point in place.
            let ok = unsafe { bssl_sys::EC_POINT_invert(g.group, r.0, g.ctx) };
            assert_eq!(ok, 1, "EC_POINT_invert failed");
        });
        r
    }

    /// Constant-time select: returns `b` if `choice`, else `a`. Computed as
    /// `a + (b - a)·s`, where `s ∈ {0, 1}` is chosen constant-time from
    /// `choice`. This avoids the SEC1 identity-encoding problem (a byte-wise
    /// select is impossible because the identity encodes to one byte) and is
    /// constant-time in `choice`: the same point operations run regardless (a
    /// difference, a constant-time scalar select, a scalar-mul via BoringSSL's
    /// constant-time ladder, and an add).
    pub fn conditional_select(a: &Point, b: &Point, choice: Choice) -> Point {
        let diff = b.add(&a.negate());
        let s = Scalar::conditional_select(&Scalar::zero(), &Scalar::one(), choice);
        a.add(&diff.mul(&s))
    }

    /// Whether this point is the identity.
    pub fn is_identity(&self) -> bool {
        self.eq(&Point::identity())
    }

    /// Hash `msg` to a curve point under domain separation tag `dst`
    /// (P256_XMD:SHA-256_SSWU_RO_, RFC 9380).
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Self {
        let r = Point::from_raw();
        with_group(|g| {
            // SAFETY: BoringSSL's hash-to-curve writes a valid point into the
            // owned output; slices provide valid ptr/len pairs.
            let ok = unsafe {
                bssl_sys::EC_hash_to_curve_p256_xmd_sha256_sswu(
                    g.group,
                    r.0,
                    dst.as_ptr(),
                    dst.len(),
                    msg.as_ptr(),
                    msg.len(),
                )
            };
            assert_eq!(ok, 1, "hash_to_curve failed");
        });
        r
    }

    /// Compressed 33-byte encoding. The identity encodes as 33 zero bytes
    /// (matching the `elliptic-curve` `GroupEncoding` the reference uses, and
    /// avoiding the 1-byte SEC1 identity form that would make a fixed-width
    /// buffer panic — a remote-DoS if an attacker supplies an identity
    /// commitment that gets hashed into a transcript).
    pub fn to_bytes(&self) -> [u8; POINT_BYTES] {
        if self.is_identity() {
            return [0u8; POINT_BYTES];
        }
        let mut out = [0u8; POINT_BYTES];
        with_group(|g| {
            // SAFETY: point2oct writes exactly POINT_BYTES for compressed form
            // (returns the byte count, 0 on error).
            let n = unsafe {
                bssl_sys::EC_POINT_point2oct(
                    g.group,
                    self.0,
                    POINT_CONVERSION_COMPRESSED,
                    out.as_mut_ptr(),
                    POINT_BYTES,
                    g.ctx,
                )
            };
            assert_eq!(n, POINT_BYTES, "point2oct wrote unexpected length");
        });
        out
    }

    /// Decode a compressed 33-byte encoding; `None` if not a valid point. The
    /// all-zero encoding decodes to the identity (round-tripping [`to_bytes`]
    /// and matching the reference `GroupEncoding`).
    pub fn from_bytes(bytes: &[u8; POINT_BYTES]) -> Option<Self> {
        if bytes.iter().all(|&b| b == 0) {
            return Some(Point::identity());
        }
        let p = Point::from_raw();
        let ok = with_group(|g| {
            // SAFETY: oct2point validates and parses the encoding into the
            // owned point; returns 0 for an invalid encoding.
            unsafe {
                bssl_sys::EC_POINT_oct2point(
                    g.group, p.0, bytes.as_ptr(), POINT_BYTES, g.ctx,
                )
            }
        });
        (ok == 1).then_some(p)
    }

    /// Whether two points are equal.
    pub fn eq(&self, other: &Point) -> bool {
        with_group(|g| {
            // SAFETY: EC_POINT_cmp returns 0 when the points are equal.
            unsafe { bssl_sys::EC_POINT_cmp(g.group, self.0, other.0, g.ctx) == 0 }
        })
    }
}

impl Clone for Point {
    fn clone(&self) -> Self {
        with_group(|g| {
            // SAFETY: EC_POINT_dup copies the point into a new owned allocation.
            let p = unsafe { bssl_sys::EC_POINT_dup(self.0, g.group) };
            assert!(!p.is_null(), "EC_POINT_dup failed");
            Point(p)
        })
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by EC_POINT_new/dup; free it once.
        unsafe { bssl_sys::EC_POINT_free(self.0) };
    }
}
