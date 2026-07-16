// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `sigma_boring`: the MoLE sigma-protocol primitives over Chromium's in-tree
//! BoringSSL. The first landed layer is P-256 group and scalar arithmetic
//! (see [`bssl`]); the duplex-sponge Fiat-Shamir codec and the
//! LinearRelation / Schnorr / composition layers build on top of it, replacing
//! the vendored `sigma-proofs` + `curve25519-dalek` stack.

pub mod bssl;
pub mod codec;
pub mod composition;
pub mod keccak;
pub mod linear_relation;
pub mod shake;

pub use bssl::{Point, Scalar, POINT_BYTES, SCALAR_BYTES};
pub use keccak::keccak_f1600;
pub use shake::Transcript;

#[cfg(test)]
mod differential_tests {
    //! Differential tests pinning the BoringSSL P-256 layer against the
    //! `p256` crate (the reference this port replaces). Same inputs must give
    //! the same scalar arithmetic and the same compressed point encodings.

    use super::*;
    use p256::elliptic_curve::ops::Reduce;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::PrimeField;

    // A fixed 32-byte big-endian value, as both a bssl Scalar and a p256 one.
    fn pair(bytes: &[u8; 32]) -> (Scalar, p256::Scalar) {
        let ours = Scalar::from_bytes_reduced(bytes);
        let theirs =
            <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(bytes.into());
        (ours, theirs)
    }

    fn theirs_bytes(s: &p256::Scalar) -> [u8; 32] {
        s.to_repr().into()
    }

    #[test]
    fn scalar_reduce_and_roundtrip_match() {
        for seed in 0u8..32 {
            let bytes = [seed.wrapping_mul(7).wrapping_add(1); 32];
            let (ours, theirs) = pair(&bytes);
            assert_eq!(ours.to_bytes(), theirs_bytes(&theirs), "reduce seed {seed}");
        }
    }

    #[test]
    fn scalar_add_sub_mul_match() {
        let a_bytes = [3u8; 32];
        let b_bytes = [0xABu8; 32];
        let (a, ta) = pair(&a_bytes);
        let (b, tb) = pair(&b_bytes);

        assert_eq!(a.add(&b).to_bytes(), theirs_bytes(&(ta + tb)), "add");
        assert_eq!(a.sub(&b).to_bytes(), theirs_bytes(&(ta - tb)), "sub");
        assert_eq!(a.mul(&b).to_bytes(), theirs_bytes(&(ta * tb)), "mul");
        assert_eq!(a.negate().to_bytes(), theirs_bytes(&(-ta)), "negate");
    }

    #[test]
    fn scalar_invert_matches() {
        let a_bytes = [0x11u8; 32];
        let (a, ta) = pair(&a_bytes);
        let inv = a.invert().expect("nonzero invertible");
        let tinv = ta.invert().unwrap();
        assert_eq!(inv.to_bytes(), theirs_bytes(&tinv), "invert");
        // a * a^-1 == 1.
        assert!(a.mul(&inv).ct_eq(&Scalar::from_bytes_reduced(&{
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        })));
    }

    #[test]
    fn zero_invert_is_none() {
        assert!(Scalar::zero().invert().is_none());
        assert!(Scalar::zero().is_zero());
    }

    #[test]
    fn generator_mul_matches() {
        for seed in 1u8..16 {
            let bytes = [seed.wrapping_mul(31).wrapping_add(2); 32];
            let (ours, theirs) = pair(&bytes);
            let our_point = Point::mul_generator(&ours);
            let their_point =
                p256::ProjectivePoint::GENERATOR * theirs;
            let their_enc =
                their_point.to_affine().to_encoded_point(true);
            assert_eq!(
                &our_point.to_bytes()[..],
                their_enc.as_bytes(),
                "G*k seed {seed}"
            );
        }
    }

    #[test]
    fn point_add_and_scalar_mul_match() {
        let k1 = pair(&[5u8; 32]);
        let k2 = pair(&[9u8; 32]);
        // P = G*k1, Q = P*k2, R = P + Q.
        let p = Point::mul_generator(&k1.0);
        let tp = p256::ProjectivePoint::GENERATOR * k1.1;
        let q = p.mul(&k2.0);
        let tq = tp * k2.1;
        let r = p.add(&q);
        let tr = tp + tq;

        let enc = |pp: &p256::ProjectivePoint| {
            pp.to_affine().to_encoded_point(true).as_bytes().to_vec()
        };
        assert_eq!(&q.to_bytes()[..], &enc(&tq)[..], "P*k2");
        assert_eq!(&r.to_bytes()[..], &enc(&tr)[..], "P+Q");
    }

    #[test]
    fn point_encode_roundtrip() {
        let k = Scalar::from_bytes_reduced(&[7u8; 32]);
        let p = Point::mul_generator(&k);
        let bytes = p.to_bytes();
        let decoded = Point::from_bytes(&bytes).expect("valid encoding");
        assert!(p.eq(&decoded));
    }

    #[test]
    fn hash_to_curve_matches_reference() {
        // RFC 9380 P256_XMD:SHA-256_SSWU_RO_; compare BoringSSL against the
        // p256 crate's hash-to-curve for the same message and DST.
        use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
        let dst = b"MOLE-sigma-test-v1";
        for msg in [&b""[..], b"abc", b"a longer test message for h2c"] {
            let ours = Point::hash_to_curve(msg, dst);
            let theirs = p256::NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(
                &[msg], &[dst],
            )
            .unwrap();
            let their_enc = theirs.to_affine().to_encoded_point(true);
            assert_eq!(
                &ours.to_bytes()[..],
                their_enc.as_bytes(),
                "h2c msg {msg:?}"
            );
        }
    }

    #[test]
    fn conditional_select_picks_correctly() {
        let a = Scalar::from_bytes_reduced(&[0x11; 32]);
        let b = Scalar::from_bytes_reduced(&[0x22; 32]);
        use subtle::Choice;
        assert!(Scalar::conditional_select(&a, &b, Choice::from(0)).ct_eq(&a));
        assert!(Scalar::conditional_select(&a, &b, Choice::from(1)).ct_eq(&b));
        let g = Point::mul_generator(&a);
        let h = Point::mul_generator(&b);
        assert!(Point::conditional_select(&g, &h, Choice::from(0)).eq(&g));
        assert!(Point::conditional_select(&g, &h, Choice::from(1)).eq(&h));
        // identity accumulator must select correctly (the arithmetic path).
        assert!(Point::conditional_select(&Point::identity(), &g, Choice::from(1)).eq(&g));
        assert!(Point::conditional_select(&Point::identity(), &g, Choice::from(0)).is_identity());
    }

    #[test]
    fn identity_encoding_matches_reference_and_roundtrips() {
        use p256::elliptic_curve::group::GroupEncoding;
        // The identity must encode as the reference's 33 zero bytes (not the
        // 1-byte SEC1 form that would panic), and round-trip.
        let id = Point::identity();
        let their_id: [u8; 33] = p256::ProjectivePoint::IDENTITY.to_bytes().into();
        assert_eq!(id.to_bytes(), their_id, "identity encoding");
        assert_eq!(id.to_bytes(), [0u8; 33]);
        let decoded = Point::from_bytes(&id.to_bytes()).expect("identity decodes");
        assert!(decoded.is_identity());
    }

    #[test]
    fn generator_matches_reference() {
        let g = Point::generator();
        let their_g = p256::ProjectivePoint::GENERATOR
            .to_affine()
            .to_encoded_point(true);
        assert_eq!(&g.to_bytes()[..], their_g.as_bytes());
    }

    #[test]
    fn hash_to_scalar_matches_reference() {
        // RFC 9380 hash-to-field for a P-256 scalar, vs the p256 crate — the
        // primitive ihat-rs's Fiat-Shamir and OR-proof challenges use.
        use p256::elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
        for (dst, msg) in [
            (&b"MOLE-IHAT-P256:fiat-shamir-getend:v1"[..], &b""[..]),
            (b"MOLE-IHAT-P256:pedersen-generator-H:v1", b"epoch-1"),
            (b"some-dst", b"a longer message for hash to field testing"),
        ] {
            let ours = Scalar::hash_to_scalar(dst, &[msg]);
            let mut theirs = [p256::Scalar::from(0u64)];
            hash_to_field::<ExpandMsgXmd<sha2::Sha256>, p256::Scalar>(
                &[msg],
                &[dst],
                &mut theirs,
            )
            .unwrap();
            let their_bytes: [u8; 32] = theirs[0].to_repr().into();
            assert_eq!(ours.to_bytes(), their_bytes, "hash_to_scalar dst {dst:?}");
        }
    }

    #[test]
    fn random_scalars_are_distinct_and_invertible() {
        let a = Scalar::random();
        let b = Scalar::random();
        assert!(!a.ct_eq(&b), "two random scalars collided");
        assert!(a.invert().is_some());
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn from_canonical_bytes_matches_reference_rejection() {
        // Canonical scalar decoding must accept exactly the values `< n` and
        // reject `>= n`, agreeing with the p256 crate's `from_repr` (which the
        // reference sigma-rs uses to deserialize wire scalars). This is what
        // closes scalar malleability on proof responses / branch challenges.
        let accept_reject = |bytes: [u8; 32], want: bool| {
            assert_eq!(Scalar::from_canonical_bytes(&bytes).is_some(), want);
            assert_eq!(
                bool::from(p256::Scalar::from_repr(bytes.into()).is_some()),
                want,
                "reference disagreement"
            );
        };
        // A small in-range value: accepted.
        accept_reject(hex32("0000000000000000000000000000000000000000000000000000000000000007"), true);
        // All-ones (2^256-1 > n): rejected.
        accept_reject([0xff; 32], false);
        // The order n itself (== n): rejected.
        accept_reject(hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"), false);
        // n - 1: the largest canonical value, accepted.
        accept_reject(hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"), true);
    }
}
