// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Differential interop tests: the reference `ihat-rs` (on the `p256` crate)
//! acts as the prover, and the ported BoringSSL verifier must accept its
//! `Presentation` wire bytes byte-for-byte — the parity gate the prune plan
//! requires before the vendored `ihat` crate can be deleted. Exercises the
//! whole verify path end to end (wire decode, DLEQ Fiat–Shamir over
//! hash-to-curve/scalar, and the CDS OR-proof), so any divergence in the
//! ported hashing or group arithmetic surfaces here.

use crate::{Point, Presentation};
use ihat::anchor::{AnchorPublicKey, AnchorSecretKey};
use ihat::{Params, WireFormat};

// Both crates name their issuance-state types identically; keep them
// fully-qualified below (`ihat::client::…` for the reference prover,
// `crate::client::…` for the ported one) so it's unambiguous which side runs.

/// A deterministic, reproducible RNG for the reference prover. Cryptographic
/// quality is irrelevant here — this test checks wire + verify interop, not
/// randomness — so a splitmix64 stream avoids depending on the OS RNG and keeps
/// the vector reproducible. `CryptoRng` is a marker the reference API requires.
struct SplitMix64(u64);

impl rand_core::RngCore for SplitMix64 {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for SplitMix64 {}

/// Run the reference issuance + redemption, returning the presentation wire
/// bytes, the accepted anchor keys' wire bytes, and the binding used.
fn reference_presentation(
    real_index: usize,
    n_anchors: usize,
) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    let pp = Params::standard();
    let mut rng = SplitMix64(0x0123_4567_89AB_CDEF);

    let anchors: Vec<AnchorSecretKey> =
        (0..n_anchors).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted: Vec<_> = anchors.iter().map(|k| k.public_key(&pp)).collect();

    // Four-message GetEnd issuance with the chosen anchor.
    let issuer = &anchors[real_index];
    let (request, client) = ihat::client::ClientNeedsSignature::request(
        b"nullifier-42".to_vec(),
        b"epoch-7".to_vec(),
        &mut rng,
    );
    let (signature, anchor) = request.sign(&pp, issuer, &mut rng);
    let (proof_request, client) =
        client.request_proof(&pp, issuer.public_key(&pp), signature);
    let proof = anchor.prove(proof_request);
    let issued = client.finalize(&pp, proof).expect("honest issuance succeeds");

    // Redeem: present with a 1-of-n OR-proof hiding which anchor issued.
    let binding = b"challenge-digest-v1".to_vec();
    let presentation = issued.show(&accepted, real_index, &binding, &mut rng);
    assert!(
        presentation.verify(&pp, &accepted, &binding),
        "reference must accept its own presentation"
    );

    let pres_bytes = presentation.to_bytes().expect("presentation encodes");
    let accepted_bytes: Vec<Vec<u8>> =
        accepted.iter().map(|k| k.to_bytes().expect("key encodes")).collect();
    (pres_bytes, accepted_bytes, binding)
}

fn ported_keys(accepted_bytes: &[Vec<u8>]) -> Vec<Point> {
    accepted_bytes
        .iter()
        .map(|b| crate::wire::decode_anchor_key(b).expect("anchor key parses"))
        .collect()
}

#[test]
fn ported_verifier_accepts_reference_presentation() {
    // For each possible hidden issuer, the reference produces a presentation and
    // the ported (BoringSSL) verifier must accept it — proving the ported wire
    // decode, DLEQ check, and OR-proof are byte-compatible with `ihat-rs`.
    for n in [1usize, 2, 4] {
        for real in 0..n {
            let (pres_bytes, accepted_bytes, binding) = reference_presentation(real, n);
            let keys = ported_keys(&accepted_bytes);
            let presentation =
                Presentation::from_wire(&pres_bytes).expect("port parses reference wire");
            assert!(
                presentation.verify(&keys, &binding),
                "ported verifier must accept reference presentation (n={n}, real={real})"
            );
        }
    }
}

#[test]
fn ported_verifier_rejects_wrong_binding() {
    // The OR-proof binds to the exact `binding`; the ported verifier must reject
    // any other, exactly as the reference does (Fiat–Shamir soundness).
    let (pres_bytes, accepted_bytes, _binding) = reference_presentation(1, 3);
    let keys = ported_keys(&accepted_bytes);
    let presentation = Presentation::from_wire(&pres_bytes).unwrap();
    assert!(!presentation.verify(&keys, b"a-different-binding"));
}

#[test]
fn ported_verifier_rejects_tampered_presentation() {
    // Flip a byte in the response region; the presentation must be rejected,
    // whether it fails to decode (non-canonical scalar) or fails verification.
    let (pres_bytes, accepted_bytes, binding) = reference_presentation(0, 2);
    let keys = ported_keys(&accepted_bytes);
    let mut bad = pres_bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let rejected = match Presentation::from_wire(&bad) {
        Ok(p) => !p.verify(&keys, &binding),
        Err(_) => true,
    };
    assert!(rejected, "tampered presentation must not verify");
}

#[test]
fn ported_verifier_rejects_wrong_accepted_set() {
    // A presentation whose true issuer is not in the accepted set must fail: the
    // OR-proof cannot bind X_hat to any accepted key. Replace the real issuer's
    // key (keeping the set size, so this isn't a length-mismatch rejection) and
    // require the ported verifier to reject.
    let (pres_bytes, accepted_bytes, binding) = reference_presentation(0, 3);
    let presentation = Presentation::from_wire(&pres_bytes).unwrap();
    let mut swapped = accepted_bytes.clone();
    swapped[0] = swapped[1].clone(); // drop the real issuer, same length
    let keys = ported_keys(&swapped);
    assert!(!presentation.verify(&keys, &binding));
}

#[test]
fn issued_endorsement_survives_serialization() {
    // Persistence foundation: the finished endorsement plus its secret witness
    // gamma must survive serialize/deserialize and still produce a valid
    // presentation — what a persisted endorsement store requires.
    let pp = Params::standard();
    let mut rng = SplitMix64(0xDADA_1234_5678_9ABC);
    let (n, real) = (3usize, 1usize);
    let anchors: Vec<AnchorSecretKey> =
        (0..n).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted_ref: Vec<AnchorPublicKey> = anchors.iter().map(|k| k.public_key(&pp)).collect();
    let accepted_pts = ported_keys(
        &accepted_ref.iter().map(|k| k.to_bytes().unwrap()).collect::<Vec<_>>(),
    );
    let issuer = &anchors[real];
    let issuer_pt =
        crate::wire::decode_anchor_key(&issuer.public_key(&pp).to_bytes().unwrap()).unwrap();

    // Ported client issuance against the reference anchor.
    let (sig_req, client) =
        crate::client::ClientNeedsSignature::request(b"nf".to_vec(), b"epoch".to_vec());
    let sig_req_ref = ihat::SignatureRequest::from_bytes(&sig_req.to_wire().unwrap()).unwrap();
    let (signature_ref, anchor) = sig_req_ref.sign(&pp, issuer, &mut rng);
    let signature = crate::Signature::from_wire(&signature_ref.to_bytes().unwrap()).unwrap();
    let (proof_req, client) = client.request_proof(issuer_pt, signature);
    let proof_req_ref = ihat::ProofRequest::from_bytes(&proof_req.to_wire().unwrap()).unwrap();
    let proof_ref = anchor.prove(proof_req_ref);
    let proof = crate::Proof::from_wire(&proof_ref.to_bytes().unwrap()).unwrap();
    let issued = client.finalize(proof).unwrap();

    // Serialize (with gamma), restore, and require byte-identical re-encoding.
    let bytes = issued.to_wire().unwrap();
    let restored = crate::IssuedEndorsement::from_wire(&bytes).unwrap();
    assert_eq!(restored.to_wire().unwrap(), bytes, "round-trip byte-identical");

    // The restored endorsement must present validly (proves gamma survived).
    let binding = b"persist-binding";
    let presentation = restored.show(&accepted_pts, real, binding);
    let presentation_ref =
        ihat::Presentation::from_bytes(&presentation.to_wire().unwrap()).unwrap();
    assert!(
        presentation_ref.verify(&pp, &accepted_ref, binding),
        "restored endorsement must present validly"
    );
}

#[test]
fn reference_verifier_accepts_ported_client_presentation() {
    // The other direction: the ported BoringSSL *client* runs the full issuance
    // state machine against the reference `ihat-rs` anchor (messages crossing
    // through the shared wire format), then the reference verifier must accept
    // the resulting presentation. This exercises the ported issuance blinding,
    // `finalize` unblinding, and `show` — proving the ported client produces
    // byte-compatible, valid endorsements.
    for n in [1usize, 2, 4] {
        for real in 0..n {
            let pp = Params::standard();
            let mut rng = SplitMix64(0x00C0_FFEE_1234_5678);

            // Reference anchors + accepted set (as reference keys and as ported
            // group elements, via the shared wire form).
            let anchors: Vec<AnchorSecretKey> =
                (0..n).map(|_| AnchorSecretKey::random(&mut rng)).collect();
            let accepted_ref: Vec<AnchorPublicKey> =
                anchors.iter().map(|k| k.public_key(&pp)).collect();
            let accepted_pts: Vec<Point> = accepted_ref
                .iter()
                .map(|k| crate::wire::decode_anchor_key(&k.to_bytes().unwrap()).unwrap())
                .collect();
            let issuer = &anchors[real];
            let issuer_pt =
                crate::wire::decode_anchor_key(&issuer.public_key(&pp).to_bytes().unwrap())
                    .unwrap();
            let binding = b"ported-client-binding";

            // Ported client → reference anchor, message by message.
            let (sig_req, client) = crate::client::ClientNeedsSignature::request(
                b"nf-9".to_vec(),
                b"epoch-3".to_vec(),
            );
            let sig_req_ref =
                ihat::SignatureRequest::from_bytes(&sig_req.to_wire().unwrap()).unwrap();
            let (signature_ref, anchor) = sig_req_ref.sign(&pp, issuer, &mut rng);

            let signature =
                crate::Signature::from_wire(&signature_ref.to_bytes().unwrap()).unwrap();
            let (proof_req, client) = client.request_proof(issuer_pt.clone(), signature);
            let proof_req_ref =
                ihat::ProofRequest::from_bytes(&proof_req.to_wire().unwrap()).unwrap();
            let proof_ref = anchor.prove(proof_req_ref);

            let proof = crate::Proof::from_wire(&proof_ref.to_bytes().unwrap()).unwrap();
            let issued = client
                .finalize(proof)
                .expect("ported finalize must accept the honest anchor proof");
            let presentation = issued.show(&accepted_pts, real, binding);

            // Reference verifier must accept the ported client's presentation.
            let presentation_ref =
                ihat::Presentation::from_bytes(&presentation.to_wire().unwrap()).unwrap();
            assert!(
                presentation_ref.verify(&pp, &accepted_ref, binding),
                "reference verifier must accept ported client presentation (n={n}, real={real})"
            );
        }
    }
}
