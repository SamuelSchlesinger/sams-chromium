// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `act_boring`: Anonymous Credit Tokens on Chromium's in-tree BoringSSL, via
//! [`sigma_boring`]. BoringSSL provides NIST P-256 but not ristretto255, so
//! this is the **ACT(P-256, SHAKE128)** ciphersuite — a P-256 re-instantiation
//! of the scheme in `third_party/mole/anonymous-credit-tokens` (which is over
//! ristretto255), not a byte-for-byte reproduction. It replaces that vendored
//! crate (and its `curve25519-dalek` dependency) in the MoLE credential pool
//! once complete.
//!
//! This first landed layer is the ciphersuite foundation: the generator basis
//! ([`params`]) and the proofs of knowledge ([`proofs`]) that every ACT
//! operation composes — issuance, spend (with base-3 range proofs), and refund
//! build on these. Correctness here is validated by prove/verify round-trips
//! over `sigma_boring`, the same way the reference validates its ristretto255
//! relations (there is no cross-curve byte oracle: this defines a new suite).

pub mod issuance;
pub mod params;
pub mod proofs;
pub mod range;
pub mod spend;
pub mod wire;

pub use issuance::{
    CreditToken, Error, IssuanceRequest, IssuanceResponse, PreIssuance, PrivateKey, PublicKey,
};
pub use params::Params;
pub use sigma_boring::{Point, Scalar};
pub use wire::WireError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proofs::{act_protocol_id, dleq, pedersen, session};

    fn distinct(encodings: &[[u8; sigma_boring::POINT_BYTES]]) -> bool {
        let mut v = encodings.to_vec();
        v.sort_unstable();
        v.dedup();
        v.len() == encodings.len()
    }

    #[test]
    fn generators_are_distinct_and_reproducible() {
        let ds = b"ACT-v1:test-org:svc:prod:2026-01-01";
        let p1 = Params::from_domain_separator(ds);
        let p2 = Params::from_domain_separator(ds);
        // Deterministic in the domain separator.
        assert_eq!(p1.h1.to_bytes(), p2.h1.to_bytes());
        assert_eq!(p1.h4.to_bytes(), p2.h4.to_bytes());
        // The base point and H1..H4 are five distinct group elements (no known
        // discrete-log relations among them).
        let g = Point::generator();
        assert!(distinct(&[
            g.to_bytes(),
            p1.h1.to_bytes(),
            p1.h2.to_bytes(),
            p1.h3.to_bytes(),
            p1.h4.to_bytes(),
        ]));
        // A different domain separator yields a different basis.
        let p3 = Params::from_domain_separator(b"ACT-v1:other:svc:prod:2026-01-01");
        assert_ne!(p1.h1.to_bytes(), p3.h1.to_bytes());
    }

    #[test]
    fn issuance_request_pedersen_pok_roundtrips() {
        // The ACT issuance-request proof of knowledge: the client commits
        // big_K = k·H2 + r·H3 and proves knowledge of (k, r) via the Pedersen
        // relation, over sigma_boring/P-256.
        let params = Params::from_domain_separator(b"ACT-v1:test-org:svc:prod:2026-01-01");
        let k = Scalar::random();
        let r = Scalar::random();
        let big_k = params.h2.mul(&k).add(&params.h3.mul(&r));

        let (relation, statement) =
            pedersen(params.h2.clone(), params.h3.clone(), big_k.clone());
        let sess = session(&params, b"request", &[]);
        let pid = act_protocol_id();
        let proof = relation.prove_compact(&[k.clone(), r.clone()], &pid, &sess, &statement);
        assert!(relation
            .verify_compact(&pid, &sess, &statement, &proof)
            .unwrap());

        // A proof produced under a wrong witness must not verify against the
        // (real) committed big_K — soundness.
        let (bad_relation, bad_statement) =
            pedersen(params.h2.clone(), params.h3.clone(), big_k);
        let bad_proof =
            bad_relation.prove_compact(&[Scalar::random(), r], &pid, &sess, &bad_statement);
        assert!(!bad_relation
            .verify_compact(&pid, &sess, &bad_statement, &bad_proof)
            .unwrap());
    }

    #[test]
    fn issuance_response_dleq_roundtrips() {
        // DLEQ(P, Q, X, Y): X = k·P and Y = k·Q — the shape of the issuer's
        // response proof (a shared discrete log against two bases).
        let params = Params::from_domain_separator(b"ACT-v1:dleq:svc:prod:2026-01-01");
        let g = Point::generator();
        let k = Scalar::random();
        let x = g.mul(&k);
        let y = params.h1.mul(&k);

        let (relation, statement) = dleq(g.clone(), params.h1.clone(), x, y);
        let pid = act_protocol_id();
        let sess = session(&params, b"respond", &[]);
        let proof = relation.prove_compact(&[k], &pid, &sess, &statement);
        assert!(relation
            .verify_compact(&pid, &sess, &statement, &proof)
            .unwrap());
    }

    #[test]
    fn issuance_roundtrip_produces_valid_token() {
        // Full ACT issuance over BoringSSL: client requests, issuer signs c
        // credits with a DLEQ proof, client verifies and unblinds to a token
        // carrying exactly c credits (and its own k, r).
        let params = Params::from_domain_separator(b"ACT-v1:issue:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(7);

        let response = issuer
            .issue::<8>(&params, &request, 20, ctx.clone())
            .expect("honest issuance succeeds");
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .expect("honest response yields a token");
        assert!(token.credits().ct_eq(&Scalar::from_u64(20)), "token holds 20 credits");
    }

    #[test]
    fn issuance_rejects_tampered_request_proof() {
        // The issuer must reject a request whose PoK does not verify.
        let params = Params::from_domain_separator(b"ACT-v1:issue:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let mut request = pre.request(&params);
        let last = request.pok.len() - 1;
        request.pok[last] ^= 0x01;
        assert!(matches!(
            issuer.issue::<8>(&params, &request, 20, Scalar::from_u64(7)),
            Err(Error::InvalidIssuanceRequestProof)
        ));
    }

    #[test]
    fn issuance_rejects_wrong_issuer_key() {
        // A response verified against the wrong issuer public key must fail: the
        // client's DLEQ reconstruction of X_G uses W, so a different key breaks
        // it.
        let params = Params::from_domain_separator(b"ACT-v1:issue:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let other = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(7);
        let response = issuer.issue::<8>(&params, &request, 20, ctx.clone()).unwrap();
        assert!(matches!(
            pre.to_credit_token(&params, other.public(), &request, &response, ctx),
            Err(Error::InvalidIssuanceResponseProof)
        ));
    }

    #[test]
    fn issuance_rejects_amount_over_ceiling() {
        // c must lie in [0, 3^D). With D=2 the ceiling is 8.
        let params = Params::from_domain_separator(b"ACT-v1:issue:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let request = PreIssuance::random().request(&params);
        assert!(matches!(
            issuer.issue::<2>(&params, &request, 9, Scalar::from_u64(1)),
            Err(Error::AmountTooBig)
        ));
    }

    #[test]
    fn range_proof_accepts_in_range_values() {
        // Values in [0, 3^d) — including the endpoints 0 and 3^d - 1 — must
        // produce proofs the verifier accepts.
        use crate::range::{prove_range, verify_range};
        let params = Params::from_domain_separator(b"ACT-v1:range:svc:prod:2026-01-01");
        let d = 4; // ceiling 3^4 = 81
        for v in [0u128, 1, 40, 80] {
            let (commitment, proof) = prove_range(&params, v, Scalar::random(), d);
            assert!(verify_range(&params, &commitment, &proof, d), "v={v} must verify");
        }
    }

    #[test]
    fn range_proof_rejects_out_of_range_value() {
        // v >= 3^d: the digits sum to v mod 3^d, so the consistency equation
        // (which binds the full v) fails and the proof does not verify.
        use crate::range::{prove_range, verify_range};
        let params = Params::from_domain_separator(b"ACT-v1:range:svc:prod:2026-01-01");
        let d = 4; // ceiling 81
        let (commitment, proof) = prove_range(&params, 90, Scalar::random(), d);
        assert!(!verify_range(&params, &commitment, &proof, d));
    }

    #[test]
    fn range_proof_rejects_mismatched_commitment() {
        // A proof for one value must not verify against a commitment to another
        // (the value witness is bound to V).
        use crate::range::{prove_range, verify_range};
        let params = Params::from_domain_separator(b"ACT-v1:range:svc:prod:2026-01-01");
        let d = 4;
        let (_c50, proof50) = prove_range(&params, 50, Scalar::random(), d);
        let (c51, _p51) = prove_range(&params, 51, Scalar::random(), d);
        assert!(!verify_range(&params, &c51, &proof50, d));
    }

    #[test]
    fn range_proof_rejects_tampered_proof() {
        use crate::range::{prove_range, verify_range};
        let params = Params::from_domain_separator(b"ACT-v1:range:svc:prod:2026-01-01");
        let d = 4;
        let (commitment, mut proof) = prove_range(&params, 40, Scalar::random(), d);
        let last = proof.pok.len() - 1;
        proof.pok[last] ^= 0x01;
        assert!(!verify_range(&params, &commitment, &proof, d));
    }

    #[test]
    fn spend_roundtrip_verifies() {
        // Full ACT flow: issue a 20-credit token, then spend 10 (no top-up).
        // The issuer must accept the spend proof.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:spend:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();

        let d = 4; // ceiling 3^4 = 81; balance 20, v1=10, v2=20 in range
        let (spend_proof, _prerefund) = prove_spend(&token, &params, 10, 0, d).unwrap();
        assert!(issuer.verify_spend(&params, &spend_proof, d), "honest spend must verify");
    }

    #[test]
    fn spend_with_topup_verifies() {
        // A declared top-up a=5: v1 = c - s = 12, v2 = c + a = 20, both in range.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:spend:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 15, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let d = 4;
        let (spend_proof, _pr) = prove_spend(&token, &params, 3, 5, d).unwrap();
        assert!(issuer.verify_spend(&params, &spend_proof, d));
    }

    #[test]
    fn spend_rejects_overspend() {
        // Spending more than the balance: c - s underflows, rejected at prove.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:spend:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        assert!(matches!(
            prove_spend(&token, &params, 25, 0, 4),
            Err(Error::InvalidAmount)
        ));
    }

    #[test]
    fn spend_rejects_tampered_proof_and_wrong_issuer() {
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:spend:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let other = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let d = 4;
        let (mut spend_proof, _pr) = prove_spend(&token, &params, 10, 0, d).unwrap();
        // A different issuer key forms a different A_bar → reject.
        assert!(!other.verify_spend(&params, &spend_proof, d));
        // Tampering the proof → reject under the correct issuer.
        let last = spend_proof.pok.len() - 1;
        spend_proof.pok[last] ^= 0x01;
        assert!(!issuer.verify_spend(&params, &spend_proof, d));
    }

    #[test]
    fn refund_roundtrip_produces_new_token() {
        // issue 20 → spend 10 (no top-up) → issuer refunds t=0 → new token with
        // balance c - s + t = 10.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:refund:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let d = 4;
        let (spend_proof, prerefund) = prove_spend(&token, &params, 10, 0, d).unwrap();
        let refund = issuer.refund(&params, &spend_proof, 0, d).unwrap();
        let new_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, issuer.public())
            .unwrap();
        assert!(new_token.credits().ct_eq(&Scalar::from_u64(10)), "balance c-s+t = 10");
    }

    #[test]
    fn refund_with_return_amount_adds_to_balance() {
        // issue 15 → spend 3, top-up 5 → issuer returns t=5 → balance (15-3)+5 = 17.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:refund:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 15, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let d = 4;
        let (spend_proof, prerefund) = prove_spend(&token, &params, 3, 5, d).unwrap();
        let refund = issuer.refund(&params, &spend_proof, 5, d).unwrap();
        let new_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, issuer.public())
            .unwrap();
        assert!(new_token.credits().ct_eq(&Scalar::from_u64(17)), "balance 12+5 = 17");
    }

    #[test]
    fn full_cycle_issue_spend_refund_spend_again() {
        // The refunded token must itself be spendable: issue 20 → spend 10 →
        // refund → the resulting 10-credit token spends 4 and the issuer accepts.
        // This closes the whole ACT loop on BoringSSL.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:cycle:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let d = 4;
        let (spend_proof, prerefund) = prove_spend(&token, &params, 10, 0, d).unwrap();
        let refund = issuer.refund(&params, &spend_proof, 0, d).unwrap();
        let new_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, issuer.public())
            .unwrap();

        let (spend2, _) = prove_spend(&new_token, &params, 4, 0, d).unwrap();
        assert!(issuer.verify_spend(&params, &spend2, d), "refunded token must be spendable");
    }

    #[test]
    fn refund_rejects_excessive_return_amount() {
        // The issuer cannot return more than s + a.
        use crate::spend::prove_spend;
        let params = Params::from_domain_separator(b"ACT-v1:refund:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let (spend_proof, _pr) = prove_spend(&token, &params, 10, 0, 4).unwrap();
        // s=10, a=0, so t must be <= 10; t=11 is rejected.
        assert!(matches!(
            issuer.refund(&params, &spend_proof, 11, 4),
            Err(Error::InvalidRefundAmount)
        ));
    }

    #[test]
    fn wire_roundtrips_the_whole_flow() {
        // Serialize every ACT message across a full issue → spend → refund flow,
        // decode each, and require: the re-encoding is byte-identical, a decoded
        // spend proof still verifies, and a decoded token round-trips its balance.
        use crate::spend::{prove_spend, Refund, SpendProof};
        let params = Params::from_domain_separator(b"ACT-v1:wire:svc:prod:2026-01-01");
        let issuer = PrivateKey::random();

        // PublicKey.
        let pk_bytes = issuer.public().to_wire();
        assert_eq!(PublicKey::from_wire(&pk_bytes).unwrap().to_wire(), pk_bytes);

        // IssuanceRequest.
        let pre = PreIssuance::random();
        let request = pre.request(&params);
        let req_bytes = request.to_wire().unwrap();
        let request = IssuanceRequest::from_wire(&req_bytes).unwrap();
        assert_eq!(request.to_wire().unwrap(), req_bytes);

        // IssuanceResponse.
        let ctx = Scalar::from_u64(11);
        let response = issuer.issue::<4>(&params, &request, 20, ctx.clone()).unwrap();
        let resp_bytes = response.to_wire().unwrap();
        let response = IssuanceResponse::from_wire(&resp_bytes).unwrap();
        assert_eq!(response.to_wire().unwrap(), resp_bytes);

        // CreditToken (local persistence).
        let token = pre
            .to_credit_token(&params, issuer.public(), &request, &response, ctx)
            .unwrap();
        let tok_bytes = token.to_wire();
        let token = CreditToken::from_wire(&tok_bytes).unwrap();
        assert_eq!(token.to_wire(), tok_bytes);

        // SpendProof — decode and require it still verifies.
        let d = 4;
        let (spend_proof, prerefund) = prove_spend(&token, &params, 10, 0, d).unwrap();
        let sp_bytes = spend_proof.to_wire().unwrap();
        let spend_proof = SpendProof::from_wire(&sp_bytes).unwrap();
        assert_eq!(spend_proof.to_wire().unwrap(), sp_bytes);
        assert!(issuer.verify_spend(&params, &spend_proof, d), "decoded spend proof verifies");

        // Refund — decode and complete the flow.
        let refund = issuer.refund(&params, &spend_proof, 0, d).unwrap();
        let rf_bytes = refund.to_wire().unwrap();
        let refund = Refund::from_wire(&rf_bytes).unwrap();
        assert_eq!(refund.to_wire().unwrap(), rf_bytes);
        let new_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, issuer.public())
            .unwrap();
        assert!(new_token.credits().ct_eq(&Scalar::from_u64(10)));
    }

    #[test]
    fn wire_rejects_truncated_and_trailing_and_noncanonical() {
        let issuer = PrivateKey::random();
        let pk_bytes = issuer.public().to_wire();
        // Truncated input.
        assert!(PublicKey::from_wire(&pk_bytes[..pk_bytes.len() - 1]).is_err());
        // Trailing bytes.
        let mut extra = pk_bytes.clone();
        extra.push(0);
        assert!(PublicKey::from_wire(&extra).is_err());
        // A non-canonical scalar in a message is rejected: build a Refund with
        // the group order n as a scalar field.
        let n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        let n: [u8; 32] = {
            let mut b = [0u8; 32];
            for i in 0..32 {
                b[i] = u8::from_str_radix(&n_hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            b
        };
        let g = Point::generator().to_bytes();
        let mut bad = Vec::new();
        bad.extend_from_slice(&g); // A
        bad.extend_from_slice(&n); // e (non-canonical)
        bad.extend_from_slice(&[0u8; 32]); // t
        bad.extend_from_slice(&0u16.to_be_bytes()); // empty pok
        assert!(crate::spend::Refund::from_wire(&bad).is_err());
    }

    #[test]
    fn request_context_scalar_is_deterministic_and_separated() {
        use crate::proofs::request_context_scalar;
        let a = request_context_scalar(b"policy-1", b"epoch-1");
        assert!(a.ct_eq(&request_context_scalar(b"policy-1", b"epoch-1")));
        assert!(!a.ct_eq(&request_context_scalar(b"policy-2", b"epoch-1")));
        assert!(!a.ct_eq(&request_context_scalar(b"policy-1", b"epoch-2")));
        // Length framing: shifting bytes across the boundary must not collide.
        assert!(!request_context_scalar(b"policy-1e", b"poch-1")
            .ct_eq(&request_context_scalar(b"policy-1", b"epoch-1")));
    }

    #[test]
    fn batchable_pedersen_also_roundtrips() {
        // The same relation via the batchable proof format, exercising the
        // other serialization path sigma_boring offers.
        let params = Params::from_domain_separator(b"ACT-v1:batch:svc:prod:2026-01-01");
        let k = Scalar::random();
        let r = Scalar::random();
        let big_k = params.h2.mul(&k).add(&params.h3.mul(&r));
        let (relation, statement) = pedersen(params.h2.clone(), params.h3.clone(), big_k);
        let pid = act_protocol_id();
        let sess = session(&params, b"request", &[]);
        let proof = relation.prove_batchable(&[k, r], &pid, &sess, &statement);
        assert!(relation
            .verify_batchable(&pid, &sess, &statement, &proof)
            .unwrap());
    }
}
