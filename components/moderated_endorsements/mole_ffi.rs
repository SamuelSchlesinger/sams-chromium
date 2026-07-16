// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! cxx FFI bridge over the MoLE cryptographic stack
//! (`//third_party/mole`), exposing the Client side of the MoLE
//! architecture to C++ as a sans-I/O state machine: every method either
//! consumes bytes received over HTTP or produces the bytes/header values the
//! next HTTP exchange must carry. All networking stays in C++.
//!
//! The Client holds a per-policy *pool* of ACT Credentials. A Credential is
//! linear — its spend must be finalized by the Moderator's refund before a
//! successor exists — so concurrent presentations require independent
//! Credentials. One endorsement redemption fills the pool with the policy's
//! `issuance-batch` of them; presentations draw from the pool front and
//! finalized successors rejoin at the back, so the chains drain evenly.
//!
//! `TestMoleAnchor` / `TestMoleModerator` are in-process ports of the
//! mole-anchor / mole-moderator server handlers, so unit tests can run the
//! whole protocol — grant, redeem & issue, presentation and update, plus the
//! double-spend and replay rejections — without sockets. They speak in the
//! same wire messages as the real servers.

use std::collections::{HashMap, VecDeque};

// ACT runs on act_boring (the ACT(P-256, SHAKE128) ciphersuite over BoringSSL),
// replacing the vendored ristretto255 `anonymous_credit_tokens` crate.
use act_boring::proofs::request_context_scalar;
use act_boring::spend::{prove_spend, scalar_to_u128, PreRefund, Refund, SpendProof};
use act_boring::{
    CreditToken, IssuanceRequest as ActIssuanceRequestMsg,
    IssuanceResponse as ActIssuanceResponseMsg, Params, PreIssuance,
    PrivateKey as ActPrivateKey, PublicKey as ActPublicKey, Scalar as ActScalar,
};
// IHAT runs on ihat_boring (BoringSSL P-256), a byte-compatible drop-in for the
// former `ihat` crate. Anchor public keys are group elements (`IhatKey`).
use ihat_boring::anchor::{AnchorNeedsProofRequest, AnchorSecretKey};
use ihat_boring::client::{ClientNeedsProof, ClientNeedsSignature, IssuedEndorsement};
use ihat_boring::wire::decode_anchor_key;
use ihat_boring::{Point as IhatKey, Proof, ProofRequest, Signature, SignatureRequest};
use mole_core::act::{key_id, truncated_key_id, BALANCE_DIGITS};
use mole_core::config::{
    AnchorDirectory, AnchorEndorsementConfig, ModeratorDirectory, ModeratorPolicy,
};
use mole_core::http::{
    b64_encode, parse_challenges, MoleAuthorization, MoleChallenge, MoleCredential,
};
use mole_core::messages::{
    ActChallenge, ActIssuanceRequest, ActIssuanceResponse, ActPresentationAndUpdate, ActUpdate,
    CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
    CredentialUpdate, EndorsementRequest, EndorsementResponse, IhatChallenge, IhatGrantRequest,
    IhatGrantResponse, IhatPresentation, ModeratorChallenge, OptionalCredentialUpdate,
};
use mole_core::wire::Wire;
use mole_core::{challenge_digest, credential_type, endorsement_type};
use rand_core::{OsRng, RngCore};

/// ACT(P-256) parameters. The digit count `D` is applied per-operation
/// (`issue`, `prove_spend`, `refund`) rather than carried in the type.
type ActParams = Params;

#[cxx::bridge(namespace = "moderated_endorsements")]
mod ffi {
    /// A status-only outcome. `error` is a diagnostic, meaningful when `ok`
    /// is false; it must never be surfaced to web content verbatim.
    struct StatusResult {
        ok: bool,
        error: String,
    }

    /// Outcome of starting an endorsement grant: where to POST and what.
    struct GrantBegin {
        ok: bool,
        error: String,
        /// Grant endpoint path, relative to the Anchor origin.
        endorse_path: String,
        /// `application/mole-endorsement-request` body for the first
        /// exchange.
        request_body: Vec<u8>,
    }

    /// Outcome of consuming a grant-exchange response. When `done` is false,
    /// `request_body` is the body of the next exchange; when true, the
    /// Endorsement is stored and no further exchange is needed.
    struct GrantStep {
        ok: bool,
        error: String,
        done: bool,
        request_body: Vec<u8>,
    }

    /// What a Moderator's challenge asks for, and whether this Client must
    /// run Redeem & Issue before it can present.
    struct ChallengeEval {
        ok: bool,
        error: String,
        /// The policy the challenge names.
        policy_context: Vec<u8>,
        /// True when the pool holds no Credential for this policy.
        needs_redeem: bool,
        /// True when redemption is impossible for want of an Endorsement
        /// from an accepted Anchor: the user agent must `collect()` one.
        /// Key-membership is the only check possible here (the epoch lives
        /// in the Moderator directory, not the challenge bytes), so false
        /// is necessary but not sufficient — a failed redeem_begin must
        /// also be treated as "collect a fresh Endorsement and retry".
        needs_endorsement: bool,
    }

    /// Outcome of building a Redeem & Issue request.
    struct RedeemBegin {
        ok: bool,
        error: String,
        /// Value for the `Authorization` request header.
        authorization_header: String,
    }

    /// Outcome of finalizing Redeem & Issue.
    struct RedeemFinish {
        ok: bool,
        error: String,
        /// Credentials now pooled for the policy.
        pool_size: usize,
    }

    /// Outcome of building a presentation. The drawn Credential is burned:
    /// it never returns to the pool, only its update-derived successor does
    /// (via `present_finish`).
    struct PresentBegin {
        ok: bool,
        error: String,
        /// Correlates the eventual `present_finish` / `present_abort`.
        presentation_id: u64,
        /// Value for the `Authorization` request header.
        authorization_header: String,
    }

    /// A byte string, for vectors-of-byte-strings (cxx has no nested Vec).
    struct Blob {
        bytes: Vec<u8>,
    }

    /// The committed parameters the browser's key-commitment registry (a
    /// component-updater component, delivered identically to every browser to
    /// defeat split-view) authorizes for one Anchor origin. Grant enforcement
    /// refuses any endorsement whose key or epoch is not committed here; this
    /// denies the "unique key/epoch per user" cross-site tagging channel.
    /// `found == false` means the origin is not enrolled, so the grant is
    /// refused outright (fail-closed).
    struct AnchorCommitment {
        found: bool,
        /// Committed Anchor IHAT public keys (33-byte SEC1-compressed P-256).
        keys: Vec<Blob>,
        /// Committed endorsement contexts (epochs). The Anchor's advertised
        /// epoch must be one of these, so an epoch cannot carry a per-user id.
        epochs: Vec<Blob>,
    }

    /// One committed Moderator policy: the exact values a redemption for this
    /// policy must match. `accepted_anchor_keys` is the WHOLE committed set in
    /// normative order; a redemption's accepted set must equal it exactly (no
    /// server-chosen subset), which denies the accepted-set partitioning
    /// channel (including singleton-set deanonymization).
    struct CommittedPolicy {
        policy_context: Vec<u8>,
        act_public_key: Vec<u8>,
        act_domain_separator: Vec<u8>,
        accepted_anchor_keys: Vec<Blob>,
        epochs: Vec<Blob>,
    }

    /// The committed policies the registry authorizes for one Moderator origin.
    /// `found == false` ⇒ not enrolled ⇒ redemption refused (fail-closed).
    struct ModeratorCommitment {
        found: bool,
        policies: Vec<CommittedPolicy>,
    }

    /// An HTTP exchange as the in-process test servers see it: a status, the
    /// header values that matter to the protocol, and a body.
    struct TestHttpResponse {
        status: u16,
        /// `WWW-Authenticate` values (present on 401s).
        www_authenticate: Vec<String>,
        /// `Mole-Credential` value, or empty.
        mole_credential: String,
        body: Vec<u8>,
    }

    extern "Rust" {
        type MoleBrowserClient;

        fn new_mole_browser_client() -> Box<MoleBrowserClient>;

        /// Start an endorsement grant against the Anchor whose directory
        /// (the `/.well-known/mole-anchor` JSON) is given. `commitment` is the
        /// registry's committed parameters for the Anchor's origin; the grant
        /// is refused unless the advertised key and epoch are both committed.
        fn grant_begin(
            self: &mut MoleBrowserClient,
            anchor_directory_json: &str,
            commitment: &AnchorCommitment,
        ) -> GrantBegin;

        /// Consume a grant-exchange response body; see [`GrantStep`].
        fn grant_step(self: &mut MoleBrowserClient, response_body: &[u8]) -> GrantStep;

        /// Evaluate a Moderator 401's `WWW-Authenticate` values.
        fn challenge_eval(
            self: &mut MoleBrowserClient,
            www_authenticate: &Vec<String>,
        ) -> ChallengeEval;

        /// Build the Redeem & Issue `Authorization` header: an endorsement
        /// presentation plus a batch of ACT issuance requests, sized by the
        /// policy entry in the Moderator directory JSON.
        fn redeem_begin(
            self: &mut MoleBrowserClient,
            moderator_directory_json: &str,
            www_authenticate: &Vec<String>,
            commitment: &ModeratorCommitment,
        ) -> RedeemBegin;

        /// Finalize Redeem & Issue from the response's `Mole-Credential`
        /// value, filling the policy's Credential pool.
        fn redeem_finish(
            self: &mut MoleBrowserClient,
            mole_credential_header: &str,
        ) -> RedeemFinish;

        /// Draw a Credential from the pool and build the presentation
        /// `Authorization` header answering the given challenge.
        fn present_begin(
            self: &mut MoleBrowserClient,
            www_authenticate: &Vec<String>,
        ) -> PresentBegin;

        /// Finalize a presentation from the response's `Mole-Credential`
        /// value: the update becomes the successor Credential and rejoins
        /// the pool.
        fn present_finish(
            self: &mut MoleBrowserClient,
            presentation_id: u64,
            mole_credential_header: &str,
        ) -> StatusResult;

        /// Abandon a presentation (e.g. network failure after the header was
        /// built). The Credential was burned when drawn and stays burned: it
        /// may already have reached the Moderator, so reuse would be a
        /// double-spend.
        fn present_abort(self: &mut MoleBrowserClient, presentation_id: u64);

        fn pool_size(self: &MoleBrowserClient, policy_context: &[u8]) -> usize;
        fn balance(self: &MoleBrowserClient, policy_context: &[u8]) -> u64;
        fn endorsement_count(self: &MoleBrowserClient) -> usize;

        // Serialize the durable client state (endorsements + per-policy
        // credential pools, all secret-bearing) to an opaque blob, and restore
        // it into a fresh client. The foundation for partitioned on-disk
        // persistence: the browser persists this blob and reloads it at startup.
        // Transient in-flight exchange state is intentionally not included.
        fn serialize_state(self: &MoleBrowserClient) -> Vec<u8>;
        fn restore_state(self: &mut MoleBrowserClient, bytes: &[u8]) -> bool;

        // --- In-process test servers (test-only) ---

        type TestMoleAnchor;

        fn new_test_anchor(endorsement_context: &[u8]) -> Box<TestMoleAnchor>;
        fn anchor_directory_json(self: &TestMoleAnchor) -> String;
        fn anchor_public_key(self: &TestMoleAnchor) -> Vec<u8>;
        /// The registry entry this Anchor would publish: its key and epoch.
        /// Used to drive the enforcement in tests as a real registry would.
        fn anchor_commitment(self: &TestMoleAnchor) -> AnchorCommitment;
        /// The grant endpoint: consumes an
        /// `application/mole-endorsement-request` body.
        fn handle_endorse(self: &mut TestMoleAnchor, body: &[u8]) -> TestHttpResponse;

        type TestMoleModerator;

        fn new_test_moderator(
            accepted_anchor_keys: &Vec<Blob>,
            endorsement_context: &[u8],
            policy_context: &[u8],
            initial_credits: u64,
            issuance_batch: u64,
            charge: u64,
            refund: u64,
        ) -> Box<TestMoleModerator>;
        fn moderator_directory_json(self: &TestMoleModerator) -> String;
        /// The registry entry this Moderator would publish for its policy.
        fn moderator_commitment(self: &TestMoleModerator) -> ModeratorCommitment;
        /// The protected resource: `authorization_header` is the raw
        /// `Authorization` value, or empty for an unauthenticated request.
        fn handle_resource(
            self: &mut TestMoleModerator,
            authorization_header: &str,
        ) -> TestHttpResponse;
        fn endorsement_nullifier_count(self: &TestMoleModerator) -> usize;
        fn spend_nullifier_count(self: &TestMoleModerator) -> usize;
    }
}

use ffi::{
    AnchorCommitment, Blob, ChallengeEval, CommittedPolicy, GrantBegin, GrantStep,
    ModeratorCommitment, PresentBegin, RedeemBegin, RedeemFinish, StatusResult,
    TestHttpResponse,
};

fn ok_status() -> StatusResult {
    StatusResult { ok: true, error: String::new() }
}

fn err_status(error: impl Into<String>) -> StatusResult {
    StatusResult { ok: false, error: error.into() }
}

// ---------------------------------------------------------------------------
// The Client
// ---------------------------------------------------------------------------

/// An unredeemed Endorsement together with what redemption needs.
struct StoredEndorsement {
    issued: IssuedEndorsement,
    anchor_key: Vec<u8>,
    endorsement_context: Vec<u8>,
}

/// A usable Credential: one independent spend chain in a policy's pool.
struct StoredCredential {
    token: CreditToken,
    act_public_key: ActPublicKey,
    act_params: ActParams,
}

/// The grant flow's state between exchanges.
enum GrantState {
    NeedsSignature {
        pending: ClientNeedsSignature,
        anchor_key: Vec<u8>,
        endorsement_context: Vec<u8>,
    },
    NeedsProof {
        pending: ClientNeedsProof,
        anchor_key: Vec<u8>,
        endorsement_context: Vec<u8>,
    },
}

/// Redeem & Issue state held between building the request and finalizing the
/// response.
struct PendingRedeem {
    pre_issuances: Vec<PreIssuance>,
    issuance_requests: Vec<ActIssuanceRequestMsg>,
    act_public_key: ActPublicKey,
    act_params: ActParams,
    policy_context: Vec<u8>,
    endorsement_context: Vec<u8>,
}

/// A presentation in flight: what finalizing its update needs.
struct InFlightPresentation {
    pre_refund: PreRefund,
    spend: SpendProof,
    act_public_key: ActPublicKey,
    act_params: ActParams,
    policy_context: Vec<u8>,
}

/// The Client side of the MoLE architecture, as a sans-I/O state machine.
pub struct MoleBrowserClient {
    endorsements: Vec<StoredEndorsement>,
    /// Per-policy Credential pools (FIFO: draw front, successors rejoin at
    /// the back).
    pools: HashMap<Vec<u8>, VecDeque<StoredCredential>>,
    /// At most one grant runs at a time (demo simplification).
    grant: Option<GrantState>,
    /// At most one redemption runs at a time (demo simplification).
    redeem: Option<PendingRedeem>,
    in_flight: HashMap<u64, InFlightPresentation>,
    next_presentation_id: u64,
}

fn new_mole_browser_client() -> Box<MoleBrowserClient> {
    Box::new(MoleBrowserClient {
        endorsements: Vec::new(),
        pools: HashMap::new(),
        grant: None,
        redeem: None,
        in_flight: HashMap::new(),
        next_presentation_id: 1,
    })
}

/// Parse the two Moderator challenges out of `WWW-Authenticate` values,
/// ignoring challenges of unknown type.
fn parse_moderator_challenges(
    header_values: &[String],
) -> Result<(CredentialChallenge, ActChallenge, ModeratorChallenge), String> {
    let refs: Vec<&str> = header_values.iter().map(|s| s.as_str()).collect();
    let challenges: Vec<MoleChallenge> = parse_challenges(&refs);

    let mut credential = None;
    let mut moderator = None;
    for challenge in &challenges {
        if credential.is_none() {
            if let Ok(c) = CredentialChallenge::from_bytes(&challenge.challenge) {
                if c.credential_type == credential_type::ACT {
                    credential = Some(c);
                    continue;
                }
            }
        }
        if moderator.is_none() {
            if let Ok(m) = ModeratorChallenge::from_bytes(&challenge.challenge) {
                if m.endorsement_type == endorsement_type::IHAT {
                    moderator = Some(m);
                }
            }
        }
    }
    let (Some(credential), Some(moderator)) = (credential, moderator) else {
        return Err("no recognizable credential + endorsement challenge pair".into());
    };
    let act = ActChallenge::from_bytes(&credential.challenge)
        .map_err(|e| format!("malformed ACT challenge: {e}"))?;
    Ok((credential, act, moderator))
}

impl MoleBrowserClient {
    fn grant_begin(
        &mut self,
        anchor_directory_json: &str,
        commitment: &AnchorCommitment,
    ) -> GrantBegin {
        let fail = |error: String| GrantBegin {
            ok: false,
            error,
            endorse_path: String::new(),
            request_body: Vec::new(),
        };

        // Fail-closed: an Anchor with no registry entry cannot be used. The
        // key and epoch below are checked against the committed set, so a
        // server cannot mint a per-user key or epoch to tag the endorsement.
        if !commitment.found {
            return fail("anchor is not enrolled in the key-commitment registry".into());
        }

        let directory: AnchorDirectory = match serde_json::from_str(anchor_directory_json) {
            Ok(d) => d,
            Err(e) => return fail(format!("malformed anchor directory: {e}")),
        };
        let Some(config) = directory
            .endorsement_configs
            .iter()
            .find(|c| c.endorsement_type == endorsement_type::IHAT)
        else {
            return fail("anchor offers no IHAT config".into());
        };
        let anchor_key = match mole_core::http::b64_decode(&config.public_key) {
            Ok(k) => k,
            Err(e) => return fail(format!("anchor key encoding: {e}")),
        };
        if decode_anchor_key(&anchor_key).is_err() {
            return fail("anchor key does not decode".into());
        }
        if !commitment.keys.iter().any(|k| k.bytes[..] == anchor_key[..]) {
            return fail("anchor key is not in the committed set".into());
        }
        let endorsement_context =
            match mole_core::http::b64_decode(&config.endorsement_context) {
                Ok(c) => c,
                Err(e) => return fail(format!("endorsement context encoding: {e}")),
            };
        if !commitment
            .epochs
            .iter()
            .any(|e| e.bytes[..] == endorsement_context[..])
        {
            return fail("endorsement epoch is not committed".into());
        }

        // The nullifier is Client-chosen and never seen by the Anchor.
        let mut nf = [0u8; 32];
        OsRng.fill_bytes(&mut nf);
        let (signature_request, pending) =
            ClientNeedsSignature::request(nf.to_vec(), endorsement_context.clone());
        let Ok(signature_request_bytes) = signature_request.to_wire() else {
            return fail("signature request does not encode".into());
        };

        self.grant = Some(GrantState::NeedsSignature {
            pending,
            anchor_key,
            endorsement_context,
        });

        let body = EndorsementRequest {
            endorsement_type: endorsement_type::IHAT,
            body: IhatGrantRequest::Step1 { signature_request: signature_request_bytes }
                .to_bytes(),
        };
        GrantBegin {
            ok: true,
            error: String::new(),
            endorse_path: config.endorse_endpoint.clone(),
            request_body: body.to_bytes(),
        }
    }

    fn grant_step(&mut self, response_body: &[u8]) -> GrantStep {
        let fail = |error: String| GrantStep {
            ok: false,
            error,
            done: false,
            request_body: Vec::new(),
        };

        let Some(state) = self.grant.take() else {
            return fail("no grant in progress".into());
        };
        let response = match EndorsementResponse::from_bytes(response_body) {
            Ok(r) => r,
            Err(e) => return fail(format!("malformed EndorsementResponse: {e}")),
        };
        if response.endorsement_type != endorsement_type::IHAT {
            return fail("anchor answered with an unknown endorsement type".into());
        }
        let grant_response = match IhatGrantResponse::from_bytes(&response.body) {
            Ok(r) => r,
            Err(e) => return fail(format!("malformed grant response body: {e}")),
        };

        match (state, grant_response) {
            (
                GrantState::NeedsSignature { pending, anchor_key, endorsement_context },
                IhatGrantResponse::Step1 { session_id, signature },
            ) => {
                let Ok(signature) = Signature::from_wire(&signature) else {
                    return fail("malformed Signature".into());
                };
                let Ok(anchor_public_key) = decode_anchor_key(&anchor_key) else {
                    return fail("anchor key does not decode".into());
                };
                let (proof_request, pending) =
                    pending.request_proof(anchor_public_key, signature);
                let Ok(proof_request_bytes) = proof_request.to_wire() else {
                    return fail("proof request does not encode".into());
                };
                self.grant = Some(GrantState::NeedsProof {
                    pending,
                    anchor_key,
                    endorsement_context,
                });
                let body = EndorsementRequest {
                    endorsement_type: endorsement_type::IHAT,
                    body: IhatGrantRequest::Step2 {
                        session_id,
                        proof_request: proof_request_bytes,
                    }
                    .to_bytes(),
                };
                GrantStep {
                    ok: true,
                    error: String::new(),
                    done: false,
                    request_body: body.to_bytes(),
                }
            }
            (
                GrantState::NeedsProof { pending, anchor_key, endorsement_context },
                IhatGrantResponse::Step2 { proof },
            ) => {
                let Ok(proof) = Proof::from_wire(&proof) else {
                    return fail("malformed Proof".into());
                };
                // On failure the session must be discarded, never retried
                // with the same state.
                let Some(issued) = pending.finalize(proof) else {
                    return fail("endorsement finalization failed; session discarded".into());
                };
                self.endorsements.push(StoredEndorsement {
                    issued,
                    anchor_key,
                    endorsement_context,
                });
                GrantStep {
                    ok: true,
                    error: String::new(),
                    done: true,
                    request_body: Vec::new(),
                }
            }
            _ => fail("anchor answered with the wrong grant step".into()),
        }
    }

    fn challenge_eval(&mut self, www_authenticate: &Vec<String>) -> ChallengeEval {
        match parse_moderator_challenges(www_authenticate) {
            Ok((_credential, act, moderator)) => {
                let needs_redeem = self
                    .pools
                    .get(&act.policy_context)
                    .map_or(true, |pool| pool.is_empty());
                // Redemption needs an Endorsement from an Anchor in the
                // accepted set. The epoch check happens in redeem_begin —
                // the challenge carries only the key set, the epoch lives in
                // the Moderator directory, which is not available here.
                let needs_endorsement = needs_redeem
                    && IhatChallenge::from_bytes(&moderator.challenge)
                        .map(|c| self.usable_endorsement(&c, None).is_none())
                        .unwrap_or(true);
                ChallengeEval {
                    ok: true,
                    error: String::new(),
                    policy_context: act.policy_context,
                    needs_redeem,
                    needs_endorsement,
                }
            }
            Err(error) => ChallengeEval {
                ok: false,
                error,
                policy_context: Vec::new(),
                needs_redeem: false,
                needs_endorsement: false,
            },
        }
    }

    /// The index of a stored Endorsement whose Anchor is in the accepted
    /// set — and, when the expected endorsement context (epoch) is known,
    /// whose epoch matches it.
    fn usable_endorsement(
        &self,
        challenge: &IhatChallenge,
        expected_context: Option<&[u8]>,
    ) -> Option<usize> {
        self.endorsements.iter().position(|e| {
            expected_context.map_or(true, |c| e.endorsement_context == c)
                && challenge.keys.iter().any(|k| k[..] == e.anchor_key[..])
        })
    }

    fn redeem_begin(
        &mut self,
        moderator_directory_json: &str,
        www_authenticate: &Vec<String>,
        commitment: &ModeratorCommitment,
    ) -> RedeemBegin {
        let fail = |error: String| RedeemBegin {
            ok: false,
            error,
            authorization_header: String::new(),
        };

        // Fail-closed: a Moderator with no registry entry cannot be redeemed
        // against.
        if !commitment.found {
            return fail("moderator is not enrolled in the key-commitment registry".into());
        }

        let (_credential_challenge, act_challenge, moderator_challenge) =
            match parse_moderator_challenges(www_authenticate) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
        let ihat_challenge = match IhatChallenge::from_bytes(&moderator_challenge.challenge) {
            Ok(c) => c,
            Err(e) => return fail(format!("malformed IHAT challenge: {e}")),
        };

        // The committed policy pins every partitionable parameter. Refuse if
        // the challenged policy is not committed for this Moderator.
        let Some(committed) = commitment
            .policies
            .iter()
            .find(|p| p.policy_context[..] == act_challenge.policy_context[..])
        else {
            return fail("policy is not committed for this moderator".into());
        };
        // The accepted Anchor set is the OR-proof's anonymity set. It must be
        // the whole committed set in the committed order — never a server-
        // chosen subset or reordering — or a Moderator could shrink/craft it
        // per user to deanonymize.
        if ihat_challenge.keys.len() != committed.accepted_anchor_keys.len()
            || ihat_challenge
                .keys
                .iter()
                .zip(&committed.accepted_anchor_keys)
                .any(|(k, c)| k[..] != c.bytes[..])
        {
            return fail("challenge accepted set does not match the committed set".into());
        }

        let directory: ModeratorDirectory = match serde_json::from_str(moderator_directory_json)
        {
            Ok(d) => d,
            Err(e) => return fail(format!("malformed moderator directory: {e}")),
        };
        let Some(policy) = directory.policies.into_iter().find(|p| {
            mole_core::http::b64_decode(&p.policy_context)
                .map(|c| c == act_challenge.policy_context)
                .unwrap_or(false)
        }) else {
            return fail("moderator directory lacks the challenged policy".into());
        };
        if policy.act_balance_digits != BALANCE_DIGITS as u64 {
            return fail(format!(
                "policy uses {} balance digits, this client is built with {}",
                policy.act_balance_digits, BALANCE_DIGITS
            ));
        }
        let act_public_key_bytes = match mole_core::http::b64_decode(&policy.act_public_key) {
            Ok(b) => b,
            Err(e) => return fail(format!("ACT key encoding: {e}")),
        };
        // The directory-advertised ACT key and domain separator must be the
        // committed ones: otherwise a per-user ACT key would deanonymize at
        // spend.
        if act_public_key_bytes[..] != committed.act_public_key[..] {
            return fail("ACT public key is not committed".into());
        }
        let act_public_key = match ActPublicKey::from_wire(&act_public_key_bytes) {
            Ok(k) => k,
            Err(e) => return fail(format!("ACT key: {e:?}")),
        };
        let domain_separator = match mole_core::http::b64_decode(&policy.act_domain_separator) {
            Ok(d) => d,
            Err(e) => return fail(format!("ACT domain separator encoding: {e}")),
        };
        if domain_separator[..] != committed.act_domain_separator[..] {
            return fail("ACT domain separator is not committed".into());
        }
        let act_params = ActParams::from_domain_separator(&domain_separator);
        let expected_context = match mole_core::http::b64_decode(&policy.endorsement_context) {
            Ok(c) => c,
            Err(e) => return fail(format!("endorsement context encoding: {e}")),
        };
        if !committed
            .epochs
            .iter()
            .any(|e| e.bytes[..] == expected_context[..])
        {
            return fail("redemption epoch is not committed".into());
        }

        // Find an Endorsement from an Anchor in the accepted set, granted in
        // the epoch the Moderator accepts.
        let Some(index) =
            self.usable_endorsement(&ihat_challenge, Some(&expected_context))
        else {
            return fail("no stored endorsement is usable against this challenge".into());
        };
        let endorsement = self.endorsements.swap_remove(index);
        let Some(true_index) = ihat_challenge
            .keys
            .iter()
            .position(|k| k[..] == endorsement.anchor_key[..])
        else {
            return fail("endorsement anchor left the accepted set".into());
        };

        // Redeem: the presentation is bound to the digest of the challenge
        // that triggered it.
        let accepted: Vec<IhatKey> = match ihat_challenge
            .keys
            .iter()
            .map(|k| decode_anchor_key(k))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(a) => a,
            Err(e) => return fail(format!("accepted set key: {e}")),
        };
        let binding = challenge_digest(&moderator_challenge.to_bytes());
        let presentation = endorsement.issued.show(&accepted, true_index, &binding);
        let Ok(presentation_bytes) = presentation.to_wire() else {
            return fail("presentation does not encode".into());
        };

        // Issue: the batch of ACT issuance requests rides along. The batch
        // size is the policy's constant.
        let Ok(batch) = usize::try_from(policy.issuance_batch) else {
            return fail("absurd issuance batch".into());
        };
        if batch == 0 || batch > 64 {
            return fail("issuance batch out of range".into());
        }
        let pre_issuances: Vec<PreIssuance> =
            (0..batch).map(|_| PreIssuance::random()).collect();
        let issuance_requests: Vec<ActIssuanceRequestMsg> = pre_issuances
            .iter()
            .map(|pre| pre.request(&act_params))
            .collect();

        let request = CredentialRequest {
            endorsement_type: endorsement_type::IHAT,
            endorsement_presentation: IhatPresentation { bytes: presentation_bytes }.to_bytes(),
            credential_type: credential_type::ACT,
            issuance_request: ActIssuanceRequest {
                truncated_key_id: truncated_key_id(&act_public_key_bytes),
                requests: issuance_requests
                    .iter()
                    .map(|r| r.to_wire().expect("issuance request encodes"))
                    .collect(),
            }
            .to_bytes(),
        };

        self.redeem = Some(PendingRedeem {
            pre_issuances,
            issuance_requests,
            act_public_key,
            act_params,
            policy_context: act_challenge.policy_context,
            endorsement_context: endorsement.endorsement_context,
        });

        RedeemBegin {
            ok: true,
            error: String::new(),
            authorization_header: MoleAuthorization::CredentialRequest(request.to_bytes())
                .to_header_value(),
        }
    }

    fn redeem_finish(&mut self, mole_credential_header: &str) -> RedeemFinish {
        let fail = |error: String| RedeemFinish { ok: false, error, pool_size: 0 };

        let Some(redeem) = self.redeem.take() else {
            return fail("no redemption in progress".into());
        };
        let response_bytes = match MoleCredential::parse(mole_credential_header) {
            Ok(MoleCredential::Response(bytes)) => bytes,
            Ok(MoleCredential::Update(_)) => {
                return fail("expected a response parameter, got update".into())
            }
            Err(e) => return fail(format!("Mole-Credential: {e}")),
        };
        let credential_response = match CredentialResponse::from_bytes(&response_bytes) {
            Ok(r) => r,
            Err(e) => return fail(format!("malformed CredentialResponse: {e}")),
        };
        if credential_response.credential_type != credential_type::ACT {
            return fail("moderator issued an unknown credential type".into());
        }
        let issuance_response =
            match ActIssuanceResponse::from_bytes(&credential_response.issuance_response) {
                Ok(r) => r,
                Err(e) => return fail(format!("malformed ActIssuanceResponse: {e}")),
            };
        if issuance_response.responses.len() != redeem.pre_issuances.len() {
            return fail("moderator answered with the wrong batch size".into());
        }

        // Finalize each response into a pool Credential: both sides derive
        // the shared request context scalar.
        let ctx = request_context_scalar(&redeem.policy_context, &redeem.endorsement_context);
        let mut pool = VecDeque::with_capacity(redeem.pre_issuances.len());
        for ((pre_issuance, issuance_request), response_bytes) in redeem
            .pre_issuances
            .into_iter()
            .zip(&redeem.issuance_requests)
            .zip(&issuance_response.responses)
        {
            let act_response = match ActIssuanceResponseMsg::from_wire(response_bytes) {
                Ok(r) => r,
                Err(e) => return fail(format!("malformed ACT response: {e:?}")),
            };
            let token = match pre_issuance.to_credit_token(
                &redeem.act_params,
                &redeem.act_public_key,
                issuance_request,
                &act_response,
                ctx.clone(),
            ) {
                Ok(t) => t,
                Err(e) => return fail(format!("credential finalization failed: {e:?}")),
            };
            pool.push_back(StoredCredential {
                token,
                act_public_key: redeem.act_public_key.clone(),
                act_params: redeem.act_params.clone(),
            });
        }

        let pool_size = pool.len();
        self.pools.insert(redeem.policy_context, pool);
        RedeemFinish { ok: true, error: String::new(), pool_size }
    }

    fn present_begin(&mut self, www_authenticate: &Vec<String>) -> PresentBegin {
        let fail = |error: String| PresentBegin {
            ok: false,
            error,
            presentation_id: 0,
            authorization_header: String::new(),
        };

        let (credential_challenge, act_challenge, _moderator_challenge) =
            match parse_moderator_challenges(www_authenticate) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };

        // Burn on use: the Credential leaves the pool before the request is
        // sent, and only its update-derived successor ever returns.
        let Some(credential) = self
            .pools
            .get_mut(&act_challenge.policy_context)
            .and_then(|pool| pool.pop_front())
        else {
            return fail("no credential pooled for this policy".into());
        };

        let (spend, pre_refund) = match prove_spend(
            &credential.token,
            &credential.act_params,
            u128::from(act_challenge.charge),
            u128::from(act_challenge.topup),
            BALANCE_DIGITS,
        ) {
            Ok(s) => s,
            Err(e) => {
                // The drawn Credential stays dropped: a token that cannot
                // cover the charge would otherwise sit at the pool front
                // failing every subsequent presentation. Draining it lets
                // `challenge_eval` steer back into Redeem & Issue.
                return fail(format!("spend proof failed (balance too low?): {e:?}"));
            }
        };

        let presentation = CredentialPresentation {
            credential_type: credential_type::ACT,
            presentation_and_update: ActPresentationAndUpdate {
                challenge_digest: challenge_digest(&credential_challenge.to_bytes()),
                key_id: key_id(&credential.act_public_key.to_wire()),
                spend_proof: spend.to_wire().expect("spend proof encodes"),
            }
            .to_bytes(),
        };

        let presentation_id = self.next_presentation_id;
        self.next_presentation_id += 1;
        self.in_flight.insert(
            presentation_id,
            InFlightPresentation {
                pre_refund,
                spend,
                act_public_key: credential.act_public_key,
                act_params: credential.act_params,
                policy_context: act_challenge.policy_context,
            },
        );

        PresentBegin {
            ok: true,
            error: String::new(),
            presentation_id,
            authorization_header: MoleAuthorization::Presentation(presentation.to_bytes())
                .to_header_value(),
        }
    }

    fn present_finish(
        &mut self,
        presentation_id: u64,
        mole_credential_header: &str,
    ) -> StatusResult {
        let Some(in_flight) = self.in_flight.remove(&presentation_id) else {
            return err_status("unknown presentation");
        };
        let update_bytes = match MoleCredential::parse(mole_credential_header) {
            Ok(MoleCredential::Update(bytes)) => bytes,
            Ok(MoleCredential::Response(_)) => {
                return err_status("expected an update parameter, got response")
            }
            Err(e) => return err_status(format!("Mole-Credential: {e}")),
        };
        let update = match OptionalCredentialUpdate::from_bytes(&update_bytes) {
            Ok(u) => u,
            Err(e) => return err_status(format!("malformed update: {e}")),
        };
        // An absent update means the Moderator consumed the Credential.
        let Some(CredentialUpdate { credential_type: ct, update_response }) = update.update
        else {
            return ok_status();
        };
        if ct != credential_type::ACT {
            return ok_status();
        }
        let act_update = match ActUpdate::from_bytes(&update_response) {
            Ok(u) => u,
            Err(e) => return err_status(format!("malformed ActUpdate: {e}")),
        };
        let refund = match Refund::from_wire(&act_update.refund) {
            Ok(r) => r,
            Err(e) => return err_status(format!("malformed Refund: {e:?}")),
        };
        let token = match in_flight.pre_refund.to_credit_token(
            &in_flight.act_params,
            &in_flight.spend,
            &refund,
            &in_flight.act_public_key,
        ) {
            Ok(t) => t,
            Err(e) => return err_status(format!("update finalization failed: {e:?}")),
        };
        self.pools
            .entry(in_flight.policy_context)
            .or_default()
            .push_back(StoredCredential {
                token,
                act_public_key: in_flight.act_public_key,
                act_params: in_flight.act_params,
            });
        ok_status()
    }

    fn present_abort(&mut self, presentation_id: u64) {
        self.in_flight.remove(&presentation_id);
    }

    fn pool_size(&self, policy_context: &[u8]) -> usize {
        self.pools.get(policy_context).map_or(0, |pool| pool.len())
    }

    fn balance(&self, policy_context: &[u8]) -> u64 {
        let Some(pool) = self.pools.get(policy_context) else {
            return 0;
        };
        pool.iter()
            .filter_map(|c| scalar_to_u128(c.token.credits()))
            .filter_map(|c| u64::try_from(c).ok())
            .sum()
    }

    fn endorsement_count(&self) -> usize {
        self.endorsements.len()
    }

    /// Serialize the durable state (endorsements + non-empty pools) to a blob.
    /// Format (version 1, u32-BE length prefixes): `1 || ne || [endorsement…]
    /// || np || [pool…]`, where each endorsement is
    /// `varbytes(issued) || varbytes(anchor_key) || varbytes(context)` and each
    /// pool is `varbytes(policy_ctx) || varbytes(act_dsep) ||
    /// varbytes(act_pubkey) || nc || [varbytes(token)…]`.
    fn serialize_state(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1u8);
        put_u32(&mut out, self.endorsements.len() as u32);
        for e in &self.endorsements {
            put_varbytes(&mut out, &e.issued.to_wire().expect("endorsement serializes"));
            put_varbytes(&mut out, &e.anchor_key);
            put_varbytes(&mut out, &e.endorsement_context);
        }
        let nonempty: Vec<(&Vec<u8>, &VecDeque<StoredCredential>)> =
            self.pools.iter().filter(|(_, p)| !p.is_empty()).collect();
        put_u32(&mut out, nonempty.len() as u32);
        for (policy_context, pool) in nonempty {
            let front = pool.front().expect("pool is non-empty");
            put_varbytes(&mut out, policy_context);
            put_varbytes(&mut out, front.act_params.domain_separator());
            put_varbytes(&mut out, &front.act_public_key.to_wire());
            put_u32(&mut out, pool.len() as u32);
            for c in pool {
                put_varbytes(&mut out, &c.token.to_wire());
            }
        }
        out
    }

    /// Restore state from [`serialize_state`], replacing the current
    /// endorsements and pools. Returns false (leaving state untouched) if the
    /// blob is malformed, so a corrupt persisted store cannot wedge the client.
    fn restore_state(&mut self, bytes: &[u8]) -> bool {
        match parse_state(bytes) {
            Some((endorsements, pools)) => {
                self.endorsements = endorsements;
                self.pools = pools;
                true
            }
            None => false,
        }
    }
}

// -- durable-state (de)serialization helpers --

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// A bounds-checked cursor over a state blob.
struct StateCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> StateCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        StateCursor { buf, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u32(&mut self) -> Option<usize> {
        let end = self.pos.checked_add(4)?;
        let raw = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u32::from_be_bytes(raw.try_into().unwrap()) as usize)
    }
    fn varbytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()?;
        let end = self.pos.checked_add(len)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

type RestoredState = (Vec<StoredEndorsement>, HashMap<Vec<u8>, VecDeque<StoredCredential>>);

/// Parse a state blob, or `None` on any malformation (including trailing bytes).
fn parse_state(bytes: &[u8]) -> Option<RestoredState> {
    let mut cur = StateCursor::new(bytes);
    if cur.u8()? != 1 {
        return None;
    }
    let ne = cur.u32()?;
    let mut endorsements = Vec::new();
    for _ in 0..ne {
        let issued = IssuedEndorsement::from_wire(cur.varbytes()?).ok()?;
        let anchor_key = cur.varbytes()?.to_vec();
        let endorsement_context = cur.varbytes()?.to_vec();
        endorsements.push(StoredEndorsement { issued, anchor_key, endorsement_context });
    }
    let np = cur.u32()?;
    let mut pools = HashMap::new();
    for _ in 0..np {
        let policy_context = cur.varbytes()?.to_vec();
        let domain_separator = cur.varbytes()?.to_vec();
        let act_public_key = ActPublicKey::from_wire(cur.varbytes()?).ok()?;
        let act_params = ActParams::from_domain_separator(&domain_separator);
        let nc = cur.u32()?;
        let mut pool = VecDeque::with_capacity(nc.min(1024));
        for _ in 0..nc {
            let token = CreditToken::from_wire(cur.varbytes()?).ok()?;
            pool.push_back(StoredCredential {
                token,
                act_public_key: act_public_key.clone(),
                act_params: act_params.clone(),
            });
        }
        pools.insert(policy_context, pool);
    }
    if !cur.is_empty() {
        return None;
    }
    Some((endorsements, pools))
}

// ---------------------------------------------------------------------------
// Test servers: in-process ports of mole-anchor / mole-moderator
// ---------------------------------------------------------------------------

fn http(status: u16, body: &[u8]) -> TestHttpResponse {
    TestHttpResponse {
        status,
        www_authenticate: Vec::new(),
        mole_credential: String::new(),
        body: body.to_vec(),
    }
}

/// The Anchor's grant handler, minus HTTP: sessions keyed the same way as
/// mole-anchor, no per-user limits (tests exercise the protocol, not quota).
pub struct TestMoleAnchor {
    key: AnchorSecretKey,
    endorsement_context: Vec<u8>,
    sessions: HashMap<Vec<u8>, AnchorNeedsProofRequest>,
}

fn new_test_anchor(endorsement_context: &[u8]) -> Box<TestMoleAnchor> {
    Box::new(TestMoleAnchor {
        key: AnchorSecretKey::random(),
        endorsement_context: endorsement_context.to_vec(),
        sessions: HashMap::new(),
    })
}

impl TestMoleAnchor {
    fn anchor_public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
    }

    fn anchor_commitment(&self) -> AnchorCommitment {
        AnchorCommitment {
            found: true,
            keys: vec![Blob { bytes: self.anchor_public_key() }],
            epochs: vec![Blob { bytes: self.endorsement_context.clone() }],
        }
    }

    fn anchor_directory_json(&self) -> String {
        let directory = AnchorDirectory {
            endorsement_configs: vec![AnchorEndorsementConfig {
                endorsement_type: endorsement_type::IHAT,
                public_key: b64_encode(&self.anchor_public_key()),
                endorsement_context: b64_encode(&self.endorsement_context),
                endorse_endpoint: "/mole/endorse".to_string(),
            }],
        };
        serde_json::to_string(&directory).expect("directory serializes")
    }

    fn handle_endorse(&mut self, body: &[u8]) -> TestHttpResponse {
        let Ok(request) = EndorsementRequest::from_bytes(body) else {
            return http(400, b"malformed EndorsementRequest");
        };
        if request.endorsement_type != endorsement_type::IHAT {
            return http(404, b"unknown endorsement type");
        }
        let Ok(grant) = IhatGrantRequest::from_bytes(&request.body) else {
            return http(400, b"malformed grant body");
        };

        let response_body = match grant {
            IhatGrantRequest::Step1 { signature_request } => {
                let Ok(sig_request) = SignatureRequest::from_wire(&signature_request) else {
                    return http(400, b"malformed SignatureRequest");
                };
                if sig_request.endorsement_context != self.endorsement_context {
                    return http(400, b"wrong endorsement context");
                }
                let (signature, pending) = sig_request.sign(&self.key);
                let mut session_id = vec![0u8; 16];
                OsRng.fill_bytes(&mut session_id);
                self.sessions.insert(session_id.clone(), pending);
                IhatGrantResponse::Step1 {
                    session_id,
                    signature: signature.to_wire(),
                }
            }
            IhatGrantRequest::Step2 { session_id, proof_request } => {
                let Some(pending) = self.sessions.remove(&session_id) else {
                    return http(400, b"unknown or spent session");
                };
                let Ok(proof_request) = ProofRequest::from_wire(&proof_request) else {
                    return http(400, b"malformed ProofRequest");
                };
                let proof = pending.prove(&proof_request);
                IhatGrantResponse::Step2 {
                    proof: proof.to_wire(),
                }
            }
        };

        let response = EndorsementResponse {
            endorsement_type: endorsement_type::IHAT,
            body: response_body.to_bytes(),
        };
        http(200, &response.to_bytes())
    }
}

/// The Moderator's resource handler, minus HTTP: the same challenge,
/// Redeem & Issue, and Presentation-and-Update logic as mole-moderator,
/// including validate-everything-before-the-nullifier and uniform 403s.
pub struct TestMoleModerator {
    policy_context: Vec<u8>,
    accepted_anchor_keys: Vec<[u8; 33]>,
    endorsement_context: Vec<u8>,
    initial_credits: u64,
    issuance_batch: u64,
    charge: u64,
    refund: u64,
    act_domain_separator: Vec<u8>,
    accepted: Vec<IhatKey>,
    act_params: ActParams,
    act_key: ActPrivateKey,
    act_key_id: [u8; 32],
    act_ctx: ActScalar,
    seen_endorsement_nullifiers: std::collections::HashSet<Vec<u8>>,
    seen_spend_nullifiers: std::collections::HashSet<[u8; 32]>,
}

fn new_test_moderator(
    accepted_anchor_keys: &Vec<Blob>,
    endorsement_context: &[u8],
    policy_context: &[u8],
    initial_credits: u64,
    issuance_batch: u64,
    charge: u64,
    refund: u64,
) -> Box<TestMoleModerator> {
    let keys: Vec<[u8; 33]> = accepted_anchor_keys
        .iter()
        .map(|k| {
            let mut key = [0u8; 33];
            key.copy_from_slice(&k.bytes);
            key
        })
        .collect();
    let accepted: Vec<IhatKey> = keys
        .iter()
        .map(|k| decode_anchor_key(k).expect("accepted anchor key decodes"))
        .collect();
    let act_domain_separator = b"MoLE-components-test:act:v1".to_vec();
    let act_params = ActParams::from_domain_separator(&act_domain_separator);
    let act_key = ActPrivateKey::random();
    let act_key_id = key_id(&act_key.public().to_wire());
    let act_ctx = request_context_scalar(policy_context, endorsement_context);
    Box::new(TestMoleModerator {
        policy_context: policy_context.to_vec(),
        accepted_anchor_keys: keys,
        endorsement_context: endorsement_context.to_vec(),
        initial_credits,
        issuance_batch,
        charge,
        refund,
        act_domain_separator,
        accepted,
        act_params,
        act_key,
        act_key_id,
        act_ctx,
        seen_endorsement_nullifiers: std::collections::HashSet::new(),
        seen_spend_nullifiers: std::collections::HashSet::new(),
    })
}

impl TestMoleModerator {
    fn moderator_challenge(&self) -> ModeratorChallenge {
        ModeratorChallenge {
            endorsement_type: endorsement_type::IHAT,
            challenge: IhatChallenge { keys: self.accepted_anchor_keys.clone() }.to_bytes(),
        }
    }

    fn credential_challenge(&self) -> CredentialChallenge {
        CredentialChallenge {
            credential_type: credential_type::ACT,
            challenge: ActChallenge {
                policy_context: self.policy_context.clone(),
                charge: self.charge,
                topup: 0,
            }
            .to_bytes(),
        }
    }

    fn moderator_commitment(&self) -> ModeratorCommitment {
        ModeratorCommitment {
            found: true,
            policies: vec![CommittedPolicy {
                policy_context: self.policy_context.clone(),
                act_public_key: self.act_key.public().to_wire(),
                act_domain_separator: self.act_domain_separator.clone(),
                accepted_anchor_keys: self
                    .accepted_anchor_keys
                    .iter()
                    .map(|k| Blob { bytes: k.to_vec() })
                    .collect(),
                epochs: vec![Blob { bytes: self.endorsement_context.clone() }],
            }],
        }
    }

    fn moderator_directory_json(&self) -> String {
        let directory = ModeratorDirectory {
            policies: vec![ModeratorPolicy {
                policy_context: b64_encode(&self.policy_context),
                credential_type: credential_type::ACT,
                act_public_key: b64_encode(&self.act_key.public().to_wire()),
                act_domain_separator: b64_encode(&self.act_domain_separator),
                act_balance_digits: BALANCE_DIGITS as u64,
                initial_credits: self.initial_credits,
                issuance_batch: self.issuance_batch,
                charge: self.charge,
                endorsement_type: endorsement_type::IHAT,
                accepted_anchor_keys: self
                    .accepted_anchor_keys
                    .iter()
                    .map(|k| b64_encode(k))
                    .collect(),
                endorsement_context: b64_encode(&self.endorsement_context),
            }],
        };
        serde_json::to_string(&directory).expect("directory serializes")
    }

    /// 401 with the two `Mole` challenges.
    fn challenge_response(&self, mole_credential: String) -> TestHttpResponse {
        let credential = MoleChallenge {
            challenge: self.credential_challenge().to_bytes(),
            realm: Some("moderator".into()),
        };
        let endorsement = MoleChallenge {
            challenge: self.moderator_challenge().to_bytes(),
            realm: Some("moderator".into()),
        };
        TestHttpResponse {
            status: 401,
            www_authenticate: vec![credential.to_header_value(), endorsement.to_header_value()],
            mole_credential,
            body: b"credential required\n".to_vec(),
        }
    }

    /// 403: understood but rejected; deliberately uniform.
    fn reject(&self) -> TestHttpResponse {
        http(403, b"rejected\n")
    }

    fn handle_resource(&mut self, authorization_header: &str) -> TestHttpResponse {
        if authorization_header.is_empty() {
            return self.challenge_response(String::new());
        }
        match MoleAuthorization::parse(authorization_header) {
            Err(_) => self.challenge_response(String::new()),
            Ok(MoleAuthorization::CredentialRequest(bytes)) => self.redeem_and_issue(&bytes),
            Ok(MoleAuthorization::Presentation(bytes)) => self.present(&bytes),
        }
    }

    fn redeem_and_issue(&mut self, bytes: &[u8]) -> TestHttpResponse {
        let Ok(request) = CredentialRequest::from_bytes(bytes) else {
            return self.reject();
        };
        if request.endorsement_type != endorsement_type::IHAT
            || request.credential_type != credential_type::ACT
        {
            return self.challenge_response(String::new());
        }

        // Redeem: verify the IHAT presentation, bound to this challenge.
        let Ok(presentation) = IhatPresentation::from_bytes(&request.endorsement_presentation)
        else {
            return self.reject();
        };
        let Ok(presentation) = ihat_boring::Presentation::from_wire(&presentation.bytes) else {
            return self.reject();
        };
        let binding = challenge_digest(&self.moderator_challenge().to_bytes());
        if !presentation.verify(&self.accepted, &binding) {
            return self.reject();
        }
        if presentation.endorsement.endorsement_context != self.endorsement_context {
            return self.reject();
        }

        // Issue: everything is validated before the nullifier is recorded,
        // so a rejected request never spends the Client's Endorsement.
        let Ok(issuance) = ActIssuanceRequest::from_bytes(&request.issuance_request) else {
            return self.reject();
        };
        if issuance.truncated_key_id != self.act_key_id[31] {
            return self.reject();
        }
        if issuance.requests.len() as u64 != self.issuance_batch {
            return self.reject();
        }
        let Ok(act_requests) = issuance
            .requests
            .iter()
            .map(|bytes| ActIssuanceRequestMsg::from_wire(bytes))
            .collect::<Result<Vec<_>, _>>()
        else {
            return self.reject();
        };
        let Ok(responses) = act_requests
            .iter()
            .map(|act_request| {
                self.act_key
                    .issue::<BALANCE_DIGITS>(
                        &self.act_params,
                        act_request,
                        u128::from(self.initial_credits),
                        self.act_ctx.clone(),
                    )
                    .map(|response| response.to_wire().expect("issuance response encodes"))
            })
            .collect::<Result<Vec<_>, _>>()
        else {
            return self.reject();
        };

        // Recording the nullifier spends the Endorsement; it is the last
        // check.
        if !self
            .seen_endorsement_nullifiers
            .insert(presentation.endorsement.nf.clone())
        {
            return self.reject();
        }

        let credential_response = CredentialResponse {
            credential_type: credential_type::ACT,
            issuance_response: ActIssuanceResponse { responses }.to_bytes(),
        };
        self.challenge_response(
            MoleCredential::Response(credential_response.to_bytes()).to_header_value(),
        )
    }

    fn present(&mut self, bytes: &[u8]) -> TestHttpResponse {
        let Ok(presentation) = CredentialPresentation::from_bytes(bytes) else {
            return self.reject();
        };
        if presentation.credential_type != credential_type::ACT {
            return self.challenge_response(String::new());
        }
        let Ok(pau) =
            ActPresentationAndUpdate::from_bytes(&presentation.presentation_and_update)
        else {
            return self.reject();
        };

        let expected_digest = challenge_digest(&self.credential_challenge().to_bytes());
        if pau.challenge_digest != expected_digest || pau.key_id != self.act_key_id {
            return self.reject();
        }

        let Ok(spend) = SpendProof::from_wire(&pau.spend_proof) else {
            return self.reject();
        };
        if scalar_to_u128(&spend.s) != Some(u128::from(self.charge))
            || scalar_to_u128(&spend.a) != Some(0)
            || !spend.ctx.ct_eq(&self.act_ctx)
        {
            return self.reject();
        }

        let Ok(refund) = self.act_key.refund(
            &self.act_params,
            &spend,
            u128::from(self.refund),
            BALANCE_DIGITS,
        ) else {
            return self.reject();
        };
        if !self.seen_spend_nullifiers.insert(spend.k.to_bytes()) {
            return self.reject();
        }

        let update = OptionalCredentialUpdate {
            update: Some(CredentialUpdate {
                credential_type: credential_type::ACT,
                update_response: ActUpdate {
                    refund: refund.to_wire().expect("refund encodes"),
                }
                .to_bytes(),
            }),
        };
        TestHttpResponse {
            status: 200,
            www_authenticate: Vec::new(),
            mole_credential: MoleCredential::Update(update.to_bytes()).to_header_value(),
            body: b"the protected resource\n".to_vec(),
        }
    }

    fn endorsement_nullifier_count(&self) -> usize {
        self.seen_endorsement_nullifiers.len()
    }

    fn spend_nullifier_count(&self) -> usize {
        self.seen_spend_nullifiers.len()
    }
}
