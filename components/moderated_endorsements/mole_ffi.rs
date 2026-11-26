// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `cxx` FFI bridge over the spec-compliant MOLE cryptographic and transport
//! stack (`//third_party/mole`), exposing the Client side of
//! `draft-jms-mole-protocols-01` and `draft-jms-mole-http-transport-01` to C++
//! as a sans-I/O state machine.
//!
//! Key properties enforced here:
//! - Batched EC-IHAT grants (`0x0002`, `draft-ladd-mole-ec-ihat-00`) keyed by
//!   `grant_id`, eliminating cross-tab grant clobbering.
//! - Out-of-band `POST <issuance-uri>` Redeem & Issue (`redeem-0002` /
//!   `redeem-0001` with 32-byte `RedemptionChallenge` + `credential-request-0001`
//!   -> `200 OK` `Mole-Credential: response-0001`), keyed by `redeem_id`.
//! - Fail-closed `MoleCommitmentRegistry` enforcement pinning Anchor keys/epochs
//!   and Moderator `credential_key`, `balance_width`, `initial_balance`,
//!   `spend_amount`, `max_top_up`, `issuance_uri`, and ordered `anchor_set`.
//! - Durable write-ahead `PendingSpend` (`InFlight` and `Held`) state supporting
//!   `Mole-Credential: held-for-update-0001`, `Authorization: Mole recovery-0001`,
//!   `Authorization: Mole signoff-0001`, and empty `update-0001=""` (`NoUpdate`).

use std::collections::{HashMap, HashSet, VecDeque};

use mole_core::act::{DEFAULT_BALANCE_WIDTH, compute_ec_act_key_id, derive_ctx_cred};
use mole_core::config::{
    AnchorConfiguration, EcActKeyConfig, EcIhatEndorsementConfig, ModeratorConfiguration,
    NoEndorsementConfig, ValidatedEcActKey, ValidatedEcIhatSet, validate_https_endpoint_uri,
};
use mole_core::http::{
    MoleAuthorization, MoleChallenge, MoleCredential, b64_encode,
    format_endorsement_request_media_type, format_endorsement_response_media_type,
    format_www_authenticate, parse_challenges, parse_endorsement_request_media_type,
    parse_endorsement_response_media_type,
};
use mole_core::messages::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, EcIhatGrantPost, GrantChallenges, GrantCommitments, GrantRequest, GrantResponses,
    RecoveryHandle, RedemptionChallenge,
};
use mole_core::wire::Wire as _;
use mole_core::{
    CIPHERSUITE_P256_SHA256, EC_IHAT_CTX_RED, challenge_digest, credential_type, endorsement_type,
    fill_random, sha256,
};
use mole_p256::zeroize::Zeroizing;

/// Default number of EC-IHAT Endorsements requested per Anchor grant batch.
pub const DEFAULT_GRANT_BATCH_COUNT: u16 = 4;

#[cxx::bridge(namespace = "moderated_endorsements")]
pub mod ffi {
    /// Byte-vector wrapper (since `cxx` disallows nested `Vec<Vec<u8>>`).
    #[derive(Clone, Debug)]
    struct Blob {
        bytes: Vec<u8>,
    }

    /// Committed parameters authorized for an Anchor origin by the browser's
    /// key-commitment registry. `found == false` refuses grants (fail-closed).
    #[derive(Clone, Debug)]
    struct AnchorCommitment {
        found: bool,
        /// Optional exact `grant-uri` pin; when empty, any HTTPS path on the
        /// Anchor's own origin is permitted.
        grant_uri: String,
        /// Committed 33-byte SEC1-compressed P-256 Anchor public keys.
        keys: Vec<Blob>,
        /// Committed `issuance-epoch` (`ctx_iss`) byte strings.
        epochs: Vec<Blob>,
    }

    /// Committed policy invariants for one `credential_context` on a Moderator.
    #[derive(Clone, Debug)]
    struct CommittedPolicy {
        credential_context: Vec<u8>,
        credential_key: Vec<u8>,
        balance_width: u8,
        /// Exact initial balance `c` the Moderator MUST grant at issuance.
        /// Pinning this closes the per-Client initial-balance tagging channel.
        initial_balance: u64,
        spend_amount: u64,
        max_top_up: u64,
        /// Ordered 33-byte SEC1 Anchor public keys in the canonical `anchor-set`.
        accepted_anchor_keys: Vec<Blob>,
        /// Accepted `issuance-epoch` (`ctx_iss`) values.
        epochs: Vec<Blob>,
        /// Whether `0x0001` (`NoEndorsement`) is permitted for this policy.
        allow_no_endorsement: bool,
        /// Optional exact `issuance-uri` pin; when empty, any HTTPS path on the
        /// Moderator's own origin is permitted.
        issuance_uri: String,
    }

    /// Committed policies authorized for a Moderator origin.
    #[derive(Clone, Debug)]
    struct ModeratorCommitment {
        found: bool,
        policies: Vec<CommittedPolicy>,
    }

    /// Outcome of starting an EC-IHAT batch grant (`POST <grant_uri>`).
    #[derive(Clone, Debug)]
    struct GrantBegin {
        ok: bool,
        error: String,
        grant_id: u64,
        grant_uri: String,
        content_type: String,
        request_body: Vec<u8>,
    }

    /// Outcome of processing one grant HTTP response.
    #[derive(Clone, Debug)]
    struct GrantStep {
        ok: bool,
        error: String,
        done: bool,
        granted_count: usize,
        content_type: String,
        request_body: Vec<u8>,
    }

    /// Evaluation of a Moderator `401` `WWW-Authenticate: Mole` challenge set.
    #[derive(Clone, Debug)]
    struct ChallengeEval {
        ok: bool,
        error: String,
        credential_context: Vec<u8>,
        needs_redeem: bool,
        needs_endorsement: bool,
    }

    /// Outcome of building a `POST <issuance_uri>` Redeem & Issue request.
    #[derive(Clone, Debug)]
    struct RedeemBegin {
        ok: bool,
        error: String,
        redeem_id: u64,
        issuance_uri: String,
        authorization_header: String,
    }

    /// Outcome of finalizing `Mole-Credential: response-0001` on Redeem & Issue.
    #[derive(Clone, Debug)]
    struct RedeemFinish {
        ok: bool,
        error: String,
        pool_size: usize,
        balance: u64,
    }

    /// Outcome of building an `Authorization: Mole presentation-0001` header
    /// and recording write-ahead `Spent` recovery state.
    #[derive(Clone, Debug)]
    struct PresentBegin {
        ok: bool,
        error: String,
        presentation_id: u64,
        authorization_header: String,
    }

    /// Outcome of processing `Mole-Credential` on a presentation response.
    #[derive(Clone, Debug)]
    struct PresentOutcome {
        ok: bool,
        error: String,
        /// Non-zero when the Moderator answered `held-for-update-0001="<secs>"`.
        held_for_secs: u64,
        /// True when the Moderator answered `update-0001=""` (`NoUpdate`).
        consumed_no_update: bool,
    }

    /// A pending `recovery-0001` or `signoff-0001` `POST <issuance_uri>` exchange
    /// that must run before starting a new presentation at `moderator_origin`.
    #[derive(Clone, Debug)]
    struct PendingSettlement {
        has_pending: bool,
        pending_id: u64,
        is_signoff: bool,
        issuance_uri: String,
        authorization_header: String,
    }

    /// Outcome of completing a `recovery-0001` or `signoff-0001` exchange.
    #[derive(Clone, Debug)]
    struct SettleOutcome {
        ok: bool,
        error: String,
        credential_restored: bool,
    }

    /// In-process HTTP response representation for unit tests.
    #[derive(Clone, Debug)]
    struct TestHttpResponse {
        status: u16,
        content_type: String,
        www_authenticate: Vec<String>,
        mole_credential: String,
        cache_control: String,
        body: Vec<u8>,
    }

    extern "Rust" {
        type MoleBrowserClient;

        fn new_mole_browser_client() -> Box<MoleBrowserClient>;

        fn grant_begin(
            self: &mut MoleBrowserClient,
            anchor_origin: &str,
            anchor_config_json: &str,
            commitment: &AnchorCommitment,
            batch_count: u16,
        ) -> GrantBegin;

        fn grant_step(
            self: &mut MoleBrowserClient,
            grant_id: u64,
            response_content_type: &str,
            response_body: &[u8],
        ) -> GrantStep;

        fn grant_abort(self: &mut MoleBrowserClient, grant_id: u64);

        fn next_settlement(
            self: &MoleBrowserClient,
            moderator_origin: &str,
            now_unix_secs: u64,
        ) -> PendingSettlement;

        fn settle_finish(
            self: &mut MoleBrowserClient,
            pending_id: u64,
            http_status: u16,
            mole_credential_header: &str,
        ) -> SettleOutcome;

        fn challenge_eval(
            self: &mut MoleBrowserClient,
            moderator_origin: &str,
            www_authenticate: &Vec<String>,
            commitment: &ModeratorCommitment,
        ) -> ChallengeEval;

        fn redeem_begin(
            self: &mut MoleBrowserClient,
            moderator_origin: &str,
            moderator_config_json: &str,
            www_authenticate: &Vec<String>,
            commitment: &ModeratorCommitment,
        ) -> RedeemBegin;

        fn redeem_finish(
            self: &mut MoleBrowserClient,
            redeem_id: u64,
            mole_credential_header: &str,
        ) -> RedeemFinish;

        fn redeem_abort(self: &mut MoleBrowserClient, redeem_id: u64);

        fn present_begin(
            self: &mut MoleBrowserClient,
            moderator_origin: &str,
            resource_url: &str,
            www_authenticate: &Vec<String>,
            commitment: &ModeratorCommitment,
            now_unix_secs: u64,
        ) -> PresentBegin;

        fn present_finish(
            self: &mut MoleBrowserClient,
            presentation_id: u64,
            mole_credential_header: &str,
            now_unix_secs: u64,
        ) -> PresentOutcome;

        fn pool_size(
            self: &MoleBrowserClient,
            moderator_origin: &str,
            credential_context: &[u8],
        ) -> usize;

        fn balance(
            self: &MoleBrowserClient,
            moderator_origin: &str,
            credential_context: &[u8],
        ) -> u64;

        fn endorsement_count(self: &MoleBrowserClient) -> usize;
        fn pending_spend_count(self: &MoleBrowserClient) -> usize;

        fn serialize_state(self: &MoleBrowserClient) -> Vec<u8>;
        fn restore_state(self: &mut MoleBrowserClient, bytes: &[u8]) -> bool;

        // --- In-process spec-compliant test servers ---

        type TestMoleAnchor;

        fn new_test_anchor(origin: &str, issuance_epoch: &[u8]) -> Box<TestMoleAnchor>;
        fn anchor_config_json(self: &TestMoleAnchor) -> String;
        fn anchor_public_key(self: &TestMoleAnchor) -> Vec<u8>;
        fn anchor_commitment(self: &TestMoleAnchor) -> AnchorCommitment;
        fn handle_grant(
            self: &mut TestMoleAnchor,
            content_type: &str,
            body: &[u8],
        ) -> TestHttpResponse;

        type TestMoleModerator;

        #[allow(clippy::too_many_arguments)]
        fn new_test_moderator(
            origin: &str,
            accepted_anchor_keys: &Vec<Blob>,
            issuance_epoch: &[u8],
            credential_context: &[u8],
            balance_width: u8,
            initial_balance: u64,
            spend_amount: u64,
            max_top_up: u64,
            refund_amount: u64,
        ) -> Box<TestMoleModerator>;

        fn set_hold_duration_secs(self: &mut TestMoleModerator, hold_secs: u64);
        fn set_withhold_update(self: &mut TestMoleModerator, withhold: bool);
        fn set_allow_no_endorsement(self: &mut TestMoleModerator, allow: bool);
        fn advance_clock_secs(self: &mut TestMoleModerator, delta_secs: u64);

        fn moderator_config_json(self: &TestMoleModerator) -> String;
        fn moderator_commitment(self: &TestMoleModerator) -> ModeratorCommitment;
        fn handle_issue(
            self: &mut TestMoleModerator,
            authorization_header: &str,
        ) -> TestHttpResponse;
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
    ModeratorCommitment, PendingSettlement, PresentBegin, PresentOutcome, RedeemBegin,
    RedeemFinish, SettleOutcome, TestHttpResponse,
};

// ---------------------------------------------------------------------------
// Client State Machine
// ---------------------------------------------------------------------------

/// Version tag for `MoleClientState` binary persistence (`0x02` = `-01` spec).
const STATE_FORMAT_VERSION: u8 = 2;

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    moderator_origin: String,
    credential_context: Vec<u8>,
}

struct StoredEndorsement {
    endorsement: ec_ihat::Endorsement,
    anchor_origin: String,
    anchor_key: [u8; 33],
    issuance_epoch: Vec<u8>,
}

struct StoredCredential {
    credential: ec_act::Credential,
    public_key: ec_act::PublicKey,
    key_id: [u8; 32],
    balance_width: u8,
    ctx_cred: Vec<u8>,
    issuance_uri: String,
}

enum PendingGrant {
    AwaitingCommitments {
        anchor_origin: String,
        anchor_key_bytes: [u8; 33],
        public_key: ec_ihat::PublicKey,
        issuance_epoch: Vec<u8>,
        requested_count: u16,
    },
    AwaitingResponses {
        anchor_origin: String,
        anchor_key_bytes: [u8; 33],
        public_key: ec_ihat::PublicKey,
        issuance_epoch: Vec<u8>,
        states: Vec<ec_ihat::ClientState>,
    },
}

struct PendingRedeem {
    moderator_origin: String,
    issuance_uri: String,
    credential_context: Vec<u8>,
    ctx_cred: Vec<u8>,
    balance_width: u8,
    expected_initial_balance: u64,
    public_key: ec_act::PublicKey,
    key_id: [u8; 32],
    params: ec_act::Params,
    issuance_state: ec_act::ClientIssuanceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingSpendStatus {
    InFlight,
    Held { hold_until_unix_secs: u64 },
}

struct PendingSpend {
    status: PendingSpendStatus,
    moderator_origin: String,
    issuance_uri: String,
    resource_url: String,
    credential_context: Vec<u8>,
    ctx_cred: Vec<u8>,
    balance_width: u8,
    public_key: ec_act::PublicKey,
    key_id: [u8; 32],
    spend_state: ec_act::ClientSpendState,
    presentation_bytes: Vec<u8>,
    recovery_handle: [u8; 96],
}

/// Sans-I/O MOLE Client state machine.
pub struct MoleBrowserClient {
    endorsements: Vec<StoredEndorsement>,
    pools: HashMap<PoolKey, VecDeque<StoredCredential>>,
    grants: HashMap<u64, PendingGrant>,
    redeems: HashMap<u64, PendingRedeem>,
    pending_spends: HashMap<u64, PendingSpend>,
    next_id: u64,
}

pub fn new_mole_browser_client() -> Box<MoleBrowserClient> {
    Box::new(MoleBrowserClient {
        endorsements: Vec::new(),
        pools: HashMap::new(),
        grants: HashMap::new(),
        redeems: HashMap::new(),
        pending_spends: Vec::new().into_iter().collect(),
        next_id: 1,
    })
}

struct ParsedModeratorChallenges {
    raw_act_challenge: Vec<u8>,
    act_challenge: EcActChallenge,
    ihat_redeem_challenge: Option<[u8; 32]>,
    no_endorsement_redeem_challenge: Option<[u8; 32]>,
}

fn parse_moderator_challenges(
    header_values: &[String],
) -> Result<ParsedModeratorChallenges, String> {
    let refs: Vec<&str> = header_values.iter().map(String::as_str).collect();
    let challenges = parse_challenges(&refs);

    let mut cred_pair: Option<(Vec<u8>, EcActChallenge)> = None;
    let mut ihat_redeem: Option<[u8; 32]> = None;
    let mut no_end_redeem: Option<[u8; 32]> = None;

    for ch in challenges {
        match ch {
            MoleChallenge::Credential {
                credential_type: credential_type::EC_ACT,
                challenge,
            } if cred_pair.is_none() => {
                if let Ok(decoded) = EcActChallenge::from_bytes(&challenge) {
                    cred_pair = Some((challenge, decoded));
                }
            }
            MoleChallenge::Redeem {
                endorsement_type: endorsement_type::EC_IHAT,
                challenge,
            } if ihat_redeem.is_none() => {
                ihat_redeem = Some(challenge);
            }
            MoleChallenge::Redeem {
                endorsement_type: endorsement_type::NO_ENDORSEMENT,
                challenge,
            } if no_end_redeem.is_none() => {
                no_end_redeem = Some(challenge);
            }
            _ => {}
        }
    }

    let Some((raw_act_challenge, act_challenge)) = cred_pair else {
        return Err("missing valid challenge-0001 in WWW-Authenticate".into());
    };
    Ok(ParsedModeratorChallenges {
        raw_act_challenge,
        act_challenge,
        ihat_redeem_challenge: ihat_redeem,
        no_endorsement_redeem_challenge: no_end_redeem,
    })
}

fn canonicalize_origin(origin: &str) -> Result<String, String> {
    let (canon, _) = validate_https_endpoint_uri(origin).map_err(|e| e.to_string())?;
    Ok(canon)
}

impl MoleBrowserClient {
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    pub fn grant_begin(
        &mut self,
        anchor_origin: &str,
        anchor_config_json: &str,
        commitment: &AnchorCommitment,
        batch_count: u16,
    ) -> GrantBegin {
        let fail = |error: String| GrantBegin {
            ok: false,
            error,
            grant_id: 0,
            grant_uri: String::new(),
            content_type: String::new(),
            request_body: Vec::new(),
        };

        if !commitment.found {
            return fail("anchor is not enrolled in the key-commitment registry".into());
        }
        let count = if batch_count == 0 {
            DEFAULT_GRANT_BATCH_COUNT
        } else {
            batch_count.min(64)
        };
        let Ok(expected_origin) = canonicalize_origin(anchor_origin) else {
            return fail("anchor origin must be https".into());
        };
        let config: AnchorConfiguration = match serde_json::from_str(anchor_config_json) {
            Ok(c) => c,
            Err(e) => return fail(format!("malformed anchor configuration JSON: {e}")),
        };
        let validated = match config.validate_ec_ihat() {
            Ok(v) => v,
            Err(e) => return fail(format!("invalid anchor configuration: {e}")),
        };
        if validated.origin != expected_origin {
            return fail("anchor grant-uri must be same-origin with anchor".into());
        }
        if !commitment.grant_uri.is_empty() && validated.grant_uri != commitment.grant_uri {
            return fail("anchor grant-uri does not match committed grant-uri".into());
        }
        if !commitment
            .keys
            .iter()
            .any(|k| k.bytes.as_slice() == validated.anchor_key_bytes)
        {
            return fail("anchor-key is not in the committed key set".into());
        }
        if !commitment
            .epochs
            .iter()
            .any(|e| e.bytes == validated.issuance_epoch)
        {
            return fail("issuance-epoch is not in the committed epoch set".into());
        }

        let Ok(request_body) = (GrantRequest { count }).to_bytes() else {
            return fail("failed to encode GrantRequest".into());
        };
        let Ok(content_type) = format_endorsement_request_media_type(endorsement_type::EC_IHAT)
        else {
            return fail("failed to format endorsement media type".into());
        };

        let grant_id = self.alloc_id();
        self.grants.insert(
            grant_id,
            PendingGrant::AwaitingCommitments {
                anchor_origin: expected_origin,
                anchor_key_bytes: validated.anchor_key_bytes,
                public_key: validated.public_key,
                issuance_epoch: validated.issuance_epoch,
                requested_count: count,
            },
        );

        GrantBegin {
            ok: true,
            error: String::new(),
            grant_id,
            grant_uri: validated.grant_uri,
            content_type,
            request_body,
        }
    }

    pub fn grant_step(
        &mut self,
        grant_id: u64,
        response_content_type: &str,
        response_body: &[u8],
    ) -> GrantStep {
        let fail = |error: String| GrantStep {
            ok: false,
            error,
            done: false,
            granted_count: 0,
            content_type: String::new(),
            request_body: Vec::new(),
        };

        let Some(state) = self.grants.remove(&grant_id) else {
            return fail("unknown or completed grant_id".into());
        };

        match parse_endorsement_response_media_type(response_content_type) {
            Ok(t) if t == endorsement_type::EC_IHAT => {}
            _ => return fail("unexpected or missing grant response Content-Type".into()),
        }

        match state {
            PendingGrant::AwaitingCommitments {
                anchor_origin,
                anchor_key_bytes,
                public_key,
                issuance_epoch,
                requested_count,
            } => {
                let Ok(grant_commitments) = GrantCommitments::from_bytes(response_body) else {
                    return fail("malformed GrantCommitments".into());
                };
                if grant_commitments.commitments.len() > usize::from(requested_count) {
                    return fail("Anchor returned more commitments than requested".into());
                }
                let mut states = Vec::with_capacity(grant_commitments.commitments.len());
                let mut challenges = Vec::with_capacity(grant_commitments.commitments.len());
                for commitment in &grant_commitments.commitments {
                    let Ok((client_state, challenge_msg)) = ec_ihat::challenge(
                        &public_key,
                        &issuance_epoch,
                        EC_IHAT_CTX_RED,
                        commitment,
                    ) else {
                        return fail("EC-IHAT challenge generation failed".into());
                    };
                    states.push(client_state);
                    challenges.push(challenge_msg);
                }
                let Ok(request_body) = (GrantChallenges {
                    session_id: grant_commitments.session_id,
                    challenges,
                })
                .to_bytes() else {
                    return fail("failed to encode GrantChallenges".into());
                };
                let Ok(content_type) =
                    format_endorsement_request_media_type(endorsement_type::EC_IHAT)
                else {
                    return fail("failed to format media type".into());
                };
                self.grants.insert(
                    grant_id,
                    PendingGrant::AwaitingResponses {
                        anchor_origin,
                        anchor_key_bytes,
                        public_key,
                        issuance_epoch,
                        states,
                    },
                );
                GrantStep {
                    ok: true,
                    error: String::new(),
                    done: false,
                    granted_count: 0,
                    content_type,
                    request_body,
                }
            }
            PendingGrant::AwaitingResponses {
                anchor_origin,
                anchor_key_bytes,
                public_key,
                issuance_epoch,
                states,
            } => {
                let Ok(grant_responses) = GrantResponses::from_bytes(response_body) else {
                    return fail("malformed GrantResponses".into());
                };
                if grant_responses.responses.len() != states.len() {
                    return fail("GrantResponses count does not match challenges sent".into());
                }
                // `draft-jms-mole-protocols-01` §4.4.2 step 3: if Finalize fails
                // for ANY session, discard EVERY session and finalized endorsement
                // in the batch!
                let mut batch_endorsements = Vec::with_capacity(states.len());
                for (client_state, response_msg) in states.into_iter().zip(&grant_responses.responses)
                {
                    let Ok(endorsement) =
                        ec_ihat::finalize(&public_key, client_state, response_msg)
                    else {
                        return fail("EC-IHAT finalize failed; entire batch discarded".into());
                    };
                    batch_endorsements.push(StoredEndorsement {
                        endorsement,
                        anchor_origin: anchor_origin.clone(),
                        anchor_key: anchor_key_bytes,
                        issuance_epoch: issuance_epoch.clone(),
                    });
                }
                let granted_count = batch_endorsements.len();
                self.endorsements.extend(batch_endorsements);
                GrantStep {
                    ok: true,
                    error: String::new(),
                    done: true,
                    granted_count,
                    content_type: String::new(),
                    request_body: Vec::new(),
                }
            }
        }
    }

    pub fn grant_abort(&mut self, grant_id: u64) {
        self.grants.remove(&grant_id);
    }

    pub fn next_settlement(&self, moderator_origin: &str, now_unix_secs: u64) -> PendingSettlement {
        let empty = PendingSettlement {
            has_pending: false,
            pending_id: 0,
            is_signoff: false,
            issuance_uri: String::new(),
            authorization_header: String::new(),
        };
        let Ok(canon_origin) = canonicalize_origin(moderator_origin) else {
            return empty;
        };
        let mut candidate_ids: Vec<u64> = self
            .pending_spends
            .iter()
            .filter(|(_, p)| p.moderator_origin == canon_origin)
            .map(|(&id, _)| id)
            .collect();
        candidate_ids.sort_unstable();
        let Some(&pending_id) = candidate_ids.first() else {
            return empty;
        };
        let pending = &self.pending_spends[&pending_id];
        let is_signoff = match pending.status {
            PendingSpendStatus::InFlight => false,
            PendingSpendStatus::Held {
                hold_until_unix_secs,
            } => now_unix_secs < hold_until_unix_secs,
        };
        let auth = if is_signoff {
            MoleAuthorization::Signoff {
                credential_type: credential_type::EC_ACT,
                recovery_handle: pending.recovery_handle.to_vec(),
            }
        } else {
            MoleAuthorization::Recovery {
                credential_type: credential_type::EC_ACT,
                recovery_handle: pending.recovery_handle.to_vec(),
            }
        };
        let Ok(authorization_header) = auth.to_header_value() else {
            return empty;
        };
        PendingSettlement {
            has_pending: true,
            pending_id,
            is_signoff,
            issuance_uri: pending.issuance_uri.clone(),
            authorization_header,
        }
    }

    pub fn settle_finish(
        &mut self,
        pending_id: u64,
        http_status: u16,
        mole_credential_header: &str,
    ) -> SettleOutcome {
        let Some(pending) = self.pending_spends.remove(&pending_id) else {
            return SettleOutcome {
                ok: false,
                error: "unknown pending_id".into(),
                credential_restored: false,
            };
        };

        // `404` means the recovery window ended or no record exists (`draft-jms-mole-http-transport-01` §5.4).
        // Per `draft-jms-mole-protocols-01` §5.2.5, discard the spend state.
        if http_status == 404 {
            return SettleOutcome {
                ok: true,
                error: String::new(),
                credential_restored: false,
            };
        }

        if mole_credential_header.is_empty() {
            // Transport drop or transient 5xx: keep pending state so a later retry can recover!
            self.pending_spends.insert(pending_id, pending);
            return SettleOutcome {
                ok: false,
                error: "missing Mole-Credential on settlement response".into(),
                credential_restored: false,
            };
        }

        match MoleCredential::parse(mole_credential_header) {
            Ok(MoleCredential::Update {
                credential_type: credential_type::EC_ACT,
                update: None,
            }) => {
                // Recorded `NoUpdate`: chain intentionally ended by Moderator.
                SettleOutcome {
                    ok: true,
                    error: String::new(),
                    credential_restored: false,
                }
            }
            Ok(MoleCredential::Update {
                credential_type: credential_type::EC_ACT,
                update: Some(bytes),
            }) => {
                let Ok(params) = ec_act::Params::new(pending.balance_width) else {
                    return SettleOutcome {
                        ok: false,
                        error: "invalid balance_width".into(),
                        credential_restored: false,
                    };
                };
                let Ok(act_update) = EcActUpdate::from_bytes(&params, &bytes) else {
                    self.pending_spends.insert(pending_id, pending);
                    return SettleOutcome {
                        ok: false,
                        error: "malformed EcActUpdate on settlement".into(),
                        credential_restored: false,
                    };
                };
                let spend_backup = pending.spend_state.to_bytes();
                let Ok(credential) = ec_act::finalize_refund(
                    &params,
                    &pending.public_key,
                    &pending.ctx_cred,
                    pending.spend_state,
                    &act_update.refund,
                ) else {
                    if let Ok(restored_spend_state) =
                        ec_act::ClientSpendState::from_bytes(&params, &spend_backup)
                    {
                        self.pending_spends.insert(
                            pending_id,
                            PendingSpend {
                                status: pending.status,
                                moderator_origin: pending.moderator_origin,
                                issuance_uri: pending.issuance_uri,
                                resource_url: pending.resource_url,
                                credential_context: pending.credential_context,
                                ctx_cred: pending.ctx_cred,
                                balance_width: pending.balance_width,
                                public_key: pending.public_key,
                                key_id: pending.key_id,
                                spend_state: restored_spend_state,
                                presentation_bytes: pending.presentation_bytes,
                                recovery_handle: pending.recovery_handle,
                            },
                        );
                    }
                    return SettleOutcome {
                        ok: false,
                        error: "settlement refund verification failed".into(),
                        credential_restored: false,
                    };
                };
                let key = PoolKey {
                    moderator_origin: pending.moderator_origin,
                    credential_context: pending.credential_context,
                };
                self.pools.entry(key).or_default().push_back(StoredCredential {
                    credential,
                    public_key: pending.public_key,
                    key_id: pending.key_id,
                    balance_width: pending.balance_width,
                    ctx_cred: pending.ctx_cred,
                    issuance_uri: pending.issuance_uri,
                });
                SettleOutcome {
                    ok: true,
                    error: String::new(),
                    credential_restored: true,
                }
            }
            _ => {
                self.pending_spends.insert(pending_id, pending);
                SettleOutcome {
                    ok: false,
                    error: "unexpected Mole-Credential parameter on settlement".into(),
                    credential_restored: false,
                }
            }
        }
    }

    fn drain_insufficient_credentials(
        &mut self,
        key: &PoolKey,
        spend_amount: u64,
        max_top_up: u64,
    ) -> bool {
        let Some(pool) = self.pools.get_mut(key) else {
            return false;
        };
        while let Some(front) = pool.front() {
            let max_bal = u64::MAX >> (64 - u32::from(front.balance_width));
            let bal = front.credential.balance();
            let covers_spend = bal >= spend_amount;
            let fits_top_up = bal
                .checked_add(max_top_up)
                .is_some_and(|sum| sum <= max_bal);
            if covers_spend && fits_top_up {
                return true;
            }
            // Drop exhausted credential so subsequent attempts steer cleanly into Redeem & Issue.
            pool.pop_front();
        }
        false
    }

    fn find_usable_endorsement(
        &self,
        accepted_keys: &[[u8; 33]],
        accepted_epochs: &[Vec<u8>],
    ) -> Option<usize> {
        self.endorsements.iter().position(|e| {
            accepted_epochs.iter().any(|ep| ep == &e.issuance_epoch)
                && accepted_keys.iter().any(|k| k == &e.anchor_key)
        })
    }

    pub fn challenge_eval(
        &mut self,
        moderator_origin: &str,
        www_authenticate: &Vec<String>,
        commitment: &ModeratorCommitment,
    ) -> ChallengeEval {
        let fail = |error: String| ChallengeEval {
            ok: false,
            error,
            credential_context: Vec::new(),
            needs_redeem: false,
            needs_endorsement: false,
        };

        if !commitment.found {
            return fail("moderator is not enrolled in the key-commitment registry".into());
        }
        let Ok(canon_origin) = canonicalize_origin(moderator_origin) else {
            return fail("moderator origin must be https".into());
        };
        let parsed = match parse_moderator_challenges(www_authenticate) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        let Some(committed) = commitment
            .policies
            .iter()
            .find(|p| p.credential_context == parsed.act_challenge.credential_context)
        else {
            return fail("challenged credential_context is not committed for this moderator".into());
        };
        if parsed.act_challenge.spend_amount != committed.spend_amount
            || parsed.act_challenge.max_top_up != committed.max_top_up
        {
            return fail("challenged spend_amount/max_top_up differ from committed policy".into());
        }

        let key = PoolKey {
            moderator_origin: canon_origin,
            credential_context: parsed.act_challenge.credential_context.clone(),
        };
        let has_usable = self.drain_insufficient_credentials(
            &key,
            parsed.act_challenge.spend_amount,
            parsed.act_challenge.max_top_up,
        );
        let needs_redeem = !has_usable;

        let mut needs_endorsement = false;
        if needs_redeem {
            let can_use_no_endorsement = committed.allow_no_endorsement
                && parsed.no_endorsement_redeem_challenge.is_some();
            if !can_use_no_endorsement {
                if parsed.ihat_redeem_challenge.is_none() {
                    return fail("challenge offers no usable redeem-T parameter".into());
                }
                let committed_keys: Option<Vec<[u8; 33]>> = committed
                    .accepted_anchor_keys
                    .iter()
                    .map(|b| b.bytes.as_slice().try_into().ok())
                    .collect();
                let Some(committed_keys) = committed_keys else {
                    return fail("committed accepted_anchor_keys has non-33B entry".into());
                };
                let committed_epochs: Vec<Vec<u8>> =
                    committed.epochs.iter().map(|e| e.bytes.clone()).collect();
                needs_endorsement =
                    self.find_usable_endorsement(&committed_keys, &committed_epochs).is_none();
            }
        }

        ChallengeEval {
            ok: true,
            error: String::new(),
            credential_context: parsed.act_challenge.credential_context,
            needs_redeem,
            needs_endorsement,
        }
    }

    pub fn redeem_begin(
        &mut self,
        moderator_origin: &str,
        moderator_config_json: &str,
        www_authenticate: &Vec<String>,
        commitment: &ModeratorCommitment,
    ) -> RedeemBegin {
        let fail = |error: String| RedeemBegin {
            ok: false,
            error,
            redeem_id: 0,
            issuance_uri: String::new(),
            authorization_header: String::new(),
        };

        if !commitment.found {
            return fail("moderator is not enrolled in the key-commitment registry".into());
        }
        let Ok(canon_origin) = canonicalize_origin(moderator_origin) else {
            return fail("moderator origin must be https".into());
        };
        let parsed = match parse_moderator_challenges(www_authenticate) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        let Some(committed) = commitment
            .policies
            .iter()
            .find(|p| p.credential_context == parsed.act_challenge.credential_context)
        else {
            return fail("challenged credential_context is not committed".into());
        };
        if parsed.act_challenge.spend_amount != committed.spend_amount
            || parsed.act_challenge.max_top_up != committed.max_top_up
        {
            return fail("challenged spend_amount/max_top_up differ from committed policy".into());
        }

        let mod_cfg_raw: ModeratorConfiguration = match serde_json::from_str(moderator_config_json)
        {
            Ok(c) => c,
            Err(e) => return fail(format!("malformed moderator configuration JSON: {e}")),
        };
        let validated_mod = match mod_cfg_raw.validate() {
            Ok(v) => v,
            Err(e) => return fail(format!("invalid moderator configuration: {e}")),
        };
        if validated_mod.issuance_origin != canon_origin {
            return fail("moderator issuance-uri must be same-origin with moderator".into());
        }
        if !committed.issuance_uri.is_empty()
            && validated_mod.issuance_uri != committed.issuance_uri
        {
            return fail("moderator issuance-uri does not match committed issuance-uri".into());
        }

        // Match and verify the committed EC-ACT key & balance_width.
        let Some(act_key): Option<&ValidatedEcActKey> = validated_mod
            .ec_act_keys
            .iter()
            .find(|k| k.credential_context == committed.credential_context)
        else {
            return fail("moderator configuration lacks challenged credential-context".into());
        };
        if act_key.public_key_bytes.as_slice() != committed.credential_key.as_slice() {
            return fail("moderator credential-key does not match committed key".into());
        }
        if act_key.balance_width != committed.balance_width {
            return fail("moderator balance-width does not match committed balance-width".into());
        }
        let Ok(params) = ec_act::Params::new(act_key.balance_width) else {
            return fail("invalid balance-width".into());
        };
        if committed.initial_balance > params.max_amount()
            || committed.spend_amount > params.max_amount()
            || committed.max_top_up > params.max_amount()
            || committed
                .spend_amount
                .checked_add(committed.max_top_up)
                .is_none_or(|s| s > params.max_amount())
        {
            return fail("committed policy amounts exceed 2^L - 1".into());
        }

        // Build the endorsement redemption (`0x0001` NoEndorsement if permitted &
        // offered, otherwise `0x0002` EC-IHAT).
        let (selected_endorsement_type, redemption_bytes) = if committed.allow_no_endorsement
            && validated_mod.allows_no_endorsement
            && parsed.no_endorsement_redeem_challenge.is_some()
        {
            (endorsement_type::NO_ENDORSEMENT, Vec::new())
        } else {
            let Some(red_chal_bytes) = parsed.ihat_redeem_challenge else {
                return fail("missing redeem-0002 challenge".into());
            };
            let committed_keys: Option<Vec<[u8; 33]>> = committed
                .accepted_anchor_keys
                .iter()
                .map(|b| b.bytes.as_slice().try_into().ok())
                .collect();
            let Some(committed_keys) = committed_keys else {
                return fail("committed accepted_anchor_keys invalid".into());
            };
            let committed_epochs: Vec<Vec<u8>> =
                committed.epochs.iter().map(|e| e.bytes.clone()).collect();

            // Verify every advertised EC-IHAT set for committed epochs matches the
            // exact ordered committed `anchor-set` (defeating subset/reordering attacks!).
            let Some(end_idx) =
                self.find_usable_endorsement(&committed_keys, &committed_epochs)
            else {
                return fail("no stored endorsement matches committed policy".into());
            };
            let target_epoch = &self.endorsements[end_idx].issuance_epoch;
            let Some(ihat_set): Option<&ValidatedEcIhatSet> = validated_mod
                .ec_ihat_sets
                .iter()
                .find(|s| &s.issuance_epoch == target_epoch)
            else {
                return fail("moderator configuration lacks endorsement epoch".into());
            };
            if ihat_set.raw_keys != committed_keys {
                return fail(
                    "moderator anchor-set does not match committed ordered anchor-set".into(),
                );
            }

            let stored = self.endorsements.swap_remove(end_idx);
            let Some(anchor_pos) = ihat_set
                .raw_keys
                .iter()
                .position(|k| k == &stored.anchor_key)
            else {
                return fail("endorsement anchor missing from anchor-set".into());
            };
            let red_challenge = RedemptionChallenge {
                redemption_context: red_chal_bytes,
            };
            let challenge_dig = red_challenge.digest();
            let Ok(redemption) = ec_ihat::redeem(
                &ihat_set.anchor_set,
                anchor_pos,
                stored.endorsement,
                &stored.issuance_epoch,
                EC_IHAT_CTX_RED,
                &challenge_dig,
            ) else {
                return fail("EC-IHAT redeem proof generation failed".into());
            };
            (endorsement_type::EC_IHAT, redemption.to_bytes())
        };

        // Create single EC-ACT IssuanceRequest (`draft-jms-mole-protocols-01` §5.2.2).
        let Ok((issuance_state, issue_req_msg)) = ec_act::issue_request(&params) else {
            return fail("EC-ACT issue_request failed".into());
        };
        let Ok(issuance_req_bytes) = (EcActIssuanceRequest {
            truncated_key_id: act_key.truncated_key_id,
            credential_context: act_key.credential_context.clone(),
            request: issue_req_msg,
        })
        .to_bytes() else {
            return fail("failed to encode EcActIssuanceRequest".into());
        };
        let Ok(authorization_header) = (MoleAuthorization::RedeemAndIssue {
            endorsement_type: selected_endorsement_type,
            redemption: redemption_bytes,
            credential_type: credential_type::EC_ACT,
            credential_request: issuance_req_bytes,
        })
        .to_header_value() else {
            return fail("failed to format Authorization header".into());
        };

        let redeem_id = self.alloc_id();
        self.redeems.insert(
            redeem_id,
            PendingRedeem {
                moderator_origin: canon_origin,
                issuance_uri: validated_mod.issuance_uri.clone(),
                credential_context: act_key.credential_context.clone(),
                ctx_cred: act_key.ctx_cred.clone(),
                balance_width: act_key.balance_width,
                expected_initial_balance: committed.initial_balance,
                public_key: act_key.public_key.clone(),
                key_id: act_key.key_id,
                params,
                issuance_state,
            },
        );

        RedeemBegin {
            ok: true,
            error: String::new(),
            redeem_id,
            issuance_uri: validated_mod.issuance_uri,
            authorization_header,
        }
    }

    pub fn redeem_finish(
        &mut self,
        redeem_id: u64,
        mole_credential_header: &str,
    ) -> RedeemFinish {
        let fail = |error: String| RedeemFinish {
            ok: false,
            error,
            pool_size: 0,
            balance: 0,
        };

        let Some(redeem) = self.redeems.remove(&redeem_id) else {
            return fail("unknown or completed redeem_id".into());
        };
        let response_bytes = match MoleCredential::parse(mole_credential_header) {
            Ok(MoleCredential::Response {
                credential_type: credential_type::EC_ACT,
                response,
            }) => response,
            _ => return fail("expected Mole-Credential: response-0001".into()),
        };
        let Ok(issuance_resp) = EcActIssuanceResponse::from_bytes(&redeem.params, &response_bytes)
        else {
            return fail("malformed EcActIssuanceResponse".into());
        };

        // Pin `initial_balance` against `CommittedPolicy` to close the per-user
        // initial-balance tagging side channel!
        if issuance_resp.response.balance() != redeem.expected_initial_balance {
            return fail(format!(
                "issued balance {} does not match committed initial_balance {}",
                issuance_resp.response.balance(),
                redeem.expected_initial_balance
            ));
        }

        let Ok(credential) = ec_act::finalize_issue(
            &redeem.params,
            &redeem.public_key,
            &redeem.ctx_cred,
            redeem.issuance_state,
            &issuance_resp.response,
        ) else {
            return fail("EC-ACT finalize_issue failed".into());
        };

        let key = PoolKey {
            moderator_origin: redeem.moderator_origin.clone(),
            credential_context: redeem.credential_context.clone(),
        };
        let pool = self.pools.entry(key).or_default();
        pool.push_back(StoredCredential {
            credential,
            public_key: redeem.public_key,
            key_id: redeem.key_id,
            balance_width: redeem.balance_width,
            ctx_cred: redeem.ctx_cred,
            issuance_uri: redeem.issuance_uri,
        });
        let pool_size = pool.len();
        let balance = self.balance(&redeem.moderator_origin, &redeem.credential_context);

        RedeemFinish {
            ok: true,
            error: String::new(),
            pool_size,
            balance,
        }
    }

    pub fn redeem_abort(&mut self, redeem_id: u64) {
        self.redeems.remove(&redeem_id);
    }

    pub fn present_begin(
        &mut self,
        moderator_origin: &str,
        resource_url: &str,
        www_authenticate: &Vec<String>,
        commitment: &ModeratorCommitment,
        _now_unix_secs: u64,
    ) -> PresentBegin {
        let fail = |error: String| PresentBegin {
            ok: false,
            error,
            presentation_id: 0,
            authorization_header: String::new(),
        };

        if !commitment.found {
            return fail("moderator is not enrolled in the key-commitment registry".into());
        }
        let Ok(canon_origin) = canonicalize_origin(moderator_origin) else {
            return fail("moderator origin must be https".into());
        };
        let parsed = match parse_moderator_challenges(www_authenticate) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        let Some(committed) = commitment
            .policies
            .iter()
            .find(|p| p.credential_context == parsed.act_challenge.credential_context)
        else {
            return fail("challenged credential_context is not committed".into());
        };
        if parsed.act_challenge.spend_amount != committed.spend_amount
            || parsed.act_challenge.max_top_up != committed.max_top_up
        {
            return fail("challenged spend_amount/max_top_up differ from committed policy".into());
        }

        let key = PoolKey {
            moderator_origin: canon_origin.clone(),
            credential_context: parsed.act_challenge.credential_context.clone(),
        };
        if !self.drain_insufficient_credentials(
            &key,
            parsed.act_challenge.spend_amount,
            parsed.act_challenge.max_top_up,
        ) {
            return fail("no usable credential pooled for this (moderator, context)".into());
        }
        let Some(stored) = self.pools.get_mut(&key).and_then(VecDeque::pop_front) else {
            return fail("no credential pooled".into());
        };

        let Ok(params) = ec_act::Params::new(stored.balance_width) else {
            return fail("invalid stored balance_width".into());
        };
        let ctx_spend = challenge_digest(&parsed.raw_act_challenge);
        let Ok((spend_state, spend_msg)) = ec_act::prove_spend(
            &params,
            stored.credential,
            &stored.ctx_cred,
            parsed.act_challenge.spend_amount,
            parsed.act_challenge.max_top_up,
            &ctx_spend,
        ) else {
            return fail("EC-ACT prove_spend failed".into());
        };

        let pau = EcActPresentationAndUpdate {
            key_id: stored.key_id,
            spend: spend_msg,
        };
        let presentation_bytes = pau.to_bytes();
        let recovery_handle = pau.recovery_handle().to_array();
        let Ok(authorization_header) = (MoleAuthorization::Presentation {
            credential_type: credential_type::EC_ACT,
            presentation: presentation_bytes.clone(),
        })
        .to_header_value() else {
            return fail("failed to format presentation Authorization header".into());
        };

        let presentation_id = self.alloc_id();
        self.pending_spends.insert(
            presentation_id,
            PendingSpend {
                status: PendingSpendStatus::InFlight,
                moderator_origin: canon_origin,
                issuance_uri: stored.issuance_uri,
                resource_url: resource_url.to_string(),
                credential_context: parsed.act_challenge.credential_context,
                ctx_cred: stored.ctx_cred,
                balance_width: stored.balance_width,
                public_key: stored.public_key,
                key_id: stored.key_id,
                spend_state,
                presentation_bytes,
                recovery_handle,
            },
        );

        PresentBegin {
            ok: true,
            error: String::new(),
            presentation_id,
            authorization_header,
        }
    }

    pub fn present_finish(
        &mut self,
        presentation_id: u64,
        mole_credential_header: &str,
        now_unix_secs: u64,
    ) -> PresentOutcome {
        let fail = |error: String| PresentOutcome {
            ok: false,
            error,
            held_for_secs: 0,
            consumed_no_update: false,
        };

        if !self.pending_spends.contains_key(&presentation_id) {
            return fail("unknown presentation_id".into());
        }

        // Per `draft-jms-mole-http-transport-01` §5.3: if no `Mole-Credential`
        // arrived (e.g., network drop or 5xx before recording), keep `InFlight`
        // so `recovery-0001` can recover the recorded decision!
        if mole_credential_header.is_empty() {
            return fail("missing Mole-Credential; keeping SpendState for recovery".into());
        }

        let parsed = match MoleCredential::parse(mole_credential_header) {
            Ok(c) => c,
            Err(e) => {
                return fail(format!(
                    "malformed Mole-Credential ({e}); keeping SpendState for recovery"
                ));
            }
        };

        match parsed {
            MoleCredential::HeldForUpdate {
                credential_type: credential_type::EC_ACT,
                duration_secs,
            } => {
                if let Some(pending) = self.pending_spends.get_mut(&presentation_id) {
                    pending.status = PendingSpendStatus::Held {
                        hold_until_unix_secs: now_unix_secs.saturating_add(duration_secs),
                    };
                }
                PresentOutcome {
                    ok: true,
                    error: String::new(),
                    held_for_secs: duration_secs,
                    consumed_no_update: false,
                }
            }
            MoleCredential::Update {
                credential_type: credential_type::EC_ACT,
                update: None,
            } => {
                self.pending_spends.remove(&presentation_id);
                PresentOutcome {
                    ok: true,
                    error: String::new(),
                    held_for_secs: 0,
                    consumed_no_update: true,
                }
            }
            MoleCredential::Update {
                credential_type: credential_type::EC_ACT,
                update: Some(bytes),
            } => {
                let Some(pending) = self.pending_spends.remove(&presentation_id) else {
                    return fail("unknown presentation_id".into());
                };
                let Ok(params) = ec_act::Params::new(pending.balance_width) else {
                    return fail("invalid balance_width".into());
                };
                let Ok(act_update) = EcActUpdate::from_bytes(&params, &bytes) else {
                    // Per `draft-jms-mole-protocols-01` §5.2.3: if refund fails
                    // verification, discard refund and retain spend state for recovery!
                    self.pending_spends.insert(presentation_id, pending);
                    return fail("malformed EcActUpdate; keeping SpendState for recovery".into());
                };
                // `finalize_refund` consumes `spend_state` by value; serialize a
                // zeroizing backup first so an unverified/corrupted header on the
                // wire cannot destroy a recoverable `PendingSpend`!
                let spend_backup = pending.spend_state.to_bytes();
                match ec_act::finalize_refund(
                    &params,
                    &pending.public_key,
                    &pending.ctx_cred,
                    pending.spend_state,
                    &act_update.refund,
                ) {
                    Ok(credential) => {
                        let key = PoolKey {
                            moderator_origin: pending.moderator_origin,
                            credential_context: pending.credential_context,
                        };
                        self.pools.entry(key).or_default().push_back(StoredCredential {
                            credential,
                            public_key: pending.public_key,
                            key_id: pending.key_id,
                            balance_width: pending.balance_width,
                            ctx_cred: pending.ctx_cred,
                            issuance_uri: pending.issuance_uri,
                        });
                        PresentOutcome {
                            ok: true,
                            error: String::new(),
                            held_for_secs: 0,
                            consumed_no_update: false,
                        }
                    }
                    Err(e) => {
                        if let Ok(restored_spend_state) =
                            ec_act::ClientSpendState::from_bytes(&params, &spend_backup)
                        {
                            self.pending_spends.insert(
                                presentation_id,
                                PendingSpend {
                                    status: pending.status,
                                    moderator_origin: pending.moderator_origin,
                                    issuance_uri: pending.issuance_uri,
                                    resource_url: pending.resource_url,
                                    credential_context: pending.credential_context,
                                    ctx_cred: pending.ctx_cred,
                                    balance_width: pending.balance_width,
                                    public_key: pending.public_key,
                                    key_id: pending.key_id,
                                    spend_state: restored_spend_state,
                                    presentation_bytes: pending.presentation_bytes,
                                    recovery_handle: pending.recovery_handle,
                                },
                            );
                        }
                        fail(format!(
                            "EC-ACT finalize_refund failed ({e}); keeping SpendState for recovery"
                        ))
                    }
                }
            }
            _ => fail("unexpected Mole-Credential parameter on presentation".into()),
        }
    }

    pub fn pool_size(&self, moderator_origin: &str, credential_context: &[u8]) -> usize {
        let Ok(canon_origin) = canonicalize_origin(moderator_origin) else {
            return 0;
        };
        let key = PoolKey {
            moderator_origin: canon_origin,
            credential_context: credential_context.to_vec(),
        };
        self.pools.get(&key).map_or(0, VecDeque::len)
    }

    pub fn balance(&self, moderator_origin: &str, credential_context: &[u8]) -> u64 {
        let Ok(canon_origin) = canonicalize_origin(moderator_origin) else {
            return 0;
        };
        let key = PoolKey {
            moderator_origin: canon_origin,
            credential_context: credential_context.to_vec(),
        };
        self.pools
            .get(&key)
            .map_or(0, |pool| pool.iter().map(|c| c.credential.balance()).sum())
    }

    pub fn endorsement_count(&self) -> usize {
        self.endorsements.len()
    }

    pub fn pending_spend_count(&self) -> usize {
        self.pending_spends.len()
    }

    /// Serializes durable client state (version 2: `endorsements` + `pools` +
    /// write-ahead `pending_spends`).
    pub fn serialize_state(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(STATE_FORMAT_VERSION);

        put_u32(&mut out, self.endorsements.len() as u32);
        for e in &self.endorsements {
            let end_bytes = e.endorsement.to_bytes();
            put_varbytes(&mut out, &end_bytes);
            put_varbytes(&mut out, e.anchor_origin.as_bytes());
            put_varbytes(&mut out, &e.anchor_key);
            put_varbytes(&mut out, &e.issuance_epoch);
        }

        let nonempty: Vec<(&PoolKey, &VecDeque<StoredCredential>)> =
            self.pools.iter().filter(|(_, p)| !p.is_empty()).collect();
        put_u32(&mut out, nonempty.len() as u32);
        for (key, pool) in nonempty {
            put_varbytes(&mut out, key.moderator_origin.as_bytes());
            put_varbytes(&mut out, &key.credential_context);
            put_u32(&mut out, pool.len() as u32);
            for c in pool {
                put_varbytes(&mut out, &c.public_key.to_bytes());
                out.push(c.balance_width);
                put_varbytes(&mut out, c.issuance_uri.as_bytes());
                let cred_bytes = c.credential.to_bytes();
                put_varbytes(&mut out, &cred_bytes);
            }
        }

        let mut pending_list: Vec<(&u64, &PendingSpend)> = self.pending_spends.iter().collect();
        pending_list.sort_by_key(|&(id, _)| *id);
        put_u32(&mut out, pending_list.len() as u32);
        for (_, p) in pending_list {
            match p.status {
                PendingSpendStatus::InFlight => {
                    out.push(0);
                    put_u64(&mut out, 0);
                }
                PendingSpendStatus::Held {
                    hold_until_unix_secs,
                } => {
                    out.push(1);
                    put_u64(&mut out, hold_until_unix_secs);
                }
            }
            put_varbytes(&mut out, p.moderator_origin.as_bytes());
            put_varbytes(&mut out, p.issuance_uri.as_bytes());
            put_varbytes(&mut out, p.resource_url.as_bytes());
            put_varbytes(&mut out, &p.credential_context);
            out.push(p.balance_width);
            put_varbytes(&mut out, &p.public_key.to_bytes());
            let spend_state_bytes = p.spend_state.to_bytes();
            put_varbytes(&mut out, &spend_state_bytes);
            put_varbytes(&mut out, &p.presentation_bytes);
            out.extend_from_slice(&p.recovery_handle);
        }

        out
    }

    pub fn restore_state(&mut self, bytes: &[u8]) -> bool {
        let Some((endorsements, pools, pending_spends, next_id)) = parse_state(bytes) else {
            return false;
        };
        self.endorsements = endorsements;
        self.pools = pools;
        self.pending_spends = pending_spends;
        self.next_id = next_id;
        true
    }
}

// ---------------------------------------------------------------------------
// Durable-State Binary Serialization Helpers
// ---------------------------------------------------------------------------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

struct StateCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> StateCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
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
        Some(u32::from_be_bytes(raw.try_into().ok()?) as usize)
    }

    fn u64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let raw = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u64::from_be_bytes(raw.try_into().ok()?))
    }

    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.pos.checked_add(N)?;
        let raw = self.buf.get(self.pos..end)?;
        self.pos = end;
        raw.try_into().ok()
    }

    fn varbytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()?;
        let end = self.pos.checked_add(len)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn varstr(&mut self) -> Option<String> {
        std::str::from_utf8(self.varbytes()?).ok().map(str::to_owned)
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

type ParsedClientState = (
    Vec<StoredEndorsement>,
    HashMap<PoolKey, VecDeque<StoredCredential>>,
    HashMap<u64, PendingSpend>,
    u64,
);

fn parse_state(bytes: &[u8]) -> Option<ParsedClientState> {
    let mut cur = StateCursor::new(bytes);
    if cur.u8()? != STATE_FORMAT_VERSION {
        return None;
    }

    let ne = cur.u32()?;
    if ne > 4096 {
        return None;
    }
    let mut endorsements = Vec::with_capacity(ne);
    for _ in 0..ne {
        let endorsement = ec_ihat::Endorsement::from_bytes(cur.varbytes()?).ok()?;
        let anchor_origin = cur.varstr()?;
        let anchor_key: [u8; 33] = cur.varbytes()?.try_into().ok()?;
        let _: ec_ihat::PublicKey = ec_ihat::PublicKey::from_bytes(&anchor_key).ok()?;
        let issuance_epoch = cur.varbytes()?.to_vec();
        endorsements.push(StoredEndorsement {
            endorsement,
            anchor_origin,
            anchor_key,
            issuance_epoch,
        });
    }

    let np = cur.u32()?;
    if np > 1024 {
        return None;
    }
    let mut pools = HashMap::with_capacity(np);
    for _ in 0..np {
        let moderator_origin = cur.varstr()?;
        let credential_context = cur.varbytes()?.to_vec();
        let nc = cur.u32()?;
        if nc > 1024 {
            return None;
        }
        let mut pool = VecDeque::with_capacity(nc);
        for _ in 0..nc {
            let pk_bytes: [u8; 33] = cur.varbytes()?.try_into().ok()?;
            let public_key = ec_act::PublicKey::from_bytes(&pk_bytes).ok()?;
            let balance_width = cur.u8()?;
            let params = ec_act::Params::new(balance_width).ok()?;
            let ctx_cred = derive_ctx_cred(&credential_context, balance_width).ok()?;
            let issuance_uri = cur.varstr()?;
            let credential = ec_act::Credential::from_bytes(&params, cur.varbytes()?).ok()?;
            let key_id = compute_ec_act_key_id(&public_key);
            pool.push_back(StoredCredential {
                credential,
                public_key,
                key_id,
                balance_width,
                ctx_cred,
                issuance_uri,
            });
        }
        pools.insert(
            PoolKey {
                moderator_origin,
                credential_context,
            },
            pool,
        );
    }

    let n_pending = cur.u32()?;
    if n_pending > 1024 {
        return None;
    }
    let mut pending_spends = HashMap::with_capacity(n_pending);
    let mut next_id = 1u64;
    for _ in 0..n_pending {
        let status_tag = cur.u8()?;
        let hold_until = cur.u64()?;
        let status = match status_tag {
            0 => PendingSpendStatus::InFlight,
            1 => PendingSpendStatus::Held {
                hold_until_unix_secs: hold_until,
            },
            _ => return None,
        };
        let moderator_origin = cur.varstr()?;
        let issuance_uri = cur.varstr()?;
        let resource_url = cur.varstr()?;
        let credential_context = cur.varbytes()?.to_vec();
        let balance_width = cur.u8()?;
        let params = ec_act::Params::new(balance_width).ok()?;
        let ctx_cred = derive_ctx_cred(&credential_context, balance_width).ok()?;
        let pk_bytes: [u8; 33] = cur.varbytes()?.try_into().ok()?;
        let public_key = ec_act::PublicKey::from_bytes(&pk_bytes).ok()?;
        let key_id = compute_ec_act_key_id(&public_key);
        let spend_state = ec_act::ClientSpendState::from_bytes(&params, cur.varbytes()?).ok()?;
        let presentation_bytes = cur.varbytes()?.to_vec();
        let recovery_handle = cur.fixed::<96>()?;

        let id = next_id;
        next_id += 1;
        pending_spends.insert(
            id,
            PendingSpend {
                status,
                moderator_origin,
                issuance_uri,
                resource_url,
                credential_context,
                ctx_cred,
                balance_width,
                public_key,
                key_id,
                spend_state,
                presentation_bytes,
                recovery_handle,
            },
        );
    }

    if !cur.is_empty() {
        return None;
    }
    Some((endorsements, pools, pending_spends, next_id))
}

// ---------------------------------------------------------------------------
// In-Process Spec-Compliant Test Servers (`TestMoleAnchor`, `TestMoleModerator`)
// ---------------------------------------------------------------------------

fn test_http(status: u16, body: &[u8]) -> TestHttpResponse {
    TestHttpResponse {
        status,
        content_type: "text/plain".into(),
        www_authenticate: Vec::new(),
        mole_credential: String::new(),
        cache_control: String::new(),
        body: body.to_vec(),
    }
}

/// Spec-compliant in-process EC-IHAT Anchor (`draft-jms-mole-protocols-01` §4.4).
pub struct TestMoleAnchor {
    origin: String,
    key: ec_ihat::SecretKey,
    issuance_epoch: Vec<u8>,
    open_sessions: HashMap<[u8; 32], Vec<ec_ihat::AnchorState>>,
    consumed_sessions: HashSet<[u8; 32]>,
}

pub fn new_test_anchor(origin: &str, issuance_epoch: &[u8]) -> Box<TestMoleAnchor> {
    let mut seed = Zeroizing::new([0u8; 48]);
    fill_random(&mut *seed).expect("RNG succeeds");
    let key = ec_ihat::SecretKey::from_seed(&seed).expect("Anchor key derives");
    let (canon_origin, _) =
        validate_https_endpoint_uri(origin).unwrap_or_else(|_| ("https://anchor.example".into(), "/".into()));
    Box::new(TestMoleAnchor {
        origin: canon_origin,
        key,
        issuance_epoch: issuance_epoch.to_vec(),
        open_sessions: HashMap::new(),
        consumed_sessions: HashSet::new(),
    })
}

impl TestMoleAnchor {
    pub fn anchor_public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
    }

    pub fn grant_uri(&self) -> String {
        format!("{}/mole/grant", self.origin)
    }

    pub fn anchor_commitment(&self) -> AnchorCommitment {
        AnchorCommitment {
            found: true,
            grant_uri: self.grant_uri(),
            keys: vec![Blob {
                bytes: self.anchor_public_key(),
            }],
            epochs: vec![Blob {
                bytes: self.issuance_epoch.clone(),
            }],
        }
    }

    pub fn anchor_config_json(&self) -> String {
        let cfg = AnchorConfiguration {
            grant_uri: self.grant_uri(),
            endorsement_type: endorsement_type::EC_IHAT,
            ciphersuite: CIPHERSUITE_P256_SHA256.into(),
            anchor_key: b64_encode(&self.anchor_public_key()),
            issuance_epoch: b64_encode(&self.issuance_epoch),
        };
        serde_json::to_string(&cfg).expect("AnchorConfiguration serializes")
    }

    pub fn handle_grant(&mut self, content_type: &str, body: &[u8]) -> TestHttpResponse {
        match parse_endorsement_request_media_type(content_type) {
            Ok(t) if t == endorsement_type::EC_IHAT => {}
            _ => return test_http(415, b"invalid Content-Type"),
        }
        let Ok(post) = EcIhatGrantPost::from_bytes(body) else {
            return test_http(400, b"malformed grant body");
        };

        let resp_bytes = match post {
            EcIhatGrantPost::Request(req) => {
                let n = usize::from(req.count.min(64));
                let mut states = Vec::with_capacity(n);
                let mut commitments = Vec::with_capacity(n);
                for _ in 0..n {
                    let Ok((st, com)) = ec_ihat::commit(&self.issuance_epoch) else {
                        return test_http(500, b"commit failed");
                    };
                    states.push(st);
                    commitments.push(com);
                }
                let mut session_id = [0u8; 32];
                fill_random(&mut session_id).expect("RNG succeeds");
                self.open_sessions.insert(session_id, states);
                GrantCommitments {
                    session_id,
                    commitments,
                }
                .to_bytes()
                .expect("GrantCommitments encodes")
            }
            EcIhatGrantPost::Challenges(chal) => {
                // Single-use claim BEFORE reading states (`draft-jms-mole-protocols-01` §4.4.2 step 2)!
                if self.consumed_sessions.contains(&chal.session_id) {
                    return test_http(400, b"replayed session_id");
                }
                let Some(states) = self.open_sessions.remove(&chal.session_id) else {
                    return test_http(400, b"unknown session_id");
                };
                self.consumed_sessions.insert(chal.session_id);
                if states.len() != chal.challenges.len() {
                    return test_http(400, b"challenge count mismatch");
                }
                let mut responses = Vec::with_capacity(states.len());
                for (state, challenge_msg) in states.into_iter().zip(&chal.challenges) {
                    let Ok(resp) = ec_ihat::respond(&self.key, state, challenge_msg) else {
                        return test_http(400, b"EC-IHAT respond rejected challenge");
                    };
                    responses.push(resp);
                }
                GrantResponses { responses }
                    .to_bytes()
                    .expect("GrantResponses encodes")
            }
        };

        TestHttpResponse {
            status: 200,
            content_type: format_endorsement_response_media_type(endorsement_type::EC_IHAT)
                .expect("media type formats"),
            www_authenticate: Vec::new(),
            mole_credential: String::new(),
            cache_control: "no-store".into(),
            body: resp_bytes,
        }
    }
}

enum RecordedSpendDecision {
    Held {
        hold_until: u64,
        raw_spend: Vec<u8>,
    },
    Refund(Vec<u8>),
    NoUpdate,
}

struct RecordedSpend {
    presentation_sha256: [u8; 32],
    recorded_at: u64,
    decision: RecordedSpendDecision,
}

/// Spec-compliant in-process EC-ACT Moderator (`draft-jms-mole-protocols-01` §5.2
/// & `draft-jms-mole-http-transport-01`).
pub struct TestMoleModerator {
    origin: String,
    accepted_anchor_keys: Vec<[u8; 33]>,
    anchor_set: Vec<ec_ihat::PublicKey>,
    issuance_epoch: Vec<u8>,
    credential_context: Vec<u8>,
    ctx_cred: Vec<u8>,
    balance_width: u8,
    initial_balance: u64,
    spend_amount: u64,
    max_top_up: u64,
    refund_amount: u64,
    result_retention_secs: u64,
    hold_duration_secs: u64,
    withhold_update: bool,
    allow_no_endorsement: bool,
    clock_secs: u64,
    params: ec_act::Params,
    secret_key: ec_act::SecretKey,
    key_id: [u8; 32],
    redemption_challenge: [u8; 32],
    seen_endorsement_nullifiers: HashSet<[u8; 32]>,
    recorded_spends: HashMap<[u8; 32], RecordedSpend>,
}

#[allow(clippy::too_many_arguments)]
pub fn new_test_moderator(
    origin: &str,
    accepted_anchor_keys: &Vec<Blob>,
    issuance_epoch: &[u8],
    credential_context: &[u8],
    balance_width: u8,
    initial_balance: u64,
    spend_amount: u64,
    max_top_up: u64,
    refund_amount: u64,
) -> Box<TestMoleModerator> {
    let bw = if balance_width == 0 {
        DEFAULT_BALANCE_WIDTH
    } else {
        balance_width
    };
    let params = ec_act::Params::new(bw).expect("valid balance_width");
    let ctx_cred = derive_ctx_cred(credential_context, bw).expect("valid credential_context");
    let mut seed = Zeroizing::new([0u8; 48]);
    fill_random(&mut *seed).expect("RNG succeeds");
    let secret_key = ec_act::SecretKey::from_seed(&seed).expect("Moderator key derives");
    let key_id = compute_ec_act_key_id(&secret_key.public_key());

    let mut raw_keys = Vec::with_capacity(accepted_anchor_keys.len());
    let mut anchor_set = Vec::with_capacity(accepted_anchor_keys.len());
    for b in accepted_anchor_keys {
        let arr: [u8; 33] = b.bytes.as_slice().try_into().expect("33-byte anchor key");
        let pk = ec_ihat::PublicKey::from_bytes(&arr).expect("valid anchor P-256 point");
        raw_keys.push(arr);
        anchor_set.push(pk);
    }

    let mut redemption_challenge = [0u8; 32];
    fill_random(&mut redemption_challenge).expect("RNG succeeds");
    let (canon_origin, _) = validate_https_endpoint_uri(origin)
        .unwrap_or_else(|_| ("https://moderator.example".into(), "/".into()));

    Box::new(TestMoleModerator {
        origin: canon_origin,
        accepted_anchor_keys: raw_keys,
        anchor_set,
        issuance_epoch: issuance_epoch.to_vec(),
        credential_context: credential_context.to_vec(),
        ctx_cred,
        balance_width: bw,
        initial_balance,
        spend_amount,
        max_top_up,
        refund_amount,
        result_retention_secs: 300,
        hold_duration_secs: 0,
        withhold_update: false,
        allow_no_endorsement: false,
        clock_secs: 1_000,
        params,
        secret_key,
        key_id,
        redemption_challenge,
        seen_endorsement_nullifiers: HashSet::new(),
        recorded_spends: HashMap::new(),
    })
}

impl TestMoleModerator {
    pub fn set_hold_duration_secs(&mut self, hold_secs: u64) {
        self.hold_duration_secs = hold_secs;
    }

    pub fn set_withhold_update(&mut self, withhold: bool) {
        self.withhold_update = withhold;
    }

    pub fn set_allow_no_endorsement(&mut self, allow: bool) {
        self.allow_no_endorsement = allow;
    }

    pub fn advance_clock_secs(&mut self, delta_secs: u64) {
        self.clock_secs = self.clock_secs.saturating_add(delta_secs);
    }

    pub fn issuance_uri(&self) -> String {
        format!("{}/mole/issue", self.origin)
    }

    fn ec_act_challenge(&self) -> EcActChallenge {
        EcActChallenge {
            spend_amount: self.spend_amount,
            max_top_up: self.max_top_up,
            credential_context: self.credential_context.clone(),
            request_context: Vec::new(),
        }
    }

    pub fn moderator_commitment(&self) -> ModeratorCommitment {
        ModeratorCommitment {
            found: true,
            policies: vec![CommittedPolicy {
                credential_context: self.credential_context.clone(),
                credential_key: self.secret_key.public_key().to_bytes().to_vec(),
                balance_width: self.balance_width,
                initial_balance: self.initial_balance,
                spend_amount: self.spend_amount,
                max_top_up: self.max_top_up,
                accepted_anchor_keys: self
                    .accepted_anchor_keys
                    .iter()
                    .map(|k| Blob { bytes: k.to_vec() })
                    .collect(),
                epochs: vec![Blob {
                    bytes: self.issuance_epoch.clone(),
                }],
                allow_no_endorsement: self.allow_no_endorsement,
                issuance_uri: self.issuance_uri(),
            }],
        }
    }

    pub fn moderator_config_json(&self) -> String {
        let mut endorsements = Vec::new();
        if !self.accepted_anchor_keys.is_empty() {
            let ihat = EcIhatEndorsementConfig {
                endorsement_type: endorsement_type::EC_IHAT,
                ciphersuite: CIPHERSUITE_P256_SHA256.into(),
                issuance_epoch: b64_encode(&self.issuance_epoch),
                anchor_set: self
                    .accepted_anchor_keys
                    .iter()
                    .map(|k| b64_encode(k))
                    .collect(),
            };
            endorsements.push(serde_json::to_value(ihat).unwrap());
        }
        if self.allow_no_endorsement {
            let no_end = NoEndorsementConfig {
                endorsement_type: endorsement_type::NO_ENDORSEMENT,
            };
            endorsements.push(serde_json::to_value(no_end).unwrap());
        }
        let act_key = EcActKeyConfig {
            credential_type: credential_type::EC_ACT,
            credential_key: b64_encode(&self.secret_key.public_key().to_bytes()),
            ciphersuite: CIPHERSUITE_P256_SHA256.into(),
            balance_width: self.balance_width,
            credential_context: b64_encode(&self.credential_context),
            result_retention: self.result_retention_secs,
        };
        let cfg = ModeratorConfiguration {
            issuance_uri: self.issuance_uri(),
            endorsements,
            credential_keys: vec![serde_json::to_value(act_key).unwrap()],
        };
        serde_json::to_string(&cfg).expect("ModeratorConfiguration serializes")
    }

    fn challenge_401(&self) -> TestHttpResponse {
        let mut challenges = vec![MoleChallenge::Credential {
            credential_type: credential_type::EC_ACT,
            challenge: self.ec_act_challenge().to_bytes().unwrap(),
        }];
        if !self.accepted_anchor_keys.is_empty() || !self.allow_no_endorsement {
            challenges.push(MoleChallenge::Redeem {
                endorsement_type: endorsement_type::EC_IHAT,
                challenge: self.redemption_challenge,
            });
        }
        if self.allow_no_endorsement {
            challenges.push(MoleChallenge::Redeem {
                endorsement_type: endorsement_type::NO_ENDORSEMENT,
                challenge: self.redemption_challenge,
            });
        }
        TestHttpResponse {
            status: 401,
            content_type: "text/plain".into(),
            www_authenticate: vec![format_www_authenticate(&challenges).unwrap()],
            mole_credential: String::new(),
            cache_control: "no-store".into(),
            body: b"credential required\n".to_vec(),
        }
    }

    fn finalize_held_decision(&mut self, nullifier: &[u8; 32]) -> Option<MoleCredential> {
        let record = self.recorded_spends.get(nullifier)?;
        let raw_spend = match &record.decision {
            RecordedSpendDecision::Held { raw_spend, .. } => raw_spend.clone(),
            RecordedSpendDecision::Refund(bytes) => {
                return Some(MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: Some(bytes.clone()),
                });
            }
            RecordedSpendDecision::NoUpdate => {
                return Some(MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: None,
                });
            }
        };

        let decision = if self.withhold_update {
            RecordedSpendDecision::NoUpdate
        } else {
            let spend_msg = ec_act::SpendMessage::from_bytes(&self.params, &raw_spend).ok()?;
            let ctx_spend = self.ec_act_challenge().ctx_spend().ok()?;
            let verified = ec_act::verify_spend(
                &self.params,
                &self.secret_key,
                &self.ctx_cred,
                &ctx_spend,
                &spend_msg,
            )
            .ok()?;
            let refund = ec_act::issue_refund(verified, self.refund_amount).ok()?;
            RecordedSpendDecision::Refund(EcActUpdate { refund }.to_bytes())
        };

        let cred = match &decision {
            RecordedSpendDecision::Refund(bytes) => MoleCredential::Update {
                credential_type: credential_type::EC_ACT,
                update: Some(bytes.clone()),
            },
            RecordedSpendDecision::NoUpdate => MoleCredential::Update {
                credential_type: credential_type::EC_ACT,
                update: None,
            },
            RecordedSpendDecision::Held { .. } => unreachable!(),
        };
        if let Some(rec) = self.recorded_spends.get_mut(nullifier) {
            rec.decision = decision;
            rec.recorded_at = self.clock_secs;
        }
        Some(cred)
    }

    /// Handles `POST /mole/issue`: Redeem & Issue (`200`), Recovery (`200`/`404`),
    /// and Signoff (`200`/`404`).
    pub fn handle_issue(&mut self, authorization_header: &str) -> TestHttpResponse {
        if authorization_header.is_empty() {
            return self.challenge_401();
        }
        let Ok(auth) = MoleAuthorization::parse(authorization_header) else {
            return test_http(400, b"malformed Authorization");
        };

        match auth {
            MoleAuthorization::RedeemAndIssue {
                endorsement_type: et,
                redemption,
                credential_type: ct,
                credential_request,
            } => {
                if ct != credential_type::EC_ACT {
                    return test_http(403, b"unsupported credential type");
                }
                // Step 1 & 2 (`draft-jms-mole-protocols-01` §5.2.2): check active key
                // & credential_context and verify IssueRequestMessage BEFORE redemption!
                let Ok(iss_req) = EcActIssuanceRequest::from_bytes(&self.params, &credential_request)
                else {
                    return test_http(400, b"malformed IssuanceRequest");
                };
                if iss_req.truncated_key_id != self.key_id[31]
                    || iss_req.credential_context != self.credential_context
                {
                    return test_http(403, b"unknown key or credential_context");
                }
                let Ok(verified_req) = ec_act::verify_issue_request(&self.params, &iss_req.request)
                else {
                    return test_http(403, b"invalid IssueRequest proof");
                };

                // Step 3: FinalizeRedeem.
                let maybe_nf: Option<[u8; 32]> = match et {
                    endorsement_type::NO_ENDORSEMENT => {
                        if !self.allow_no_endorsement || !redemption.is_empty() {
                            return test_http(403, b"NoEndorsement not permitted");
                        }
                        None
                    }
                    endorsement_type::EC_IHAT => {
                        let Ok(red) =
                            ec_ihat::Redemption::from_bytes(&redemption, self.anchor_set.len())
                        else {
                            return test_http(403, b"malformed EC-IHAT Redemption");
                        };
                        let challenge_dig = sha256(&self.redemption_challenge);
                        let Ok(nf) = ec_ihat::verify_redemption(
                            &self.anchor_set,
                            &red,
                            &self.issuance_epoch,
                            EC_IHAT_CTX_RED,
                            &challenge_dig,
                        ) else {
                            return test_http(403, b"EC-IHAT verification failed");
                        };
                        Some(nf)
                    }
                    _ => return test_http(403, b"unsupported endorsement type"),
                };

                // Step 4: IssueResponse + atomic replay-protection insert.
                let Ok(response) = ec_act::issue_response(
                    &self.secret_key,
                    &self.ctx_cred,
                    self.initial_balance,
                    verified_req,
                ) else {
                    return test_http(403, b"EC-ACT issue_response failed");
                };
                if let Some(nf) = maybe_nf {
                    if !self.seen_endorsement_nullifiers.insert(nf) {
                        return test_http(403, b"replayed endorsement nullifier");
                    }
                }

                let mole_credential = MoleCredential::Response {
                    credential_type: credential_type::EC_ACT,
                    response: EcActIssuanceResponse { response }.to_bytes(),
                }
                .to_header_value()
                .unwrap();

                TestHttpResponse {
                    status: 200,
                    content_type: "text/plain".into(),
                    www_authenticate: Vec::new(),
                    mole_credential,
                    cache_control: "no-store".into(),
                    body: Vec::new(),
                }
            }
            MoleAuthorization::Recovery {
                credential_type: credential_type::EC_ACT,
                recovery_handle,
            } => {
                let Ok(handle) = RecoveryHandle::from_bytes(&recovery_handle) else {
                    return test_http(400, b"malformed RecoveryHandle");
                };
                if handle.key_id != self.key_id {
                    return test_http(404, b"not found");
                }
                let Some(rec) = self.recorded_spends.get(&handle.nullifier) else {
                    return test_http(404, b"not found");
                };
                if rec.presentation_sha256 != handle.presentation_sha256 {
                    return test_http(404, b"not found");
                }
                match &rec.decision {
                    RecordedSpendDecision::Held { hold_until, .. } => {
                        if self.clock_secs < *hold_until {
                            return test_http(404, b"still held");
                        }
                        let Some(cred) = self.finalize_held_decision(&handle.nullifier) else {
                            return test_http(404, b"not found");
                        };
                        TestHttpResponse {
                            status: 200,
                            content_type: "text/plain".into(),
                            www_authenticate: Vec::new(),
                            mole_credential: cred.to_header_value().unwrap(),
                            cache_control: "no-store".into(),
                            body: Vec::new(),
                        }
                    }
                    RecordedSpendDecision::Refund(bytes) => {
                        if self.clock_secs.saturating_sub(rec.recorded_at)
                            > self.result_retention_secs
                        {
                            return test_http(404, b"expired");
                        }
                        let cred = MoleCredential::Update {
                            credential_type: credential_type::EC_ACT,
                            update: Some(bytes.clone()),
                        };
                        TestHttpResponse {
                            status: 200,
                            content_type: "text/plain".into(),
                            www_authenticate: Vec::new(),
                            mole_credential: cred.to_header_value().unwrap(),
                            cache_control: "no-store".into(),
                            body: Vec::new(),
                        }
                    }
                    RecordedSpendDecision::NoUpdate => {
                        if self.clock_secs.saturating_sub(rec.recorded_at)
                            > self.result_retention_secs
                        {
                            return test_http(404, b"expired");
                        }
                        let cred = MoleCredential::Update {
                            credential_type: credential_type::EC_ACT,
                            update: None,
                        };
                        TestHttpResponse {
                            status: 200,
                            content_type: "text/plain".into(),
                            www_authenticate: Vec::new(),
                            mole_credential: cred.to_header_value().unwrap(),
                            cache_control: "no-store".into(),
                            body: Vec::new(),
                        }
                    }
                }
            }
            MoleAuthorization::Signoff {
                credential_type: credential_type::EC_ACT,
                recovery_handle,
            } => {
                let Ok(handle) = RecoveryHandle::from_bytes(&recovery_handle) else {
                    return test_http(400, b"malformed RecoveryHandle");
                };
                if handle.key_id != self.key_id {
                    return test_http(404, b"not found");
                }
                let Some(rec) = self.recorded_spends.get(&handle.nullifier) else {
                    return test_http(404, b"not found");
                };
                if rec.presentation_sha256 != handle.presentation_sha256 {
                    return test_http(404, b"not found");
                }
                let Some(cred) = self.finalize_held_decision(&handle.nullifier) else {
                    return test_http(404, b"not found");
                };
                TestHttpResponse {
                    status: 200,
                    content_type: "text/plain".into(),
                    www_authenticate: Vec::new(),
                    mole_credential: cred.to_header_value().unwrap(),
                    cache_control: "no-store".into(),
                    body: Vec::new(),
                }
            }
            _ => test_http(400, b"unsupported issue operation"),
        }
    }

    /// Handles protected resource requests (`GET /gate`).
    pub fn handle_resource(&mut self, authorization_header: &str) -> TestHttpResponse {
        if authorization_header.is_empty() {
            return self.challenge_401();
        }
        let Ok(auth) = MoleAuthorization::parse(authorization_header) else {
            return test_http(400, b"malformed Authorization");
        };
        let MoleAuthorization::Presentation {
            credential_type: ct,
            presentation,
        } = auth
        else {
            return test_http(400, b"expected presentation on resource endpoint");
        };

        // Unknown / greased credential types (`0x?A?A`) on required endpoints are
        // challenged (`401`) per `draft-jms-mole-http-transport-01` §3.
        if ct != credential_type::EC_ACT {
            return self.challenge_401();
        }

        let Ok(pau) = EcActPresentationAndUpdate::from_bytes(&self.params, &presentation) else {
            return test_http(403, b"malformed PresentationAndUpdate");
        };
        if pau.key_id != self.key_id {
            return test_http(403, b"unknown key_id");
        }
        let nf = pau.spend.nullifier();
        let pau_sha256 = sha256(&presentation);

        // Step 1 (`draft-jms-mole-protocols-01` §5.2.3): check nullifier store for
        // byte-identical duplicate (`409 Conflict` + retained result, no operation
        // re-execution) vs conflicting double-spend (`403 Forbidden`)!
        if let Some(existing) = self.recorded_spends.get(&nf) {
            if existing.presentation_sha256 != pau_sha256
                || self.clock_secs.saturating_sub(existing.recorded_at)
                    > self.result_retention_secs
            {
                return test_http(403, b"conflicting or expired duplicate presentation");
            }
            let cred = match &existing.decision {
                RecordedSpendDecision::Held { hold_until, .. } => MoleCredential::HeldForUpdate {
                    credential_type: credential_type::EC_ACT,
                    duration_secs: hold_until.saturating_sub(self.clock_secs),
                },
                RecordedSpendDecision::Refund(bytes) => MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: Some(bytes.clone()),
                },
                RecordedSpendDecision::NoUpdate => MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: None,
                },
            };
            return TestHttpResponse {
                status: 409,
                content_type: "text/plain".into(),
                www_authenticate: Vec::new(),
                mole_credential: cred.to_header_value().unwrap(),
                cache_control: "no-store".into(),
                body: b"duplicate presentation\n".to_vec(),
            };
        }

        // Step 2: check challenged amounts (`s`, `a`).
        if pau.spend.amount() != self.spend_amount
            || pau.spend.allowance() != self.max_top_up
        {
            return test_http(403, b"spend amounts do not match challenge");
        }

        // Step 3: VerifySpend + record result atomically.
        let Ok(ctx_spend) = self.ec_act_challenge().ctx_spend() else {
            return test_http(500, b"challenge encode failed");
        };
        let Ok(verified) = ec_act::verify_spend(
            &self.params,
            &self.secret_key,
            &self.ctx_cred,
            &ctx_spend,
            &pau.spend,
        ) else {
            return test_http(403, b"EC-ACT verify_spend failed");
        };

        let (decision, mole_cred) = if self.hold_duration_secs > 0 {
            let hold_until = self.clock_secs.saturating_add(self.hold_duration_secs);
            (
                RecordedSpendDecision::Held {
                    hold_until,
                    raw_spend: pau.spend.to_bytes(),
                },
                MoleCredential::HeldForUpdate {
                    credential_type: credential_type::EC_ACT,
                    duration_secs: self.hold_duration_secs,
                },
            )
        } else if self.withhold_update {
            (
                RecordedSpendDecision::NoUpdate,
                MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: None,
                },
            )
        } else {
            let Ok(refund) = ec_act::issue_refund(verified, self.refund_amount) else {
                return test_http(403, b"EC-ACT issue_refund failed");
            };
            let bytes = EcActUpdate { refund }.to_bytes();
            (
                RecordedSpendDecision::Refund(bytes.clone()),
                MoleCredential::Update {
                    credential_type: credential_type::EC_ACT,
                    update: Some(bytes),
                },
            )
        };

        self.recorded_spends.insert(
            nf,
            RecordedSpend {
                presentation_sha256: pau_sha256,
                recorded_at: self.clock_secs,
                decision,
            },
        );

        TestHttpResponse {
            status: 200,
            content_type: "text/plain".into(),
            www_authenticate: Vec::new(),
            mole_credential: mole_cred.to_header_value().unwrap(),
            cache_control: "no-store".into(),
            body: b"the protected resource\n".to_vec(),
        }
    }

    pub fn endorsement_nullifier_count(&self) -> usize {
        self.seen_endorsement_nullifiers.len()
    }

    pub fn spend_nullifier_count(&self) -> usize {
        self.recorded_spends.len()
    }
}
