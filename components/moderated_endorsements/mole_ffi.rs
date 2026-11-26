// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Sans-I/O cryptographic and wire-protocol FFI for Moderated Endorsements
//! (`//components/moderated_endorsements:mole_ffi`).
//!
//! Architectural invariants enforced here:
//! - `#![deny(unsafe_code)]` across all hand-written Rust (only `#[cxx::bridge]`
//!   macro-generated FFI glue opts in via `#[allow(unsafe_code)]`).
//! - Stateless / session-bundle functions (`Send + Sync`, zero global mutable
//!   state) so `content/browser/moderated_endorsements/` runs all `EC-IHAT` and
//!   `EC-ACT` zero-knowledge proof generation/verification on `base::ThreadPool`
//!   while `ModeratedEndorsementsStore` owns the authoritative SQLite + AES-GCM
//!   state machine on the UI/DB sequence.
//! - All secret intermediates (`ec_ihat::ClientState`, `ec_ihat::Endorsement`,
//!   `ec_act::ClientIssuanceState`, `ec_act::Credential`,
//!   `ec_act::ClientSpendState`) are wrapped in `zeroize::Zeroizing` buffers.
//! - Enforces `>= min_anchor_set_size` (default 3) Anchors in Moderator Anchor
//!   Sets, exact ordered `accepted_anchor_keys` commitment matching, `L in 1..=16`
//!   (`L=8` and `L=16`), `stored.key_id == committed.key_id` rotation pruning,
//!   `initial_balance` pinning, `allowed_refund_amounts` tier pinning, and
//!   cryptographic P-256 ECDSA (`P1363` SHA-256) / Ed25519 verification of
//!   Split `ClearanceToken`s and cross-site `Mole-Challenge` delegations via
//!   Chromium's `//third_party/boringssl:bssl_crypto`.

#![deny(unsafe_code)]

use std::collections::{HashMap, HashSet};

use bssl_crypto::{ec::P256, ecdsa, ed25519};
use mole_core::act::{compute_ec_act_key_id, derive_ctx_cred};
use mole_core::config::{
    AnchorConfiguration, ClearancePublicKey, ModeratorConfiguration, ValidatedEcActKey,
    ValidatedEcIhatSet, validate_https_endpoint_uri,
};
use mole_core::http::{
    MoleAuthorization, MoleChallenge, MoleCredential, b64_encode,
    format_endorsement_request_media_type, format_endorsement_response_media_type,
    parse_challenges, parse_endorsement_request_media_type, parse_endorsement_response_media_type,
};
use mole_core::messages::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, EcIhatGrantPost, GrantChallenges, GrantCommitments, GrantRequest, GrantResponses,
    ProtectedRequestContext, RecoveryHandle, RedemptionChallenge,
};
use mole_core::split::{
    ClearanceToken, IssueRequestEnvelope, IssueResponseEnvelope, MoleInfo, PresentRequestEnvelope,
    PresentResponseEnvelope, SecMoleAuthorization, SecMoleGrease, SettleRequestEnvelope,
    SettleResponseEnvelope, SplitMoleChallenge,
};
use mole_core::wire::Wire as _;
use mole_core::{
    CIPHERSUITE_P256_SHA256, EC_IHAT_CTX_RED, MAX_BROWSER_BALANCE_WIDTH, challenge_digest,
    credential_type, endorsement_type, fill_random, sha256,
};
use zeroize::Zeroizing;

/// Default number of EC-IHAT Endorsements requested per Anchor grant batch.
pub const DEFAULT_GRANT_BATCH_COUNT: u16 = 4;

/// Maximum presentations per EC-ACT credential chain before retirement.
pub const MAX_PRESENTATIONS_PER_CREDENTIAL: u32 = 16;

/// Default minimum Anchor Set size required by the browser policy.
pub const DEFAULT_MIN_ANCHOR_SET_SIZE: u16 = 3;

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "moderated_endorsements")]
pub mod ffi {
    /// Byte-vector wrapper (`cxx` disallows nested `Vec<Vec<u8>>`).
    #[derive(Clone, Debug)]
    struct Blob {
        bytes: Vec<u8>,
    }

    /// Committed parameters authorized for an Anchor origin.
    #[derive(Clone, Debug)]
    struct AnchorCommitment {
        found: bool,
        grant_uri: String,
        keys: Vec<Blob>,
        epochs: Vec<Blob>,
    }

    /// Committed policy invariants for one `(policy_id, credential_context)` on a Moderator.
    #[derive(Clone, Debug)]
    struct CommittedPolicy {
        policy_id: String,
        credential_context: Vec<u8>,
        credential_key: Vec<u8>,
        /// 33-byte SEC1 compressed P-256 ECDSA key or 32-byte Ed25519 key for Split tokens.
        clearance_public_key: Vec<u8>,
        balance_width: u8,
        initial_balance: u64,
        spend_amount: u64,
        max_top_up: u64,
        /// Explicit allowed refund tiers `r` (`0 <= r <= spend_amount + max_top_up`).
        /// When empty, defaults to `{0, spend_amount, spend_amount + max_top_up}`.
        allowed_refund_amounts: Vec<u64>,
        /// Minimum Anchor Set size (defaults to 3 when 0 is supplied).
        min_anchor_set_size: u16,
        accepted_anchor_keys: Vec<Blob>,
        epochs: Vec<Blob>,
        /// Canonical HTTPS origins authorized to challenge for this Moderator without a `sig`.
        allowed_sites: Vec<String>,
        allow_no_endorsement: bool,
        issuance_uri: String,
        present_uri: String,
        settle_uri: String,
    }

    /// Committed policies authorized for a Moderator origin.
    #[derive(Clone, Debug)]
    struct ModeratorCommitment {
        found: bool,
        policies: Vec<CommittedPolicy>,
    }

    // --- Anchor 2-RTT Batch Grant ---

    #[derive(Clone, Debug)]
    struct GrantBeginOut {
        ok: bool,
        error: String,
        grant_uri: String,
        content_type: String,
        request_body: Vec<u8>,
        anchor_key: Vec<u8>,
        issuance_epoch: Vec<u8>,
        requested_count: u16,
    }

    #[derive(Clone, Debug)]
    struct GrantCommitmentsOut {
        ok: bool,
        error: String,
        content_type: String,
        request_body: Vec<u8>,
        session_bundle: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct GrantFinalizeOut {
        ok: bool,
        error: String,
        endorsements: Vec<Blob>,
    }

    // --- Split Plane 1 & Plane 2 Operations ---

    #[derive(Clone, Debug)]
    struct SplitChallengeEval {
        ok: bool,
        error: String,
        moderator_origin: String,
        policy_id: String,
        credential_context: Vec<u8>,
        cost: u64,
        challenge_nonce: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct SplitIssueBeginOut {
        ok: bool,
        error: String,
        issue_uri: String,
        idempotency_key: Vec<u8>,
        key_id: Vec<u8>,
        balance_width: u8,
        request_body: Vec<u8>,
        issuance_state_bundle: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct SplitIssueFinishOut {
        ok: bool,
        error: String,
        credential_bytes: Vec<u8>,
        key_id: Vec<u8>,
        balance_width: u8,
        balance: u64,
    }

    #[derive(Clone, Debug)]
    struct CredentialCheckOut {
        usable: bool,
        prune_permanent: bool,
        reason: String,
        balance: u64,
    }

    #[derive(Clone, Debug)]
    struct SplitPresentBeginOut {
        ok: bool,
        error: String,
        present_uri: String,
        settle_uri: String,
        key_id: Vec<u8>,
        recovery_handle: Vec<u8>,
        request_body: Vec<u8>,
        spend_bundle: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct SplitPresentFinishOut {
        ok: bool,
        error: String,
        keep_spend_for_recovery: bool,
        is_held: bool,
        consumed_no_update: bool,
        session_handle: String,
        min_delay_ms: u64,
        max_hold_ms: u64,
        sec_mole_authorization: String,
        sec_mole_grease: String,
        refunded_credential_bytes: Vec<u8>,
        new_balance: u64,
    }

    #[derive(Clone, Debug)]
    struct SplitSettleFinishOut {
        ok: bool,
        error: String,
        keep_spend_for_retry: bool,
        credential_restored: bool,
        refunded_credential_bytes: Vec<u8>,
        new_balance: u64,
    }

    #[derive(Clone, Debug)]
    struct MoleInfoOut {
        ok: bool,
        session_handle: String,
        settle_ready: bool,
    }

    // --- Inline `-01` Compatibility Operations ---

    #[derive(Clone, Debug)]
    struct InlineChallengeEval {
        ok: bool,
        error: String,
        credential_context: Vec<u8>,
        spend_amount: u64,
        max_top_up: u64,
        raw_act_challenge: Vec<u8>,
        has_ihat_redeem: bool,
        ihat_redeem_challenge: Vec<u8>,
        can_use_no_endorsement: bool,
    }

    #[derive(Clone, Debug)]
    struct InlineRedeemBeginOut {
        ok: bool,
        error: String,
        issuance_uri: String,
        authorization_header: String,
        key_id: Vec<u8>,
        balance_width: u8,
        issuance_state_bundle: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct InlinePresentBeginOut {
        ok: bool,
        error: String,
        authorization_header: String,
        key_id: Vec<u8>,
        recovery_handle: Vec<u8>,
        spend_bundle: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct InlinePresentFinishOut {
        ok: bool,
        error: String,
        keep_spend_for_recovery: bool,
        is_held: bool,
        held_for_secs: u64,
        consumed_no_update: bool,
        refunded_credential_bytes: Vec<u8>,
        new_balance: u64,
    }

    // --- Signing / Verification & Test Server Types ---

    #[derive(Clone, Debug)]
    struct KeypairOut {
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct OriginVerifyOut {
        ok: bool,
        error: String,
        moderator_origin: String,
        policy_id: String,
        cost: u64,
        session_id: String,
    }

    #[derive(Clone, Debug)]
    struct TestHttpResponse {
        status: u16,
        content_type: String,
        www_authenticate: Vec<String>,
        mole_credential: String,
        mole_challenge: String,
        mole_info: String,
        body: Vec<u8>,
    }

    extern "Rust" {
        fn compute_credential_key_id(credential_public_key: &[u8]) -> Vec<u8>;
        fn make_grease_header() -> String;
        fn parse_mole_info_header(header_value: &str) -> MoleInfoOut;

        // Anchor 2-RTT Batch Grant
        fn grant_begin_batch(
            anchor_origin: &str,
            anchor_config_json: &str,
            commitment: &AnchorCommitment,
            batch_count: u16,
        ) -> GrantBeginOut;

        fn grant_step_commitments(
            anchor_key: &[u8],
            issuance_epoch: &[u8],
            requested_count: u16,
            response_content_type: &str,
            response_body: &[u8],
        ) -> GrantCommitmentsOut;

        fn grant_finalize_responses(
            anchor_key: &[u8],
            issuance_epoch: &[u8],
            session_bundle: &[u8],
            response_content_type: &str,
            response_body: &[u8],
        ) -> GrantFinalizeOut;

        // Split Plane 1 & Plane 2
        fn parse_and_verify_split_challenge(
            target_origin: &str,
            mole_challenge_header: &str,
            commitment: &ModeratorCommitment,
            now_unix_secs: u64,
        ) -> SplitChallengeEval;

        #[allow(clippy::too_many_arguments)]
        fn build_split_issue_request(
            moderator_origin: &str,
            moderator_config_json: &str,
            commitment: &ModeratorCommitment,
            policy_id: &str,
            endorsement_bytes: &[u8],
            endorsement_anchor_key: &[u8],
            endorsement_epoch: &[u8],
            idempotency_key_override: &[u8],
        ) -> SplitIssueBeginOut;

        fn finalize_split_issue_response(
            issuance_state_bundle: &[u8],
            http_status: u16,
            response_body: &[u8],
            expected_initial_balance: u64,
        ) -> SplitIssueFinishOut;

        fn check_credential_usable(
            credential_bytes: &[u8],
            stored_key_id: &[u8],
            stored_balance_width: u8,
            presentations_used: u32,
            committed_policy: &CommittedPolicy,
            required_cost: u64,
        ) -> CredentialCheckOut;

        #[allow(clippy::too_many_arguments)]
        fn build_split_present_request(
            moderator_origin: &str,
            moderator_config_json: &str,
            committed_policy: &CommittedPolicy,
            credential_bytes: &[u8],
            target_origin: &str,
            method: &str,
            path_and_query: &str,
            challenge_nonce: &[u8],
            cost: u64,
            allow_deferred: bool,
        ) -> SplitPresentBeginOut;

        #[allow(clippy::too_many_arguments)]
        fn finalize_split_present_response(
            spend_bundle: &[u8],
            http_status: u16,
            response_body: &[u8],
            clearance_public_key: &[u8],
            expected_moderator_origin: &str,
            expected_policy_id: &str,
            expected_target_origin: &str,
            expected_method: &str,
            expected_path_and_query: &str,
            expected_challenge_nonce: &[u8],
            expected_cost: u64,
            allowed_refund_amounts: &[u64],
            include_grease: bool,
            now_unix_secs: u64,
        ) -> SplitPresentFinishOut;

        fn build_split_settle_request(
            session_handle: &str,
            recovery_handle: &[u8],
            is_signoff: bool,
        ) -> Vec<u8>;

        fn finalize_split_settle_response(
            spend_bundle: &[u8],
            http_status: u16,
            response_body: &[u8],
            allowed_refund_amounts: &[u64],
        ) -> SplitSettleFinishOut;

        // Inline `-01` Compatibility
        fn eval_inline_challenge(
            moderator_origin: &str,
            www_authenticate: &Vec<String>,
            commitment: &ModeratorCommitment,
        ) -> InlineChallengeEval;

        #[allow(clippy::too_many_arguments)]
        fn build_inline_redeem_request(
            moderator_origin: &str,
            moderator_config_json: &str,
            www_authenticate: &Vec<String>,
            commitment: &ModeratorCommitment,
            endorsement_bytes: &[u8],
            endorsement_anchor_key: &[u8],
            endorsement_epoch: &[u8],
        ) -> InlineRedeemBeginOut;

        fn finalize_inline_redeem_response(
            issuance_state_bundle: &[u8],
            mole_credential_header: &str,
            expected_initial_balance: u64,
        ) -> SplitIssueFinishOut;

        fn build_inline_present_request(
            committed_policy: &CommittedPolicy,
            credential_bytes: &[u8],
            raw_act_challenge: &[u8],
            spend_amount: u64,
            max_top_up: u64,
        ) -> InlinePresentBeginOut;

        fn finalize_inline_present_response(
            spend_bundle: &[u8],
            mole_credential_header: &str,
            allowed_refund_amounts: &[u64],
        ) -> InlinePresentFinishOut;

        fn build_inline_settlement_header(recovery_handle: &[u8], is_signoff: bool) -> String;

        fn finalize_inline_settlement_response(
            spend_bundle: &[u8],
            http_status: u16,
            mole_credential_header: &str,
            allowed_refund_amounts: &[u64],
        ) -> SplitSettleFinishOut;

        // Clearance Token & Challenge Delegation Crypto Helpers
        fn generate_p256_clearance_keypair() -> KeypairOut;

        #[allow(clippy::too_many_arguments)]
        fn sign_split_mole_challenge_p256(
            clearance_private_key: &[u8],
            moderator_origin: &str,
            policy_id: &str,
            target_origin: &str,
            cost: u64,
            nonce: &[u8],
            exp: u64,
        ) -> String;

        #[allow(clippy::too_many_arguments)]
        fn verify_sec_mole_authorization_at_origin(
            sec_mole_authorization_header: &str,
            clearance_public_key: &[u8],
            expected_moderator_origin: &str,
            expected_policy_id: &str,
            expected_target_origin: &str,
            expected_method: &str,
            expected_path_and_query: &str,
            expected_challenge_nonce: &[u8],
            min_cost: u64,
            now_unix_secs: u64,
        ) -> OriginVerifyOut;

        // In-process Spec-Compliant Test Servers (`TestMoleAnchor`, `TestSplitModerator`)
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

        type TestSplitModerator;
        #[allow(clippy::too_many_arguments)]
        fn new_test_split_moderator(
            origin: &str,
            policy_id: &str,
            accepted_anchor_keys: &Vec<Blob>,
            issuance_epoch: &[u8],
            credential_context: &[u8],
            balance_width: u8,
            initial_balance: u64,
            spend_amount: u64,
            max_top_up: u64,
            refund_amount: u64,
            allowed_sites: &Vec<String>,
        ) -> Box<TestSplitModerator>;

        fn set_defer_hold_ms(self: &mut TestSplitModerator, min_delay_ms: u64, max_hold_ms: u64);
        fn set_custom_refund_amount(self: &mut TestSplitModerator, refund_amount: u64);
        fn set_custom_initial_balance_override(
            self: &mut TestSplitModerator,
            override_enabled: bool,
            initial_balance: u64,
        );
        fn rotate_credential_key(self: &mut TestSplitModerator);
        fn advance_clock_secs(self: &mut TestSplitModerator, delta_secs: u64);
        fn now_unix_secs(self: &TestSplitModerator) -> u64;

        fn moderator_config_json(self: &TestSplitModerator) -> String;
        fn moderator_commitment(self: &TestSplitModerator) -> ModeratorCommitment;
        fn clearance_public_key(self: &TestSplitModerator) -> Vec<u8>;
        fn credential_public_key(self: &TestSplitModerator) -> Vec<u8>;
        fn make_origin_challenge_header(
            self: &TestSplitModerator,
            target_origin: &str,
            cost: u64,
            nonce: &[u8],
            include_delegation_sig: bool,
        ) -> String;

        fn handle_split_issue(self: &mut TestSplitModerator, body: &[u8]) -> TestHttpResponse;
        fn handle_split_present(self: &mut TestSplitModerator, body: &[u8]) -> TestHttpResponse;
        fn handle_split_settle(self: &mut TestSplitModerator, body: &[u8]) -> TestHttpResponse;
        fn record_origin_reward(
            self: &mut TestSplitModerator,
            session_handle: &str,
            reward_refund_amount: u64,
        ) -> bool;

        fn consumed_endorsement_nullifiers(self: &TestSplitModerator) -> usize;
        fn consumed_spend_nullifiers(self: &TestSplitModerator) -> usize;
        fn idempotency_cache_hits(self: &TestSplitModerator) -> usize;
    }
}

use ffi::*;

// ---------------------------------------------------------------------------
// Internal Binary Bundle Helpers (Zeroizing Secret Serialization)
// ---------------------------------------------------------------------------

const GRANT_SESSION_MAGIC: u8 = 0xA1;
const ISSUANCE_BUNDLE_MAGIC: u8 = 0xA2;
const SPEND_BUNDLE_MAGIC: u8 = 0xA3;

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

struct BundleReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BundleReader<'a> {
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
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u32::from_be_bytes(s.try_into().ok()?) as usize)
    }

    fn u64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u64::from_be_bytes(s.try_into().ok()?))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()?;
        let end = self.pos.checked_add(len)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes()?.try_into().ok()
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn canonicalize_origin(origin: &str) -> Result<String, String> {
    let (canon, path) = validate_https_endpoint_uri(origin).map_err(|e| e.to_string())?;
    if path != "/" {
        return Err("origin must not contain path or query".into());
    }
    Ok(canon)
}

fn compute_split_ctx_spend(req_ctx: &ProtectedRequestContext, cost: u64, max_top_up: u64, credential_context: &[u8]) -> Result<[u8; 32], String> {
    let rc_bytes = req_ctx.to_bytes().map_err(|e| e.to_string())?;
    let act_chal = EcActChallenge {
        spend_amount: cost,
        max_top_up,
        credential_context: credential_context.to_vec(),
        request_context: rc_bytes,
    };
    act_chal.ctx_spend().map_err(|e| e.to_string())
}

fn verify_signature_bytes(public_key_bytes: &[u8], payload: &[u8], sig: &[u8]) -> Result<(), String> {
    let parsed_pk = ClearancePublicKey::from_bytes(public_key_bytes).map_err(|e| e.to_string())?;
    match parsed_pk {
        ClearancePublicKey::P256Ecdsa(sec1) => {
            if sig.len() != 64 {
                return Err("P-256 ECDSA P1363 signature must be 64 bytes".into());
            }
            let pk = ecdsa::PublicKey::<P256>::from_x962_compressed(&sec1)
                .ok_or_else(|| "invalid P-256 ECDSA compressed public key".to_string())?;
            pk.verify_p1363(payload, sig)
                .map_err(|_| "P-256 ECDSA signature verification failed".to_string())
        }
        ClearancePublicKey::Ed25519(ed_bytes) => {
            let sig_arr: [u8; 64] = sig
                .try_into()
                .map_err(|_| "Ed25519 signature must be 64 bytes".to_string())?;
            let pk = ed25519::PublicKey::from_bytes(&ed_bytes);
            pk.verify(payload, &sig_arr)
                .map_err(|_| "Ed25519 signature verification failed".to_string())
        }
    }
}

fn sign_p256_fixed64(private_key_scalar: &[u8], payload: &[u8]) -> Result<[u8; 64], String> {
    let sk = ecdsa::PrivateKey::<P256>::from_big_endian(private_key_scalar)
        .ok_or_else(|| "invalid P-256 ECDSA private scalar".to_string())?;
    sk.sign_p1363(payload)
        .as_slice()
        .try_into()
        .map_err(|_| "ECDSA P1363 signature was not 64 bytes".to_string())
}

fn check_allowed_refund(
    refund_amount: u64,
    spend_amount: u64,
    max_top_up: u64,
    allowed_refund_amounts: &[u64],
) -> Result<(), String> {
    let Some(max_refund) = spend_amount.checked_add(max_top_up) else {
        return Err("spend_amount + max_top_up overflow".into());
    };
    if refund_amount > max_refund {
        return Err(format!(
            "refund_amount {refund_amount} exceeds spend_amount + max_top_up ({max_refund})"
        ));
    }
    if allowed_refund_amounts.is_empty() {
        if refund_amount != 0 && refund_amount != spend_amount && refund_amount != max_refund {
            return Err(format!(
                "refund_amount {refund_amount} is not in default pinned tiers {{0, {spend_amount}, {max_refund}}}"
            ));
        }
    } else if !allowed_refund_amounts.contains(&refund_amount) {
        return Err(format!(
            "refund_amount {refund_amount} is not in committed allowed_refund_amounts"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public FFI Functions
// ---------------------------------------------------------------------------

pub fn compute_credential_key_id(credential_public_key: &[u8]) -> Vec<u8> {
    let Ok(arr): Result<[u8; 33], _> = credential_public_key.try_into() else {
        return Vec::new();
    };
    let Ok(pk) = <ec_act::PublicKey>::from_bytes(&arr) else {
        return Vec::new();
    };
    compute_ec_act_key_id(&pk).to_vec()
}

pub fn make_grease_header() -> String {
    let mut rnd = [0u8; 2];
    let _ = fill_random(&mut rnd);
    let suite = ((u16::from(rnd[0] & 0xF0) | 0x0A) << 8) | (u16::from(rnd[1] & 0xF0) | 0x0A);
    (SecMoleGrease { suite })
        .to_header_value()
        .unwrap_or_else(|_| "suite=\"0x0a0a\"".to_string())
}

pub fn parse_mole_info_header(header_value: &str) -> MoleInfoOut {
    match MoleInfo::parse(header_value) {
        Ok(parsed) => MoleInfoOut {
            ok: true,
            session_handle: parsed.session.unwrap_or_default(),
            settle_ready: parsed.settle_ready,
        },
        Err(_) => MoleInfoOut {
            ok: false,
            session_handle: String::new(),
            settle_ready: false,
        },
    }
}

// --- Anchor 2-RTT Batch Grant ---

pub fn grant_begin_batch(
    anchor_origin: &str,
    anchor_config_json: &str,
    commitment: &AnchorCommitment,
    batch_count: u16,
) -> GrantBeginOut {
    let fail = |error: String| GrantBeginOut {
        ok: false,
        error,
        grant_uri: String::new(),
        content_type: String::new(),
        request_body: Vec::new(),
        anchor_key: Vec::new(),
        issuance_epoch: Vec::new(),
        requested_count: 0,
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
    let Ok(content_type) = format_endorsement_request_media_type(endorsement_type::EC_IHAT) else {
        return fail("failed to format endorsement media type".into());
    };

    GrantBeginOut {
        ok: true,
        error: String::new(),
        grant_uri: validated.grant_uri,
        content_type,
        request_body,
        anchor_key: validated.anchor_key_bytes.to_vec(),
        issuance_epoch: validated.issuance_epoch,
        requested_count: count,
    }
}

pub fn grant_step_commitments(
    anchor_key: &[u8],
    issuance_epoch: &[u8],
    requested_count: u16,
    response_content_type: &str,
    response_body: &[u8],
) -> GrantCommitmentsOut {
    let fail = |error: String| GrantCommitmentsOut {
        ok: false,
        error,
        content_type: String::new(),
        request_body: Vec::new(),
        session_bundle: Vec::new(),
    };

    match parse_endorsement_response_media_type(response_content_type) {
        Ok(t) if t == endorsement_type::EC_IHAT => {}
        _ => return fail("unexpected or missing grant response Content-Type".into()),
    }
    let Ok(key_arr): Result<[u8; 33], _> = anchor_key.try_into() else {
        return fail("anchor_key must be 33 bytes".into());
    };
    let Ok(public_key) = <ec_ihat::PublicKey>::from_bytes(&key_arr) else {
        return fail("invalid anchor P-256 public key".into());
    };
    let Ok(grant_commitments) = GrantCommitments::from_bytes(response_body) else {
        return fail("malformed GrantCommitments".into());
    };
    if grant_commitments.commitments.is_empty()
        || grant_commitments.commitments.len() > usize::from(requested_count.min(64))
    {
        return fail("Anchor returned invalid commitment count".into());
    }

    let mut session_bundle = Vec::new();
    session_bundle.push(GRANT_SESSION_MAGIC);
    put_u32(&mut session_bundle, grant_commitments.commitments.len() as u32);

    let mut challenges = Vec::with_capacity(grant_commitments.commitments.len());
    for commitment in &grant_commitments.commitments {
        let Ok((client_state, challenge_msg)) =
            ec_ihat::challenge(&public_key, issuance_epoch, EC_IHAT_CTX_RED, commitment)
        else {
            let _ = Zeroizing::new(session_bundle);
            return fail("EC-IHAT challenge generation failed".into());
        };
        let state_bytes = Zeroizing::new(client_state.to_bytes());
        put_bytes(&mut session_bundle, state_bytes.as_ref());
        challenges.push(challenge_msg);
    }

    let Ok(request_body) = (GrantChallenges {
        session_id: grant_commitments.session_id,
        challenges,
    })
    .to_bytes() else {
        let _ = Zeroizing::new(session_bundle);
        return fail("failed to encode GrantChallenges".into());
    };
    let Ok(content_type) = format_endorsement_request_media_type(endorsement_type::EC_IHAT) else {
        let _ = Zeroizing::new(session_bundle);
        return fail("failed to format media type".into());
    };

    GrantCommitmentsOut {
        ok: true,
        error: String::new(),
        content_type,
        request_body,
        session_bundle,
    }
}

pub fn grant_finalize_responses(
    anchor_key: &[u8],
    _issuance_epoch: &[u8],
    session_bundle: &[u8],
    response_content_type: &str,
    response_body: &[u8],
) -> GrantFinalizeOut {
    let fail = |error: String| GrantFinalizeOut {
        ok: false,
        error,
        endorsements: Vec::new(),
    };

    match parse_endorsement_response_media_type(response_content_type) {
        Ok(t) if t == endorsement_type::EC_IHAT => {}
        _ => return fail("unexpected or missing grant response Content-Type".into()),
    }
    let Ok(key_arr): Result<[u8; 33], _> = anchor_key.try_into() else {
        return fail("anchor_key must be 33 bytes".into());
    };
    let Ok(public_key) = <ec_ihat::PublicKey>::from_bytes(&key_arr) else {
        return fail("invalid anchor P-256 public key".into());
    };

    let mut reader = BundleReader::new(session_bundle);
    if reader.u8() != Some(GRANT_SESSION_MAGIC) {
        return fail("invalid grant session bundle magic".into());
    }
    let Some(count) = reader.u32() else {
        return fail("truncated grant session bundle".into());
    };
    if count == 0 || count > 64 {
        return fail("invalid grant session count".into());
    }
    let mut states = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(raw_st) = reader.bytes() else {
            return fail("truncated ClientState in bundle".into());
        };
        let Ok(client_state) = <ec_ihat::ClientState>::from_bytes(raw_st) else {
            return fail("malformed ClientState in bundle".into());
        };
        states.push(client_state);
    }
    if !reader.is_empty() {
        return fail("trailing bytes in grant session bundle".into());
    }

    let Ok(grant_responses) = GrantResponses::from_bytes(response_body) else {
        return fail("malformed GrantResponses".into());
    };
    if grant_responses.responses.len() != states.len() {
        return fail("GrantResponses count does not match challenges sent".into());
    }

    let mut endorsements: Vec<Blob> = Vec::with_capacity(states.len());
    for (client_state, response_msg) in states.into_iter().zip(&grant_responses.responses) {
        let Ok(endorsement) = ec_ihat::finalize(&public_key, client_state, response_msg) else {
            for mut blob in endorsements {
                zeroize::Zeroize::zeroize(&mut blob.bytes);
            }
            return fail("EC-IHAT finalize failed; entire batch discarded".into());
        };
        let raw_end = endorsement.to_bytes();
        endorsements.push(Blob {
            bytes: raw_end.to_vec(),
        });
    }

    GrantFinalizeOut {
        ok: true,
        error: String::new(),
        endorsements,
    }
}

// --- Split Plane 1 & Plane 2 ---

fn find_split_policy<'a>(
    commitment: &'a ModeratorCommitment,
    policy_id: &str,
) -> Option<&'a CommittedPolicy> {
    if !policy_id.is_empty() {
        if let Some(p) = commitment.policies.iter().find(|p| p.policy_id == policy_id) {
            return Some(p);
        }
        if let Some(p) = commitment
            .policies
            .iter()
            .find(|p| p.credential_context == policy_id.as_bytes())
        {
            return Some(p);
        }
    }
    if commitment.policies.len() == 1 {
        commitment.policies.first()
    } else {
        None
    }
}

pub fn parse_and_verify_split_challenge(
    target_origin: &str,
    mole_challenge_header: &str,
    commitment: &ModeratorCommitment,
    now_unix_secs: u64,
) -> SplitChallengeEval {
    let fail = |error: String| SplitChallengeEval {
        ok: false,
        error,
        moderator_origin: String::new(),
        policy_id: String::new(),
        credential_context: Vec::new(),
        cost: 0,
        challenge_nonce: Vec::new(),
    };

    let Ok(canon_target) = canonicalize_origin(target_origin) else {
        return fail("target_origin must be canonical https".into());
    };
    let parsed = match SplitMoleChallenge::parse(mole_challenge_header) {
        Ok(c) => c,
        Err(e) => return fail(format!("malformed Mole-Challenge: {e}")),
    };
    if !commitment.found {
        return fail("challenged moderator is not enrolled in the key-commitment registry".into());
    }
    let Some(policy) = find_split_policy(commitment, &parsed.policy) else {
        return fail("challenged policy is not committed for this moderator".into());
    };
    if parsed.cost > policy.spend_amount {
        return fail(format!(
            "challenged cost {} exceeds committed spend_amount {}",
            parsed.cost, policy.spend_amount
        ));
    }

    // Cross-site Moderator delegation / squatting defense:
    // Either `target_origin` is explicitly in `policy.allowed_sites` (or `"*"`
    // or same-origin with Moderator), OR `Mole-Challenge` carries a valid
    // unexpired Moderator delegation signature `sig` under `clearance_public_key`.
    let in_allowed_sites = canon_target == parsed.moderator
        || policy.allowed_sites.iter().any(|s| {
            s == "*"
                || canonicalize_origin(s)
                    .map(|c| c == canon_target)
                    .unwrap_or(false)
        });

    if !in_allowed_sites {
        let Some(sig) = parsed.sig.as_deref() else {
            return fail(
                "unauthorized origin for cross-site Moderator: not in allowed_sites and missing delegation sig"
                    .into(),
            );
        };
        let Some(exp) = parsed.exp else {
            return fail("delegated Mole-Challenge must specify exp".into());
        };
        if now_unix_secs > exp {
            return fail("delegated Mole-Challenge sig has expired".into());
        }
        let max_cost = parsed.max_cost.unwrap_or(parsed.cost);
        let Ok(payload) = SplitMoleChallenge::delegation_signing_payload(
            &canon_target,
            &parsed.moderator,
            &parsed.policy,
            max_cost,
            exp,
        ) else {
            return fail("failed to build delegation signing payload".into());
        };
        if let Err(e) = verify_signature_bytes(&policy.clearance_public_key, &payload, sig) {
            return fail(format!("Mole-Challenge delegation signature invalid: {e}"));
        }
    }

    SplitChallengeEval {
        ok: true,
        error: String::new(),
        moderator_origin: parsed.moderator,
        policy_id: parsed.policy,
        credential_context: policy.credential_context.clone(),
        cost: parsed.cost,
        challenge_nonce: parsed.nonce,
    }
}

#[allow(clippy::type_complexity)]
fn validate_moderator_against_policy(
    moderator_origin: &str,
    moderator_config_json: &str,
    committed: &CommittedPolicy,
) -> Result<
    (
        String,
        String,
        String,
        ValidatedEcActKey,
        ec_act::Params,
        Vec<ValidatedEcIhatSet>,
        bool,
    ),
    String,
> {
    let canon_origin = canonicalize_origin(moderator_origin)?;
    let mod_cfg_raw: ModeratorConfiguration = serde_json::from_str(moderator_config_json)
        .map_err(|e| format!("malformed moderator configuration JSON: {e}"))?;

    let min_anchors = if committed.allow_no_endorsement {
        1
    } else if committed.min_anchor_set_size == 0 {
        usize::from(DEFAULT_MIN_ANCHOR_SET_SIZE)
    } else {
        usize::from(committed.min_anchor_set_size)
    };

    if !committed.allow_no_endorsement && committed.accepted_anchor_keys.len() < min_anchors {
        return Err(format!(
            "committed accepted_anchor_keys size {} is below browser minimum {min_anchors}",
            committed.accepted_anchor_keys.len()
        ));
    }

    let validated_mod = mod_cfg_raw
        .validate_with_min_anchors(min_anchors)
        .map_err(|e| format!("invalid moderator configuration: {e}"))?;

    if validated_mod.issuance_origin != canon_origin {
        return Err("moderator issuance-uri must be same-origin with moderator".into());
    }
    let issue_uri = validated_mod.issuance_uri.clone();
    let present_uri = validated_mod
        .present_uri
        .as_ref()
        .map(|(u, _)| u.clone())
        .unwrap_or_else(|| format!("{canon_origin}/mole/v1/present"));
    let settle_uri = validated_mod.settle_uri.0.clone();

    if !committed.issuance_uri.is_empty() && issue_uri != committed.issuance_uri {
        return Err("moderator issue-uri does not match committed issuance-uri".into());
    }
    if !committed.present_uri.is_empty() && present_uri != committed.present_uri {
        return Err("moderator present-uri does not match committed present-uri".into());
    }
    if !committed.settle_uri.is_empty() && settle_uri != committed.settle_uri {
        return Err("moderator settle-uri does not match committed settle-uri".into());
    }
    if let Some(cfg_clearance) = &validated_mod.clearance_public_key {
        if !committed.clearance_public_key.is_empty()
            && cfg_clearance.as_bytes() != committed.clearance_public_key.as_slice()
        {
            return Err(
                "moderator clearance-public-key does not match committed clearance key".into(),
            );
        }
    }

    if committed.balance_width == 0 || committed.balance_width > MAX_BROWSER_BALANCE_WIDTH {
        return Err(format!(
            "committed balance-width {} outside 1..={MAX_BROWSER_BALANCE_WIDTH}",
            committed.balance_width
        ));
    }

    let act_key = validated_mod
        .ec_act_keys
        .iter()
        .find(|k| k.credential_context == committed.credential_context)
        .cloned()
        .ok_or_else(|| "moderator configuration lacks committed credential-context".to_string())?;

    if act_key.public_key_bytes.as_slice() != committed.credential_key.as_slice() {
        return Err("moderator credential-key does not match committed key".into());
    }
    if act_key.balance_width != committed.balance_width {
        return Err("moderator balance-width does not match committed balance-width".into());
    }
    let params =
        ec_act::Params::new(act_key.balance_width).map_err(|_| "invalid balance-width".to_string())?;
    if committed.initial_balance > params.max_amount()
        || committed.spend_amount > params.max_amount()
        || committed.max_top_up > params.max_amount()
        || committed
            .spend_amount
            .checked_add(committed.max_top_up)
            .is_none_or(|s| s > params.max_amount())
    {
        return Err("committed policy amounts exceed 2^L - 1".into());
    }

    Ok((
        issue_uri,
        present_uri,
        settle_uri,
        act_key,
        params,
        validated_mod.ec_ihat_sets,
        validated_mod.allows_no_endorsement,
    ))
}

fn encode_issuance_bundle(
    balance_width: u8,
    public_key_bytes: &[u8; 33],
    key_id: &[u8; 32],
    ctx_cred: &[u8],
    issuance_state: &ec_act::ClientIssuanceState,
) -> Vec<u8> {
    let mut bundle = Vec::new();
    bundle.push(ISSUANCE_BUNDLE_MAGIC);
    bundle.push(balance_width);
    put_bytes(&mut bundle, public_key_bytes);
    put_bytes(&mut bundle, key_id);
    put_bytes(&mut bundle, ctx_cred);
    let raw_state = Zeroizing::new(issuance_state.to_bytes());
    put_bytes(&mut bundle, raw_state.as_ref());
    bundle
}

#[allow(clippy::too_many_arguments)]
pub fn build_split_issue_request(
    moderator_origin: &str,
    moderator_config_json: &str,
    commitment: &ModeratorCommitment,
    policy_id: &str,
    endorsement_bytes: &[u8],
    endorsement_anchor_key: &[u8],
    endorsement_epoch: &[u8],
    idempotency_key_override: &[u8],
) -> SplitIssueBeginOut {
    let fail = |error: String| SplitIssueBeginOut {
        ok: false,
        error,
        issue_uri: String::new(),
        idempotency_key: Vec::new(),
        key_id: Vec::new(),
        balance_width: 0,
        request_body: Vec::new(),
        issuance_state_bundle: Vec::new(),
    };

    if !commitment.found {
        return fail("moderator is not enrolled in the key-commitment registry".into());
    }
    let Some(committed) = find_split_policy(commitment, policy_id) else {
        return fail("policy is not committed for this moderator".into());
    };
    let Ok(canon_mod_origin) = canonicalize_origin(moderator_origin) else {
        return fail("moderator origin must be https".into());
    };
    let (issue_uri, _, _, act_key, params, ec_ihat_sets, allows_no_end) =
        match validate_moderator_against_policy(&canon_mod_origin, moderator_config_json, committed)
        {
            Ok(v) => v,
            Err(e) => return fail(e),
        };

    let mut idempotency_key = [0u8; 32];
    if idempotency_key_override.len() == 32 {
        idempotency_key.copy_from_slice(idempotency_key_override);
    } else if fill_random(&mut idempotency_key).is_err() {
        return fail("OS RNG failure generating idempotency_key".into());
    }

    let effective_policy_id = if !policy_id.is_empty() {
        policy_id.to_string()
    } else {
        committed.policy_id.clone()
    };

    let mut ctx_input = Vec::new();
    ctx_input.extend_from_slice(b"MOLE-SPLIT-ISSUE-v1|");
    ctx_input.extend_from_slice(canon_mod_origin.as_bytes());
    ctx_input.push(b'|');
    ctx_input.extend_from_slice(effective_policy_id.as_bytes());
    ctx_input.push(b'|');
    ctx_input.extend_from_slice(&idempotency_key);
    let redemption_context = sha256(&ctx_input);

    let (selected_end_type, redemption_bytes) = if endorsement_bytes.is_empty()
        && committed.allow_no_endorsement
        && allows_no_end
    {
        (endorsement_type::NO_ENDORSEMENT, Vec::new())
    } else {
        let Ok(endorsement) = <ec_ihat::Endorsement>::from_bytes(endorsement_bytes) else {
            return fail("malformed EC-IHAT Endorsement bytes".into());
        };
        let Ok(anchor_arr): Result<[u8; 33], _> = endorsement_anchor_key.try_into() else {
            return fail("endorsement_anchor_key must be 33 bytes".into());
        };
        let committed_keys: Option<Vec<[u8; 33]>> = committed
            .accepted_anchor_keys
            .iter()
            .map(|b| b.bytes.as_slice().try_into().ok())
            .collect();
        let Some(committed_keys) = committed_keys else {
            return fail("committed accepted_anchor_keys invalid".into());
        };
        if !committed.epochs.iter().any(|e| e.bytes == endorsement_epoch) {
            return fail("endorsement epoch is not committed for this policy".into());
        }
        let Some(ihat_set) = ec_ihat_sets
            .iter()
            .find(|s| s.issuance_epoch == endorsement_epoch)
        else {
            return fail("moderator configuration lacks endorsement epoch".into());
        };
        if ihat_set.raw_keys != committed_keys {
            return fail(
                "moderator anchor-set does not match committed ordered anchor-set".into(),
            );
        }
        let Some(anchor_pos) = ihat_set.raw_keys.iter().position(|k| k == &anchor_arr) else {
            return fail("endorsement anchor missing from anchor-set".into());
        };

        let challenge_dig = (RedemptionChallenge { redemption_context }).digest();
        let Ok(redemption) = ec_ihat::redeem(
            &ihat_set.anchor_set,
            anchor_pos,
            endorsement,
            endorsement_epoch,
            EC_IHAT_CTX_RED,
            &challenge_dig,
        ) else {
            return fail("EC-IHAT redeem proof generation failed".into());
        };
        (endorsement_type::EC_IHAT, redemption.to_bytes())
    };

    let Ok((issuance_state, issue_req_msg)) = ec_act::issue_request(&params) else {
        return fail("EC-ACT issue_request failed".into());
    };
    let Ok(act_issue_request) = (EcActIssuanceRequest {
        truncated_key_id: act_key.truncated_key_id,
        credential_context: act_key.credential_context.clone(),
        request: issue_req_msg,
    })
    .to_bytes() else {
        return fail("failed to encode EcActIssuanceRequest".into());
    };

    let Ok(request_body) = (IssueRequestEnvelope {
        policy_id: effective_policy_id,
        key_id: act_key.key_id,
        idempotency_key,
        endorsement_type: selected_end_type,
        redemption_context,
        ihat_redeem_proof: redemption_bytes,
        act_issue_request,
    })
    .to_bytes() else {
        return fail("failed to encode IssueRequestEnvelope".into());
    };

    let issuance_state_bundle = encode_issuance_bundle(
        act_key.balance_width,
        &act_key.public_key_bytes,
        &act_key.key_id,
        &act_key.ctx_cred,
        &issuance_state,
    );

    SplitIssueBeginOut {
        ok: true,
        error: String::new(),
        issue_uri,
        idempotency_key: idempotency_key.to_vec(),
        key_id: act_key.key_id.to_vec(),
        balance_width: act_key.balance_width,
        request_body,
        issuance_state_bundle,
    }
}

fn finalize_issuance_bytes(
    issuance_state_bundle: &[u8],
    act_issue_response_bytes: &[u8],
    expected_initial_balance: u64,
) -> SplitIssueFinishOut {
    let fail = |error: String| SplitIssueFinishOut {
        ok: false,
        error,
        credential_bytes: Vec::new(),
        key_id: Vec::new(),
        balance_width: 0,
        balance: 0,
    };

    let mut r = BundleReader::new(issuance_state_bundle);
    if r.u8() != Some(ISSUANCE_BUNDLE_MAGIC) {
        return fail("invalid issuance bundle magic".into());
    }
    let Some(balance_width) = r.u8() else {
        return fail("truncated issuance bundle".into());
    };
    let Some(pk_arr) = r.fixed::<33>() else {
        return fail("invalid pk in issuance bundle".into());
    };
    let Some(key_id) = r.fixed::<32>() else {
        return fail("invalid key_id in issuance bundle".into());
    };
    let Some(ctx_cred) = r.bytes() else {
        return fail("missing ctx_cred in issuance bundle".into());
    };
    let Some(raw_state) = r.bytes() else {
        return fail("missing issuance_state in issuance bundle".into());
    };
    if !r.is_empty() {
        return fail("trailing bytes in issuance bundle".into());
    }

    let Ok(params) = ec_act::Params::new(balance_width) else {
        return fail("invalid balance_width in issuance bundle".into());
    };
    let Ok(public_key) = <ec_act::PublicKey>::from_bytes(&pk_arr) else {
        return fail("invalid P-256 public key in issuance bundle".into());
    };
    let Ok(issuance_state) = <ec_act::ClientIssuanceState>::from_bytes(&params, raw_state) else {
        return fail("malformed ClientIssuanceState in bundle".into());
    };
    let Ok(issuance_resp) = EcActIssuanceResponse::from_bytes(&params, act_issue_response_bytes)
    else {
        return fail("malformed EcActIssuanceResponse".into());
    };

    if issuance_resp.response.balance() != expected_initial_balance {
        return fail(format!(
            "issued balance {} does not match committed initial_balance {}",
            issuance_resp.response.balance(),
            expected_initial_balance
        ));
    }

    let Ok(credential) = ec_act::finalize_issue(
        &params,
        &public_key,
        ctx_cred,
        issuance_state,
        &issuance_resp.response,
    ) else {
        return fail("EC-ACT finalize_issue failed".into());
    };
    let balance = credential.balance();
    let cred_raw = credential.to_bytes();

    SplitIssueFinishOut {
        ok: true,
        error: String::new(),
        credential_bytes: cred_raw.to_vec(),
        key_id: key_id.to_vec(),
        balance_width,
        balance,
    }
}

pub fn finalize_split_issue_response(
    issuance_state_bundle: &[u8],
    http_status: u16,
    response_body: &[u8],
    expected_initial_balance: u64,
) -> SplitIssueFinishOut {
    if http_status != 200 {
        return SplitIssueFinishOut {
            ok: false,
            error: format!("Moderator /issue returned HTTP {http_status}"),
            credential_bytes: Vec::new(),
            key_id: Vec::new(),
            balance_width: 0,
            balance: 0,
        };
    }
    let Ok(env) = IssueResponseEnvelope::from_bytes(response_body) else {
        return SplitIssueFinishOut {
            ok: false,
            error: "malformed IssueResponseEnvelope".into(),
            credential_bytes: Vec::new(),
            key_id: Vec::new(),
            balance_width: 0,
            balance: 0,
        };
    };
    if env.initial_credit != expected_initial_balance {
        return SplitIssueFinishOut {
            ok: false,
            error: format!(
                "envelope initial_credit {} does not match committed initial_balance {}",
                env.initial_credit, expected_initial_balance
            ),
            credential_bytes: Vec::new(),
            key_id: Vec::new(),
            balance_width: 0,
            balance: 0,
        };
    }
    finalize_issuance_bytes(
        issuance_state_bundle,
        &env.act_issue_response,
        expected_initial_balance,
    )
}

pub fn check_credential_usable(
    credential_bytes: &[u8],
    stored_key_id: &[u8],
    stored_balance_width: u8,
    presentations_used: u32,
    committed_policy: &CommittedPolicy,
    required_cost: u64,
) -> CredentialCheckOut {
    let prune = |reason: &str| CredentialCheckOut {
        usable: false,
        prune_permanent: true,
        reason: reason.to_string(),
        balance: 0,
    };

    if presentations_used >= MAX_PRESENTATIONS_PER_CREDENTIAL {
        return prune("credential reached kMaxPresentationsPerCredential (16)");
    }
    if stored_balance_width != committed_policy.balance_width {
        return prune("stored balance_width differs from committed balance_width");
    }
    let expected_key_id = compute_credential_key_id(&committed_policy.credential_key);
    if expected_key_id.len() != 32 || stored_key_id != expected_key_id.as_slice() {
        return prune("stored key_id differs from committed key_id (key rotated)");
    }
    let Ok(params) = ec_act::Params::new(stored_balance_width) else {
        return prune("invalid stored balance_width");
    };
    let Ok(cred) = <ec_act::Credential>::from_bytes(&params, credential_bytes) else {
        return prune("corrupted stored EC-ACT credential bytes");
    };
    let bal = cred.balance();
    let max_bal = params.max_amount();
    let effective_spend = required_cost.max(committed_policy.spend_amount);
    if bal < effective_spend {
        return prune("credential balance exhausted below required spend_amount");
    }
    if bal
        .checked_add(committed_policy.max_top_up)
        .is_none_or(|sum| sum > max_bal)
    {
        return prune("credential balance + max_top_up would overflow 2^L - 1");
    }

    CredentialCheckOut {
        usable: true,
        prune_permanent: false,
        reason: String::new(),
        balance: bal,
    }
}

fn encode_spend_bundle(
    balance_width: u8,
    spend_amount: u64,
    max_top_up: u64,
    pk_arr: &[u8; 33],
    key_id: &[u8; 32],
    ctx_cred: &[u8],
    spend_state: &ec_act::ClientSpendState,
) -> Vec<u8> {
    let mut bundle = Vec::new();
    bundle.push(SPEND_BUNDLE_MAGIC);
    bundle.push(balance_width);
    put_u64(&mut bundle, spend_amount);
    put_u64(&mut bundle, max_top_up);
    put_bytes(&mut bundle, pk_arr);
    put_bytes(&mut bundle, key_id);
    put_bytes(&mut bundle, ctx_cred);
    let raw_spend = Zeroizing::new(spend_state.to_bytes());
    put_bytes(&mut bundle, raw_spend.as_ref());
    bundle
}

#[allow(clippy::type_complexity)]
fn decode_spend_bundle(
    spend_bundle: &[u8],
) -> Result<
    (
        ec_act::Params,
        u64,
        u64,
        ec_act::PublicKey,
        [u8; 32],
        Vec<u8>,
        ec_act::ClientSpendState,
    ),
    String,
> {
    let mut r = BundleReader::new(spend_bundle);
    if r.u8() != Some(SPEND_BUNDLE_MAGIC) {
        return Err("invalid spend bundle magic".into());
    }
    let balance_width = r.u8().ok_or("truncated spend bundle")?;
    let spend_amount = r.u64().ok_or("truncated spend_amount")?;
    let max_top_up = r.u64().ok_or("truncated max_top_up")?;
    let pk_arr = r.fixed::<33>().ok_or("invalid pk in spend bundle")?;
    let key_id = r.fixed::<32>().ok_or("invalid key_id in spend bundle")?;
    let ctx_cred = r.bytes().ok_or("missing ctx_cred")?.to_vec();
    let raw_spend = r.bytes().ok_or("missing spend_state")?;
    if !r.is_empty() {
        return Err("trailing bytes in spend bundle".into());
    }
    let params = ec_act::Params::new(balance_width).map_err(|_| "invalid balance_width")?;
    let pk = <ec_act::PublicKey>::from_bytes(&pk_arr).map_err(|_| "invalid pk")?;
    let spend_state = <ec_act::ClientSpendState>::from_bytes(&params, raw_spend)
        .map_err(|_| "invalid spend_state")?;
    Ok((
        params,
        spend_amount,
        max_top_up,
        pk,
        key_id,
        ctx_cred,
        spend_state,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn build_split_present_request(
    moderator_origin: &str,
    moderator_config_json: &str,
    committed_policy: &CommittedPolicy,
    credential_bytes: &[u8],
    target_origin: &str,
    method: &str,
    path_and_query: &str,
    challenge_nonce: &[u8],
    cost: u64,
    allow_deferred: bool,
) -> SplitPresentBeginOut {
    let fail = |error: String| SplitPresentBeginOut {
        ok: false,
        error,
        present_uri: String::new(),
        settle_uri: String::new(),
        key_id: Vec::new(),
        recovery_handle: Vec::new(),
        request_body: Vec::new(),
        spend_bundle: Vec::new(),
    };

    let Ok(canon_target) = canonicalize_origin(target_origin) else {
        return fail("target_origin must be canonical https".into());
    };
    let (_, present_uri, settle_uri, act_key, params, _, _) = match validate_moderator_against_policy(
        moderator_origin,
        moderator_config_json,
        committed_policy,
    ) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };

    if cost > committed_policy.spend_amount {
        return fail("requested cost exceeds committed spend_amount".into());
    }
    if challenge_nonce.is_empty() || challenge_nonce.len() > 128 {
        return fail("challenge_nonce must be 1..=128 bytes".into());
    }
    let Ok(cred) = <ec_act::Credential>::from_bytes(&params, credential_bytes) else {
        return fail("corrupted EC-ACT credential".into());
    };

    let upper_method = method.to_ascii_uppercase();
    let req_ctx = ProtectedRequestContext {
        target_origin: canon_target.clone(),
        method: upper_method.clone(),
        path_and_query: path_and_query.to_string(),
        challenge_nonce: challenge_nonce.to_vec(),
        cost,
        allow_deferred,
    };
    let ctx_spend = match compute_split_ctx_spend(
        &req_ctx,
        cost,
        committed_policy.max_top_up,
        &act_key.credential_context,
    ) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };

    let Ok((spend_state, spend_msg)) = ec_act::prove_spend(
        &params,
        cred,
        &act_key.ctx_cred,
        cost,
        committed_policy.max_top_up,
        &ctx_spend,
    ) else {
        return fail("EC-ACT prove_spend failed".into());
    };

    let pau = EcActPresentationAndUpdate {
        key_id: act_key.key_id,
        spend: spend_msg,
    };
    let act_presentation = pau.to_bytes();
    let recovery_handle = pau.recovery_handle().to_array();

    let Ok(request_body) = (PresentRequestEnvelope {
        policy_id: committed_policy.policy_id.clone(),
        key_id: act_key.key_id,
        target_origin: canon_target,
        method: upper_method,
        path_and_query: path_and_query.to_string(),
        challenge_nonce: challenge_nonce.to_vec(),
        cost,
        max_top_up: committed_policy.max_top_up,
        allow_deferred,
        act_presentation,
    })
    .to_bytes() else {
        return fail("failed to encode PresentRequestEnvelope".into());
    };

    let spend_bundle = encode_spend_bundle(
        act_key.balance_width,
        cost,
        committed_policy.max_top_up,
        &act_key.public_key_bytes,
        &act_key.key_id,
        &act_key.ctx_cred,
        &spend_state,
    );

    SplitPresentBeginOut {
        ok: true,
        error: String::new(),
        present_uri,
        settle_uri,
        key_id: act_key.key_id.to_vec(),
        recovery_handle: recovery_handle.to_vec(),
        request_body,
        spend_bundle,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_split_present_response(
    spend_bundle: &[u8],
    http_status: u16,
    response_body: &[u8],
    clearance_public_key: &[u8],
    expected_moderator_origin: &str,
    expected_policy_id: &str,
    expected_target_origin: &str,
    expected_method: &str,
    expected_path_and_query: &str,
    expected_challenge_nonce: &[u8],
    expected_cost: u64,
    allowed_refund_amounts: &[u64],
    include_grease: bool,
    now_unix_secs: u64,
) -> SplitPresentFinishOut {
    let fail = |error: String, keep_spend_for_recovery: bool| SplitPresentFinishOut {
        ok: false,
        error,
        keep_spend_for_recovery,
        is_held: false,
        consumed_no_update: false,
        session_handle: String::new(),
        min_delay_ms: 0,
        max_hold_ms: 0,
        sec_mole_authorization: String::new(),
        sec_mole_grease: String::new(),
        refunded_credential_bytes: Vec::new(),
        new_balance: 0,
    };

    if http_status != 200 && http_status != 202 {
        return fail(
            format!("Moderator /present returned HTTP {http_status}"),
            true,
        );
    }

    let (params, spend_amount, max_top_up, pk, _key_id, ctx_cred, spend_state) =
        match decode_spend_bundle(spend_bundle) {
            Ok(v) => v,
            Err(e) => return fail(e, false),
        };

    let Ok(env) = PresentResponseEnvelope::from_bytes(response_body) else {
        return fail("malformed PresentResponseEnvelope".into(), true);
    };

    let clearance_bytes = match &env {
        PresentResponseEnvelope::Settled {
            clearance_token, ..
        }
        | PresentResponseEnvelope::Held {
            clearance_token, ..
        } => clearance_token.clone(),
    };

    let Ok(token) = ClearanceToken::from_bytes(&clearance_bytes) else {
        return fail("malformed ClearanceToken in PresentResponseEnvelope".into(), true);
    };
    let signing_payload = match token.signing_payload() {
        Ok(p) => p,
        Err(e) => return fail(format!("invalid ClearanceToken fields: {e}"), true),
    };
    if let Err(e) = verify_signature_bytes(clearance_public_key, &signing_payload, &token.signature)
    {
        return fail(format!("ClearanceToken signature invalid: {e}"), true);
    }

    let Ok(canon_mod) = canonicalize_origin(expected_moderator_origin) else {
        return fail("invalid expected_moderator_origin".into(), true);
    };
    let Ok(canon_target) = canonicalize_origin(expected_target_origin) else {
        return fail("invalid expected_target_origin".into(), true);
    };
    if token.moderator_origin != canon_mod
        || (!expected_policy_id.is_empty() && token.policy_id != expected_policy_id)
        || token
            .verify_claims(
                &canon_target,
                expected_method,
                expected_path_and_query,
                expected_challenge_nonce,
                expected_cost,
                now_unix_secs,
            )
            .is_err()
        || token.cost != expected_cost
    {
        return fail("ClearanceToken claims do not match bound request".into(), true);
    }

    let grease_val = if include_grease {
        make_grease_header()
    } else {
        String::new()
    };

    match env {
        PresentResponseEnvelope::Held {
            clearance_token,
            session_handle,
            min_delay_ms,
            max_hold_ms,
        } => {
            let auth_hdr = match (SecMoleAuthorization {
                clearance: clearance_token,
                session: Some(session_handle.clone()),
            })
            .to_header_value()
            {
                Ok(h) => h,
                Err(e) => return fail(format!("Sec-Mole-Authorization encode error: {e}"), true),
            };
            SplitPresentFinishOut {
                ok: true,
                error: String::new(),
                keep_spend_for_recovery: false,
                is_held: true,
                consumed_no_update: false,
                session_handle,
                min_delay_ms: u64::from(min_delay_ms),
                max_hold_ms: u64::from(max_hold_ms),
                sec_mole_authorization: auth_hdr,
                sec_mole_grease: grease_val,
                refunded_credential_bytes: Vec::new(),
                new_balance: 0,
            }
        }
        PresentResponseEnvelope::Settled {
            clearance_token,
            act_refund_response,
        } => {
            let auth_hdr = match (SecMoleAuthorization {
                clearance: clearance_token,
                session: if token.session_id.is_empty() {
                    None
                } else {
                    Some(token.session_id)
                },
            })
            .to_header_value()
            {
                Ok(h) => h,
                Err(e) => return fail(format!("Sec-Mole-Authorization encode error: {e}"), true),
            };

            if act_refund_response.is_empty() {
                return SplitPresentFinishOut {
                    ok: true,
                    error: String::new(),
                    keep_spend_for_recovery: false,
                    is_held: false,
                    consumed_no_update: true,
                    session_handle: String::new(),
                    min_delay_ms: 0,
                    max_hold_ms: 0,
                    sec_mole_authorization: auth_hdr,
                    sec_mole_grease: grease_val,
                    refunded_credential_bytes: Vec::new(),
                    new_balance: 0,
                };
            }

            let Ok(act_update) = EcActUpdate::from_bytes(&params, &act_refund_response) else {
                return fail("malformed EcActUpdate in Settled response".into(), true);
            };
            if let Err(e) = check_allowed_refund(
                act_update.refund.return_amount(),
                spend_amount,
                max_top_up,
                allowed_refund_amounts,
            ) {
                return fail(e, true);
            }

            let Ok(new_cred) =
                ec_act::finalize_refund(&params, &pk, &ctx_cred, spend_state, &act_update.refund)
            else {
                return fail("EC-ACT finalize_refund failed".into(), true);
            };
            let new_balance = new_cred.balance();
            let raw_cred = new_cred.to_bytes();

            SplitPresentFinishOut {
                ok: true,
                error: String::new(),
                keep_spend_for_recovery: false,
                is_held: false,
                consumed_no_update: false,
                session_handle: String::new(),
                min_delay_ms: 0,
                max_hold_ms: 0,
                sec_mole_authorization: auth_hdr,
                sec_mole_grease: grease_val,
                refunded_credential_bytes: raw_cred.to_vec(),
                new_balance,
            }
        }
    }
}

pub fn build_split_settle_request(
    session_handle: &str,
    recovery_handle: &[u8],
    is_signoff: bool,
) -> Vec<u8> {
    let rec_opt = recovery_handle
        .try_into()
        .ok()
        .map(RecoveryHandle::from_array);
    (SettleRequestEnvelope {
        session_handle: session_handle.to_string(),
        recovery_handle: rec_opt,
        is_signoff,
    })
    .to_bytes()
    .unwrap_or_default()
}

pub fn finalize_split_settle_response(
    spend_bundle: &[u8],
    http_status: u16,
    response_body: &[u8],
    allowed_refund_amounts: &[u64],
) -> SplitSettleFinishOut {
    if http_status == 404 {
        return SplitSettleFinishOut {
            ok: true,
            error: String::new(),
            keep_spend_for_retry: false,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    }
    if http_status != 200 {
        return SplitSettleFinishOut {
            ok: false,
            error: format!("Moderator /settle returned HTTP {http_status}"),
            keep_spend_for_retry: true,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    }

    let (params, spend_amount, max_top_up, pk, _key_id, ctx_cred, spend_state) =
        match decode_spend_bundle(spend_bundle) {
            Ok(v) => v,
            Err(e) => {
                return SplitSettleFinishOut {
                    ok: false,
                    error: e,
                    keep_spend_for_retry: false,
                    credential_restored: false,
                    refunded_credential_bytes: Vec::new(),
                    new_balance: 0,
                };
            }
        };

    let Ok(env) = SettleResponseEnvelope::from_bytes(response_body) else {
        return SplitSettleFinishOut {
            ok: false,
            error: "malformed SettleResponseEnvelope".into(),
            keep_spend_for_retry: true,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    };

    let act_refund_response = match env {
        SettleResponseEnvelope::Pending { .. } => {
            return SplitSettleFinishOut {
                ok: false,
                error: "hold still pending".into(),
                keep_spend_for_retry: true,
                credential_restored: false,
                refunded_credential_bytes: Vec::new(),
                new_balance: 0,
            };
        }
        SettleResponseEnvelope::Settled {
            act_refund_response,
        } => act_refund_response,
    };

    if act_refund_response.is_empty() {
        return SplitSettleFinishOut {
            ok: true,
            error: String::new(),
            keep_spend_for_retry: false,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    }

    let Ok(act_update) = EcActUpdate::from_bytes(&params, &act_refund_response) else {
        return SplitSettleFinishOut {
            ok: false,
            error: "malformed EcActUpdate in SettleResponseEnvelope".into(),
            keep_spend_for_retry: true,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    };

    if let Err(e) = check_allowed_refund(
        act_update.refund.return_amount(),
        spend_amount,
        max_top_up,
        allowed_refund_amounts,
    ) {
        return SplitSettleFinishOut {
            ok: false,
            error: e,
            keep_spend_for_retry: false,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    }

    let Ok(new_cred) =
        ec_act::finalize_refund(&params, &pk, &ctx_cred, spend_state, &act_update.refund)
    else {
        return SplitSettleFinishOut {
            ok: false,
            error: "EC-ACT finalize_refund failed on /settle".into(),
            keep_spend_for_retry: true,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    };
    let new_balance = new_cred.balance();
    let raw_cred = new_cred.to_bytes();

    SplitSettleFinishOut {
        ok: true,
        error: String::new(),
        keep_spend_for_retry: false,
        credential_restored: true,
        refunded_credential_bytes: raw_cred.to_vec(),
        new_balance,
    }
}

// ---------------------------------------------------------------------------
// Inline `-01` Compatibility Functions
// ---------------------------------------------------------------------------

struct ParsedInlineChallenges {
    raw_act_challenge: Vec<u8>,
    act_challenge: EcActChallenge,
    ihat_redeem_challenge: Option<[u8; 32]>,
    no_endorsement_redeem_challenge: Option<[u8; 32]>,
}

fn parse_inline_challenges(header_values: &[String]) -> Result<ParsedInlineChallenges, String> {
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
    Ok(ParsedInlineChallenges {
        raw_act_challenge,
        act_challenge,
        ihat_redeem_challenge: ihat_redeem,
        no_endorsement_redeem_challenge: no_end_redeem,
    })
}

pub fn eval_inline_challenge(
    moderator_origin: &str,
    www_authenticate: &Vec<String>,
    commitment: &ModeratorCommitment,
) -> InlineChallengeEval {
    let fail = |error: String| InlineChallengeEval {
        ok: false,
        error,
        credential_context: Vec::new(),
        spend_amount: 0,
        max_top_up: 0,
        raw_act_challenge: Vec::new(),
        has_ihat_redeem: false,
        ihat_redeem_challenge: Vec::new(),
        can_use_no_endorsement: false,
    };

    if !commitment.found {
        return fail("moderator is not enrolled in the key-commitment registry".into());
    }
    if canonicalize_origin(moderator_origin).is_err() {
        return fail("moderator origin must be https".into());
    }
    let parsed = match parse_inline_challenges(www_authenticate) {
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

    InlineChallengeEval {
        ok: true,
        error: String::new(),
        credential_context: parsed.act_challenge.credential_context,
        spend_amount: parsed.act_challenge.spend_amount,
        max_top_up: parsed.act_challenge.max_top_up,
        raw_act_challenge: parsed.raw_act_challenge,
        has_ihat_redeem: parsed.ihat_redeem_challenge.is_some(),
        ihat_redeem_challenge: parsed
            .ihat_redeem_challenge
            .map(|c| c.to_vec())
            .unwrap_or_default(),
        can_use_no_endorsement: committed.allow_no_endorsement
            && parsed.no_endorsement_redeem_challenge.is_some(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_inline_redeem_request(
    moderator_origin: &str,
    moderator_config_json: &str,
    www_authenticate: &Vec<String>,
    commitment: &ModeratorCommitment,
    endorsement_bytes: &[u8],
    endorsement_anchor_key: &[u8],
    endorsement_epoch: &[u8],
) -> InlineRedeemBeginOut {
    let fail = |error: String| InlineRedeemBeginOut {
        ok: false,
        error,
        issuance_uri: String::new(),
        authorization_header: String::new(),
        key_id: Vec::new(),
        balance_width: 0,
        issuance_state_bundle: Vec::new(),
    };

    if !commitment.found {
        return fail("moderator is not enrolled in the key-commitment registry".into());
    }
    let parsed = match parse_inline_challenges(www_authenticate) {
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

    let (issuance_uri, _, _, act_key, params, ec_ihat_sets, allows_no_end) =
        match validate_moderator_against_policy(moderator_origin, moderator_config_json, committed) {
            Ok(v) => v,
            Err(e) => return fail(e),
        };

    let (selected_type, redemption_bytes) = if endorsement_bytes.is_empty()
        && committed.allow_no_endorsement
        && allows_no_end
        && parsed.no_endorsement_redeem_challenge.is_some()
    {
        (endorsement_type::NO_ENDORSEMENT, Vec::new())
    } else {
        let Some(red_chal_bytes) = parsed.ihat_redeem_challenge else {
            return fail("missing redeem-0002 challenge".into());
        };
        let Ok(endorsement) = <ec_ihat::Endorsement>::from_bytes(endorsement_bytes) else {
            return fail("malformed EC-IHAT endorsement".into());
        };
        let Ok(anchor_arr): Result<[u8; 33], _> = endorsement_anchor_key.try_into() else {
            return fail("endorsement_anchor_key must be 33 bytes".into());
        };
        let committed_keys: Option<Vec<[u8; 33]>> = committed
            .accepted_anchor_keys
            .iter()
            .map(|b| b.bytes.as_slice().try_into().ok())
            .collect();
        let Some(committed_keys) = committed_keys else {
            return fail("invalid committed accepted_anchor_keys".into());
        };
        let Some(ihat_set) = ec_ihat_sets
            .iter()
            .find(|s| s.issuance_epoch == endorsement_epoch)
        else {
            return fail("moderator configuration lacks endorsement epoch".into());
        };
        if ihat_set.raw_keys != committed_keys {
            return fail(
                "moderator anchor-set does not match committed ordered anchor-set".into(),
            );
        }
        let Some(anchor_pos) = ihat_set.raw_keys.iter().position(|k| k == &anchor_arr) else {
            return fail("endorsement anchor missing from anchor-set".into());
        };
        let challenge_dig = (RedemptionChallenge {
            redemption_context: red_chal_bytes,
        })
        .digest();
        let Ok(redemption) = ec_ihat::redeem(
            &ihat_set.anchor_set,
            anchor_pos,
            endorsement,
            endorsement_epoch,
            EC_IHAT_CTX_RED,
            &challenge_dig,
        ) else {
            return fail("EC-IHAT redeem proof failed".into());
        };
        (endorsement_type::EC_IHAT, redemption.to_bytes())
    };

    let Ok((issuance_state, issue_req_msg)) = ec_act::issue_request(&params) else {
        return fail("EC-ACT issue_request failed".into());
    };
    let Ok(credential_request) = (EcActIssuanceRequest {
        truncated_key_id: act_key.truncated_key_id,
        credential_context: act_key.credential_context.clone(),
        request: issue_req_msg,
    })
    .to_bytes() else {
        return fail("failed to encode EcActIssuanceRequest".into());
    };
    let Ok(authorization_header) = (MoleAuthorization::RedeemAndIssue {
        endorsement_type: selected_type,
        redemption: redemption_bytes,
        credential_type: credential_type::EC_ACT,
        credential_request,
    })
    .to_header_value() else {
        return fail("failed to format Authorization header".into());
    };

    let issuance_state_bundle = encode_issuance_bundle(
        act_key.balance_width,
        &act_key.public_key_bytes,
        &act_key.key_id,
        &act_key.ctx_cred,
        &issuance_state,
    );

    InlineRedeemBeginOut {
        ok: true,
        error: String::new(),
        issuance_uri,
        authorization_header,
        key_id: act_key.key_id.to_vec(),
        balance_width: act_key.balance_width,
        issuance_state_bundle,
    }
}

pub fn finalize_inline_redeem_response(
    issuance_state_bundle: &[u8],
    mole_credential_header: &str,
    expected_initial_balance: u64,
) -> SplitIssueFinishOut {
    let response_bytes = match MoleCredential::parse(mole_credential_header) {
        Ok(MoleCredential::Response {
            credential_type: credential_type::EC_ACT,
            response,
        }) => response,
        _ => {
            return SplitIssueFinishOut {
                ok: false,
                error: "expected Mole-Credential: response-0001".into(),
                credential_bytes: Vec::new(),
                key_id: Vec::new(),
                balance_width: 0,
                balance: 0,
            };
        }
    };
    finalize_issuance_bytes(issuance_state_bundle, &response_bytes, expected_initial_balance)
}

pub fn build_inline_present_request(
    committed_policy: &CommittedPolicy,
    credential_bytes: &[u8],
    raw_act_challenge: &[u8],
    spend_amount: u64,
    max_top_up: u64,
) -> InlinePresentBeginOut {
    let fail = |error: String| InlinePresentBeginOut {
        ok: false,
        error,
        authorization_header: String::new(),
        key_id: Vec::new(),
        recovery_handle: Vec::new(),
        spend_bundle: Vec::new(),
    };

    let Ok(pk_arr): Result<[u8; 33], _> = committed_policy.credential_key.as_slice().try_into()
    else {
        return fail("committed credential_key must be 33 bytes".into());
    };
    let Ok(pk) = <ec_act::PublicKey>::from_bytes(&pk_arr) else {
        return fail("invalid committed credential_key".into());
    };
    let Ok(params) = ec_act::Params::new(committed_policy.balance_width) else {
        return fail("invalid committed balance_width".into());
    };
    let Ok(ctx_cred) = derive_ctx_cred(
        &committed_policy.credential_context,
        committed_policy.balance_width,
    ) else {
        return fail("invalid credential_context".into());
    };
    let Ok(cred) = <ec_act::Credential>::from_bytes(&params, credential_bytes) else {
        return fail("corrupted EC-ACT credential".into());
    };
    let key_id = compute_ec_act_key_id(&pk);
    let ctx_spend = challenge_digest(raw_act_challenge);

    let Ok((spend_state, spend_msg)) =
        ec_act::prove_spend(&params, cred, &ctx_cred, spend_amount, max_top_up, &ctx_spend)
    else {
        return fail("EC-ACT prove_spend failed".into());
    };

    let pau = EcActPresentationAndUpdate {
        key_id,
        spend: spend_msg,
    };
    let presentation = pau.to_bytes();
    let recovery_handle = pau.recovery_handle().to_array();
    let Ok(authorization_header) = (MoleAuthorization::Presentation {
        credential_type: credential_type::EC_ACT,
        presentation,
    })
    .to_header_value() else {
        return fail("failed to format Authorization header".into());
    };

    let spend_bundle = encode_spend_bundle(
        committed_policy.balance_width,
        spend_amount,
        max_top_up,
        &pk_arr,
        &key_id,
        &ctx_cred,
        &spend_state,
    );

    InlinePresentBeginOut {
        ok: true,
        error: String::new(),
        authorization_header,
        key_id: key_id.to_vec(),
        recovery_handle: recovery_handle.to_vec(),
        spend_bundle,
    }
}

pub fn finalize_inline_present_response(
    spend_bundle: &[u8],
    mole_credential_header: &str,
    allowed_refund_amounts: &[u64],
) -> InlinePresentFinishOut {
    let fail = |error: String, keep_spend_for_recovery: bool| InlinePresentFinishOut {
        ok: false,
        error,
        keep_spend_for_recovery,
        is_held: false,
        held_for_secs: 0,
        consumed_no_update: false,
        refunded_credential_bytes: Vec::new(),
        new_balance: 0,
    };

    if mole_credential_header.is_empty() {
        return fail("missing Mole-Credential header".into(), true);
    }
    let (params, spend_amount, max_top_up, pk, _, ctx_cred, spend_state) =
        match decode_spend_bundle(spend_bundle) {
            Ok(v) => v,
            Err(e) => return fail(e, false),
        };
    let parsed = match MoleCredential::parse(mole_credential_header) {
        Ok(c) => c,
        Err(e) => return fail(format!("malformed Mole-Credential: {e}"), true),
    };

    match parsed {
        MoleCredential::HeldForUpdate {
            credential_type: credential_type::EC_ACT,
            duration_secs,
        } => InlinePresentFinishOut {
            ok: true,
            error: String::new(),
            keep_spend_for_recovery: false,
            is_held: true,
            held_for_secs: duration_secs,
            consumed_no_update: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        },
        MoleCredential::Update {
            credential_type: credential_type::EC_ACT,
            update: None,
        } => InlinePresentFinishOut {
            ok: true,
            error: String::new(),
            keep_spend_for_recovery: false,
            is_held: false,
            held_for_secs: 0,
            consumed_no_update: true,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        },
        MoleCredential::Update {
            credential_type: credential_type::EC_ACT,
            update: Some(bytes),
        } => {
            let Ok(act_update) = EcActUpdate::from_bytes(&params, &bytes) else {
                return fail("malformed EcActUpdate".into(), true);
            };
            if let Err(e) = check_allowed_refund(
                act_update.refund.return_amount(),
                spend_amount,
                max_top_up,
                allowed_refund_amounts,
            ) {
                return fail(e, true);
            }
            let Ok(new_cred) =
                ec_act::finalize_refund(&params, &pk, &ctx_cred, spend_state, &act_update.refund)
            else {
                return fail("EC-ACT finalize_refund failed".into(), true);
            };
            let new_balance = new_cred.balance();
            let raw_cred = new_cred.to_bytes();
            InlinePresentFinishOut {
                ok: true,
                error: String::new(),
                keep_spend_for_recovery: false,
                is_held: false,
                held_for_secs: 0,
                consumed_no_update: false,
                refunded_credential_bytes: raw_cred.to_vec(),
                new_balance,
            }
        }
        _ => fail("unexpected Mole-Credential parameter".into(), true),
    }
}

pub fn build_inline_settlement_header(recovery_handle: &[u8], is_signoff: bool) -> String {
    let auth = if is_signoff {
        MoleAuthorization::Signoff {
            credential_type: credential_type::EC_ACT,
            recovery_handle: recovery_handle.to_vec(),
        }
    } else {
        MoleAuthorization::Recovery {
            credential_type: credential_type::EC_ACT,
            recovery_handle: recovery_handle.to_vec(),
        }
    };
    auth.to_header_value().unwrap_or_default()
}

pub fn finalize_inline_settlement_response(
    spend_bundle: &[u8],
    http_status: u16,
    mole_credential_header: &str,
    allowed_refund_amounts: &[u64],
) -> SplitSettleFinishOut {
    if http_status == 404 {
        return SplitSettleFinishOut {
            ok: true,
            error: String::new(),
            keep_spend_for_retry: false,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    }
    if mole_credential_header.is_empty() {
        return SplitSettleFinishOut {
            ok: false,
            error: "missing Mole-Credential on settlement".into(),
            keep_spend_for_retry: true,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        };
    }
    let (params, spend_amount, max_top_up, pk, _, ctx_cred, spend_state) =
        match decode_spend_bundle(spend_bundle) {
            Ok(v) => v,
            Err(e) => {
                return SplitSettleFinishOut {
                    ok: false,
                    error: e,
                    keep_spend_for_retry: false,
                    credential_restored: false,
                    refunded_credential_bytes: Vec::new(),
                    new_balance: 0,
                };
            }
        };

    match MoleCredential::parse(mole_credential_header) {
        Ok(MoleCredential::Update {
            credential_type: credential_type::EC_ACT,
            update: None,
        }) => SplitSettleFinishOut {
            ok: true,
            error: String::new(),
            keep_spend_for_retry: false,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        },
        Ok(MoleCredential::Update {
            credential_type: credential_type::EC_ACT,
            update: Some(bytes),
        }) => {
            let Ok(act_update) = EcActUpdate::from_bytes(&params, &bytes) else {
                return SplitSettleFinishOut {
                    ok: false,
                    error: "malformed EcActUpdate on settlement".into(),
                    keep_spend_for_retry: true,
                    credential_restored: false,
                    refunded_credential_bytes: Vec::new(),
                    new_balance: 0,
                };
            };
            if let Err(e) = check_allowed_refund(
                act_update.refund.return_amount(),
                spend_amount,
                max_top_up,
                allowed_refund_amounts,
            ) {
                return SplitSettleFinishOut {
                    ok: false,
                    error: e,
                    keep_spend_for_retry: false,
                    credential_restored: false,
                    refunded_credential_bytes: Vec::new(),
                    new_balance: 0,
                };
            }
            let Ok(new_cred) =
                ec_act::finalize_refund(&params, &pk, &ctx_cred, spend_state, &act_update.refund)
            else {
                return SplitSettleFinishOut {
                    ok: false,
                    error: "EC-ACT finalize_refund failed on settlement".into(),
                    keep_spend_for_retry: true,
                    credential_restored: false,
                    refunded_credential_bytes: Vec::new(),
                    new_balance: 0,
                };
            };
            let new_balance = new_cred.balance();
            let raw_cred = new_cred.to_bytes();
            SplitSettleFinishOut {
                ok: true,
                error: String::new(),
                keep_spend_for_retry: false,
                credential_restored: true,
                refunded_credential_bytes: raw_cred.to_vec(),
                new_balance,
            }
        }
        _ => SplitSettleFinishOut {
            ok: false,
            error: "unexpected Mole-Credential on settlement".into(),
            keep_spend_for_retry: true,
            credential_restored: false,
            refunded_credential_bytes: Vec::new(),
            new_balance: 0,
        },
    }
}

// ---------------------------------------------------------------------------
// Clearance Token & Challenge Delegation Crypto Helpers
// ---------------------------------------------------------------------------

pub fn generate_p256_clearance_keypair() -> KeypairOut {
    let sk = ecdsa::PrivateKey::<P256>::generate();
    let priv_bytes = Zeroizing::new(sk.to_big_endian().as_ref().to_vec());
    let pub_bytes = sk.to_x962_compressed().as_ref().to_vec();
    KeypairOut {
        private_key: priv_bytes.to_vec(),
        public_key: pub_bytes,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign_split_mole_challenge_p256(
    clearance_private_key: &[u8],
    moderator_origin: &str,
    policy_id: &str,
    target_origin: &str,
    cost: u64,
    nonce: &[u8],
    exp: u64,
) -> String {
    if nonce.is_empty() || nonce.len() > 128 {
        return String::new();
    }
    let Ok(canon_mod) = canonicalize_origin(moderator_origin) else {
        return String::new();
    };
    let Ok(canon_target) = canonicalize_origin(target_origin) else {
        return String::new();
    };
    let Ok(payload) = SplitMoleChallenge::delegation_signing_payload(
        &canon_target,
        &canon_mod,
        policy_id,
        cost,
        exp,
    ) else {
        return String::new();
    };
    let Ok(sig) = sign_p256_fixed64(clearance_private_key, &payload) else {
        return String::new();
    };
    (SplitMoleChallenge {
        moderator: canon_mod,
        policy: policy_id.to_string(),
        cost,
        nonce: nonce.to_vec(),
        max_cost: Some(cost),
        exp: Some(exp),
        sig: Some(sig.to_vec()),
    })
    .to_header_value()
    .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
pub fn verify_sec_mole_authorization_at_origin(
    sec_mole_authorization_header: &str,
    clearance_public_key: &[u8],
    expected_moderator_origin: &str,
    expected_policy_id: &str,
    expected_target_origin: &str,
    expected_method: &str,
    expected_path_and_query: &str,
    expected_challenge_nonce: &[u8],
    min_cost: u64,
    now_unix_secs: u64,
) -> OriginVerifyOut {
    let fail = |error: String| OriginVerifyOut {
        ok: false,
        error,
        moderator_origin: String::new(),
        policy_id: String::new(),
        cost: 0,
        session_id: String::new(),
    };

    let parsed_hdr = match SecMoleAuthorization::parse(sec_mole_authorization_header) {
        Ok(h) => h,
        Err(e) => return fail(format!("malformed Sec-Mole-Authorization: {e}")),
    };
    let token = match ClearanceToken::from_bytes(&parsed_hdr.clearance) {
        Ok(t) => t,
        Err(e) => return fail(format!("malformed ClearanceToken: {e}")),
    };
    let payload = match token.signing_payload() {
        Ok(p) => p,
        Err(e) => return fail(format!("invalid ClearanceToken fields: {e}")),
    };
    if let Err(e) = verify_signature_bytes(clearance_public_key, &payload, &token.signature) {
        return fail(e);
    }

    let Ok(canon_mod) = canonicalize_origin(expected_moderator_origin) else {
        return fail("invalid expected_moderator_origin".into());
    };
    let Ok(canon_target) = canonicalize_origin(expected_target_origin) else {
        return fail("invalid expected_target_origin".into());
    };

    if token.moderator_origin != canon_mod {
        return fail("ClearanceToken moderator_origin mismatch".into());
    }
    if !expected_policy_id.is_empty() && token.policy_id != expected_policy_id {
        return fail("ClearanceToken policy_id mismatch".into());
    }
    if let Err(e) = token.verify_claims(
        &canon_target,
        expected_method,
        expected_path_and_query,
        expected_challenge_nonce,
        min_cost,
        now_unix_secs,
    ) {
        return fail(e.to_string());
    }

    OriginVerifyOut {
        ok: true,
        error: String::new(),
        moderator_origin: token.moderator_origin,
        policy_id: token.policy_id,
        cost: token.cost,
        session_id: parsed_hdr.session.unwrap_or(token.session_id),
    }
}

// ---------------------------------------------------------------------------
// In-Process Spec-Compliant Test Servers (`TestMoleAnchor`, `TestSplitModerator`)
// ---------------------------------------------------------------------------

fn empty_test_resp(status: u16, body: &[u8]) -> TestHttpResponse {
    TestHttpResponse {
        status,
        content_type: "application/octet-stream".into(),
        www_authenticate: Vec::new(),
        mole_credential: String::new(),
        mole_challenge: String::new(),
        mole_info: String::new(),
        body: body.to_vec(),
    }
}

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
    let canon = canonicalize_origin(origin).unwrap_or_else(|_| "https://anchor.example".into());
    Box::new(TestMoleAnchor {
        origin: canon,
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

    pub fn anchor_commitment(&self) -> AnchorCommitment {
        AnchorCommitment {
            found: true,
            grant_uri: format!("{}/mole/grant", self.origin),
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
            grant_uri: format!("{}/mole/grant", self.origin),
            endorsement_type: endorsement_type::EC_IHAT,
            ciphersuite: CIPHERSUITE_P256_SHA256.into(),
            anchor_key: b64_encode(&self.anchor_public_key()),
            issuance_epoch: b64_encode(&self.issuance_epoch),
        };
        serde_json::to_string(&cfg).expect("serializes")
    }

    pub fn handle_grant(&mut self, content_type: &str, body: &[u8]) -> TestHttpResponse {
        match parse_endorsement_request_media_type(content_type) {
            Ok(t) if t == endorsement_type::EC_IHAT => {}
            _ => return empty_test_resp(415, b"invalid Content-Type"),
        }
        let Ok(post) = EcIhatGrantPost::from_bytes(body) else {
            return empty_test_resp(400, b"malformed grant body");
        };
        let resp_bytes = match post {
            EcIhatGrantPost::Request(req) => {
                let n = usize::from(req.count.min(64));
                let mut states = Vec::with_capacity(n);
                let mut commitments = Vec::with_capacity(n);
                for _ in 0..n {
                    let Ok((st, com)) = ec_ihat::commit(&self.issuance_epoch) else {
                        return empty_test_resp(500, b"commit failed");
                    };
                    states.push(st);
                    commitments.push(com);
                }
                let mut sid = [0u8; 32];
                let _ = fill_random(&mut sid);
                self.open_sessions.insert(sid, states);
                (GrantCommitments {
                    session_id: sid,
                    commitments,
                })
                .to_bytes()
                .expect("encodes")
            }
            EcIhatGrantPost::Challenges(ch) => {
                if self.consumed_sessions.contains(&ch.session_id) {
                    return empty_test_resp(400, b"replayed session_id");
                }
                let Some(states) = self.open_sessions.remove(&ch.session_id) else {
                    return empty_test_resp(400, b"unknown session_id");
                };
                self.consumed_sessions.insert(ch.session_id);
                if ch.challenges.len() != states.len() {
                    return empty_test_resp(400, b"challenge count mismatch");
                }
                let mut responses = Vec::with_capacity(states.len());
                for (st, chal) in states.into_iter().zip(&ch.challenges) {
                    let Ok(resp) = ec_ihat::respond(&self.key, st, chal) else {
                        return empty_test_resp(400, b"respond failed");
                    };
                    responses.push(resp);
                }
                (GrantResponses { responses }).to_bytes().expect("encodes")
            }
        };

        let mut resp = empty_test_resp(200, &resp_bytes);
        resp.content_type =
            format_endorsement_response_media_type(endorsement_type::EC_IHAT).expect("ct");
        resp
    }
}

struct CachedIssueRecord {
    idempotency_key: [u8; 32],
    expires_at_secs: u64,
    response_body: Vec<u8>,
}

struct RecordedSession {
    recovery_handle: RecoveryHandle,
    hold_until_secs: u64,
    settled_update: Option<Vec<u8>>,
    spend_msg_bytes: Vec<u8>,
    ctx_spend: [u8; 32],
    reward_override: Option<u64>,
}

pub struct TestSplitModerator {
    origin: String,
    policy_id: String,
    raw_anchor_keys: Vec<[u8; 33]>,
    anchor_set: Vec<ec_ihat::PublicKey>,
    issuance_epoch: Vec<u8>,
    credential_context: Vec<u8>,
    ctx_cred: Vec<u8>,
    balance_width: u8,
    params: ec_act::Params,
    act_key: ec_act::SecretKey,
    clearance_sk: ecdsa::PrivateKey<P256>,
    initial_balance: u64,
    override_initial_balance: Option<u64>,
    spend_amount: u64,
    max_top_up: u64,
    refund_amount: u64,
    allowed_sites: Vec<String>,
    defer_min_delay_ms: u64,
    defer_max_hold_ms: u64,
    now_secs: u64,
    next_session_seq: u64,
    endorsement_nullifiers: HashMap<[u8; 32], CachedIssueRecord>,
    idempotency_hits: usize,
    spend_nullifiers: HashSet<[u8; 32]>,
    sessions_by_handle: HashMap<String, RecordedSession>,
    handle_by_recovery: HashMap<RecoveryHandle, String>,
}

#[allow(clippy::too_many_arguments)]
pub fn new_test_split_moderator(
    origin: &str,
    policy_id: &str,
    accepted_anchor_keys: &Vec<Blob>,
    issuance_epoch: &[u8],
    credential_context: &[u8],
    balance_width: u8,
    initial_balance: u64,
    spend_amount: u64,
    max_top_up: u64,
    refund_amount: u64,
    allowed_sites: &Vec<String>,
) -> Box<TestSplitModerator> {
    let canon = canonicalize_origin(origin).unwrap_or_else(|_| "https://moderator.example".into());
    let mut raw_anchor_keys = Vec::with_capacity(accepted_anchor_keys.len());
    let mut anchor_set = Vec::with_capacity(accepted_anchor_keys.len());
    for b in accepted_anchor_keys {
        let arr: [u8; 33] = b.bytes.as_slice().try_into().expect("33B anchor key");
        anchor_set.push(<ec_ihat::PublicKey>::from_bytes(&arr).expect("valid anchor key"));
        raw_anchor_keys.push(arr);
    }
    let params = ec_act::Params::new(balance_width).expect("valid balance_width");
    let mut seed = Zeroizing::new([0u8; 48]);
    fill_random(&mut *seed).expect("RNG");
    let act_key = ec_act::SecretKey::from_seed(&seed).expect("ACT key");
    let clearance_sk = ecdsa::PrivateKey::<P256>::generate();
    let ctx_cred = derive_ctx_cred(credential_context, balance_width).expect("ctx_cred");

    Box::new(TestSplitModerator {
        origin: canon,
        policy_id: policy_id.to_string(),
        raw_anchor_keys,
        anchor_set,
        issuance_epoch: issuance_epoch.to_vec(),
        credential_context: credential_context.to_vec(),
        ctx_cred,
        balance_width,
        params,
        act_key,
        clearance_sk,
        initial_balance,
        override_initial_balance: None,
        spend_amount,
        max_top_up,
        refund_amount,
        allowed_sites: allowed_sites.clone(),
        defer_min_delay_ms: 0,
        defer_max_hold_ms: 0,
        now_secs: 1_764_200_000,
        next_session_seq: 1,
        endorsement_nullifiers: HashMap::new(),
        idempotency_hits: 0,
        spend_nullifiers: HashSet::new(),
        sessions_by_handle: HashMap::new(),
        handle_by_recovery: HashMap::new(),
    })
}

impl TestSplitModerator {
    pub fn set_defer_hold_ms(&mut self, min_delay_ms: u64, max_hold_ms: u64) {
        self.defer_min_delay_ms = min_delay_ms;
        self.defer_max_hold_ms = max_hold_ms;
    }

    pub fn set_custom_refund_amount(&mut self, refund_amount: u64) {
        self.refund_amount = refund_amount;
    }

    pub fn set_custom_initial_balance_override(
        &mut self,
        override_enabled: bool,
        initial_balance: u64,
    ) {
        self.override_initial_balance = if override_enabled {
            Some(initial_balance)
        } else {
            None
        };
    }

    pub fn rotate_credential_key(&mut self) {
        let mut seed = Zeroizing::new([0u8; 48]);
        fill_random(&mut *seed).expect("RNG");
        self.act_key = ec_act::SecretKey::from_seed(&seed).expect("ACT key");
    }

    pub fn advance_clock_secs(&mut self, delta_secs: u64) {
        self.now_secs = self.now_secs.saturating_add(delta_secs);
    }

    pub fn now_unix_secs(&self) -> u64 {
        self.now_secs
    }

    pub fn clearance_public_key(&self) -> Vec<u8> {
        self.clearance_sk.to_x962_compressed().as_ref().to_vec()
    }

    pub fn credential_public_key(&self) -> Vec<u8> {
        self.act_key.public_key().to_bytes().to_vec()
    }

    pub fn moderator_config_json(&self) -> String {
        let cfg = serde_json::json!({
            "issuance-uri": format!("{}/mole/v1/issue", self.origin),
            "issue-uri": format!("{}/mole/v1/issue", self.origin),
            "present-uri": format!("{}/mole/v1/present", self.origin),
            "settle-uri": format!("{}/mole/v1/settle", self.origin),
            "policy-id": self.policy_id,
            "clearance-public-key": b64_encode(&self.clearance_public_key()),
            "allowed-sites": self.allowed_sites,
            "endorsements": [{
                "endorsement-type": endorsement_type::EC_IHAT,
                "ciphersuite": CIPHERSUITE_P256_SHA256,
                "anchor-set": self.raw_anchor_keys.iter().map(|k| b64_encode(k)).collect::<Vec<_>>(),
                "issuance-epoch": b64_encode(&self.issuance_epoch),
            }],
            "credential-keys": [{
                "credential-type": credential_type::EC_ACT,
                "ciphersuite": CIPHERSUITE_P256_SHA256,
                "credential-key": b64_encode(&self.credential_public_key()),
                "credential-context": b64_encode(&self.credential_context),
                "balance-width": self.balance_width,
                "result-retention": 300,
            }]
        });
        serde_json::to_string(&cfg).expect("serializes")
    }

    pub fn moderator_commitment(&self) -> ModeratorCommitment {
        ModeratorCommitment {
            found: true,
            policies: vec![CommittedPolicy {
                policy_id: self.policy_id.clone(),
                credential_context: self.credential_context.clone(),
                credential_key: self.credential_public_key(),
                clearance_public_key: self.clearance_public_key(),
                balance_width: self.balance_width,
                initial_balance: self.initial_balance,
                spend_amount: self.spend_amount,
                max_top_up: self.max_top_up,
                allowed_refund_amounts: vec![
                    0,
                    self.spend_amount,
                    self.spend_amount.saturating_add(self.max_top_up),
                ],
                min_anchor_set_size: DEFAULT_MIN_ANCHOR_SET_SIZE,
                accepted_anchor_keys: self
                    .raw_anchor_keys
                    .iter()
                    .map(|k| Blob { bytes: k.to_vec() })
                    .collect(),
                epochs: vec![Blob {
                    bytes: self.issuance_epoch.clone(),
                }],
                allowed_sites: self.allowed_sites.clone(),
                allow_no_endorsement: false,
                issuance_uri: format!("{}/mole/v1/issue", self.origin),
                present_uri: format!("{}/mole/v1/present", self.origin),
                settle_uri: format!("{}/mole/v1/settle", self.origin),
            }],
        }
    }

    pub fn make_origin_challenge_header(
        &self,
        target_origin: &str,
        cost: u64,
        nonce: &[u8],
        include_delegation_sig: bool,
    ) -> String {
        if include_delegation_sig {
            let sk_bytes = Zeroizing::new(self.clearance_sk.to_big_endian().as_ref().to_vec());
            sign_split_mole_challenge_p256(
                &sk_bytes,
                &self.origin,
                &self.policy_id,
                target_origin,
                cost,
                nonce,
                self.now_secs + 300,
            )
        } else {
            (SplitMoleChallenge {
                moderator: self.origin.clone(),
                policy: self.policy_id.clone(),
                cost,
                nonce: nonce.to_vec(),
                max_cost: None,
                exp: None,
                sig: None,
            })
            .to_header_value()
            .expect("header")
        }
    }

    pub fn handle_split_issue(&mut self, body: &[u8]) -> TestHttpResponse {
        let Ok(req) = IssueRequestEnvelope::from_bytes(body) else {
            return empty_test_resp(400, b"malformed IssueRequestEnvelope");
        };
        if req.endorsement_type != endorsement_type::EC_IHAT {
            return empty_test_resp(400, b"unsupported endorsement_type");
        }
        let expected_key_id = compute_ec_act_key_id(&self.act_key.public_key());
        if req.key_id != expected_key_id {
            return empty_test_resp(400, b"wrong key_id");
        }

        let mut ctx_input = Vec::new();
        ctx_input.extend_from_slice(b"MOLE-SPLIT-ISSUE-v1|");
        ctx_input.extend_from_slice(self.origin.as_bytes());
        ctx_input.push(b'|');
        ctx_input.extend_from_slice(req.policy_id.as_bytes());
        ctx_input.push(b'|');
        ctx_input.extend_from_slice(&req.idempotency_key);
        let expected_red_ctx = sha256(&ctx_input);
        if req.redemption_context != expected_red_ctx {
            return empty_test_resp(400, b"mismatched redemption_context");
        }

        let Ok(redemption) =
            <ec_ihat::Redemption>::from_bytes(&req.ihat_redeem_proof, self.anchor_set.len())
        else {
            return empty_test_resp(400, b"malformed EC-IHAT Redemption");
        };
        let challenge_dig = (RedemptionChallenge {
            redemption_context: expected_red_ctx,
        })
        .digest();
        let Ok(nullifier) = ec_ihat::verify_redemption(
            &self.anchor_set,
            &redemption,
            &self.issuance_epoch,
            EC_IHAT_CTX_RED,
            &challenge_dig,
        ) else {
            return empty_test_resp(401, b"EC-IHAT verify_redemption failed");
        };

        // 5-minute `(nullifier_A, idempotency_key)` cache!
        if let Some(cached) = self.endorsement_nullifiers.get(&nullifier) {
            if cached.idempotency_key == req.idempotency_key
                && self.now_secs <= cached.expires_at_secs
            {
                self.idempotency_hits += 1;
                return empty_test_resp(200, &cached.response_body);
            }
            return empty_test_resp(401, b"double-spent EC-IHAT nullifier");
        }

        let Ok(act_req) = EcActIssuanceRequest::from_bytes(&self.params, &req.act_issue_request)
        else {
            return empty_test_resp(400, b"malformed EcActIssuanceRequest");
        };
        if act_req.truncated_key_id != expected_key_id[31]
            || act_req.credential_context != self.credential_context
        {
            return empty_test_resp(400, b"wrong truncated_key_id or context");
        }
        let Ok(verified_req) = ec_act::verify_issue_request(&self.params, &act_req.request) else {
            return empty_test_resp(400, b"invalid IssueRequest proof");
        };

        let grant_bal = self.override_initial_balance.unwrap_or(self.initial_balance);
        let Ok(issue_resp) = ec_act::issue_response(
            &self.act_key,
            &self.ctx_cred,
            grant_bal,
            verified_req,
        ) else {
            return empty_test_resp(400, b"EC-ACT issue_response failed");
        };

        let resp_body = (IssueResponseEnvelope {
            act_issue_response: (EcActIssuanceResponse {
                response: issue_resp,
            })
            .to_bytes(),
            initial_credit: grant_bal,
        })
        .to_bytes()
        .expect("encodes");

        self.endorsement_nullifiers.insert(
            nullifier,
            CachedIssueRecord {
                idempotency_key: req.idempotency_key,
                expires_at_secs: self.now_secs + 300,
                response_body: resp_body.clone(),
            },
        );
        empty_test_resp(200, &resp_body)
    }

    pub fn handle_split_present(&mut self, body: &[u8]) -> TestHttpResponse {
        let Ok(req) = PresentRequestEnvelope::from_bytes(body) else {
            return empty_test_resp(400, b"malformed PresentRequestEnvelope");
        };
        let Ok(pau) = EcActPresentationAndUpdate::from_bytes(&self.params, &req.act_presentation)
        else {
            return empty_test_resp(400, b"malformed EcActPresentationAndUpdate");
        };
        let expected_key_id = compute_ec_act_key_id(&self.act_key.public_key());
        if req.key_id != expected_key_id || pau.key_id != expected_key_id {
            return empty_test_resp(401, b"unknown/rotated key_id");
        }
        let nullifier = pau.spend.nullifier();
        if self.spend_nullifiers.contains(&nullifier) {
            return empty_test_resp(401, b"double-spent EC-ACT nullifier");
        }
        if pau.spend.amount() != req.cost || pau.spend.allowance() != self.max_top_up {
            return empty_test_resp(400, b"spend amounts mismatch");
        }
        let prc = req.protected_request_context();
        let Ok(ctx_spend) = compute_split_ctx_spend(
            &prc,
            req.cost,
            self.max_top_up,
            &self.credential_context,
        ) else {
            return empty_test_resp(400, b"invalid ProtectedRequestContext");
        };

        let spend_msg_bytes = pau.spend.to_bytes().to_vec();
        let rec_handle = pau.recovery_handle();
        let Ok(verified_spend) = ec_act::verify_spend(
            &self.params,
            &self.act_key,
            &self.ctx_cred,
            &ctx_spend,
            &pau.spend,
        ) else {
            return empty_test_resp(401, b"EC-ACT verify_spend failed");
        };
        self.spend_nullifiers.insert(nullifier);

        let session_handle = format!("sess-{}", self.next_session_seq);
        self.next_session_seq += 1;

        let mut token = ClearanceToken {
            version: ClearanceToken::VERSION,
            moderator_origin: self.origin.clone(),
            policy_id: self.policy_id.clone(),
            target_origin: req.target_origin,
            method: req.method,
            path_and_query: req.path_and_query,
            challenge_nonce: req.challenge_nonce,
            cost: req.cost,
            issued_at: self.now_secs,
            expires_at: self.now_secs + 120,
            session_id: session_handle.clone(),
            signature: [0u8; 64],
        };
        let signing_payload = token.signing_payload().expect("payload");
        token.signature = self
            .clearance_sk
            .sign_p1363(&signing_payload)
            .as_slice()
            .try_into()
            .expect("64B ECDSA P1363 sig");
        let token_bytes = token.to_bytes().expect("token encodes");

        if req.allow_deferred && self.defer_min_delay_ms > 0 {
            let hold_secs = self.defer_min_delay_ms.div_ceil(1000);
            self.handle_by_recovery
                .insert(rec_handle, session_handle.clone());
            self.sessions_by_handle.insert(
                session_handle.clone(),
                RecordedSession {
                    recovery_handle: rec_handle,
                    hold_until_secs: self.now_secs + hold_secs,
                    settled_update: None,
                    spend_msg_bytes,
                    ctx_spend,
                    reward_override: None,
                },
            );
            let resp_body = (PresentResponseEnvelope::Held {
                clearance_token: token_bytes,
                session_handle,
                min_delay_ms: self.defer_min_delay_ms as u32,
                max_hold_ms: self.defer_max_hold_ms as u32,
            })
            .to_bytes()
            .expect("encodes");
            return empty_test_resp(202, &resp_body);
        }

        let Ok(refund) = ec_act::issue_refund(verified_spend, self.refund_amount) else {
            return empty_test_resp(500, b"issue_refund failed");
        };
        let upd_bytes = (EcActUpdate { refund }).to_bytes();

        self.handle_by_recovery
            .insert(rec_handle, session_handle.clone());
        self.sessions_by_handle.insert(
            session_handle,
            RecordedSession {
                recovery_handle: rec_handle,
                hold_until_secs: self.now_secs,
                settled_update: Some(upd_bytes.clone()),
                spend_msg_bytes,
                ctx_spend,
                reward_override: None,
            },
        );

        let resp_body = (PresentResponseEnvelope::Settled {
            clearance_token: token_bytes,
            act_refund_response: upd_bytes,
        })
        .to_bytes()
        .expect("encodes");
        empty_test_resp(200, &resp_body)
    }

    pub fn record_origin_reward(
        &mut self,
        session_handle: &str,
        reward_refund_amount: u64,
    ) -> bool {
        let Some(sess) = self.sessions_by_handle.get_mut(session_handle) else {
            return false;
        };
        sess.reward_override = Some(reward_refund_amount);
        sess.hold_until_secs = self.now_secs;
        true
    }

    pub fn handle_split_settle(&mut self, body: &[u8]) -> TestHttpResponse {
        let Ok(req) = SettleRequestEnvelope::from_bytes(body) else {
            return empty_test_resp(400, b"malformed SettleRequestEnvelope");
        };
        let handle = if !req.session_handle.is_empty() {
            req.session_handle
        } else if let Some(rec) = req.recovery_handle {
            match self.handle_by_recovery.get(&rec) {
                Some(h) => h.clone(),
                None => return empty_test_resp(404, b"unknown recovery_handle"),
            }
        } else {
            return empty_test_resp(400, b"missing handle");
        };

        let Some(sess) = self.sessions_by_handle.get_mut(&handle) else {
            return empty_test_resp(404, b"unknown session");
        };
        if let Some(rec) = req.recovery_handle {
            if rec != sess.recovery_handle {
                return empty_test_resp(404, b"mismatched recovery_handle");
            }
        }

        if sess.settled_update.is_none() {
            if !req.is_signoff && self.now_secs < sess.hold_until_secs {
                let retry_ms =
                    ((sess.hold_until_secs - self.now_secs).saturating_mul(1000)) as u32;
                let pending_body = (SettleResponseEnvelope::Pending {
                    retry_after_ms: retry_ms,
                })
                .to_bytes()
                .expect("encodes");
                return empty_test_resp(202, &pending_body);
            }
            let effective_refund = sess.reward_override.unwrap_or(self.refund_amount);
            let spend = <ec_act::SpendMessage>::from_bytes(&self.params, &sess.spend_msg_bytes)
                .expect("stored spend valid");
            let Ok(verified_spend) = ec_act::verify_spend(
                &self.params,
                &self.act_key,
                &self.ctx_cred,
                &sess.ctx_spend,
                &spend,
            ) else {
                return empty_test_resp(500, b"settle verify_spend failed");
            };
            let Ok(refund) = ec_act::issue_refund(verified_spend, effective_refund) else {
                return empty_test_resp(500, b"settle issue_refund failed");
            };
            sess.settled_update = Some((EcActUpdate { refund }).to_bytes());
        }

        let act_refund_response = sess.settled_update.clone().unwrap_or_default();
        let resp_body = (SettleResponseEnvelope::Settled {
            act_refund_response,
        })
        .to_bytes()
        .expect("encodes");
        empty_test_resp(200, &resp_body)
    }

    pub fn consumed_endorsement_nullifiers(&self) -> usize {
        self.endorsement_nullifiers.len()
    }

    pub fn consumed_spend_nullifiers(&self) -> usize {
        self.spend_nullifiers.len()
    }

    pub fn idempotency_cache_hits(&self) -> usize {
        self.idempotency_hits
    }
}
