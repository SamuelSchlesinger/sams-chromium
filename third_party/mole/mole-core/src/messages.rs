// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Direct (unwrapped) binary protocol messages per `draft-jms-mole-protocols-01`
//! and Split Moderation & Redemption request-context binding:
//! - EC-IHAT batched grants (`GrantRequest`, `GrantCommitments`, `GrantChallenges`, `GrantResponses`)
//! - 32-byte `RedemptionChallenge` (§4.1)
//! - EC-ACT `IssuanceRequest`, `IssuanceResponse`, `Challenge`, `PresentationAndUpdate`,
//!   `Update`, and 96-byte `RecoveryHandle` (§5.2)
//! - `ProtectedRequestContext` (`MOLE-PROTECTED-REQUEST-v1`)

use crate::act::compute_recovery_handle;
use crate::wire::{
    Wire, WireError, get_fixed, get_opaque_bounded, get_opaque_slice, get_str_v, get_u8, get_u16,
    get_u64, put_opaque_v, put_str_v, put_u8, put_u16, put_u64,
};
use crate::{
    MAX_ANCHOR_SET_LEN, MAX_CREDENTIAL_CONTEXT_LEN, MAX_REQUEST_CONTEXT_LEN, challenge_digest,
};

/// Domain separation prefix for `ProtectedRequestContext`.
pub const PROTECTED_REQUEST_DST: &[u8] = b"MOLE-PROTECTED-REQUEST-v1";

fn encode_fixed_batch<const N: usize, T>(
    prefix_session_id: Option<&[u8; 32]>,
    items: &[T],
    empty_err: &'static str,
    to_bytes: impl Fn(&T) -> [u8; N],
) -> Result<Vec<u8>, WireError> {
    if items.is_empty() || items.len() > MAX_ANCHOR_SET_LEN {
        return Err(WireError::Malformed(empty_err));
    }
    let mut raw = Vec::with_capacity(items.len() * N);
    for item in items {
        raw.extend_from_slice(&to_bytes(item));
    }
    let mut out = Vec::with_capacity(prefix_session_id.map_or(0, |s| s.len()) + 8 + raw.len());
    if let Some(sid) = prefix_session_id {
        out.extend_from_slice(sid);
    }
    put_opaque_v(&mut out, &raw)?;
    Ok(out)
}

fn decode_fixed_batch<const N: usize, T, E>(
    buf: &mut &[u8],
    len_err: &'static str,
    crypto_err: &'static str,
    from_slice: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<Vec<T>, WireError> {
    let raw = get_opaque_slice(buf)?;
    if raw.is_empty() || raw.len() % N != 0 || (raw.len() / N) > MAX_ANCHOR_SET_LEN {
        return Err(WireError::Malformed(len_err));
    }
    raw.as_chunks::<N>()
        .0
        .iter()
        .map(|chunk| from_slice(chunk.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| WireError::Malformed(crypto_err))
}

// ---------------------------------------------------------------------------
// EC-IHAT Batch Grant (`draft-jms-mole-protocols-01` §4.4.2)
// ---------------------------------------------------------------------------

/// `struct { uint16 count; } GrantRequest;`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    /// Requested number of Endorsements (`1 <= count <= 64`).
    pub count: u16,
}

impl GrantRequest {
    /// Encoded length (always 2 bytes).
    pub const LENGTH: usize = 2;
}

impl Wire for GrantRequest {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.count == 0 || usize::from(self.count) > MAX_ANCHOR_SET_LEN {
            return Err(WireError::Malformed("GrantRequest count must be in 1..=64"));
        }
        put_u16(out, self.count);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let count = get_u16(buf)?;
        if count == 0 || usize::from(count) > MAX_ANCHOR_SET_LEN {
            return Err(WireError::Malformed("GrantRequest count must be in 1..=64"));
        }
        Ok(Self { count })
    }
}

/// `struct { opaque session_id[32]; CommitMessage commitments<V>; } GrantCommitments;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantCommitments {
    /// Fresh 32-byte Anchor batch session identifier.
    pub session_id: [u8; 32],
    /// Ordered `CommitMessage` items (`1 <= len <= count`).
    pub commitments: Vec<ec_ihat::CommitMessage>,
}

impl Wire for GrantCommitments {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&encode_fixed_batch(
            Some(&self.session_id),
            &self.commitments,
            "GrantCommitments count out of range",
            ec_ihat::CommitMessage::to_bytes,
        )?);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let session_id = get_fixed::<32>(buf)?;
        let commitments = decode_fixed_batch::<{ <ec_ihat::CommitMessage>::LENGTH }, _, _>(
            buf,
            "GrantCommitments vector length invalid",
            "malformed EC-IHAT CommitMessage",
            ec_ihat::CommitMessage::from_bytes,
        )?;
        Ok(Self {
            session_id,
            commitments,
        })
    }
}

/// `struct { opaque session_id[32]; ChallengeMessage challenges<V>; } GrantChallenges;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantChallenges {
    /// Correlating 32-byte Anchor batch session identifier.
    pub session_id: [u8; 32],
    /// Ordered `ChallengeMessage` items matching `GrantCommitments`.
    pub challenges: Vec<ec_ihat::ChallengeMessage>,
}

impl Wire for GrantChallenges {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&encode_fixed_batch(
            Some(&self.session_id),
            &self.challenges,
            "GrantChallenges count out of range",
            ec_ihat::ChallengeMessage::to_bytes,
        )?);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let session_id = get_fixed::<32>(buf)?;
        let challenges = decode_fixed_batch::<{ <ec_ihat::ChallengeMessage>::LENGTH }, _, _>(
            buf,
            "GrantChallenges vector length invalid",
            "malformed EC-IHAT ChallengeMessage",
            ec_ihat::ChallengeMessage::from_bytes,
        )?;
        Ok(Self {
            session_id,
            challenges,
        })
    }
}

/// `struct { ResponseMessage responses<V>; } GrantResponses;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantResponses {
    /// Ordered `ResponseMessage` items matching `GrantChallenges`.
    pub responses: Vec<ec_ihat::ResponseMessage>,
}

impl Wire for GrantResponses {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&encode_fixed_batch(
            None,
            &self.responses,
            "GrantResponses count out of range",
            ec_ihat::ResponseMessage::to_bytes,
        )?);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let responses = decode_fixed_batch::<{ <ec_ihat::ResponseMessage>::LENGTH }, _, _>(
            buf,
            "GrantResponses vector length invalid",
            "malformed EC-IHAT ResponseMessage",
            ec_ihat::ResponseMessage::from_bytes,
        )?;
        Ok(Self { responses })
    }
}

/// Disambiguates an incoming EC-IHAT grant POST body (`application/mole-endorsement-request; type=0002`):
/// Step 1 (`GrantRequest`) is 2 bytes; Step 2 (`GrantChallenges`) is `>= 65` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcIhatGrantPost {
    /// Step 1: initial batch request.
    Request(GrantRequest),
    /// Step 2: blinded challenge submission.
    Challenges(GrantChallenges),
}

impl EcIhatGrantPost {
    /// Parses a raw EC-IHAT grant POST body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() == GrantRequest::LENGTH {
            Ok(Self::Request(GrantRequest::from_bytes(bytes)?))
        } else {
            Ok(Self::Challenges(GrantChallenges::from_bytes(bytes)?))
        }
    }
}

// ---------------------------------------------------------------------------
// Endorsement Redemption (`draft-jms-mole-protocols-01` §4.1)
// ---------------------------------------------------------------------------

/// `struct { opaque redemption_context[32]; } RedemptionChallenge;`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedemptionChallenge {
    /// Moderator-constructed 32-byte redemption context.
    pub redemption_context: [u8; 32],
}

impl RedemptionChallenge {
    /// Exact encoded length (32 bytes).
    pub const LENGTH: usize = 32;

    /// Computes `challenge_digest = SHA-256(moderator_challenge)`.
    pub fn digest(&self) -> [u8; 32] {
        challenge_digest(&self.redemption_context)
    }
}

impl Wire for RedemptionChallenge {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&self.redemption_context);
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Self {
            redemption_context: get_fixed::<32>(buf)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Protected Request Context (`MOLE-PROTECTED-REQUEST-v1`)
// ---------------------------------------------------------------------------

/// Canonical request-binding structure embedded inside `EcActChallenge.request_context`
/// in Split Moderation & Redemption (`POST /mole/v1/present`) so the EC-ACT
/// zero-knowledge spend proof is cryptographically bound to the exact Origin request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedRequestContext {
    /// Canonical target HTTPS origin (`https://shoes.example:8443`).
    pub target_origin: String,
    /// Uppercase HTTP method (`GET`, `POST`, ...).
    pub method: String,
    /// Origin path and optional query (`/api/purchase?sku=1`).
    pub path_and_query: String,
    /// Origin-issued challenge nonce (`Mole-Challenge` `nonce`, or empty on proactive spend).
    pub challenge_nonce: Vec<u8>,
    /// Spend cost `s`.
    pub cost: u64,
    /// Whether the client allows deferred settlement (`202 Accepted` hold).
    pub allow_deferred: bool,
}

impl Wire for ProtectedRequestContext {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let start = out.len();
        out.extend_from_slice(PROTECTED_REQUEST_DST);
        put_str_v(out, &self.target_origin, 256)?;
        put_str_v(out, &self.method, 32)?;
        put_str_v(out, &self.path_and_query, 512)?;
        if self.challenge_nonce.len() > 128 {
            return Err(WireError::OutOfRange);
        }
        put_opaque_v(out, &self.challenge_nonce)?;
        put_u64(out, self.cost);
        put_u8(out, u8::from(self.allow_deferred));
        if out.len() - start > MAX_REQUEST_CONTEXT_LEN {
            return Err(WireError::OutOfRange);
        }
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        if buf.len() > MAX_REQUEST_CONTEXT_LEN {
            return Err(WireError::OutOfRange);
        }
        let prefix = crate::wire::take(buf, PROTECTED_REQUEST_DST.len())?;
        if prefix != PROTECTED_REQUEST_DST {
            return Err(WireError::Malformed("invalid ProtectedRequestContext DST"));
        }
        let target_origin = get_str_v(buf, 256)?;
        let method = get_str_v(buf, 32)?;
        let path_and_query = get_str_v(buf, 512)?;
        let challenge_nonce = get_opaque_bounded(buf, 128)?.to_vec();
        let cost = get_u64(buf)?;
        let allow_deferred = match get_u8(buf)? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Malformed("invalid allow_deferred boolean")),
        };
        Ok(Self {
            target_origin,
            method,
            path_and_query,
            challenge_nonce,
            cost,
            allow_deferred,
        })
    }
}

// ---------------------------------------------------------------------------
// EC-ACT Credential Messages (`draft-jms-mole-protocols-01` §5.2)
// ---------------------------------------------------------------------------

/// `struct { uint8 truncated_key_id; opaque credential_context<V>; IssueRequestMessage request; } IssuanceRequest;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActIssuanceRequest {
    /// Last byte of `key_id = SHA-256(SerializeElement(pkM))`.
    pub truncated_key_id: u8,
    /// Configured `credential_context` (`<= MAX_CREDENTIAL_CONTEXT_LEN`).
    pub credential_context: Vec<u8>,
    /// Underlying EC-ACT `IssueRequestMessage` (129 bytes).
    pub request: ec_act::IssueRequestMessage,
}

impl EcActIssuanceRequest {
    /// Encodes `EcActIssuanceRequest`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        if self.credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(WireError::OutOfRange);
        }
        let req_bytes = self.request.to_bytes();
        let mut out = Vec::with_capacity(1 + 4 + self.credential_context.len() + req_bytes.len());
        put_u8(&mut out, self.truncated_key_id);
        put_opaque_v(&mut out, &self.credential_context)?;
        out.extend_from_slice(&req_bytes);
        Ok(out)
    }

    /// Splits `(truncated_key_id, credential_context, raw_request_bytes)` before
    /// `Params` selection (`draft-jms-mole-protocols-01` §5.2.2 step 1).
    pub fn split_header(bytes: &[u8]) -> Result<(u8, Vec<u8>, &[u8; 129]), WireError> {
        let mut cur = bytes;
        let truncated_key_id = get_u8(&mut cur)?;
        let credential_context = get_opaque_bounded(&mut cur, MAX_CREDENTIAL_CONTEXT_LEN)?;
        let Some((req_arr, trailing)) =
            cur.split_first_chunk::<{ <ec_act::IssueRequestMessage>::LENGTH }>()
        else {
            return Err(WireError::UnexpectedEof);
        };
        if !trailing.is_empty() {
            return Err(WireError::TrailingBytes);
        }
        Ok((truncated_key_id, credential_context.to_vec(), req_arr))
    }

    /// Decodes `EcActIssuanceRequest` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, WireError> {
        let (truncated_key_id, credential_context, req_arr) = Self::split_header(bytes)?;
        let request = ec_act::IssueRequestMessage::from_bytes(params, req_arr)
            .map_err(|_| WireError::Malformed("invalid EC-ACT IssueRequestMessage"))?;
        Ok(Self {
            truncated_key_id,
            credential_context,
            request,
        })
    }
}

/// `struct { IssueResponseMessage response; } IssuanceResponse;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActIssuanceResponse {
    /// Underlying EC-ACT `IssueResponseMessage` (137 bytes).
    pub response: ec_act::IssueResponseMessage,
}

impl EcActIssuanceResponse {
    /// Encodes `EcActIssuanceResponse`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.response.to_bytes().to_vec()
    }

    /// Decodes `EcActIssuanceResponse` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, WireError> {
        let response = ec_act::IssueResponseMessage::from_bytes(params, bytes)
            .map_err(|_| WireError::Malformed("invalid EC-ACT IssueResponseMessage"))?;
        Ok(Self { response })
    }
}

/// `struct { uint64 spend_amount; uint64 max_top_up; opaque credential_context<V>; opaque request_context<V>; } Challenge;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActChallenge {
    /// Required spend amount `s`.
    pub spend_amount: u64,
    /// Maximum offered top-up `a`.
    pub max_top_up: u64,
    /// Credential context (`<= MAX_CREDENTIAL_CONTEXT_LEN`).
    pub credential_context: Vec<u8>,
    /// Policy-scoped (empty) or request-bound context bytes (`<= MAX_REQUEST_CONTEXT_LEN`).
    pub request_context: Vec<u8>,
}

impl EcActChallenge {
    /// Computes `ctx_spend = SHA-256(credential_challenge)` (`draft-jms-mole-protocols-01` §5.2.3.1).
    pub fn ctx_spend(&self) -> Result<[u8; 32], WireError> {
        Ok(challenge_digest(&self.to_bytes()?))
    }
}

impl Wire for EcActChallenge {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN
            || self.request_context.len() > MAX_REQUEST_CONTEXT_LEN
        {
            return Err(WireError::OutOfRange);
        }
        put_u64(out, self.spend_amount);
        put_u64(out, self.max_top_up);
        put_opaque_v(out, &self.credential_context)?;
        put_opaque_v(out, &self.request_context)?;
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let spend_amount = get_u64(buf)?;
        let max_top_up = get_u64(buf)?;
        let credential_context = get_opaque_bounded(buf, MAX_CREDENTIAL_CONTEXT_LEN)?;
        let request_context = get_opaque_bounded(buf, MAX_REQUEST_CONTEXT_LEN)?;
        Ok(Self {
            spend_amount,
            max_top_up,
            credential_context: credential_context.to_vec(),
            request_context: request_context.to_vec(),
        })
    }
}

/// `struct { opaque key_id[32]; SpendMessage spend; } PresentationAndUpdate;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActPresentationAndUpdate {
    /// Full 32-byte `key_id = SHA-256(SerializeElement(pkM))`.
    pub key_id: [u8; 32],
    /// Underlying EC-ACT `SpendMessage`.
    pub spend: ec_act::SpendMessage,
}

impl EcActPresentationAndUpdate {
    /// Encodes `EcActPresentationAndUpdate`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let spend_bytes = self.spend.to_bytes();
        let mut out = Vec::with_capacity(32 + spend_bytes.len());
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&spend_bytes);
        out
    }

    /// Splits `(key_id, spend_slice)` so the Moderator can select active key
    /// `Params` before decoding `SpendMessage` (`draft-jms-mole-protocols-01` §5.2.3.2 step 1).
    pub fn split_key_id(bytes: &[u8]) -> Result<([u8; 32], &[u8]), WireError> {
        match bytes.split_first_chunk::<32>() {
            Some((&key_id, spend_slice)) if !spend_slice.is_empty() => Ok((key_id, spend_slice)),
            _ => Err(WireError::UnexpectedEof),
        }
    }

    /// Decodes `EcActPresentationAndUpdate` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, WireError> {
        let (key_id, spend_slice) = Self::split_key_id(bytes)?;
        let spend = ec_act::SpendMessage::from_bytes(params, spend_slice)
            .map_err(|_| WireError::Malformed("invalid EC-ACT SpendMessage"))?;
        Ok(Self { key_id, spend })
    }

    /// Computes the 96-byte `RecoveryHandle` for this presentation.
    pub fn recovery_handle(&self) -> RecoveryHandle {
        let raw = self.to_bytes();
        let nf = self.spend.nullifier();
        RecoveryHandle::from_array(compute_recovery_handle(&self.key_id, &nf, &raw))
    }
}

/// `struct { RefundMessage refund; } Update;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActUpdate {
    /// Underlying EC-ACT `RefundMessage` (137 bytes).
    pub refund: ec_act::RefundMessage,
}

impl EcActUpdate {
    /// Encodes `EcActUpdate` (non-empty).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.refund.to_bytes().to_vec()
    }

    /// Decodes `EcActUpdate` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, WireError> {
        let refund = ec_act::RefundMessage::from_bytes(params, bytes)
            .map_err(|_| WireError::Malformed("invalid EC-ACT RefundMessage"))?;
        Ok(Self { refund })
    }
}

/// 96-byte EC-ACT recovery / signoff handle (`draft-jms-mole-protocols-01` §5.2.5):
/// `key_id[32] || SerializeScalar(spend.k)[32] || SHA-256(PresentationAndUpdate)[32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecoveryHandle {
    /// 32-byte `key_id`.
    pub key_id: [u8; 32],
    /// 32-byte big-endian encoding of `spend.k`.
    pub nullifier: [u8; 32],
    /// 32-byte SHA-256 digest of the `PresentationAndUpdate` octets.
    pub presentation_sha256: [u8; 32],
}

impl RecoveryHandle {
    /// Exact encoded length (96 bytes).
    pub const LENGTH: usize = 96;

    /// Constructs from a 96-byte array.
    pub fn from_array(bytes: [u8; Self::LENGTH]) -> Self {
        let ([key_id, nullifier, presentation_sha256], _) = bytes.as_chunks::<32>() else {
            unreachable!()
        };
        Self {
            key_id: *key_id,
            nullifier: *nullifier,
            presentation_sha256: *presentation_sha256,
        }
    }

    /// Encodes to a 96-byte array.
    pub fn to_array(&self) -> [u8; Self::LENGTH] {
        let mut out = [0u8; Self::LENGTH];
        out[..32].copy_from_slice(&self.key_id);
        out[32..64].copy_from_slice(&self.nullifier);
        out[64..96].copy_from_slice(&self.presentation_sha256);
        out
    }
}

impl Wire for RecoveryHandle {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&self.to_array());
        Ok(())
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Self::from_array(get_fixed::<96>(buf)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_request_and_disambiguation() {
        let req = GrantRequest { count: 4 };
        let bytes = req.to_bytes().unwrap();
        assert_eq!(bytes, vec![0x00, 0x04]);
        assert_eq!(
            EcIhatGrantPost::from_bytes(&bytes).unwrap(),
            EcIhatGrantPost::Request(req)
        );
        assert!(GrantRequest { count: 0 }.to_bytes().is_err());
        assert!(GrantRequest { count: 65 }.to_bytes().is_err());
        assert!(GrantRequest::from_bytes(&[0, 0]).is_err());
    }

    #[test]
    fn ec_act_challenge_field_order_and_bounds() {
        let chal = EcActChallenge {
            spend_amount: 1,
            max_top_up: 2,
            credential_context: b"ctx".to_vec(),
            request_context: b"req".to_vec(),
        };
        let bytes = chal.to_bytes().unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(&[3, b'c', b't', b'x', 3, b'r', b'e', b'q']);
        assert_eq!(bytes, expected);
        assert_eq!(EcActChallenge::from_bytes(&bytes).unwrap(), chal);

        let oversized = EcActChallenge {
            spend_amount: 1,
            max_top_up: 0,
            credential_context: vec![0u8; MAX_CREDENTIAL_CONTEXT_LEN + 1],
            request_context: Vec::new(),
        };
        assert!(oversized.to_bytes().is_err());
    }

    #[test]
    fn protected_request_context_round_trips() {
        let prc = ProtectedRequestContext {
            target_origin: "https://shoes.example:8443".into(),
            method: "POST".into(),
            path_and_query: "/api/purchase?sku=42".into(),
            challenge_nonce: vec![0xAA; 16],
            cost: 2,
            allow_deferred: true,
        };
        let enc = prc.to_bytes().unwrap();
        assert_eq!(ProtectedRequestContext::from_bytes(&enc).unwrap(), prc);
    }

    #[test]
    fn recovery_handle_round_trips() {
        let h = RecoveryHandle {
            key_id: [0x11; 32],
            nullifier: [0x22; 32],
            presentation_sha256: [0x33; 32],
        };
        let bytes = h.to_bytes().unwrap();
        assert_eq!(bytes.len(), 96);
        assert_eq!(RecoveryHandle::from_bytes(&bytes).unwrap(), h);
    }
}
