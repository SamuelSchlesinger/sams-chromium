// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The `Mole` HTTP authentication scheme and grant media types
//! (`draft-jms-mole-http-transport-01` & `draft-jms-mole-protocols-01` §8.3):
//! - `WWW-Authenticate: Mole` (`endorse-XXXX`, `redeem-XXXX`, `challenge-XXXX`)
//! - `Authorization: Mole` (`redeem-EEEE` + `credential-request-CCCC`,
//!   `presentation-TTTT`, `recovery-TTTT`, `signoff-TTTT`)
//! - `Mole-Credential` (`response-TTTT`, `update-TTTT`, `held-for-update-TTTT`)
//! - `application/mole-endorsement-{request,response}; type=XXXX`

use core::fmt;
use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::MAX_MOLE_HEADER_LEN;
use crate::endorsement_type;
use crate::messages::RedemptionChallenge;

/// The HTTP authentication scheme token.
pub const SCHEME: &str = "Mole";
/// Lowercase `Mole-Credential` response header name.
pub const MOLE_CREDENTIAL: &str = "mole-credential";
/// Grant request media-type essence.
pub const ENDORSEMENT_REQUEST_MEDIA_TYPE: &str = "application/mole-endorsement-request";
/// Grant response media-type essence.
pub const ENDORSEMENT_RESPONSE_MEDIA_TYPE: &str = "application/mole-endorsement-response";

/// Encodes `bytes` as canonical unpadded base64url (RFC 4648 §5).
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes canonical unpadded base64url, rejecting padding (`=`), whitespace,
/// and non-zero trailing bits (`draft-jms-mole-http-transport-01` §§2, 3).
pub fn b64_decode(value: &str) -> Result<Vec<u8>, HeaderError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| HeaderError::InvalidBase64)
}

/// Error parsing or formatting a MOLE HTTP header or media type.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HeaderError {
    /// Header exceeded `MAX_MOLE_HEADER_LEN` (`4096` bytes).
    TooLarge,
    /// Header did not use the `Mole` authentication scheme.
    NotMole,
    /// Header parameters or RFC 9110 auth-param grammar were malformed.
    MalformedParams,
    /// Parameter value was not canonical unpadded base64url.
    InvalidBase64,
    /// Type suffix was `0000` or not 4 hexadecimal digits.
    InvalidTypeSuffix,
    /// Grant media type or `type` parameter was invalid.
    InvalidMediaType,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("Mole header exceeds MAX_MOLE_HEADER_LEN"),
            Self::NotMole => f.write_str("not a Mole header"),
            Self::MalformedParams => f.write_str("malformed Mole header parameters"),
            Self::InvalidBase64 => f.write_str("invalid canonical base64url value"),
            Self::InvalidTypeSuffix => f.write_str("invalid 4-digit hexadecimal protocol type suffix"),
            Self::InvalidMediaType => f.write_str("invalid MOLE endorsement media type"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Parses an exact 4-character hexadecimal suffix, rejecting `0000`.
pub fn parse_hex4_nonzero(s: &str) -> Result<u16, HeaderError> {
    if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HeaderError::InvalidTypeSuffix);
    }
    match u16::from_str_radix(s, 16) {
        Ok(val) if val != 0 => Ok(val),
        _ => Err(HeaderError::InvalidTypeSuffix),
    }
}

fn format_typed_param(prefix: &str, type_id: u16, payload: &[u8]) -> Result<String, HeaderError> {
    if type_id == 0 {
        return Err(HeaderError::InvalidTypeSuffix);
    }
    Ok(format!("{prefix}{type_id:04x}=\"{}\"", b64_encode(payload)))
}

/// Formats `application/mole-endorsement-request; type=XXXX`.
pub fn format_endorsement_request_media_type(endorsement_type_id: u16) -> Result<String, HeaderError> {
    if endorsement_type_id == 0 {
        return Err(HeaderError::InvalidTypeSuffix);
    }
    Ok(format!("{ENDORSEMENT_REQUEST_MEDIA_TYPE}; type={endorsement_type_id:04x}"))
}

/// Formats `application/mole-endorsement-response; type=XXXX`.
pub fn format_endorsement_response_media_type(endorsement_type_id: u16) -> Result<String, HeaderError> {
    if endorsement_type_id == 0 {
        return Err(HeaderError::InvalidTypeSuffix);
    }
    Ok(format!("{ENDORSEMENT_RESPONSE_MEDIA_TYPE}; type={endorsement_type_id:04x}"))
}

/// Parses and validates `application/mole-endorsement-request; type=XXXX`.
pub fn parse_endorsement_request_media_type(header_value: &str) -> Result<u16, HeaderError> {
    parse_mole_media_type(header_value, ENDORSEMENT_REQUEST_MEDIA_TYPE)
}

/// Parses and validates `application/mole-endorsement-response; type=XXXX`.
pub fn parse_endorsement_response_media_type(header_value: &str) -> Result<u16, HeaderError> {
    parse_mole_media_type(header_value, ENDORSEMENT_RESPONSE_MEDIA_TYPE)
}

/// Parses `<expected_essence>; type=XXXX`, rejecting missing/duplicate/extra
/// parameters or `0000` (`draft-jms-mole-protocols-01` §8.3).
pub fn parse_mole_media_type(input: &str, expected_essence: &str) -> Result<u16, HeaderError> {
    if input.len() > MAX_MOLE_HEADER_LEN {
        return Err(HeaderError::TooLarge);
    }
    let mut parts = input.split(';');
    let essence = parts.next().ok_or(HeaderError::InvalidMediaType)?.trim();
    if !essence.eq_ignore_ascii_case(expected_essence) {
        return Err(HeaderError::InvalidMediaType);
    }
    let param = parts.next().ok_or(HeaderError::InvalidMediaType)?.trim();
    if parts.next().is_some() {
        return Err(HeaderError::InvalidMediaType);
    }
    let (name, raw_val) = param.split_once('=').ok_or(HeaderError::InvalidMediaType)?;
    if !name.trim().eq_ignore_ascii_case("type") {
        return Err(HeaderError::InvalidMediaType);
    }
    let val = unquote_token_or_quoted(raw_val.trim()).ok_or(HeaderError::InvalidMediaType)?;
    parse_hex4_nonzero(&val).map_err(|_| HeaderError::InvalidMediaType)
}

fn unquote_token_or_quoted(raw: &str) -> Option<String> {
    if let Some(inner) = raw.strip_prefix('"') {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            if c == '\\' {
                let esc = chars.next()?;
                out.push(esc);
            } else if c == '"' {
                closed = true;
                break;
            } else {
                out.push(c);
            }
        }
        if !closed || chars.next().is_some() {
            return None;
        }
        Some(out)
    } else if !raw.is_empty() && raw.bytes().all(is_tchar) {
        Some(raw.to_string())
    } else {
        None
    }
}

/// Parsed `Mole` challenge from `WWW-Authenticate` (`draft-jms-mole-http-transport-01` §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleChallenge {
    /// `endorse-T="<anchor-context>"`
    Endorse {
        endorsement_type: u16,
        context: Vec<u8>,
    },
    /// `redeem-T="<32-byte RedemptionChallenge>"` (32 bytes for all `T`, including `0001`).
    Redeem {
        endorsement_type: u16,
        challenge: [u8; RedemptionChallenge::LENGTH],
    },
    /// `challenge-T="<credential-challenge>"`
    Credential {
        credential_type: u16,
        challenge: Vec<u8>,
    },
}

impl MoleChallenge {
    /// Formats a single `WWW-Authenticate` challenge (`Mole <param>="<b64url>"`).
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        let param = match self {
            Self::Endorse {
                endorsement_type,
                context,
            } => format_typed_param("endorse-", *endorsement_type, context)?,
            Self::Redeem {
                endorsement_type,
                challenge,
            } => format_typed_param("redeem-", *endorsement_type, challenge)?,
            Self::Credential {
                credential_type,
                challenge,
            } => format_typed_param("challenge-", *credential_type, challenge)?,
        };
        Ok(format!("{SCHEME} {param}"))
    }
}

/// Formats multiple `MoleChallenge` values into a comma-separated `WWW-Authenticate` header.
pub fn format_www_authenticate(challenges: &[MoleChallenge]) -> Result<String, HeaderError> {
    if challenges.is_empty() {
        return Err(HeaderError::MalformedParams);
    }
    challenges
        .iter()
        .map(MoleChallenge::to_header_value)
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.join(", "))
}

/// Parsed `Authorization: Mole ...` credential (`draft-jms-mole-http-transport-01` §§3, 5.4, 5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleAuthorization {
    /// `redeem-E="<redemption>", credential-request-C="<issuance-request>"`
    RedeemAndIssue {
        endorsement_type: u16,
        redemption: Vec<u8>,
        credential_type: u16,
        credential_request: Vec<u8>,
    },
    /// `presentation-T="<presentation-and-update>"`
    Presentation {
        credential_type: u16,
        presentation: Vec<u8>,
    },
    /// `recovery-T="<recovery-handle>"`
    Recovery {
        credential_type: u16,
        recovery_handle: Vec<u8>,
    },
    /// `signoff-T="<recovery-handle>"`
    Signoff {
        credential_type: u16,
        recovery_handle: Vec<u8>,
    },
}

impl MoleAuthorization {
    /// Formats as an `Authorization` header value.
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        let body = match self {
            Self::RedeemAndIssue {
                endorsement_type,
                redemption,
                credential_type,
                credential_request,
            } => {
                if *endorsement_type == endorsement_type::NO_ENDORSEMENT && !redemption.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                if *endorsement_type != endorsement_type::NO_ENDORSEMENT && redemption.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                if credential_request.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                format!(
                    "{}, {}",
                    format_typed_param("redeem-", *endorsement_type, redemption)?,
                    format_typed_param("credential-request-", *credential_type, credential_request)?
                )
            }
            Self::Presentation {
                credential_type,
                presentation,
            } => format_typed_param("presentation-", *credential_type, presentation)?,
            Self::Recovery {
                credential_type,
                recovery_handle,
            } => {
                if recovery_handle.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                format_typed_param("recovery-", *credential_type, recovery_handle)?
            }
            Self::Signoff {
                credential_type,
                recovery_handle,
            } => {
                if recovery_handle.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                format_typed_param("signoff-", *credential_type, recovery_handle)?
            }
        };
        Ok(format!("{SCHEME} {body}"))
    }

    /// Strictly parses an `Authorization` header value.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let challenges = parse_rfc9110_challenges(value)?;
        let [ch] = challenges.as_slice() else {
            return Err(HeaderError::MalformedParams);
        };
        if !ch.scheme.eq_ignore_ascii_case(SCHEME) {
            return Err(HeaderError::NotMole);
        }
        if ch.params.is_empty() {
            return Err(HeaderError::MalformedParams);
        }
        ensure_no_duplicate_params(&ch.params)?;

        let mut redeem: Option<(u16, Vec<u8>)> = None;
        let mut cred_req: Option<(u16, Vec<u8>)> = None;
        let mut presentation: Option<(u16, Vec<u8>)> = None;
        let mut recovery: Option<(u16, Vec<u8>)> = None;
        let mut signoff: Option<(u16, Vec<u8>)> = None;

        for (raw_name, val) in &ch.params {
            let name = raw_name.to_ascii_lowercase();
            match classify_op(&name)? {
                None => {} // Ignore unknown extension params such as `realm`
                Some((OpKind::Redeem, type_id)) => {
                    if redeem.is_some() {
                        return Err(HeaderError::MalformedParams);
                    }
                    let decoded = b64_decode(val)?;
                    if type_id == endorsement_type::NO_ENDORSEMENT && !decoded.is_empty() {
                        return Err(HeaderError::MalformedParams);
                    }
                    if type_id != endorsement_type::NO_ENDORSEMENT && decoded.is_empty() {
                        return Err(HeaderError::MalformedParams);
                    }
                    redeem = Some((type_id, decoded));
                }
                Some((OpKind::CredentialRequest, type_id)) => {
                    if cred_req.is_some() {
                        return Err(HeaderError::MalformedParams);
                    }
                    let decoded = b64_decode(val)?;
                    if decoded.is_empty() {
                        return Err(HeaderError::MalformedParams);
                    }
                    cred_req = Some((type_id, decoded));
                }
                Some((OpKind::Presentation, type_id)) => {
                    if presentation.is_some() {
                        return Err(HeaderError::MalformedParams);
                    }
                    presentation = Some((type_id, b64_decode(val)?));
                }
                Some((OpKind::Recovery, type_id)) => {
                    if recovery.is_some() {
                        return Err(HeaderError::MalformedParams);
                    }
                    let decoded = b64_decode(val)?;
                    if decoded.is_empty() {
                        return Err(HeaderError::MalformedParams);
                    }
                    recovery = Some((type_id, decoded));
                }
                Some((OpKind::Signoff, type_id)) => {
                    if signoff.is_some() {
                        return Err(HeaderError::MalformedParams);
                    }
                    let decoded = b64_decode(val)?;
                    if decoded.is_empty() {
                        return Err(HeaderError::MalformedParams);
                    }
                    signoff = Some((type_id, decoded));
                }
                Some(_) => return Err(HeaderError::MalformedParams),
            }
        }

        let has_redeem_pair = redeem.is_some() || cred_req.is_some();
        let active_ops = usize::from(has_redeem_pair)
            + usize::from(presentation.is_some())
            + usize::from(recovery.is_some())
            + usize::from(signoff.is_some());
        if active_ops != 1 {
            return Err(HeaderError::MalformedParams);
        }

        if has_redeem_pair {
            let (Some((endorsement_type, redemption)), Some((credential_type, credential_request))) =
                (redeem, cred_req)
            else {
                return Err(HeaderError::MalformedParams);
            };
            Ok(Self::RedeemAndIssue {
                endorsement_type,
                redemption,
                credential_type,
                credential_request,
            })
        } else if let Some((credential_type, presentation)) = presentation {
            Ok(Self::Presentation {
                credential_type,
                presentation,
            })
        } else if let Some((credential_type, recovery_handle)) = recovery {
            Ok(Self::Recovery {
                credential_type,
                recovery_handle,
            })
        } else if let Some((credential_type, recovery_handle)) = signoff {
            Ok(Self::Signoff {
                credential_type,
                recovery_handle,
            })
        } else {
            Err(HeaderError::MalformedParams)
        }
    }
}

/// Parsed `Mole-Credential` response header (`draft-jms-mole-http-transport-01` §§4, 5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleCredential {
    /// `response-T="<issuance-response>"`
    Response {
        credential_type: u16,
        response: Vec<u8>,
    },
    /// `update-T="<update>"` (`Some`) or `update-T=""` (`None` = recorded `NoUpdate`).
    Update {
        credential_type: u16,
        update: Option<Vec<u8>>,
    },
    /// `held-for-update-T="<seconds>"`
    HeldForUpdate {
        credential_type: u16,
        duration_secs: u64,
    },
}

impl MoleCredential {
    /// Formats as a `Mole-Credential` header value.
    pub fn to_header_value(&self) -> Result<String, HeaderError> {
        match self {
            Self::Response {
                credential_type,
                response,
            } => {
                if response.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                format_typed_param("response-", *credential_type, response)
            }
            Self::Update {
                credential_type,
                update: Some(bytes),
            } => {
                if bytes.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                format_typed_param("update-", *credential_type, bytes)
            }
            Self::Update {
                credential_type,
                update: None,
            } => {
                if *credential_type == 0 {
                    return Err(HeaderError::InvalidTypeSuffix);
                }
                Ok(format!("update-{credential_type:04x}=\"\""))
            }
            Self::HeldForUpdate {
                credential_type,
                duration_secs,
            } => {
                if *credential_type == 0 {
                    return Err(HeaderError::InvalidTypeSuffix);
                }
                Ok(format!("held-for-update-{credential_type:04x}=\"{duration_secs}\""))
            }
        }
    }

    /// Strictly parses a single `Mole-Credential` header value (must contain
    /// exactly one parameter, `draft-jms-mole-http-transport-01` §4).
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        if value.len() > MAX_MOLE_HEADER_LEN {
            return Err(HeaderError::TooLarge);
        }
        let trimmed = value.trim_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with(',') || trimmed.ends_with(',') {
            return Err(HeaderError::MalformedParams);
        }
        let synthetic = format!("{SCHEME} {trimmed}");
        let challenges = parse_rfc9110_challenges(&synthetic)?;
        let [ch] = challenges.as_slice() else {
            return Err(HeaderError::MalformedParams);
        };
        let [(raw_name, val)] = ch.params.as_slice() else {
            return Err(HeaderError::MalformedParams);
        };
        let name = raw_name.to_ascii_lowercase();
        match classify_op(&name)? {
            Some((OpKind::Response, type_id)) => {
                let decoded = b64_decode(val)?;
                if decoded.is_empty() {
                    return Err(HeaderError::MalformedParams);
                }
                Ok(Self::Response {
                    credential_type: type_id,
                    response: decoded,
                })
            }
            Some((OpKind::Update, type_id)) => {
                let update = if val.is_empty() {
                    None
                } else {
                    Some(b64_decode(val)?)
                };
                Ok(Self::Update {
                    credential_type: type_id,
                    update,
                })
            }
            Some((OpKind::HeldForUpdate, type_id)) => {
                let duration_secs = parse_ascii_u64_seconds(val)?;
                Ok(Self::HeldForUpdate {
                    credential_type: type_id,
                    duration_secs,
                })
            }
            _ => Err(HeaderError::MalformedParams),
        }
    }
}

fn parse_ascii_u64_seconds(s: &str) -> Result<u64, HeaderError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HeaderError::MalformedParams);
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(HeaderError::MalformedParams);
    }
    s.parse::<u64>().map_err(|_| HeaderError::MalformedParams)
}

/// Parses all valid `Mole` challenges across `WWW-Authenticate` header lines,
/// ignoring non-`Mole` schemes and skipping malformed individual `Mole`
/// challenges per `draft-jms-mole-http-transport-01` §3.
pub fn parse_challenges(header_values: &[&str]) -> Vec<MoleChallenge> {
    let mut out = Vec::new();
    for line in header_values {
        if let Ok(raw_list) = parse_rfc9110_challenges(line) {
            for raw in raw_list {
                if raw.scheme.eq_ignore_ascii_case(SCHEME) {
                    if let Ok(ch) = parse_mole_challenge_from_raw(&raw) {
                        out.push(ch);
                    }
                }
            }
        }
    }
    out
}

/// Strictly parses a single `Mole` challenge string (`Mole <param>="<val>"`).
pub fn parse_single_challenge_strict(input: &str) -> Result<MoleChallenge, HeaderError> {
    let list = parse_rfc9110_challenges(input)?;
    let [raw] = list.as_slice() else {
        return Err(HeaderError::MalformedParams);
    };
    if !raw.scheme.eq_ignore_ascii_case(SCHEME) {
        return Err(HeaderError::NotMole);
    }
    parse_mole_challenge_from_raw(raw)
}

fn parse_mole_challenge_from_raw(raw: &RawChallenge) -> Result<MoleChallenge, HeaderError> {
    ensure_no_duplicate_params(&raw.params)?;
    let mut parsed: Option<MoleChallenge> = None;
    for (raw_name, val) in &raw.params {
        let name = raw_name.to_ascii_lowercase();
        match classify_op(&name)? {
            None => {}
            Some((OpKind::Endorse, type_id)) => {
                if parsed.is_some() {
                    return Err(HeaderError::MalformedParams);
                }
                parsed = Some(MoleChallenge::Endorse {
                    endorsement_type: type_id,
                    context: b64_decode(val)?,
                });
            }
            Some((OpKind::Redeem, type_id)) => {
                if parsed.is_some() {
                    return Err(HeaderError::MalformedParams);
                }
                let decoded = b64_decode(val)?;
                let challenge: [u8; RedemptionChallenge::LENGTH] = decoded
                    .try_into()
                    .map_err(|_| HeaderError::MalformedParams)?;
                parsed = Some(MoleChallenge::Redeem {
                    endorsement_type: type_id,
                    challenge,
                });
            }
            Some((OpKind::Challenge, type_id)) => {
                if parsed.is_some() {
                    return Err(HeaderError::MalformedParams);
                }
                parsed = Some(MoleChallenge::Credential {
                    credential_type: type_id,
                    challenge: b64_decode(val)?,
                });
            }
            Some(_) => return Err(HeaderError::MalformedParams),
        }
    }
    parsed.ok_or(HeaderError::MalformedParams)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpKind {
    Endorse,
    Redeem,
    Challenge,
    CredentialRequest,
    Presentation,
    Recovery,
    Signoff,
    Response,
    Update,
    HeldForUpdate,
}

const OPERATIONS: &[(&str, OpKind)] = &[
    ("endorse-", OpKind::Endorse),
    ("redeem-", OpKind::Redeem),
    ("challenge-", OpKind::Challenge),
    ("credential-request-", OpKind::CredentialRequest),
    ("presentation-", OpKind::Presentation),
    ("recovery-", OpKind::Recovery),
    ("signoff-", OpKind::Signoff),
    ("response-", OpKind::Response),
    ("update-", OpKind::Update),
    ("held-for-update-", OpKind::HeldForUpdate),
];

fn classify_op(lowercase_name: &str) -> Result<Option<(OpKind, u16)>, HeaderError> {
    for &(prefix, kind) in OPERATIONS {
        if let Some(suffix) = lowercase_name.strip_prefix(prefix) {
            return Ok(Some((kind, parse_hex4_nonzero(suffix)?)));
        }
    }
    Ok(None)
}

fn ensure_no_duplicate_params(params: &[(String, String)]) -> Result<(), HeaderError> {
    let mut seen = HashSet::with_capacity(params.len());
    for (name, _) in params {
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(HeaderError::MalformedParams);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 9110 §11.2 / §11.6.1 Challenge & Auth-Param Parser
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RawChallenge {
    scheme: String,
    params: Vec<(String, String)>,
}

fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
            | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

fn skip_ows(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
        pos += 1;
    }
    pos
}

fn skip_commas_and_ows(bytes: &[u8], mut pos: usize) -> (usize, bool) {
    let mut saw_comma = false;
    loop {
        pos = skip_ows(bytes, pos);
        if pos < bytes.len() && bytes[pos] == b',' {
            saw_comma = true;
            pos += 1;
        } else {
            break;
        }
    }
    (pos, saw_comma)
}

fn read_token(input: &str, pos: usize) -> Option<(&str, usize)> {
    let bytes = input.as_bytes();
    let mut end = pos;
    while end < bytes.len() && is_tchar(bytes[end]) {
        end += 1;
    }
    if end == pos {
        None
    } else {
        Some((&input[pos..end], end))
    }
}

fn read_quoted_string(input: &str, pos: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    if bytes.get(pos) != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = pos + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                i += 1;
                let esc = *bytes.get(i)?;
                if !(esc == b'\t' || (0x20..=0x7E).contains(&esc)) {
                    return None;
                }
                out.push(esc as char);
                i += 1;
            }
            b if b == b'\t' || (0x20..=0x7E).contains(&b) => {
                out.push(b as char);
                i += 1;
            }
            _ => return None,
        }
    }
    None
}

fn parse_rfc9110_challenges(input: &str) -> Result<Vec<RawChallenge>, HeaderError> {
    if input.len() > MAX_MOLE_HEADER_LEN {
        return Err(HeaderError::TooLarge);
    }
    let bytes = input.as_bytes();
    let (mut pos, _) = skip_commas_and_ows(bytes, 0);
    if pos >= bytes.len() {
        return Err(HeaderError::MalformedParams);
    }

    let mut challenges = Vec::new();
    while pos < bytes.len() {
        let (scheme, after_scheme) = read_token(input, pos).ok_or(HeaderError::MalformedParams)?;
        pos = after_scheme;

        // End of string or `,` immediately after scheme -> parameterless challenge.
        if pos >= bytes.len() {
            challenges.push(RawChallenge {
                scheme: scheme.to_string(),
                params: Vec::new(),
            });
            break;
        }

        let ows_after_scheme = skip_ows(bytes, pos);
        if ows_after_scheme < bytes.len() && bytes[ows_after_scheme] == b',' {
            challenges.push(RawChallenge {
                scheme: scheme.to_string(),
                params: Vec::new(),
            });
            let (next_pos, _) = skip_commas_and_ows(bytes, ows_after_scheme);
            pos = next_pos;
            continue;
        }

        // Must have required SP(s) after auth-scheme.
        let mut sp_end = pos;
        while sp_end < bytes.len() && bytes[sp_end] == b' ' {
            sp_end += 1;
        }
        if sp_end == pos {
            return Err(HeaderError::MalformedParams);
        }
        pos = sp_end;

        // Check for token68 (e.g. `Bearer abc.def=` with no auth-param `name=val`).
        // A token68 has tchars + `+/-._~` + trailing `=*`, followed by end or `,`.
        if let Some(after_t68) = try_skip_token68(bytes, pos) {
            let after_ows = skip_ows(bytes, after_t68);
            if after_ows == bytes.len() || bytes[after_ows] == b',' {
                // Non-Mole token68 challenge (e.g. `Bearer xyz`); if scheme is `Mole`, reject!
                if scheme.eq_ignore_ascii_case(SCHEME) {
                    return Err(HeaderError::MalformedParams);
                }
                challenges.push(RawChallenge {
                    scheme: scheme.to_string(),
                    params: Vec::new(),
                });
                let (next_pos, _) = skip_commas_and_ows(bytes, after_ows);
                pos = next_pos;
                continue;
            }
        }

        // Parse comma-separated `auth-param`s until end of input or next `scheme ...`.
        let mut params = Vec::new();
        loop {
            let (pname, after_pname) = read_token(input, pos).ok_or(HeaderError::MalformedParams)?;
            let eq_pos = skip_ows(bytes, after_pname);
            if eq_pos >= bytes.len() || bytes[eq_pos] != b'=' {
                return Err(HeaderError::MalformedParams);
            }
            let val_pos = skip_ows(bytes, eq_pos + 1);
            let (pval, after_pval) = if bytes.get(val_pos) == Some(&b'"') {
                read_quoted_string(input, val_pos).ok_or(HeaderError::MalformedParams)?
            } else {
                let (tok, end) = read_token(input, val_pos).ok_or(HeaderError::MalformedParams)?;
                (tok.to_string(), end)
            };
            params.push((pname.to_string(), pval));

            let after_ows = skip_ows(bytes, after_pval);
            if after_ows >= bytes.len() {
                pos = after_ows;
                break;
            }
            if bytes[after_ows] != b',' {
                return Err(HeaderError::MalformedParams);
            }
            let (next_tok_pos, _) = skip_commas_and_ows(bytes, after_ows);
            if next_tok_pos >= bytes.len() {
                pos = next_tok_pos;
                break;
            }

            // Look ahead after the next token: if followed by OWS + `=`, it is
            // another auth-param of THIS challenge; otherwise it starts a NEW challenge!
            let (_, look_after_tok) =
                read_token(input, next_tok_pos).ok_or(HeaderError::MalformedParams)?;
            let look_ows = skip_ows(bytes, look_after_tok);
            if look_ows < bytes.len() && bytes[look_ows] == b'=' {
                pos = next_tok_pos;
            } else {
                pos = next_tok_pos;
                break;
            }
        }

        challenges.push(RawChallenge {
            scheme: scheme.to_string(),
            params,
        });
    }

    if challenges.is_empty() {
        return Err(HeaderError::MalformedParams);
    }
    Ok(challenges)
}

fn try_skip_token68(bytes: &[u8], pos: usize) -> Option<usize> {
    let mut i = pos;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric()
            || matches!(bytes[i], b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
    {
        i += 1;
    }
    if i == pos {
        return None;
    }
    while i < bytes.len() && bytes[i] == b'=' {
        i += 1;
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_base64url_rejects_padding_and_noncanonical_bits() {
        assert!(b64_decode("AQID").is_ok());
        assert!(b64_decode("AQ==").is_err());
        // 'AB' has non-zero trailing bits in the second sextet.
        assert!(b64_decode("AB").is_err());
    }

    #[test]
    fn www_authenticate_parses_multi_challenge_and_requires_32b_redeem() {
        let cred = MoleChallenge::Credential {
            credential_type: 0x0001,
            challenge: vec![1, 2, 3, 4],
        };
        let red_ihat = MoleChallenge::Redeem {
            endorsement_type: 0x0002,
            challenge: [0xAB; 32],
        };
        let red_none = MoleChallenge::Redeem {
            endorsement_type: 0x0001,
            challenge: [0xCD; 32],
        };
        let combined = format!(
            "Bearer xyz123==, {}, realm=\"moderator\", {}, {}",
            cred.to_header_value().unwrap(),
            red_ihat.to_header_value().unwrap(),
            red_none.to_header_value().unwrap()
        );
        let parsed = parse_challenges(&[combined.as_str()]);
        assert_eq!(parsed, vec![cred, red_ihat, red_none]);

        // Empty redeem-0001 challenge in WWW-Authenticate MUST be rejected per -01 §4.1.
        assert!(parse_single_challenge_strict("Mole redeem-0001=\"\"").is_err());
        assert!(parse_single_challenge_strict("Mole redeem-0002=\"AQID\"").is_err());
        assert!(parse_single_challenge_strict("Mole ENDORSE-0002=\"\"").is_ok());
        assert!(parse_single_challenge_strict("Mole challenge-0000=\"AQID\"").is_err());
        assert!(parse_single_challenge_strict("Mole challenge-001=\"AQID\"").is_err());
    }

    #[test]
    fn authorization_parses_either_redeem_order_and_rejects_mixed_or_dup() {
        let auth = MoleAuthorization::RedeemAndIssue {
            endorsement_type: 0x0002,
            redemption: vec![7; 48],
            credential_type: 0x0001,
            credential_request: vec![8; 64],
        };
        let hdr = auth.to_header_value().unwrap();
        assert_eq!(MoleAuthorization::parse(&hdr).unwrap(), auth);

        // Reversed parameter order is explicitly allowed by §3.
        let reversed = format!(
            "Mole credential-request-0001=\"{}\", redeem-0002=\"{}\"",
            b64_encode(&[8; 64]),
            b64_encode(&[7; 48])
        );
        assert_eq!(MoleAuthorization::parse(&reversed).unwrap(), auth);

        // No-endorsement uses empty redeem-0001="" in Authorization.
        let no_end = MoleAuthorization::RedeemAndIssue {
            endorsement_type: 0x0001,
            redemption: Vec::new(),
            credential_type: 0x0001,
            credential_request: vec![9; 32],
        };
        assert_eq!(
            MoleAuthorization::parse(&no_end.to_header_value().unwrap()).unwrap(),
            no_end
        );

        // Recovery and Signoff round-trip.
        for op in [
            MoleAuthorization::Presentation {
                credential_type: 0x0001,
                presentation: vec![5; 80],
            },
            MoleAuthorization::Recovery {
                credential_type: 0x0001,
                recovery_handle: vec![6; 96],
            },
            MoleAuthorization::Signoff {
                credential_type: 0x0001,
                recovery_handle: vec![4; 96],
            },
        ] {
            let h = op.to_header_value().unwrap();
            assert_eq!(MoleAuthorization::parse(&h).unwrap(), op);
        }

        // Mixed operations & duplicates fail.
        assert!(MoleAuthorization::parse("Mole redeem-0002=\"AQID\"").is_err());
        assert!(
            MoleAuthorization::parse(
                "Mole presentation-0001=\"AQID\", recovery-0001=\"AQID\""
            )
            .is_err()
        );
    }

    #[test]
    fn mole_credential_supports_response_update_no_update_and_held() {
        for c in [
            MoleCredential::Response {
                credential_type: 0x0001,
                response: vec![1; 137],
            },
            MoleCredential::Update {
                credential_type: 0x0001,
                update: Some(vec![2; 137]),
            },
            MoleCredential::Update {
                credential_type: 0x0001,
                update: None,
            },
            MoleCredential::HeldForUpdate {
                credential_type: 0x0001,
                duration_secs: 30,
            },
        ] {
            let hdr = c.to_header_value().unwrap();
            assert_eq!(MoleCredential::parse(&hdr).unwrap(), c);
        }
        assert!(MoleCredential::parse("update-0001=\"AQID\", response-0001=\"AQID\"").is_err());
        assert!(MoleCredential::parse("held-for-update-0001=\"030\"").is_err());
    }

    #[test]
    fn media_type_requires_exact_4_hex_type() {
        let req = format_endorsement_request_media_type(0x0002).unwrap();
        assert_eq!(req, "application/mole-endorsement-request; type=0002");
        assert_eq!(parse_endorsement_request_media_type(&req).unwrap(), 0x0002);
        assert!(parse_endorsement_request_media_type("application/mole-endorsement-request").is_err());
        assert!(
            parse_endorsement_request_media_type(
                "application/mole-endorsement-request; type=0000"
            )
            .is_err()
        );
        assert!(
            parse_endorsement_request_media_type(
                "application/mole-endorsement-request; type=0002; extra=1"
            )
            .is_err()
        );
    }
}
