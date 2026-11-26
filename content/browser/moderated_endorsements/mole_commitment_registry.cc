// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_commitment_registry.h"

#include <optional>
#include <utility>

#include "base/base64url.h"
#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/no_destructor.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "content/public/browser/mole_key_commitments.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {

namespace {

// Dev/test override: inline registry JSON supplied on the command line, so a
// deployment without the published component (e.g. content_shell demos, tests)
// can still enroll Anchors and Moderators. Mirrors Private State Tokens'
// `--additional-trust-token-key-commitments`.
constexpr char kMoleKeyCommitmentsSwitch[] = "mole-key-commitments";

// Top-level sections.
constexpr char kAnchorsField[] = "anchors";
constexpr char kModeratorsField[] = "moderators";
// Anchor entry (`draft-jms-mole-protocols-01` §6).
constexpr char kGrantUriField[] = "grant-uri";
constexpr char kKeysField[] = "keys";
constexpr char kEpochsField[] = "epochs";
// Moderator policy entry (`draft-jms-mole-protocols-01` §6, §8).
constexpr char kPoliciesField[] = "policies";
constexpr char kCredentialContextField[] = "credential-context";
constexpr char kCredentialKeyField[] = "credential-key";
constexpr char kBalanceWidthField[] = "balance-width";
constexpr char kInitialBalanceField[] = "initial-balance";
constexpr char kSpendAmountField[] = "spend-amount";
constexpr char kMaxTopUpField[] = "max-top-up";
constexpr char kAcceptedAnchorKeysField[] = "accepted-anchor-keys";
constexpr char kAllowNoEndorsementField[] = "allow-no-endorsement";
constexpr char kIssuanceUriField[] = "issuance-uri";

using Bytes = std::vector<uint8_t>;

// Unpadded base64url (RFC 4648 §5), matching `mole_core`'s wire encoding.
std::optional<Bytes> DecodeB64(const std::string& in) {
  std::string decoded;
  if (!base::Base64UrlDecode(in, base::Base64UrlDecodePolicy::DISALLOW_PADDING,
                             &decoded)) {
    return std::nullopt;
  }
  return Bytes(decoded.begin(), decoded.end());
}

// Decodes a JSON array of base64url strings into `out`; false on any bad entry.
bool DecodeB64Array(const base::ListValue& list, std::vector<Bytes>* out) {
  for (const base::Value& v : list) {
    if (!v.is_string()) {
      return false;
    }
    std::optional<Bytes> bytes = DecodeB64(v.GetString());
    if (!bytes) {
      return false;
    }
    out->push_back(std::move(*bytes));
  }
  return true;
}

// Canonical serialized HTTPS origin ("https://host:port"), or empty if invalid.
std::string CanonicalOrigin(const std::string& raw) {
  url::Origin origin = url::Origin::Create(GURL(raw));
  if (origin.opaque() || origin.scheme() != "https") {
    return std::string();
  }
  return origin.Serialize();
}

moderated_endorsements::Blob ToBlob(const Bytes& bytes) {
  moderated_endorsements::Blob blob;
  rust::Vec<uint8_t> v;
  v.reserve(bytes.size());
  for (uint8_t b : bytes) {
    v.push_back(b);
  }
  blob.bytes = std::move(v);
  return blob;
}

rust::Vec<uint8_t> ToRustVec(const Bytes& bytes) {
  rust::Vec<uint8_t> v;
  v.reserve(bytes.size());
  for (uint8_t b : bytes) {
    v.push_back(b);
  }
  return v;
}

rust::Vec<moderated_endorsements::Blob> ToBlobs(
    const std::vector<Bytes>& items) {
  rust::Vec<moderated_endorsements::Blob> out;
  for (const Bytes& item : items) {
    out.push_back(ToBlob(item));
  }
  return out;
}

}  // namespace

// static
MoleCommitmentRegistry& MoleCommitmentRegistry::GetInstance() {
  static base::NoDestructor<MoleCommitmentRegistry> instance;
  return *instance;
}

MoleCommitmentRegistry::MoleCommitmentRegistry() {
  // Seed from the command-line override, if present. The component updater
  // overwrites this later via SetMoleKeyCommitments once a signed component is
  // delivered.
  const base::CommandLine* command_line =
      base::CommandLine::ForCurrentProcess();
  if (command_line->HasSwitch(kMoleKeyCommitmentsSwitch)) {
    ParseAndSet(command_line->GetSwitchValueASCII(kMoleKeyCommitmentsSwitch));
  }
}

MoleCommitmentRegistry::~MoleCommitmentRegistry() = default;

bool MoleCommitmentRegistry::ParseAndSet(std::string_view json) {
  std::optional<base::DictValue> parsed =
      base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
  if (!parsed) {
    return false;
  }
  const base::DictValue& root = *parsed;

  // Build into fresh maps and swap only on full success, so a malformed
  // document never leaves the registry half-updated.
  base::flat_map<std::string, CommittedAnchor> anchors;
  base::flat_map<std::string, CommittedModerator> moderators;

  if (const base::DictValue* anchors_dict = root.FindDict(kAnchorsField)) {
    for (const auto [raw_origin, value] : *anchors_dict) {
      std::string origin = CanonicalOrigin(raw_origin);
      const base::DictValue* entry = value.GetIfDict();
      if (origin.empty() || !entry) {
        return false;
      }
      CommittedAnchor anchor;
      if (const base::Value* grant_uri_val = entry->Find(kGrantUriField)) {
        if (!grant_uri_val->is_string() ||
            !base::IsStringUTF8(grant_uri_val->GetString())) {
          return false;
        }
        anchor.grant_uri = grant_uri_val->GetString();
      }
      const base::ListValue* keys = entry->FindList(kKeysField);
      const base::ListValue* epochs = entry->FindList(kEpochsField);
      if (!keys || !epochs || !DecodeB64Array(*keys, &anchor.keys) ||
          !DecodeB64Array(*epochs, &anchor.epochs)) {
        return false;
      }
      anchors.insert_or_assign(std::move(origin), std::move(anchor));
    }
  }

  if (const base::DictValue* moderators_dict =
          root.FindDict(kModeratorsField)) {
    for (const auto [raw_origin, value] : *moderators_dict) {
      std::string origin = CanonicalOrigin(raw_origin);
      const base::DictValue* entry = value.GetIfDict();
      if (origin.empty() || !entry) {
        return false;
      }
      const base::ListValue* policies = entry->FindList(kPoliciesField);
      if (!policies) {
        return false;
      }
      CommittedModerator moderator;
      for (const base::Value& policy_value : *policies) {
        const base::DictValue* policy = policy_value.GetIfDict();
        if (!policy) {
          return false;
        }
        const std::string* credential_context =
            policy->FindString(kCredentialContextField);
        const std::string* credential_key =
            policy->FindString(kCredentialKeyField);
        const base::ListValue* accepted =
            policy->FindList(kAcceptedAnchorKeysField);
        const base::ListValue* epochs = policy->FindList(kEpochsField);
        if (!credential_context || !credential_key || !accepted || !epochs) {
          return false;
        }
        CommittedPolicy committed;
        std::optional<Bytes> cc = DecodeB64(*credential_context);
        std::optional<Bytes> ck = DecodeB64(*credential_key);
        if (!cc || !ck ||
            !DecodeB64Array(*accepted, &committed.accepted_anchor_keys) ||
            !DecodeB64Array(*epochs, &committed.epochs)) {
          return false;
        }
        committed.credential_context = std::move(*cc);
        committed.credential_key = std::move(*ck);

        // `balance-width` is required and must be in `1..=64` (`draft-schlesinger-mole-ec-act-00`).
        std::optional<int> balance_width = policy->FindInt(kBalanceWidthField);
        if (!balance_width || *balance_width < 1 || *balance_width > 64) {
          return false;
        }
        committed.balance_width = static_cast<uint8_t>(*balance_width);

        // `initial-balance` and `spend-amount` are required and non-negative;
        // `max-top-up` defaults to 0.
        std::optional<int> initial_balance =
            policy->FindInt(kInitialBalanceField);
        std::optional<int> spend_amount = policy->FindInt(kSpendAmountField);
        std::optional<int> max_top_up = policy->FindInt(kMaxTopUpField);
        if (!initial_balance || *initial_balance < 0 || !spend_amount ||
            *spend_amount < 0 || (max_top_up && *max_top_up < 0)) {
          return false;
        }
        committed.initial_balance = static_cast<uint64_t>(*initial_balance);
        committed.spend_amount = static_cast<uint64_t>(*spend_amount);
        committed.max_top_up = static_cast<uint64_t>(max_top_up.value_or(0));

        if (const base::Value* allow_val =
                policy->Find(kAllowNoEndorsementField)) {
          if (!allow_val->is_bool()) {
            return false;
          }
          committed.allow_no_endorsement = allow_val->GetBool();
        }
        if (const base::Value* iss_uri_val = policy->Find(kIssuanceUriField)) {
          if (!iss_uri_val->is_string() ||
              !base::IsStringUTF8(iss_uri_val->GetString())) {
            return false;
          }
          committed.issuance_uri = iss_uri_val->GetString();
        }

        moderator.policies.push_back(std::move(committed));
      }
      moderators.insert_or_assign(std::move(origin), std::move(moderator));
    }
  }

  anchors_ = std::move(anchors);
  moderators_ = std::move(moderators);
  return true;
}

moderated_endorsements::AnchorCommitment
MoleCommitmentRegistry::GetAnchorCommitment(const url::Origin& origin) const {
  moderated_endorsements::AnchorCommitment out;
  out.found = false;
  auto it = anchors_.find(origin.Serialize());
  if (it == anchors_.end()) {
    return out;
  }
  out.found = true;
  out.grant_uri = rust::String(it->second.grant_uri);
  out.keys = ToBlobs(it->second.keys);
  out.epochs = ToBlobs(it->second.epochs);
  return out;
}

moderated_endorsements::ModeratorCommitment
MoleCommitmentRegistry::GetModeratorCommitment(
    const url::Origin& origin) const {
  moderated_endorsements::ModeratorCommitment out;
  out.found = false;
  auto it = moderators_.find(origin.Serialize());
  if (it == moderators_.end()) {
    return out;
  }
  out.found = true;
  for (const CommittedPolicy& policy : it->second.policies) {
    moderated_endorsements::CommittedPolicy p;
    p.credential_context = ToRustVec(policy.credential_context);
    p.credential_key = ToRustVec(policy.credential_key);
    p.balance_width = policy.balance_width;
    p.initial_balance = policy.initial_balance;
    p.spend_amount = policy.spend_amount;
    p.max_top_up = policy.max_top_up;
    p.accepted_anchor_keys = ToBlobs(policy.accepted_anchor_keys);
    p.epochs = ToBlobs(policy.epochs);
    p.allow_no_endorsement = policy.allow_no_endorsement;
    p.issuance_uri = rust::String(policy.issuance_uri);
    out.policies.push_back(std::move(p));
  }
  return out;
}

void MoleCommitmentRegistry::ClearForTesting() {
  anchors_.clear();
  moderators_.clear();
}

bool SetMoleKeyCommitments(std::string_view json) {
  return MoleCommitmentRegistry::GetInstance().ParseAndSet(json);
}

}  // namespace content
