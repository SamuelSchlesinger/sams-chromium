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
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {

namespace {

constexpr char kMoleKeyCommitmentsSwitch[] = "mole-key-commitments";

constexpr char kAnchorsField[] = "anchors";
constexpr char kModeratorsField[] = "moderators";
constexpr char kGrantUriField[] = "grant-uri";
constexpr char kKeysField[] = "keys";
constexpr char kEpochsField[] = "epochs";

constexpr char kPoliciesField[] = "policies";
constexpr char kPolicyIdField[] = "policy-id";
constexpr char kCredentialContextField[] = "credential-context";
constexpr char kCredentialKeyField[] = "credential-key";
constexpr char kClearancePublicKeyField[] = "clearance-public-key";
constexpr char kBalanceWidthField[] = "balance-width";
constexpr char kInitialBalanceField[] = "initial-balance";
constexpr char kSpendAmountField[] = "spend-amount";
constexpr char kMaxTopUpField[] = "max-top-up";
constexpr char kAllowedRefundAmountsField[] = "allowed-refund-amounts";
constexpr char kMinAnchorSetSizeField[] = "min-anchor-set-size";
constexpr char kAcceptedAnchorKeysField[] = "accepted-anchor-keys";
constexpr char kAllowedSitesField[] = "allowed-sites";
constexpr char kAllowNoEndorsementField[] = "allow-no-endorsement";
constexpr char kIssuanceUriField[] = "issuance-uri";
constexpr char kPresentUriField[] = "present-uri";
constexpr char kSettleUriField[] = "settle-uri";

using Bytes = std::vector<uint8_t>;

std::optional<Bytes> DecodeB64(const std::string& in) {
  std::string decoded;
  if (!base::Base64UrlDecode(in, base::Base64UrlDecodePolicy::DISALLOW_PADDING,
                             &decoded)) {
    return std::nullopt;
  }
  return Bytes(decoded.begin(), decoded.end());
}

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

std::string CanonicalHttpsOrigin(const std::string& raw) {
  GURL gurl(raw);
  url::Origin origin = url::Origin::Create(gurl);
  if (!gurl.is_valid() || origin.opaque() || origin.scheme() != "https" ||
      !network::IsOriginPotentiallyTrustworthy(origin)) {
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
  out.reserve(items.size());
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

  base::flat_map<std::string, StoredAnchor> anchors;
  base::flat_map<std::string, StoredModerator> moderators;

  if (const base::DictValue* anchors_dict = root.FindDict(kAnchorsField)) {
    for (const auto [raw_origin, value] : *anchors_dict) {
      std::string origin = CanonicalHttpsOrigin(raw_origin);
      const base::DictValue* entry = value.GetIfDict();
      if (origin.empty() || !entry) {
        return false;
      }
      StoredAnchor anchor;
      if (const base::Value* grant_uri_val = entry->Find(kGrantUriField)) {
        if (!grant_uri_val->is_string() ||
            !base::IsStringUTF8(grant_uri_val->GetString())) {
          return false;
        }
        anchor.grant_uri = grant_uri_val->GetString();
      }
      const base::ListValue* keys = entry->FindList(kKeysField);
      const base::ListValue* epochs = entry->FindList(kEpochsField);
      if (!keys || !epochs || keys->empty() || epochs->empty() ||
          !DecodeB64Array(*keys, &anchor.keys) ||
          !DecodeB64Array(*epochs, &anchor.epochs)) {
        return false;
      }
      anchors.insert_or_assign(std::move(origin), std::move(anchor));
    }
  }

  if (const base::DictValue* moderators_dict =
          root.FindDict(kModeratorsField)) {
    for (const auto [raw_origin, value] : *moderators_dict) {
      std::string origin = CanonicalHttpsOrigin(raw_origin);
      const base::DictValue* entry = value.GetIfDict();
      if (origin.empty() || !entry) {
        return false;
      }
      const base::ListValue* policies = entry->FindList(kPoliciesField);
      if (!policies || policies->empty()) {
        return false;
      }
      StoredModerator moderator;
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
        if (!credential_context || !credential_key || !accepted || !epochs ||
            epochs->empty()) {
          return false;
        }

        StoredPolicy committed;
        if (const std::string* policy_id = policy->FindString(kPolicyIdField)) {
          if (policy_id->empty() || !base::IsStringUTF8(*policy_id)) {
            return false;
          }
          committed.policy_id = *policy_id;
        } else {
          committed.policy_id = "default";
        }

        std::optional<Bytes> cc = DecodeB64(*credential_context);
        std::optional<Bytes> ck = DecodeB64(*credential_key);
        if (!cc || cc->empty() || cc->size() > 256 || !ck ||
            !DecodeB64Array(*accepted, &committed.accepted_anchor_keys) ||
            !DecodeB64Array(*epochs, &committed.epochs) ||
            committed.accepted_anchor_keys.size() > 64) {
          return false;
        }
        committed.credential_context = std::move(*cc);
        committed.credential_key = std::move(*ck);

        if (const base::Value* clearance_val =
                policy->Find(kClearancePublicKeyField)) {
          if (!clearance_val->is_string()) {
            return false;
          }
          std::optional<Bytes> cpk = DecodeB64(clearance_val->GetString());
          if (!cpk || (cpk->size() != 32 && cpk->size() != 33)) {
            return false;
          }
          committed.clearance_public_key = std::move(*cpk);
        }

        // Browser-enforced balance width ceiling `1..=16` (`L=8` and `L=16`).
        std::optional<int> balance_width = policy->FindInt(kBalanceWidthField);
        if (!balance_width || *balance_width < 1 || *balance_width > 16) {
          return false;
        }
        committed.balance_width = static_cast<uint8_t>(*balance_width);

        std::optional<int> initial_balance =
            policy->FindInt(kInitialBalanceField);
        std::optional<int> spend_amount = policy->FindInt(kSpendAmountField);
        std::optional<int> max_top_up = policy->FindInt(kMaxTopUpField);
        if (!initial_balance || *initial_balance < 0 || !spend_amount ||
            *spend_amount < 0 || (max_top_up && *max_top_up < 0)) {
          return false;
        }
        const uint64_t max_representable =
            (uint64_t{1} << committed.balance_width) - 1;
        const uint64_t top_up = static_cast<uint64_t>(max_top_up.value_or(0));
        if (static_cast<uint64_t>(*initial_balance) > max_representable ||
            static_cast<uint64_t>(*spend_amount) > max_representable ||
            top_up > max_representable ||
            static_cast<uint64_t>(*spend_amount) + top_up > max_representable ||
            static_cast<uint64_t>(*initial_balance) + top_up >
                max_representable) {
          return false;
        }
        committed.initial_balance = static_cast<uint64_t>(*initial_balance);
        committed.spend_amount = static_cast<uint64_t>(*spend_amount);
        committed.max_top_up = top_up;

        if (const base::Value* allow_val =
                policy->Find(kAllowNoEndorsementField)) {
          if (!allow_val->is_bool()) {
            return false;
          }
          committed.allow_no_endorsement = allow_val->GetBool();
        }

        if (const base::Value* min_anchors_val =
                policy->Find(kMinAnchorSetSizeField)) {
          if (!min_anchors_val->is_int() || min_anchors_val->GetInt() < 3 ||
              min_anchors_val->GetInt() > 64) {
            return false;
          }
          committed.min_anchor_set_size =
              static_cast<uint16_t>(min_anchors_val->GetInt());
        } else {
          committed.min_anchor_set_size = 3;
        }

        // Enforce `>= min_anchor_set_size` (>= 3) Anchors in every committed
        // Anchor Set unless the policy explicitly operates without endorsements.
        if (!committed.allow_no_endorsement &&
            committed.accepted_anchor_keys.size() <
                committed.min_anchor_set_size) {
          return false;
        }

        if (const base::Value* refunds_val =
                policy->Find(kAllowedRefundAmountsField)) {
          const base::ListValue* refunds_list = refunds_val->GetIfList();
          if (!refunds_list || refunds_list->empty()) {
            return false;
          }
          const uint64_t max_refund =
              committed.spend_amount + committed.max_top_up;
          for (const base::Value& item : *refunds_list) {
            if (!item.is_int() || item.GetInt() < 0 ||
                static_cast<uint64_t>(item.GetInt()) > max_refund) {
              return false;
            }
            committed.allowed_refund_amounts.push_back(
                static_cast<uint64_t>(item.GetInt()));
          }
        }

        if (const base::Value* sites_val = policy->Find(kAllowedSitesField)) {
          const base::ListValue* sites_list = sites_val->GetIfList();
          if (!sites_list) {
            return false;
          }
          for (const base::Value& item : *sites_list) {
            if (!item.is_string()) {
              return false;
            }
            if (item.GetString() == "*") {
              committed.allowed_sites.emplace_back("*");
              continue;
            }
            std::string site_origin = CanonicalHttpsOrigin(item.GetString());
            if (site_origin.empty()) {
              return false;
            }
            committed.allowed_sites.push_back(std::move(site_origin));
          }
        }

        auto parse_optional_uri = [&](const char* key, std::string* dst) {
          if (const base::Value* uri_val = policy->Find(key)) {
            if (!uri_val->is_string() ||
                !base::IsStringUTF8(uri_val->GetString())) {
              return false;
            }
            *dst = uri_val->GetString();
          }
          return true;
        };
        if (!parse_optional_uri(kIssuanceUriField, &committed.issuance_uri) ||
            !parse_optional_uri(kPresentUriField, &committed.present_uri) ||
            !parse_optional_uri(kSettleUriField, &committed.settle_uri)) {
          return false;
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

// static
moderated_endorsements::CommittedPolicy MoleCommitmentRegistry::ToFfiPolicy(
    const StoredPolicy& policy) {
  moderated_endorsements::CommittedPolicy p;
  p.policy_id = rust::String(policy.policy_id);
  p.credential_context = ToRustVec(policy.credential_context);
  p.credential_key = ToRustVec(policy.credential_key);
  p.clearance_public_key = ToRustVec(policy.clearance_public_key);
  p.balance_width = policy.balance_width;
  p.initial_balance = policy.initial_balance;
  p.spend_amount = policy.spend_amount;
  p.max_top_up = policy.max_top_up;
  for (uint64_t tier : policy.allowed_refund_amounts) {
    p.allowed_refund_amounts.push_back(tier);
  }
  p.min_anchor_set_size = policy.min_anchor_set_size;
  p.accepted_anchor_keys = ToBlobs(policy.accepted_anchor_keys);
  p.epochs = ToBlobs(policy.epochs);
  for (const std::string& site : policy.allowed_sites) {
    p.allowed_sites.push_back(rust::String(site));
  }
  p.allow_no_endorsement = policy.allow_no_endorsement;
  p.issuance_uri = rust::String(policy.issuance_uri);
  p.present_uri = rust::String(policy.present_uri);
  p.settle_uri = rust::String(policy.settle_uri);
  return p;
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
  for (const StoredPolicy& policy : it->second.policies) {
    out.policies.push_back(ToFfiPolicy(policy));
  }
  return out;
}

std::optional<moderated_endorsements::CommittedPolicy>
MoleCommitmentRegistry::FindCommittedPolicy(const url::Origin& moderator_origin,
                                            std::string_view policy_id) const {
  auto it = moderators_.find(moderator_origin.Serialize());
  if (it == moderators_.end() || it->second.policies.empty()) {
    return std::nullopt;
  }
  if (policy_id.empty()) {
    return ToFfiPolicy(it->second.policies.front());
  }
  for (const StoredPolicy& policy : it->second.policies) {
    if (policy.policy_id == policy_id) {
      return ToFfiPolicy(policy);
    }
  }
  return std::nullopt;
}

void MoleCommitmentRegistry::ClearForTesting() {
  anchors_.clear();
  moderators_.clear();
}

bool SetMoleKeyCommitments(std::string_view json) {
  return MoleCommitmentRegistry::GetInstance().ParseAndSet(json);
}

}  // namespace content
