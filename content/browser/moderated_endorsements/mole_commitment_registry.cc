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
#include "base/values.h"
#include "content/public/browser/mole_key_commitments.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {

namespace {

// Dev/test override: inline registry JSON supplied on the command line, so a
// deployment without the published component (e.g. content_shell demos, tests)
// can still enroll Anchors and Moderators. Mirrors Private State Tokens'
// --additional-trust-token-key-commitments.
constexpr char kMoleKeyCommitmentsSwitch[] = "mole-key-commitments";

// Top-level sections.
constexpr char kAnchorsField[] = "anchors";
constexpr char kModeratorsField[] = "moderators";
// Anchor entry.
constexpr char kKeysField[] = "keys";
constexpr char kEpochsField[] = "epochs";
// Moderator entry.
constexpr char kPoliciesField[] = "policies";
constexpr char kPolicyContextField[] = "policy-context";
constexpr char kActPublicKeyField[] = "act-public-key";
constexpr char kActDomainSeparatorField[] = "act-domain-separator";
constexpr char kAcceptedAnchorKeysField[] = "accepted-anchor-keys";
constexpr char kChargeField[] = "charge";
constexpr char kTopupField[] = "topup";

using Bytes = std::vector<uint8_t>;

// base64url-without-padding, matching mole_core's wire encoding, into bytes.
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

// Canonical serialized origin ("https://host:port"), or empty if unsuitable.
std::string CanonicalOrigin(const std::string& raw) {
  url::Origin origin = url::Origin::Create(GURL(raw));
  if (origin.opaque()) {
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
        const std::string* policy_context =
            policy->FindString(kPolicyContextField);
        const std::string* act_public_key =
            policy->FindString(kActPublicKeyField);
        const std::string* act_domain_separator =
            policy->FindString(kActDomainSeparatorField);
        const base::ListValue* accepted =
            policy->FindList(kAcceptedAnchorKeysField);
        const base::ListValue* epochs = policy->FindList(kEpochsField);
        if (!policy_context || !act_public_key || !act_domain_separator ||
            !accepted || !epochs) {
          return false;
        }
        CommittedPolicy committed;
        std::optional<Bytes> pc = DecodeB64(*policy_context);
        std::optional<Bytes> apk = DecodeB64(*act_public_key);
        std::optional<Bytes> ads = DecodeB64(*act_domain_separator);
        if (!pc || !apk || !ads ||
            !DecodeB64Array(*accepted, &committed.accepted_anchor_keys) ||
            !DecodeB64Array(*epochs, &committed.epochs)) {
          return false;
        }
        committed.policy_context = std::move(*pc);
        committed.act_public_key = std::move(*apk);
        committed.act_domain_separator = std::move(*ads);
        // `charge` is required and must be non-negative; `topup` defaults to 0.
        std::optional<int> charge = policy->FindInt(kChargeField);
        std::optional<int> topup = policy->FindInt(kTopupField);
        if (!charge || *charge < 0 || (topup && *topup < 0)) {
          return false;
        }
        committed.charge = static_cast<uint64_t>(*charge);
        committed.topup = static_cast<uint64_t>(topup.value_or(0));
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
    p.policy_context = ToRustVec(policy.policy_context);
    p.act_public_key = ToRustVec(policy.act_public_key);
    p.act_domain_separator = ToRustVec(policy.act_domain_separator);
    p.accepted_anchor_keys = ToBlobs(policy.accepted_anchor_keys);
    p.epochs = ToBlobs(policy.epochs);
    p.charge = policy.charge;
    p.topup = policy.topup;
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
