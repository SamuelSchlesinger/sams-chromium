// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_COMMITMENT_REGISTRY_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_COMMITMENT_REGISTRY_H_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/containers/flat_map.h"
#include "base/no_destructor.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/common/content_export.h"

namespace url {
class Origin;
}  // namespace url

namespace content {

// Browser-process singleton holding Component-Updater-committed parameters for
// Moderated Endorsements (MOLE) Anchors and Moderators (both Split Moderation
// & Redemption and `-01` inline protocols).
//
// Enforces fail-closed anti-split-view invariants before any network packet is
// sent:
// - Anchor `keys`, `epochs`, and optional `grant-uri`.
// - Moderator `policy-id`, `credential-context`, `credential-key`,
//   `clearance-public-key` (P-256 ECDSA 33B SEC1 or Ed25519 32B),
//   `balance-width` (`1..=16`, supporting `L=8` and `L=16`),
//   `initial-balance`, `spend-amount`, `max-top-up`,
//   `allowed-refund-amounts`, `min-anchor-set-size >= 3` (with `>= 3` committed
//   `accepted-anchor-keys` unless `allow-no-endorsement` is true),
//   `allowed-sites`, and `issuance-uri` / `present-uri` / `settle-uri`.
class CONTENT_EXPORT MoleCommitmentRegistry {
 public:
  static MoleCommitmentRegistry& GetInstance();

  MoleCommitmentRegistry(const MoleCommitmentRegistry&) = delete;
  MoleCommitmentRegistry& operator=(const MoleCommitmentRegistry&) = delete;

  bool ParseAndSet(std::string_view json);

  moderated_endorsements::AnchorCommitment GetAnchorCommitment(
      const url::Origin& origin) const;
  moderated_endorsements::ModeratorCommitment GetModeratorCommitment(
      const url::Origin& origin) const;

  // Finds a committed policy for `(moderator_origin, policy_id)` (or the first
  // committed policy if `policy_id` is empty).
  std::optional<moderated_endorsements::CommittedPolicy> FindCommittedPolicy(
      const url::Origin& moderator_origin,
      std::string_view policy_id) const;

  void ClearForTesting();

 private:
  friend class base::NoDestructor<MoleCommitmentRegistry>;

  using Bytes = std::vector<uint8_t>;
  struct StoredAnchor {
    std::string grant_uri;
    std::vector<Bytes> keys;
    std::vector<Bytes> epochs;
  };
  struct StoredPolicy {
    std::string policy_id;
    Bytes credential_context;
    Bytes credential_key;
    Bytes clearance_public_key;
    uint8_t balance_width = 8;
    uint64_t initial_balance = 0;
    uint64_t spend_amount = 0;
    uint64_t max_top_up = 0;
    std::vector<uint64_t> allowed_refund_amounts;
    uint16_t min_anchor_set_size = 3;
    std::vector<Bytes> accepted_anchor_keys;
    std::vector<Bytes> epochs;
    std::vector<std::string> allowed_sites;
    bool allow_no_endorsement = false;
    std::string issuance_uri;
    std::string present_uri;
    std::string settle_uri;
  };
  struct StoredModerator {
    std::vector<StoredPolicy> policies;
  };

  static moderated_endorsements::CommittedPolicy ToFfiPolicy(
      const StoredPolicy& policy);

  MoleCommitmentRegistry();
  ~MoleCommitmentRegistry();

  base::flat_map<std::string, StoredAnchor> anchors_;
  base::flat_map<std::string, StoredModerator> moderators_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_COMMITMENT_REGISTRY_H_
