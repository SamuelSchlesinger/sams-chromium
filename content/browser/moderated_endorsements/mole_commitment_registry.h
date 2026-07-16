// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_COMMITMENT_REGISTRY_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_COMMITMENT_REGISTRY_H_

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

// The MoLE key-commitment registry: the per-origin committed parameters the
// browser will accept from Anchors and Moderators. Modeled on Private State
// Tokens' key commitments (services/network/trust_tokens): the registry is a
// component-updater component delivered as one signed blob, identical for every
// browser, so a server cannot present different keys/epochs/policies to
// different users (the split-view attack that would otherwise reopen the
// cross-site tracking channels).
//
// Unlike PST — whose token traffic lives in the network service — MoLE's
// exchanges run in the browser process (ModeratedEndorsementServiceImpl), so
// this store is a browser-process, UI-thread singleton fed directly by the
// component installer's ComponentReady callback (no Mojo hop).
//
// Enforcement is fail-closed: an origin with no entry yields a commitment whose
// `found` is false, and the Rust FFI refuses the grant/redemption.
class CONTENT_EXPORT MoleCommitmentRegistry {
 public:
  static MoleCommitmentRegistry& GetInstance();

  MoleCommitmentRegistry(const MoleCommitmentRegistry&) = delete;
  MoleCommitmentRegistry& operator=(const MoleCommitmentRegistry&) = delete;

  // Replaces the registry contents from the component's JSON (see the .cc for
  // the schema). Malformed input leaves the previous contents untouched and
  // returns false; a well-formed but empty document clears the registry.
  bool ParseAndSet(std::string_view json);

  // The committed parameters for `origin` in each role, or a commitment with
  // `found == false` when the origin is not enrolled. The returned structs are
  // exactly what the FFI's grant_begin / redeem_begin enforce against.
  moderated_endorsements::AnchorCommitment GetAnchorCommitment(
      const url::Origin& origin) const;
  moderated_endorsements::ModeratorCommitment GetModeratorCommitment(
      const url::Origin& origin) const;

  // Drops all entries (for tests, which share the process-global instance).
  void ClearForTesting();

 private:
  friend class base::NoDestructor<MoleCommitmentRegistry>;

  // Plain-C++ storage; converted to the cxx structs on lookup.
  using Bytes = std::vector<uint8_t>;
  struct CommittedAnchor {
    std::vector<Bytes> keys;
    std::vector<Bytes> epochs;
  };
  struct CommittedPolicy {
    Bytes policy_context;
    Bytes act_public_key;
    Bytes act_domain_separator;
    std::vector<Bytes> accepted_anchor_keys;
    std::vector<Bytes> epochs;
  };
  struct CommittedModerator {
    std::vector<CommittedPolicy> policies;
  };

  MoleCommitmentRegistry();
  ~MoleCommitmentRegistry();

  // Keyed by the canonical serialized origin ("https://host:port").
  base::flat_map<std::string, CommittedAnchor> anchors_;
  base::flat_map<std::string, CommittedModerator> moderators_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_COMMITMENT_REGISTRY_H_
