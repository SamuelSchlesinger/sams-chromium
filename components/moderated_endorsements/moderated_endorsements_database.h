// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_DATABASE_H_
#define COMPONENTS_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_DATABASE_H_

#include <stdint.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

#include "components/moderated_endorsements/mole_platform.h"

namespace moderated_endorsements {

enum class EndorsementRowState : int {
  kAvailable = 0,
  kReservedInFlight = 1,
};

enum class CredentialRowState : int {
  kAvailable = 0,
  kReservedInFlight = 1,
};

enum class PendingSpendRowStatus : int {
  kInFlight = 0,
  kHeldForUpdate = 1,
  kNeedsRecovery = 2,
};

struct EndorsementRecord {
  int64_t id = 0;
  std::string anchor_origin;
  std::vector<uint8_t> anchor_key;
  std::vector<uint8_t> issuance_epoch;
  EndorsementRowState state = EndorsementRowState::kAvailable;
  int64_t created_at_us = 0;
  ZeroizingBytes endorsement_bytes;
};

struct CredentialRecord {
  int64_t id = 0;
  std::string moderator_origin;
  std::vector<uint8_t> credential_context;
  std::vector<uint8_t> key_id;
  uint8_t balance_width = 8;
  uint64_t balance = 0;
  uint32_t presentations_used = 0;
  CredentialRowState state = CredentialRowState::kAvailable;
  int64_t created_at_us = 0;
  int64_t last_used_at_us = 0;
  ZeroizingBytes credential_bytes;
};

struct PendingSpendRecord {
  int64_t id = 0;
  std::string top_frame_site;
  std::string moderator_origin;
  std::vector<uint8_t> credential_context;
  std::vector<uint8_t> key_id;
  uint8_t balance_width = 8;
  uint32_t presentations_used = 0;
  PendingSpendRowStatus status = PendingSpendRowStatus::kInFlight;
  int64_t hold_until_us = 0;
  std::string session_handle;
  std::vector<uint8_t> recovery_handle;
  std::string settle_uri;
  bool is_split = true;
  int64_t created_at_us = 0;
  ZeroizingBytes spend_bundle;
};

struct PendingIssueRecord {
  int64_t id = 0;
  std::string moderator_origin;
  std::string policy_id;
  int64_t endorsement_id = 0;
  std::vector<uint8_t> idempotency_key;
  std::string issue_uri;
  bool wire_bytes_sent = false;
  int64_t expires_at_us = 0;
  int64_t created_at_us = 0;
  std::vector<uint8_t> request_body;
  ZeroizingBytes issuance_state_bundle;
};

struct SiteModeratorAssociation {
  std::string top_frame_site;
  std::string moderator_origin;
  int64_t first_associated_at_us = 0;
};

struct SiteBootstrapBudget {
  std::string top_frame_site;
  int64_t last_bootstrap_at_us = 0;
};

// SQLite + AES-256-GCM persistence layer for Moderated Endorsements.
//
// Invariants:
// - `is_off_the_record == true` opens an ephemeral `:memory:` SQLite database
//   (zero disk writes, zero parent-profile carryover).
// - Every secret payload (`endorsement_bytes`, `credential_bytes`,
//   `spend_bundle`, `issuance_state_bundle`, `holdout_seed`) is encrypted via
//   BoringSSL `EVP_aead_aes_256_gcm` with table + row-key AAD binding before
//   touching SQLite.
class ModeratedEndorsementsDatabase {
 public:
  ModeratedEndorsementsDatabase(
      bool is_off_the_record,
      std::string db_file_path,
      const std::array<uint8_t, MoleAead::kKeyLength>& aead_key);
  ~ModeratedEndorsementsDatabase();

  ModeratedEndorsementsDatabase(const ModeratedEndorsementsDatabase&) = delete;
  ModeratedEndorsementsDatabase& operator=(
      const ModeratedEndorsementsDatabase&) = delete;

  bool Initialize();
  void Close();
  bool is_off_the_record() const { return is_off_the_record_; }

  // Secret 32-byte per-profile holdout seed stored encrypted in `meta`.
  std::optional<std::array<uint8_t, 32>> LoadOrCreateHoldoutSeed();
  bool RotateHoldoutSeed(std::array<uint8_t, 32>* new_seed_out);

  // Endorsements (`ec_ihat_endorsements`)
  std::optional<int64_t> InsertEndorsement(const EndorsementRecord& record);
  bool UpdateEndorsementState(int64_t id, EndorsementRowState state);
  bool DeleteEndorsement(int64_t id);
  std::vector<EndorsementRecord> LoadAllEndorsements();

  // Credentials (`ec_act_credentials`)
  std::optional<int64_t> InsertCredential(const CredentialRecord& record);
  bool UpdateCredentialState(int64_t id,
                             CredentialRowState state,
                             int64_t last_used_at_us);
  bool DeleteCredential(int64_t id);
  std::vector<CredentialRecord> LoadAllCredentials();

  // Pending Spends (`pending_spends`)
  std::optional<int64_t> InsertPendingSpend(const PendingSpendRecord& record);
  bool UpdatePendingSpendStatus(int64_t id,
                                PendingSpendRowStatus status,
                                int64_t hold_until_us,
                                const std::string& session_handle);
  bool DeletePendingSpend(int64_t id);
  std::vector<PendingSpendRecord> LoadAllPendingSpends();

  // Pending 5m `/issue` Idempotency Records (`pending_issues`)
  std::optional<int64_t> InsertPendingIssue(const PendingIssueRecord& record);
  bool MarkPendingIssueWireSent(int64_t id);
  bool DeletePendingIssue(int64_t id);
  std::vector<PendingIssueRecord> LoadAllPendingIssues();

  // Rate-limit & Privacy Budget Tables
  bool UpsertSiteModeratorAssociation(const SiteModeratorAssociation& assoc);
  bool DeleteSiteModeratorAssociationsBefore(int64_t cutoff_us);
  bool DeleteSiteModeratorAssociation(const std::string& top_frame_site,
                                      const std::string& moderator_origin);
  std::vector<SiteModeratorAssociation> LoadAllSiteModeratorAssociations();

  bool UpsertSiteBootstrapBudget(const SiteBootstrapBudget& budget);
  bool DeleteSiteBootstrapBudget(const std::string& top_frame_site);
  std::vector<SiteBootstrapBudget> LoadAllSiteBootstrapBudgets();

 private:
  bool CreateSchema();

  const bool is_off_the_record_;
  const std::string db_file_path_;
  MoleAead aead_;
  SqlDb db_;
};

}  // namespace moderated_endorsements

#endif  // COMPONENTS_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_DATABASE_H_
