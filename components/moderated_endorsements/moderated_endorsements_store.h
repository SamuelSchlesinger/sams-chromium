// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_STORE_H_
#define COMPONENTS_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_STORE_H_

#include <stdint.h>

#include <array>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "components/moderated_endorsements/moderated_endorsements_database.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "components/moderated_endorsements/mole_platform.h"

namespace moderated_endorsements {

// Authoritative UI-sequence privacy & token state manager backed by write-ahead
// SQLite + BoringSSL AES-256-GCM encryption (`ModeratedEndorsementsDatabase`).
class ModeratedEndorsementsStore {
 public:
  static constexpr size_t kMaxEndorsementsPerAnchor = 64;
  static constexpr uint32_t kMaxPresentationsPerCredential = 16;
  static constexpr size_t kMaxModeratorsPerSite = 2;
  static constexpr uint8_t kMaxSettlementRetries = 2;
  static constexpr int64_t kMaxSettlementRetryBackoffUs = 60LL * 1'000'000;
  static constexpr int64_t kModeratorAssociationWindowUs =
      30LL * 24 * 60 * 60 * 1'000'000;  // 30 days
  static constexpr int64_t kBootstrapCooldownUs =
      24LL * 60 * 60 * 1'000'000;  // 24 hours
  static constexpr int64_t kIssueIdempotencyTtlUs =
      5LL * 60 * 1'000'000;  // 5 minutes
  // 3277 / 65536 = 0.050003 (~5.0% sticky holdout probability per layer).
  static constexpr uint16_t kHoldoutThresholdU16 = 3277;

  struct BootstrapReservation {
    uint64_t op_generation = 0;
    std::string top_frame_site;
    bool had_previous = false;
    int64_t previous_timestamp_us = 0;
  };

  struct DataDeletionFilter {
    bool match_all_origins = false;
    std::vector<std::string> origins;
    std::vector<std::string> registrable_domains;
    // When true, matches origins/domains NOT in `origins`/`registrable_domains`
    // (mirrors `BrowsingDataFilterBuilder::Mode::kPreserve`).
    bool exclude_listed = false;
    int64_t delete_begin_us = 0;
    int64_t delete_end_us = INT64_MAX;
    // `false` for site-initiated `Clear-Site-Data` headers (which MUST NOT
    // reset `site_moderator_associations` or `site_bootstrap_budget`);
    // `true` for user-initiated `BrowsingDataRemover`.
    bool is_user_initiated = true;
  };

  struct ReservedEndorsement {
    uint64_t op_generation = 0;
    int64_t endorsement_id = 0;
    std::string anchor_origin;
    std::vector<uint8_t> anchor_key;
    std::vector<uint8_t> issuance_epoch;
    ZeroizingBytes endorsement_bytes;
  };

  struct CachedIssueRetry {
    uint64_t op_generation = 0;
    int64_t pending_issue_id = 0;
    int64_t endorsement_id = 0;
    std::string issue_uri;
    std::vector<uint8_t> idempotency_key;
    std::vector<uint8_t> request_body;
    ZeroizingBytes issuance_state_bundle;
  };

  struct ReservedCredential {
    uint64_t op_generation = 0;
    int64_t reservation_id = 0;
    int64_t pending_spend_id = 0;
    std::string top_frame_site;
    std::string moderator_origin;
    std::vector<uint8_t> credential_context;
    std::vector<uint8_t> key_id;
    uint8_t balance_width = 8;
    uint64_t balance = 0;
    uint32_t presentations_used = 0;
    ZeroizingBytes credential_bytes;
  };

  struct ReadySettlement {
    uint64_t op_generation = 0;
    int64_t pending_spend_id = 0;
    std::string top_frame_site;
    std::string moderator_origin;
    std::vector<uint8_t> credential_context;
    std::vector<uint8_t> key_id;
    uint8_t balance_width = 8;
    uint32_t presentations_used = 0;
    bool is_signoff = false;
    bool is_split = true;
    std::string session_handle;
    std::vector<uint8_t> recovery_handle;
    std::string settle_uri;
    ZeroizingBytes spend_bundle;
  };

  ModeratedEndorsementsStore(
      bool is_off_the_record,
      std::string db_file_path,
      const std::array<uint8_t, MoleAead::kKeyLength>& aead_key);
  ~ModeratedEndorsementsStore();

  ModeratedEndorsementsStore(const ModeratedEndorsementsStore&) = delete;
  ModeratedEndorsementsStore& operator=(const ModeratedEndorsementsStore&) =
      delete;

  bool Initialize(int64_t now_us);
  void Shutdown();

  uint64_t current_generation() const { return store_generation_; }
  bool is_off_the_record() const { return db_->is_off_the_record(); }

  // --- Rate Limits & Sticky Holdouts ---

  // Enforces <= 2 distinct Moderators per top-level `SchemefulSite` (eTLD+1)
  // within a rolling 30-day window. Subdomains (`a.shoes.com`, `b.shoes.com`)
  // share one `https://shoes.com` budget.
  bool CheckAndRecordModeratorAssociation(std::string_view top_frame_origin,
                                          std::string_view moderator_origin,
                                          int64_t now_us);

  // Enforces <= 1 automatic Endorsement bootstrap per `SchemefulSite` per 24h.
  bool CheckBootstrapBudgetAvailable(std::string_view top_frame_origin,
                                     int64_t now_us) const;
  bool RecordBootstrapUsed(std::string_view top_frame_origin, int64_t now_us);
  std::optional<BootstrapReservation> TryConsumeBootstrapBudget(
      std::string_view top_frame_origin,
      int64_t now_us);
  void RollbackBootstrapBudget(const BootstrapReservation& reservation);

  // Deterministic ~5% sticky holdouts (`p_boot = 0.05`, `p_pres = 0.05`) per
  // `(profile_holdout_seed, SchemefulSite, moderator_origin, epoch)`.
  bool ShouldHoldoutBootstrap(std::string_view top_frame_origin,
                              std::string_view moderator_origin,
                              const std::vector<uint8_t>& epoch) const;
  bool ShouldHoldoutPresentation(std::string_view top_frame_origin,
                                 std::string_view moderator_origin,
                                 const std::vector<uint8_t>& epoch) const;

  void SetHoldoutsEnabledForTesting(bool enabled) {
    holdouts_enabled_ = enabled;
  }
  void SetHoldoutSeedForTesting(const std::array<uint8_t, 32>& seed) {
    holdout_seed_ = seed;
  }

  // --- Anchor Grant Persistence ---

  // Persists a completed batch of EC-IHAT endorsements iff
  // `op_generation == store_generation_`. Caps at 64 per `anchor_origin`,
  // FIFO-evicting the oldest `Available` rows.
  size_t StoreGrantedEndorsements(uint64_t op_generation,
                                  std::string_view anchor_origin,
                                  const std::vector<uint8_t>& anchor_key,
                                  const std::vector<uint8_t>& issuance_epoch,
                                  const rust::Vec<Blob>& endorsements,
                                  int64_t now_us);

  // --- Write-Ahead Endorsement Redemption (`POST /issue`) ---

  // Claims an unexpired 5-minute cached `/issue` request from a dropped
  // post-wire HTTP response for `(moderator_origin, policy_id)`. Marks the
  // entry in `active_issue_retries_` so concurrent callers never double-mint
  // duplicate `ec_act::Credential`s (`nullifier_k`).
  std::optional<CachedIssueRetry> TakePendingIssueRetry(
      std::string_view moderator_origin,
      std::string_view policy_id,
      int64_t now_us);

  // Synchronously reserves a matching `Available` Endorsement in RAM AND marks
  // it `kReservedInFlight` in SQLite before any network packet is sent.
  std::optional<ReservedEndorsement> ReserveEndorsementForIssue(
      const CommittedPolicy& committed_policy);

  // Records the built `/issue` request + zeroizing `ClientIssuanceState` in
  // SQLite BEFORE sending, conservatively persisting `wire_bytes_sent = true`
  // so any abrupt OS `SIGKILL` mid-flight recovers idempotently via
  // `pending_issues` (or purges after 5m) and NEVER restores a wire-spent
  // `EC-IHAT` endorsement to `kAvailable`.
  std::optional<int64_t> RecordPendingIssueBeforeSend(
      uint64_t op_generation,
      std::string_view moderator_origin,
      std::string_view policy_id,
      int64_t endorsement_id,
      const std::vector<uint8_t>& idempotency_key,
      const std::string& issue_uri,
      const std::vector<uint8_t>& request_body,
      ZeroizingBytes issuance_state_bundle,
      int64_t now_us);

  void MarkIssueWireBytesSent(int64_t pending_issue_id);

  // Finalizes a successful `/issue` (consumes the reserved endorsement,
  // atomically erases `pending_issues` requiring count == 1 when
  // `pending_issue_id > 0`, and stores the newly issued EC-ACT credential iff
  // `op_generation == store_generation_`).
  bool CompleteIssue(uint64_t op_generation,
                     int64_t endorsement_id,
                     int64_t pending_issue_id,
                     std::string_view moderator_origin,
                     const std::vector<uint8_t>& credential_context,
                     const std::vector<uint8_t>& key_id,
                     uint8_t balance_width,
                     uint64_t balance,
                     ZeroizingBytes credential_bytes,
                     int64_t now_us);

  // Settles a failed `/issue`:
  // - If `!wire_bytes_sent` and `op_generation == store_generation_`: releases
  //   the Endorsement back to `Available` and deletes `pending_issues`.
  // - If `wire_bytes_sent`: NEVER returns the Endorsement to `Available`; if
  //   `keep_idempotency_retry == true`, leaves `pending_issues` for 5m retry,
  //   otherwise permanently deletes both.
  void FailIssue(uint64_t op_generation,
                 int64_t endorsement_id,
                 int64_t pending_issue_id,
                 bool wire_bytes_sent,
                 bool keep_idempotency_retry);

  // --- Write-Ahead Credential Presentation (`POST /present` / Origin) ---

  // Synchronously selects a usable `Available` credential (pruning rotated
  // `key_id`s, exhausted balances, and `presentations_used >= 16` chains!) and
  // reserves it in RAM before proof generation.
  std::optional<ReservedCredential> ReserveCredentialForPresent(
      std::string_view top_frame_origin,
      std::string_view moderator_origin,
      const CommittedPolicy& committed_policy,
      uint64_t required_cost,
      int64_t now_us);

  void ReleaseUnbuiltCredentialReservation(uint64_t op_generation,
                                           int64_t reservation_id);

  // Write-ahead flush BEFORE any packet hits the wire: persists `pending_spends`
  // (`kInFlight`, including `presentations_used` and original `created_at_us`)
  // in SQLite and removes the pre-spend credential from `ec_act_credentials`
  // on disk.
  std::optional<int64_t> RecordSpendBeforeSend(
      uint64_t op_generation,
      int64_t reservation_id,
      const std::string& settle_uri,
      bool is_split,
      const std::vector<uint8_t>& recovery_handle,
      ZeroizingBytes spend_bundle,
      int64_t now_us);

  // Settles an immediate `200 OK` presentation. Increments `presentations_used`
  // and returns the refunded credential to the idle pool iff `< 16` and
  // `!consumed_no_update`, preserving original `created_at_us`.
  bool CompletePresentSettled(uint64_t op_generation,
                              int64_t reservation_id,
                              int64_t pending_spend_id,
                              bool consumed_no_update,
                              uint64_t new_balance,
                              ZeroizingBytes refunded_credential_bytes,
                              int64_t now_us);

  // Transitions an in-flight presentation to `kHeldForUpdate` partitioned
  // strictly under `(top_frame_site, moderator_origin)`.
  bool MarkPresentHeld(uint64_t op_generation,
                       int64_t reservation_id,
                       int64_t pending_spend_id,
                       const std::string& session_handle,
                       int64_t hold_until_us);

  // Settles a failed presentation using sticky `wire_bytes_sent`.
  void FailPresent(uint64_t op_generation,
                   int64_t reservation_id,
                   int64_t pending_spend_id,
                   bool wire_bytes_sent,
                   bool keep_for_recovery);

  // --- Partitioned Deferred Settlement (`POST /settle` / `signoff`) ---

  bool MarkSessionSettleReady(std::string_view top_frame_origin,
                              std::string_view moderator_origin,
                              std::string_view session_handle,
                              int64_t now_us);

  // Claims settlements strictly for `(SchemefulSite(top_frame_origin), moderator_origin)`,
  // deduplicating concurrent in-flight `/settle` requests via `settling_spend_ids_`.
  std::vector<ReadySettlement> GetReadySettlementsForSite(
      std::string_view top_frame_origin,
      std::string_view moderator_origin,
      bool force_signoff,
      int64_t now_us);

  // Claims all `HeldForUpdate` / `NeedsRecovery` spends across all Moderators
  // for `top_frame_origin` when its last frame closes (`force_signoff = true`).
  std::vector<ReadySettlement> GetSettlementsForClosingSite(
      std::string_view top_frame_origin,
      int64_t now_us);

  // Finalizes or backs off a claimed settlement (`<= 2` retries max).
  bool CompleteSettlement(uint64_t op_generation,
                          int64_t pending_spend_id,
                          bool keep_for_retry,
                          bool credential_restored,
                          uint64_t new_balance,
                          ZeroizingBytes refunded_credential_bytes,
                          int64_t now_us,
                          uint64_t retry_after_ms = 5'000);

  // --- Browsing Data Deletion & Session-Only Cleanup ---

  void DeleteData(const DataDeletionFilter& filter);

  // Invoked on profile shutdown with `DeleteCookieOnExitPredicate` taking a
  // domain/host string and returning true if session-only.
  void ClearSessionOnlyData(
      FunctionRef<bool(const std::string&)> is_session_only_domain);

  // --- Diagnostics & Inspection ---

  size_t AvailableEndorsementCount() const;
  size_t AvailableEndorsementCountForAnchor(
      std::string_view anchor_origin) const;
  size_t AvailableCredentialCount(
      std::string_view moderator_origin,
      const std::vector<uint8_t>& credential_context) const;
  uint64_t TotalAvailableBalance(
      std::string_view moderator_origin,
      const std::vector<uint8_t>& credential_context) const;
  size_t PendingSpendCountForSite(std::string_view top_frame_origin,
                                  std::string_view moderator_origin) const;
  size_t TotalPendingSpendCount() const { return pending_spends_.size(); }
  size_t AssociatedModeratorCountForSite(std::string_view top_frame_origin,
                                         int64_t now_us) const;

 private:
  struct PreWirePresentBackup {
    std::string top_frame_site;
    CredentialRecord original_record;
    int64_t pending_spend_id = 0;
  };

  void EvictExcessEndorsementsForAnchor(const std::string& canon_anchor);
  bool MatchesFilter(std::string_view origin_or_site,
                     int64_t timestamp_us,
                     const DataDeletionFilter& filter) const;

  std::unique_ptr<ModeratedEndorsementsDatabase> db_;
  uint64_t store_generation_ = 1;
  int64_t next_reservation_id_ = 1;
  bool holdouts_enabled_ = true;
  std::array<uint8_t, 32> holdout_seed_{};

  std::map<int64_t, EndorsementRecord> endorsements_;
  std::map<int64_t, CredentialRecord> credentials_;
  std::map<int64_t, PendingSpendRecord> pending_spends_;
  std::map<int64_t, PendingIssueRecord> pending_issues_;
  std::set<int64_t> active_issue_retries_;
  std::set<int64_t> settling_spend_ids_;
  std::map<int64_t, uint8_t> settle_retry_counts_;
  std::map<int64_t, PreWirePresentBackup> pre_wire_backups_;
  std::vector<SiteModeratorAssociation> site_moderator_associations_;
  std::map<std::string, int64_t> site_bootstrap_budgets_;
};

}  // namespace moderated_endorsements

#endif  // COMPONENTS_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_STORE_H_
