// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/moderated_endorsements/moderated_endorsements_store.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace moderated_endorsements {

namespace {

rust::Slice<const uint8_t> AsSlice(const std::vector<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

rust::Slice<const uint8_t> AsSlice(const ZeroizingBytes& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

int64_t SaturatingAddMicros(int64_t base_us, int64_t delta_us) {
  if (delta_us <= 0) {
    return base_us;
  }
  if (base_us > std::numeric_limits<int64_t>::max() - delta_us) {
    return std::numeric_limits<int64_t>::max();
  }
  return base_us + delta_us;
}

bool ComputeHoldoutDecision(const std::array<uint8_t, 32>& seed,
                            std::string_view layer,
                            std::string_view site,
                            std::string_view mod_origin,
                            const std::vector<uint8_t>& epoch,
                            uint16_t threshold) {
  std::vector<uint8_t> buf;
  constexpr std::string_view kDst = "MOLE-HOLDOUT-v1|";
  buf.insert(buf.end(), kDst.begin(), kDst.end());
  buf.insert(buf.end(), seed.begin(), seed.end());
  buf.push_back('|');
  buf.insert(buf.end(), layer.begin(), layer.end());
  buf.push_back('|');
  buf.insert(buf.end(), site.begin(), site.end());
  buf.push_back('|');
  buf.insert(buf.end(), mod_origin.begin(), mod_origin.end());
  buf.push_back('|');
  buf.insert(buf.end(), epoch.begin(), epoch.end());

  std::array<uint8_t, 32> digest = Sha256Digest(buf);
  OPENSSL_cleanse(buf.data(), buf.size());
  const uint16_t sample =
      (static_cast<uint16_t>(digest[0]) << 8) | static_cast<uint16_t>(digest[1]);
  return sample < threshold;
}

}  // namespace

ModeratedEndorsementsStore::ModeratedEndorsementsStore(
    bool is_off_the_record,
    std::string db_file_path,
    const std::array<uint8_t, MoleAead::kKeyLength>& aead_key)
    : db_(std::make_unique<ModeratedEndorsementsDatabase>(
          is_off_the_record,
          std::move(db_file_path),
          aead_key)) {}

ModeratedEndorsementsStore::~ModeratedEndorsementsStore() {
  Shutdown();
}

bool ModeratedEndorsementsStore::Initialize(int64_t now_us) {
  if (!db_->Initialize()) {
    return false;
  }
  auto loaded_seed = db_->LoadOrCreateHoldoutSeed();
  if (!loaded_seed) {
    return false;
  }
  holdout_seed_ = *loaded_seed;

  endorsements_.clear();
  credentials_.clear();
  pending_spends_.clear();
  pending_issues_.clear();
  active_issue_retries_.clear();
  settling_spend_ids_.clear();
  settle_retry_counts_.clear();
  pre_wire_backups_.clear();
  site_moderator_associations_.clear();
  site_bootstrap_budgets_.clear();

  // 1. Load `pending_issues` to distinguish pre-wire crashes from post-wire
  //    5-minute idempotency retry candidates.
  std::map<int64_t, bool> retryable_endorsement_ids;
  std::map<int64_t, bool> unwired_issue_endorsement_ids;
  for (PendingIssueRecord& issue : db_->LoadAllPendingIssues()) {
    if (!issue.wire_bytes_sent) {
      unwired_issue_endorsement_ids[issue.endorsement_id] = true;
      db_->DeletePendingIssue(issue.id);
      continue;
    }
    if (issue.expires_at_us <= now_us) {
      db_->DeletePendingIssue(issue.id);
      if (issue.endorsement_id > 0) {
        db_->DeleteEndorsement(issue.endorsement_id);
      }
      continue;
    }
    if (issue.endorsement_id > 0) {
      retryable_endorsement_ids[issue.endorsement_id] = true;
    }
    pending_issues_.emplace(issue.id, std::move(issue));
  }

  // 2. Load `ec_ihat_endorsements`. Any `kReservedInFlight` row NOT backed by
  //    an unexpired `pending_issues` retry record (and not an unwired pre-send
  //    crash) is purged so deterministic EC-IHAT nullifiers are NEVER replayed!
  for (EndorsementRecord& end : db_->LoadAllEndorsements()) {
    if (end.state == EndorsementRowState::kReservedInFlight) {
      if (unwired_issue_endorsement_ids.contains(end.id)) {
        end.state = EndorsementRowState::kAvailable;
        db_->UpdateEndorsementState(end.id, EndorsementRowState::kAvailable);
      } else if (!retryable_endorsement_ids.contains(end.id)) {
        db_->DeleteEndorsement(end.id);
        continue;
      }
    }
    endorsements_.emplace(end.id, std::move(end));
  }

  // 3. Load `ec_act_credentials`.
  for (CredentialRecord& cred : db_->LoadAllCredentials()) {
    if (cred.state == CredentialRowState::kReservedInFlight ||
        cred.presentations_used >= kMaxPresentationsPerCredential) {
      db_->DeleteCredential(cred.id);
      continue;
    }
    credentials_.emplace(cred.id, std::move(cred));
  }

  // 4. Load `pending_spends`. Any `kInFlight` spend interrupted by a browser
  //    crash transitions immediately to `kNeedsRecovery`.
  for (PendingSpendRecord& sp : db_->LoadAllPendingSpends()) {
    if (sp.status == PendingSpendRowStatus::kInFlight) {
      sp.status = PendingSpendRowStatus::kNeedsRecovery;
      db_->UpdatePendingSpendStatus(sp.id, PendingSpendRowStatus::kNeedsRecovery,
                                    sp.hold_until_us, sp.session_handle);
    }
    pending_spends_.emplace(sp.id, std::move(sp));
  }

  // 5. Load rate-limit tables & prune >30d Moderator associations.
  const int64_t assoc_cutoff = now_us - kModeratorAssociationWindowUs;
  db_->DeleteSiteModeratorAssociationsBefore(assoc_cutoff);
  site_moderator_associations_ = db_->LoadAllSiteModeratorAssociations();
  for (const SiteBootstrapBudget& b : db_->LoadAllSiteBootstrapBudgets()) {
    site_bootstrap_budgets_[b.top_frame_site] = b.last_bootstrap_at_us;
  }

  return true;
}

void ModeratedEndorsementsStore::Shutdown() {
  OPENSSL_cleanse(holdout_seed_.data(), holdout_seed_.size());
  pre_wire_backups_.clear();
  active_issue_retries_.clear();
  settling_spend_ids_.clear();
  settle_retry_counts_.clear();
  db_->Close();
}

bool ModeratedEndorsementsStore::CheckAndRecordModeratorAssociation(
    std::string_view top_frame_origin,
    std::string_view moderator_origin,
    int64_t now_us) {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string mod = CanonicalHttpsOrigin(moderator_origin);
  if (site.empty() || mod.empty()) {
    return false;
  }

  const int64_t cutoff = now_us - kModeratorAssociationWindowUs;
  std::erase_if(site_moderator_associations_,
                [cutoff](const SiteModeratorAssociation& a) {
                  return a.first_associated_at_us <= cutoff;
                });
  db_->DeleteSiteModeratorAssociationsBefore(cutoff + 1);

  size_t count_for_site = 0;
  for (const SiteModeratorAssociation& a : site_moderator_associations_) {
    if (a.top_frame_site == site) {
      if (a.moderator_origin == mod) {
        return true;
      }
      ++count_for_site;
    }
  }
  if (count_for_site >= kMaxModeratorsPerSite) {
    return false;
  }

  SiteModeratorAssociation assoc{site, mod, now_us};
  site_moderator_associations_.push_back(assoc);
  db_->UpsertSiteModeratorAssociation(assoc);
  return true;
}

bool ModeratedEndorsementsStore::CheckBootstrapBudgetAvailable(
    std::string_view top_frame_origin,
    int64_t now_us) const {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  if (site.empty()) {
    return false;
  }
  auto it = site_bootstrap_budgets_.find(site);
  if (it == site_bootstrap_budgets_.end()) {
    return true;
  }
  return (now_us - it->second) >= kBootstrapCooldownUs;
}

bool ModeratedEndorsementsStore::RecordBootstrapUsed(
    std::string_view top_frame_origin,
    int64_t now_us) {
  return TryConsumeBootstrapBudget(top_frame_origin, now_us).has_value();
}

std::optional<ModeratedEndorsementsStore::BootstrapReservation>
ModeratedEndorsementsStore::TryConsumeBootstrapBudget(
    std::string_view top_frame_origin,
    int64_t now_us) {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  if (site.empty()) {
    return std::nullopt;
  }
  BootstrapReservation res;
  res.op_generation = store_generation_;
  res.top_frame_site = site;
  if (auto it = site_bootstrap_budgets_.find(site);
      it != site_bootstrap_budgets_.end()) {
    if ((now_us - it->second) < kBootstrapCooldownUs) {
      return std::nullopt;
    }
    res.had_previous = true;
    res.previous_timestamp_us = it->second;
  }
  if (!db_->UpsertSiteBootstrapBudget({site, now_us})) {
    return std::nullopt;
  }
  site_bootstrap_budgets_[site] = now_us;
  return res;
}

void ModeratedEndorsementsStore::RollbackBootstrapBudget(
    const BootstrapReservation& reservation) {
  if (reservation.op_generation != store_generation_ ||
      reservation.top_frame_site.empty()) {
    return;
  }
  if (reservation.had_previous) {
    site_bootstrap_budgets_[reservation.top_frame_site] =
        reservation.previous_timestamp_us;
    db_->UpsertSiteBootstrapBudget(
        {reservation.top_frame_site, reservation.previous_timestamp_us});
  } else {
    site_bootstrap_budgets_.erase(reservation.top_frame_site);
    db_->DeleteSiteBootstrapBudget(reservation.top_frame_site);
  }
}

bool ModeratedEndorsementsStore::ShouldHoldoutBootstrap(
    std::string_view top_frame_origin,
    std::string_view moderator_origin,
    const std::vector<uint8_t>& epoch) const {
  if (!holdouts_enabled_) {
    return false;
  }
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string mod = CanonicalHttpsOrigin(moderator_origin);
  return ComputeHoldoutDecision(holdout_seed_, "boot", site, mod, epoch,
                                kHoldoutThresholdU16);
}

bool ModeratedEndorsementsStore::ShouldHoldoutPresentation(
    std::string_view top_frame_origin,
    std::string_view moderator_origin,
    const std::vector<uint8_t>& epoch) const {
  if (!holdouts_enabled_) {
    return false;
  }
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string mod = CanonicalHttpsOrigin(moderator_origin);
  return ComputeHoldoutDecision(holdout_seed_, "pres", site, mod, epoch,
                                kHoldoutThresholdU16);
}

void ModeratedEndorsementsStore::EvictExcessEndorsementsForAnchor(
    const std::string& canon_anchor) {
  std::vector<int64_t> available_ids;
  size_t total_for_anchor = 0;
  for (const auto& [id, rec] : endorsements_) {
    if (rec.anchor_origin == canon_anchor) {
      ++total_for_anchor;
      if (rec.state == EndorsementRowState::kAvailable) {
        available_ids.push_back(id);
      }
    }
  }
  size_t idx = 0;
  while (total_for_anchor > kMaxEndorsementsPerAnchor &&
         idx < available_ids.size()) {
    const int64_t victim_id = available_ids[idx++];
    endorsements_.erase(victim_id);
    db_->DeleteEndorsement(victim_id);
    --total_for_anchor;
  }
}

size_t ModeratedEndorsementsStore::StoreGrantedEndorsements(
    uint64_t op_generation,
    std::string_view anchor_origin,
    const std::vector<uint8_t>& anchor_key,
    const std::vector<uint8_t>& issuance_epoch,
    const rust::Vec<Blob>& endorsements,
    int64_t now_us) {
  if (op_generation != store_generation_) {
    return 0;
  }
  const std::string canon_anchor = CanonicalHttpsOrigin(anchor_origin);
  if (canon_anchor.empty()) {
    return 0;
  }

  size_t stored = 0;
  for (const Blob& b : endorsements) {
    EndorsementRecord rec;
    rec.anchor_origin = canon_anchor;
    rec.anchor_key.assign(anchor_key.begin(), anchor_key.end());
    rec.issuance_epoch.assign(issuance_epoch.begin(), issuance_epoch.end());
    rec.state = EndorsementRowState::kAvailable;
    rec.created_at_us = now_us;
    std::vector<uint8_t> raw(b.bytes.begin(), b.bytes.end());
    rec.endorsement_bytes = ZeroizingBytes(std::move(raw));

    auto row_id = db_->InsertEndorsement(rec);
    if (!row_id) {
      continue;
    }
    rec.id = *row_id;
    endorsements_.emplace(rec.id, std::move(rec));
    ++stored;
  }

  EvictExcessEndorsementsForAnchor(canon_anchor);
  return stored;
}

std::optional<ModeratedEndorsementsStore::CachedIssueRetry>
ModeratedEndorsementsStore::TakePendingIssueRetry(
    std::string_view moderator_origin,
    std::string_view policy_id,
    int64_t now_us) {
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  std::vector<int64_t> expired_ids;
  std::optional<CachedIssueRetry> match;

  for (auto& [id, rec] : pending_issues_) {
    if (rec.expires_at_us <= now_us) {
      expired_ids.push_back(id);
      continue;
    }
    if (!match && rec.wire_bytes_sent && !active_issue_retries_.contains(id) &&
        rec.moderator_origin == canon_mod &&
        (policy_id.empty() || rec.policy_id == policy_id)) {
      active_issue_retries_.insert(id);
      CachedIssueRetry retry;
      retry.op_generation = store_generation_;
      retry.pending_issue_id = rec.id;
      retry.endorsement_id = rec.endorsement_id;
      retry.issue_uri = rec.issue_uri;
      retry.idempotency_key = rec.idempotency_key;
      retry.request_body = rec.request_body;
      retry.issuance_state_bundle = rec.issuance_state_bundle;
      match = std::move(retry);
    }
  }

  for (int64_t exp_id : expired_ids) {
    active_issue_retries_.erase(exp_id);
    auto it = pending_issues_.find(exp_id);
    if (it != pending_issues_.end()) {
      const int64_t end_id = it->second.endorsement_id;
      pending_issues_.erase(it);
      db_->DeletePendingIssue(exp_id);
      if (end_id > 0) {
        endorsements_.erase(end_id);
        db_->DeleteEndorsement(end_id);
      }
    }
  }

  return match;
}

std::optional<ModeratedEndorsementsStore::ReservedEndorsement>
ModeratedEndorsementsStore::ReserveEndorsementForIssue(
    const CommittedPolicy& committed_policy) {
  for (auto& [id, rec] : endorsements_) {
    if (rec.state != EndorsementRowState::kAvailable) {
      continue;
    }
    bool epoch_ok = false;
    for (const Blob& ep : committed_policy.epochs) {
      if (std::ranges::equal(rec.issuance_epoch, ep.bytes)) {
        epoch_ok = true;
        break;
      }
    }
    if (!epoch_ok) {
      continue;
    }
    bool key_ok = false;
    for (const Blob& ak : committed_policy.accepted_anchor_keys) {
      if (std::ranges::equal(rec.anchor_key, ak.bytes)) {
        key_ok = true;
        break;
      }
    }
    if (!key_ok) {
      continue;
    }

    if (!db_->UpdateEndorsementState(id,
                                     EndorsementRowState::kReservedInFlight)) {
      return std::nullopt;
    }
    rec.state = EndorsementRowState::kReservedInFlight;

    ReservedEndorsement out;
    out.op_generation = store_generation_;
    out.endorsement_id = rec.id;
    out.anchor_origin = rec.anchor_origin;
    out.anchor_key = rec.anchor_key;
    out.issuance_epoch = rec.issuance_epoch;
    out.endorsement_bytes = rec.endorsement_bytes;
    return out;
  }
  return std::nullopt;
}

std::optional<int64_t> ModeratedEndorsementsStore::RecordPendingIssueBeforeSend(
    uint64_t op_generation,
    std::string_view moderator_origin,
    std::string_view policy_id,
    int64_t endorsement_id,
    const std::vector<uint8_t>& idempotency_key,
    const std::string& issue_uri,
    const std::vector<uint8_t>& request_body,
    ZeroizingBytes issuance_state_bundle,
    int64_t now_us) {
  if (op_generation != store_generation_) {
    return std::nullopt;
  }
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  if (canon_mod.empty()) {
    return std::nullopt;
  }

  PendingIssueRecord rec;
  rec.moderator_origin = canon_mod;
  rec.policy_id = std::string(policy_id);
  rec.endorsement_id = endorsement_id;
  rec.idempotency_key = idempotency_key;
  rec.issue_uri = issue_uri;
  // Persist `wire_bytes_sent = true` BEFORE network transmission begins so any
  // abrupt OS `SIGKILL` mid-flight conservatively treats the packet as wire-sent
  // (eliminating the 100ms `UploadProgressTracker` blind window) and NEVER
  // restores a wire-spent `EC-IHAT` endorsement to `kAvailable`! Only explicit
  // provably pre-wire errors in `FailIssue(..., false, ...)` roll back.
  rec.wire_bytes_sent = true;
  rec.expires_at_us = SaturatingAddMicros(now_us, kIssueIdempotencyTtlUs);
  rec.created_at_us = now_us;
  rec.request_body = request_body;
  rec.issuance_state_bundle = std::move(issuance_state_bundle);

  auto row_id = db_->InsertPendingIssue(rec);
  if (!row_id) {
    return std::nullopt;
  }
  rec.id = *row_id;
  // Also mark in-flight so a concurrent request while the initial send is live
  // cannot claim this `PendingIssueRecord` via `TakePendingIssueRetry`!
  active_issue_retries_.insert(rec.id);
  pending_issues_.emplace(rec.id, std::move(rec));
  return *row_id;
}

void ModeratedEndorsementsStore::MarkIssueWireBytesSent(
    int64_t pending_issue_id) {
  auto it = pending_issues_.find(pending_issue_id);
  if (it != pending_issues_.end() && !it->second.wire_bytes_sent) {
    it->second.wire_bytes_sent = true;
    db_->MarkPendingIssueWireSent(pending_issue_id);
  }
}

bool ModeratedEndorsementsStore::CompleteIssue(
    uint64_t op_generation,
    int64_t endorsement_id,
    int64_t pending_issue_id,
    std::string_view moderator_origin,
    const std::vector<uint8_t>& credential_context,
    const std::vector<uint8_t>& key_id,
    uint8_t balance_width,
    uint64_t balance,
    ZeroizingBytes credential_bytes,
    int64_t now_us) {
  if (op_generation != store_generation_) {
    return false;
  }
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  if (canon_mod.empty()) {
    return false;
  }

  if (pending_issue_id > 0) {
    active_issue_retries_.erase(pending_issue_id);
    if (pending_issues_.erase(pending_issue_id) != 1u) {
      return false;
    }
    db_->DeletePendingIssue(pending_issue_id);
  }
  if (endorsement_id > 0) {
    if (pending_issue_id <= 0 && endorsements_.erase(endorsement_id) != 1u) {
      return false;
    }
    endorsements_.erase(endorsement_id);
    db_->DeleteEndorsement(endorsement_id);
  }

  CredentialRecord cred;
  cred.moderator_origin = canon_mod;
  cred.credential_context = credential_context;
  cred.key_id = key_id;
  cred.balance_width = balance_width;
  cred.balance = balance;
  cred.presentations_used = 0;
  cred.state = CredentialRowState::kAvailable;
  cred.created_at_us = now_us;
  cred.last_used_at_us = now_us;
  cred.credential_bytes = std::move(credential_bytes);

  auto row_id = db_->InsertCredential(cred);
  if (!row_id) {
    return false;
  }
  cred.id = *row_id;
  credentials_.emplace(cred.id, std::move(cred));
  return true;
}

void ModeratedEndorsementsStore::FailIssue(uint64_t op_generation,
                                           int64_t endorsement_id,
                                           int64_t pending_issue_id,
                                           bool wire_bytes_sent,
                                           bool keep_idempotency_retry) {
  if (op_generation != store_generation_) {
    return;
  }
  if (pending_issue_id > 0) {
    active_issue_retries_.erase(pending_issue_id);
  }
  if (!wire_bytes_sent) {
    if (pending_issue_id > 0) {
      pending_issues_.erase(pending_issue_id);
      db_->DeletePendingIssue(pending_issue_id);
    }
    if (endorsement_id > 0) {
      auto it = endorsements_.find(endorsement_id);
      if (it != endorsements_.end()) {
        it->second.state = EndorsementRowState::kAvailable;
        db_->UpdateEndorsementState(endorsement_id,
                                    EndorsementRowState::kAvailable);
      }
    }
    return;
  }

  if (keep_idempotency_retry && pending_issue_id > 0 &&
      pending_issues_.contains(pending_issue_id)) {
    MarkIssueWireBytesSent(pending_issue_id);
    return;
  }
  if (pending_issue_id > 0) {
    pending_issues_.erase(pending_issue_id);
    db_->DeletePendingIssue(pending_issue_id);
  }
  if (endorsement_id > 0) {
    endorsements_.erase(endorsement_id);
    db_->DeleteEndorsement(endorsement_id);
  }
}

std::optional<ModeratedEndorsementsStore::ReservedCredential>
ModeratedEndorsementsStore::ReserveCredentialForPresent(
    std::string_view top_frame_origin,
    std::string_view moderator_origin,
    const CommittedPolicy& committed_policy,
    uint64_t required_cost,
    int64_t now_us) {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  if (site.empty() || canon_mod.empty()) {
    return std::nullopt;
  }

  std::vector<int64_t> prune_ids;
  std::optional<int64_t> chosen_id;

  for (const auto& [id, cred] : credentials_) {
    if (cred.state != CredentialRowState::kAvailable ||
        cred.moderator_origin != canon_mod) {
      continue;
    }
    if (!std::ranges::equal(cred.credential_context,
                            committed_policy.credential_context)) {
      continue;
    }

    CredentialCheckOut check = check_credential_usable(
        AsSlice(cred.credential_bytes), AsSlice(cred.key_id),
        cred.balance_width, cred.presentations_used, committed_policy,
        required_cost);
    if (!check.usable) {
      if (check.prune_permanent) {
        prune_ids.push_back(id);
      }
      continue;
    }
    chosen_id = id;
    break;
  }

  for (int64_t pid : prune_ids) {
    credentials_.erase(pid);
    db_->DeleteCredential(pid);
  }

  if (!chosen_id) {
    return std::nullopt;
  }

  auto it = credentials_.find(*chosen_id);
  if (it == credentials_.end()) {
    return std::nullopt;
  }
  if (!db_->UpdateCredentialState(it->first,
                                  CredentialRowState::kReservedInFlight,
                                  now_us)) {
    return std::nullopt;
  }
  it->second.state = CredentialRowState::kReservedInFlight;
  it->second.last_used_at_us = now_us;

  const int64_t reservation_id = next_reservation_id_++;
  PreWirePresentBackup backup;
  backup.top_frame_site = site;
  backup.original_record = it->second;
  backup.original_record.state = CredentialRowState::kAvailable;
  pre_wire_backups_.emplace(reservation_id, std::move(backup));

  ReservedCredential out;
  out.op_generation = store_generation_;
  out.reservation_id = reservation_id;
  out.top_frame_site = site;
  out.moderator_origin = canon_mod;
  out.credential_context = it->second.credential_context;
  out.key_id = it->second.key_id;
  out.balance_width = it->second.balance_width;
  out.balance = it->second.balance;
  out.presentations_used = it->second.presentations_used;
  out.credential_bytes = it->second.credential_bytes;
  return out;
}

void ModeratedEndorsementsStore::ReleaseUnbuiltCredentialReservation(
    uint64_t op_generation,
    int64_t reservation_id) {
  if (op_generation != store_generation_) {
    pre_wire_backups_.erase(reservation_id);
    return;
  }
  auto b_it = pre_wire_backups_.find(reservation_id);
  if (b_it == pre_wire_backups_.end()) {
    return;
  }
  const int64_t cred_id = b_it->second.original_record.id;
  auto c_it = credentials_.find(cred_id);
  if (c_it != credentials_.end()) {
    c_it->second.state = CredentialRowState::kAvailable;
    db_->UpdateCredentialState(cred_id, CredentialRowState::kAvailable,
                               c_it->second.last_used_at_us);
  }
  pre_wire_backups_.erase(b_it);
}

std::optional<int64_t> ModeratedEndorsementsStore::RecordSpendBeforeSend(
    uint64_t op_generation,
    int64_t reservation_id,
    const std::string& settle_uri,
    bool is_split,
    const std::vector<uint8_t>& recovery_handle,
    ZeroizingBytes spend_bundle,
    int64_t now_us) {
  (void)now_us;
  if (op_generation != store_generation_) {
    pre_wire_backups_.erase(reservation_id);
    return std::nullopt;
  }
  auto b_it = pre_wire_backups_.find(reservation_id);
  if (b_it == pre_wire_backups_.end()) {
    return std::nullopt;
  }

  const CredentialRecord& orig = b_it->second.original_record;
  PendingSpendRecord sp;
  sp.top_frame_site = b_it->second.top_frame_site;
  sp.moderator_origin = orig.moderator_origin;
  sp.credential_context = orig.credential_context;
  sp.key_id = orig.key_id;
  sp.balance_width = orig.balance_width;
  sp.presentations_used = orig.presentations_used;
  sp.status = PendingSpendRowStatus::kInFlight;
  sp.hold_until_us = 0;
  sp.session_handle = std::string();
  sp.recovery_handle = recovery_handle;
  sp.settle_uri = settle_uri;
  sp.is_split = is_split;
  // Preserve original `created_at_us` across presentations so time-range
  // BrowsingDataRemover clears match either initial mint time or last use time!
  sp.created_at_us = orig.created_at_us;
  sp.spend_bundle = std::move(spend_bundle);

  // Flush `pending_spends` (`kInFlight`) to SQLite FIRST, then delete the
  // pre-spend `ec_act_credentials` row from SQLite so a crash after wire send
  // never leaves the pre-spend credential on disk!
  auto sp_id = db_->InsertPendingSpend(sp);
  if (!sp_id) {
    return std::nullopt;
  }
  db_->DeleteCredential(orig.id);
  credentials_.erase(orig.id);

  sp.id = *sp_id;
  b_it->second.pending_spend_id = *sp_id;
  pending_spends_.emplace(sp.id, std::move(sp));
  return *sp_id;
}

bool ModeratedEndorsementsStore::CompletePresentSettled(
    uint64_t op_generation,
    int64_t reservation_id,
    int64_t pending_spend_id,
    bool consumed_no_update,
    uint64_t new_balance,
    ZeroizingBytes refunded_credential_bytes,
    int64_t now_us) {
  if (op_generation != store_generation_) {
    pre_wire_backups_.erase(reservation_id);
    return false;
  }
  pre_wire_backups_.erase(reservation_id);

  auto sp_it = pending_spends_.find(pending_spend_id);
  if (sp_it == pending_spends_.end()) {
    return false;
  }
  const PendingSpendRecord sp = std::move(sp_it->second);
  pending_spends_.erase(sp_it);
  settling_spend_ids_.erase(pending_spend_id);
  settle_retry_counts_.erase(pending_spend_id);
  db_->DeletePendingSpend(pending_spend_id);

  const uint32_t next_used = sp.presentations_used + 1;
  if (consumed_no_update || refunded_credential_bytes.empty() ||
      next_used >= kMaxPresentationsPerCredential) {
    return true;
  }

  CredentialRecord refunded;
  refunded.moderator_origin = sp.moderator_origin;
  refunded.credential_context = sp.credential_context;
  refunded.key_id = sp.key_id;
  refunded.balance_width = sp.balance_width;
  refunded.balance = new_balance;
  refunded.presentations_used = next_used;
  refunded.state = CredentialRowState::kAvailable;
  refunded.created_at_us = sp.created_at_us;
  refunded.last_used_at_us = now_us;
  refunded.credential_bytes = std::move(refunded_credential_bytes);

  auto row_id = db_->InsertCredential(refunded);
  if (!row_id) {
    return false;
  }
  refunded.id = *row_id;
  credentials_.emplace(refunded.id, std::move(refunded));
  return true;
}

bool ModeratedEndorsementsStore::MarkPresentHeld(
    uint64_t op_generation,
    int64_t reservation_id,
    int64_t pending_spend_id,
    const std::string& session_handle,
    int64_t hold_until_us) {
  if (op_generation != store_generation_) {
    pre_wire_backups_.erase(reservation_id);
    return false;
  }
  pre_wire_backups_.erase(reservation_id);

  auto sp_it = pending_spends_.find(pending_spend_id);
  if (sp_it == pending_spends_.end()) {
    return false;
  }
  sp_it->second.status = PendingSpendRowStatus::kHeldForUpdate;
  sp_it->second.session_handle = session_handle;
  sp_it->second.hold_until_us = hold_until_us;
  return db_->UpdatePendingSpendStatus(pending_spend_id,
                                       PendingSpendRowStatus::kHeldForUpdate,
                                       hold_until_us, session_handle);
}

void ModeratedEndorsementsStore::FailPresent(uint64_t op_generation,
                                             int64_t reservation_id,
                                             int64_t pending_spend_id,
                                             bool wire_bytes_sent,
                                             bool keep_for_recovery) {
  if (op_generation != store_generation_) {
    pre_wire_backups_.erase(reservation_id);
    return;
  }

  if (!wire_bytes_sent) {
    if (pending_spend_id > 0) {
      pending_spends_.erase(pending_spend_id);
      settling_spend_ids_.erase(pending_spend_id);
      settle_retry_counts_.erase(pending_spend_id);
      db_->DeletePendingSpend(pending_spend_id);
    }
    auto b_it = pre_wire_backups_.find(reservation_id);
    if (b_it != pre_wire_backups_.end()) {
      CredentialRecord restored = std::move(b_it->second.original_record);
      pre_wire_backups_.erase(b_it);
      restored.state = CredentialRowState::kAvailable;
      if (auto row_id = db_->InsertCredential(restored)) {
        restored.id = *row_id;
        credentials_.emplace(restored.id, std::move(restored));
      }
    }
    return;
  }

  // `wire_bytes_sent == true`: NEVER restore the pre-spend credential!
  pre_wire_backups_.erase(reservation_id);
  auto sp_it = pending_spends_.find(pending_spend_id);
  if (sp_it == pending_spends_.end()) {
    return;
  }
  if (!keep_for_recovery) {
    pending_spends_.erase(sp_it);
    settling_spend_ids_.erase(pending_spend_id);
    settle_retry_counts_.erase(pending_spend_id);
    db_->DeletePendingSpend(pending_spend_id);
    return;
  }
  sp_it->second.status = PendingSpendRowStatus::kNeedsRecovery;
  db_->UpdatePendingSpendStatus(pending_spend_id,
                                PendingSpendRowStatus::kNeedsRecovery,
                                sp_it->second.hold_until_us,
                                sp_it->second.session_handle);
}

bool ModeratedEndorsementsStore::MarkSessionSettleReady(
    std::string_view top_frame_origin,
    std::string_view moderator_origin,
    std::string_view session_handle,
    int64_t now_us) {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  bool found = false;
  for (auto& [id, sp] : pending_spends_) {
    if (sp.top_frame_site == site && sp.moderator_origin == canon_mod &&
        (session_handle.empty() || sp.session_handle == session_handle) &&
        sp.status == PendingSpendRowStatus::kHeldForUpdate) {
      sp.hold_until_us = now_us;
      db_->UpdatePendingSpendStatus(id, sp.status, now_us, sp.session_handle);
      found = true;
    }
  }
  return found;
}

std::vector<ModeratedEndorsementsStore::ReadySettlement>
ModeratedEndorsementsStore::GetReadySettlementsForSite(
    std::string_view top_frame_origin,
    std::string_view moderator_origin,
    bool force_signoff,
    int64_t now_us) {
  std::vector<ReadySettlement> out;
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  if (site.empty() || canon_mod.empty()) {
    return out;
  }

  for (const auto& [id, sp] : pending_spends_) {
    if (sp.top_frame_site != site || sp.moderator_origin != canon_mod) {
      continue;
    }
    if (sp.status == PendingSpendRowStatus::kInFlight ||
        settling_spend_ids_.contains(id)) {
      continue;
    }
    bool ready = false;
    bool is_signoff = false;
    if (sp.status == PendingSpendRowStatus::kNeedsRecovery) {
      if (force_signoff || now_us >= sp.hold_until_us) {
        ready = true;
        is_signoff = false;
      }
    } else if (sp.status == PendingSpendRowStatus::kHeldForUpdate) {
      if (now_us >= sp.hold_until_us) {
        ready = true;
        is_signoff = false;
      } else if (force_signoff) {
        ready = true;
        is_signoff = true;
      }
    }
    if (!ready) {
      continue;
    }

    settling_spend_ids_.insert(id);
    ReadySettlement r;
    r.op_generation = store_generation_;
    r.pending_spend_id = id;
    r.top_frame_site = sp.top_frame_site;
    r.moderator_origin = sp.moderator_origin;
    r.credential_context = sp.credential_context;
    r.key_id = sp.key_id;
    r.balance_width = sp.balance_width;
    r.presentations_used = sp.presentations_used;
    r.is_signoff = is_signoff;
    r.is_split = sp.is_split;
    r.session_handle = sp.session_handle;
    r.recovery_handle = sp.recovery_handle;
    r.settle_uri = sp.settle_uri;
    r.spend_bundle = sp.spend_bundle;
    out.push_back(std::move(r));
  }
  return out;
}

std::vector<ModeratedEndorsementsStore::ReadySettlement>
ModeratedEndorsementsStore::GetSettlementsForClosingSite(
    std::string_view top_frame_origin,
    int64_t now_us) {
  std::vector<ReadySettlement> out;
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  if (site.empty()) {
    return out;
  }
  for (const auto& [id, sp] : pending_spends_) {
    if (sp.top_frame_site != site ||
        sp.status == PendingSpendRowStatus::kInFlight ||
        settling_spend_ids_.contains(id)) {
      continue;
    }
    settling_spend_ids_.insert(id);
    ReadySettlement r;
    r.op_generation = store_generation_;
    r.pending_spend_id = id;
    r.top_frame_site = sp.top_frame_site;
    r.moderator_origin = sp.moderator_origin;
    r.credential_context = sp.credential_context;
    r.key_id = sp.key_id;
    r.balance_width = sp.balance_width;
    r.presentations_used = sp.presentations_used;
    r.is_signoff = (sp.status == PendingSpendRowStatus::kHeldForUpdate &&
                    now_us < sp.hold_until_us);
    r.is_split = sp.is_split;
    r.session_handle = sp.session_handle;
    r.recovery_handle = sp.recovery_handle;
    r.settle_uri = sp.settle_uri;
    r.spend_bundle = sp.spend_bundle;
    out.push_back(std::move(r));
  }
  return out;
}

bool ModeratedEndorsementsStore::CompleteSettlement(
    uint64_t op_generation,
    int64_t pending_spend_id,
    bool keep_for_retry,
    bool credential_restored,
    uint64_t new_balance,
    ZeroizingBytes refunded_credential_bytes,
    int64_t now_us,
    uint64_t retry_after_ms) {
  if (op_generation != store_generation_) {
    return false;
  }
  settling_spend_ids_.erase(pending_spend_id);
  auto sp_it = pending_spends_.find(pending_spend_id);
  if (sp_it == pending_spends_.end()) {
    settle_retry_counts_.erase(pending_spend_id);
    return false;
  }
  if (keep_for_retry) {
    uint8_t& retries = settle_retry_counts_[pending_spend_id];
    ++retries;
    if (retries > kMaxSettlementRetries) {
      pending_spends_.erase(sp_it);
      settle_retry_counts_.erase(pending_spend_id);
      db_->DeletePendingSpend(pending_spend_id);
      return false;
    }
    const uint64_t clamped_ms = std::clamp<uint64_t>(retry_after_ms, 50, 60'000);
    const int64_t next_ready_us = SaturatingAddMicros(
        now_us,
        std::min<int64_t>(static_cast<int64_t>(clamped_ms) * 1'000,
                          kMaxSettlementRetryBackoffUs));
    sp_it->second.hold_until_us = next_ready_us;
    db_->UpdatePendingSpendStatus(pending_spend_id, sp_it->second.status,
                                  next_ready_us, sp_it->second.session_handle);
    return false;
  }

  settle_retry_counts_.erase(pending_spend_id);
  const PendingSpendRecord sp = std::move(sp_it->second);
  pending_spends_.erase(sp_it);
  db_->DeletePendingSpend(pending_spend_id);

  const uint32_t next_used = sp.presentations_used + 1;
  if (!credential_restored || refunded_credential_bytes.empty() ||
      next_used >= kMaxPresentationsPerCredential) {
    return true;
  }

  CredentialRecord refunded;
  refunded.moderator_origin = sp.moderator_origin;
  refunded.credential_context = sp.credential_context;
  refunded.key_id = sp.key_id;
  refunded.balance_width = sp.balance_width;
  refunded.balance = new_balance;
  refunded.presentations_used = next_used;
  refunded.state = CredentialRowState::kAvailable;
  refunded.created_at_us = sp.created_at_us;
  refunded.last_used_at_us = now_us;
  refunded.credential_bytes = std::move(refunded_credential_bytes);

  auto row_id = db_->InsertCredential(refunded);
  if (!row_id) {
    return false;
  }
  refunded.id = *row_id;
  credentials_.emplace(refunded.id, std::move(refunded));
  return true;
}

bool ModeratedEndorsementsStore::MatchesFilter(
    std::string_view origin_or_site,
    int64_t timestamp_us,
    const DataDeletionFilter& filter) const {
  if (timestamp_us < filter.delete_begin_us ||
      timestamp_us > filter.delete_end_us) {
    return false;
  }
  if (filter.match_all_origins) {
    return true;
  }

  const std::string canon_origin = CanonicalHttpsOrigin(origin_or_site);
  const std::string reg_domain =
      ExtractRegistrableDomainOrHost(origin_or_site);

  bool in_list = false;
  for (const std::string& o : filter.origins) {
    if (!canon_origin.empty() && CanonicalHttpsOrigin(o) == canon_origin) {
      in_list = true;
      break;
    }
  }
  if (!in_list && !reg_domain.empty()) {
    for (const std::string& d : filter.registrable_domains) {
      if (d == reg_domain) {
        in_list = true;
        break;
      }
    }
  }

  return filter.exclude_listed ? !in_list : in_list;
}

void ModeratedEndorsementsStore::DeleteData(const DataDeletionFilter& filter) {
  // Synchronously bump `store_generation_` FIRST so any in-flight async
  // grant/issue/present/settle carrying an older `op_generation` drops its
  // output instead of resurrecting deleted state!
  ++store_generation_;
  pre_wire_backups_.clear();
  active_issue_retries_.clear();
  settling_spend_ids_.clear();

  std::vector<int64_t> del_ends;
  for (const auto& [id, rec] : endorsements_) {
    if (MatchesFilter(rec.anchor_origin, rec.created_at_us, filter)) {
      del_ends.push_back(id);
    }
  }
  for (int64_t id : del_ends) {
    endorsements_.erase(id);
    db_->DeleteEndorsement(id);
  }

  std::vector<int64_t> del_creds;
  for (const auto& [id, rec] : credentials_) {
    if (MatchesFilter(rec.moderator_origin, rec.created_at_us, filter) ||
        MatchesFilter(rec.moderator_origin, rec.last_used_at_us, filter)) {
      del_creds.push_back(id);
    }
  }
  for (int64_t id : del_creds) {
    credentials_.erase(id);
    db_->DeleteCredential(id);
  }

  std::vector<int64_t> del_spends;
  for (const auto& [id, sp] : pending_spends_) {
    if (MatchesFilter(sp.top_frame_site, sp.created_at_us, filter) ||
        MatchesFilter(sp.moderator_origin, sp.created_at_us, filter)) {
      del_spends.push_back(id);
    }
  }
  for (int64_t id : del_spends) {
    pending_spends_.erase(id);
    settle_retry_counts_.erase(id);
    db_->DeletePendingSpend(id);
  }

  std::vector<int64_t> del_issues;
  for (const auto& [id, iss] : pending_issues_) {
    if (MatchesFilter(iss.moderator_origin, iss.created_at_us, filter)) {
      del_issues.push_back(id);
    }
  }
  for (int64_t id : del_issues) {
    auto it = pending_issues_.find(id);
    if (it != pending_issues_.end()) {
      const int64_t end_id = it->second.endorsement_id;
      pending_issues_.erase(it);
      db_->DeletePendingIssue(id);
      if (end_id > 0) {
        endorsements_.erase(end_id);
        db_->DeleteEndorsement(end_id);
      }
    }
  }

  // CRITICAL PRIVACY INVARIANT:
  // Site-initiated `Clear-Site-Data` (`filter.is_user_initiated == false`)
  // MUST NOT reset `site_moderator_associations` or `site_bootstrap_budget`
  // (preventing a site from cycling `Clear-Site-Data` across redirects to
  // bypass the <= 2 Moderators/30d or <= 1 bootstrap/24h caps!).
  if (!filter.is_user_initiated) {
    return;
  }

  std::vector<SiteModeratorAssociation> kept_assocs;
  for (const SiteModeratorAssociation& a : site_moderator_associations_) {
    if (MatchesFilter(a.top_frame_site, a.first_associated_at_us, filter) ||
        MatchesFilter(a.moderator_origin, a.first_associated_at_us, filter)) {
      db_->DeleteSiteModeratorAssociation(a.top_frame_site,
                                          a.moderator_origin);
    } else {
      kept_assocs.push_back(a);
    }
  }
  site_moderator_associations_ = std::move(kept_assocs);

  std::vector<std::string> del_budgets;
  for (const auto& [site, ts] : site_bootstrap_budgets_) {
    if (MatchesFilter(site, ts, filter)) {
      del_budgets.push_back(site);
    }
  }
  for (const std::string& site : del_budgets) {
    site_bootstrap_budgets_.erase(site);
    db_->DeleteSiteBootstrapBudget(site);
  }

  if (filter.match_all_origins && filter.delete_begin_us == 0 &&
      filter.delete_end_us == INT64_MAX) {
    db_->RotateHoldoutSeed(&holdout_seed_);
  }
}

void ModeratedEndorsementsStore::ClearSessionOnlyData(
    FunctionRef<bool(const std::string&)> is_session_only_domain) {
  ++store_generation_;
  pre_wire_backups_.clear();
  active_issue_retries_.clear();
  settling_spend_ids_.clear();

  auto matches_domain = [&](std::string_view origin_or_site) {
    const std::string dom = ExtractRegistrableDomainOrHost(origin_or_site);
    return !dom.empty() && is_session_only_domain(dom);
  };

  std::vector<int64_t> del_ends;
  for (const auto& [id, rec] : endorsements_) {
    if (matches_domain(rec.anchor_origin)) {
      del_ends.push_back(id);
    }
  }
  for (int64_t id : del_ends) {
    endorsements_.erase(id);
    db_->DeleteEndorsement(id);
  }

  std::vector<int64_t> del_creds;
  for (const auto& [id, rec] : credentials_) {
    if (matches_domain(rec.moderator_origin)) {
      del_creds.push_back(id);
    }
  }
  for (int64_t id : del_creds) {
    credentials_.erase(id);
    db_->DeleteCredential(id);
  }

  std::vector<int64_t> del_spends;
  for (const auto& [id, sp] : pending_spends_) {
    if (matches_domain(sp.top_frame_site) ||
        matches_domain(sp.moderator_origin)) {
      del_spends.push_back(id);
    }
  }
  for (int64_t id : del_spends) {
    pending_spends_.erase(id);
    settle_retry_counts_.erase(id);
    db_->DeletePendingSpend(id);
  }

  std::vector<int64_t> del_issues;
  for (const auto& [id, iss] : pending_issues_) {
    if (matches_domain(iss.moderator_origin)) {
      del_issues.push_back(id);
    }
  }
  for (int64_t id : del_issues) {
    auto it = pending_issues_.find(id);
    if (it != pending_issues_.end()) {
      const int64_t end_id = it->second.endorsement_id;
      pending_issues_.erase(it);
      db_->DeletePendingIssue(id);
      if (end_id > 0) {
        endorsements_.erase(end_id);
        db_->DeleteEndorsement(end_id);
      }
    }
  }

  std::vector<SiteModeratorAssociation> kept_assocs;
  for (const SiteModeratorAssociation& a : site_moderator_associations_) {
    if (matches_domain(a.top_frame_site) ||
        matches_domain(a.moderator_origin)) {
      db_->DeleteSiteModeratorAssociation(a.top_frame_site,
                                          a.moderator_origin);
    } else {
      kept_assocs.push_back(a);
    }
  }
  site_moderator_associations_ = std::move(kept_assocs);

  std::vector<std::string> del_budgets;
  for (const auto& [site, _] : site_bootstrap_budgets_) {
    if (matches_domain(site)) {
      del_budgets.push_back(site);
    }
  }
  for (const std::string& site : del_budgets) {
    site_bootstrap_budgets_.erase(site);
    db_->DeleteSiteBootstrapBudget(site);
  }
}

size_t ModeratedEndorsementsStore::AvailableEndorsementCount() const {
  size_t count = 0;
  for (const auto& [_, rec] : endorsements_) {
    if (rec.state == EndorsementRowState::kAvailable) {
      ++count;
    }
  }
  return count;
}

size_t ModeratedEndorsementsStore::AvailableEndorsementCountForAnchor(
    std::string_view anchor_origin) const {
  const std::string canon = CanonicalHttpsOrigin(anchor_origin);
  size_t count = 0;
  for (const auto& [_, rec] : endorsements_) {
    if (rec.state == EndorsementRowState::kAvailable &&
        rec.anchor_origin == canon) {
      ++count;
    }
  }
  return count;
}

size_t ModeratedEndorsementsStore::AvailableCredentialCount(
    std::string_view moderator_origin,
    const std::vector<uint8_t>& credential_context) const {
  const std::string canon = CanonicalHttpsOrigin(moderator_origin);
  size_t count = 0;
  for (const auto& [_, cred] : credentials_) {
    if (cred.state == CredentialRowState::kAvailable &&
        cred.moderator_origin == canon &&
        cred.credential_context == credential_context) {
      ++count;
    }
  }
  return count;
}

uint64_t ModeratedEndorsementsStore::TotalAvailableBalance(
    std::string_view moderator_origin,
    const std::vector<uint8_t>& credential_context) const {
  const std::string canon = CanonicalHttpsOrigin(moderator_origin);
  uint64_t sum = 0;
  for (const auto& [_, cred] : credentials_) {
    if (cred.state == CredentialRowState::kAvailable &&
        cred.moderator_origin == canon &&
        cred.credential_context == credential_context) {
      sum += cred.balance;
    }
  }
  return sum;
}

size_t ModeratedEndorsementsStore::PendingSpendCountForSite(
    std::string_view top_frame_origin,
    std::string_view moderator_origin) const {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const std::string canon_mod = CanonicalHttpsOrigin(moderator_origin);
  size_t count = 0;
  for (const auto& [_, sp] : pending_spends_) {
    if (sp.top_frame_site == site &&
        (canon_mod.empty() || sp.moderator_origin == canon_mod)) {
      ++count;
    }
  }
  return count;
}

size_t ModeratedEndorsementsStore::AssociatedModeratorCountForSite(
    std::string_view top_frame_origin,
    int64_t now_us) const {
  const std::string site = CanonicalSchemefulSite(top_frame_origin);
  const int64_t cutoff = now_us - kModeratorAssociationWindowUs;
  size_t count = 0;
  for (const SiteModeratorAssociation& a : site_moderator_associations_) {
    if (a.top_frame_site == site && a.first_associated_at_us > cutoff) {
      ++count;
    }
  }
  return count;
}

}  // namespace moderated_endorsements
