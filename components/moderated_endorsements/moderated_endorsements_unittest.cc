// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/moderated_endorsements/moderated_endorsements_store.h"

#include <stdint.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#if !defined(MOLE_STANDALONE_BUILD)
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#endif
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace moderated_endorsements {
namespace {

rust::Slice<const uint8_t> SliceOf(const std::vector<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

rust::Slice<const uint8_t> SliceOf(const rust::Vec<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

rust::Slice<const uint8_t> SliceOf(const ZeroizingBytes& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

rust::Slice<const uint64_t> SliceOfU64(const rust::Vec<uint64_t>& v) {
  return rust::Slice<const uint64_t>(v.data(), v.size());
}

std::vector<uint8_t> ToStdVec(const rust::Vec<uint8_t>& v) {
  return std::vector<uint8_t>(v.begin(), v.end());
}

ZeroizingBytes ToZeroizing(const rust::Vec<uint8_t>& v) {
  return ZeroizingBytes(std::vector<uint8_t>(v.begin(), v.end()));
}

std::vector<uint8_t> ReadRawFileBytes(const std::string& path) {
#if defined(MOLE_STANDALONE_BUILD)
  return ReadStandaloneFileBytes(path);
#else
  return base::ReadFileToBytes(base::FilePath::FromUTF8Unsafe(path))
      .value_or(std::vector<uint8_t>{});
#endif
}

bool TestPathExists(const std::string& path) {
#if defined(MOLE_STANDALONE_BUILD)
  return StandalonePathExists(path);
#else
  return base::PathExists(base::FilePath::FromUTF8Unsafe(path));
#endif
}

bool ContainsSubslice(ByteSpan haystack, ByteSpan needle) {
  if (needle.empty() || haystack.size() < needle.size()) {
    return false;
  }
  return !std::ranges::search(haystack, needle).empty();
}

struct ThreeAnchorEnvironment {
  std::vector<uint8_t> epoch = {'2', '0', '2', '6', '-', '1', '1'};
  std::vector<uint8_t> cred_ctx = {'s', 'h', 'o', 'p', '-', 'v', '1'};
  rust::Box<TestMoleAnchor> anchor1 =
      new_test_anchor("https://anchor1.example", SliceOf(epoch));
  rust::Box<TestMoleAnchor> anchor2 =
      new_test_anchor("https://anchor2.example", SliceOf(epoch));
  rust::Box<TestMoleAnchor> anchor3 =
      new_test_anchor("https://anchor3.example", SliceOf(epoch));

  rust::Vec<Blob> AcceptedKeys() const {
    rust::Vec<Blob> keys;
    keys.push_back(Blob{anchor1->anchor_public_key()});
    keys.push_back(Blob{anchor2->anchor_public_key()});
    keys.push_back(Blob{anchor3->anchor_public_key()});
    return keys;
  }

  rust::Vec<rust::String> DefaultAllowedSites() const {
    rust::Vec<rust::String> sites;
    sites.push_back("https://shoes.com");
    sites.push_back("https://socks.com");
    return sites;
  }
};

// Runs a full 2-RTT batch grant from `anchor` into `store`.
size_t RunBatchGrant(TestMoleAnchor& anchor,
                     const std::string& anchor_origin,
                     ModeratedEndorsementsStore& store,
                     uint16_t batch_count,
                     int64_t now_us) {
  const uint64_t op_gen = store.current_generation();
  AnchorCommitment com = anchor.anchor_commitment();
  std::string cfg = std::string(anchor.anchor_config_json());
  GrantBeginOut begin =
      grant_begin_batch(anchor_origin, cfg, com, batch_count);
  if (!begin.ok) {
    return 0;
  }
  TestHttpResponse r1 =
      anchor.handle_grant(std::string(begin.content_type),
                          SliceOf(begin.request_body));
  if (r1.status != 200) {
    return 0;
  }
  GrantCommitmentsOut step = grant_step_commitments(
      SliceOf(begin.anchor_key), SliceOf(begin.issuance_epoch),
      begin.requested_count, std::string(r1.content_type), SliceOf(r1.body));
  if (!step.ok) {
    return 0;
  }
  TestHttpResponse r2 =
      anchor.handle_grant(std::string(step.content_type),
                          SliceOf(step.request_body));
  if (r2.status != 200) {
    return 0;
  }
  GrantFinalizeOut fin = grant_finalize_responses(
      SliceOf(begin.anchor_key), SliceOf(begin.issuance_epoch),
      SliceOf(step.session_bundle), std::string(r2.content_type),
      SliceOf(r2.body));
  if (!fin.ok) {
    return 0;
  }
  return store.StoreGrantedEndorsements(
      op_gen, anchor_origin, ToStdVec(begin.anchor_key),
      ToStdVec(begin.issuance_epoch), fin.endorsements, now_us);
}

// Runs Split `/issue` from `store` against `moderator`.
bool RunSplitIssue(TestSplitModerator& moderator,
                   const std::string& moderator_origin,
                   ModeratedEndorsementsStore& store,
                   int64_t now_us) {
  ModeratorCommitment com = moderator.moderator_commitment();
  const CommittedPolicy& policy = com.policies[0];
  auto reserved = store.ReserveEndorsementForIssue(policy);
  if (!reserved) {
    return false;
  }
  std::vector<uint8_t> empty_override;
  SplitIssueBeginOut begin = build_split_issue_request(
      moderator_origin, std::string(moderator.moderator_config_json()), com,
      std::string(policy.policy_id), SliceOf(reserved->endorsement_bytes),
      SliceOf(reserved->anchor_key), SliceOf(reserved->issuance_epoch),
      SliceOf(empty_override));
  if (!begin.ok) {
    store.FailIssue(reserved->op_generation, reserved->endorsement_id, 0,
                    /*wire_bytes_sent=*/false, /*keep_idempotency_retry=*/false);
    return false;
  }
  auto pending_issue_id = store.RecordPendingIssueBeforeSend(
      reserved->op_generation, moderator_origin, std::string(policy.policy_id),
      reserved->endorsement_id, ToStdVec(begin.idempotency_key),
      std::string(begin.issue_uri), ToStdVec(begin.request_body),
      ToZeroizing(begin.issuance_state_bundle), now_us);
  if (!pending_issue_id) {
    return false;
  }
  store.MarkIssueWireBytesSent(*pending_issue_id);
  TestHttpResponse resp =
      moderator.handle_split_issue(SliceOf(begin.request_body));
  SplitIssueFinishOut fin = finalize_split_issue_response(
      SliceOf(begin.issuance_state_bundle), resp.status, SliceOf(resp.body),
      policy.initial_balance);
  if (!fin.ok) {
    store.FailIssue(reserved->op_generation, reserved->endorsement_id,
                    *pending_issue_id, /*wire_bytes_sent=*/true,
                    /*keep_idempotency_retry=*/false);
    return false;
  }
  return store.CompleteIssue(
      reserved->op_generation, reserved->endorsement_id, *pending_issue_id,
      moderator_origin, ToStdVec(policy.credential_context),
      ToStdVec(fin.key_id), fin.balance_width, fin.balance,
      ToZeroizing(fin.credential_bytes), now_us);
}

class ModeratedEndorsementsTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if defined(MOLE_STANDALONE_BUILD)
    test_dir_ = CreateStandaloneTempDir();
    ASSERT_FALSE(test_dir_.empty());
#else
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath().AsUTF8Unsafe();
#endif
    db_path_ = test_dir_ + "/moderated_endorsements.sqlite";
    FillRandom(aead_key_);
  }

  void TearDown() override {
#if defined(MOLE_STANDALONE_BUILD)
    RemoveStandaloneTempDir(test_dir_);
#endif
  }

#if !defined(MOLE_STANDALONE_BUILD)
  base::ScopedTempDir scoped_temp_dir_;
#endif
  std::string test_dir_;
  std::string db_path_;
  std::array<uint8_t, MoleAead::kKeyLength> aead_key_{};
};

// 1. Full Split Moderation & Redemption (`L=8` and `L=16`) + Local Origin
//    P-256 ECDSA Verification + Cross-Origin & Nonce Replay Rejection.
TEST_F(ModeratedEndorsementsTest,
       SplitEndToEndL8AndL16AndOriginReplayRejection) {
  for (uint8_t width : {uint8_t{8}, uint8_t{16}}) {
    ThreeAnchorEnvironment env;
    const uint64_t init_bal = width == 16 ? 1000 : 20;
    const uint64_t spend_amt = width == 16 ? 100 : 5;
    const uint64_t max_top = width == 16 ? 50 : 2;
    const uint64_t refund_amt = spend_amt + max_top;

    auto mod = new_test_split_moderator(
        "https://mod.example", "checkout-v1", env.AcceptedKeys(),
        SliceOf(env.epoch), SliceOf(env.cred_ctx), width, init_bal, spend_amt,
        max_top, refund_amt, env.DefaultAllowedSites());

    ModeratedEndorsementsStore store(
        /*is_off_the_record=*/false,
        db_path_ + "_" + UintToDecimalString(width), aead_key_);
    ASSERT_TRUE(store.Initialize(/*now_us=*/1'000'000));
    store.SetHoldoutsEnabledForTesting(false);

    ASSERT_EQ(4u, RunBatchGrant(*env.anchor2, "https://anchor2.example", store,
                                4, 1'000'000));
    ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
    EXPECT_EQ(init_bal,
              store.TotalAvailableBalance("https://mod.example", env.cred_ctx));

    // Origin (`shoes.com`) challenges with `Mole-Challenge`.
    std::vector<uint8_t> nonce(32, 0x42);
    std::string challenge_hdr = std::string(mod->make_origin_challenge_header(
        "https://shoes.com", spend_amt, SliceOf(nonce),
        /*include_delegation_sig=*/false));
    ModeratorCommitment mod_com = mod->moderator_commitment();
    SplitChallengeEval chal = parse_and_verify_split_challenge(
        "https://shoes.com", challenge_hdr, mod_com, mod->now_unix_secs());
    ASSERT_TRUE(chal.ok) << std::string(chal.error);

    // Reserve credential & build Split `POST /present`.
    auto cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", mod_com.policies[0],
        chal.cost, 2'000'000);
    ASSERT_TRUE(cred.has_value());

    SplitPresentBeginOut pbegin = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        mod_com.policies[0], SliceOf(cred->credential_bytes),
        "https://shoes.com", "POST", "/api/purchase", SliceOf(nonce), chal.cost,
        /*allow_deferred=*/false);
    ASSERT_TRUE(pbegin.ok) << std::string(pbegin.error);

    auto sp_id = store.RecordSpendBeforeSend(
        cred->op_generation, cred->reservation_id,
        std::string(pbegin.settle_uri), /*is_split=*/true,
        ToStdVec(pbegin.recovery_handle), ToZeroizing(pbegin.spend_bundle),
        2'000'000);
    ASSERT_TRUE(sp_id.has_value());

    TestHttpResponse pres_resp =
        mod->handle_split_present(SliceOf(pbegin.request_body));
    ASSERT_EQ(200, pres_resp.status);

    SplitPresentFinishOut pfin = finalize_split_present_response(
        SliceOf(pbegin.spend_bundle), pres_resp.status, SliceOf(pres_resp.body),
        SliceOf(mod_com.policies[0].clearance_public_key),
        "https://mod.example", "checkout-v1", "https://shoes.com", "POST",
        "/api/purchase", SliceOf(nonce), chal.cost,
        SliceOfU64(mod_com.policies[0].allowed_refund_amounts),
        /*include_grease=*/true, mod->now_unix_secs());
    ASSERT_TRUE(pfin.ok) << std::string(pfin.error);
    EXPECT_FALSE(pfin.is_held);
    EXPECT_FALSE(std::string(pfin.sec_mole_grease).empty());

    ASSERT_TRUE(store.CompletePresentSettled(
        cred->op_generation, cred->reservation_id, *sp_id,
        pfin.consumed_no_update, pfin.new_balance,
        ToZeroizing(pfin.refunded_credential_bytes), 2'000'000));
    EXPECT_EQ(init_bal - spend_amt + refund_amt,
              store.TotalAvailableBalance("https://mod.example", env.cred_ctx));

    // Origin (`shoes.com`) verifies `Sec-Mole-Authorization` locally via P-256 ECDSA!
    OriginVerifyOut ok_verify = verify_sec_mole_authorization_at_origin(
        std::string(pfin.sec_mole_authorization),
        SliceOf(mod_com.policies[0].clearance_public_key),
        "https://mod.example", "checkout-v1", "https://shoes.com", "POST",
        "/api/purchase", SliceOf(nonce), spend_amt, mod->now_unix_secs());
    EXPECT_TRUE(ok_verify.ok) << std::string(ok_verify.error);

    // Cross-origin replay to `https://socks.com` MUST fail!
    OriginVerifyOut cross_origin = verify_sec_mole_authorization_at_origin(
        std::string(pfin.sec_mole_authorization),
        SliceOf(mod_com.policies[0].clearance_public_key),
        "https://mod.example", "checkout-v1", "https://socks.com", "POST",
        "/api/purchase", SliceOf(nonce), spend_amt, mod->now_unix_secs());
    EXPECT_FALSE(cross_origin.ok);

    // Different nonce replay at `https://shoes.com` MUST fail!
    std::vector<uint8_t> other_nonce(32, 0x99);
    OriginVerifyOut wrong_nonce = verify_sec_mole_authorization_at_origin(
        std::string(pfin.sec_mole_authorization),
        SliceOf(mod_com.policies[0].clearance_public_key),
        "https://mod.example", "checkout-v1", "https://shoes.com", "POST",
        "/api/purchase", SliceOf(other_nonce), spend_amt, mod->now_unix_secs());
    EXPECT_FALSE(wrong_nonce.ok);
  }
}

// 2. Unauthorized Cross-Site Moderator Squatting Rejected Without Valid
//    Delegation Signature, and `< 3` Anchor Set Rejected.
TEST_F(ModeratedEndorsementsTest,
       RejectsUnauthorizedModeratorSquattingAndSmallAnchorSets) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();

  std::vector<uint8_t> nonce(32, 0x11);
  // `https://evil-tracker.example` is NOT in `allowed_sites` -> unsigned
  // challenge MUST be rejected!
  std::string unsigned_evil = std::string(mod->make_origin_challenge_header(
      "https://evil-tracker.example", 5, SliceOf(nonce),
      /*include_delegation_sig=*/false));
  SplitChallengeEval eval_unsigned = parse_and_verify_split_challenge(
      "https://evil-tracker.example", unsigned_evil, com, mod->now_unix_secs());
  EXPECT_FALSE(eval_unsigned.ok);

  // With a valid Moderator P-256 ECDSA delegation signature bound to
  // `https://partner.example`, challenge succeeds; replaying that signature on
  // `https://evil-tracker.example` fails!
  std::string signed_partner = std::string(mod->make_origin_challenge_header(
      "https://partner.example", 5, SliceOf(nonce),
      /*include_delegation_sig=*/true));
  SplitChallengeEval eval_partner = parse_and_verify_split_challenge(
      "https://partner.example", signed_partner, com, mod->now_unix_secs());
  EXPECT_TRUE(eval_partner.ok) << std::string(eval_partner.error);

  SplitChallengeEval eval_stolen = parse_and_verify_split_challenge(
      "https://evil-tracker.example", signed_partner, com,
      mod->now_unix_secs());
  EXPECT_FALSE(eval_stolen.ok);

  // `< 3` Anchors in Anchor Set MUST be rejected by browser policy!
  rust::Vec<Blob> only_two_anchors;
  only_two_anchors.push_back(Blob{env.anchor1->anchor_public_key()});
  only_two_anchors.push_back(Blob{env.anchor2->anchor_public_key()});
  auto weak_mod = new_test_split_moderator(
      "https://weakmod.example", "p1", only_two_anchors, SliceOf(env.epoch),
      SliceOf(env.cred_ctx), 8, 20, 5, 0, 5, env.DefaultAllowedSites());
  ModeratorCommitment weak_com = weak_mod->moderator_commitment();

  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));
  ASSERT_EQ(2u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                              2, 1'000'000));
  EXPECT_FALSE(RunSplitIssue(*weak_mod, "https://weakmod.example", store,
                             1'000'000));
  // Because validation failed before wire send, all 2 endorsements remain Available!
  EXPECT_EQ(2u, store.AvailableEndorsementCount());
}

// 3. Write-Ahead SQLite Reservation: Pre-Wire Release vs Post-Wire Crash
//    Recovery (Zero EC-IHAT Nullifier Replay + EC-ACT `/settle` Recovery).
TEST_F(ModeratedEndorsementsTest,
       WriteAheadPreWireReleaseAndPostWireCrashRecovery) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment mod_com = mod->moderator_commitment();

  // Phase A: Pre-wire failure (`!wire_bytes_sent`) on Issue AND Present
  // releases tokens back to `Available` without loss!
  {
    ModeratedEndorsementsStore store(false, db_path_, aead_key_);
    ASSERT_TRUE(store.Initialize(1'000'000));
    ASSERT_EQ(2u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                                2, 1'000'000));

    auto res_end = store.ReserveEndorsementForIssue(mod_com.policies[0]);
    ASSERT_TRUE(res_end.has_value());
    EXPECT_EQ(1u, store.AvailableEndorsementCount());
    // Simulated DNS error before wire bytes sent -> restored to 2!
    store.FailIssue(res_end->op_generation, res_end->endorsement_id, 0,
                    /*wire_bytes_sent=*/false, /*keep_idempotency_retry=*/false);
    EXPECT_EQ(2u, store.AvailableEndorsementCount());

    // Issue 1 credential (leaving 1 Available endorsement).
    ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
    EXPECT_EQ(1u, store.AvailableEndorsementCount());
    EXPECT_EQ(1u,
              store.AvailableCredentialCount("https://mod.example", env.cred_ctx));

    // Reserve credential & flush write-ahead `pending_spends`, then simulate
    // TLS failure BEFORE wire send (`wire_bytes_sent = false`) -> credential
    // restored cleanly!
    auto res_cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", mod_com.policies[0], 5,
        2'000'000);
    ASSERT_TRUE(res_cred.has_value());
    std::vector<uint8_t> nonce(32, 0x33);
    SplitPresentBeginOut pbegin = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        mod_com.policies[0], SliceOf(res_cred->credential_bytes),
        "https://shoes.com", "POST", "/api/purchase", SliceOf(nonce), 5, false);
    ASSERT_TRUE(pbegin.ok);
    auto sp_id = store.RecordSpendBeforeSend(
        res_cred->op_generation, res_cred->reservation_id,
        std::string(pbegin.settle_uri), true, ToStdVec(pbegin.recovery_handle),
        ToZeroizing(pbegin.spend_bundle), 2'000'000);
    ASSERT_TRUE(sp_id.has_value());
    EXPECT_EQ(0u,
              store.AvailableCredentialCount("https://mod.example", env.cred_ctx));

    store.FailPresent(res_cred->op_generation, res_cred->reservation_id, *sp_id,
                      /*wire_bytes_sent=*/false, /*keep_for_recovery=*/true);
    EXPECT_EQ(1u,
              store.AvailableCredentialCount("https://mod.example", env.cred_ctx));
    EXPECT_EQ(0u, store.TotalPendingSpendCount());

    // Now reserve BOTH the remaining endorsement (as if crashed mid-redeem
    // without an idempotency retry record) AND send a real `/present` to the
    // Moderator, then simulate `kill -9` (destroying `store` before processing
    // the response)!
    auto crash_end = store.ReserveEndorsementForIssue(mod_com.policies[0]);
    ASSERT_TRUE(crash_end.has_value());

    auto crash_cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", mod_com.policies[0], 5,
        3'000'000);
    ASSERT_TRUE(crash_cred.has_value());
    std::vector<uint8_t> crash_nonce(32, 0x55);
    SplitPresentBeginOut crash_pbegin = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        mod_com.policies[0], SliceOf(crash_cred->credential_bytes),
        "https://shoes.com", "POST", "/api/purchase", SliceOf(crash_nonce), 5,
        false);
    ASSERT_TRUE(crash_pbegin.ok);
    ASSERT_TRUE(store
                    .RecordSpendBeforeSend(
                        crash_cred->op_generation, crash_cred->reservation_id,
                        std::string(crash_pbegin.settle_uri), true,
                        ToStdVec(crash_pbegin.recovery_handle),
                        ToZeroizing(crash_pbegin.spend_bundle), 3'000'000)
                    .has_value());

    // Packet reaches Moderator (`200 OK`), then browser crashes before reading!
    TestHttpResponse dropped_resp =
        mod->handle_split_present(SliceOf(crash_pbegin.request_body));
    ASSERT_EQ(200, dropped_resp.status);
  }

  // Phase B: Restart browser (`ModeratedEndorsementsStore::Initialize`).
  // - `crash_end` (`RESERVED_IN_FLIGHT` without idempotency record) MUST be
  //   purged so deterministic EC-IHAT nullifiers are NEVER replayed!
  // - `crash_cred` is NOT in `ec_act_credentials`, and `pending_spends`
  //   transitioned `kInFlight -> kNeedsRecovery`, which recovers via `/settle`!
  {
    ModeratedEndorsementsStore restarted(false, db_path_, aead_key_);
    ASSERT_TRUE(restarted.Initialize(4'000'000));
    EXPECT_EQ(0u, restarted.AvailableEndorsementCount());
    EXPECT_EQ(0u, restarted.AvailableCredentialCount("https://mod.example",
                                                     env.cred_ctx));
    EXPECT_EQ(1u, restarted.PendingSpendCountForSite("https://shoes.com",
                                                     "https://mod.example"));

    auto ready = restarted.GetReadySettlementsForSite(
        "https://shoes.com", "https://mod.example", /*force_signoff=*/false,
        4'000'000);
    ASSERT_EQ(1u, ready.size());
    EXPECT_FALSE(ready[0].is_signoff);

    rust::Vec<uint8_t> settle_req = build_split_settle_request(
        ready[0].session_handle, SliceOf(ready[0].recovery_handle),
        ready[0].is_signoff);
    TestHttpResponse settle_resp =
        mod->handle_split_settle(SliceOf(settle_req));
    ASSERT_EQ(200, settle_resp.status);

    SplitSettleFinishOut sfin = finalize_split_settle_response(
        SliceOf(ready[0].spend_bundle), settle_resp.status,
        SliceOf(settle_resp.body),
        SliceOfU64(mod_com.policies[0].allowed_refund_amounts));
    ASSERT_TRUE(sfin.ok) << std::string(sfin.error);
    ASSERT_TRUE(sfin.credential_restored);

    ASSERT_TRUE(restarted.CompleteSettlement(
        ready[0].op_generation, ready[0].pending_spend_id,
        sfin.keep_spend_for_retry, sfin.credential_restored, sfin.new_balance,
        ToZeroizing(sfin.refunded_credential_bytes), 4'000'000));
    EXPECT_EQ(20u, restarted.TotalAvailableBalance("https://mod.example",
                                                   env.cred_ctx));
  }
}

// 4. Dropped `POST /issue` HTTP Response Recovered via Moderator 5-Minute
//    `(nullifier_A, idempotency_key)` Cache Without Burning Endorsement!
TEST_F(ModeratedEndorsementsTest,
       DroppedIssueResponseRecoversViaFiveMinuteIdempotencyCache) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 25, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();
  const CommittedPolicy& policy = com.policies[0];

  {
    ModeratedEndorsementsStore store(false, db_path_, aead_key_);
    ASSERT_TRUE(store.Initialize(10'000'000));
    ASSERT_EQ(1u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                                1, 10'000'000));

    auto reserved = store.ReserveEndorsementForIssue(policy);
    ASSERT_TRUE(reserved.has_value());
    std::vector<uint8_t> no_override;
    SplitIssueBeginOut begin = build_split_issue_request(
        "https://mod.example", std::string(mod->moderator_config_json()), com,
        "checkout-v1", SliceOf(reserved->endorsement_bytes),
        SliceOf(reserved->anchor_key), SliceOf(reserved->issuance_epoch),
        SliceOf(no_override));
    ASSERT_TRUE(begin.ok);

    auto p_id = store.RecordPendingIssueBeforeSend(
        reserved->op_generation, "https://mod.example", "checkout-v1",
        reserved->endorsement_id, ToStdVec(begin.idempotency_key),
        std::string(begin.issue_uri), ToStdVec(begin.request_body),
        ToZeroizing(begin.issuance_state_bundle), 10'000'000);
    ASSERT_TRUE(p_id.has_value());
    store.MarkIssueWireBytesSent(*p_id);

    // Moderator processes `/issue` and caches blind `IssueResponse`, but the
    // HTTP response drops on the wire before reaching the browser!
    TestHttpResponse dropped =
        mod->handle_split_issue(SliceOf(begin.request_body));
    ASSERT_EQ(200, dropped.status);
    EXPECT_EQ(1u, mod->consumed_endorsement_nullifiers());
    EXPECT_EQ(0u, mod->idempotency_cache_hits());

    store.FailIssue(reserved->op_generation, reserved->endorsement_id, *p_id,
                    /*wire_bytes_sent=*/true, /*keep_idempotency_retry=*/true);
  }

  // Even across a browser restart 30 seconds later, `TakePendingIssueRetry`
  // replays the exact `(nullifier_A, idempotency_key)` and recovers the 25-unit
  // EC-ACT credential with ZERO extra endorsement burned!
  {
    ModeratedEndorsementsStore restarted(false, db_path_, aead_key_);
    ASSERT_TRUE(restarted.Initialize(40'000'000));
    auto retry = restarted.TakePendingIssueRetry("https://mod.example",
                                                 "checkout-v1", 40'000'000);
    ASSERT_TRUE(retry.has_value());

    TestHttpResponse replayed =
        mod->handle_split_issue(SliceOf(retry->request_body));
    ASSERT_EQ(200, replayed.status);
    EXPECT_EQ(1u, mod->idempotency_cache_hits());
    EXPECT_EQ(1u, mod->consumed_endorsement_nullifiers());

    SplitIssueFinishOut fin = finalize_split_issue_response(
        SliceOf(retry->issuance_state_bundle), replayed.status,
        SliceOf(replayed.body), policy.initial_balance);
    ASSERT_TRUE(fin.ok) << std::string(fin.error);

    ASSERT_TRUE(restarted.CompleteIssue(
        retry->op_generation, retry->endorsement_id, retry->pending_issue_id,
        "https://mod.example", ToStdVec(policy.credential_context),
        ToStdVec(fin.key_id), fin.balance_width, fin.balance,
        ToZeroizing(fin.credential_bytes), 40'000'000));
    EXPECT_EQ(25u, restarted.TotalAvailableBalance("https://mod.example",
                                                   env.cred_ctx));
  }
}

// 5. Cross-Site `HeldForUpdate` Isolation: `shoes.com` Deferred Hold (`202`)
//    Never Leaks `signoff` to `socks.com` and Never Blocks `socks.com`;
//    `Mole-Info: settle-ready=?1` and Closing `shoes.com` Settle Cleanly.
TEST_F(ModeratedEndorsementsTest,
       CrossSiteHeldForUpdateIsolationAndTabCloseSignoff) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 5, 5,
      env.DefaultAllowedSites());
  // Enable 60-second deferred behavioral refund holds (`202 Accepted`).
  mod->set_defer_hold_ms(60'000, 300'000);
  ModeratorCommitment com = mod->moderator_commitment();

  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));
  store.SetHoldoutsEnabledForTesting(false);

  // Grant 2 endorsements & issue 2 independent credentials in the pool.
  ASSERT_EQ(2u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                              2, 1'000'000));
  ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
  ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
  EXPECT_EQ(2u,
            store.AvailableCredentialCount("https://mod.example", env.cred_ctx));

  // `shoes.com` presents Credential #1 with `allow_deferred = true` -> `202 Held`.
  auto shoes_cred = store.ReserveCredentialForPresent(
      "https://shoes.com", "https://mod.example", com.policies[0], 5,
      2'000'000);
  ASSERT_TRUE(shoes_cred.has_value());
  std::vector<uint8_t> shoes_nonce(32, 0xA1);
  SplitPresentBeginOut shoes_pbegin = build_split_present_request(
      "https://mod.example", std::string(mod->moderator_config_json()),
      com.policies[0], SliceOf(shoes_cred->credential_bytes),
      "https://shoes.com", "POST", "/api/comment", SliceOf(shoes_nonce), 5,
      /*allow_deferred=*/true);
  ASSERT_TRUE(shoes_pbegin.ok);
  auto shoes_sp_id = store.RecordSpendBeforeSend(
      shoes_cred->op_generation, shoes_cred->reservation_id,
      std::string(shoes_pbegin.settle_uri), true,
      ToStdVec(shoes_pbegin.recovery_handle),
      ToZeroizing(shoes_pbegin.spend_bundle), 2'000'000);
  ASSERT_TRUE(shoes_sp_id.has_value());

  TestHttpResponse shoes_pres =
      mod->handle_split_present(SliceOf(shoes_pbegin.request_body));
  ASSERT_EQ(202, shoes_pres.status);
  SplitPresentFinishOut shoes_pfin = finalize_split_present_response(
      SliceOf(shoes_pbegin.spend_bundle), shoes_pres.status,
      SliceOf(shoes_pres.body),
      SliceOf(com.policies[0].clearance_public_key), "https://mod.example",
      "checkout-v1", "https://shoes.com", "POST", "/api/comment",
      SliceOf(shoes_nonce), 5,
      SliceOfU64(com.policies[0].allowed_refund_amounts), false,
      mod->now_unix_secs());
  ASSERT_TRUE(shoes_pfin.ok && shoes_pfin.is_held);
  ASSERT_TRUE(store.MarkPresentHeld(
      shoes_cred->op_generation, shoes_cred->reservation_id, *shoes_sp_id,
      std::string(shoes_pfin.session_handle),
      2'000'000 + static_cast<int64_t>(shoes_pfin.min_delay_ms) * 1000));

  // CRITICAL CHECK: `socks.com` checks for settlements -> MUST see ZERO
  // settlements (NEVER sending `signoff` for `shoes.com`'s active hold!) and
  // MUST NOT block from spending Credential #2 concurrently!
  EXPECT_TRUE(store
                  .GetReadySettlementsForSite("https://socks.com",
                                              "https://mod.example",
                                              /*force_signoff=*/true, 3'000'000)
                  .empty());

  auto socks_cred = store.ReserveCredentialForPresent(
      "https://socks.com", "https://mod.example", com.policies[0], 5,
      3'000'000);
  ASSERT_TRUE(socks_cred.has_value());
  store.ReleaseUnbuiltCredentialReservation(socks_cred->op_generation,
                                            socks_cred->reservation_id);

  // Now `shoes.com` closes its last active tab before the 60s hold expires ->
  // `GetSettlementsForClosingSite("https://shoes.com")` emits `is_signoff = true`!
  auto closing = store.GetSettlementsForClosingSite("https://shoes.com",
                                                    /*now_us=*/5'000'000);
  ASSERT_EQ(1u, closing.size());
  EXPECT_TRUE(closing[0].is_signoff);

  // Origin also granted a full +5 reward (`refund = 10` = `spend_amount + max_top_up`)!
  ASSERT_TRUE(mod->record_origin_reward(closing[0].session_handle, 10));
  rust::Vec<uint8_t> settle_req = build_split_settle_request(
      closing[0].session_handle, SliceOf(closing[0].recovery_handle),
      closing[0].is_signoff);
  TestHttpResponse settle_resp = mod->handle_split_settle(SliceOf(settle_req));
  ASSERT_EQ(200, settle_resp.status);

  SplitSettleFinishOut sfin = finalize_split_settle_response(
      SliceOf(closing[0].spend_bundle), settle_resp.status,
      SliceOf(settle_resp.body),
      SliceOfU64(com.policies[0].allowed_refund_amounts));
  ASSERT_TRUE(sfin.ok && sfin.credential_restored);
  EXPECT_EQ(25u, sfin.new_balance);  // 20 - 5 + 10 = 25!

  ASSERT_TRUE(store.CompleteSettlement(
      closing[0].op_generation, closing[0].pending_spend_id,
      sfin.keep_spend_for_retry, sfin.credential_restored, sfin.new_balance,
      ToZeroizing(sfin.refunded_credential_bytes), 5'000'000));
  EXPECT_EQ(45u,
            store.TotalAvailableBalance("https://mod.example", env.cred_ctx));
}

// 6. Per-`SchemefulSite` Moderator Cap (`<= 2` per 30d Blocking Subdomain
//    Farming), 24h Bootstrap Cap (`<= 1`), & `Clear-Site-Data` Bypass Defense
//    vs User-Initiated `DeleteData` + Time-Range + `ClearSessionOnlyData`.
TEST_F(ModeratedEndorsementsTest,
       SchemefulSiteCapsClearSiteDataDefenseAndBrowsingDataDeletion) {
  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));

  // Subdomains `a.shoes.com` and `b.shoes.com` share `https://shoes.com`!
  EXPECT_TRUE(store.CheckAndRecordModeratorAssociation(
      "https://a.shoes.com", "https://mod1.example", 1'000'000));
  EXPECT_TRUE(store.CheckAndRecordModeratorAssociation(
      "https://b.shoes.com", "https://mod2.example", 2'000'000));
  // 3rd Moderator on `c.shoes.com` MUST be blocked!
  EXPECT_FALSE(store.CheckAndRecordModeratorAssociation(
      "https://c.shoes.com", "https://mod3.example", 3'000'000));
  // Re-using `mod1.example` on `c.shoes.com` is allowed.
  EXPECT_TRUE(store.CheckAndRecordModeratorAssociation(
      "https://c.shoes.com", "https://mod1.example", 3'000'000));

  // 24h Endorsement bootstrap cap per `SchemefulSite`:
  EXPECT_TRUE(store.RecordBootstrapUsed("https://a.shoes.com", 1'000'000));
  EXPECT_FALSE(
      store.CheckBootstrapBudgetAvailable("https://b.shoes.com", 2'000'000));
  EXPECT_FALSE(store.RecordBootstrapUsed("https://b.shoes.com", 2'000'000));
  // Different site (`socks.com`) has independent budget!
  EXPECT_TRUE(store.RecordBootstrapUsed("https://socks.com", 2'000'000));

  // Site-initiated `Clear-Site-Data: "cookies" | "storage"` (`is_user_initiated = false`)
  // MUST NOT reset `site_moderator_associations` or `site_bootstrap_budget`!
  ModeratedEndorsementsStore::DataDeletionFilter site_clear;
  site_clear.registrable_domains = {"shoes.com"};
  site_clear.is_user_initiated = false;
  store.DeleteData(site_clear);

  EXPECT_FALSE(store.CheckAndRecordModeratorAssociation(
      "https://shoes.com", "https://mod3.example", 4'000'000));
  EXPECT_FALSE(
      store.CheckBootstrapBudgetAvailable("https://shoes.com", 4'000'000));

  // User-initiated `DeleteData` (`is_user_initiated = true`) with a time range
  // `[1'500'000, 2'500'000]` deletes `mod2.example` (associated at `2'000'000`)
  // while keeping `mod1.example` (`1'000'000`), freeing 1 Moderator slot!
  ModeratedEndorsementsStore::DataDeletionFilter user_window_clear;
  user_window_clear.registrable_domains = {"shoes.com"};
  user_window_clear.delete_begin_us = 1'500'000;
  user_window_clear.delete_end_us = 2'500'000;
  user_window_clear.is_user_initiated = true;
  store.DeleteData(user_window_clear);

  EXPECT_EQ(1u, store.AssociatedModeratorCountForSite("https://shoes.com",
                                                      4'000'000));
  EXPECT_TRUE(store.CheckAndRecordModeratorAssociation(
      "https://shoes.com", "https://mod3.example", 4'000'000));

  // Shutdown `ClearSessionOnlyData` (`DeleteCookieOnExitPredicate`):
  store.ClearSessionOnlyData(
      [](const std::string& domain) { return domain == "shoes.com"; });
  EXPECT_EQ(0u, store.AssociatedModeratorCountForSite("https://shoes.com",
                                                      5'000'000));
  EXPECT_TRUE(
      store.CheckBootstrapBudgetAvailable("https://shoes.com", 5'000'000));
  // `socks.com` was NOT session-only -> budget still intact!
  EXPECT_FALSE(
      store.CheckBootstrapBudgetAvailable("https://socks.com", 5'000'000));
}

// 7. `store_generation_` Defeats In-Flight Async Grant / Issue / Present
//    Resurrection Across `DeleteData`!
TEST_F(ModeratedEndorsementsTest,
       StoreGenerationDefeatsInFlightResurrectionAcrossDeleteData) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();

  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));

  // Capture `stale_gen` before user clears browsing data.
  const uint64_t stale_gen = store.current_generation();

  // Start an in-flight batch grant under `stale_gen`.
  GrantBeginOut gbegin = grant_begin_batch(
      "https://anchor1.example", std::string(env.anchor1->anchor_config_json()),
      env.anchor1->anchor_commitment(), 4);
  TestHttpResponse gr1 = env.anchor1->handle_grant(
      std::string(gbegin.content_type), SliceOf(gbegin.request_body));
  GrantCommitmentsOut gstep = grant_step_commitments(
      SliceOf(gbegin.anchor_key), SliceOf(gbegin.issuance_epoch),
      gbegin.requested_count, std::string(gr1.content_type), SliceOf(gr1.body));
  TestHttpResponse gr2 = env.anchor1->handle_grant(
      std::string(gstep.content_type), SliceOf(gstep.request_body));
  GrantFinalizeOut gfin = grant_finalize_responses(
      SliceOf(gbegin.anchor_key), SliceOf(gbegin.issuance_epoch),
      SliceOf(gstep.session_bundle), std::string(gr2.content_type),
      SliceOf(gr2.body));
  ASSERT_TRUE(gfin.ok);

  // User clears all data BEFORE the async grant callback posts back!
  ModeratedEndorsementsStore::DataDeletionFilter clear_all;
  clear_all.match_all_origins = true;
  clear_all.is_user_initiated = true;
  store.DeleteData(clear_all);
  EXPECT_GT(store.current_generation(), stale_gen);

  // Stale grant completion MUST be dropped (0 endorsements resurrected!).
  EXPECT_EQ(0u, store.StoreGrantedEndorsements(
                    stale_gen, "https://anchor1.example",
                    ToStdVec(gbegin.anchor_key),
                    ToStdVec(gbegin.issuance_epoch), gfin.endorsements,
                    2'000'000));
  EXPECT_EQ(0u, store.AvailableEndorsementCount());

  // Stale `CompleteIssue` MUST ALSO be dropped!
  ZeroizingBytes dummy_cred({1, 2, 3, 4});
  EXPECT_FALSE(store.CompleteIssue(
      stale_gen, 0, 0, "https://mod.example",
      ToStdVec(com.policies[0].credential_context), std::vector<uint8_t>(32, 1),
      8, 20, std::move(dummy_cred), 2'000'000));
  EXPECT_EQ(0u,
            store.AvailableCredentialCount("https://mod.example", env.cred_ctx));
}

// 8. Sticky ~5% Dual-Layer Holdouts (`p_boot = 0.05`, `p_pres = 0.05`):
//    Deterministic Across 20 Retries & ~5% Rate Across Cohort.
TEST_F(ModeratedEndorsementsTest, StickyDualLayerHoldoutDeterminismAndRate) {
  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));
  std::vector<uint8_t> epoch = {'2', '0', '2', '6', '-', '1', '1'};

  const bool first_boot = store.ShouldHoldoutBootstrap(
      "https://shoes.com", "https://mod.example", epoch);
  const bool first_pres = store.ShouldHoldoutPresentation(
      "https://shoes.com", "https://mod.example", epoch);
  for (int retry = 0; retry < 20; ++retry) {
    // Even across different subdomains of `shoes.com`, sticky holdout MUST
    // return the exact same bit!
    EXPECT_EQ(first_boot,
              store.ShouldHoldoutBootstrap("https://sub.shoes.com",
                                           "https://mod.example", epoch));
    EXPECT_EQ(first_pres,
              store.ShouldHoldoutPresentation("https://sub.shoes.com",
                                              "https://mod.example", epoch));
  }

  size_t boot_holdouts = 0;
  size_t pres_holdouts = 0;
  constexpr size_t kTrials = 2000;
  for (size_t i = 0; i < kTrials; ++i) {
    const std::string site =
        "https://site" + UintToDecimalString(i) + ".example";
    if (store.ShouldHoldoutBootstrap(site, "https://mod.example", epoch)) {
      ++boot_holdouts;
    }
    if (store.ShouldHoldoutPresentation(site, "https://mod.example", epoch)) {
      ++pres_holdouts;
    }
  }
  // Expected = 100 (5% of 2000); wide 3.0%..7.0% band avoids any flake.
  EXPECT_GE(boot_holdouts, 60u);
  EXPECT_LE(boot_holdouts, 140u);
  EXPECT_GE(pres_holdouts, 60u);
  EXPECT_LE(pres_holdouts, 140u);
}

// 9. Key-Rotation Cohort Pruning, Initial-Balance Pinning, Refund-Tier Pinning,
//    and `kMaxPresentationsPerCredential = 16` Chain Retirement!
TEST_F(ModeratedEndorsementsTest,
       KeyRotationPruningTierPinningAndSixteenPresentationCap) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 10, 5,
      env.DefaultAllowedSites());

  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));
  store.SetHoldoutsEnabledForTesting(false);
  ASSERT_EQ(4u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                              4, 1'000'000));

  // A) Moderator attempting per-user initial-balance tagging (`19` instead of
  //    committed `20`) MUST be rejected!
  mod->set_custom_initial_balance_override(true, 19);
  EXPECT_FALSE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
  mod->set_custom_initial_balance_override(false, 20);

  // Issue valid credential under Key #1.
  ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
  EXPECT_EQ(1u,
            store.AvailableCredentialCount("https://mod.example", env.cred_ctx));

  // B) Moderator rotates its EC-ACT key and publishes new commitment ->
  //    `ReserveCredentialForPresent` MUST prune the pre-rotation credential
  //    instead of presenting its old `key_id`!
  mod->rotate_credential_key();
  ModeratorCommitment rotated_com = mod->moderator_commitment();
  EXPECT_FALSE(
      store
          .ReserveCredentialForPresent("https://shoes.com",
                                       "https://mod.example",
                                       rotated_com.policies[0], 5, 2'000'000)
          .has_value());
  EXPECT_EQ(0u,
            store.AvailableCredentialCount("https://mod.example", env.cred_ctx));

  // Issue fresh credential under rotated Key #2.
  ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 2'000'000));

  // C) Moderator attempting fine-grained refund tagging (`refund_amount = 7`,
  //    not in `{0, 5, 15}`) MUST be rejected by `finalize_split_present_response`!
  mod->set_custom_refund_amount(7);
  {
    auto cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", rotated_com.policies[0], 5,
        3'000'000);
    ASSERT_TRUE(cred.has_value());
    std::vector<uint8_t> nonce(32, 0x77);
    SplitPresentBeginOut pb = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        rotated_com.policies[0], SliceOf(cred->credential_bytes),
        "https://shoes.com", "POST", "/api/purchase", SliceOf(nonce), 5, false);
    ASSERT_TRUE(pb.ok);
    auto sp_id = store.RecordSpendBeforeSend(
        cred->op_generation, cred->reservation_id, std::string(pb.settle_uri),
        true, ToStdVec(pb.recovery_handle), ToZeroizing(pb.spend_bundle),
        3'000'000);
    TestHttpResponse r = mod->handle_split_present(SliceOf(pb.request_body));
    SplitPresentFinishOut fin = finalize_split_present_response(
        SliceOf(pb.spend_bundle), r.status, SliceOf(r.body),
        SliceOf(rotated_com.policies[0].clearance_public_key),
        "https://mod.example", "checkout-v1", "https://shoes.com", "POST",
        "/api/purchase", SliceOf(nonce), 5,
        SliceOfU64(rotated_com.policies[0].allowed_refund_amounts), false,
        mod->now_unix_secs());
    EXPECT_FALSE(fin.ok);
    store.FailPresent(cred->op_generation, cred->reservation_id, *sp_id,
                      /*wire_bytes_sent=*/true, /*keep_for_recovery=*/false);
  }

  // D) `kMaxPresentationsPerCredential = 16` chain retirement: even when
  //    refunded full `spend_amount` (`5`) every time, after 16 presentations
  //    the credential MUST automatically retire!
  mod->set_custom_refund_amount(5);
  ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 4'000'000));
  for (uint32_t step = 0; step < 16; ++step) {
    auto cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", rotated_com.policies[0], 5,
        5'000'000 + step);
    ASSERT_TRUE(cred.has_value()) << "failed at presentation " << step;
    EXPECT_EQ(step, cred->presentations_used);

    std::vector<uint8_t> nonce(32, static_cast<uint8_t>(step + 1));
    SplitPresentBeginOut pb = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        rotated_com.policies[0], SliceOf(cred->credential_bytes),
        "https://shoes.com", "POST", "/api/purchase", SliceOf(nonce), 5, false);
    ASSERT_TRUE(pb.ok);
    auto sp_id = store.RecordSpendBeforeSend(
        cred->op_generation, cred->reservation_id, std::string(pb.settle_uri),
        true, ToStdVec(pb.recovery_handle), ToZeroizing(pb.spend_bundle),
        5'000'000 + step);
    TestHttpResponse r = mod->handle_split_present(SliceOf(pb.request_body));
    SplitPresentFinishOut fin = finalize_split_present_response(
        SliceOf(pb.spend_bundle), r.status, SliceOf(r.body),
        SliceOf(rotated_com.policies[0].clearance_public_key),
        "https://mod.example", "checkout-v1", "https://shoes.com", "POST",
        "/api/purchase", SliceOf(nonce), 5,
        SliceOfU64(rotated_com.policies[0].allowed_refund_amounts), false,
        mod->now_unix_secs());
    ASSERT_TRUE(fin.ok);
    ASSERT_TRUE(store.CompletePresentSettled(
        cred->op_generation, cred->reservation_id, *sp_id,
        fin.consumed_no_update, fin.new_balance,
        ToZeroizing(fin.refunded_credential_bytes), 5'000'000 + step));
  }
  // Presentation #17 MUST see 0 pooled credentials (retired at 16)!
  EXPECT_EQ(0u,
            store.AvailableCredentialCount("https://mod.example", env.cred_ctx));
}

// 10. AES-256-GCM Encryption at Rest (Zero Plaintext Secret Bytes in Raw SQLite
//     / WAL Files + Wrong-Key Rejection) & `IsOffTheRecord()` `:memory:` Isolation!
TEST_F(ModeratedEndorsementsTest,
       Aes256GcmDiskEncryptionZeroPlaintextAndIncognitoIsolation) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();

  std::vector<uint8_t> raw_endorsement_secret;
  std::vector<uint8_t> raw_credential_secret;

  {
    ModeratedEndorsementsStore store(false, db_path_, aead_key_);
    ASSERT_TRUE(store.Initialize(1'000'000));
    ASSERT_EQ(2u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                                2, 1'000'000));

    // Peek secret bytes of one endorsement & one issued credential so we can
    // scan the raw SQLite database + WAL files on disk for any plaintext leak!
    auto res_end = store.ReserveEndorsementForIssue(com.policies[0]);
    ASSERT_TRUE(res_end.has_value());
    raw_endorsement_secret = res_end->endorsement_bytes.vec();
    store.FailIssue(res_end->op_generation, res_end->endorsement_id, 0,
                    /*wire_bytes_sent=*/false, false);

    ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));
    auto res_cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", com.policies[0], 5,
        2'000'000);
    ASSERT_TRUE(res_cred.has_value());
    raw_credential_secret = res_cred->credential_bytes.vec();
    store.ReleaseUnbuiltCredentialReservation(res_cred->op_generation,
                                              res_cred->reservation_id);
    store.Shutdown();
  }

  ASSERT_GE(raw_endorsement_secret.size(), 64u);
  ASSERT_GE(raw_credential_secret.size(), 64u);

  std::vector<uint8_t> disk_bytes = ReadRawFileBytes(db_path_);
  std::vector<uint8_t> wal_bytes = ReadRawFileBytes(db_path_ + "-wal");
  disk_bytes.insert(disk_bytes.end(), wal_bytes.begin(), wal_bytes.end());
  ASSERT_GT(disk_bytes.size(), 0u);

  // Neither the full secret nor any 32-byte scalar window of the endorsement or
  // credential may appear in plaintext anywhere in the SQLite DB or WAL!
  ByteSpan endorse_span(raw_endorsement_secret);
  ByteSpan cred_span(raw_credential_secret);
  EXPECT_FALSE(ContainsSubslice(disk_bytes, endorse_span.first<32>()));
  EXPECT_FALSE(ContainsSubslice(disk_bytes, endorse_span.subspan(32u, 32u)));
  EXPECT_FALSE(ContainsSubslice(disk_bytes, cred_span.first<32>()));
  EXPECT_FALSE(ContainsSubslice(disk_bytes, cred_span.subspan(32u, 32u)));

  // Opening the same DB with a different AEAD key rejects every tampered/unreadable
  // ciphertext and yields 0 tokens!
  {
    std::array<uint8_t, MoleAead::kKeyLength> wrong_key{};
    FillRandom(wrong_key);
    ModeratedEndorsementsStore wrong_store(false, db_path_, wrong_key);
    ASSERT_TRUE(wrong_store.Initialize(3'000'000));
    EXPECT_EQ(0u, wrong_store.AvailableEndorsementCount());
    EXPECT_EQ(0u, wrong_store.AvailableCredentialCount("https://mod.example",
                                                       env.cred_ctx));
  }

  // `IsOffTheRecord()` (`is_off_the_record = true`): opens `:memory:`, never
  // touches `otr_path` on disk, and never inherits tokens from `db_path_`!
  const std::string otr_path = test_dir_ + "/should_never_exist_otr.sqlite";
  {
    ModeratedEndorsementsStore otr_store(/*is_off_the_record=*/true, otr_path,
                                         aead_key_);
    ASSERT_TRUE(otr_store.Initialize(3'000'000));
    EXPECT_TRUE(otr_store.is_off_the_record());
    EXPECT_EQ(0u, otr_store.AvailableEndorsementCount());
    ASSERT_EQ(2u, RunBatchGrant(*env.anchor1, "https://anchor1.example",
                                otr_store, 2, 3'000'000));
    EXPECT_EQ(2u, otr_store.AvailableEndorsementCount());
    EXPECT_FALSE(TestPathExists(otr_path));
  }
  EXPECT_FALSE(TestPathExists(otr_path));
}

// 11. Mid-Flight `SIGKILL` After `RecordPendingIssueBeforeSend` Preserves
//     `wire_bytes_sent = true` (Eliminating 100ms Blind Window) AND Concurrent
//     `TakePendingIssueRetry` Deduplicates Retries & Rejects Duplicate Mint!
TEST_F(ModeratedEndorsementsTest,
       MidFlightSigkillPreservesPendingIssueAndConcurrentRetryDedupes) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 25, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();
  const CommittedPolicy& policy = com.policies[0];

  {
    ModeratedEndorsementsStore store(false, db_path_, aead_key_);
    ASSERT_TRUE(store.Initialize(10'000'000));
    ASSERT_EQ(1u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                                1, 10'000'000));

    auto reserved = store.ReserveEndorsementForIssue(policy);
    ASSERT_TRUE(reserved.has_value());
    std::vector<uint8_t> no_override;
    SplitIssueBeginOut begin = build_split_issue_request(
        "https://mod.example", std::string(mod->moderator_config_json()), com,
        "checkout-v1", SliceOf(reserved->endorsement_bytes),
        SliceOf(reserved->anchor_key), SliceOf(reserved->issuance_epoch),
        SliceOf(no_override));
    ASSERT_TRUE(begin.ok);

    auto p_id = store.RecordPendingIssueBeforeSend(
        reserved->op_generation, "https://mod.example", "checkout-v1",
        reserved->endorsement_id, ToStdVec(begin.idempotency_key),
        std::string(begin.issue_uri), ToStdVec(begin.request_body),
        ToZeroizing(begin.issuance_state_bundle), 10'000'000);
    ASSERT_TRUE(p_id.has_value());

    // While the initial send is in-flight, a concurrent caller MUST NOT claim
    // the same `PendingIssueRecord`!
    EXPECT_FALSE(store
                     .TakePendingIssueRetry("https://mod.example",
                                            "checkout-v1", 10'000'100)
                     .has_value());

    // Packet hits Moderator, then OS `SIGKILL`s Chrome at t=5ms BEFORE
    // `MarkIssueWireBytesSent` or `FailIssue` ever executes!
    TestHttpResponse sent =
        mod->handle_split_issue(SliceOf(begin.request_body));
    ASSERT_EQ(200, sent.status);
  }

  // On restart, `Initialize` MUST NOT restore the endorsement to `kAvailable`
  // (preventing deterministic `nullifier_A` replay!) and MUST expose the
  // `PendingIssueRecord` to at most ONE concurrent `TakePendingIssueRetry`!
  {
    ModeratedEndorsementsStore restarted(false, db_path_, aead_key_);
    ASSERT_TRUE(restarted.Initialize(20'000'000));
    EXPECT_EQ(0u, restarted.AvailableEndorsementCount());

    auto retry1 = restarted.TakePendingIssueRetry("https://mod.example",
                                                  "checkout-v1", 20'000'000);
    ASSERT_TRUE(retry1.has_value());
    // Concurrent caller #2 receives `nullopt` while `retry1` is in-flight!
    auto retry2 = restarted.TakePendingIssueRetry("https://mod.example",
                                                  "checkout-v1", 20'000'000);
    EXPECT_FALSE(retry2.has_value());

    TestHttpResponse replayed =
        mod->handle_split_issue(SliceOf(retry1->request_body));
    ASSERT_EQ(200, replayed.status);
    SplitIssueFinishOut fin = finalize_split_issue_response(
        SliceOf(retry1->issuance_state_bundle), replayed.status,
        SliceOf(replayed.body), policy.initial_balance);
    ASSERT_TRUE(fin.ok);

    ASSERT_TRUE(restarted.CompleteIssue(
        retry1->op_generation, retry1->endorsement_id, retry1->pending_issue_id,
        "https://mod.example", ToStdVec(policy.credential_context),
        ToStdVec(fin.key_id), fin.balance_width, fin.balance,
        ToZeroizing(fin.credential_bytes), 20'000'000));

    // A duplicate `CompleteIssue` with the same `pending_issue_id` MUST fail
    // closed (`false`) and NEVER insert a second copy of the credential!
    EXPECT_FALSE(restarted.CompleteIssue(
        retry1->op_generation, retry1->endorsement_id, retry1->pending_issue_id,
        "https://mod.example", ToStdVec(policy.credential_context),
        ToStdVec(fin.key_id), fin.balance_width, fin.balance,
        ToZeroizing(fin.credential_bytes), 20'000'000));
    EXPECT_EQ(1u, restarted.AvailableCredentialCount("https://mod.example",
                                                     env.cred_ctx));
  }
}

// 12. `presentations_used` Chain Cap (`16`) Persists on `pending_spends`
//     Across Browser Restarts, & Settlement Retries Deduplicate and Cap at 2!
TEST_F(ModeratedEndorsementsTest,
       PendingSpendPresentationsUsedPersistsAcrossRestartAndRetryCapRetires) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();

  std::string held_session;
  {
    ModeratedEndorsementsStore store(false, db_path_, aead_key_);
    ASSERT_TRUE(store.Initialize(1'000'000));
    store.SetHoldoutsEnabledForTesting(false);
    ASSERT_EQ(1u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                                1, 1'000'000));
    ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));

    // Perform 15 immediate presentations (`presentations_used` reaches 15).
    for (uint32_t step = 0; step < 15; ++step) {
      auto cred = store.ReserveCredentialForPresent(
          "https://shoes.com", "https://mod.example", com.policies[0], 5,
          2'000'000 + step);
      ASSERT_TRUE(cred.has_value());
      std::vector<uint8_t> nonce(32, static_cast<uint8_t>(step + 1));
      SplitPresentBeginOut pb = build_split_present_request(
          "https://mod.example", std::string(mod->moderator_config_json()),
          com.policies[0], SliceOf(cred->credential_bytes), "https://shoes.com",
          "POST", "/api/purchase", SliceOf(nonce), 5, false);
      ASSERT_TRUE(pb.ok);
      auto sp_id = store.RecordSpendBeforeSend(
          cred->op_generation, cred->reservation_id,
          std::string(pb.settle_uri), true, ToStdVec(pb.recovery_handle),
          ToZeroizing(pb.spend_bundle), 2'000'000 + step);
      TestHttpResponse r = mod->handle_split_present(SliceOf(pb.request_body));
      SplitPresentFinishOut fin = finalize_split_present_response(
          SliceOf(pb.spend_bundle), r.status, SliceOf(r.body),
          SliceOf(com.policies[0].clearance_public_key), "https://mod.example",
          "checkout-v1", "https://shoes.com", "POST", "/api/purchase",
          SliceOf(nonce), 5, SliceOfU64(com.policies[0].allowed_refund_amounts),
          false, mod->now_unix_secs());
      ASSERT_TRUE(fin.ok);
      ASSERT_TRUE(store.CompletePresentSettled(
          cred->op_generation, cred->reservation_id, *sp_id, false,
          fin.new_balance, ToZeroizing(fin.refunded_credential_bytes),
          2'000'000 + step));
    }

    // Presentation #16 (`presentations_used = 15`) enters `202 Held`, then
    // browser restarts BEFORE `/settle`!
    mod->set_defer_hold_ms(5'000, 30'000);
    auto cred16 = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", com.policies[0], 5,
        3'000'000);
    ASSERT_TRUE(cred16.has_value());
    EXPECT_EQ(15u, cred16->presentations_used);

    std::vector<uint8_t> nonce16(32, 0x99);
    SplitPresentBeginOut pb16 = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        com.policies[0], SliceOf(cred16->credential_bytes), "https://shoes.com",
        "POST", "/api/purchase", SliceOf(nonce16), 5, true);
    ASSERT_TRUE(pb16.ok);
    auto sp16 = store.RecordSpendBeforeSend(
        cred16->op_generation, cred16->reservation_id,
        std::string(pb16.settle_uri), true, ToStdVec(pb16.recovery_handle),
        ToZeroizing(pb16.spend_bundle), 3'000'000);
    TestHttpResponse r16 = mod->handle_split_present(SliceOf(pb16.request_body));
    ASSERT_EQ(202, r16.status);
    SplitPresentFinishOut fin16 = finalize_split_present_response(
        SliceOf(pb16.spend_bundle), r16.status, SliceOf(r16.body),
        SliceOf(com.policies[0].clearance_public_key), "https://mod.example",
        "checkout-v1", "https://shoes.com", "POST", "/api/purchase",
        SliceOf(nonce16), 5, SliceOfU64(com.policies[0].allowed_refund_amounts),
        false, mod->now_unix_secs());
    ASSERT_TRUE(fin16.ok && fin16.is_held);
    held_session = std::string(fin16.session_handle);
    ASSERT_TRUE(store.MarkPresentHeld(cred16->op_generation,
                                      cred16->reservation_id, *sp16,
                                      held_session, 8'000'000));
  }

  // Reopen SQLite after restart: `presentations_used == 15` MUST survive!
  {
    ModeratedEndorsementsStore restarted(false, db_path_, aead_key_);
    ASSERT_TRUE(restarted.Initialize(10'000'000));
    auto ready = restarted.GetReadySettlementsForSite(
        "https://shoes.com", "https://mod.example", false, 10'000'000);
    ASSERT_EQ(1u, ready.size());
    EXPECT_EQ(15u, ready[0].presentations_used);

    // Concurrent `GetReadySettlementsForSite` while in-flight returns empty!
    EXPECT_TRUE(
        restarted
            .GetReadySettlementsForSite("https://shoes.com",
                                        "https://mod.example", false, 10'000'000)
            .empty());

    // Simulate 2 transient `keep_for_retry` failures, then verify attempt #3
    // permanently retires the spend (`TotalPendingSpendCount() == 0`)!
    EXPECT_FALSE(restarted.CompleteSettlement(
        ready[0].op_generation, ready[0].pending_spend_id,
        /*keep_for_retry=*/true, false, 0, ZeroizingBytes(), 10'000'000, 100));
    EXPECT_EQ(1u, restarted.TotalPendingSpendCount());

    auto retry1 = restarted.GetReadySettlementsForSite(
        "https://shoes.com", "https://mod.example", false, 10'200'000);
    ASSERT_EQ(1u, retry1.size());
    EXPECT_FALSE(restarted.CompleteSettlement(
        retry1[0].op_generation, retry1[0].pending_spend_id,
        /*keep_for_retry=*/true, false, 0, ZeroizingBytes(), 10'200'000, 100));
    EXPECT_EQ(1u, restarted.TotalPendingSpendCount());

    auto retry2 = restarted.GetReadySettlementsForSite(
        "https://shoes.com", "https://mod.example", false, 10'400'000);
    ASSERT_EQ(1u, retry2.size());
    // Exceeding `kMaxSettlementRetries = 2` retires the row!
    EXPECT_FALSE(restarted.CompleteSettlement(
        retry2[0].op_generation, retry2[0].pending_spend_id,
        /*keep_for_retry=*/true, false, 0, ZeroizingBytes(), 10'400'000, 100));
    EXPECT_EQ(0u, restarted.TotalPendingSpendCount());
    EXPECT_EQ(0u, restarted.AvailableCredentialCount("https://mod.example",
                                                     env.cred_ctx));
  }
}

// 13. Time-Range `DeleteData` Matches Preserved `created_at_us` OR
//     `last_used_at_us`, and `ClearSessionOnlyData` Purges Linked Pending
//     Endorsements!
TEST_F(ModeratedEndorsementsTest,
       TimeRangeDeleteMatchesCreatedOrLastUsedAndSessionOnlyCleansPendingIssues) {
  ThreeAnchorEnvironment env;
  auto mod = new_test_split_moderator(
      "https://mod.example", "checkout-v1", env.AcceptedKeys(),
      SliceOf(env.epoch), SliceOf(env.cred_ctx), 8, 20, 5, 0, 5,
      env.DefaultAllowedSites());
  ModeratorCommitment com = mod->moderator_commitment();

  ModeratedEndorsementsStore store(false, db_path_, aead_key_);
  ASSERT_TRUE(store.Initialize(1'000'000));
  store.SetHoldoutsEnabledForTesting(false);

  // Mint credential at `t = 1'000'000`, spend & refund at `t = 9'000'000`.
  ASSERT_EQ(2u, RunBatchGrant(*env.anchor1, "https://anchor1.example", store,
                              2, 1'000'000));
  ASSERT_TRUE(RunSplitIssue(*mod, "https://mod.example", store, 1'000'000));

  {
    auto cred = store.ReserveCredentialForPresent(
        "https://shoes.com", "https://mod.example", com.policies[0], 5,
        9'000'000);
    ASSERT_TRUE(cred.has_value());
    std::vector<uint8_t> nonce(32, 0x12);
    SplitPresentBeginOut pb = build_split_present_request(
        "https://mod.example", std::string(mod->moderator_config_json()),
        com.policies[0], SliceOf(cred->credential_bytes), "https://shoes.com",
        "POST", "/api/purchase", SliceOf(nonce), 5, false);
    auto sp_id = store.RecordSpendBeforeSend(
        cred->op_generation, cred->reservation_id, std::string(pb.settle_uri),
        true, ToStdVec(pb.recovery_handle), ToZeroizing(pb.spend_bundle),
        9'000'000);
    TestHttpResponse r = mod->handle_split_present(SliceOf(pb.request_body));
    SplitPresentFinishOut fin = finalize_split_present_response(
        SliceOf(pb.spend_bundle), r.status, SliceOf(r.body),
        SliceOf(com.policies[0].clearance_public_key), "https://mod.example",
        "checkout-v1", "https://shoes.com", "POST", "/api/purchase",
        SliceOf(nonce), 5, SliceOfU64(com.policies[0].allowed_refund_amounts),
        false, mod->now_unix_secs());
    ASSERT_TRUE(store.CompletePresentSettled(
        cred->op_generation, cred->reservation_id, *sp_id, false,
        fin.new_balance, ToZeroizing(fin.refunded_credential_bytes),
        9'000'000));
  }

  // Clearing `[500'000, 1'500'000]` MUST delete the refunded credential because
  // its original `created_at_us = 1'000'000` was preserved!
  ModeratedEndorsementsStore::DataDeletionFilter early_window;
  early_window.origins = {"https://mod.example"};
  early_window.delete_begin_us = 500'000;
  early_window.delete_end_us = 1'500'000;
  store.DeleteData(early_window);
  EXPECT_EQ(0u,
            store.AvailableCredentialCount("https://mod.example", env.cred_ctx));

  // Reserve the remaining endorsement into `pending_issues` for `mod.example`
  // (anchor = `anchor1.example`, NOT session-only), then run
  // `ClearSessionOnlyData` matching `mod.example`: both `pending_issues` AND
  // the linked `kReservedInFlight` endorsement MUST be purged!
  auto res_end = store.ReserveEndorsementForIssue(com.policies[0]);
  ASSERT_TRUE(res_end.has_value());
  ASSERT_TRUE(store
                  .RecordPendingIssueBeforeSend(
                      res_end->op_generation, "https://mod.example",
                      "checkout-v1", res_end->endorsement_id,
                      std::vector<uint8_t>(32, 0xAB),
                      "https://mod.example/mole/v1/issue", {1, 2, 3},
                      ZeroizingBytes(std::vector<uint8_t>{4, 5, 6}), 10'000'000)
                  .has_value());
  store.ClearSessionOnlyData(
      [](const std::string& dom) { return dom == "mod.example"; });
  EXPECT_FALSE(store
                   .TakePendingIssueRetry("https://mod.example", "checkout-v1",
                                          10'000'100)
                   .has_value());
}

}  // namespace
}  // namespace moderated_endorsements
