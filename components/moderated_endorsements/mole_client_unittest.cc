// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace moderated_endorsements {
namespace {

constexpr char kAnchorOrigin[] = "https://anchor.example";
constexpr char kModeratorOrigin[] = "https://moderator.example";
constexpr char kResourceUrl[] = "https://moderator.example/gate";
constexpr char kEpoch[] = "epoch-unittest-2026-w48";
constexpr char kContext[] = "policy-unittest-1";

rust::Slice<const uint8_t> AsSlice(const std::string& s) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                    s.size());
}

rust::Slice<const uint8_t> AsSlice(const rust::Vec<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

struct Deployment {
  rust::Box<TestMoleAnchor> anchor;
  std::vector<rust::Box<TestMoleAnchor>> decoys;
  rust::Box<TestMoleModerator> moderator;
  rust::Box<MoleBrowserClient> client;
};

Deployment Deploy(uint8_t balance_width,
                  uint64_t initial_balance,
                  uint64_t spend_amount,
                  uint64_t max_top_up,
                  uint64_t refund_amount,
                  int decoy_anchors) {
  auto anchor = new_test_anchor(kAnchorOrigin, AsSlice(kEpoch));

  rust::Vec<Blob> accepted;
  {
    Blob real;
    real.bytes = anchor->anchor_public_key();
    accepted.push_back(std::move(real));
  }
  std::vector<rust::Box<TestMoleAnchor>> decoys;
  for (int i = 0; i < decoy_anchors; ++i) {
    auto decoy = new_test_anchor("https://decoy.example", AsSlice(kEpoch));
    Blob key;
    key.bytes = decoy->anchor_public_key();
    accepted.push_back(std::move(key));
    decoys.push_back(std::move(decoy));
  }

  auto moderator = new_test_moderator(
      kModeratorOrigin, accepted, AsSlice(kEpoch), AsSlice(kContext),
      balance_width, initial_balance, spend_amount, max_top_up, refund_amount);
  return Deployment{std::move(anchor), std::move(decoys), std::move(moderator),
                    new_mole_browser_client()};
}

// Runs the two-exchange EC-IHAT batch grant flow; returns granted count.
size_t CollectEndorsements(Deployment& d, uint16_t batch_count = 4) {
  std::string cfg(d.anchor->anchor_config_json());
  GrantBegin begin = d.client->grant_begin(
      kAnchorOrigin, cfg, d.anchor->anchor_commitment(), batch_count);
  if (!begin.ok) {
    ADD_FAILURE() << "grant_begin: " << std::string(begin.error);
    return 0;
  }

  TestHttpResponse first = d.anchor->handle_grant(
      std::string(begin.content_type), AsSlice(begin.request_body));
  if (first.status != 200) {
    ADD_FAILURE() << "first grant exchange: " << first.status;
    return 0;
  }
  GrantStep step = d.client->grant_step(
      begin.grant_id, std::string(first.content_type), AsSlice(first.body));
  if (!step.ok || step.done) {
    ADD_FAILURE() << "grant_step 1: " << std::string(step.error);
    return 0;
  }

  TestHttpResponse second = d.anchor->handle_grant(
      std::string(step.content_type), AsSlice(step.request_body));
  if (second.status != 200) {
    ADD_FAILURE() << "second grant exchange: " << second.status;
    return 0;
  }
  step = d.client->grant_step(begin.grant_id, std::string(second.content_type),
                              AsSlice(second.body));
  if (!step.ok || !step.done) {
    ADD_FAILURE() << "grant_step 2: " << std::string(step.error);
    return 0;
  }
  return step.granted_count;
}

// Runs `POST <issuance-uri>` Redeem & Issue; returns resulting pool size.
size_t RedeemAndIssue(Deployment& d) {
  TestHttpResponse challenge = d.moderator->handle_resource("");
  EXPECT_EQ(challenge.status, 401);

  RedeemBegin redeem = d.client->redeem_begin(
      kModeratorOrigin, std::string(d.moderator->moderator_config_json()),
      challenge.www_authenticate, d.moderator->moderator_commitment());
  if (!redeem.ok) {
    ADD_FAILURE() << "redeem_begin: " << std::string(redeem.error);
    return 0;
  }

  TestHttpResponse response =
      d.moderator->handle_issue(std::string(redeem.authorization_header));
  if (response.status != 200 || response.mole_credential.empty()) {
    ADD_FAILURE() << "redeem exchange: " << response.status;
    return 0;
  }
  EXPECT_EQ(std::string(response.cache_control), "no-store");

  RedeemFinish finish = d.client->redeem_finish(
      redeem.redeem_id, std::string(response.mole_credential));
  if (!finish.ok) {
    ADD_FAILURE() << "redeem_finish: " << std::string(finish.error);
    return 0;
  }
  return finish.pool_size;
}

// Runs one Presentation & Update exchange; returns resource body.
std::string Present(Deployment& d, uint64_t now_secs = 1000) {
  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), now_secs);
  if (!begin.ok) {
    ADD_FAILURE() << "present_begin: " << std::string(begin.error);
    return "";
  }
  TestHttpResponse response =
      d.moderator->handle_resource(std::string(begin.authorization_header));
  if (response.status != 200) {
    ADD_FAILURE() << "presentation rejected: " << response.status;
    return "";
  }
  PresentOutcome finish = d.client->present_finish(
      begin.presentation_id, std::string(response.mole_credential), now_secs);
  EXPECT_TRUE(finish.ok) << std::string(finish.error);
  return std::string(response.body.begin(), response.body.end());
}

TEST(MoleClientTest, FullFlowBatchedGrantRedeemPresentUpdate) {
  Deployment d = Deploy(/*balance_width=*/8, /*initial_balance=*/4,
                        /*spend_amount=*/1, /*max_top_up=*/0,
                        /*refund_amount=*/0, /*decoy_anchors=*/3);

  ASSERT_EQ(CollectEndorsements(d, /*batch_count=*/4), 4u);
  EXPECT_EQ(d.client->endorsement_count(), 4u);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  ASSERT_EQ(challenge.status, 401);
  ChallengeEval eval = d.client->challenge_eval(
      kModeratorOrigin, challenge.www_authenticate,
      d.moderator->moderator_commitment());
  ASSERT_TRUE(eval.ok) << std::string(eval.error);
  EXPECT_TRUE(eval.needs_redeem);
  EXPECT_FALSE(eval.needs_endorsement);

  ASSERT_EQ(RedeemAndIssue(d), 1u);
  EXPECT_EQ(d.client->endorsement_count(), 3u);
  EXPECT_EQ(d.moderator->endorsement_nullifier_count(), 1u);
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 4u);

  // Sequential presentations spend and update the single EC-ACT credential.
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->pool_size(kModeratorOrigin, AsSlice(kContext)), 1u);
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 3u);

  ChallengeEval later = d.client->challenge_eval(
      kModeratorOrigin, challenge.www_authenticate,
      d.moderator->moderator_commitment());
  EXPECT_TRUE(later.ok && !later.needs_redeem);
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 2u);
  EXPECT_EQ(d.moderator->endorsement_nullifier_count(), 1u);
  EXPECT_EQ(d.moderator->spend_nullifier_count(), 2u);
}

TEST(MoleClientTest,
     DuplicatePresentationReturns409WithCachedUpdateAndSettlesClient) {
  Deployment d = Deploy(8, /*initial_balance=*/3, /*spend_amount=*/1,
                        /*max_top_up=*/0, /*refund_amount=*/1,
                        /*decoy_anchors=*/0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), /*now_unix_secs=*/1000);
  ASSERT_TRUE(begin.ok);

  std::string header(begin.authorization_header);
  TestHttpResponse first = d.moderator->handle_resource(header);
  ASSERT_EQ(first.status, 200);

  // Byte-identical duplicate returns 409 Conflict with the cached
  // `Mole-Credential` without double-executing the resource operation.
  TestHttpResponse dup = d.moderator->handle_resource(header);
  EXPECT_EQ(dup.status, 409);
  EXPECT_EQ(std::string(dup.mole_credential),
            std::string(first.mole_credential));
  EXPECT_EQ(d.moderator->spend_nullifier_count(), 1u);

  // Client processes `Mole-Credential` on 409 and restores its credential.
  PresentOutcome pf = d.client->present_finish(
      begin.presentation_id, std::string(dup.mole_credential), 1000);
  EXPECT_TRUE(pf.ok);
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 3u);
}

TEST(MoleClientTest, ReplayedRedemptionRejected) {
  Deployment d = Deploy(8, 2, 1, 0, 0, /*decoy_anchors=*/0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  RedeemBegin redeem = d.client->redeem_begin(
      kModeratorOrigin, std::string(d.moderator->moderator_config_json()),
      challenge.www_authenticate, d.moderator->moderator_commitment());
  ASSERT_TRUE(redeem.ok);

  std::string header(redeem.authorization_header);
  TestHttpResponse first = d.moderator->handle_issue(header);
  EXPECT_EQ(first.status, 200);
  EXPECT_FALSE(first.mole_credential.empty());

  TestHttpResponse replay = d.moderator->handle_issue(header);
  EXPECT_EQ(replay.status, 403);
  EXPECT_TRUE(replay.mole_credential.empty());
  EXPECT_EQ(d.moderator->endorsement_nullifier_count(), 1u);
}

TEST(MoleClientTest, RefundSustainsBalanceAcrossManyPresentations) {
  Deployment d = Deploy(8, /*initial_balance=*/2, /*spend_amount=*/1,
                        /*max_top_up=*/0, /*refund_amount=*/1,
                        /*decoy_anchors=*/0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  for (int i = 0; i < 6; ++i) {
    EXPECT_EQ(Present(d), "the protected resource\n") << "presentation " << i;
    EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 2u)
        << "presentation " << i;
  }
}

TEST(MoleClientTest, ExhaustedCredentialDrainsAndSteersToRedemption) {
  Deployment d = Deploy(8, /*initial_balance=*/1, /*spend_amount=*/1,
                        /*max_top_up=*/0, /*refund_amount=*/0,
                        /*decoy_anchors=*/0);
  ASSERT_EQ(CollectEndorsements(d, /*batch_count=*/2), 2u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);
  EXPECT_EQ(d.client->endorsement_count(), 1u);

  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 0u);

  // Zero-balance credential cannot cover `spend_amount = 1`: `challenge_eval`
  // drains it and steers into Redeem & Issue using the second stored
  // endorsement without revisiting the Anchor.
  TestHttpResponse challenge = d.moderator->handle_resource("");
  ChallengeEval eval = d.client->challenge_eval(
      kModeratorOrigin, challenge.www_authenticate,
      d.moderator->moderator_commitment());
  ASSERT_TRUE(eval.ok);
  EXPECT_TRUE(eval.needs_redeem);
  EXPECT_FALSE(eval.needs_endorsement);

  ASSERT_EQ(RedeemAndIssue(d), 1u);
  EXPECT_EQ(d.client->endorsement_count(), 0u);
  EXPECT_EQ(Present(d), "the protected resource\n");

  // Once the second endorsement is also exhausted, `needs_endorsement` flips.
  ChallengeEval exhausted = d.client->challenge_eval(
      kModeratorOrigin, challenge.www_authenticate,
      d.moderator->moderator_commitment());
  ASSERT_TRUE(exhausted.ok);
  EXPECT_TRUE(exhausted.needs_redeem);
  EXPECT_TRUE(exhausted.needs_endorsement);
}

TEST(MoleClientTest, PresentationBoundToChallenge) {
  Deployment d = Deploy(8, 2, 1, 0, 0, /*decoy_anchors=*/0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  rust::Vec<Blob> accepted;
  Blob key;
  key.bytes = d.anchor->anchor_public_key();
  accepted.push_back(std::move(key));
  auto other_moderator = new_test_moderator(
      "https://other-mod.example", accepted, AsSlice(kEpoch),
      AsSlice("policy-other"), 8, 2, 1, 0, 0);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), 1000);
  ASSERT_TRUE(begin.ok);

  TestHttpResponse wrong =
      other_moderator->handle_resource(std::string(begin.authorization_header));
  EXPECT_EQ(wrong.status, 403);
  EXPECT_EQ(other_moderator->spend_nullifier_count(), 0u);

  TestHttpResponse right =
      d.moderator->handle_resource(std::string(begin.authorization_header));
  EXPECT_EQ(right.status, 200);
  EXPECT_TRUE(d.client
                  ->present_finish(begin.presentation_id,
                                   std::string(right.mole_credential), 1000)
                  .ok);
}

TEST(MoleClientTest, HeldForUpdateEarlySignoffAndPostHoldRecovery) {
  Deployment d = Deploy(8, /*initial_balance=*/3, /*spend_amount=*/1,
                        /*max_top_up=*/0, /*refund_amount=*/1,
                        /*decoy_anchors=*/0);
  d.moderator->set_hold_duration_secs(30);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  TestHttpResponse challenge = d.moderator->handle_resource("");

  // 1. Early settlement (`now < hold_until`) sends `signoff-0001`.
  PresentBegin pb1 = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), /*now=*/1000);
  ASSERT_TRUE(pb1.ok);
  TestHttpResponse r1 =
      d.moderator->handle_resource(std::string(pb1.authorization_header));
  ASSERT_EQ(r1.status, 200);
  PresentOutcome pf1 = d.client->present_finish(
      pb1.presentation_id, std::string(r1.mole_credential), 1000);
  ASSERT_TRUE(pf1.ok);
  EXPECT_EQ(pf1.held_for_secs, 30u);

  PendingSettlement s1 = d.client->next_settlement(kModeratorOrigin, 1010);
  ASSERT_TRUE(s1.has_pending);
  EXPECT_TRUE(s1.is_signoff);
  TestHttpResponse sr1 =
      d.moderator->handle_issue(std::string(s1.authorization_header));
  ASSERT_EQ(sr1.status, 200);
  SettleOutcome so1 = d.client->settle_finish(s1.pending_id, sr1.status,
                                              std::string(sr1.mole_credential));
  ASSERT_TRUE(so1.ok && so1.credential_restored);
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 3u);

  // 2. Post-hold settlement (`now >= hold_until`) sends `recovery-0001`.
  PresentBegin pb2 = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), /*now=*/1010);
  ASSERT_TRUE(pb2.ok);
  TestHttpResponse r2 =
      d.moderator->handle_resource(std::string(pb2.authorization_header));
  ASSERT_TRUE(d.client
                  ->present_finish(pb2.presentation_id,
                                   std::string(r2.mole_credential), 1010)
                  .ok);

  d.moderator->advance_clock_secs(35);
  PendingSettlement s2 = d.client->next_settlement(kModeratorOrigin, 1045);
  ASSERT_TRUE(s2.has_pending);
  EXPECT_FALSE(s2.is_signoff);
  TestHttpResponse sr2 =
      d.moderator->handle_issue(std::string(s2.authorization_header));
  ASSERT_EQ(sr2.status, 200);
  SettleOutcome so2 = d.client->settle_finish(s2.pending_id, sr2.status,
                                              std::string(sr2.mole_credential));
  ASSERT_TRUE(so2.ok && so2.credential_restored);
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 3u);
}

TEST(MoleClientTest, WriteAheadPendingSpendSurvivesSerializeRestoreAndRecovers) {
  Deployment d = Deploy(8, /*initial_balance=*/4, /*spend_amount=*/2,
                        /*max_top_up=*/1, /*refund_amount=*/3,
                        /*decoy_anchors=*/1);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin pb = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), 1000);
  ASSERT_TRUE(pb.ok);
  EXPECT_EQ(d.client->pending_spend_count(), 1u);

  // Write-ahead snapshot BEFORE transmitting `presentation-0001`:
  rust::Vec<uint8_t> wal = d.client->serialize_state();

  // Moderator records the presentation & refund (+3 => balance 5), then the
  // client crashes before receiving the response.
  TestHttpResponse resp =
      d.moderator->handle_resource(std::string(pb.authorization_header));
  ASSERT_EQ(resp.status, 200);

  rust::Box<MoleBrowserClient> crashed = new_mole_browser_client();
  ASSERT_TRUE(crashed->restore_state(AsSlice(wal)));
  EXPECT_EQ(crashed->pending_spend_count(), 1u);

  PendingSettlement settlement =
      crashed->next_settlement(kModeratorOrigin, 1005);
  ASSERT_TRUE(settlement.has_pending && !settlement.is_signoff);
  TestHttpResponse rec =
      d.moderator->handle_issue(std::string(settlement.authorization_header));
  ASSERT_EQ(rec.status, 200);
  SettleOutcome outcome = crashed->settle_finish(
      settlement.pending_id, rec.status, std::string(rec.mole_credential));
  ASSERT_TRUE(outcome.ok && outcome.credential_restored);
  EXPECT_EQ(crashed->balance(kModeratorOrigin, AsSlice(kContext)), 5u);
}

TEST(MoleClientTest, DynamicRevocationNoUpdateAndNoEndorsementMode) {
  Deployment d = Deploy(8, /*initial_balance=*/2, /*spend_amount=*/1,
                        /*max_top_up=*/0, /*refund_amount=*/0,
                        /*decoy_anchors=*/0);
  d.moderator->set_allow_no_endorsement(true);
  d.moderator->set_withhold_update(true);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  ChallengeEval eval = d.client->challenge_eval(
      kModeratorOrigin, challenge.www_authenticate,
      d.moderator->moderator_commitment());
  ASSERT_TRUE(eval.ok && eval.needs_redeem && !eval.needs_endorsement);

  ASSERT_EQ(RedeemAndIssue(d), 1u);
  PresentBegin pb = d.client->present_begin(
      kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
      d.moderator->moderator_commitment(), 1000);
  ASSERT_TRUE(pb.ok);
  TestHttpResponse resp =
      d.moderator->handle_resource(std::string(pb.authorization_header));
  ASSERT_EQ(resp.status, 200);
  EXPECT_EQ(std::string(resp.mole_credential), "update-0001=\"\"");

  PresentOutcome pf = d.client->present_finish(
      pb.presentation_id, std::string(resp.mole_credential), 1000);
  EXPECT_TRUE(pf.ok && pf.consumed_no_update);
  EXPECT_EQ(d.client->pool_size(kModeratorOrigin, AsSlice(kContext)), 0u);
}

TEST(MoleClientTest, UnknownGreasedCredentialTypeTriggers401Challenge) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 0);
  TestHttpResponse greased =
      d.moderator->handle_resource("Mole presentation-0a0a=\"AAAA\"");
  EXPECT_EQ(greased.status, 401);
}

TEST(MoleClientTest, EndorsementsAndPoolSurviveSerializeRestore) {
  Deployment d = Deploy(8, 3, 1, 0, 0, /*decoy_anchors=*/2);
  ASSERT_EQ(CollectEndorsements(d, 4), 4u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  rust::Vec<uint8_t> blob = d.client->serialize_state();
  rust::Box<MoleBrowserClient> restored = new_mole_browser_client();
  ASSERT_TRUE(restored->restore_state(AsSlice(blob)));
  EXPECT_EQ(restored->endorsement_count(), 3u);
  EXPECT_EQ(restored->pool_size(kModeratorOrigin, AsSlice(kContext)), 1u);
  EXPECT_EQ(restored->balance(kModeratorOrigin, AsSlice(kContext)), 3u);

  d.client = std::move(restored);
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->balance(kModeratorOrigin, AsSlice(kContext)), 2u);
}

TEST(MoleClientTest, RestoreRejectsCorruptBlobAndLeavesStateIntact) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 1);
  ASSERT_EQ(CollectEndorsements(d, 2), 2u);

  const std::vector<uint8_t> garbage = {0x02, 0xff, 0xff, 0xff};
  EXPECT_FALSE(d.client->restore_state(
      rust::Slice<const uint8_t>(garbage.data(), garbage.size())));
  EXPECT_EQ(d.client->endorsement_count(), 2u);
}

// --- Key-commitment enforcement (cross-site channel closure) --------------

TEST(MoleClientCommitmentTest, GrantRefusedForUnenrolledAnchor) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 0);
  AnchorCommitment absent;
  absent.found = false;
  GrantBegin begin = d.client->grant_begin(
      kAnchorOrigin, std::string(d.anchor->anchor_config_json()), absent, 4);
  EXPECT_FALSE(begin.ok);
}

TEST(MoleClientCommitmentTest, GrantRefusedForUncommittedKey) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 0);
  auto other = new_test_anchor(kAnchorOrigin, AsSlice(kEpoch));
  GrantBegin begin = d.client->grant_begin(
      kAnchorOrigin, std::string(d.anchor->anchor_config_json()),
      other->anchor_commitment(), 4);
  EXPECT_FALSE(begin.ok);
}

TEST(MoleClientCommitmentTest, GrantRefusedForUncommittedEpoch) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 0);
  AnchorCommitment c = d.anchor->anchor_commitment();
  c.epochs.clear();
  Blob other_epoch;
  for (char ch : std::string("some-other-epoch")) {
    other_epoch.bytes.push_back(static_cast<uint8_t>(ch));
  }
  c.epochs.push_back(std::move(other_epoch));
  GrantBegin begin = d.client->grant_begin(
      kAnchorOrigin, std::string(d.anchor->anchor_config_json()), c, 4);
  EXPECT_FALSE(begin.ok);
}

TEST(MoleClientCommitmentTest, GrantRefusedForUncommittedGrantUri) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 0);
  AnchorCommitment c = d.anchor->anchor_commitment();
  c.grant_uri = "https://anchor.example/mole/other-grant";
  GrantBegin begin = d.client->grant_begin(
      kAnchorOrigin, std::string(d.anchor->anchor_config_json()), c, 4);
  EXPECT_FALSE(begin.ok);
}

TEST(MoleClientCommitmentTest, RedeemRefusedForUnenrolledModerator) {
  Deployment d = Deploy(8, 2, 1, 0, 0, 0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  TestHttpResponse challenge = d.moderator->handle_resource("");
  ModeratorCommitment absent;
  absent.found = false;
  RedeemBegin redeem = d.client->redeem_begin(
      kModeratorOrigin, std::string(d.moderator->moderator_config_json()),
      challenge.www_authenticate, absent);
  EXPECT_FALSE(redeem.ok);
}

TEST(MoleClientCommitmentTest, RedeemRefusedForCraftedOrReorderedAnchorSet) {
  Deployment d = Deploy(8, 2, 1, 0, 0, /*decoy_anchors=*/1);
  ASSERT_EQ(CollectEndorsements(d, 2), 2u);
  TestHttpResponse challenge = d.moderator->handle_resource("");

  // Reordering the committed ordered `anchor-set` is refused.
  ModeratorCommitment swapped = d.moderator->moderator_commitment();
  std::swap(swapped.policies[0].accepted_anchor_keys[0],
            swapped.policies[0].accepted_anchor_keys[1]);
  EXPECT_FALSE(
      d.client
          ->redeem_begin(kModeratorOrigin,
                         std::string(d.moderator->moderator_config_json()),
                         challenge.www_authenticate, swapped)
          .ok);

  // Adding an uncommitted decoy key is also refused.
  ModeratorCommitment extra_set = d.moderator->moderator_commitment();
  auto decoy = new_test_anchor("https://extra.example", AsSlice(kEpoch));
  Blob extra;
  extra.bytes = decoy->anchor_public_key();
  extra_set.policies[0].accepted_anchor_keys.push_back(std::move(extra));
  EXPECT_FALSE(
      d.client
          ->redeem_begin(kModeratorOrigin,
                         std::string(d.moderator->moderator_config_json()),
                         challenge.www_authenticate, extra_set)
          .ok);
}

TEST(MoleClientCommitmentTest, RedeemRefusedForUncommittedInitialBalance) {
  // Closes the per-Client initial-balance tagging channel: if a Moderator
  // issues `c = 5` when the committed policy pins `initial_balance = 4`,
  // `redeem_finish` refuses the credential.
  Deployment d = Deploy(8, /*initial_balance=*/5, /*spend_amount=*/1,
                        /*max_top_up=*/0, /*refund_amount=*/0, 0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  TestHttpResponse challenge = d.moderator->handle_resource("");
  ModeratorCommitment c = d.moderator->moderator_commitment();
  c.policies[0].initial_balance = 4;

  RedeemBegin rb = d.client->redeem_begin(
      kModeratorOrigin, std::string(d.moderator->moderator_config_json()),
      challenge.www_authenticate, c);
  ASSERT_TRUE(rb.ok);
  TestHttpResponse resp =
      d.moderator->handle_issue(std::string(rb.authorization_header));
  ASSERT_EQ(resp.status, 200);
  RedeemFinish rf =
      d.client->redeem_finish(rb.redeem_id, std::string(resp.mole_credential));
  EXPECT_FALSE(rf.ok);
  EXPECT_EQ(d.client->pool_size(kModeratorOrigin, AsSlice(kContext)), 0u);
}

TEST(MoleClientCommitmentTest, PresentRefusedForUncommittedAmounts) {
  Deployment d = Deploy(8, 4, /*spend_amount=*/1, /*max_top_up=*/0, 0, 0);
  ASSERT_EQ(CollectEndorsements(d, 1), 1u);
  ASSERT_EQ(RedeemAndIssue(d), 1u);
  TestHttpResponse challenge = d.moderator->handle_resource("");

  ModeratorCommitment wrong_spend = d.moderator->moderator_commitment();
  wrong_spend.policies[0].spend_amount = 2;
  EXPECT_FALSE(d.client
                   ->present_begin(kModeratorOrigin, kResourceUrl,
                                   challenge.www_authenticate, wrong_spend,
                                   1000)
                   .ok);

  ModeratorCommitment wrong_top_up = d.moderator->moderator_commitment();
  wrong_top_up.policies[0].max_top_up = 1;
  EXPECT_FALSE(d.client
                   ->present_begin(kModeratorOrigin, kResourceUrl,
                                   challenge.www_authenticate, wrong_top_up,
                                   1000)
                   .ok);
}

}  // namespace
}  // namespace moderated_endorsements
