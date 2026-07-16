// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <string>
#include <vector>

#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace moderated_endorsements {
namespace {

constexpr char kEpoch[] = "epoch-unittest-1";
constexpr char kPolicy[] = "policy-unittest-1";

rust::Slice<const uint8_t> AsSlice(const std::string& s) {
  return rust::Slice<const uint8_t>(
      reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

rust::Slice<const uint8_t> AsSlice(const rust::Vec<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

// A deployment: one real Anchor (plus optional decoys in the accepted set)
// and one Moderator, with a Client wired against them in process.
struct Deployment {
  rust::Box<TestMoleAnchor> anchor;
  std::vector<rust::Box<TestMoleAnchor>> decoys;
  rust::Box<TestMoleModerator> moderator;
  rust::Box<MoleBrowserClient> client;
};

Deployment Deploy(uint64_t initial_credits,
                  uint64_t issuance_batch,
                  uint64_t charge,
                  uint64_t refund,
                  int decoy_anchors) {
  auto anchor = new_test_anchor(AsSlice(kEpoch));

  rust::Vec<Blob> accepted;
  {
    Blob real;
    real.bytes = anchor->anchor_public_key();
    accepted.push_back(std::move(real));
  }
  std::vector<rust::Box<TestMoleAnchor>> decoys;
  for (int i = 0; i < decoy_anchors; ++i) {
    auto decoy = new_test_anchor(AsSlice(kEpoch));
    Blob key;
    key.bytes = decoy->anchor_public_key();
    accepted.push_back(std::move(key));
    decoys.push_back(std::move(decoy));
  }

  auto moderator =
      new_test_moderator(accepted, AsSlice(kEpoch), AsSlice(kPolicy),
                         initial_credits, issuance_batch, charge, refund);
  return Deployment{std::move(anchor), std::move(decoys),
                    std::move(moderator), new_mole_browser_client()};
}

// Runs the two-exchange grant flow; returns true on success.
bool CollectEndorsement(Deployment& d) {
  std::string directory(d.anchor->anchor_directory_json());
  GrantBegin begin = d.client->grant_begin(directory);
  if (!begin.ok) {
    ADD_FAILURE() << "grant_begin: " << std::string(begin.error);
    return false;
  }

  TestHttpResponse first = d.anchor->handle_endorse(AsSlice(begin.request_body));
  if (first.status != 200) {
    ADD_FAILURE() << "first grant exchange: " << first.status;
    return false;
  }
  GrantStep step = d.client->grant_step(AsSlice(first.body));
  if (!step.ok || step.done) {
    ADD_FAILURE() << "grant_step 1: " << std::string(step.error);
    return false;
  }

  TestHttpResponse second = d.anchor->handle_endorse(AsSlice(step.request_body));
  if (second.status != 200) {
    ADD_FAILURE() << "second grant exchange: " << second.status;
    return false;
  }
  step = d.client->grant_step(AsSlice(second.body));
  if (!step.ok || !step.done) {
    ADD_FAILURE() << "grant_step 2: " << std::string(step.error);
    return false;
  }
  return true;
}

// Runs Redeem & Issue against the Moderator's current challenge; returns the
// resulting pool size (0 on failure).
size_t RedeemAndIssue(Deployment& d) {
  TestHttpResponse challenge = d.moderator->handle_resource("");
  EXPECT_EQ(challenge.status, 401);

  RedeemBegin redeem = d.client->redeem_begin(
      std::string(d.moderator->moderator_directory_json()),
      challenge.www_authenticate);
  if (!redeem.ok) {
    ADD_FAILURE() << "redeem_begin: " << std::string(redeem.error);
    return 0;
  }

  TestHttpResponse response =
      d.moderator->handle_resource(std::string(redeem.authorization_header));
  // Redemption success still challenges: the Client has not presented yet.
  if (response.status != 401 || response.mole_credential.empty()) {
    ADD_FAILURE() << "redeem exchange: " << response.status;
    return 0;
  }

  RedeemFinish finish =
      d.client->redeem_finish(std::string(response.mole_credential));
  if (!finish.ok) {
    ADD_FAILURE() << "redeem_finish: " << std::string(finish.error);
    return 0;
  }
  return finish.pool_size;
}

// One full presentation: draw, send, finalize. Returns the resource body.
std::string Present(Deployment& d) {
  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(challenge.www_authenticate);
  if (!begin.ok) {
    ADD_FAILURE() << "present_begin: " << std::string(begin.error);
    return "";
  }
  TestHttpResponse response =
      d.moderator->handle_resource(std::string(begin.authorization_header));
  if (response.status != 200) {
    d.client->present_abort(begin.presentation_id);
    ADD_FAILURE() << "presentation rejected: " << response.status;
    return "";
  }
  StatusResult finish = d.client->present_finish(
      begin.presentation_id, std::string(response.mole_credential));
  EXPECT_TRUE(finish.ok) << std::string(finish.error);
  return std::string(response.body.begin(), response.body.end());
}

TEST(MoleClientTest, FullFlowGrantRedeemPresentUpdate) {
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/4,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/3);

  // The user agent collects an endorsement at the Anchor...
  ASSERT_TRUE(CollectEndorsement(d));
  EXPECT_EQ(d.client->endorsement_count(), 1u);

  // ...evaluates the Moderator's challenge...
  TestHttpResponse challenge = d.moderator->handle_resource("");
  ASSERT_EQ(challenge.status, 401);
  ChallengeEval eval = d.client->challenge_eval(challenge.www_authenticate);
  ASSERT_TRUE(eval.ok) << std::string(eval.error);
  EXPECT_TRUE(eval.needs_redeem);
  EXPECT_FALSE(eval.needs_endorsement);

  // ...redeems it for a pool of Credentials...
  ASSERT_EQ(RedeemAndIssue(d), 4u);
  EXPECT_EQ(d.client->endorsement_count(), 0u);
  EXPECT_EQ(d.moderator->endorsement_nullifier_count(), 1u);
  EXPECT_EQ(d.client->balance(AsSlice(kPolicy)), 8u);

  // ...and presents. The spent Credential's successor rejoins the pool.
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 4u);
  EXPECT_EQ(d.client->balance(AsSlice(kPolicy)), 7u);

  // Later presentations draw on the pool without redeeming.
  ChallengeEval later = d.client->challenge_eval(challenge.www_authenticate);
  EXPECT_FALSE(later.needs_redeem);
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->balance(AsSlice(kPolicy)), 6u);
  EXPECT_EQ(d.moderator->endorsement_nullifier_count(), 1u);
  EXPECT_EQ(d.moderator->spend_nullifier_count(), 2u);
}

TEST(MoleClientTest, ParallelPresentationsFromOnePool) {
  // The property the pool exists for: several presentations in flight at
  // once, none depending on another's update.
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/4,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/0);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 4u);

  TestHttpResponse challenge = d.moderator->handle_resource("");

  // Draw three Credentials before any response returns.
  PresentBegin a = d.client->present_begin(challenge.www_authenticate);
  PresentBegin b = d.client->present_begin(challenge.www_authenticate);
  PresentBegin c = d.client->present_begin(challenge.www_authenticate);
  ASSERT_TRUE(a.ok && b.ok && c.ok);
  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 1u);

  // All three presentations succeed, in an order unrelated to draw order.
  TestHttpResponse rc =
      d.moderator->handle_resource(std::string(c.authorization_header));
  TestHttpResponse ra =
      d.moderator->handle_resource(std::string(a.authorization_header));
  TestHttpResponse rb =
      d.moderator->handle_resource(std::string(b.authorization_header));
  EXPECT_EQ(rc.status, 200);
  EXPECT_EQ(ra.status, 200);
  EXPECT_EQ(rb.status, 200);

  EXPECT_TRUE(d.client
                  ->present_finish(c.presentation_id,
                                   std::string(rc.mole_credential))
                  .ok);
  EXPECT_TRUE(d.client
                  ->present_finish(a.presentation_id,
                                   std::string(ra.mole_credential))
                  .ok);
  EXPECT_TRUE(d.client
                  ->present_finish(b.presentation_id,
                                   std::string(rb.mole_credential))
                  .ok);

  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 4u);
  EXPECT_EQ(d.moderator->spend_nullifier_count(), 3u);
  EXPECT_EQ(d.client->balance(AsSlice(kPolicy)), 5u);
}

TEST(MoleClientTest, ReplayedPresentationRejected) {
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/2,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/0);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 2u);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(challenge.www_authenticate);
  ASSERT_TRUE(begin.ok);

  std::string header(begin.authorization_header);
  EXPECT_EQ(d.moderator->handle_resource(header).status, 200);
  // The spend nullifier is recorded: the identical presentation is dead.
  EXPECT_EQ(d.moderator->handle_resource(header).status, 403);
  EXPECT_EQ(d.moderator->spend_nullifier_count(), 1u);
}

TEST(MoleClientTest, ReplayedRedemptionRejected) {
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/2,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/0);
  ASSERT_TRUE(CollectEndorsement(d));

  TestHttpResponse challenge = d.moderator->handle_resource("");
  RedeemBegin redeem = d.client->redeem_begin(
      std::string(d.moderator->moderator_directory_json()),
      challenge.www_authenticate);
  ASSERT_TRUE(redeem.ok);

  std::string header(redeem.authorization_header);
  TestHttpResponse first = d.moderator->handle_resource(header);
  EXPECT_EQ(first.status, 401);
  EXPECT_FALSE(first.mole_credential.empty());

  // The endorsement nullifier is spent: the identical redemption is dead.
  TestHttpResponse replay = d.moderator->handle_resource(header);
  EXPECT_EQ(replay.status, 403);
  EXPECT_TRUE(replay.mole_credential.empty());
  EXPECT_EQ(d.moderator->endorsement_nullifier_count(), 1u);
}

TEST(MoleClientTest, RefundSustainsBalance) {
  // refund == charge: the Moderator dynamically sustains access, and the
  // pool's total balance never drops.
  Deployment d = Deploy(/*initial_credits=*/1, /*issuance_batch=*/2,
                        /*charge=*/1, /*refund=*/1, /*decoy_anchors=*/0);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 2u);

  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(Present(d), "the protected resource\n") << "presentation " << i;
    EXPECT_EQ(d.client->balance(AsSlice(kPolicy)), 2u) << "presentation " << i;
  }
  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 2u);
}

TEST(MoleClientTest, ExhaustedPoolSteersBackToRedemption) {
  // With no refund, balances drain to zero; drained Credentials drop out of
  // the pool and challenge_eval steers back into Redeem & Issue.
  Deployment d = Deploy(/*initial_credits=*/1, /*issuance_batch=*/1,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/0);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 1u);

  // First presentation spends the single credit; the zero-balance successor
  // rejoins the pool.
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 1u);
  EXPECT_EQ(d.client->balance(AsSlice(kPolicy)), 0u);

  // Drawing it fails (cannot cover the charge) and drains it from the pool.
  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(challenge.www_authenticate);
  EXPECT_FALSE(begin.ok);
  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 0u);

  // The next challenge evaluation asks for redemption — and since the only
  // endorsement was already redeemed, for a fresh endorsement too.
  ChallengeEval eval = d.client->challenge_eval(challenge.www_authenticate);
  ASSERT_TRUE(eval.ok);
  EXPECT_TRUE(eval.needs_redeem);
  EXPECT_TRUE(eval.needs_endorsement);

  // Collecting and redeeming again restores service.
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 1u);
  EXPECT_EQ(Present(d), "the protected resource\n");
}

TEST(MoleClientTest, PresentationBoundToChallenge) {
  // A presentation answers one specific challenge; a Moderator with a
  // different policy context (hence different challenge digest) rejects it,
  // and the failed attempt burns no nullifier.
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/2,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/0);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 2u);

  rust::Vec<Blob> accepted;
  Blob key;
  key.bytes = d.anchor->anchor_public_key();
  accepted.push_back(std::move(key));
  auto other_moderator = new_test_moderator(
      accepted, AsSlice(kEpoch), AsSlice("policy-other"), 2, 2, 1, 0);

  TestHttpResponse challenge = d.moderator->handle_resource("");
  PresentBegin begin = d.client->present_begin(challenge.www_authenticate);
  ASSERT_TRUE(begin.ok);

  // The wrong moderator rejects it without recording anything.
  TestHttpResponse wrong = other_moderator->handle_resource(
      std::string(begin.authorization_header));
  EXPECT_EQ(wrong.status, 403);
  EXPECT_EQ(other_moderator->spend_nullifier_count(), 0u);

  // The right moderator still accepts the same presentation.
  TestHttpResponse right =
      d.moderator->handle_resource(std::string(begin.authorization_header));
  EXPECT_EQ(right.status, 200);
  EXPECT_TRUE(d.client
                  ->present_finish(begin.presentation_id,
                                   std::string(right.mole_credential))
                  .ok);
}

// Persistence foundation: the durable client state (endorsements + pools)
// survives serialize/restore into a fresh client, and the restored state is
// fully usable.

TEST(MoleClientTest, EndorsementSurvivesSerializeRestore) {
  // Collect an endorsement, serialize it (with its secret gamma witness),
  // restore into a fresh client, and require the restored client to redeem and
  // present — proving the persisted endorsement is intact and usable.
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/4,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/3);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(d.client->endorsement_count(), 1u);

  rust::Vec<uint8_t> blob = d.client->serialize_state();
  rust::Box<MoleBrowserClient> restored = new_mole_browser_client();
  ASSERT_TRUE(restored->restore_state(AsSlice(blob)));
  EXPECT_EQ(restored->endorsement_count(), 1u);

  d.client = std::move(restored);
  ASSERT_EQ(RedeemAndIssue(d), 4u);
  EXPECT_EQ(Present(d), "the protected resource\n");
}

TEST(MoleClientTest, PoolSurvivesSerializeRestore) {
  // Fill a credential pool, serialize it, restore into a fresh client, and
  // require the restored client to present from the restored pool.
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/4,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/3);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(RedeemAndIssue(d), 4u);
  const uint64_t balance_before = d.client->balance(AsSlice(kPolicy));

  rust::Vec<uint8_t> blob = d.client->serialize_state();
  rust::Box<MoleBrowserClient> restored = new_mole_browser_client();
  ASSERT_TRUE(restored->restore_state(AsSlice(blob)));
  EXPECT_EQ(restored->pool_size(AsSlice(kPolicy)), 4u);
  EXPECT_EQ(restored->balance(AsSlice(kPolicy)), balance_before);

  d.client = std::move(restored);
  EXPECT_EQ(Present(d), "the protected resource\n");
  EXPECT_EQ(d.client->pool_size(AsSlice(kPolicy)), 4u);
}

TEST(MoleClientTest, RestoreRejectsCorruptBlobAndLeavesStateIntact) {
  Deployment d = Deploy(/*initial_credits=*/2, /*issuance_batch=*/4,
                        /*charge=*/1, /*refund=*/0, /*decoy_anchors=*/3);
  ASSERT_TRUE(CollectEndorsement(d));
  ASSERT_EQ(d.client->endorsement_count(), 1u);

  // A malformed blob (wrong version, truncated) is rejected and the existing
  // state is untouched.
  const std::vector<uint8_t> garbage = {0x02, 0xff, 0xff, 0xff};
  EXPECT_FALSE(d.client->restore_state(
      rust::Slice<const uint8_t>(garbage.data(), garbage.size())));
  EXPECT_EQ(d.client->endorsement_count(), 1u);
}

}  // namespace
}  // namespace moderated_endorsements
