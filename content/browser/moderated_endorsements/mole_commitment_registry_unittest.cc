// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_commitment_registry.h"

#include <string>
#include <vector>

#include "base/base64url.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {
namespace {

std::string B64(const std::string& raw) {
  std::string out;
  base::Base64UrlEncode(raw, base::Base64UrlEncodePolicy::OMIT_PADDING, &out);
  return out;
}

std::vector<uint8_t> Bytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

url::Origin Origin(const std::string& s) {
  return url::Origin::Create(GURL(s));
}

// A `-01` registry document naming one Anchor (grant-uri, key "AK", epoch "E1")
// and one Moderator (credential-context "P", credential-key "MK", balance-width
// 8, initial-balance 4, spend-amount 1, max-top-up 0, accepted {"AK"}, epoch
// "E1", issuance-uri).
std::string SampleRegistry() {
  return R"({
    "anchors": {
      "https://anchor.example": {
        "grant-uri": "https://anchor.example/mole/grant",
        "keys": [")" +
         B64("AK") + R"("],
        "epochs": [")" +
         B64("E1") + R"("]
      }
    },
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "credential-context": ")" +
         B64("P") + R"(",
          "credential-key": ")" +
         B64("MK") + R"(",
          "balance-width": 8,
          "initial-balance": 4,
          "spend-amount": 1,
          "max-top-up": 2,
          "accepted-anchor-keys": [")" +
         B64("AK") + R"("],
          "epochs": [")" +
         B64("E1") + R"(",
          "allow-no-endorsement": false,
          "issuance-uri": "https://mod.example/mole/issue"
        }]
      }
    }
  })";
}

class MoleCommitmentRegistryTest : public testing::Test {
 protected:
  void SetUp() override {
    MoleCommitmentRegistry::GetInstance().ClearForTesting();
  }
  void TearDown() override {
    MoleCommitmentRegistry::GetInstance().ClearForTesting();
  }
};

TEST_F(MoleCommitmentRegistryTest, ParsesAndReturnsCommittedAnchor) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  auto anchor = registry.GetAnchorCommitment(Origin("https://anchor.example"));
  EXPECT_TRUE(anchor.found);
  EXPECT_EQ(std::string(anchor.grant_uri),
            "https://anchor.example/mole/grant");
  ASSERT_EQ(anchor.keys.size(), 1u);
  EXPECT_EQ(std::vector<uint8_t>(anchor.keys[0].bytes.begin(),
                                 anchor.keys[0].bytes.end()),
            Bytes("AK"));
  ASSERT_EQ(anchor.epochs.size(), 1u);
  EXPECT_EQ(std::vector<uint8_t>(anchor.epochs[0].bytes.begin(),
                                 anchor.epochs[0].bytes.end()),
            Bytes("E1"));
}

TEST_F(MoleCommitmentRegistryTest, ParsesAndReturnsCommittedModerator) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  auto mod = registry.GetModeratorCommitment(Origin("https://mod.example"));
  EXPECT_TRUE(mod.found);
  ASSERT_EQ(mod.policies.size(), 1u);
  const auto& p = mod.policies[0];
  EXPECT_EQ(std::vector<uint8_t>(p.credential_context.begin(),
                                 p.credential_context.end()),
            Bytes("P"));
  EXPECT_EQ(
      std::vector<uint8_t>(p.credential_key.begin(), p.credential_key.end()),
      Bytes("MK"));
  EXPECT_EQ(p.balance_width, 8u);
  EXPECT_EQ(p.initial_balance, 4u);
  EXPECT_EQ(p.spend_amount, 1u);
  EXPECT_EQ(p.max_top_up, 2u);
  EXPECT_FALSE(p.allow_no_endorsement);
  EXPECT_EQ(std::string(p.issuance_uri), "https://mod.example/mole/issue");
  ASSERT_EQ(p.accepted_anchor_keys.size(), 1u);
  EXPECT_EQ(std::vector<uint8_t>(p.accepted_anchor_keys[0].bytes.begin(),
                                 p.accepted_anchor_keys[0].bytes.end()),
            Bytes("AK"));
}

TEST_F(MoleCommitmentRegistryTest, UnenrolledOriginIsNotFound) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  EXPECT_FALSE(
      registry.GetAnchorCommitment(Origin("https://other.example")).found);
  EXPECT_FALSE(
      registry.GetModeratorCommitment(Origin("https://other.example")).found);
  EXPECT_FALSE(
      registry.GetAnchorCommitment(Origin("https://mod.example")).found);
}

TEST_F(MoleCommitmentRegistryTest,
       RejectsOutOfRangeBalanceWidthOrMissingInitialBalance) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  // `balance-width` 0 and 65 are outside `1..=64` (`draft-schlesinger-mole-ec-act-00`).
  EXPECT_FALSE(registry.ParseAndSet(R"({
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "credential-context": ")" +
                                    B64("P") + R"(",
          "credential-key": ")" + B64("MK") +
                                    R"(",
          "balance-width": 65,
          "initial-balance": 4,
          "spend-amount": 1,
          "accepted-anchor-keys": [],
          "epochs": []
        }]
      }
    }
  })"));

  // Missing `initial-balance` is rejected so initial-balance tagging stays closed.
  EXPECT_FALSE(registry.ParseAndSet(R"({
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "credential-context": ")" +
                                    B64("P") + R"(",
          "credential-key": ")" + B64("MK") +
                                    R"(",
          "balance-width": 8,
          "spend-amount": 1,
          "accepted-anchor-keys": [],
          "epochs": []
        }]
      }
    }
  })"));

  // Previous valid state remains intact.
  EXPECT_TRUE(
      registry.GetModeratorCommitment(Origin("https://mod.example")).found);
}

TEST_F(MoleCommitmentRegistryTest, MalformedInputLeavesPreviousStateIntact) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  EXPECT_FALSE(registry.ParseAndSet("this is not json"));
  EXPECT_FALSE(registry.ParseAndSet("[]"));
  EXPECT_FALSE(registry.ParseAndSet(
      R"({"anchors":{"https://a.example":{"keys":["!!not-b64!!"],"epochs":[]}}})"));

  EXPECT_TRUE(
      registry.GetAnchorCommitment(Origin("https://anchor.example")).found);
}

TEST_F(MoleCommitmentRegistryTest, NonHttpsOrOpaqueOriginKeyIsRejected) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  EXPECT_FALSE(registry.ParseAndSet(
      R"({"anchors":{"not a url":{"keys":[],"epochs":[]}}})"));
  EXPECT_FALSE(registry.ParseAndSet(
      R"({"anchors":{"http://insecure.example":{"keys":[],"epochs":[]}}})"));
}

}  // namespace
}  // namespace content
