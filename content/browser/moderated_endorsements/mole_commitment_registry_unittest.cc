// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_commitment_registry.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {
namespace {

class MoleCommitmentRegistryTest : public testing::Test {
 protected:
  void TearDown() override {
    MoleCommitmentRegistry::GetInstance().ClearForTesting();
  }
};

TEST_F(MoleCommitmentRegistryTest, ParsesSplitPolicyAndEnforcesMinThreeAnchors) {
  auto& reg = MoleCommitmentRegistry::GetInstance();

  // Fewer than 3 anchors must be rejected fail-closed!
  constexpr char kTwoAnchorsJson[] = R"({
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "policy-id": "p1",
          "credential-context": "Y3R4LTE",
          "credential-key": "AQID",
          "clearance-public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "balance-width": 8,
          "initial-balance": 10,
          "spend-amount": 1,
          "max-top-up": 2,
          "accepted-anchor-keys": ["AQID", "BAUG"],
          "epochs": ["MjAyNi0xMQ"]
        }]
      }
    }
  })";
  EXPECT_FALSE(reg.ParseAndSet(kTwoAnchorsJson));

  // Valid Split commitment with 3 anchors, `L=16`, `allowed-refund-amounts`,
  // and `allowed-sites` succeeds.
  constexpr char kValidSplitJson[] = R"({
    "anchors": {
      "https://anchor1.example": {
        "grant-uri": "https://anchor1.example/mole/grant",
        "keys": ["AQID"],
        "epochs": ["MjAyNi0xMQ"]
      }
    },
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "policy-id": "checkout-v2",
          "credential-context": "Y3R4LTE",
          "credential-key": "AQID",
          "clearance-public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "balance-width": 16,
          "initial-balance": 1000,
          "spend-amount": 10,
          "max-top-up": 20,
          "allowed-refund-amounts": [0, 10, 30],
          "min-anchor-set-size": 3,
          "accepted-anchor-keys": ["AQID", "BAUG", "BwgJ"],
          "epochs": ["MjAyNi0xMQ"],
          "allowed-sites": ["https://shoes.example", "https://socks.example"],
          "issuance-uri": "https://mod.example/mole/v1/issue",
          "present-uri": "https://mod.example/mole/v1/present",
          "settle-uri": "https://mod.example/mole/v1/settle"
        }]
      }
    }
  })";
  ASSERT_TRUE(reg.ParseAndSet(kValidSplitJson));

  const auto anchor = reg.GetAnchorCommitment(
      url::Origin::Create(GURL("https://anchor1.example")));
  EXPECT_TRUE(anchor.found);

  const auto policy = reg.FindCommittedPolicy(
      url::Origin::Create(GURL("https://mod.example")), "checkout-v2");
  ASSERT_TRUE(policy.has_value());
  EXPECT_EQ(policy->balance_width, 16u);
  EXPECT_EQ(policy->accepted_anchor_keys.size(), 3u);
  EXPECT_EQ(policy->allowed_refund_amounts.size(), 3u);
  EXPECT_EQ(policy->allowed_sites.size(), 2u);
  EXPECT_EQ(std::string(policy->present_uri),
            "https://mod.example/mole/v1/present");
}

TEST_F(MoleCommitmentRegistryTest, RejectsOversizedBalanceWidthAtomically) {
  auto& reg = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(reg.ParseAndSet(R"({
    "anchors": {
      "https://anchor.example": {
        "keys": ["AQID"],
        "epochs": ["MjAyNi0xMQ"]
      }
    }
  })"));

  // `balance-width > 16` is rejected and preserves the existing anchor entry.
  EXPECT_FALSE(reg.ParseAndSet(R"({
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "credential-context": "Y3R4",
          "credential-key": "AQID",
          "balance-width": 32,
          "initial-balance": 10,
          "spend-amount": 1,
          "accepted-anchor-keys": ["AQID", "BAUG", "BwgJ"],
          "epochs": ["MjAyNi0xMQ"]
        }]
      }
    }
  })"));

  EXPECT_TRUE(
      reg.GetAnchorCommitment(
             url::Origin::Create(GURL("https://anchor.example")))
          .found);
}

TEST_F(MoleCommitmentRegistryTest,
       SupportsWildcardAllowedSitesAndRejectsTopUpOverflow) {
  auto& reg = MoleCommitmentRegistry::GetInstance();

  // Wildcard `"*"` in `allowed-sites` is accepted and preserved.
  ASSERT_TRUE(reg.ParseAndSet(R"({
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "policy-id": "wildcard-v1",
          "credential-context": "Y3R4",
          "credential-key": "AQID",
          "clearance-public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "balance-width": 8,
          "initial-balance": 200,
          "spend-amount": 5,
          "max-top-up": 50,
          "accepted-anchor-keys": ["AQID", "BAUG", "BwgJ"],
          "epochs": ["MjAyNi0xMQ"],
          "allowed-sites": ["*"]
        }]
      }
    }
  })"));
  const auto wildcard_policy = reg.FindCommittedPolicy(
      url::Origin::Create(GURL("https://mod.example")), "wildcard-v1");
  ASSERT_TRUE(wildcard_policy.has_value());
  ASSERT_EQ(wildcard_policy->allowed_sites.size(), 1u);
  EXPECT_EQ(std::string(wildcard_policy->allowed_sites[0]), "*");

  // `initial_balance + max_top_up > 255` (`L=8`) must be rejected fail-closed.
  EXPECT_FALSE(reg.ParseAndSet(R"({
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "policy-id": "overflow-v1",
          "credential-context": "Y3R4",
          "credential-key": "AQID",
          "balance-width": 8,
          "initial-balance": 200,
          "spend-amount": 5,
          "max-top-up": 60,
          "accepted-anchor-keys": ["AQID", "BAUG", "BwgJ"],
          "epochs": ["MjAyNi0xMQ"]
        }]
      }
    }
  })"));
}

}  // namespace
}  // namespace content
