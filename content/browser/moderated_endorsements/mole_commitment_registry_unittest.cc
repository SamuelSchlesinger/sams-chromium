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

// A registry document naming one anchor (key "AK", epoch "E1") and one
// moderator (policy "P", act key "MK", domain "D", accepted {"AK"}, epoch "E1").
std::string SampleRegistry() {
  return R"({
    "anchors": {
      "https://anchor.example": {
        "keys": [")" + B64("AK") + R"("],
        "epochs": [")" + B64("E1") + R"("]
      }
    },
    "moderators": {
      "https://mod.example": {
        "policies": [{
          "policy-context": ")" + B64("P") + R"(",
          "act-public-key": ")" + B64("MK") + R"(",
          "act-domain-separator": ")" + B64("D") + R"(",
          "accepted-anchor-keys": [")" + B64("AK") + R"("],
          "epochs": [")" + B64("E1") + R"("]
        }]
      }
    }
  })";
}

class MoleCommitmentRegistryTest : public testing::Test {
 protected:
  void SetUp() override { MoleCommitmentRegistry::GetInstance().ClearForTesting(); }
  void TearDown() override {
    MoleCommitmentRegistry::GetInstance().ClearForTesting();
  }
};

TEST_F(MoleCommitmentRegistryTest, ParsesAndReturnsCommittedAnchor) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  auto anchor = registry.GetAnchorCommitment(Origin("https://anchor.example"));
  EXPECT_TRUE(anchor.found);
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
  EXPECT_EQ(std::vector<uint8_t>(p.policy_context.begin(), p.policy_context.end()),
            Bytes("P"));
  EXPECT_EQ(std::vector<uint8_t>(p.act_public_key.begin(), p.act_public_key.end()),
            Bytes("MK"));
  EXPECT_EQ(std::vector<uint8_t>(p.act_domain_separator.begin(),
                                 p.act_domain_separator.end()),
            Bytes("D"));
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
  // A moderator origin is not, by that fact, an anchor origin.
  EXPECT_FALSE(
      registry.GetAnchorCommitment(Origin("https://mod.example")).found);
}

TEST_F(MoleCommitmentRegistryTest, MalformedInputLeavesPreviousStateIntact) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  ASSERT_TRUE(registry.ParseAndSet(SampleRegistry()));

  // Not JSON, a non-object, and a bad-base64 key all fail without clobbering.
  EXPECT_FALSE(registry.ParseAndSet("this is not json"));
  EXPECT_FALSE(registry.ParseAndSet("[]"));
  EXPECT_FALSE(registry.ParseAndSet(
      R"({"anchors":{"https://a.example":{"keys":["!!not-b64!!"],"epochs":[]}}})"));

  EXPECT_TRUE(
      registry.GetAnchorCommitment(Origin("https://anchor.example")).found);
}

TEST_F(MoleCommitmentRegistryTest, OpaqueOriginKeyIsRejected) {
  auto& registry = MoleCommitmentRegistry::GetInstance();
  EXPECT_FALSE(registry.ParseAndSet(
      R"({"anchors":{"not a url":{"keys":[],"epochs":[]}}})"));
}

}  // namespace
}  // namespace content
