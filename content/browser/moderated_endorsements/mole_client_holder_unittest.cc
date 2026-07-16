// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_client_holder.h"

#include <memory>
#include <string>

#include "base/files/scoped_temp_dir.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/public/test/browser_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

using moderated_endorsements::MoleBrowserClient;
using moderated_endorsements::TestMoleAnchor;
using moderated_endorsements::TestMoleModerator;

constexpr char kEpoch[] = "epoch-holder-test";
constexpr char kPolicy[] = "policy-holder-test";

rust::Slice<const uint8_t> AsSlice(const std::string& s) {
  return rust::Slice<const uint8_t>(
      reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
rust::Slice<const uint8_t> AsSlice(const rust::Vec<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

// Runs the two-round grant against `anchor`, storing an endorsement in `client`.
bool CollectEndorsement(MoleBrowserClient& client, TestMoleAnchor& anchor) {
  std::string directory(anchor.anchor_directory_json());
  auto begin = client.grant_begin(directory, anchor.anchor_commitment());
  if (!begin.ok) {
    return false;
  }
  auto first = anchor.handle_endorse(AsSlice(begin.request_body));
  if (first.status != 200) {
    return false;
  }
  auto step = client.grant_step(AsSlice(first.body));
  if (!step.ok || step.done) {
    return false;
  }
  auto second = anchor.handle_endorse(AsSlice(step.request_body));
  if (second.status != 200) {
    return false;
  }
  step = client.grant_step(AsSlice(second.body));
  return step.ok && step.done;
}

// Redeems against `mod`, filling `client`'s credential pool; returns pool size.
size_t RedeemAndIssue(MoleBrowserClient& client, TestMoleModerator& mod) {
  auto challenge = mod.handle_resource("");
  auto redeem = client.redeem_begin(std::string(mod.moderator_directory_json()),
                                    challenge.www_authenticate,
                                    mod.moderator_commitment());
  if (!redeem.ok) {
    return 0;
  }
  auto response = mod.handle_resource(std::string(redeem.authorization_header));
  if (response.status != 401 || response.mole_credential.empty()) {
    return 0;
  }
  auto finish = client.redeem_finish(std::string(response.mole_credential));
  return finish.ok ? finish.pool_size : 0;
}

// A test anchor + moderator wired to accept the anchor.
struct TestDeployment {
  rust::Box<TestMoleAnchor> anchor;
  rust::Box<TestMoleModerator> moderator;
};

TestDeployment Deploy() {
  auto anchor = moderated_endorsements::new_test_anchor(AsSlice(std::string(kEpoch)));
  rust::Vec<moderated_endorsements::Blob> accepted;
  moderated_endorsements::Blob real;
  real.bytes = anchor->anchor_public_key();
  accepted.push_back(std::move(real));
  auto moderator = moderated_endorsements::new_test_moderator(
      accepted, AsSlice(std::string(kEpoch)), AsSlice(std::string(kPolicy)),
      /*initial_credits=*/2, /*issuance_batch=*/4, /*charge=*/1, /*refund=*/0);
  return TestDeployment{std::move(anchor), std::move(moderator)};
}

// A filled credential pool persisted to disk in one holder is restored intact
// into a fresh holder rooted at the same profile path.
TEST(MoleClientHolderPersistenceTest, PoolSurvivesReloadFromDisk) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string policy(kPolicy);

  TestDeployment d = Deploy();

  // Session 1: collect an endorsement, redeem into a pool, persist.
  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();  // async load of the (absent) file
    ASSERT_TRUE(holder->loaded_for_testing());

    ASSERT_TRUE(CollectEndorsement(holder->client(), *d.anchor));
    ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 4u);
    EXPECT_EQ(holder->client().pool_size(AsSlice(policy)), 4u);

    holder->SchedulePersist();
    holder.reset();  // destructor flushes the debounced write
    task_environment.RunUntilIdle();  // background atomic write completes
  }

  // Session 2: a fresh holder on the same path restores the pool.
  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();  // async load reads the persisted blob
    ASSERT_TRUE(holder->loaded_for_testing());
    EXPECT_EQ(holder->client().pool_size(AsSlice(policy)), 4u);
  }
}

// ClearAndReset drops in-memory state and wipes the persisted blob, so a later
// reload comes back empty.
TEST(MoleClientHolderPersistenceTest, ClearAndResetWipesState) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string policy(kPolicy);

  TestDeployment d = Deploy();

  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_TRUE(CollectEndorsement(holder->client(), *d.anchor));
    ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 4u);
    holder->SchedulePersist();
    holder.reset();
    task_environment.RunUntilIdle();
  }
  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_EQ(holder->client().pool_size(AsSlice(policy)), 4u);
    holder->ClearAndReset();
    EXPECT_EQ(holder->client().pool_size(AsSlice(policy)), 0u);
    holder.reset();
    task_environment.RunUntilIdle();
  }
  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    EXPECT_EQ(holder->client().pool_size(AsSlice(policy)), 0u);
  }
}

// A browsing-data clear that removes cookies wipes the store; an unrelated
// data type (local storage) leaves it intact.
TEST(MoleClientHolderPersistenceTest, ClearsStoreOnCookieRemoval) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string policy(kPolicy);

  TestDeployment d = Deploy();

  auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
  task_environment.RunUntilIdle();
  ASSERT_TRUE(CollectEndorsement(holder->client(), *d.anchor));
  ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 4u);
  ASSERT_EQ(holder->client().pool_size(AsSlice(policy)), 4u);

  // OnStorageKeyDataCleared overrides a public interface method; reach it
  // through the base pointer.
  auto* observer =
      static_cast<StoragePartition::DataRemovalObserver*>(holder.get());

  // A non-cookie clear leaves the pool untouched.
  observer->OnStorageKeyDataCleared(
      StoragePartition::REMOVE_DATA_MASK_LOCAL_STORAGE,
      StoragePartition::StorageKeyMatcherFunction(), base::Time(),
      base::Time::Max());
  EXPECT_EQ(holder->client().pool_size(AsSlice(policy)), 4u);

  // A cookie clear drops the whole store.
  observer->OnStorageKeyDataCleared(
      StoragePartition::REMOVE_DATA_MASK_COOKIES,
      StoragePartition::StorageKeyMatcherFunction(), base::Time(),
      base::Time::Max());
  EXPECT_EQ(holder->client().pool_size(AsSlice(policy)), 0u);
}

}  // namespace
}  // namespace content
