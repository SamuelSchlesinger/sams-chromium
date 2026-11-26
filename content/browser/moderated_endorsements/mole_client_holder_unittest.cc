// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_client_holder.h"

#include <memory>
#include <string>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/run_loop.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/public/test/browser_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

using moderated_endorsements::MoleBrowserClient;
using moderated_endorsements::TestMoleAnchor;
using moderated_endorsements::TestMoleModerator;

constexpr char kAnchorOrigin[] = "https://anchor.example";
constexpr char kModeratorOrigin[] = "https://moderator.example";
constexpr char kResourceUrl[] = "https://moderator.example/gate";
constexpr char kEpoch[] = "epoch-holder-test";
constexpr char kContext[] = "context-holder-test";

rust::Slice<const uint8_t> AsSlice(const std::string& s) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                    s.size());
}

rust::Slice<const uint8_t> AsSlice(const rust::Vec<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

bool CollectEndorsementBatch(MoleBrowserClient& client,
                             TestMoleAnchor& anchor,
                             uint16_t batch_count = 4) {
  std::string cfg(anchor.anchor_config_json());
  auto begin = client.grant_begin(kAnchorOrigin, cfg,
                                  anchor.anchor_commitment(), batch_count);
  if (!begin.ok) {
    return false;
  }
  auto first = anchor.handle_grant(std::string(begin.content_type),
                                   AsSlice(begin.request_body));
  if (first.status != 200) {
    return false;
  }
  auto step = client.grant_step(begin.grant_id, std::string(first.content_type),
                                AsSlice(first.body));
  if (!step.ok || step.done) {
    return false;
  }
  auto second = anchor.handle_grant(std::string(step.content_type),
                                    AsSlice(step.request_body));
  if (second.status != 200) {
    return false;
  }
  step = client.grant_step(begin.grant_id, std::string(second.content_type),
                           AsSlice(second.body));
  return step.ok && step.done;
}

size_t RedeemAndIssue(MoleBrowserClient& client, TestMoleModerator& mod) {
  auto challenge = mod.handle_resource("");
  auto redeem = client.redeem_begin(
      kModeratorOrigin, std::string(mod.moderator_config_json()),
      challenge.www_authenticate, mod.moderator_commitment());
  if (!redeem.ok) {
    return 0;
  }
  auto response = mod.handle_issue(std::string(redeem.authorization_header));
  if (response.status != 200 || response.mole_credential.empty()) {
    return 0;
  }
  auto finish = client.redeem_finish(redeem.redeem_id,
                                     std::string(response.mole_credential));
  return finish.ok ? finish.pool_size : 0;
}

struct TestDeployment {
  rust::Box<TestMoleAnchor> anchor;
  rust::Box<TestMoleModerator> moderator;
};

TestDeployment Deploy() {
  auto anchor = moderated_endorsements::new_test_anchor(
      kAnchorOrigin, AsSlice(std::string(kEpoch)));
  rust::Vec<moderated_endorsements::Blob> accepted;
  moderated_endorsements::Blob real;
  real.bytes = anchor->anchor_public_key();
  accepted.push_back(std::move(real));
  auto moderator = moderated_endorsements::new_test_moderator(
      kModeratorOrigin, accepted, AsSlice(std::string(kEpoch)),
      AsSlice(std::string(kContext)),
      /*balance_width=*/8, /*initial_balance=*/4, /*spend_amount=*/1,
      /*max_top_up=*/0, /*refund_amount=*/1);
  return TestDeployment{std::move(anchor), std::move(moderator)};
}

TEST(MoleClientHolderPersistenceTest, PoolAndEndorsementsSurviveReload) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string context(kContext);

  TestDeployment d = Deploy();

  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_TRUE(holder->loaded_for_testing());
    EXPECT_FALSE(holder->is_ephemeral_for_testing());

    ASSERT_TRUE(CollectEndorsementBatch(holder->client(), *d.anchor, 4));
    ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 1u);
    EXPECT_EQ(holder->client().endorsement_count(), 3u);
    EXPECT_EQ(holder->client().balance(kModeratorOrigin, AsSlice(context)), 4u);

    holder->SchedulePersist();
    holder.reset();
    task_environment.RunUntilIdle();
  }

  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_TRUE(holder->loaded_for_testing());
    EXPECT_EQ(holder->client().endorsement_count(), 3u);
    EXPECT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)),
              1u);
    EXPECT_EQ(holder->client().balance(kModeratorOrigin, AsSlice(context)), 4u);
  }
}

TEST(MoleClientHolderPersistenceTest,
     WriteAheadPersistBeforeSendSurvivesCrashAndRecovers) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string context(kContext);

  TestDeployment d = Deploy();
  std::string sent_auth_header;

  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_TRUE(CollectEndorsementBatch(holder->client(), *d.anchor, 1));
    ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 1u);

    auto challenge = d.moderator->handle_resource("");
    auto present = holder->client().present_begin(
        kModeratorOrigin, kResourceUrl, challenge.www_authenticate,
        d.moderator->moderator_commitment(), /*now_unix_secs=*/1000);
    ASSERT_TRUE(present.ok);
    sent_auth_header = std::string(present.authorization_header);

    base::RunLoop wal_loop;
    holder->PersistBeforeSend(wal_loop.QuitClosure());
    wal_loop.Run();
    // Simulate sudden process crash before `present_finish` runs (no destructor
    // write needed because `PersistBeforeSend` already flushed atomically).
  }

  // Moderator processed the request and recorded the refund (+1 => balance 4).
  auto mod_resp = d.moderator->handle_resource(sent_auth_header);
  ASSERT_EQ(mod_resp.status, 200);

  // Fresh session restores the write-ahead `PendingSpend` and recovers via
  // `POST /mole/issue` (`Authorization: Mole recovery-0001=...`).
  auto restarted = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
  task_environment.RunUntilIdle();
  EXPECT_EQ(restarted->client().pending_spend_count(), 1u);
  EXPECT_EQ(restarted->client().pool_size(kModeratorOrigin, AsSlice(context)),
            0u);

  auto settlement =
      restarted->client().next_settlement(kModeratorOrigin, /*now=*/1005);
  ASSERT_TRUE(settlement.has_pending);
  EXPECT_FALSE(settlement.is_signoff);
  auto settle_resp =
      d.moderator->handle_issue(std::string(settlement.authorization_header));
  ASSERT_EQ(settle_resp.status, 200);
  auto outcome = restarted->client().settle_finish(
      settlement.pending_id, settle_resp.status,
      std::string(settle_resp.mole_credential));
  ASSERT_TRUE(outcome.ok && outcome.credential_restored);
  EXPECT_EQ(restarted->client().balance(kModeratorOrigin, AsSlice(context)),
            4u);
}

TEST(MoleClientHolderPersistenceTest,
     OffTheRecordEmptyPathNeverReadsOrWritesDisk) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  TestDeployment d = Deploy();

  // Ephemeral holder (as constructed for OffTheRecord BrowserContexts).
  auto otr_holder = std::make_unique<MoleClientHolder>(base::FilePath());
  EXPECT_TRUE(otr_holder->loaded_for_testing());
  EXPECT_TRUE(otr_holder->is_ephemeral_for_testing());
  ASSERT_TRUE(CollectEndorsementBatch(otr_holder->client(), *d.anchor, 2));

  bool flushed = false;
  otr_holder->PersistBeforeSend(
      base::BindOnce([](bool* f) { *f = true; }, &flushed));
  EXPECT_TRUE(flushed);
  otr_holder->SchedulePersist();
  otr_holder.reset();
  task_environment.RunUntilIdle();

  EXPECT_FALSE(
      base::PathExists(temp_dir.GetPath().AppendASCII("MoleClientState")));
}

TEST(MoleClientHolderPersistenceTest, ClearAndResetWipesState) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string context(kContext);

  TestDeployment d = Deploy();

  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_TRUE(CollectEndorsementBatch(holder->client(), *d.anchor, 2));
    ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 1u);
    holder->SchedulePersist();
    holder.reset();
    task_environment.RunUntilIdle();
  }
  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    ASSERT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)),
              1u);
    holder->ClearAndReset();
    EXPECT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)),
              0u);
    holder.reset();
    task_environment.RunUntilIdle();
  }
  {
    auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
    task_environment.RunUntilIdle();
    EXPECT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)),
              0u);
  }
}

TEST(MoleClientHolderPersistenceTest, ClearsStoreOnCookieRemoval) {
  BrowserTaskEnvironment task_environment;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const std::string context(kContext);

  TestDeployment d = Deploy();

  auto holder = std::make_unique<MoleClientHolder>(temp_dir.GetPath());
  task_environment.RunUntilIdle();
  ASSERT_TRUE(CollectEndorsementBatch(holder->client(), *d.anchor, 1));
  ASSERT_EQ(RedeemAndIssue(holder->client(), *d.moderator), 1u);
  ASSERT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)), 1u);

  auto* observer =
      static_cast<StoragePartition::DataRemovalObserver*>(holder.get());
  observer->OnStorageKeyDataCleared(
      StoragePartition::REMOVE_DATA_MASK_LOCAL_STORAGE,
      StoragePartition::StorageKeyMatcherFunction(), base::Time(),
      base::Time::Max());
  EXPECT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)), 1u);

  observer->OnStorageKeyDataCleared(
      StoragePartition::REMOVE_DATA_MASK_COOKIES,
      StoragePartition::StorageKeyMatcherFunction(), base::Time(),
      base::Time::Max());
  EXPECT_EQ(holder->client().pool_size(kModeratorOrigin, AsSlice(context)), 0u);
}

TEST(MoleClientHolderPersistenceTest,
     PerModeratorFlightsSerializeSameOriginAndParallelizeDistinctOrigins) {
  BrowserTaskEnvironment task_environment;
  MoleClientHolder holder{base::FilePath()};

  bool resumed_same_1 = false;
  bool resumed_same_2 = false;
  auto f1 = holder.TryAcquireModeratorFlight("https://mod-a.example");
  ASSERT_TRUE(f1.has_value());

  // A different Moderator acquires immediately in parallel.
  auto f_other = holder.TryAcquireModeratorFlight("https://mod-b.example");
  ASSERT_TRUE(f_other.has_value());

  // Contenders on `mod-a.example` fail TryAcquire and queue in FIFO order.
  EXPECT_FALSE(
      holder.TryAcquireModeratorFlight("https://mod-a.example").has_value());
  holder.EnqueueModeratorWaiter(
      "https://mod-a.example",
      base::BindOnce([](bool* b) { *b = true; }, &resumed_same_1));
  holder.EnqueueModeratorWaiter(
      "https://mod-a.example",
      base::BindOnce([](bool* b) { *b = true; }, &resumed_same_2));

  // Releasing `f1` wakes ONLY the first queued contender (`resumed_same_1`).
  f1->Release();
  task_environment.RunUntilIdle();
  EXPECT_TRUE(resumed_same_1);
  EXPECT_FALSE(resumed_same_2);

  // Once the woken contender acquires and releases, `resumed_same_2` wakes.
  auto f2 = holder.TryAcquireModeratorFlight("https://mod-a.example");
  ASSERT_TRUE(f2.has_value());
  f2.reset();
  task_environment.RunUntilIdle();
  EXPECT_TRUE(resumed_same_2);
}

}  // namespace
}  // namespace content
