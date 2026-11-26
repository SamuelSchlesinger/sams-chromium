// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_client_holder.h"

#include <utility>

#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "content/public/browser/browser_context.h"

namespace content {

namespace {

const char kMoleClientHolderKey[] = "moderated-endorsements-mole-client";

constexpr base::FilePath::CharType kStateFileName[] =
    FILE_PATH_LITERAL("MoleClientState");

// How long to coalesce non-critical state mutations into a single disk write.
constexpr base::TimeDelta kPersistDelay = base::Seconds(5);

std::optional<std::vector<uint8_t>> ReadStateOnBackend(
    const base::FilePath& path) {
  std::string contents;
  if (!base::ReadFileToString(path, &contents)) {
    return std::nullopt;
  }
  return std::vector<uint8_t>(contents.begin(), contents.end());
}

}  // namespace

MoleClientHolder::ScopedModeratorFlight::ScopedModeratorFlight() = default;

MoleClientHolder::ScopedModeratorFlight::ScopedModeratorFlight(
    base::WeakPtr<MoleClientHolder> holder,
    std::string moderator_origin)
    : holder_(std::move(holder)),
      moderator_origin_(std::move(moderator_origin)) {}

MoleClientHolder::ScopedModeratorFlight::ScopedModeratorFlight(
    ScopedModeratorFlight&& other) noexcept
    : holder_(std::move(other.holder_)),
      moderator_origin_(std::move(other.moderator_origin_)) {
  other.holder_.reset();
  other.moderator_origin_.clear();
}

MoleClientHolder::ScopedModeratorFlight&
MoleClientHolder::ScopedModeratorFlight::operator=(
    ScopedModeratorFlight&& other) noexcept {
  if (this != &other) {
    Release();
    holder_ = std::move(other.holder_);
    moderator_origin_ = std::move(other.moderator_origin_);
    other.holder_.reset();
    other.moderator_origin_.clear();
  }
  return *this;
}

MoleClientHolder::ScopedModeratorFlight::~ScopedModeratorFlight() {
  Release();
}

void MoleClientHolder::ScopedModeratorFlight::Release() {
  if (holder_ && !moderator_origin_.empty()) {
    std::string origin = std::move(moderator_origin_);
    moderator_origin_.clear();
    MoleClientHolder* holder = holder_.get();
    holder_.reset();
    holder->ReleaseModeratorFlight(origin);
  } else {
    holder_.reset();
    moderator_origin_.clear();
  }
}

MoleClientHolder::MoleClientHolder(const base::FilePath& profile_path)
    : client_(moderated_endorsements::new_mole_browser_client()) {
  if (profile_path.empty()) {
    // Ephemeral / OffTheRecord BrowserContext: never read or write on-disk
    // state.
    loaded_ = true;
    return;
  }

  backend_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
       base::TaskShutdownBehavior::BLOCK_SHUTDOWN});
  writer_.emplace(profile_path.Append(kStateFileName), backend_task_runner_,
                  kPersistDelay, "MoleClientState");
  backend_task_runner_->PostTaskAndReplyWithResult(
      FROM_HERE, base::BindOnce(&ReadStateOnBackend, writer_->path()),
      base::BindOnce(&MoleClientHolder::OnLoaded, weak_factory_.GetWeakPtr()));
}

MoleClientHolder::~MoleClientHolder() {
  if (writer_ && writer_->HasPendingWrite()) {
    writer_->DoScheduledWrite();
  }
}

// static
MoleClientHolder& MoleClientHolder::GetOrCreate(
    BrowserContext* browser_context) {
  auto* holder = static_cast<MoleClientHolder*>(
      browser_context->GetUserData(kMoleClientHolderKey));
  if (!holder) {
    // OffTheRecord profiles frequently share `GetPath()` with their parent
    // regular profile; pass an empty path so Incognito/Guest contexts stay
    // strictly in-memory and isolated from regular-profile state.
    const base::FilePath storage_dir = browser_context->IsOffTheRecord()
                                           ? base::FilePath()
                                           : browser_context->GetPath();
    auto owned = std::make_unique<MoleClientHolder>(storage_dir);
    holder = owned.get();
    browser_context->SetUserData(kMoleClientHolderKey, std::move(owned));
    browser_context->GetDefaultStoragePartition()->AddObserver(holder);
  }
  return *holder;
}

void MoleClientHolder::PostWhenLoaded(base::OnceClosure op) {
  if (loaded_) {
    std::move(op).Run();
  } else {
    load_waiters_.push_back(std::move(op));
  }
}

void MoleClientHolder::SchedulePersist() {
  if (writer_) {
    writer_->ScheduleWriteWithBackgroundDataSerializer(this);
  }
}

void MoleClientHolder::PersistBeforeSend(base::OnceClosure after_flush) {
  if (!writer_) {
    std::move(after_flush).Run();
    return;
  }
  rust::Vec<uint8_t> blob = client_->serialize_state();
  std::string data(blob.begin(), blob.end());
  // `WriteNow` cancels any pending debounced timer and posts an atomic
  // temp-file write + fsync + rename onto `backend_task_runner_`. Because
  // `backend_task_runner_` is a `SequencedTaskRunner`, the barrier task below
  // replies on the UI thread strictly after that atomic write completes, and
  // concurrent flushes for distinct Moderators never clobber one another's
  // callbacks.
  writer_->WriteNow(std::move(data));
  backend_task_runner_->PostTaskAndReply(FROM_HERE, base::DoNothing(),
                                         std::move(after_flush));
}

std::optional<MoleClientHolder::ScopedModeratorFlight>
MoleClientHolder::TryAcquireModeratorFlight(
    const std::string& moderator_origin) {
  ModeratorFlightQueue& queue = moderator_flights_[moderator_origin];
  if (queue.in_flight) {
    return std::nullopt;
  }
  queue.in_flight = true;
  return ScopedModeratorFlight(weak_factory_.GetWeakPtr(), moderator_origin);
}

void MoleClientHolder::EnqueueModeratorWaiter(
    const std::string& moderator_origin,
    base::OnceClosure resume) {
  ModeratorFlightQueue& queue = moderator_flights_[moderator_origin];
  if (!queue.in_flight) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(FROM_HERE,
                                                             std::move(resume));
    return;
  }
  queue.waiters.push_back(std::move(resume));
}

void MoleClientHolder::ReleaseModeratorFlight(
    const std::string& moderator_origin) {
  auto it = moderator_flights_.find(moderator_origin);
  if (it == moderator_flights_.end()) {
    return;
  }
  it->second.in_flight = false;
  if (it->second.waiters.empty()) {
    moderator_flights_.erase(it);
    return;
  }
  base::OnceClosure next = std::move(it->second.waiters.front());
  it->second.waiters.erase(it->second.waiters.begin());
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(FROM_HERE,
                                                           std::move(next));
}

void MoleClientHolder::ClearAndReset() {
  client_ = moderated_endorsements::new_mole_browser_client();
  SchedulePersist();
}

void MoleClientHolder::OnStorageKeyDataCleared(
    uint32_t remove_mask,
    StoragePartition::StorageKeyMatcherFunction storage_key_matcher,
    base::Time begin,
    base::Time end) {
  if (remove_mask & StoragePartition::REMOVE_DATA_MASK_COOKIES) {
    ClearAndReset();
  }
}

base::ImportantFileWriter::BackgroundDataProducerCallback
MoleClientHolder::GetSerializedDataProducerForBackgroundSequence() {
  rust::Vec<uint8_t> blob = client_->serialize_state();
  std::string data(blob.begin(), blob.end());
  return base::BindOnce(
      [](std::string data) -> std::optional<std::string> {
        return std::move(data);
      },
      std::move(data));
}

void MoleClientHolder::OnLoaded(std::optional<std::vector<uint8_t>> bytes) {
  if (bytes && !bytes->empty()) {
    client_->restore_state(
        rust::Slice<const uint8_t>(bytes->data(), bytes->size()));
  }
  loaded_ = true;
  std::vector<base::OnceClosure> waiters = std::move(load_waiters_);
  load_waiters_.clear();
  for (auto& waiter : waiters) {
    std::move(waiter).Run();
  }
}

}  // namespace content
