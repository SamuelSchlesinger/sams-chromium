// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/mole_client_holder.h"

#include <string>
#include <utility>

#include "base/files/file_util.h"
#include "base/functional/bind.h"
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

// How long to coalesce a burst of state changes into a single disk write.
constexpr base::TimeDelta kPersistDelay = base::Seconds(5);

// Runs on the backend sequence: read the persisted blob, or nullopt when it is
// absent or unreadable (a fresh profile, or a wiped file).
std::optional<std::vector<uint8_t>> ReadStateOnBackend(
    const base::FilePath& path) {
  std::string contents;
  if (!base::ReadFileToString(path, &contents)) {
    return std::nullopt;
  }
  return std::vector<uint8_t>(contents.begin(), contents.end());
}

}  // namespace

MoleClientHolder::MoleClientHolder(const base::FilePath& profile_path)
    : backend_task_runner_(base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
           base::TaskShutdownBehavior::BLOCK_SHUTDOWN})),
      writer_(profile_path.Append(kStateFileName),
              backend_task_runner_,
              kPersistDelay,
              "MoleClientState"),
      client_(moderated_endorsements::new_mole_browser_client()) {
  backend_task_runner_->PostTaskAndReplyWithResult(
      FROM_HERE, base::BindOnce(&ReadStateOnBackend, writer_.path()),
      base::BindOnce(&MoleClientHolder::OnLoaded, weak_factory_.GetWeakPtr()));
}

MoleClientHolder::~MoleClientHolder() {
  // Flush any debounced write so a pending state change is not lost at
  // shutdown (the backend runner is BLOCK_SHUTDOWN).
  if (writer_.HasPendingWrite()) {
    writer_.DoScheduledWrite();
  }
}

// static
MoleClientHolder& MoleClientHolder::GetOrCreate(
    BrowserContext* browser_context) {
  auto* holder = static_cast<MoleClientHolder*>(
      browser_context->GetUserData(kMoleClientHolderKey));
  if (!holder) {
    auto owned = std::make_unique<MoleClientHolder>(browser_context->GetPath());
    holder = owned.get();
    browser_context->SetUserData(kMoleClientHolderKey, std::move(owned));
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
  writer_.ScheduleWriteWithBackgroundDataSerializer(this);
}

void MoleClientHolder::ClearAndReset() {
  client_ = moderated_endorsements::new_mole_browser_client();
  // Persist the now-empty state, overwriting the on-disk blob.
  SchedulePersist();
}

base::ImportantFileWriter::BackgroundDataProducerCallback
MoleClientHolder::GetSerializedDataProducerForBackgroundSequence() {
  // Snapshot the durable state on the UI thread; push the bytes on the backend.
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
    // A corrupt blob leaves the fresh client untouched (restore_state returns
    // false without mutating), which self-heals rather than wedging.
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
