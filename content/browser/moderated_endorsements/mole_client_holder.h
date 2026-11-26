// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_CLIENT_HOLDER_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_CLIENT_HOLDER_H_

#include <optional>
#include <string>
#include <vector>

#include "base/containers/flat_map.h"
#include "base/files/file_path.h"
#include "base/files/important_file_writer.h"
#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/supports_user_data.h"
#include "base/time/time.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/common/content_export.h"
#include "content/public/browser/storage_partition.h"

namespace base {
class SequencedTaskRunner;
}  // namespace base

namespace content {

class BrowserContext;

// Owns the MOLE client state (endorsement store, per-policy EC-ACT credential
// pools, and write-ahead `PendingSpend` recovery records) for a
// `BrowserContext`.
//
// Persistence & OffTheRecord isolation:
// - Regular profiles pass `browser_context->GetPath()` and persist state to
//   `<profile>/MoleClientState` via `base::ImportantFileWriter` on a sequenced
//   background runner.
// - OffTheRecord (Incognito / Guest) profiles pass an empty `base::FilePath()`:
//   `writer_` remains `std::nullopt`, `loaded_` starts `true`, and zero disk
//   reads or writes ever occur — preventing cross-session endorsement/credential
//   leakage in either direction between regular and Incognito windows.
// - Before sending `Authorization: Mole presentation-0001` over the network,
//   callers invoke `PersistBeforeSend(...)`, which atomically writes and
//   flushes the updated `PendingSpend` record before running its continuation
//   (`draft-jms-mole-protocols-01` §5.2.3).
class CONTENT_EXPORT MoleClientHolder
    : public base::SupportsUserData::Data,
      public base::ImportantFileWriter::BackgroundDataSerializer,
      public StoragePartition::DataRemovalObserver {
 public:
  // RAII token representing exclusive ownership of a Moderator origin's
  // challenge/settlement/redemption/presentation pipeline. Releases the slot
  // and wakes the next queued challenge automatically on destruction (including
  // if the owning document is torn down mid-flight).
  class CONTENT_EXPORT ScopedModeratorFlight {
   public:
    ScopedModeratorFlight();
    ScopedModeratorFlight(base::WeakPtr<MoleClientHolder> holder,
                          std::string moderator_origin);
    ScopedModeratorFlight(ScopedModeratorFlight&& other) noexcept;
    ScopedModeratorFlight& operator=(ScopedModeratorFlight&& other) noexcept;
    ScopedModeratorFlight(const ScopedModeratorFlight&) = delete;
    ScopedModeratorFlight& operator=(const ScopedModeratorFlight&) = delete;
    ~ScopedModeratorFlight();

    void Release();

   private:
    base::WeakPtr<MoleClientHolder> holder_;
    std::string moderator_origin_;
  };

  explicit MoleClientHolder(const base::FilePath& profile_path);
  MoleClientHolder(const MoleClientHolder&) = delete;
  MoleClientHolder& operator=(const MoleClientHolder&) = delete;
  ~MoleClientHolder() override;

  // Returns the per-BrowserContext holder, constructing it on first use.
  // OffTheRecord BrowserContexts receive an ephemeral in-memory holder.
  static MoleClientHolder& GetOrCreate(BrowserContext* browser_context);

  moderated_endorsements::MoleBrowserClient& client() { return *client_; }

  // Runs `op` once the on-disk state has loaded (immediately if already loaded
  // or if OffTheRecord/in-memory).
  void PostWhenLoaded(base::OnceClosure op);

  // Debounced atomic persist of the current durable state. No-op when
  // OffTheRecord (`profile_path` empty).
  void SchedulePersist();

  // Immediately snapshots and atomically flushes durable client state on the
  // background sequence before invoking `after_flush` on the UI sequence.
  // Required before transmitting `presentation-0001` so `PendingSpend` survives
  // crashes (`draft-jms-mole-protocols-01` §5.2.3). Runs `after_flush`
  // immediately when OffTheRecord (`!writer_`).
  void PersistBeforeSend(base::OnceClosure after_flush);

  // Claims exclusive execution for `moderator_origin` if idle; returns
  // `std::nullopt` when another flight for the same `moderator_origin` is
  // already active (call `EnqueueModeratorWaiter` to run once it finishes).
  // Flights to distinct Moderators run in parallel.
  std::optional<ScopedModeratorFlight> TryAcquireModeratorFlight(
      const std::string& moderator_origin);
  void EnqueueModeratorWaiter(const std::string& moderator_origin,
                              base::OnceClosure resume);

  // Drops the persisted and in-memory state (for a browsing-data clear).
  void ClearAndReset();

  bool loaded_for_testing() const { return loaded_; }
  bool is_ephemeral_for_testing() const { return !writer_.has_value(); }

 private:
  struct ModeratorFlightQueue {
    bool in_flight = false;
    std::vector<base::OnceClosure> waiters;
  };

  void ReleaseModeratorFlight(const std::string& moderator_origin);

  // StoragePartition::DataRemovalObserver:
  void OnStorageKeyDataCleared(
      uint32_t remove_mask,
      StoragePartition::StorageKeyMatcherFunction storage_key_matcher,
      base::Time begin,
      base::Time end) override;

  // base::ImportantFileWriter::BackgroundDataSerializer:
  base::ImportantFileWriter::BackgroundDataProducerCallback
  GetSerializedDataProducerForBackgroundSequence() override;

  void OnLoaded(std::optional<std::vector<uint8_t>> bytes);

  scoped_refptr<base::SequencedTaskRunner> backend_task_runner_;
  std::optional<base::ImportantFileWriter> writer_;
  rust::Box<moderated_endorsements::MoleBrowserClient> client_;
  bool loaded_ = false;
  std::vector<base::OnceClosure> load_waiters_;
  base::flat_map<std::string, ModeratorFlightQueue> moderator_flights_;
  base::WeakPtrFactory<MoleClientHolder> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_CLIENT_HOLDER_H_
