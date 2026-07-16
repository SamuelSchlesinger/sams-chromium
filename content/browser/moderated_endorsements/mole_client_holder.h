// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_CLIENT_HOLDER_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_CLIENT_HOLDER_H_

#include <optional>
#include <vector>

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

// Owns the MoLE client state (endorsement store + per-policy ACT credential
// pools) for a BrowserContext, and persists it to disk. The durable state is
// serialized to an opaque, secret-bearing blob via base::ImportantFileWriter
// (debounced, atomic writes on a background sequence) and restored
// asynchronously at construction. Because endorsements collected on one site
// answer challenges on another, this state is BrowserContext-wide (not scoped
// to a StorageKey); it is dropped on a full browsing-data clear via
// ClearAndReset(), driven by observing the default StoragePartition's data
// removal (see OnStorageKeyDataCleared).
class CONTENT_EXPORT MoleClientHolder
    : public base::SupportsUserData::Data,
      public base::ImportantFileWriter::BackgroundDataSerializer,
      public StoragePartition::DataRemovalObserver {
 public:
  explicit MoleClientHolder(const base::FilePath& profile_path);
  MoleClientHolder(const MoleClientHolder&) = delete;
  MoleClientHolder& operator=(const MoleClientHolder&) = delete;
  ~MoleClientHolder() override;

  // Returns the per-BrowserContext holder, constructing it (and starting the
  // async load of its persisted state) on first use.
  static MoleClientHolder& GetOrCreate(BrowserContext* browser_context);

  moderated_endorsements::MoleBrowserClient& client() { return *client_; }

  // Runs `op` once the on-disk state has loaded (immediately if already
  // loaded). Entry points that touch the client MUST route through this so no
  // operation observes a not-yet-restored client (the use-before-load race).
  void PostWhenLoaded(base::OnceClosure op);

  // Debounced atomic persist of the current durable state. Call after any
  // successful state mutation (new endorsement, filled pool, spent/refunded
  // credential).
  void SchedulePersist();

  // Drop the persisted and in-memory state (for a full browsing-data clear).
  void ClearAndReset();

  bool loaded_for_testing() const { return loaded_; }

  // BrowserContext-wide Redeem & Issue coordination (one redemption at a time).
  bool redeem_in_flight = false;
  std::vector<base::OnceClosure> pool_waiters;

 private:
  // StoragePartition::DataRemovalObserver: a browsing-data clear that removes
  // cookies wipes the whole MoLE store. MoLE credentials are unlinkable,
  // cross-site material with no owning StorageKey, so they cannot be cleared
  // selectively; any cookie clear conservatively drops all of it (fail-closed
  // — the user re-collects endorsements as needed). `storage_key_matcher`,
  // `begin`, and `end` are therefore not consulted.
  void OnStorageKeyDataCleared(
      uint32_t remove_mask,
      StoragePartition::StorageKeyMatcherFunction storage_key_matcher,
      base::Time begin,
      base::Time end) override;

  // base::ImportantFileWriter::BackgroundDataSerializer: snapshots the state on
  // the calling (UI) thread and returns a producer that pushes the bytes on the
  // background sequence.
  base::ImportantFileWriter::BackgroundDataProducerCallback
  GetSerializedDataProducerForBackgroundSequence() override;

  // Reply from the async load: restore the client if a blob was read, then
  // flip `loaded_` and drain the deferred operations.
  void OnLoaded(std::optional<std::vector<uint8_t>> bytes);

  scoped_refptr<base::SequencedTaskRunner> backend_task_runner_;
  base::ImportantFileWriter writer_;
  rust::Box<moderated_endorsements::MoleBrowserClient> client_;
  bool loaded_ = false;
  std::vector<base::OnceClosure> load_waiters_;
  base::WeakPtrFactory<MoleClientHolder> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MOLE_CLIENT_HOLDER_H_
