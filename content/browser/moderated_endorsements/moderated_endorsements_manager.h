// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_MANAGER_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_MANAGER_H_

#include <array>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/containers/flat_map.h"
#include "base/files/file_path.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "components/moderated_endorsements/moderated_endorsements_store.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/common/content_export.h"
#include "content/public/browser/global_routing_id.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/unique_receiver_set.h"
#include "services/network/public/mojom/moderated_endorsements.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "storage/browser/quota/special_storage_policy.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/moderated_endorsements/moderated_endorsements.mojom.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace network {
class SharedURLLoaderFactory;
class SimpleURLLoader;
}  // namespace network

namespace content {

class BrowserContext;
class BrowsingDataFilterBuilder;
class StoragePartitionImpl;

// Per-`StoragePartition` coordinator for Moderated Endorsements (MOLE).
//
// Responsibilities:
// - Owns `moderated_endorsements::ModeratedEndorsementsStore` (SQLite WAL +
//   OS-keychain-wrapped AES-256-GCM encryption on disk, `:memory:` in OTR).
// - Implements context-bound `network::mojom::MoleAuthObserver` pipes for
//   eligible frames, Service Workers, and `<form moderated>` navigations.
// - Drives Anchor grant requests with first-party same-origin credentials while
//   sending all Moderator control requests over a `header_client`-free
//   `URLLoaderFactory` with transient `IsolationInfo`, `CredentialsMode::kOmit`,
//   `kURLLoadOptionBlockAllCookies`, and `RedirectMode::kError`.
// - Offloads all `EC-IHAT` / `EC-ACT` zero-knowledge proof computation to
//   `base::ThreadPool` (`MayBlock`) so `BrowserThread::UI` never blocks on
//   elliptic-curve operations.
class CONTENT_EXPORT ModeratedEndorsementsManager
    : public network::mojom::MoleAuthObserver {
 public:
  struct MoleObserverContext {
    enum class Kind {
      kFrame,
      kServiceWorker,
      kBrowserNavigation,
    };

    MoleObserverContext();
    MoleObserverContext(const MoleObserverContext&);
    MoleObserverContext& operator=(const MoleObserverContext&);
    MoleObserverContext(MoleObserverContext&&);
    MoleObserverContext& operator=(MoleObserverContext&&);
    ~MoleObserverContext();

    Kind kind = Kind::kBrowserNavigation;
    GlobalRenderFrameHostId frame_id;
    url::Origin worker_origin;
  };

  // Production constructor owned by `StoragePartitionImpl`.
  explicit ModeratedEndorsementsManager(StoragePartitionImpl* storage_partition);

  // Testing constructor with explicit encryption key and loader factory.
  ModeratedEndorsementsManager(
      bool is_off_the_record,
      const base::FilePath& db_path,
      const std::array<uint8_t, 32>& aead_key,
      scoped_refptr<network::SharedURLLoaderFactory> control_loader_factory);

  ~ModeratedEndorsementsManager() override;

  ModeratedEndorsementsManager(const ModeratedEndorsementsManager&) = delete;
  ModeratedEndorsementsManager& operator=(const ModeratedEndorsementsManager&) =
      delete;

  mojo::PendingRemote<network::mojom::MoleAuthObserver>
  CreateObserverRemoteForFrame(GlobalRenderFrameHostId frame_id);
  mojo::PendingRemote<network::mojom::MoleAuthObserver>
  CreateObserverRemoteForServiceWorker(const url::Origin& worker_origin);
  mojo::PendingRemote<network::mojom::MoleAuthObserver>
  CreateObserverRemoteForBrowserNavigation();

  // Cleans session-only origins from `<partition_path>/ModeratedEndorsements`
  // on browser shutdown even if `ModeratedEndorsementsManager` was never
  // instantiated or initialized during the closing session.
  static void ScheduleColdSessionOnlyCleanup(
      BrowserContext* browser_context,
      const base::FilePath& partition_path,
      storage::SpecialStoragePolicy::DeleteCookieOnExitPredicate predicate);

  // `navigator.endorsement.endorse({ authorization })` entry point.
  void Endorse(const url::Origin& anchor_origin,
               bool had_transient_user_activation,
               const std::optional<std::string>& authorization,
               blink::mojom::ModeratedEndorsementService::EndorseCallback cb);

  // `navigator.endorsement.settle({ moderator })` entry point.
  void Settle(const url::Origin& top_frame_origin,
              const std::optional<url::Origin>& moderator_filter,
              blink::mojom::ModeratedEndorsementService::SettleCallback cb);

  // Active top-level document tracking for automatic background `signoff` when
  // the last active document for `top_frame_origin`'s `SchemefulSite` closes.
  void OnTopLevelDocumentActivated(const url::Origin& top_frame_origin);
  void OnTopLevelDocumentDestroyed(const url::Origin& top_frame_origin);

  // Browsing data & shutdown hooks invoked by `StoragePartitionImpl`.
  void ClearData(BrowsingDataFilterBuilder* filter_builder,
                 const blink::StorageKey& storage_key,
                 bool is_user_initiated,
                 base::Time begin,
                 base::Time end,
                 base::OnceClosure callback);

  void Shutdown(
      storage::SpecialStoragePolicy::DeleteCookieOnExitPredicate
          delete_cookie_on_exit_predicate);

  // network::mojom::MoleAuthObserver:
  void OnMoleOutboundRequest(
      const GURL& request_url,
      const std::string& method,
      const url::Origin& top_frame_origin,
      network::mojom::MoleRequestParamsPtr params,
      OnMoleOutboundRequestCallback callback) override;
  void OnMoleChallengeReceived(
      const GURL& request_url,
      const std::string& method,
      const url::Origin& top_frame_origin,
      network::mojom::MoleRequestParamsPtr params,
      int32_t http_status,
      const std::optional<std::string>& mole_challenge_header,
      const std::vector<std::string>& www_authenticate_mole_headers,
      OnMoleChallengeReceivedCallback callback) override;
  void Clone(
      mojo::PendingReceiver<network::mojom::MoleAuthObserver> listener) override;

  moderated_endorsements::ModeratedEndorsementsStore* store_for_testing() {
    return store_.get();
  }

 private:
  class PresentationFinalizer;

  using LoaderList = std::list<std::unique_ptr<network::SimpleURLLoader>>;
  struct ControlHttpResult {
    ControlHttpResult();
    ControlHttpResult(ControlHttpResult&&);
    ControlHttpResult& operator=(ControlHttpResult&&);
    ~ControlHttpResult();

    int net_error = 0;
    int http_status = 0;
    bool wire_bytes_sent = false;
    std::string content_type;
    std::optional<std::string> mole_credential;
    std::optional<std::string> body;
  };
  using ControlHttpCallback = base::OnceCallback<void(ControlHttpResult)>;

  std::optional<url::Origin> ResolveAuthorizedTopFrameOrigin(
      const MoleObserverContext& ctx,
      const url::Origin& reported_top_frame_origin) const;

  void EnsureInitialized(base::OnceClosure task);
  void OnEncryptionKeyReady(std::array<uint8_t, 32> aead_key);
  scoped_refptr<network::SharedURLLoaderFactory> GetControlLoaderFactory();

  // When `credentialed_same_origin_anchor` is `std::nullopt` (ALL Moderator
  // requests), enforces `CredentialsMode::kOmit`, `kURLLoadOptionBlockAllCookies`,
  // and `IsolationInfo::CreateTransient()`. When set (Anchor `Endorse`),
  // verifies exact same-origin match and attaches first-party Anchor cookies.
  void SendControlRequest(
      const GURL& url,
      const std::string& method,
      std::optional<url::Origin> credentialed_same_origin_anchor,
      const std::optional<std::string>& authorization_header,
      const std::optional<std::string>& content_type,
      std::optional<std::string> request_body,
      base::OnceClosure on_wire_progress,
      ControlHttpCallback callback);

  // Endorse pipeline:
  void EndorseAfterInit(
      url::Origin anchor_origin,
      bool had_transient_user_activation,
      std::optional<std::string> authorization,
      blink::mojom::ModeratedEndorsementService::EndorseCallback cb);
  void OnAnchorDirectoryFetched(
      url::Origin anchor_origin,
      std::optional<std::string> authorization,
      moderated_endorsements::AnchorCommitment commitment,
      uint64_t op_generation,
      blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
      ControlHttpResult dir_result);
  void OnGrantBeginBuilt(
      url::Origin anchor_origin,
      std::optional<std::string> authorization,
      uint64_t op_generation,
      blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
      moderated_endorsements::GrantBeginOut begin_out);
  void OnGrantRtt1Complete(
      url::Origin anchor_origin,
      GURL grant_url,
      std::optional<std::string> authorization,
      uint64_t op_generation,
      std::vector<uint8_t> anchor_key,
      std::vector<uint8_t> issuance_epoch,
      uint16_t requested_count,
      blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
      ControlHttpResult rtt1_result);
  void OnGrantStepBuilt(
      url::Origin anchor_origin,
      GURL grant_url,
      std::optional<std::string> authorization,
      uint64_t op_generation,
      std::vector<uint8_t> anchor_key,
      std::vector<uint8_t> issuance_epoch,
      blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
      moderated_endorsements::GrantCommitmentsOut step_out);
  void OnGrantRtt2Complete(
      url::Origin anchor_origin,
      uint64_t op_generation,
      std::vector<uint8_t> anchor_key,
      std::vector<uint8_t> issuance_epoch,
      blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
      moderated_endorsements::GrantFinalizeOut fin_out);

  // Split Challenge -> [Issue] -> Present pipeline:
  void HandleChallengeAfterInit(
      MoleObserverContext observer_ctx,
      GURL request_url,
      std::string method,
      url::Origin reported_top_frame_origin,
      network::mojom::MoleRequestParamsPtr params,
      std::optional<std::string> mole_challenge_header,
      std::vector<std::string> www_authenticate_mole_headers,
      OnMoleChallengeReceivedCallback callback);
  void EnsureModeratorConfig(
      const url::Origin& moderator_origin,
      base::OnceCallback<void(std::optional<std::string>)> callback);
  void ContinueSplitChallengeWithConfig(
      GURL request_url,
      std::string method,
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      moderated_endorsements::CommittedPolicy committed_policy,
      moderated_endorsements::SplitChallengeEval eval,
      bool allow_deferred_update,
      OnMoleChallengeReceivedCallback callback,
      std::optional<std::string> mod_config_json);
  void PresentReservedSplitCredential(
      GURL request_url,
      std::string method,
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      std::string mod_config_json,
      moderated_endorsements::CommittedPolicy committed_policy,
      moderated_endorsements::SplitChallengeEval eval,
      bool allow_deferred_update,
      moderated_endorsements::ModeratedEndorsementsStore::ReservedCredential
          reserved,
      OnMoleChallengeReceivedCallback callback);
  void OnSplitPresentBuilt(
      GURL request_url,
      std::string method,
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      moderated_endorsements::CommittedPolicy committed_policy,
      moderated_endorsements::SplitChallengeEval eval,
      uint64_t op_generation,
      int64_t reservation_id,
      OnMoleChallengeReceivedCallback callback,
      moderated_endorsements::SplitPresentBeginOut begin_out);
  void OnSplitPresentHttpComplete(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      std::string target_origin,
      std::string method,
      std::string path_and_query,
      moderated_endorsements::CommittedPolicy committed_policy,
      moderated_endorsements::SplitChallengeEval eval,
      uint64_t op_generation,
      int64_t reservation_id,
      int64_t pending_spend_id,
      std::vector<uint8_t> spend_bundle,
      OnMoleChallengeReceivedCallback callback,
      ControlHttpResult http_result);
  void OnSplitPresentFinalized(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      uint64_t op_generation,
      int64_t reservation_id,
      int64_t pending_spend_id,
      bool wire_bytes_sent,
      OnMoleChallengeReceivedCallback callback,
      moderated_endorsements::SplitPresentFinishOut finish_out);

  // Split Issue (`POST /mole/v1/issue`) with 5m idempotency retry:
  void RunSplitIssueAndContinue(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      std::string mod_config_json,
      moderated_endorsements::ModeratorCommitment mod_commitment,
      moderated_endorsements::CommittedPolicy committed_policy,
      base::OnceCallback<void(bool)> on_issue_done);
  void DispatchSplitIssueHttp(
      url::Origin moderator_origin,
      moderated_endorsements::CommittedPolicy committed_policy,
      uint64_t op_generation,
      int64_t endorsement_id,
      int64_t pending_issue_id,
      std::optional<
          moderated_endorsements::ModeratedEndorsementsStore::BootstrapReservation>
          bootstrap_reservation,
      std::string issue_uri,
      std::vector<uint8_t> request_body,
      std::vector<uint8_t> issuance_state_bundle,
      base::OnceCallback<void(bool)> on_issue_done);

  // `-01` Inline Redeem, Presentation, and Settlement pipeline:
  void HandleInlineChallenge(
      GURL request_url,
      url::Origin top_frame_origin,
      network::mojom::MoleRequestParamsPtr params,
      std::vector<std::string> www_authenticate_mole_headers,
      OnMoleChallengeReceivedCallback callback);
  void ContinueInlineChallenge(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      moderated_endorsements::ModeratorCommitment mod_commitment,
      moderated_endorsements::CommittedPolicy matched_policy,
      moderated_endorsements::InlineChallengeEval eval,
      std::vector<std::string> www_authenticate_mole_headers,
      OnMoleChallengeReceivedCallback callback);
  void PresentReservedInlineCredential(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      moderated_endorsements::CommittedPolicy matched_policy,
      moderated_endorsements::InlineChallengeEval eval,
      moderated_endorsements::ModeratedEndorsementsStore::ReservedCredential
          reserved,
      OnMoleChallengeReceivedCallback callback);
  void RunInlineRedeemAndContinue(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      moderated_endorsements::ModeratorCommitment mod_commitment,
      moderated_endorsements::CommittedPolicy matched_policy,
      std::vector<std::string> www_authenticate_mole_headers,
      bool can_use_no_endorsement,
      base::OnceCallback<void(bool)> on_redeem_done);
  void SettleInlineResponse(
      url::Origin top_frame_origin,
      url::Origin moderator_origin,
      uint64_t op_generation,
      int64_t reservation_id,
      int64_t pending_spend_id,
      std::vector<uint8_t> spend_bundle,
      std::vector<uint64_t> allowed_refund_amounts,
      int32_t http_status,
      const std::optional<std::string>& mole_credential_header,
      bool wire_bytes_sent,
      base::OnceClosure done_cb);
  void AbortInlinePresentation(uint64_t op_generation,
                               int64_t reservation_id,
                               int64_t pending_spend_id,
                               bool wire_bytes_sent);

  // Deferred Settlement (`POST /mole/v1/settle` or `-01` inline settlement):
  void TriggerSettlements(
      std::vector<
          moderated_endorsements::ModeratedEndorsementsStore::ReadySettlement>
          settlements,
      base::OnceCallback<void(bool)> done_callback);
  void DispatchSingleSettlement(
      moderated_endorsements::ModeratedEndorsementsStore::ReadySettlement item,
      base::OnceCallback<void(bool)> item_done);
  void OnOriginMoleInfoReceived(const url::Origin& top_frame_origin,
                                const url::Origin& moderator_origin,
                                const std::optional<std::string>& mole_info);

  raw_ptr<StoragePartitionImpl> storage_partition_ = nullptr;
  bool init_started_ = false;
  bool init_complete_ = false;
  bool is_shut_down_ = false;
  std::deque<base::OnceClosure> pending_init_tasks_;

  std::unique_ptr<moderated_endorsements::ModeratedEndorsementsStore> store_;
  mojo::Remote<network::mojom::URLLoaderFactory> direct_network_factory_;
  scoped_refptr<network::SharedURLLoaderFactory> control_loader_factory_;
  LoaderList active_loaders_;

  // Short-lived cache of `.well-known/mole-moderator` documents keyed by
  // canonical Moderator origin.
  struct CachedModeratorDirectory {
    std::string raw_json;
    base::TimeTicks expires_at;
  };
  base::flat_map<std::string, CachedModeratorDirectory> moderator_config_cache_;

  // Count of active top-level documents per canonical `SchemefulSite`.
  std::map<std::string, size_t> active_site_frame_counts_;

  mojo::ReceiverSet<network::mojom::MoleAuthObserver, MoleObserverContext>
      observer_receivers_;
  mojo::UniqueReceiverSet<network::mojom::MoleResponseFinalizer>
      finalizer_receivers_;

  base::WeakPtrFactory<ModeratedEndorsementsManager> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_MANAGER_H_
