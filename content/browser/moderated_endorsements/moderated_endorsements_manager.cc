// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/moderated_endorsements_manager.h"

#include <algorithm>
#include <functional>
#include <utility>

#include "base/barrier_callback.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/numerics/clamped_math.h"
#include "base/rand_util.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/string_view_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "content/browser/moderated_endorsements/mole_commitment_registry.h"
#include "content/browser/renderer_host/render_frame_host_impl.h"
#include "content/browser/storage_partition_impl.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/browsing_data_filter_builder.h"
#include "content/public/browser/content_browser_client.h"
#include "content/public/common/content_client.h"
#include "content/public/common/content_switches.h"
#include "crypto/random.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/schemeful_site.h"
#include "net/cookies/site_for_cookies.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/constants.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/permissions_policy/permissions_policy_feature.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace content {

namespace {

constexpr char kAnchorWellKnownPath[] = "/.well-known/mole-anchor";
constexpr char kModeratorWellKnownPath[] = "/.well-known/mole-moderator";
constexpr char kMoleEnvelopeMediaType[] = "application/mole+octet-stream";
constexpr size_t kMaxControlResponseBytes = 256 * 1024;
constexpr base::TimeDelta kControlRequestTimeout = base::Seconds(15);
constexpr base::TimeDelta kModeratorConfigCacheTtl = base::Minutes(5);
constexpr uint16_t kGrantBatchCount = 4;
constexpr uint64_t kMaxHoldDurationMs = 300'000;
constexpr uint64_t kDefaultSettlementRetryAfterMs = 2'000;

constexpr net::NetworkTrafficAnnotationTag kMoleControlTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("moderated_endorsements_control", R"(
      semantics {
        sender: "Moderated Endorsements"
        description:
          "Out-of-band Anchor endorsement grants and Split Moderator "
          "issuance/presentation/settlement exchanges for Moderated "
          "Endorsements (MOLE)."
        trigger:
          "Web page invokes navigator.endorsement.{endorse, settle}() or "
          "fetches an opted-in resource via fetch(url, { moderated }) or "
          "<form moderated>."
        data:
          "Blinded EC-IHAT endorsement material, EC-ACT zero-knowledge "
          "spend/refund proofs, and request-bound clearance parameters. "
          "Moderator requests use transient network isolation and never "
          "carry cookies; Anchor grant requests use same-origin first-party "
          "credentials."
        destination: OTHER
      }
      policy {
        cookies_allowed: YES
        cookies_store: "user"
        setting: "Controlled via site data settings and ModeratedEndorsements."
        policy_exception_justification: "Experimental web platform feature."
      })");

struct WireProgressTracker : public base::RefCounted<WireProgressTracker> {
  explicit WireProgressTracker(base::OnceClosure cb)
      : on_first_wire(std::move(cb)) {}

  void NotifyWireProgress() {
    if (!wire_started) {
      wire_started = true;
      if (on_first_wire) {
        std::move(on_first_wire).Run();
      }
    }
  }

  bool wire_started = false;
  base::OnceClosure on_first_wire;

 private:
  friend class base::RefCounted<WireProgressTracker>;
  ~WireProgressTracker() = default;
};

// Returns true ONLY when `net_error` guarantees that zero HTTP request bytes
// left the client over TLS/TCP (e.g. DNS failure, TCP SYN refused, or TLS
// handshake failure prior to application-data transmission). Any post-connect
// transport drop (`ERR_CONNECTION_RESET`, `ERR_TIMED_OUT`, `ERR_ABORTED`, etc.)
// conservatively returns false so single-use proofs are never treated as
// unspent when packets may have reached the server.
bool IsProvablyPreWireNetError(int net_error) {
  switch (net_error) {
    case net::ERR_NAME_NOT_RESOLVED:
    case net::ERR_INTERNET_DISCONNECTED:
    case net::ERR_ADDRESS_UNREACHABLE:
    case net::ERR_ADDRESS_INVALID:
    case net::ERR_CONNECTION_REFUSED:
    case net::ERR_NETWORK_ACCESS_DENIED:
    case net::ERR_INVALID_URL:
    case net::ERR_DISALLOWED_URL_SCHEME:
    case net::ERR_UNKNOWN_URL_SCHEME:
    case net::ERR_CERT_COMMON_NAME_INVALID:
    case net::ERR_CERT_DATE_INVALID:
    case net::ERR_CERT_AUTHORITY_INVALID:
    case net::ERR_CERT_INVALID:
    case net::ERR_SSL_PROTOCOL_ERROR:
    case net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH:
    case net::ERR_BAD_SSL_CLIENT_AUTH_CERT:
      return true;
    default:
      return false;
  }
}

int64_t NowMicros() {
  return base::Time::Now().InMillisecondsSinceUnixEpoch() * 1000;
}

uint64_t NowUnixSecs() {
  double secs = base::Time::Now().InSecondsFSinceUnixEpoch();
  return secs > 0.0 ? static_cast<uint64_t>(secs) : 0u;
}

std::vector<uint8_t> ToStdVec(const rust::Vec<uint8_t>& v) {
  return std::vector<uint8_t>(v.begin(), v.end());
}

std::string BytesToString(base::span<const uint8_t> s) {
  return std::string(base::as_string_view(s));
}

std::string RustBytesToString(const rust::Vec<uint8_t>& v) {
  std::string out;
  out.reserve(v.size());
  for (uint8_t b : v) {
    out.push_back(static_cast<char>(b));
  }
  return out;
}

moderated_endorsements::ZeroizingBytes ToZeroizing(
    const rust::Vec<uint8_t>& v) {
  std::vector<uint8_t> tmp(v.begin(), v.end());
  return moderated_endorsements::ZeroizingBytes(std::move(tmp));
}

rust::Slice<const uint8_t> SpanToRustSlice(base::span<const uint8_t> s) {
  return rust::Slice<const uint8_t>(s.data(), s.size());
}

rust::Slice<const uint8_t> StringToRustSlice(std::string_view s) {
  return SpanToRustSlice(base::as_byte_span(s));
}

rust::Slice<const uint8_t> RustVecToSlice(const rust::Vec<uint8_t>& v) {
  return rust::Slice<const uint8_t>(v.data(), v.size());
}

rust::Slice<const uint64_t> U64VecToSlice(const rust::Vec<uint64_t>& v) {
  return rust::Slice<const uint64_t>(v.data(), v.size());
}

std::string PathAndQuery(const GURL& url) {
  if (!url.has_query()) {
    return url.GetPath();
  }
  return base::StrCat({url.GetPath(), "?", url.GetQuery()});
}

std::string CanonicalSiteKey(const url::Origin& origin) {
  return net::SchemefulSite(origin).Serialize();
}

}  // namespace

ModeratedEndorsementsManager::MoleObserverContext::MoleObserverContext() =
    default;
ModeratedEndorsementsManager::MoleObserverContext::MoleObserverContext(
    const MoleObserverContext&) = default;
ModeratedEndorsementsManager::MoleObserverContext&
ModeratedEndorsementsManager::MoleObserverContext::operator=(
    const MoleObserverContext&) = default;
ModeratedEndorsementsManager::MoleObserverContext::MoleObserverContext(
    MoleObserverContext&&) = default;
ModeratedEndorsementsManager::MoleObserverContext&
ModeratedEndorsementsManager::MoleObserverContext::operator=(
    MoleObserverContext&&) = default;
ModeratedEndorsementsManager::MoleObserverContext::~MoleObserverContext() =
    default;

class ModeratedEndorsementsManager::PresentationFinalizer
    : public network::mojom::MoleResponseFinalizer {
 public:
  // Constructor for Split presentations (already settled/held at `/present`;
  // listens for `Mole-Info: settle-ready=?1`).
  PresentationFinalizer(base::WeakPtr<ModeratedEndorsementsManager> manager,
                        url::Origin top_frame_origin,
                        url::Origin moderator_origin)
      : manager_(std::move(manager)),
        top_frame_origin_(std::move(top_frame_origin)),
        moderator_origin_(std::move(moderator_origin)) {}

  // Constructor for `-01` inline presentations (settles `Mole-Credential` or
  // rolls back pre-wire aborts using `wire_bytes_sent`).
  PresentationFinalizer(base::WeakPtr<ModeratedEndorsementsManager> manager,
                        url::Origin top_frame_origin,
                        url::Origin moderator_origin,
                        uint64_t op_generation,
                        int64_t reservation_id,
                        int64_t pending_spend_id,
                        std::vector<uint8_t> spend_bundle,
                        std::vector<uint64_t> allowed_refund_amounts)
      : manager_(std::move(manager)),
        top_frame_origin_(std::move(top_frame_origin)),
        moderator_origin_(std::move(moderator_origin)),
        is_inline_(true),
        op_generation_(op_generation),
        reservation_id_(reservation_id),
        pending_spend_id_(pending_spend_id),
        spend_bundle_(std::move(spend_bundle)),
        allowed_refund_amounts_(std::move(allowed_refund_amounts)) {}

  ~PresentationFinalizer() override = default;

  void OnOriginResponse(int32_t http_status,
                        const std::optional<std::string>& mole_info_header,
                        const std::optional<std::string>& mole_credential_header,
                        bool wire_bytes_sent,
                        OnOriginResponseCallback callback) override {
    settled_ = true;
    if (is_inline_) {
      if (manager_) {
        manager_->SettleInlineResponse(
            top_frame_origin_, moderator_origin_, op_generation_,
            reservation_id_, pending_spend_id_, std::move(spend_bundle_),
            std::move(allowed_refund_amounts_), http_status,
            mole_credential_header, wire_bytes_sent, std::move(callback));
        return;
      }
      std::move(callback).Run();
      return;
    }
    if (manager_ && mole_info_header.has_value()) {
      manager_->OnOriginMoleInfoReceived(top_frame_origin_, moderator_origin_,
                                         mole_info_header);
    }
    std::move(callback).Run();
  }

  void OnAbortedOrCompleted(int32_t net_error, bool wire_bytes_sent) override {
    if (is_inline_ && !settled_ && manager_) {
      settled_ = true;
      const bool conservative_wire_sent =
          wire_bytes_sent || !IsProvablyPreWireNetError(net_error);
      manager_->AbortInlinePresentation(op_generation_, reservation_id_,
                                        pending_spend_id_,
                                        conservative_wire_sent);
    }
  }

 private:
  base::WeakPtr<ModeratedEndorsementsManager> manager_;
  url::Origin top_frame_origin_;
  url::Origin moderator_origin_;
  bool is_inline_ = false;
  bool settled_ = false;
  uint64_t op_generation_ = 0;
  int64_t reservation_id_ = 0;
  int64_t pending_spend_id_ = 0;
  std::vector<uint8_t> spend_bundle_;
  std::vector<uint64_t> allowed_refund_amounts_;
};

ModeratedEndorsementsManager::ControlHttpResult::ControlHttpResult() = default;
ModeratedEndorsementsManager::ControlHttpResult::ControlHttpResult(
    ControlHttpResult&&) = default;
ModeratedEndorsementsManager::ControlHttpResult&
ModeratedEndorsementsManager::ControlHttpResult::operator=(
    ControlHttpResult&&) = default;
ModeratedEndorsementsManager::ControlHttpResult::~ControlHttpResult() = default;

ModeratedEndorsementsManager::ModeratedEndorsementsManager(
    StoragePartitionImpl* storage_partition)
    : storage_partition_(storage_partition) {
  CHECK(storage_partition_);
}

ModeratedEndorsementsManager::ModeratedEndorsementsManager(
    bool is_off_the_record,
    const base::FilePath& db_path,
    const std::array<uint8_t, 32>& aead_key,
    scoped_refptr<network::SharedURLLoaderFactory> control_loader_factory)
    : init_started_(true),
      init_complete_(true),
      control_loader_factory_(std::move(control_loader_factory)) {
  store_ = std::make_unique<moderated_endorsements::ModeratedEndorsementsStore>(
      is_off_the_record, db_path.AsUTF8Unsafe(), aead_key);
  store_->Initialize(NowMicros());
}

ModeratedEndorsementsManager::~ModeratedEndorsementsManager() {
  if (store_ && !is_shut_down_) {
    store_->Shutdown();
  }
}

mojo::PendingRemote<network::mojom::MoleAuthObserver>
ModeratedEndorsementsManager::CreateObserverRemoteForFrame(
    GlobalRenderFrameHostId frame_id) {
  mojo::PendingRemote<network::mojom::MoleAuthObserver> remote;
  MoleObserverContext ctx;
  ctx.kind = MoleObserverContext::Kind::kFrame;
  ctx.frame_id = frame_id;
  observer_receivers_.Add(this, remote.InitWithNewPipeAndPassReceiver(),
                          std::move(ctx));
  return remote;
}

mojo::PendingRemote<network::mojom::MoleAuthObserver>
ModeratedEndorsementsManager::CreateObserverRemoteForServiceWorker(
    const url::Origin& worker_origin) {
  mojo::PendingRemote<network::mojom::MoleAuthObserver> remote;
  MoleObserverContext ctx;
  ctx.kind = MoleObserverContext::Kind::kServiceWorker;
  ctx.worker_origin = worker_origin;
  observer_receivers_.Add(this, remote.InitWithNewPipeAndPassReceiver(),
                          std::move(ctx));
  return remote;
}

mojo::PendingRemote<network::mojom::MoleAuthObserver>
ModeratedEndorsementsManager::CreateObserverRemoteForBrowserNavigation() {
  mojo::PendingRemote<network::mojom::MoleAuthObserver> remote;
  MoleObserverContext ctx;
  ctx.kind = MoleObserverContext::Kind::kBrowserNavigation;
  observer_receivers_.Add(this, remote.InitWithNewPipeAndPassReceiver(),
                          std::move(ctx));
  return remote;
}

void ModeratedEndorsementsManager::Clone(
    mojo::PendingReceiver<network::mojom::MoleAuthObserver> listener) {
  observer_receivers_.Add(this, std::move(listener),
                          observer_receivers_.current_context());
}

std::optional<url::Origin>
ModeratedEndorsementsManager::ResolveAuthorizedTopFrameOrigin(
    const MoleObserverContext& ctx,
    const url::Origin& reported_top_frame_origin) const {
  switch (ctx.kind) {
    case MoleObserverContext::Kind::kFrame: {
      RenderFrameHostImpl* rfh = RenderFrameHostImpl::FromID(ctx.frame_id);
      if (!rfh || rfh->IsInFencedFrameTree() ||
          rfh->GetLifecycleState() != RenderFrameHost::LifecycleState::kActive ||
          !rfh->IsFeatureEnabled(
              network::mojom::PermissionsPolicyFeature::kModeratedEndorsements)) {
        return std::nullopt;
      }
      const url::Origin top_origin =
          rfh->GetMainFrame()->GetLastCommittedOrigin();
      if (top_origin.opaque() || top_origin.scheme() != "https" ||
          !network::IsOriginPotentiallyTrustworthy(top_origin)) {
        return std::nullopt;
      }
      return top_origin;
    }
    case MoleObserverContext::Kind::kServiceWorker: {
      if (ctx.worker_origin.opaque() || ctx.worker_origin.scheme() != "https" ||
          !network::IsOriginPotentiallyTrustworthy(ctx.worker_origin)) {
        return std::nullopt;
      }
      const url::Origin effective = !reported_top_frame_origin.opaque()
                                        ? reported_top_frame_origin
                                        : ctx.worker_origin;
      if (effective.opaque() || effective.scheme() != "https" ||
          !network::IsOriginPotentiallyTrustworthy(effective)) {
        return std::nullopt;
      }
      const net::SchemefulSite target_site(effective);
      if (target_site != net::SchemefulSite(ctx.worker_origin)) {
        return std::nullopt;
      }
      if (storage_partition_) {
        bool has_active_main_frame = false;
        for (const auto& wc : WebContentsImpl::GetAllWebContents()) {
          if (!wc) {
            continue;
          }
          RenderFrameHostImpl* main_rfh = wc->GetPrimaryMainFrame();
          if (main_rfh &&
              main_rfh->GetStoragePartition() == storage_partition_ &&
              !main_rfh->IsInFencedFrameTree() &&
              main_rfh->GetLifecycleState() ==
                  RenderFrameHost::LifecycleState::kActive &&
              main_rfh->IsFeatureEnabled(
                  network::mojom::PermissionsPolicyFeature::
                      kModeratedEndorsements) &&
              net::SchemefulSite(main_rfh->GetLastCommittedOrigin()) ==
                  target_site) {
            has_active_main_frame = true;
            break;
          }
        }
        if (!has_active_main_frame) {
          return std::nullopt;
        }
      }
      return effective;
    }
    case MoleObserverContext::Kind::kBrowserNavigation: {
      if (reported_top_frame_origin.opaque() ||
          reported_top_frame_origin.scheme() != "https" ||
          !network::IsOriginPotentiallyTrustworthy(reported_top_frame_origin)) {
        return std::nullopt;
      }
      return reported_top_frame_origin;
    }
  }
}

void ModeratedEndorsementsManager::EnsureInitialized(base::OnceClosure task) {
  if (is_shut_down_) {
    return;
  }
  if (init_complete_) {
    std::move(task).Run();
    return;
  }
  pending_init_tasks_.push_back(std::move(task));
  if (init_started_) {
    return;
  }
  init_started_ = true;

  BrowserContext* browser_context = storage_partition_->browser_context();
  if (!browser_context || browser_context->IsOffTheRecord() ||
      storage_partition_->GetPath().empty()) {
    std::array<uint8_t, 32> ephemeral_key;
    crypto::RandBytes(ephemeral_key);
    OnEncryptionKeyReady(ephemeral_key);
    OPENSSL_cleanse(ephemeral_key.data(), ephemeral_key.size());
    return;
  }

  GetContentClient()->browser()->GetModeratedEndorsementsEncryptionKey(
      browser_context, storage_partition_->GetPath(),
      base::BindOnce(&ModeratedEndorsementsManager::OnEncryptionKeyReady,
                     weak_factory_.GetWeakPtr()));
}

void ModeratedEndorsementsManager::OnEncryptionKeyReady(
    std::array<uint8_t, 32> aead_key) {
  if (is_shut_down_) {
    OPENSSL_cleanse(aead_key.data(), aead_key.size());
    return;
  }
  BrowserContext* browser_context =
      storage_partition_ ? storage_partition_->browser_context() : nullptr;
  const bool is_otr = !browser_context || browser_context->IsOffTheRecord() ||
                      storage_partition_->GetPath().empty();
  const std::string db_path =
      is_otr ? std::string()
             : storage_partition_->GetPath()
                   .Append(FILE_PATH_LITERAL("ModeratedEndorsements"))
                   .AsUTF8Unsafe();

  store_ = std::make_unique<moderated_endorsements::ModeratedEndorsementsStore>(
      is_otr, db_path, aead_key);
  OPENSSL_cleanse(aead_key.data(), aead_key.size());
  store_->Initialize(NowMicros());
  init_complete_ = true;

  std::deque<base::OnceClosure> tasks = std::move(pending_init_tasks_);
  pending_init_tasks_.clear();
  for (auto& task : tasks) {
    std::move(task).Run();
  }
}

scoped_refptr<network::SharedURLLoaderFactory>
ModeratedEndorsementsManager::GetControlLoaderFactory() {
  if (control_loader_factory_ &&
      (!direct_network_factory_.is_bound() ||
       direct_network_factory_.is_connected())) {
    return control_loader_factory_;
  }
  if (!storage_partition_) {
    return control_loader_factory_;
  }

  // Bind directly to `NetworkContext::CreateURLLoaderFactory` WITHOUT going
  // through `WillCreateURLLoaderFactory`, ensuring zero extension
  // `TrustedHeaderClient` interception and zero recursive `mole_observer`.
  direct_network_factory_.reset();
  auto params = network::mojom::URLLoaderFactoryParams::New();
  params->process_id = network::OriginatingProcessId::browser();
  params->is_trusted = true;
  params->is_orb_enabled = false;
  params->automatically_assign_isolation_info = false;
  params->disable_web_security =
      base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisableWebSecurity);
  params->network_restrictions_id = network::GetNoOpNetworkRestrictionsId();
  storage_partition_->GetNetworkContext()->CreateURLLoaderFactory(
      direct_network_factory_.BindNewPipeAndPassReceiver(), std::move(params));
  direct_network_factory_.reset_on_disconnect();

  mojo::PendingRemote<network::mojom::URLLoaderFactory> factory_remote;
  direct_network_factory_->Clone(
      factory_remote.InitWithNewPipeAndPassReceiver());
  control_loader_factory_ =
      base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
          std::move(factory_remote));
  return control_loader_factory_;
}

void ModeratedEndorsementsManager::SendControlRequest(
    const GURL& url,
    const std::string& method,
    std::optional<url::Origin> credentialed_same_origin_anchor,
    const std::optional<std::string>& authorization_header,
    const std::optional<std::string>& content_type,
    std::optional<std::string> request_body,
    base::OnceClosure on_wire_progress,
    ControlHttpCallback callback) {
  scoped_refptr<network::SharedURLLoaderFactory> factory =
      GetControlLoaderFactory();
  if (!factory || !url.is_valid() || !url.SchemeIs("https") ||
      (credentialed_same_origin_anchor.has_value() &&
       (credentialed_same_origin_anchor->opaque() ||
        !credentialed_same_origin_anchor->IsSameOriginWith(
            url::Origin::Create(url))))) {
    ControlHttpResult err;
    err.net_error = net::ERR_INVALID_URL;
    err.wire_bytes_sent = false;
    std::move(callback).Run(std::move(err));
    return;
  }

  auto req = std::make_unique<network::ResourceRequest>();
  req->url = url;
  req->method = method;
  req->redirect_mode = network::mojom::RedirectMode::kError;
  req->load_flags = net::LOAD_BYPASS_CACHE | net::LOAD_DISABLE_CACHE;
  req->trusted_params.emplace();
  if (credentialed_same_origin_anchor.has_value()) {
    // Anchor grant exchange (`navigator.endorsement.endorse()`): send
    // same-origin first-party cookies under `anchor_origin`'s `IsolationInfo`.
    const url::Origin& anchor = *credentialed_same_origin_anchor;
    req->credentials_mode = network::mojom::CredentialsMode::kInclude;
    req->request_initiator = anchor;
    req->site_for_cookies = net::SiteForCookies::FromOrigin(anchor);
    req->trusted_params->isolation_info = net::IsolationInfo::Create(
        net::IsolationInfo::RequestType::kOther, anchor, anchor,
        net::SiteForCookies::FromOrigin(anchor));
  } else {
    // Moderator control request: strict transient network isolation and zero
    // cookies (`CredentialsMode::kOmit` + `kURLLoadOptionBlockAllCookies`).
    req->credentials_mode = network::mojom::CredentialsMode::kOmit;
    req->site_for_cookies = net::SiteForCookies();
    req->trusted_params->isolation_info =
        net::IsolationInfo::CreateTransient(/*nonce=*/std::nullopt);
  }
  if (authorization_header.has_value() && !authorization_header->empty()) {
    req->headers.SetHeader(net::HttpRequestHeaders::kAuthorization,
                           *authorization_header);
  }

  auto loader = network::SimpleURLLoader::Create(std::move(req),
                                                 kMoleControlTrafficAnnotation);
  if (!credentialed_same_origin_anchor.has_value()) {
    loader->SetURLLoaderFactoryOptions(
        network::mojom::kURLLoadOptionBlockAllCookies);
  }
  loader->SetAllowHttpErrorResults(true);
  loader->SetTimeoutDuration(kControlRequestTimeout);
  if (request_body.has_value()) {
    loader->AttachStringForUpload(
        std::move(*request_body),
        content_type.value_or(kMoleEnvelopeMediaType));
  }

  auto tracker =
      base::MakeRefCounted<WireProgressTracker>(std::move(on_wire_progress));
  loader->SetOnUploadProgressCallback(base::BindRepeating(
      [](scoped_refptr<WireProgressTracker> trk, uint64_t current,
         uint64_t /*total*/) {
        if (current > 0) {
          trk->NotifyWireProgress();
        }
      },
      tracker));
  loader->SetOnResponseStartedCallback(base::BindOnce(
      [](scoped_refptr<WireProgressTracker> trk, const GURL& /*final_url*/,
         const network::mojom::URLResponseHead& /*head*/) {
        trk->NotifyWireProgress();
      },
      tracker));

  active_loaders_.push_back(std::move(loader));
  auto it = std::prev(active_loaders_.end());
  (*it)->DownloadToString(
      factory.get(),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             LoaderList::iterator loader_it,
             scoped_refptr<WireProgressTracker> trk,
             ControlHttpCallback done_cb, std::optional<std::string> body) {
            if (!self) {
              return;
            }
            std::unique_ptr<network::SimpleURLLoader> owned =
                std::move(*loader_it);
            self->active_loaders_.erase(loader_it);

            ControlHttpResult res;
            res.net_error = owned->NetError();
            res.wire_bytes_sent = trk->wire_started ||
                                  owned->ResponseInfo() != nullptr ||
                                  !IsProvablyPreWireNetError(res.net_error);
            if (owned->ResponseInfo() && owned->ResponseInfo()->headers) {
              trk->NotifyWireProgress();
              const auto& hdrs = *owned->ResponseInfo()->headers;
              res.http_status = hdrs.response_code();
              hdrs.GetMimeTypeAndCharset(&res.content_type, nullptr);
              if (std::optional<std::string> ct =
                      hdrs.GetNormalizedHeader("Content-Type")) {
                res.content_type = *ct;
              }
              res.mole_credential =
                  hdrs.GetNormalizedHeader("Mole-Credential");
            }
            res.body = std::move(body);
            std::move(done_cb).Run(std::move(res));
          },
          weak_factory_.GetWeakPtr(), it, tracker, std::move(callback)),
      kMaxControlResponseBytes);
}

// --- Active Top-Level Document Tracking ---

void ModeratedEndorsementsManager::OnTopLevelDocumentActivated(
    const url::Origin& top_frame_origin) {
  if (top_frame_origin.opaque()) {
    return;
  }
  ++active_site_frame_counts_[CanonicalSiteKey(top_frame_origin)];
}

void ModeratedEndorsementsManager::OnTopLevelDocumentDestroyed(
    const url::Origin& top_frame_origin) {
  if (top_frame_origin.opaque()) {
    return;
  }
  const std::string key = CanonicalSiteKey(top_frame_origin);
  auto it = active_site_frame_counts_.find(key);
  if (it != active_site_frame_counts_.end()) {
    if (it->second <= 1) {
      active_site_frame_counts_.erase(it);
      if (init_complete_ && store_ && !is_shut_down_) {
        auto settlements = store_->GetSettlementsForClosingSite(
            top_frame_origin.Serialize(), NowMicros());
        if (!settlements.empty()) {
          TriggerSettlements(std::move(settlements), base::DoNothing());
        }
      }
    } else {
      --it->second;
    }
  }
}

// --- Browsing Data & Shutdown ---

void ModeratedEndorsementsManager::ClearData(
    BrowsingDataFilterBuilder* filter_builder,
    const blink::StorageKey& storage_key,
    bool is_user_initiated,
    base::Time begin,
    base::Time end,
    base::OnceClosure callback) {
  moderated_endorsements::ModeratedEndorsementsStore::DataDeletionFilter filter;
  filter.is_user_initiated = is_user_initiated;
  filter.delete_begin_us =
      begin.is_null() ? 0 : begin.InMillisecondsSinceUnixEpoch() * 1000;
  filter.delete_end_us =
      end.is_max() ? INT64_MAX : end.InMillisecondsSinceUnixEpoch() * 1000;
  if (!storage_key.origin().opaque()) {
    filter.origins.push_back(storage_key.origin().Serialize());
  } else if (!filter_builder ||
             filter_builder->MatchesAllOriginsAndDomains()) {
    filter.match_all_origins = true;
  } else {
    filter.exclude_listed =
        filter_builder->GetMode() == BrowsingDataFilterBuilder::Mode::kPreserve;
    for (const url::Origin& origin : filter_builder->GetOrigins()) {
      filter.origins.push_back(origin.Serialize());
    }
    for (const std::string& domain : filter_builder->GetRegisterableDomains()) {
      filter.registrable_domains.push_back(domain);
    }
  }

  // Abort active control loaders and finalizers immediately so in-flight
  // exchanges cannot persist credentials after deletion begins.
  active_loaders_.clear();
  finalizer_receivers_.Clear();

  const bool is_full_user_wipe =
      filter.is_user_initiated && filter.match_all_origins &&
      filter.delete_begin_us == 0 && filter.delete_end_us == INT64_MAX;

  EnsureInitialized(base::BindOnce(
      [](base::WeakPtr<ModeratedEndorsementsManager> self,
         moderated_endorsements::ModeratedEndorsementsStore::DataDeletionFilter
             f,
         bool full_wipe, base::OnceClosure cb) {
        if (self && self->store_) {
          self->active_loaders_.clear();
          self->finalizer_receivers_.Clear();
          self->moderator_config_cache_.clear();
          self->store_->DeleteData(f);
          if (full_wipe && self->storage_partition_ &&
              self->storage_partition_->browser_context() &&
              !self->storage_partition_->GetPath().empty()) {
            GetContentClient()
                ->browser()
                ->DeleteModeratedEndorsementsEncryptionKey(
                    self->storage_partition_->browser_context(),
                    self->storage_partition_->GetPath());
          }
        }
        std::move(cb).Run();
      },
      weak_factory_.GetWeakPtr(), std::move(filter), is_full_user_wipe,
      std::move(callback)));
}

// static
void ModeratedEndorsementsManager::ScheduleColdSessionOnlyCleanup(
    BrowserContext* browser_context,
    const base::FilePath& partition_path,
    storage::SpecialStoragePolicy::DeleteCookieOnExitPredicate predicate) {
  if (!browser_context || browser_context->IsOffTheRecord() ||
      partition_path.empty() || !predicate) {
    return;
  }
  const base::FilePath db_file =
      partition_path.Append(FILE_PATH_LITERAL("ModeratedEndorsements"));
  GetContentClient()->browser()->GetModeratedEndorsementsEncryptionKey(
      browser_context, partition_path,
      base::BindOnce(
          [](base::FilePath db_path,
             storage::SpecialStoragePolicy::DeleteCookieOnExitPredicate pred,
             std::array<uint8_t, 32> aead_key) {
            base::ThreadPool::PostTask(
                FROM_HERE,
                {base::MayBlock(), base::TaskPriority::BEST_EFFORT,
                 base::TaskShutdownBehavior::BLOCK_SHUTDOWN},
                base::BindOnce(
                    [](base::FilePath path,
                       storage::SpecialStoragePolicy::DeleteCookieOnExitPredicate
                           p,
                       std::array<uint8_t, 32> key) {
                      if (base::PathExists(path)) {
                        moderated_endorsements::ModeratedEndorsementsStore
                            cold_store(/*is_off_the_record=*/false,
                                       path.AsUTF8Unsafe(), key);
                        if (cold_store.Initialize(NowMicros())) {
                          cold_store.ClearSessionOnlyData(
                              [&](const std::string& host) {
                                return p.Run(host, /*is_https=*/true) ||
                                       p.Run(host, /*is_https=*/false);
                              });
                        }
                        cold_store.Shutdown();
                      }
                      OPENSSL_cleanse(key.data(), key.size());
                    },
                    std::move(db_path), std::move(pred), aead_key));
            OPENSSL_cleanse(aead_key.data(), aead_key.size());
          },
          db_file, std::move(predicate)));
}

void ModeratedEndorsementsManager::Shutdown(
    storage::SpecialStoragePolicy::DeleteCookieOnExitPredicate
        delete_cookie_on_exit_predicate) {
  if (is_shut_down_) {
    return;
  }
  is_shut_down_ = true;
  active_loaders_.clear();
  finalizer_receivers_.Clear();
  pending_init_tasks_.clear();
  if (store_) {
    if (delete_cookie_on_exit_predicate) {
      store_->ClearSessionOnlyData([&](const std::string& host) {
        return delete_cookie_on_exit_predicate.Run(host, /*is_https=*/true) ||
               delete_cookie_on_exit_predicate.Run(host, /*is_https=*/false);
      });
    }
    store_->Shutdown();
  } else if (delete_cookie_on_exit_predicate && storage_partition_ &&
             storage_partition_->browser_context() &&
             !storage_partition_->is_off_the_record() &&
             !storage_partition_->GetPath().empty()) {
    ScheduleColdSessionOnlyCleanup(storage_partition_->browser_context(),
                                   storage_partition_->GetPath(),
                                   std::move(delete_cookie_on_exit_predicate));
  }
}

// --- `navigator.endorsement.endorse()` ---

void ModeratedEndorsementsManager::Endorse(
    const url::Origin& anchor_origin,
    bool had_transient_user_activation,
    const std::optional<std::string>& authorization,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb) {
  EnsureInitialized(base::BindOnce(
      &ModeratedEndorsementsManager::EndorseAfterInit,
      weak_factory_.GetWeakPtr(), anchor_origin, had_transient_user_activation,
      authorization, std::move(cb)));
}

void ModeratedEndorsementsManager::EndorseAfterInit(
    url::Origin anchor_origin,
    bool had_transient_user_activation,
    std::optional<std::string> authorization,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (!store_ || !had_transient_user_activation || anchor_origin.opaque() ||
      anchor_origin.scheme() != "https" ||
      !network::IsOriginPotentiallyTrustworthy(anchor_origin)) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  // Enforce commitment registry BEFORE any network call!
  auto commitment =
      MoleCommitmentRegistry::GetInstance().GetAnchorCommitment(anchor_origin);
  if (!commitment.found) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  const uint64_t op_gen = store_->current_generation();
  GURL dir_url = anchor_origin.GetURL().Resolve(kAnchorWellKnownPath);
  SendControlRequest(
      dir_url, net::HttpRequestHeaders::kGetMethod,
      /*credentialed_same_origin_anchor=*/anchor_origin,
      /*authorization_header=*/std::nullopt, /*content_type=*/std::nullopt,
      /*request_body=*/std::nullopt, base::NullCallback(),
      base::BindOnce(&ModeratedEndorsementsManager::OnAnchorDirectoryFetched,
                     weak_factory_.GetWeakPtr(), anchor_origin,
                     std::move(authorization), std::move(commitment), op_gen,
                     std::move(cb)));
}

void ModeratedEndorsementsManager::OnAnchorDirectoryFetched(
    url::Origin anchor_origin,
    std::optional<std::string> authorization,
    moderated_endorsements::AnchorCommitment commitment,
    uint64_t op_generation,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
    ControlHttpResult dir_result) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (dir_result.net_error != net::OK || !dir_result.body.has_value()) {
    std::move(cb).Run(Status::kNetworkError);
    return;
  }
  if (dir_result.http_status < 200 || dir_result.http_status >= 300) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  const std::string origin_str = anchor_origin.Serialize();
  std::string dir_json = std::move(*dir_result.body);
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](std::string orig, std::string json,
             moderated_endorsements::AnchorCommitment comm) {
            return moderated_endorsements::grant_begin_batch(
                orig, json, comm, kGrantBatchCount);
          },
          origin_str, std::move(dir_json), std::move(commitment)),
      base::BindOnce(&ModeratedEndorsementsManager::OnGrantBeginBuilt,
                     weak_factory_.GetWeakPtr(), std::move(anchor_origin),
                     std::move(authorization), op_generation, std::move(cb)));
}

void ModeratedEndorsementsManager::OnGrantBeginBuilt(
    url::Origin anchor_origin,
    std::optional<std::string> authorization,
    uint64_t op_generation,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
    moderated_endorsements::GrantBeginOut begin_out) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (!begin_out.ok) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  GURL grant_url(std::string(begin_out.grant_uri));
  if (!grant_url.is_valid() ||
      !anchor_origin.IsSameOriginWith(url::Origin::Create(grant_url))) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  std::optional<std::string> auth_hdr;
  if (authorization.has_value() && !authorization->empty()) {
    auth_hdr = *authorization;
  }
  std::string content_type(begin_out.content_type);
  std::string req_body = RustBytesToString(begin_out.request_body);
  SendControlRequest(
      grant_url, net::HttpRequestHeaders::kPostMethod,
      /*credentialed_same_origin_anchor=*/anchor_origin, auth_hdr, content_type,
      std::move(req_body), base::NullCallback(),
      base::BindOnce(&ModeratedEndorsementsManager::OnGrantRtt1Complete,
                     weak_factory_.GetWeakPtr(), anchor_origin, grant_url,
                     std::move(authorization), op_generation,
                     ToStdVec(begin_out.anchor_key),
                     ToStdVec(begin_out.issuance_epoch),
                     begin_out.requested_count, std::move(cb)));
}

void ModeratedEndorsementsManager::OnGrantRtt1Complete(
    url::Origin anchor_origin,
    GURL grant_url,
    std::optional<std::string> authorization,
    uint64_t op_generation,
    std::vector<uint8_t> anchor_key,
    std::vector<uint8_t> issuance_epoch,
    uint16_t requested_count,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
    ControlHttpResult rtt1_result) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (rtt1_result.net_error != net::OK || !rtt1_result.body.has_value()) {
    std::move(cb).Run(Status::kNetworkError);
    return;
  }
  if (rtt1_result.http_status < 200 || rtt1_result.http_status >= 300) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  std::string resp_ct = std::move(rtt1_result.content_type);
  std::string resp_body = std::move(*rtt1_result.body);
  std::vector<uint8_t> key_copy = anchor_key;
  std::vector<uint8_t> epoch_copy = issuance_epoch;
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](std::vector<uint8_t> ak, std::vector<uint8_t> ep, uint16_t count,
             std::string ct, std::string body) {
            return moderated_endorsements::grant_step_commitments(
                SpanToRustSlice(ak), SpanToRustSlice(ep), count, ct,
                StringToRustSlice(body));
          },
          std::move(key_copy), std::move(epoch_copy), requested_count,
          std::move(resp_ct), std::move(resp_body)),
      base::BindOnce(&ModeratedEndorsementsManager::OnGrantStepBuilt,
                     weak_factory_.GetWeakPtr(), std::move(anchor_origin),
                     std::move(grant_url), std::move(authorization),
                     op_generation, std::move(anchor_key),
                     std::move(issuance_epoch), std::move(cb)));
}

void ModeratedEndorsementsManager::OnGrantStepBuilt(
    url::Origin anchor_origin,
    GURL grant_url,
    std::optional<std::string> authorization,
    uint64_t op_generation,
    std::vector<uint8_t> anchor_key,
    std::vector<uint8_t> issuance_epoch,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
    moderated_endorsements::GrantCommitmentsOut step_out) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (!step_out.ok) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }

  std::optional<std::string> auth_hdr;
  if (authorization.has_value() && !authorization->empty()) {
    auth_hdr = *authorization;
  }
  std::string content_type(step_out.content_type);
  std::string req_body = RustBytesToString(step_out.request_body);
  std::vector<uint8_t> session_bundle = ToStdVec(step_out.session_bundle);
  SendControlRequest(
      grant_url, net::HttpRequestHeaders::kPostMethod,
      /*credentialed_same_origin_anchor=*/anchor_origin, auth_hdr, content_type,
      std::move(req_body), base::NullCallback(),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin orig, uint64_t op_gen, std::vector<uint8_t> ak,
             std::vector<uint8_t> ep, std::vector<uint8_t> bundle,
             blink::mojom::ModeratedEndorsementService::EndorseCallback done_cb,
             ControlHttpResult rtt2_res) {
            using St = blink::mojom::ModeratedEndorsementStatus;
            if (!self) {
              return;
            }
            if (rtt2_res.net_error != net::OK || !rtt2_res.body.has_value()) {
              std::move(done_cb).Run(St::kNetworkError);
              return;
            }
            if (rtt2_res.http_status < 200 || rtt2_res.http_status >= 300) {
              std::move(done_cb).Run(St::kNotAllowed);
              return;
            }
            std::vector<uint8_t> ak_copy = ak;
            std::vector<uint8_t> ep_copy = ep;
            std::string ct = std::move(rtt2_res.content_type);
            std::string body = std::move(*rtt2_res.body);
            base::ThreadPool::PostTaskAndReplyWithResult(
                FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
                base::BindOnce(
                    [](std::vector<uint8_t> k, std::vector<uint8_t> e,
                       std::vector<uint8_t> b, std::string c, std::string bd) {
                      return moderated_endorsements::grant_finalize_responses(
                          SpanToRustSlice(k), SpanToRustSlice(e),
                          SpanToRustSlice(b), c, StringToRustSlice(bd));
                    },
                    std::move(ak_copy), std::move(ep_copy), std::move(bundle),
                    std::move(ct), std::move(body)),
                base::BindOnce(&ModeratedEndorsementsManager::OnGrantRtt2Complete,
                               self, std::move(orig), op_gen, std::move(ak),
                               std::move(ep), std::move(done_cb)));
          },
          weak_factory_.GetWeakPtr(), anchor_origin, op_generation,
          std::move(anchor_key), std::move(issuance_epoch),
          std::move(session_bundle), std::move(cb)));
}

void ModeratedEndorsementsManager::OnGrantRtt2Complete(
    url::Origin anchor_origin,
    uint64_t op_generation,
    std::vector<uint8_t> anchor_key,
    std::vector<uint8_t> issuance_epoch,
    blink::mojom::ModeratedEndorsementService::EndorseCallback cb,
    moderated_endorsements::GrantFinalizeOut fin_out) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (!fin_out.ok || !store_) {
    std::move(cb).Run(Status::kNotAllowed);
    return;
  }
  store_->StoreGrantedEndorsements(op_generation, anchor_origin.Serialize(),
                                   anchor_key, issuance_epoch,
                                   fin_out.endorsements, NowMicros());
  std::move(cb).Run(Status::kOk);
}

// --- `navigator.endorsement.settle()` ---

void ModeratedEndorsementsManager::Settle(
    const url::Origin& top_frame_origin,
    const std::optional<url::Origin>& moderator_filter,
    blink::mojom::ModeratedEndorsementService::SettleCallback cb) {
  EnsureInitialized(base::BindOnce(
      [](base::WeakPtr<ModeratedEndorsementsManager> self,
         url::Origin top_origin, std::optional<url::Origin> mod_filter,
         blink::mojom::ModeratedEndorsementService::SettleCallback done_cb) {
        using Status = blink::mojom::ModeratedEndorsementStatus;
        if (!self || !self->store_ || top_origin.opaque()) {
          std::move(done_cb).Run(Status::kNotAllowed);
          return;
        }
        std::vector<
            moderated_endorsements::ModeratedEndorsementsStore::ReadySettlement>
            settlements;
        if (mod_filter.has_value()) {
          settlements = self->store_->GetReadySettlementsForSite(
              top_origin.Serialize(), mod_filter->Serialize(),
              /*force_signoff=*/true, NowMicros());
        } else {
          settlements = self->store_->GetSettlementsForClosingSite(
              top_origin.Serialize(), NowMicros());
        }
        if (settlements.empty()) {
          std::move(done_cb).Run(Status::kOk);
          return;
        }
        self->TriggerSettlements(
            std::move(settlements),
            base::BindOnce(
                [](blink::mojom::ModeratedEndorsementService::SettleCallback c,
                   bool ok) {
                  std::move(c).Run(ok ? Status::kOk : Status::kNetworkError);
                },
                std::move(done_cb)));
      },
      weak_factory_.GetWeakPtr(), top_frame_origin, moderator_filter,
      std::move(cb)));
}

// --- `MoleAuthObserver`: Outbound & Challenge-Retry ---

void ModeratedEndorsementsManager::OnMoleOutboundRequest(
    const GURL& request_url,
    const std::string& method,
    const url::Origin& top_frame_origin,
    network::mojom::MoleRequestParamsPtr params,
    OnMoleOutboundRequestCallback callback) {
  const MoleObserverContext observer_ctx =
      observer_receivers_.current_context();
  if (!ResolveAuthorizedTopFrameOrigin(observer_ctx, top_frame_origin)) {
    std::move(callback).Run(net::HttpRequestHeaders(), mojo::NullRemote());
    return;
  }

  EnsureInitialized(base::BindOnce(
      [](base::WeakPtr<ModeratedEndorsementsManager> self,
         MoleObserverContext ctx, url::Origin reported_top_origin,
         network::mojom::MoleRequestParamsPtr p,
         OnMoleOutboundRequestCallback cb) {
        net::HttpRequestHeaders hdrs;
        if (self && self->store_ && p) {
          if (std::optional<url::Origin> verified_top =
                  self->ResolveAuthorizedTopFrameOrigin(ctx,
                                                        reported_top_origin)) {
            if (p->moderator.has_value()) {
              auto ready = self->store_->GetReadySettlementsForSite(
                  verified_top->Serialize(), p->moderator->Serialize(),
                  /*force_signoff=*/false, NowMicros());
              if (!ready.empty()) {
                self->TriggerSettlements(std::move(ready), base::DoNothing());
              }
            }
            // ~5% wire greasing on `auto` opted-in `moderated` requests
            // (`http-transport` §6.6); suppressed on `challenge-only`.
            if (p->behavior !=
                    network::mojom::MoleModerationBehavior::kChallengeOnly &&
                base::RandGenerator(20) == 0) {
              hdrs.SetHeader(
                  "Sec-Mole-Grease",
                  std::string(moderated_endorsements::make_grease_header()));
            }
          }
        }
        std::move(cb).Run(std::move(hdrs), mojo::NullRemote());
      },
      weak_factory_.GetWeakPtr(), observer_ctx, top_frame_origin,
      std::move(params), std::move(callback)));
}

void ModeratedEndorsementsManager::OnMoleChallengeReceived(
    const GURL& request_url,
    const std::string& method,
    const url::Origin& top_frame_origin,
    network::mojom::MoleRequestParamsPtr params,
    int32_t /*http_status*/,
    const std::optional<std::string>& mole_challenge_header,
    const std::vector<std::string>& www_authenticate_mole_headers,
    OnMoleChallengeReceivedCallback callback) {
  const MoleObserverContext observer_ctx =
      observer_receivers_.current_context();
  if (!ResolveAuthorizedTopFrameOrigin(observer_ctx, top_frame_origin)) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  EnsureInitialized(base::BindOnce(
      &ModeratedEndorsementsManager::HandleChallengeAfterInit,
      weak_factory_.GetWeakPtr(), observer_ctx, request_url, method,
      top_frame_origin, std::move(params), mole_challenge_header,
      www_authenticate_mole_headers, std::move(callback)));
}

void ModeratedEndorsementsManager::HandleChallengeAfterInit(
    MoleObserverContext observer_ctx,
    GURL request_url,
    std::string method,
    url::Origin reported_top_frame_origin,
    network::mojom::MoleRequestParamsPtr params,
    std::optional<std::string> mole_challenge_header,
    std::vector<std::string> www_authenticate_mole_headers,
    OnMoleChallengeReceivedCallback callback) {
  auto fail = [&]() {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
  };
  std::optional<url::Origin> verified_top =
      ResolveAuthorizedTopFrameOrigin(observer_ctx, reported_top_frame_origin);
  if (!store_ || !params || !verified_top.has_value() ||
      !request_url.SchemeIs("https")) {
    fail();
    return;
  }
  url::Origin top_frame_origin = std::move(*verified_top);

  if (!mole_challenge_header.has_value()) {
    if (!www_authenticate_mole_headers.empty()) {
      HandleInlineChallenge(std::move(request_url), std::move(top_frame_origin),
                            std::move(params),
                            std::move(www_authenticate_mole_headers),
                            std::move(callback));
      return;
    }
    fail();
    return;
  }

  // Parse the Moderator origin from `Mole-Challenge` or `params->moderator` to
  // look up its anti-split-view commitment BEFORE any network call!
  url::Origin candidate_mod;
  if (params->moderator.has_value()) {
    candidate_mod = *params->moderator;
  } else {
    const std::string& hdr = *mole_challenge_header;
    size_t pos = hdr.find("moderator=\"");
    if (pos != std::string::npos) {
      pos += 11;
      size_t end = hdr.find('"', pos);
      if (end != std::string::npos) {
        candidate_mod = url::Origin::Create(GURL(hdr.substr(pos, end - pos)));
      }
    }
  }
  if (candidate_mod.opaque() || candidate_mod.scheme() != "https" ||
      !network::IsOriginPotentiallyTrustworthy(candidate_mod)) {
    fail();
    return;
  }

  auto mod_commitment =
      MoleCommitmentRegistry::GetInstance().GetModeratorCommitment(
          candidate_mod);
  if (!mod_commitment.found) {
    fail();
    return;
  }

  const url::Origin target_origin = url::Origin::Create(request_url);
  auto eval = moderated_endorsements::parse_and_verify_split_challenge(
      target_origin.Serialize(), *mole_challenge_header, mod_commitment,
      NowUnixSecs());
  if (!eval.ok) {
    fail();
    return;
  }

  const url::Origin verified_mod =
      url::Origin::Create(GURL(std::string(eval.moderator_origin)));
  if (!verified_mod.IsSameOriginWith(candidate_mod) ||
      (params->max_cost > 0 && eval.cost > params->max_cost)) {
    fail();
    return;
  }

  auto committed_policy =
      MoleCommitmentRegistry::GetInstance().FindCommittedPolicy(
          verified_mod, std::string(eval.policy_id));
  if (!committed_policy.has_value()) {
    fail();
    return;
  }

  const int64_t now_us = NowMicros();
  if (!store_->CheckAndRecordModeratorAssociation(
          top_frame_origin.Serialize(), verified_mod.Serialize(), now_us)) {
    fail();
    return;
  }

  std::vector<uint8_t> primary_epoch =
      committed_policy->epochs.empty()
          ? std::vector<uint8_t>()
          : ToStdVec(committed_policy->epochs.front().bytes);
  if (store_->ShouldHoldoutPresentation(top_frame_origin.Serialize(),
                                        verified_mod.Serialize(),
                                        primary_epoch)) {
    fail();
    return;
  }

  EnsureModeratorConfig(
      verified_mod,
      base::BindOnce(
          &ModeratedEndorsementsManager::ContinueSplitChallengeWithConfig,
          weak_factory_.GetWeakPtr(), std::move(request_url), std::move(method),
          std::move(top_frame_origin), verified_mod,
          std::move(*committed_policy), std::move(eval),
          params->allow_deferred_update, std::move(callback)));
}

void ModeratedEndorsementsManager::EnsureModeratorConfig(
    const url::Origin& moderator_origin,
    base::OnceCallback<void(std::optional<std::string>)> callback) {
  const std::string key = moderator_origin.Serialize();
  auto it = moderator_config_cache_.find(key);
  if (it != moderator_config_cache_.end() &&
      base::TimeTicks::Now() < it->second.expires_at) {
    std::move(callback).Run(it->second.raw_json);
    return;
  }

  GURL dir_url = moderator_origin.GetURL().Resolve(kModeratorWellKnownPath);
  SendControlRequest(
      dir_url, net::HttpRequestHeaders::kGetMethod,
      /*credentialed_same_origin_anchor=*/std::nullopt, std::nullopt,
      std::nullopt, std::nullopt, base::NullCallback(),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             std::string mod_key,
             base::OnceCallback<void(std::optional<std::string>)> cb,
             ControlHttpResult res) {
            if (!self || res.net_error != net::OK || res.http_status < 200 ||
                res.http_status >= 300 || !res.body.has_value()) {
              std::move(cb).Run(std::nullopt);
              return;
            }
            self->moderator_config_cache_[mod_key] = CachedModeratorDirectory{
                *res.body, base::TimeTicks::Now() + kModeratorConfigCacheTtl};
            std::move(cb).Run(std::move(res.body));
          },
          weak_factory_.GetWeakPtr(), key, std::move(callback)));
}

void ModeratedEndorsementsManager::ContinueSplitChallengeWithConfig(
    GURL request_url,
    std::string method,
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    moderated_endorsements::CommittedPolicy committed_policy,
    moderated_endorsements::SplitChallengeEval eval,
    bool allow_deferred_update,
    OnMoleChallengeReceivedCallback callback,
    std::optional<std::string> mod_config_json) {
  if (!store_ || !mod_config_json.has_value()) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  // First settle any ready deferred spends strictly for THIS
  // `(top_frame_site, moderator_origin)` before reserving!
  auto ready = store_->GetReadySettlementsForSite(
      top_frame_origin.Serialize(), moderator_origin.Serialize(),
      /*force_signoff=*/false, NowMicros());
  if (!ready.empty()) {
    TriggerSettlements(
        std::move(ready),
        base::BindOnce(
            [](base::WeakPtr<ModeratedEndorsementsManager> self, GURL url,
               std::string m, url::Origin top_orig, url::Origin mod_orig,
               moderated_endorsements::CommittedPolicy pol,
               moderated_endorsements::SplitChallengeEval ev, bool allow_def,
               OnMoleChallengeReceivedCallback cb, std::string cfg_json,
               bool /*settled_ok*/) {
              if (!self) {
                return;
              }
              self->ContinueSplitChallengeWithConfig(
                  std::move(url), std::move(m), std::move(top_orig),
                  std::move(mod_orig), std::move(pol), std::move(ev), allow_def,
                  std::move(cb), std::move(cfg_json));
            },
            weak_factory_.GetWeakPtr(), std::move(request_url),
            std::move(method), std::move(top_frame_origin),
            std::move(moderator_origin), std::move(committed_policy),
            std::move(eval), allow_deferred_update, std::move(callback),
            std::move(*mod_config_json)));
    return;
  }

  if (auto reserved = store_->ReserveCredentialForPresent(
          top_frame_origin.Serialize(), moderator_origin.Serialize(),
          committed_policy, eval.cost, NowMicros())) {
    PresentReservedSplitCredential(
        std::move(request_url), std::move(method), std::move(top_frame_origin),
        std::move(moderator_origin), std::move(*mod_config_json),
        std::move(committed_policy), std::move(eval), allow_deferred_update,
        std::move(*reserved), std::move(callback));
    return;
  }

  // No idle credential with sufficient balance: check sticky ~5% bootstrap
  // holdout, then redeem an Endorsement (or 5m idempotency retry) via `/issue`.
  std::vector<uint8_t> primary_epoch =
      committed_policy.epochs.empty()
          ? std::vector<uint8_t>()
          : ToStdVec(committed_policy.epochs.front().bytes);
  if (store_->ShouldHoldoutBootstrap(top_frame_origin.Serialize(),
                                     moderator_origin.Serialize(),
                                     primary_epoch)) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  auto mod_commitment =
      MoleCommitmentRegistry::GetInstance().GetModeratorCommitment(
          moderator_origin);
  std::string cfg_copy = *mod_config_json;
  moderated_endorsements::CommittedPolicy pol_copy = committed_policy;
  url::Origin top_copy = top_frame_origin;
  RunSplitIssueAndContinue(
      std::move(top_copy), moderator_origin, std::move(cfg_copy),
      std::move(mod_commitment), std::move(pol_copy),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self, GURL url,
             std::string m, url::Origin top_orig, url::Origin mod_orig,
             std::string cfg_json, moderated_endorsements::CommittedPolicy pol,
             moderated_endorsements::SplitChallengeEval ev, bool allow_def,
             OnMoleChallengeReceivedCallback cb, bool issue_ok) {
            if (!self || !self->store_ || !issue_ok) {
              std::move(cb).Run(false, net::HttpRequestHeaders(),
                                mojo::NullRemote());
              return;
            }
            auto res = self->store_->ReserveCredentialForPresent(
                top_orig.Serialize(), mod_orig.Serialize(), pol, ev.cost,
                NowMicros());
            if (!res) {
              std::move(cb).Run(false, net::HttpRequestHeaders(),
                                mojo::NullRemote());
              return;
            }
            self->PresentReservedSplitCredential(
                std::move(url), std::move(m), std::move(top_orig),
                std::move(mod_orig), std::move(cfg_json), std::move(pol),
                std::move(ev), allow_def, std::move(*res), std::move(cb));
          },
          weak_factory_.GetWeakPtr(), std::move(request_url), std::move(method),
          std::move(top_frame_origin), moderator_origin,
          std::move(*mod_config_json), std::move(committed_policy),
          std::move(eval), allow_deferred_update, std::move(callback)));
}

void ModeratedEndorsementsManager::RunSplitIssueAndContinue(
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    std::string mod_config_json,
    moderated_endorsements::ModeratorCommitment mod_commitment,
    moderated_endorsements::CommittedPolicy committed_policy,
    base::OnceCallback<void(bool)> on_issue_done) {
  if (!store_) {
    std::move(on_issue_done).Run(false);
    return;
  }

  const int64_t now_us = NowMicros();

  // 1. Check 5-minute idempotency retry cache first (does NOT charge a new 24h
  // bootstrap budget since the endorsement was already redeemed in-flight).
  if (auto retry = store_->TakePendingIssueRetry(
          moderator_origin.Serialize(), std::string(committed_policy.policy_id),
          now_us)) {
    std::vector<uint8_t> bundle = retry->issuance_state_bundle.vec();
    DispatchSplitIssueHttp(
        moderator_origin, std::move(committed_policy), retry->op_generation,
        retry->endorsement_id, retry->pending_issue_id,
        /*bootstrap_reservation=*/std::nullopt, std::move(retry->issue_uri),
        std::move(retry->request_body), std::move(bundle),
        std::move(on_issue_done));
    return;
  }

  // 2. Enforce <= 1 automatic Endorsement bootstrap per `SchemefulSite` per
  // 24h BEFORE reserving an `Available` Endorsement!
  auto bootstrap_res =
      store_->TryConsumeBootstrapBudget(top_frame_origin.Serialize(), now_us);
  if (!bootstrap_res) {
    std::move(on_issue_done).Run(false);
    return;
  }

  // 3. Reserve an `Available` Endorsement in SQLite BEFORE building/sending!
  auto reserved_end = store_->ReserveEndorsementForIssue(committed_policy);
  if (!reserved_end) {
    store_->RollbackBootstrapBudget(*bootstrap_res);
    std::move(on_issue_done).Run(false);
    return;
  }

  const uint64_t op_gen = reserved_end->op_generation;
  const int64_t end_id = reserved_end->endorsement_id;
  std::vector<uint8_t> end_bytes = reserved_end->endorsement_bytes.vec();
  std::vector<uint8_t> ak = std::move(reserved_end->anchor_key);
  std::vector<uint8_t> ep = std::move(reserved_end->issuance_epoch);
  std::string mod_str = moderator_origin.Serialize();
  std::string pol_id(committed_policy.policy_id);

  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](std::string m_orig, std::string cfg,
             moderated_endorsements::ModeratorCommitment m_comm,
             std::string p_id, std::vector<uint8_t> eb, std::vector<uint8_t> a,
             std::vector<uint8_t> e) {
            return moderated_endorsements::build_split_issue_request(
                m_orig, cfg, m_comm, p_id, SpanToRustSlice(eb),
                SpanToRustSlice(a), SpanToRustSlice(e),
                rust::Slice<const uint8_t>());
          },
          std::move(mod_str), std::move(mod_config_json),
          std::move(mod_commitment), std::move(pol_id), std::move(end_bytes),
          std::move(ak), std::move(ep)),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin mod_orig, moderated_endorsements::CommittedPolicy pol,
             uint64_t gen, int64_t eid,
             moderated_endorsements::ModeratedEndorsementsStore::
                 BootstrapReservation boot_res,
             base::OnceCallback<void(bool)> done_cb,
             moderated_endorsements::SplitIssueBeginOut begin_out) {
            if (!self || !self->store_) {
              std::move(done_cb).Run(false);
              return;
            }
            if (!begin_out.ok) {
              self->store_->FailIssue(gen, eid, /*pending_issue_id=*/0,
                                      /*wire_bytes_sent=*/false,
                                      /*keep_idempotency_retry=*/false);
              self->store_->RollbackBootstrapBudget(boot_res);
              std::move(done_cb).Run(false);
              return;
            }
            std::vector<uint8_t> req_body = ToStdVec(begin_out.request_body);
            std::vector<uint8_t> bundle =
                ToStdVec(begin_out.issuance_state_bundle);
            auto pending_id = self->store_->RecordPendingIssueBeforeSend(
                gen, mod_orig.Serialize(), std::string(pol.policy_id), eid,
                ToStdVec(begin_out.idempotency_key),
                std::string(begin_out.issue_uri), req_body,
                ToZeroizing(begin_out.issuance_state_bundle), NowMicros());
            if (!pending_id) {
              self->store_->FailIssue(gen, eid, /*pending_issue_id=*/0,
                                      /*wire_bytes_sent=*/false,
                                      /*keep_idempotency_retry=*/false);
              self->store_->RollbackBootstrapBudget(boot_res);
              std::move(done_cb).Run(false);
              return;
            }
            self->DispatchSplitIssueHttp(
                std::move(mod_orig), std::move(pol), gen, eid, *pending_id,
                std::move(boot_res), std::string(begin_out.issue_uri),
                std::move(req_body), std::move(bundle), std::move(done_cb));
          },
          weak_factory_.GetWeakPtr(), std::move(moderator_origin),
          std::move(committed_policy), op_gen, end_id,
          std::move(*bootstrap_res), std::move(on_issue_done)));
}

void ModeratedEndorsementsManager::DispatchSplitIssueHttp(
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
    base::OnceCallback<void(bool)> on_issue_done) {
  GURL issue_url(issue_uri);
  if (!issue_url.is_valid() ||
      !moderator_origin.IsSameOriginWith(url::Origin::Create(issue_url))) {
    store_->FailIssue(op_generation, endorsement_id, pending_issue_id,
                      /*wire_bytes_sent=*/false,
                      /*keep_idempotency_retry=*/false);
    if (bootstrap_reservation.has_value()) {
      store_->RollbackBootstrapBudget(*bootstrap_reservation);
    }
    std::move(on_issue_done).Run(false);
    return;
  }

  std::string body_str = BytesToString(request_body);
  SendControlRequest(
      issue_url, net::HttpRequestHeaders::kPostMethod,
      /*credentialed_same_origin_anchor=*/std::nullopt, std::nullopt,
      kMoleEnvelopeMediaType, std::move(body_str),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self, int64_t pid) {
            if (self && self->store_) {
              self->store_->MarkIssueWireBytesSent(pid);
            }
          },
          weak_factory_.GetWeakPtr(), pending_issue_id),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin mod_orig, moderated_endorsements::CommittedPolicy pol,
             uint64_t gen, int64_t eid, int64_t pid,
             std::optional<moderated_endorsements::ModeratedEndorsementsStore::
                               BootstrapReservation>
                 boot_res,
             std::vector<uint8_t> bundle,
             base::OnceCallback<void(bool)> done_cb, ControlHttpResult res) {
            if (!self || !self->store_) {
              std::move(done_cb).Run(false);
              return;
            }
            if (res.net_error != net::OK || !res.body.has_value()) {
              self->store_->FailIssue(
                  gen, eid, pid, res.wire_bytes_sent,
                  /*keep_idempotency_retry=*/res.wire_bytes_sent);
              if (!res.wire_bytes_sent && boot_res.has_value()) {
                self->store_->RollbackBootstrapBudget(*boot_res);
              }
              std::move(done_cb).Run(false);
              return;
            }
            const uint16_t status = static_cast<uint16_t>(res.http_status);
            const uint64_t expected_bal = pol.initial_balance;
            std::string resp_body = std::move(*res.body);
            base::ThreadPool::PostTaskAndReplyWithResult(
                FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
                base::BindOnce(
                    [](std::vector<uint8_t> b, uint16_t st, std::string bd,
                       uint64_t exp_bal) {
                      return moderated_endorsements::
                          finalize_split_issue_response(
                              SpanToRustSlice(b), st, StringToRustSlice(bd),
                              exp_bal);
                    },
                    std::move(bundle), status, std::move(resp_body),
                    expected_bal),
                base::BindOnce(
                    [](base::WeakPtr<ModeratedEndorsementsManager> mgr,
                       url::Origin m_orig,
                       moderated_endorsements::CommittedPolicy p, uint64_t g,
                       int64_t e_id, int64_t p_id, uint16_t http_st,
                       base::OnceCallback<void(bool)> cb,
                       moderated_endorsements::SplitIssueFinishOut fin) {
                      if (!mgr || !mgr->store_) {
                        std::move(cb).Run(false);
                        return;
                      }
                      if (!fin.ok) {
                        mgr->store_->FailIssue(
                            g, e_id, p_id, /*wire_bytes_sent=*/true,
                            /*keep_idempotency_retry=*/http_st >= 500);
                        std::move(cb).Run(false);
                        return;
                      }
                      bool stored = mgr->store_->CompleteIssue(
                          g, e_id, p_id, m_orig.Serialize(),
                          ToStdVec(p.credential_context), ToStdVec(fin.key_id),
                          fin.balance_width, fin.balance,
                          ToZeroizing(fin.credential_bytes), NowMicros());
                      std::move(cb).Run(stored);
                    },
                    self, std::move(mod_orig), std::move(pol), gen, eid, pid,
                    status, std::move(done_cb)));
          },
          weak_factory_.GetWeakPtr(), std::move(moderator_origin),
          std::move(committed_policy), op_generation, endorsement_id,
          pending_issue_id, std::move(bootstrap_reservation),
          std::move(issuance_state_bundle), std::move(on_issue_done)));
}

void ModeratedEndorsementsManager::PresentReservedSplitCredential(
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
    OnMoleChallengeReceivedCallback callback) {
  const uint64_t op_gen = reserved.op_generation;
  const int64_t res_id = reserved.reservation_id;
  std::vector<uint8_t> cred_bytes = reserved.credential_bytes.vec();
  std::string mod_str = moderator_origin.Serialize();
  std::string target_orig = url::Origin::Create(request_url).Serialize();
  std::string path_query = PathAndQuery(request_url);
  std::vector<uint8_t> nonce = ToStdVec(eval.challenge_nonce);
  const uint64_t cost = eval.cost;
  moderated_endorsements::CommittedPolicy pol_copy = committed_policy;
  std::string method_copy = method;

  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](std::string m_orig, std::string cfg,
             moderated_endorsements::CommittedPolicy pol,
             std::vector<uint8_t> cb, std::string t_orig, std::string m,
             std::string pq, std::vector<uint8_t> n, uint64_t c,
             bool allow_def) {
            return moderated_endorsements::build_split_present_request(
                m_orig, cfg, pol, SpanToRustSlice(cb), t_orig, m, pq,
                SpanToRustSlice(n), c, allow_def);
          },
          std::move(mod_str), std::move(mod_config_json), std::move(pol_copy),
          std::move(cred_bytes), std::move(target_orig), std::move(method_copy),
          std::move(path_query), std::move(nonce), cost, allow_deferred_update),
      base::BindOnce(&ModeratedEndorsementsManager::OnSplitPresentBuilt,
                     weak_factory_.GetWeakPtr(), std::move(request_url),
                     std::move(method), std::move(top_frame_origin),
                     std::move(moderator_origin), std::move(committed_policy),
                     std::move(eval), op_gen, res_id, std::move(callback)));
}

void ModeratedEndorsementsManager::OnSplitPresentBuilt(
    GURL request_url,
    std::string method,
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    moderated_endorsements::CommittedPolicy committed_policy,
    moderated_endorsements::SplitChallengeEval eval,
    uint64_t op_generation,
    int64_t reservation_id,
    OnMoleChallengeReceivedCallback callback,
    moderated_endorsements::SplitPresentBeginOut begin_out) {
  if (!store_ || !begin_out.ok) {
    if (store_) {
      store_->ReleaseUnbuiltCredentialReservation(op_generation,
                                                  reservation_id);
    }
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  GURL present_url(std::string(begin_out.present_uri));
  if (!present_url.is_valid() ||
      !moderator_origin.IsSameOriginWith(url::Origin::Create(present_url))) {
    store_->ReleaseUnbuiltCredentialReservation(op_generation, reservation_id);
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  // Write-ahead SQLite flush BEFORE sending `POST /mole/v1/present`!
  std::vector<uint8_t> spend_bundle = ToStdVec(begin_out.spend_bundle);
  auto pending_spend_id = store_->RecordSpendBeforeSend(
      op_generation, reservation_id, std::string(begin_out.settle_uri),
      /*is_split=*/true, ToStdVec(begin_out.recovery_handle),
      ToZeroizing(begin_out.spend_bundle), NowMicros());
  if (!pending_spend_id) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  std::string body_str = RustBytesToString(begin_out.request_body);
  std::string target_orig = url::Origin::Create(request_url).Serialize();
  std::string path_query = PathAndQuery(request_url);
  SendControlRequest(
      present_url, net::HttpRequestHeaders::kPostMethod,
      /*credentialed_same_origin_anchor=*/std::nullopt, std::nullopt,
      kMoleEnvelopeMediaType, std::move(body_str), base::NullCallback(),
      base::BindOnce(&ModeratedEndorsementsManager::OnSplitPresentHttpComplete,
                     weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
                     std::move(moderator_origin), std::move(target_orig),
                     std::move(method), std::move(path_query),
                     std::move(committed_policy), std::move(eval),
                     op_generation, reservation_id, *pending_spend_id,
                     std::move(spend_bundle), std::move(callback)));
}

void ModeratedEndorsementsManager::OnSplitPresentHttpComplete(
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
    ControlHttpResult http_result) {
  if (!store_) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }
  if (http_result.net_error != net::OK || !http_result.body.has_value()) {
    store_->FailPresent(op_generation, reservation_id, pending_spend_id,
                        http_result.wire_bytes_sent,
                        /*keep_for_recovery=*/http_result.wire_bytes_sent);
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  const uint16_t status = static_cast<uint16_t>(http_result.http_status);
  const bool wire_sent = http_result.wire_bytes_sent;
  const uint64_t now_secs = NowUnixSecs();
  std::string resp_body = std::move(*http_result.body);
  std::string mod_str = moderator_origin.Serialize();

  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](std::vector<uint8_t> bundle, uint16_t st, std::string bd,
             moderated_endorsements::CommittedPolicy pol, std::string m_orig,
             moderated_endorsements::SplitChallengeEval ev, std::string t_orig,
             std::string m, std::string pq, uint64_t now_s) {
            return moderated_endorsements::finalize_split_present_response(
                SpanToRustSlice(bundle), st, StringToRustSlice(bd),
                RustVecToSlice(pol.clearance_public_key), m_orig,
                std::string(ev.policy_id), t_orig, m, pq,
                RustVecToSlice(ev.challenge_nonce), ev.cost,
                U64VecToSlice(pol.allowed_refund_amounts),
                /*include_grease=*/false, now_s);
          },
          std::move(spend_bundle), status, std::move(resp_body),
          std::move(committed_policy), std::move(mod_str), std::move(eval),
          std::move(target_origin), std::move(method),
          std::move(path_and_query), now_secs),
      base::BindOnce(&ModeratedEndorsementsManager::OnSplitPresentFinalized,
                     weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
                     std::move(moderator_origin), op_generation, reservation_id,
                     pending_spend_id, wire_sent, std::move(callback)));
}

void ModeratedEndorsementsManager::OnSplitPresentFinalized(
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    uint64_t op_generation,
    int64_t reservation_id,
    int64_t pending_spend_id,
    bool wire_bytes_sent,
    OnMoleChallengeReceivedCallback callback,
    moderated_endorsements::SplitPresentFinishOut finish_out) {
  if (!store_ || !finish_out.ok) {
    if (store_) {
      store_->FailPresent(op_generation, reservation_id, pending_spend_id,
                          wire_bytes_sent, finish_out.keep_spend_for_recovery);
    }
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  const int64_t now_us = NowMicros();
  if (finish_out.is_held) {
    const uint64_t clamped_delay_ms =
        std::min<uint64_t>(finish_out.min_delay_ms, kMaxHoldDurationMs);
    const int64_t hold_until_us = base::ClampAdd(
        now_us, static_cast<int64_t>(clamped_delay_ms) * 1'000);
    store_->MarkPresentHeld(op_generation, reservation_id, pending_spend_id,
                            std::string(finish_out.session_handle),
                            hold_until_us);
    // Schedule automatic background settlement once `clamped_delay_ms` elapses!
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(
            [](base::WeakPtr<ModeratedEndorsementsManager> self,
               url::Origin top_orig, url::Origin mod_orig) {
              if (!self || !self->store_ || self->is_shut_down_) {
                return;
              }
              auto ready = self->store_->GetReadySettlementsForSite(
                  top_orig.Serialize(), mod_orig.Serialize(),
                  /*force_signoff=*/false, NowMicros());
              if (!ready.empty()) {
                self->TriggerSettlements(std::move(ready), base::DoNothing());
              }
            },
            weak_factory_.GetWeakPtr(), top_frame_origin, moderator_origin),
        base::Milliseconds(clamped_delay_ms + 50));
  } else {
    store_->CompletePresentSettled(
        op_generation, reservation_id, pending_spend_id,
        finish_out.consumed_no_update, finish_out.new_balance,
        ToZeroizing(finish_out.refunded_credential_bytes), now_us);
  }

  net::HttpRequestHeaders retry_headers;
  retry_headers.SetHeader("Sec-Mole-Authorization",
                          std::string(finish_out.sec_mole_authorization));
  if (!finish_out.sec_mole_grease.empty()) {
    retry_headers.SetHeader("Sec-Mole-Grease",
                            std::string(finish_out.sec_mole_grease));
  }

  mojo::PendingRemote<network::mojom::MoleResponseFinalizer> finalizer_remote;
  finalizer_receivers_.Add(
      std::make_unique<PresentationFinalizer>(
          weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
          std::move(moderator_origin)),
      finalizer_remote.InitWithNewPipeAndPassReceiver());

  std::move(callback).Run(true, std::move(retry_headers),
                          std::move(finalizer_remote));
}

// --- `-01` Inline Redeem, Presentation, and Settlement ---

void ModeratedEndorsementsManager::HandleInlineChallenge(
    GURL request_url,
    url::Origin top_frame_origin,
    network::mojom::MoleRequestParamsPtr params,
    std::vector<std::string> www_authenticate_mole_headers,
    OnMoleChallengeReceivedCallback callback) {
  auto fail = [&]() {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
  };
  const url::Origin moderator_origin = url::Origin::Create(request_url);
  if (params->moderator.has_value() &&
      !params->moderator->IsSameOriginWith(moderator_origin)) {
    fail();
    return;
  }

  auto mod_commitment =
      MoleCommitmentRegistry::GetInstance().GetModeratorCommitment(
          moderator_origin);
  if (!mod_commitment.found) {
    fail();
    return;
  }

  rust::Vec<rust::String> rust_www;
  for (const std::string& h : www_authenticate_mole_headers) {
    rust_www.push_back(rust::String(h));
  }
  auto eval = moderated_endorsements::eval_inline_challenge(
      moderator_origin.Serialize(), rust_www, mod_commitment);
  if (!eval.ok ||
      (params->max_cost > 0 && eval.spend_amount > params->max_cost)) {
    fail();
    return;
  }

  std::optional<moderated_endorsements::CommittedPolicy> matched_policy;
  for (const auto& pol : mod_commitment.policies) {
    if (std::ranges::equal(pol.credential_context, eval.credential_context)) {
      matched_policy = pol;
      break;
    }
  }
  if (!matched_policy.has_value()) {
    fail();
    return;
  }

  const int64_t now_us = NowMicros();
  if (!store_->CheckAndRecordModeratorAssociation(
          top_frame_origin.Serialize(), moderator_origin.Serialize(), now_us)) {
    fail();
    return;
  }

  std::vector<uint8_t> primary_epoch =
      matched_policy->epochs.empty()
          ? std::vector<uint8_t>()
          : ToStdVec(matched_policy->epochs.front().bytes);
  if (store_->ShouldHoldoutPresentation(top_frame_origin.Serialize(),
                                        moderator_origin.Serialize(),
                                        primary_epoch)) {
    fail();
    return;
  }

  ContinueInlineChallenge(
      std::move(top_frame_origin), moderator_origin, std::move(mod_commitment),
      std::move(*matched_policy), std::move(eval),
      std::move(www_authenticate_mole_headers), std::move(callback));
}

void ModeratedEndorsementsManager::ContinueInlineChallenge(
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    moderated_endorsements::ModeratorCommitment mod_commitment,
    moderated_endorsements::CommittedPolicy matched_policy,
    moderated_endorsements::InlineChallengeEval eval,
    std::vector<std::string> www_authenticate_mole_headers,
    OnMoleChallengeReceivedCallback callback) {
  if (!store_) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  auto ready = store_->GetReadySettlementsForSite(
      top_frame_origin.Serialize(), moderator_origin.Serialize(),
      /*force_signoff=*/false, NowMicros());
  if (!ready.empty()) {
    TriggerSettlements(
        std::move(ready),
        base::BindOnce(
            [](base::WeakPtr<ModeratedEndorsementsManager> self,
               url::Origin top_orig, url::Origin mod_orig,
               moderated_endorsements::ModeratorCommitment comm,
               moderated_endorsements::CommittedPolicy pol,
               moderated_endorsements::InlineChallengeEval ev,
               std::vector<std::string> www_hdrs,
               OnMoleChallengeReceivedCallback cb, bool /*settled_ok*/) {
              if (!self) {
                return;
              }
              self->ContinueInlineChallenge(
                  std::move(top_orig), std::move(mod_orig), std::move(comm),
                  std::move(pol), std::move(ev), std::move(www_hdrs),
                  std::move(cb));
            },
            weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
            moderator_origin, std::move(mod_commitment),
            std::move(matched_policy), std::move(eval),
            std::move(www_authenticate_mole_headers), std::move(callback)));
    return;
  }

  if (auto reserved = store_->ReserveCredentialForPresent(
          top_frame_origin.Serialize(), moderator_origin.Serialize(),
          matched_policy, eval.spend_amount, NowMicros())) {
    PresentReservedInlineCredential(
        std::move(top_frame_origin), std::move(moderator_origin),
        std::move(matched_policy), std::move(eval), std::move(*reserved),
        std::move(callback));
    return;
  }

  if (!eval.has_ihat_redeem && !eval.can_use_no_endorsement) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  std::vector<uint8_t> primary_epoch =
      matched_policy.epochs.empty()
          ? std::vector<uint8_t>()
          : ToStdVec(matched_policy.epochs.front().bytes);
  if (store_->ShouldHoldoutBootstrap(top_frame_origin.Serialize(),
                                     moderator_origin.Serialize(),
                                     primary_epoch)) {
    std::move(callback).Run(false, net::HttpRequestHeaders(),
                            mojo::NullRemote());
    return;
  }

  url::Origin top_copy = top_frame_origin;
  moderated_endorsements::CommittedPolicy pol_copy = matched_policy;
  const bool allow_no_end = eval.can_use_no_endorsement;
  RunInlineRedeemAndContinue(
      std::move(top_copy), moderator_origin, std::move(mod_commitment),
      std::move(pol_copy), std::move(www_authenticate_mole_headers),
      allow_no_end,
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin top_orig, url::Origin mod_orig,
             moderated_endorsements::CommittedPolicy pol,
             moderated_endorsements::InlineChallengeEval ev,
             OnMoleChallengeReceivedCallback cb, bool redeem_ok) {
            if (!self || !self->store_ || !redeem_ok) {
              std::move(cb).Run(false, net::HttpRequestHeaders(),
                                mojo::NullRemote());
              return;
            }
            auto res = self->store_->ReserveCredentialForPresent(
                top_orig.Serialize(), mod_orig.Serialize(), pol,
                ev.spend_amount, NowMicros());
            if (!res) {
              std::move(cb).Run(false, net::HttpRequestHeaders(),
                                mojo::NullRemote());
              return;
            }
            self->PresentReservedInlineCredential(
                std::move(top_orig), std::move(mod_orig), std::move(pol),
                std::move(ev), std::move(*res), std::move(cb));
          },
          weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
          moderator_origin, std::move(matched_policy), std::move(eval),
          std::move(callback)));
}

void ModeratedEndorsementsManager::RunInlineRedeemAndContinue(
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    moderated_endorsements::ModeratorCommitment mod_commitment,
    moderated_endorsements::CommittedPolicy matched_policy,
    std::vector<std::string> www_authenticate_mole_headers,
    bool can_use_no_endorsement,
    base::OnceCallback<void(bool)> on_redeem_done) {
  EnsureModeratorConfig(
      moderator_origin,
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin top_orig, url::Origin mod_orig,
             moderated_endorsements::ModeratorCommitment comm,
             moderated_endorsements::CommittedPolicy pol,
             std::vector<std::string> www_hdrs, bool allow_no_end,
             base::OnceCallback<void(bool)> done_cb,
             std::optional<std::string> mod_cfg_json) {
            if (!self || !self->store_ || !mod_cfg_json.has_value()) {
              std::move(done_cb).Run(false);
              return;
            }
            const int64_t now_us = NowMicros();
            auto boot_res = self->store_->TryConsumeBootstrapBudget(
                top_orig.Serialize(), now_us);
            if (!boot_res) {
              std::move(done_cb).Run(false);
              return;
            }

            uint64_t op_gen = self->store_->current_generation();
            int64_t end_id = 0;
            std::vector<uint8_t> end_bytes;
            std::vector<uint8_t> ak;
            std::vector<uint8_t> ep;
            if (auto reserved_end =
                    self->store_->ReserveEndorsementForIssue(pol)) {
              op_gen = reserved_end->op_generation;
              end_id = reserved_end->endorsement_id;
              end_bytes = reserved_end->endorsement_bytes.vec();
              ak = std::move(reserved_end->anchor_key);
              ep = std::move(reserved_end->issuance_epoch);
            } else if (!allow_no_end) {
              self->store_->RollbackBootstrapBudget(*boot_res);
              std::move(done_cb).Run(false);
              return;
            }

            std::string mod_str = mod_orig.Serialize();
            base::ThreadPool::PostTaskAndReplyWithResult(
                FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
                base::BindOnce(
                    [](std::string m_str, std::string cfg,
                       std::vector<std::string> hdrs,
                       moderated_endorsements::ModeratorCommitment c,
                       std::vector<uint8_t> eb, std::vector<uint8_t> a,
                       std::vector<uint8_t> e) {
                      rust::Vec<rust::String> r_hdrs;
                      for (const std::string& h : hdrs) {
                        r_hdrs.push_back(rust::String(h));
                      }
                      return moderated_endorsements::build_inline_redeem_request(
                          m_str, cfg, r_hdrs, c, SpanToRustSlice(eb),
                          SpanToRustSlice(a), SpanToRustSlice(e));
                    },
                    std::move(mod_str), std::move(*mod_cfg_json),
                    std::move(www_hdrs), std::move(comm), std::move(end_bytes),
                    std::move(ak), std::move(ep)),
                base::BindOnce(
                    [](base::WeakPtr<ModeratedEndorsementsManager> mgr,
                       url::Origin m_orig,
                       moderated_endorsements::CommittedPolicy p, uint64_t gen,
                       int64_t eid,
                       moderated_endorsements::ModeratedEndorsementsStore::
                           BootstrapReservation b_res,
                       base::OnceCallback<void(bool)> cb,
                       moderated_endorsements::InlineRedeemBeginOut begin_out) {
                      if (!mgr || !mgr->store_) {
                        std::move(cb).Run(false);
                        return;
                      }
                      GURL redeem_url(std::string(begin_out.issuance_uri));
                      if (!begin_out.ok || !redeem_url.is_valid() ||
                          !m_orig.IsSameOriginWith(
                              url::Origin::Create(redeem_url))) {
                        if (eid > 0) {
                          mgr->store_->FailIssue(gen, eid,
                                                 /*pending_issue_id=*/0,
                                                 /*wire_bytes_sent=*/false,
                                                 /*keep_idempotency_retry=*/false);
                        }
                        mgr->store_->RollbackBootstrapBudget(b_res);
                        std::move(cb).Run(false);
                        return;
                      }

                      int64_t pid = 0;
                      if (eid > 0) {
                        std::array<uint8_t, 16> idem;
                        crypto::RandBytes(idem);
                        std::vector<uint8_t> idem_vec(idem.begin(), idem.end());
                        auto recorded =
                            mgr->store_->RecordPendingIssueBeforeSend(
                                gen, m_orig.Serialize(),
                                std::string(p.policy_id), eid, idem_vec,
                                std::string(begin_out.issuance_uri),
                                std::vector<uint8_t>(),
                                ToZeroizing(begin_out.issuance_state_bundle),
                                NowMicros());
                        if (!recorded) {
                          mgr->store_->FailIssue(gen, eid,
                                                 /*pending_issue_id=*/0,
                                                 /*wire_bytes_sent=*/false,
                                                 /*keep_idempotency_retry=*/false);
                          mgr->store_->RollbackBootstrapBudget(b_res);
                          std::move(cb).Run(false);
                          return;
                        }
                        pid = *recorded;
                      }

                      std::string auth_hdr(begin_out.authorization_header);
                      std::vector<uint8_t> state_bundle =
                          ToStdVec(begin_out.issuance_state_bundle);
                      mgr->SendControlRequest(
                          redeem_url, net::HttpRequestHeaders::kPostMethod,
                          /*credentialed_same_origin_anchor=*/std::nullopt,
                          auth_hdr, std::nullopt, std::string(),
                          base::NullCallback(),
                          base::BindOnce(
                              [](base::WeakPtr<ModeratedEndorsementsManager> m,
                                 url::Origin mod,
                                 moderated_endorsements::CommittedPolicy pol_in,
                                 uint64_t g, int64_t e_id, int64_t p_id,
                                 moderated_endorsements::
                                     ModeratedEndorsementsStore::
                                         BootstrapReservation br,
                                 std::vector<uint8_t> bundle,
                                 base::OnceCallback<void(bool)> done,
                                 ControlHttpResult http_res) {
                                if (!m || !m->store_) {
                                  std::move(done).Run(false);
                                  return;
                                }
                                if (http_res.net_error != net::OK ||
                                    http_res.http_status < 200 ||
                                    http_res.http_status >= 300 ||
                                    !http_res.mole_credential.has_value()) {
                                  if (e_id > 0) {
                                    m->store_->FailIssue(
                                        g, e_id, p_id, http_res.wire_bytes_sent,
                                        /*keep_idempotency_retry=*/false);
                                  }
                                  if (!http_res.wire_bytes_sent) {
                                    m->store_->RollbackBootstrapBudget(br);
                                  }
                                  std::move(done).Run(false);
                                  return;
                                }
                                std::string cred_hdr =
                                    *http_res.mole_credential;
                                const uint64_t exp_bal = pol_in.initial_balance;
                                base::ThreadPool::PostTaskAndReplyWithResult(
                                    FROM_HERE,
                                    {base::MayBlock(),
                                     base::TaskPriority::USER_VISIBLE},
                                    base::BindOnce(
                                        [](std::vector<uint8_t> sb,
                                           std::string ch, uint64_t bal) {
                                          return moderated_endorsements::
                                              finalize_inline_redeem_response(
                                                  SpanToRustSlice(sb), ch, bal);
                                        },
                                        std::move(bundle), std::move(cred_hdr),
                                        exp_bal),
                                    base::BindOnce(
                                        [](base::WeakPtr<
                                               ModeratedEndorsementsManager>
                                               mgr2,
                                           url::Origin mod2,
                                           moderated_endorsements::
                                               CommittedPolicy pol2,
                                           uint64_t g2, int64_t eid2,
                                           int64_t pid2,
                                           base::OnceCallback<void(bool)> done2,
                                           moderated_endorsements::
                                               SplitIssueFinishOut fin) {
                                          if (!mgr2 || !mgr2->store_) {
                                            std::move(done2).Run(false);
                                            return;
                                          }
                                          if (!fin.ok) {
                                            if (eid2 > 0) {
                                              mgr2->store_->FailIssue(
                                                  g2, eid2, pid2,
                                                  /*wire_bytes_sent=*/true,
                                                  /*keep_idempotency_retry=*/false);
                                            }
                                            std::move(done2).Run(false);
                                            return;
                                          }
                                          bool ok = mgr2->store_->CompleteIssue(
                                              g2, eid2, pid2, mod2.Serialize(),
                                              ToStdVec(pol2.credential_context),
                                              ToStdVec(fin.key_id),
                                              fin.balance_width, fin.balance,
                                              ToZeroizing(fin.credential_bytes),
                                              NowMicros());
                                          std::move(done2).Run(ok);
                                        },
                                        m, std::move(mod), std::move(pol_in), g,
                                        e_id, p_id, std::move(done)));
                              },
                              mgr, std::move(m_orig), std::move(p), gen, eid,
                              pid, std::move(b_res), std::move(state_bundle),
                              std::move(cb)));
                    },
                    self, std::move(mod_orig), std::move(pol), op_gen, end_id,
                    std::move(*boot_res), std::move(done_cb)));
          },
          weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
          moderator_origin, std::move(mod_commitment),
          std::move(matched_policy), std::move(www_authenticate_mole_headers),
          can_use_no_endorsement, std::move(on_redeem_done)));
}

void ModeratedEndorsementsManager::PresentReservedInlineCredential(
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    moderated_endorsements::CommittedPolicy matched_policy,
    moderated_endorsements::InlineChallengeEval eval,
    moderated_endorsements::ModeratedEndorsementsStore::ReservedCredential
        reserved,
    OnMoleChallengeReceivedCallback callback) {
  const uint64_t op_gen = reserved.op_generation;
  const int64_t res_id = reserved.reservation_id;
  std::vector<uint8_t> cred_bytes = reserved.credential_bytes.vec();
  std::vector<uint8_t> raw_act = ToStdVec(eval.raw_act_challenge);
  const uint64_t spend_amt = eval.spend_amount;
  const uint64_t max_top = eval.max_top_up;
  std::vector<uint64_t> allowed_tiers(
      matched_policy.allowed_refund_amounts.begin(),
      matched_policy.allowed_refund_amounts.end());
  std::string settle_uri(matched_policy.issuance_uri);
  if (settle_uri.empty()) {
    settle_uri = moderator_origin.GetURL().Resolve("/.well-known/mole-issuer").spec();
  }

  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](moderated_endorsements::CommittedPolicy p, std::vector<uint8_t> cb,
             std::vector<uint8_t> ch, uint64_t s, uint64_t m) {
            return moderated_endorsements::build_inline_present_request(
                p, SpanToRustSlice(cb), SpanToRustSlice(ch), s, m);
          },
          std::move(matched_policy), std::move(cred_bytes), std::move(raw_act),
          spend_amt, max_top),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin top_orig, url::Origin mod_orig, uint64_t gen,
             int64_t rid, std::string s_uri, std::vector<uint64_t> tiers,
             OnMoleChallengeReceivedCallback cb,
             moderated_endorsements::InlinePresentBeginOut begin_out) {
            if (!self || !self->store_ || !begin_out.ok) {
              if (self && self->store_) {
                self->store_->ReleaseUnbuiltCredentialReservation(gen, rid);
              }
              std::move(cb).Run(false, net::HttpRequestHeaders(),
                                mojo::NullRemote());
              return;
            }
            std::vector<uint8_t> bundle = ToStdVec(begin_out.spend_bundle);
            auto ps_id = self->store_->RecordSpendBeforeSend(
                gen, rid, s_uri, /*is_split=*/false,
                ToStdVec(begin_out.recovery_handle),
                ToZeroizing(begin_out.spend_bundle), NowMicros());
            if (!ps_id) {
              std::move(cb).Run(false, net::HttpRequestHeaders(),
                                mojo::NullRemote());
              return;
            }
            net::HttpRequestHeaders retry_headers;
            retry_headers.SetHeader(
                net::HttpRequestHeaders::kAuthorization,
                std::string(begin_out.authorization_header));
            mojo::PendingRemote<network::mojom::MoleResponseFinalizer>
                fin_remote;
            self->finalizer_receivers_.Add(
                std::make_unique<PresentationFinalizer>(
                    self, std::move(top_orig), std::move(mod_orig), gen, rid,
                    *ps_id, std::move(bundle), std::move(tiers)),
                fin_remote.InitWithNewPipeAndPassReceiver());
            std::move(cb).Run(true, std::move(retry_headers),
                              std::move(fin_remote));
          },
          weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
          std::move(moderator_origin), op_gen, res_id, std::move(settle_uri),
          std::move(allowed_tiers), std::move(callback)));
}

void ModeratedEndorsementsManager::SettleInlineResponse(
    url::Origin top_frame_origin,
    url::Origin moderator_origin,
    uint64_t op_generation,
    int64_t reservation_id,
    int64_t pending_spend_id,
    std::vector<uint8_t> spend_bundle,
    std::vector<uint64_t> allowed_refund_amounts,
    int32_t /*http_status*/,
    const std::optional<std::string>& mole_credential_header,
    bool wire_bytes_sent,
    base::OnceClosure done_cb) {
  if (!store_) {
    std::move(done_cb).Run();
    return;
  }
  if (!mole_credential_header.has_value()) {
    store_->FailPresent(op_generation, reservation_id, pending_spend_id,
                        wire_bytes_sent, /*keep_for_recovery=*/wire_bytes_sent);
    std::move(done_cb).Run();
    return;
  }
  std::string cred_hdr = *mole_credential_header;
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](std::vector<uint8_t> b, std::string hdr, std::vector<uint64_t> t) {
            return moderated_endorsements::finalize_inline_present_response(
                SpanToRustSlice(b), hdr,
                rust::Slice<const uint64_t>(t.data(), t.size()));
          },
          std::move(spend_bundle), std::move(cred_hdr),
          std::move(allowed_refund_amounts)),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self,
             url::Origin top_orig, url::Origin mod_orig, uint64_t gen,
             int64_t rid, int64_t pid, bool wire_sent, base::OnceClosure cb,
             moderated_endorsements::InlinePresentFinishOut fin) {
            if (self && self->store_) {
              const int64_t now_us = NowMicros();
              if (!fin.ok) {
                self->store_->FailPresent(gen, rid, pid, wire_sent,
                                          fin.keep_spend_for_recovery);
              } else if (fin.is_held) {
                const uint64_t clamped_delay_ms = std::min<uint64_t>(
                    fin.held_for_secs > kMaxHoldDurationMs / 1'000
                        ? kMaxHoldDurationMs
                        : fin.held_for_secs * 1'000,
                    kMaxHoldDurationMs);
                const int64_t hold_until_us = base::ClampAdd(
                    now_us, static_cast<int64_t>(clamped_delay_ms) * 1'000);
                self->store_->MarkPresentHeld(gen, rid, pid, std::string(),
                                              hold_until_us);
                base::SingleThreadTaskRunner::GetCurrentDefault()
                    ->PostDelayedTask(
                        FROM_HERE,
                        base::BindOnce(
                            [](base::WeakPtr<ModeratedEndorsementsManager> mgr,
                               url::Origin t_orig, url::Origin m_orig) {
                              if (!mgr || !mgr->store_ || mgr->is_shut_down_) {
                                return;
                              }
                              auto ready =
                                  mgr->store_->GetReadySettlementsForSite(
                                      t_orig.Serialize(), m_orig.Serialize(),
                                      /*force_signoff=*/false, NowMicros());
                              if (!ready.empty()) {
                                mgr->TriggerSettlements(std::move(ready),
                                                        base::DoNothing());
                              }
                            },
                            self, std::move(top_orig), std::move(mod_orig)),
                        base::Milliseconds(clamped_delay_ms + 50));
              } else {
                self->store_->CompletePresentSettled(
                    gen, rid, pid, fin.consumed_no_update, fin.new_balance,
                    ToZeroizing(fin.refunded_credential_bytes), now_us);
              }
            }
            std::move(cb).Run();
          },
          weak_factory_.GetWeakPtr(), std::move(top_frame_origin),
          std::move(moderator_origin), op_generation, reservation_id,
          pending_spend_id, wire_bytes_sent, std::move(done_cb)));
}

void ModeratedEndorsementsManager::AbortInlinePresentation(
    uint64_t op_generation,
    int64_t reservation_id,
    int64_t pending_spend_id,
    bool wire_bytes_sent) {
  if (store_) {
    store_->FailPresent(op_generation, reservation_id, pending_spend_id,
                        wire_bytes_sent, /*keep_for_recovery=*/wire_bytes_sent);
  }
}

void ModeratedEndorsementsManager::OnOriginMoleInfoReceived(
    const url::Origin& top_frame_origin,
    const url::Origin& moderator_origin,
    const std::optional<std::string>& mole_info) {
  if (!store_ || !mole_info.has_value() || is_shut_down_) {
    return;
  }
  auto info = moderated_endorsements::parse_mole_info_header(*mole_info);
  if (!info.ok || !info.settle_ready) {
    return;
  }
  if (store_->MarkSessionSettleReady(top_frame_origin.Serialize(),
                                     moderator_origin.Serialize(),
                                     std::string(info.session_handle),
                                     NowMicros())) {
    auto ready = store_->GetReadySettlementsForSite(
        top_frame_origin.Serialize(), moderator_origin.Serialize(),
        /*force_signoff=*/false, NowMicros());
    if (!ready.empty()) {
      TriggerSettlements(std::move(ready), base::DoNothing());
    }
  }
}

void ModeratedEndorsementsManager::TriggerSettlements(
    std::vector<
        moderated_endorsements::ModeratedEndorsementsStore::ReadySettlement>
        settlements,
    base::OnceCallback<void(bool)> done_callback) {
  if (settlements.empty()) {
    std::move(done_callback).Run(true);
    return;
  }

  auto barrier = base::BarrierCallback<bool>(
      settlements.size(),
      base::BindOnce(
          [](base::OnceCallback<void(bool)> cb,
             const std::vector<bool>& results) {
            std::move(cb).Run(std::ranges::all_of(results, std::identity{}));
          },
          std::move(done_callback)));

  for (auto& item : settlements) {
    DispatchSingleSettlement(std::move(item), barrier);
  }
}

void ModeratedEndorsementsManager::DispatchSingleSettlement(
    moderated_endorsements::ModeratedEndorsementsStore::ReadySettlement item,
    base::OnceCallback<void(bool)> item_done) {
  GURL settle_url(item.settle_uri);
  url::Origin mod_origin = url::Origin::Create(GURL(item.moderator_origin));
  if (!settle_url.is_valid() ||
      !mod_origin.IsSameOriginWith(url::Origin::Create(settle_url))) {
    if (store_) {
      store_->CompleteSettlement(
          item.op_generation, item.pending_spend_id, /*keep_for_retry=*/false,
          /*credential_restored=*/false, /*new_balance=*/0,
          moderated_endorsements::ZeroizingBytes(), NowMicros(),
          kDefaultSettlementRetryAfterMs);
    }
    std::move(item_done).Run(false);
    return;
  }

  auto mod_commitment =
      MoleCommitmentRegistry::GetInstance().GetModeratorCommitment(mod_origin);
  std::vector<uint64_t> allowed_vec;
  for (const auto& pol : mod_commitment.policies) {
    if (std::ranges::equal(pol.credential_context, item.credential_context)) {
      allowed_vec.assign(pol.allowed_refund_amounts.begin(),
                         pol.allowed_refund_amounts.end());
      break;
    }
  }

  std::vector<uint8_t> spend_bundle = item.spend_bundle.vec();
  const uint64_t op_gen = item.op_generation;
  const int64_t ps_id = item.pending_spend_id;

  if (!item.is_split) {
    // `-01` Inline settlement (`Authorization: Mole recovery-0001=...`).
    std::string auth_hdr(
        moderated_endorsements::build_inline_settlement_header(
            SpanToRustSlice(item.recovery_handle), item.is_signoff));
    SendControlRequest(
        settle_url, net::HttpRequestHeaders::kPostMethod,
        /*credentialed_same_origin_anchor=*/std::nullopt, auth_hdr,
        std::nullopt, std::string(), base::NullCallback(),
        base::BindOnce(
            [](base::WeakPtr<ModeratedEndorsementsManager> self, uint64_t gen,
               int64_t spend_id, std::vector<uint8_t> bundle,
               std::vector<uint64_t> tiers,
               base::OnceCallback<void(bool)> done_cb, ControlHttpResult res) {
              if (!self || !self->store_) {
                std::move(done_cb).Run(false);
                return;
              }
              if (res.net_error != net::OK) {
                self->store_->CompleteSettlement(
                    gen, spend_id, /*keep_for_retry=*/true,
                    /*credential_restored=*/false, /*new_balance=*/0,
                    moderated_endorsements::ZeroizingBytes(), NowMicros(),
                    kDefaultSettlementRetryAfterMs);
                std::move(done_cb).Run(false);
                return;
              }
              const uint16_t st = static_cast<uint16_t>(res.http_status);
              std::string cred_hdr =
                  res.mole_credential.value_or(std::string());
              base::ThreadPool::PostTaskAndReplyWithResult(
                  FROM_HERE,
                  {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
                  base::BindOnce(
                      [](std::vector<uint8_t> b, uint16_t status,
                         std::string hdr, std::vector<uint64_t> t) {
                        return moderated_endorsements::
                            finalize_inline_settlement_response(
                                SpanToRustSlice(b), status, hdr,
                                rust::Slice<const uint64_t>(t.data(),
                                                            t.size()));
                      },
                      std::move(bundle), st, std::move(cred_hdr),
                      std::move(tiers)),
                  base::BindOnce(
                      [](base::WeakPtr<ModeratedEndorsementsManager> mgr,
                         uint64_t g, int64_t sid,
                         base::OnceCallback<void(bool)> cb,
                         moderated_endorsements::SplitSettleFinishOut fin) {
                        if (!mgr || !mgr->store_) {
                          std::move(cb).Run(false);
                          return;
                        }
                        mgr->store_->CompleteSettlement(
                            g, sid, fin.keep_spend_for_retry,
                            fin.credential_restored, fin.new_balance,
                            ToZeroizing(fin.refunded_credential_bytes),
                            NowMicros(), kDefaultSettlementRetryAfterMs);
                        std::move(cb).Run(fin.ok);
                      },
                      self, gen, spend_id, std::move(done_cb)));
            },
            weak_factory_.GetWeakPtr(), op_gen, ps_id, std::move(spend_bundle),
            std::move(allowed_vec), std::move(item_done)));
    return;
  }

  rust::Vec<uint8_t> req_vec =
      moderated_endorsements::build_split_settle_request(
          item.session_handle, SpanToRustSlice(item.recovery_handle),
          item.is_signoff);
  std::string body_str = RustBytesToString(req_vec);

  SendControlRequest(
      settle_url, net::HttpRequestHeaders::kPostMethod,
      /*credentialed_same_origin_anchor=*/std::nullopt, std::nullopt,
      kMoleEnvelopeMediaType, std::move(body_str), base::NullCallback(),
      base::BindOnce(
          [](base::WeakPtr<ModeratedEndorsementsManager> self, uint64_t gen,
             int64_t spend_id, std::vector<uint8_t> bundle,
             std::vector<uint64_t> tiers,
             base::OnceCallback<void(bool)> done_cb, ControlHttpResult res) {
            if (!self || !self->store_) {
              std::move(done_cb).Run(false);
              return;
            }
            if (res.net_error != net::OK || !res.body.has_value()) {
              self->store_->CompleteSettlement(
                  gen, spend_id, /*keep_for_retry=*/true,
                  /*credential_restored=*/false, /*new_balance=*/0,
                  moderated_endorsements::ZeroizingBytes(), NowMicros(),
                  kDefaultSettlementRetryAfterMs);
              std::move(done_cb).Run(false);
              return;
            }
            const uint16_t st = static_cast<uint16_t>(res.http_status);
            std::string bd = std::move(*res.body);
            base::ThreadPool::PostTaskAndReplyWithResult(
                FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
                base::BindOnce(
                    [](std::vector<uint8_t> b, uint16_t status,
                       std::string body, std::vector<uint64_t> t) {
                      return moderated_endorsements::
                          finalize_split_settle_response(
                              SpanToRustSlice(b), status,
                              StringToRustSlice(body),
                              rust::Slice<const uint64_t>(t.data(), t.size()));
                    },
                    std::move(bundle), st, std::move(bd), std::move(tiers)),
                base::BindOnce(
                    [](base::WeakPtr<ModeratedEndorsementsManager> mgr,
                       uint64_t g, int64_t sid,
                       base::OnceCallback<void(bool)> cb,
                       moderated_endorsements::SplitSettleFinishOut fin) {
                      if (!mgr || !mgr->store_) {
                        std::move(cb).Run(false);
                        return;
                      }
                      mgr->store_->CompleteSettlement(
                          g, sid, fin.keep_spend_for_retry,
                          fin.credential_restored, fin.new_balance,
                          ToZeroizing(fin.refunded_credential_bytes),
                          NowMicros(), kDefaultSettlementRetryAfterMs);
                      std::move(cb).Run(fin.ok);
                    },
                    self, gen, spend_id, std::move(done_cb)));
          },
          weak_factory_.GetWeakPtr(), op_gen, ps_id, std::move(spend_bundle),
          std::move(allowed_vec), std::move(item_done)));
}

}  // namespace content
