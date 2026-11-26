// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/moderated_endorsement_service_impl.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/browser/moderated_endorsements/mole_commitment_registry.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/storage_partition.h"
#include "net/cookies/site_for_cookies.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {

namespace {

using blink::mojom::EndorsementStatus;

// Well-known discovery paths (`draft-jms-mole-protocols-01` §6).
constexpr char kAnchorDirectoryPath[] = "/.well-known/mole-anchor";
constexpr char kModeratorDirectoryPath[] = "/.well-known/mole-moderator";

constexpr char kMoleCredentialHeader[] = "Mole-Credential";
constexpr char kContentTypeHeader[] = "Content-Type";

// Number of EC-IHAT Endorsements requested per Anchor grant batch (`count`).
constexpr uint16_t kDefaultGrantBatchCount = 4;

// Grant/redeem/present exchanges carry kilobyte-scale material; 1MB is a
// generous protocol ceiling.
constexpr size_t kMaxBodySize = 1024 * 1024;

// Bounds retries when an exhausted credential is drained during `Present()`.
constexpr int kMaxChallengeAttempts = 3;

constexpr net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("moderated_endorsements_fetch", R"(
    semantics {
      sender: "Moderated Endorsements"
      description:
        "Exchanges for the experimental MOLE (Moderation of unLinkable "
        "Endorsements) implementation: collecting EC-IHAT endorsements from "
        "an Anchor, and redeeming/presenting EC-ACT anonymous credentials "
        "against a Moderator when the page calls navigator.endorsement APIs."
      trigger: "A page calls navigator.endorsement.collect()/challenge()."
      data:
        "MOLE protocol messages: blinded cryptographic material and "
        "zero-knowledge proofs. Moderator requests carry no cookies."
      destination: OTHER
    }
    policy {
      cookies_allowed: NO
      setting: "Gated behind the experimental ModeratedEndorsements feature."
      policy_exception_justification: "Experimental demonstration API."
    })");

std::string BytesToString(const rust::Vec<uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

rust::Slice<const uint8_t> StringToSlice(const std::string& s) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                    s.size());
}

uint64_t NowUnixSecs() {
  double secs = base::Time::Now().InSecondsFSinceUnixEpoch();
  return secs > 0.0 ? static_cast<uint64_t>(secs) : 0u;
}

std::vector<std::string> WwwAuthenticateValues(
    const net::HttpResponseHeaders& headers) {
  std::vector<std::string> values;
  size_t iter = 0;
  std::string value;
  while (headers.EnumerateHeader(&iter, "WWW-Authenticate", &value)) {
    values.push_back(value);
  }
  return values;
}

bool AllUtf8(const std::vector<std::string>& values) {
  for (const auto& value : values) {
    if (!base::IsStringUTF8(value)) {
      return false;
    }
  }
  return true;
}

rust::Vec<rust::String> ToRustStrings(const std::vector<std::string>& values) {
  rust::Vec<rust::String> out;
  for (const auto& value : values) {
    out.push_back(rust::String(value));
  }
  return out;
}

}  // namespace

// static
void ModeratedEndorsementServiceImpl::Create(
    RenderFrameHost* render_frame_host,
    mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver) {
  CHECK(render_frame_host);
  new ModeratedEndorsementServiceImpl(*render_frame_host, std::move(receiver));
}

ModeratedEndorsementServiceImpl::ModeratedEndorsementServiceImpl(
    RenderFrameHost& render_frame_host,
    mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver)
    : DocumentService(render_frame_host, std::move(receiver)) {}

ModeratedEndorsementServiceImpl::~ModeratedEndorsementServiceImpl() {
  // Clean up any half-open ephemeral grant/redeem states in the Rust client
  // if the document navigates away or closes mid-exchange. (`ScopedFlight`
  // objects bound inside `loaders_in_progress_` release per-Moderator flights
  // automatically as `loaders_in_progress_` tears down.)
  if (!active_grant_ids_.empty() || !active_redeem_ids_.empty()) {
    MoleClientHolder& client_holder = holder();
    for (uint64_t grant_id : active_grant_ids_) {
      client_holder.client().grant_abort(grant_id);
    }
    for (uint64_t redeem_id : active_redeem_ids_) {
      client_holder.client().redeem_abort(redeem_id);
    }
  }
}

MoleClientHolder& ModeratedEndorsementServiceImpl::holder() {
  return MoleClientHolder::GetOrCreate(render_frame_host().GetBrowserContext());
}

void ModeratedEndorsementServiceImpl::Fetch(
    const GURL& url,
    const std::string& method,
    const std::string& authorization,
    const std::string& upload_content_type,
    std::optional<std::string> upload_body,
    bool send_credentials,
    FetchCallback callback) {
  if (!url_loader_factory_) {
    url_loader_factory_ = render_frame_host()
                              .GetStoragePartition()
                              ->GetURLLoaderFactoryForBrowserProcess();
  }

  auto resource_request = std::make_unique<network::ResourceRequest>();
  resource_request->url = url;
  resource_request->method = method;
  resource_request->credentials_mode =
      send_credentials ? network::mojom::CredentialsMode::kInclude
                       : network::mojom::CredentialsMode::kOmit;
  if (send_credentials) {
    const url::Origin& document_origin = origin();
    resource_request->request_initiator = document_origin;
    resource_request->site_for_cookies =
        net::SiteForCookies::FromOrigin(document_origin);
  }
  if (!authorization.empty()) {
    resource_request->headers.SetHeader(net::HttpRequestHeaders::kAuthorization,
                                        authorization);
  }

  auto loader = network::SimpleURLLoader::Create(std::move(resource_request),
                                                 kTrafficAnnotation);
  if (upload_body.has_value()) {
    loader->AttachStringForUpload(*upload_body, upload_content_type);
  }
  loader->SetAllowHttpErrorResults(true);
  loader->SetTimeoutDuration(base::Seconds(30));

  network::SimpleURLLoader* loader_ptr = loader.get();
  auto it = loaders_in_progress_.insert(loaders_in_progress_.begin(),
                                        std::move(loader));
  loader_ptr->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&ModeratedEndorsementServiceImpl::OnFetchComplete,
                     base::Unretained(this), it, std::move(callback)),
      kMaxBodySize);
}

void ModeratedEndorsementServiceImpl::OnFetchComplete(
    UrlLoaderList::iterator it,
    FetchCallback callback,
    std::optional<std::string> body) {
  std::unique_ptr<network::SimpleURLLoader> loader = std::move(*it);
  loaders_in_progress_.erase(it);

  scoped_refptr<net::HttpResponseHeaders> headers;
  if (loader->ResponseInfo() && loader->ResponseInfo()->headers) {
    headers = loader->ResponseInfo()->headers;
  }
  std::move(callback).Run(std::move(body), std::move(headers));
}

// --- collect() ------------------------------------------------------------

void ModeratedEndorsementServiceImpl::Collect(const GURL& endorse_url,
                                              CollectCallback callback) {
  // Per `draft-jms-mole-http-transport-01` §2, all MOLE exchanges require HTTPS
  // and `collect()` must be same-origin with the document.
  if (!endorse_url.is_valid() || !endorse_url.SchemeIsCryptographic() ||
      !origin().IsSameOriginWith(endorse_url)) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }
  holder().PostWhenLoaded(base::BindOnce(
      &ModeratedEndorsementServiceImpl::CollectImpl, weak_factory_.GetWeakPtr(),
      endorse_url, std::move(callback)));
}

void ModeratedEndorsementServiceImpl::CollectImpl(const GURL& endorse_url,
                                                  CollectCallback callback) {
  GURL directory_url =
      endorse_url.GetWithEmptyPath().Resolve(kAnchorDirectoryPath);
  Fetch(directory_url, "GET", /*authorization=*/{},
        /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
        /*send_credentials=*/true,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnAnchorDirectory,
                       weak_factory_.GetWeakPtr(), endorse_url,
                       std::move(callback)));
}

void ModeratedEndorsementServiceImpl::OnAnchorDirectory(
    const GURL& endorse_url,
    CollectCallback callback,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers || !body) {
    std::move(callback).Run(EndorsementStatus::kNetworkError);
    return;
  }
  if (headers->response_code() != 200) {
    std::move(callback).Run(headers->response_code() >= 500
                                ? EndorsementStatus::kNetworkError
                                : EndorsementStatus::kRejected);
    return;
  }
  if (!base::IsStringUTF8(*body)) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }

  url::Origin anchor_origin = url::Origin::Create(endorse_url);
  auto commitment =
      MoleCommitmentRegistry::GetInstance().GetAnchorCommitment(anchor_origin);
  std::string serialized_origin = anchor_origin.Serialize();
  auto begin = holder().client().grant_begin(
      rust::Str(serialized_origin), rust::Str(*body), commitment,
      kDefaultGrantBatchCount);
  if (!begin.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }

  GURL grant_url(std::string(begin.grant_uri));
  if (!grant_url.is_valid() || !grant_url.SchemeIsCryptographic() ||
      !anchor_origin.IsSameOriginWith(grant_url)) {
    holder().client().grant_abort(begin.grant_id);
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }

  active_grant_ids_.insert(begin.grant_id);
  Fetch(grant_url, "POST", /*authorization=*/{},
        std::string(begin.content_type), BytesToString(begin.request_body),
        /*send_credentials=*/true,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnGrantExchange,
                       weak_factory_.GetWeakPtr(), grant_url, begin.grant_id,
                       std::move(callback)));
}

void ModeratedEndorsementServiceImpl::OnGrantExchange(
    const GURL& grant_url,
    uint64_t grant_id,
    CollectCallback callback,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers || !body) {
    AbortGrant(grant_id);
    std::move(callback).Run(EndorsementStatus::kNetworkError);
    return;
  }
  if (headers->response_code() != 200) {
    AbortGrant(grant_id);
    std::move(callback).Run(headers->response_code() >= 500
                                ? EndorsementStatus::kNetworkError
                                : EndorsementStatus::kRejected);
    return;
  }

  std::optional<std::string> response_ct =
      headers->GetNormalizedHeader(kContentTypeHeader);
  if (!response_ct || !base::IsStringUTF8(*response_ct)) {
    AbortGrant(grant_id);
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }

  auto step = holder().client().grant_step(
      grant_id, rust::Str(*response_ct), StringToSlice(*body));
  if (!step.ok) {
    active_grant_ids_.erase(grant_id);
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }
  if (step.done) {
    active_grant_ids_.erase(grant_id);
    holder().SchedulePersist();
    std::move(callback).Run(EndorsementStatus::kSuccess);
    return;
  }

  Fetch(grant_url, "POST", /*authorization=*/{},
        std::string(step.content_type), BytesToString(step.request_body),
        /*send_credentials=*/true,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnGrantExchange,
                       weak_factory_.GetWeakPtr(), grant_url, grant_id,
                       std::move(callback)));
}

void ModeratedEndorsementServiceImpl::AbortGrant(uint64_t grant_id) {
  active_grant_ids_.erase(grant_id);
  holder().client().grant_abort(grant_id);
}

// --- challenge() ------------------------------------------------------------

void ModeratedEndorsementServiceImpl::Challenge(const GURL& resource_url,
                                                ChallengeCallback callback) {
  if (!resource_url.is_valid() || !resource_url.SchemeIsCryptographic()) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }
  holder().PostWhenLoaded(base::BindOnce(
      &ModeratedEndorsementServiceImpl::AcquireFlightAndStartChallenge,
      weak_factory_.GetWeakPtr(), resource_url, std::move(callback),
      /*attempt=*/0));
}

void ModeratedEndorsementServiceImpl::AcquireFlightAndStartChallenge(
    const GURL& resource_url,
    ChallengeCallback callback,
    int attempt) {
  std::string moderator_origin = url::Origin::Create(resource_url).Serialize();
  std::optional<ScopedFlight> flight =
      holder().TryAcquireModeratorFlight(moderator_origin);
  if (!flight) {
    holder().EnqueueModeratorWaiter(
        moderator_origin,
        base::BindOnce(
            &ModeratedEndorsementServiceImpl::AcquireFlightAndStartChallenge,
            weak_factory_.GetWeakPtr(), resource_url, std::move(callback),
            attempt));
    return;
  }
  SettleOrProbeChallenge(resource_url, std::move(*flight), std::move(callback),
                         attempt);
}

void ModeratedEndorsementServiceImpl::SettleOrProbeChallenge(
    const GURL& resource_url,
    ScopedFlight flight,
    ChallengeCallback callback,
    int attempt) {
  if (attempt >= kMaxChallengeAttempts) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  // Before initiating a new presentation at this Moderator, settle any
  // interrupted (`recovery-0001`) or deferred (`signoff-0001` /
  // `recovery-0001`) spend (`draft-jms-mole-http-transport-01` §§5.3-5.5).
  url::Origin moderator_origin = url::Origin::Create(resource_url);
  std::string serialized_origin = moderator_origin.Serialize();
  auto settlement = holder().client().next_settlement(
      rust::Str(serialized_origin), NowUnixSecs());
  if (settlement.has_pending) {
    GURL issuance_url(std::string(settlement.issuance_uri));
    if (!issuance_url.is_valid() || !issuance_url.SchemeIsCryptographic() ||
        !moderator_origin.IsSameOriginWith(issuance_url)) {
      std::move(callback).Run(EndorsementStatus::kRejected, std::string());
      return;
    }
    Fetch(issuance_url, "POST", std::string(settlement.authorization_header),
          /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
          /*send_credentials=*/false,
          base::BindOnce(&ModeratedEndorsementServiceImpl::OnSettlementExchange,
                         weak_factory_.GetWeakPtr(), resource_url,
                         std::move(flight), settlement.pending_id,
                         std::move(callback), attempt));
    return;
  }

  Fetch(resource_url, "GET", /*authorization=*/{},
        /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
        /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnChallengeProbe,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(flight), std::move(callback), attempt));
}

void ModeratedEndorsementServiceImpl::OnSettlementExchange(
    const GURL& resource_url,
    ScopedFlight flight,
    uint64_t pending_id,
    ChallengeCallback callback,
    int attempt,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers) {
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }

  std::string credential_header;
  if (std::optional<std::string> raw =
          headers->GetNormalizedHeader(kMoleCredentialHeader);
      raw && base::IsStringUTF8(*raw)) {
    credential_header = std::move(*raw);
  }

  auto outcome = holder().client().settle_finish(
      pending_id, static_cast<uint16_t>(headers->response_code()),
      rust::Str(credential_header));
  if (!outcome.ok) {
    std::move(callback).Run(headers->response_code() >= 500
                                ? EndorsementStatus::kNetworkError
                                : EndorsementStatus::kRejected,
                            std::string());
    return;
  }
  holder().SchedulePersist();
  SettleOrProbeChallenge(resource_url, std::move(flight), std::move(callback),
                         attempt);
}

void ModeratedEndorsementServiceImpl::OnChallengeProbe(
    const GURL& resource_url,
    ScopedFlight flight,
    ChallengeCallback callback,
    int attempt,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers) {
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }
  if (headers->response_code() == 200) {
    std::move(callback).Run(EndorsementStatus::kSuccess,
                            body ? *body : std::string());
    return;
  }
  if (headers->response_code() != 401) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  std::vector<std::string> www_authenticate = WwwAuthenticateValues(*headers);
  if (!AllUtf8(www_authenticate)) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  url::Origin moderator_origin = url::Origin::Create(resource_url);
  auto commitment = MoleCommitmentRegistry::GetInstance()
                        .GetModeratorCommitment(moderator_origin);
  std::string serialized_origin = moderator_origin.Serialize();
  auto eval = holder().client().challenge_eval(
      rust::Str(serialized_origin), ToRustStrings(www_authenticate),
      commitment);
  if (!eval.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  if (eval.needs_endorsement) {
    // Fetch `/.well-known/mole-moderator` before rejecting so a bare `401`
    // without a real Moderator directory cannot distinguish endorsement
    // possession via timing or status.
    GURL directory_url =
        resource_url.GetWithEmptyPath().Resolve(kModeratorDirectoryPath);
    Fetch(directory_url, "GET", /*authorization=*/{},
          /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
          /*send_credentials=*/false,
          base::BindOnce(
              &ModeratedEndorsementServiceImpl::OnNoEndorsementDirectory,
              weak_factory_.GetWeakPtr(), std::move(flight),
              std::move(callback)));
    return;
  }

  if (!eval.needs_redeem) {
    Present(resource_url, std::move(flight), std::move(callback), attempt,
            www_authenticate);
    return;
  }

  GURL directory_url =
      resource_url.GetWithEmptyPath().Resolve(kModeratorDirectoryPath);
  Fetch(directory_url, "GET", /*authorization=*/{},
        /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
        /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnModeratorDirectory,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(flight), std::move(callback), attempt,
                       std::move(www_authenticate)));
}

void ModeratedEndorsementServiceImpl::OnNoEndorsementDirectory(
    ScopedFlight flight,
    ChallengeCallback callback,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!body || !headers || headers->response_code() != 200) {
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }
  std::move(callback).Run(EndorsementStatus::kRejected, std::string());
}

void ModeratedEndorsementServiceImpl::OnModeratorDirectory(
    const GURL& resource_url,
    ScopedFlight flight,
    ChallengeCallback callback,
    int attempt,
    std::vector<std::string> www_authenticate,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers || !body) {
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }
  if (headers->response_code() != 200) {
    std::move(callback).Run(headers->response_code() >= 500
                                ? EndorsementStatus::kNetworkError
                                : EndorsementStatus::kRejected,
                            std::string());
    return;
  }
  if (!base::IsStringUTF8(*body)) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  url::Origin moderator_origin = url::Origin::Create(resource_url);
  auto commitment = MoleCommitmentRegistry::GetInstance()
                        .GetModeratorCommitment(moderator_origin);
  std::string serialized_origin = moderator_origin.Serialize();
  auto redeem = holder().client().redeem_begin(
      rust::Str(serialized_origin), rust::Str(*body),
      ToRustStrings(www_authenticate), commitment);
  if (!redeem.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  GURL issuance_url(std::string(redeem.issuance_uri));
  if (!issuance_url.is_valid() || !issuance_url.SchemeIsCryptographic() ||
      !moderator_origin.IsSameOriginWith(issuance_url)) {
    holder().client().redeem_abort(redeem.redeem_id);
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  // `draft-jms-mole-http-transport-01` §3: Redeem & Issue is an uncredentialed
  // `POST <issuance-uri>` with `Authorization: Mole redeem-T="...",
  // credential-request-0001="..."` returning `200 OK` + `Mole-Credential:
  // response-0001="..."`.
  active_redeem_ids_.insert(redeem.redeem_id);
  Fetch(issuance_url, "POST", std::string(redeem.authorization_header),
        /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
        /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnRedeemExchange,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(flight), redeem.redeem_id, std::move(callback),
                       attempt, std::move(www_authenticate)));
}

void ModeratedEndorsementServiceImpl::OnRedeemExchange(
    const GURL& resource_url,
    ScopedFlight flight,
    uint64_t redeem_id,
    ChallengeCallback callback,
    int attempt,
    std::vector<std::string> www_authenticate,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers) {
    AbortRedeem(redeem_id);
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }
  if (headers->response_code() != 200) {
    AbortRedeem(redeem_id);
    std::move(callback).Run(headers->response_code() >= 500
                                ? EndorsementStatus::kNetworkError
                                : EndorsementStatus::kRejected,
                            std::string());
    return;
  }

  std::optional<std::string> credential_header =
      headers->GetNormalizedHeader(kMoleCredentialHeader);
  if (!credential_header || !base::IsStringUTF8(*credential_header)) {
    AbortRedeem(redeem_id);
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  active_redeem_ids_.erase(redeem_id);
  auto finish = holder().client().redeem_finish(redeem_id,
                                                rust::Str(*credential_header));
  if (!finish.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  holder().SchedulePersist();
  Present(resource_url, std::move(flight), std::move(callback), attempt,
          www_authenticate);
}

void ModeratedEndorsementServiceImpl::AbortRedeem(uint64_t redeem_id) {
  active_redeem_ids_.erase(redeem_id);
  holder().client().redeem_abort(redeem_id);
}

void ModeratedEndorsementServiceImpl::Present(
    const GURL& resource_url,
    ScopedFlight flight,
    ChallengeCallback callback,
    int attempt,
    const std::vector<std::string>& www_authenticate) {
  url::Origin moderator_origin = url::Origin::Create(resource_url);
  auto commitment = MoleCommitmentRegistry::GetInstance()
                        .GetModeratorCommitment(moderator_origin);
  std::string serialized_origin = moderator_origin.Serialize();
  std::string resource_spec = resource_url.spec();
  auto begin = holder().client().present_begin(
      rust::Str(serialized_origin), rust::Str(resource_spec),
      ToRustStrings(www_authenticate), commitment, NowUnixSecs());
  if (!begin.ok) {
    SettleOrProbeChallenge(resource_url, std::move(flight), std::move(callback),
                           attempt + 1);
    return;
  }

  // Write-ahead durability (`draft-jms-mole-protocols-01` §5.2.3): flush the
  // `PendingSpend` (`InFlight`) before transmitting `presentation-0001`.
  std::string auth_header(begin.authorization_header);
  holder().PersistBeforeSend(base::BindOnce(
      &ModeratedEndorsementServiceImpl::SendPresentAfterPersist,
      weak_factory_.GetWeakPtr(), resource_url, std::move(flight),
      std::move(callback), begin.presentation_id, std::move(auth_header)));
}

void ModeratedEndorsementServiceImpl::SendPresentAfterPersist(
    const GURL& resource_url,
    ScopedFlight flight,
    ChallengeCallback callback,
    uint64_t presentation_id,
    std::string authorization_header) {
  Fetch(resource_url, "GET", authorization_header,
        /*upload_content_type=*/{}, /*upload_body=*/std::nullopt,
        /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnPresentExchange,
                       weak_factory_.GetWeakPtr(), std::move(flight),
                       std::move(callback), presentation_id));
}

void ModeratedEndorsementServiceImpl::OnPresentExchange(
    ScopedFlight flight,
    ChallengeCallback callback,
    uint64_t presentation_id,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers) {
    // Transport drop: `PendingSpend` stays on disk for `recovery-0001`.
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }

  // `draft-jms-mole-http-transport-01` §4: process `Mole-Credential` on ANY
  // HTTP status code (including `200`, `409 Conflict` duplicate presentation,
  // or application errors after spend recording). When `Mole-Credential` is
  // absent, retain `PendingSpend` so `recovery-0001` reconciles state on the
  // next request.
  if (std::optional<std::string> credential_header =
          headers->GetNormalizedHeader(kMoleCredentialHeader);
      credential_header && base::IsStringUTF8(*credential_header)) {
    holder().client().present_finish(
        presentation_id, rust::Str(*credential_header), NowUnixSecs());
    holder().SchedulePersist();
  }

  if (headers->response_code() == 200) {
    std::move(callback).Run(EndorsementStatus::kSuccess,
                            body ? *body : std::string());
    return;
  }
  std::move(callback).Run(EndorsementStatus::kRejected, std::string());
}

}  // namespace content
