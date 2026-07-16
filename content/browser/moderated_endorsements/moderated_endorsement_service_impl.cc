// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/moderated_endorsement_service_impl.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "components/moderated_endorsements/mole_ffi.rs.h"
#include "content/browser/moderated_endorsements/mole_client_holder.h"
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

// Directory well-known paths (mole-core config formats).
constexpr char kAnchorDirectoryPath[] = "/.well-known/mole-anchor";
constexpr char kModeratorDirectoryPath[] = "/.well-known/mole-moderator";

constexpr char kEndorsementRequestMediaType[] =
    "application/mole-endorsement-request";
constexpr char kMoleCredentialHeader[] = "Mole-Credential";

// Grant/redeem/present exchanges carry kilobyte-scale material; 1MB is a
// generous protocol ceiling, not a tuned limit.
constexpr size_t kMaxBodySize = 1024 * 1024;

// A challenge that loses a pool race retries from the probe; two rounds of
// redemption is already a protocol failure, not contention.
constexpr int kMaxChallengeAttempts = 3;

constexpr net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("moderated_endorsements_fetch", R"(
    semantics {
      sender: "Moderated Endorsements"
      description:
        "Exchanges for the experimental MoLE (Moderation of unLinkable "
        "Endorsements) demonstration: collecting an endorsement from a "
        "site (anchor), and redeeming/presenting anonymous credentials "
        "against an anti-abuse service (moderator) when the page calls "
        "navigator.endorsement APIs."
      trigger: "A page calls navigator.endorsement.collect()/challenge()."
      data:
        "MoLE protocol messages: blinded cryptographic material and "
        "zero-knowledge proofs. No identifiers or cookies."
      destination: OTHER
    }
    policy {
      cookies_allowed: NO
      setting: "Gated behind the experimental MoleEndorsements feature."
      policy_exception_justification: "Experimental demonstration API."
    })");

std::string BytesToString(const rust::Vec<uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

rust::Slice<const uint8_t> StringToSlice(const std::string& s) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                    s.size());
}

// All `WWW-Authenticate` values of a response, one string per header line.
// (They must stay separate: each line is one Mole challenge.)
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

// rust::Str / rust::String constructors reject (and, without exceptions,
// abort on) invalid UTF-8, and these values arrive from the network — so
// everything is validated before it crosses the FFI. Mole header values and
// directories are ASCII by construction, so rejection is protocol-conformant.
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

// The MoLE client state (endorsement store, credential pools), its persistence,
// and the one-at-a-time Redeem & Issue coordination live in MoleClientHolder
// (mole_client_holder.h), a BrowserContext-scoped object: endorsements
// collected on one site answer challenges on another.

// static
void ModeratedEndorsementServiceImpl::Create(
    RenderFrameHost* render_frame_host,
    mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver) {
  CHECK(render_frame_host);
  // Self-owned: DocumentService tears down on document destruction or pipe
  // disconnect.
  new ModeratedEndorsementServiceImpl(*render_frame_host, std::move(receiver));
}

ModeratedEndorsementServiceImpl::ModeratedEndorsementServiceImpl(
    RenderFrameHost& render_frame_host,
    mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver)
    : DocumentService(render_frame_host, std::move(receiver)) {}

ModeratedEndorsementServiceImpl::~ModeratedEndorsementServiceImpl() {
  // Dying mid-redemption must not wedge the BrowserContext-wide slot: the
  // in-flight loaders die with us, so their continuations will never run.
  if (owns_redeem_flight_) {
    FinishRedeemFlight();
  }
}

MoleClientHolder& ModeratedEndorsementServiceImpl::holder() {
  return MoleClientHolder::GetOrCreate(
      render_frame_host().GetBrowserContext());
}

void ModeratedEndorsementServiceImpl::Fetch(
    const GURL& url,
    const std::string& authorization,
    std::unique_ptr<std::string> post_body,
    bool send_credentials,
    FetchCallback callback) {
  if (!url_loader_factory_) {
    url_loader_factory_ = render_frame_host()
                              .GetStoragePartition()
                              ->GetURLLoaderFactoryForBrowserProcess();
  }

  auto resource_request = std::make_unique<network::ResourceRequest>();
  resource_request->url = url;
  resource_request->method = post_body ? "POST" : "GET";
  // Credentials go to the Anchor (which authenticates the user to decide
  // whether to endorse) but NEVER to the Moderator: a cookie there would
  // relink the unlinkable presentation, defeating the whole design.
  resource_request->credentials_mode =
      send_credentials ? network::mojom::CredentialsMode::kInclude
                       : network::mojom::CredentialsMode::kOmit;
  if (send_credentials) {
    // Tag the request same-site with the document so the Anchor's
    // SameSite=Lax session cookie is included. collect() is validated
    // same-origin with the document in the renderer, so the Anchor's site
    // is the document's site.
    const url::Origin& document_origin = origin();
    resource_request->request_initiator = document_origin;
    resource_request->site_for_cookies =
        net::SiteForCookies::FromOrigin(document_origin);
  }
  if (!authorization.empty()) {
    resource_request->headers.SetHeader(
        net::HttpRequestHeaders::kAuthorization, authorization);
  }

  auto loader = network::SimpleURLLoader::Create(std::move(resource_request),
                                                 kTrafficAnnotation);
  if (post_body) {
    loader->AttachStringForUpload(*post_body, kEndorsementRequestMediaType);
  }
  // MoLE answers carry protocol material on 401s; error bodies and headers
  // are the point.
  loader->SetAllowHttpErrorResults(true);
  loader->SetTimeoutDuration(base::Seconds(30));

  network::SimpleURLLoader* loader_ptr = loader.get();
  auto it =
      loaders_in_progress_.insert(loaders_in_progress_.begin(), std::move(loader));
  // Unretained is safe: the loader is owned by `this` and never outlives it.
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
  if (!endorse_url.is_valid() || !endorse_url.SchemeIsHTTPOrHTTPS() ||
      !origin().IsSameOriginWith(endorse_url)) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }
  // Defer until the persisted endorsement store has loaded, so a grant never
  // races the async restore.
  holder().PostWhenLoaded(
      base::BindOnce(&ModeratedEndorsementServiceImpl::CollectImpl,
                     weak_factory_.GetWeakPtr(), endorse_url,
                     std::move(callback)));
}

void ModeratedEndorsementServiceImpl::CollectImpl(const GURL& endorse_url,
                                                  CollectCallback callback) {
  GURL directory_url = endorse_url.GetWithEmptyPath().Resolve(
      kAnchorDirectoryPath);
  Fetch(directory_url, /*authorization=*/{}, /*post_body=*/nullptr,
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
  if (!body || !headers || headers->response_code() != 200) {
    std::move(callback).Run(EndorsementStatus::kNetworkError);
    return;
  }
  if (!base::IsStringUTF8(*body)) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }

  auto begin = holder().client().grant_begin(rust::Str(*body));
  if (!begin.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }

  GURL grant_url = endorse_url.GetWithEmptyPath().Resolve(
      std::string(begin.endorse_path));
  Fetch(grant_url, /*authorization=*/{},
        std::make_unique<std::string>(BytesToString(begin.request_body)),
        /*send_credentials=*/true,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnGrantExchange,
                       weak_factory_.GetWeakPtr(), grant_url,
                       std::move(callback)));
}

void ModeratedEndorsementServiceImpl::OnGrantExchange(
    const GURL& grant_url,
    CollectCallback callback,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!body || !headers || headers->response_code() != 200) {
    std::move(callback).Run(EndorsementStatus::kNetworkError);
    return;
  }

  auto step = holder().client().grant_step(StringToSlice(*body));
  if (!step.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected);
    return;
  }
  if (step.done) {
    // A new endorsement was stored; persist the durable state.
    holder().SchedulePersist();
    std::move(callback).Run(EndorsementStatus::kSuccess);
    return;
  }
  Fetch(grant_url, /*authorization=*/{},
        std::make_unique<std::string>(BytesToString(step.request_body)),
        /*send_credentials=*/true,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnGrantExchange,
                       weak_factory_.GetWeakPtr(), grant_url,
                       std::move(callback)));
}

// --- challenge() ------------------------------------------------------------

void ModeratedEndorsementServiceImpl::Challenge(const GURL& resource_url,
                                                ChallengeCallback callback) {
  if (!resource_url.is_valid() || !resource_url.SchemeIsHTTPOrHTTPS()) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }
  // Defer until the persisted pool/endorsement state has loaded.
  holder().PostWhenLoaded(
      base::BindOnce(&ModeratedEndorsementServiceImpl::StartChallenge,
                     weak_factory_.GetWeakPtr(), resource_url,
                     std::move(callback), /*attempt=*/0));
}

void ModeratedEndorsementServiceImpl::StartChallenge(
    const GURL& resource_url,
    ChallengeCallback callback,
    int attempt) {
  if (attempt >= kMaxChallengeAttempts) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }
  Fetch(resource_url, /*authorization=*/{}, /*post_body=*/nullptr,
        /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnChallengeProbe,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(callback), attempt));
}

void ModeratedEndorsementServiceImpl::OnChallengeProbe(
    const GURL& resource_url,
    ChallengeCallback callback,
    int attempt,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers) {
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }
  if (headers->response_code() == 200) {
    // Not (or no longer) protected: the resource is simply served.
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
  auto eval = holder().client().challenge_eval(ToRustStrings(www_authenticate));
  if (!eval.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }
  if (eval.needs_endorsement) {
    // The user holds no endorsement for this challenge's accepted anchor set.
    // This is decided from local, cross-site endorsement state with no
    // redemption performed, so it MUST NOT be distinguishable to the page: a
    // distinct outcome here would be a cross-site possession oracle (the caller
    // can name arbitrary anchor keys in a crafted 401). We already collapse the
    // *status* to the opaque rejection; to also deny a timing oracle, fetch the
    // Moderator directory first — the same first round-trip the redeem path
    // makes — so that a bare 401 (no directory) is indistinguishable from a
    // transport failure, and possession is only ever observable to a caller
    // that serves a genuine Moderator directory (i.e. acts as a Moderator).
    // No redeem flight is taken: there is nothing to redeem.
    GURL directory_url =
        resource_url.GetWithEmptyPath().Resolve(kModeratorDirectoryPath);
    Fetch(directory_url, /*authorization=*/{}, /*post_body=*/nullptr,
          /*send_credentials=*/false,
          base::BindOnce(
              &ModeratedEndorsementServiceImpl::OnNoEndorsementDirectory,
              weak_factory_.GetWeakPtr(), std::move(callback)));
    return;
  }

  if (!eval.needs_redeem) {
    Present(resource_url, std::move(callback), attempt, www_authenticate);
    return;
  }

  // Redeem & Issue fills a whole pool at once, so concurrent challenges
  // queue behind the one redemption in flight and retry once it lands.
  MoleClientHolder& client_holder = holder();
  if (client_holder.redeem_in_flight) {
    client_holder.pool_waiters.push_back(
        base::BindOnce(&ModeratedEndorsementServiceImpl::StartChallenge,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(callback), attempt + 1));
    return;
  }
  client_holder.redeem_in_flight = true;
  owns_redeem_flight_ = true;

  GURL directory_url = resource_url.GetWithEmptyPath().Resolve(
      kModeratorDirectoryPath);
  Fetch(directory_url, /*authorization=*/{}, /*post_body=*/nullptr,
        /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnModeratorDirectory,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(callback), attempt,
                       std::move(www_authenticate)));
}

void ModeratedEndorsementServiceImpl::OnNoEndorsementDirectory(
    ChallengeCallback callback,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  // A bare 401 with no genuine Moderator directory behind it is
  // indistinguishable from a transport failure; only a caller that serves a
  // real directory (acting as a Moderator) reaches the opaque rejection. Either
  // way the page learns nothing that distinguishes endorsement possession from
  // a network error without acting as a Moderator. The directory contents are
  // not inspected: there is no endorsement to redeem regardless.
  if (!body || !headers || headers->response_code() != 200) {
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }
  std::move(callback).Run(EndorsementStatus::kRejected, std::string());
}

void ModeratedEndorsementServiceImpl::OnModeratorDirectory(
    const GURL& resource_url,
    ChallengeCallback callback,
    int attempt,
    std::vector<std::string> www_authenticate,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!body || !headers || headers->response_code() != 200) {
    FinishRedeemFlight();
    std::move(callback).Run(EndorsementStatus::kNetworkError, std::string());
    return;
  }

  if (!base::IsStringUTF8(*body)) {
    FinishRedeemFlight();
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }
  auto redeem = holder().client().redeem_begin(
      rust::Str(*body), ToRustStrings(www_authenticate));
  if (!redeem.ok) {
    // No usable endorsement for this moderator's policy (or a malformed
    // directory). Opaque to the page for the same reason as the probe-time
    // short-circuit above: the outcome must not distinguish endorsement
    // possession.
    FinishRedeemFlight();
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  Fetch(resource_url, std::string(redeem.authorization_header),
        /*post_body=*/nullptr, /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnRedeemExchange,
                       weak_factory_.GetWeakPtr(), resource_url,
                       std::move(callback), attempt,
                       std::move(www_authenticate)));
}

void ModeratedEndorsementServiceImpl::OnRedeemExchange(
    const GURL& resource_url,
    ChallengeCallback callback,
    int attempt,
    std::vector<std::string> www_authenticate,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  // A successful Redeem & Issue still answers 401 (nothing was presented
  // yet); the credentials ride in the Mole-Credential header.
  std::optional<std::string> credential_header;
  if (headers) {
    credential_header = headers->GetNormalizedHeader(kMoleCredentialHeader);
  }
  if (!headers || !credential_header ||
      !base::IsStringUTF8(*credential_header)) {
    FinishRedeemFlight();
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }

  auto finish = holder().client().redeem_finish(rust::Str(*credential_header));
  FinishRedeemFlight();
  if (!finish.ok) {
    std::move(callback).Run(EndorsementStatus::kRejected, std::string());
    return;
  }
  // The endorsement was spent and the credential pool filled; persist.
  holder().SchedulePersist();
  Present(resource_url, std::move(callback), attempt, www_authenticate);
}

void ModeratedEndorsementServiceImpl::FinishRedeemFlight() {
  MoleClientHolder& client_holder = holder();
  owns_redeem_flight_ = false;
  client_holder.redeem_in_flight = false;
  std::vector<base::OnceClosure> waiters =
      std::move(client_holder.pool_waiters);
  client_holder.pool_waiters.clear();
  for (auto& waiter : waiters) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(waiter));
  }
}

void ModeratedEndorsementServiceImpl::Present(
    const GURL& resource_url,
    ChallengeCallback callback,
    int attempt,
    const std::vector<std::string>& www_authenticate) {
  auto begin = holder().client().present_begin(ToRustStrings(www_authenticate));
  if (!begin.ok) {
    // Lost a pool race (or drained a spent credential): retry from the
    // probe, which will steer into Redeem & Issue if the pool is empty.
    StartChallenge(resource_url, std::move(callback), attempt + 1);
    return;
  }

  Fetch(resource_url, std::string(begin.authorization_header),
        /*post_body=*/nullptr, /*send_credentials=*/false,
        base::BindOnce(&ModeratedEndorsementServiceImpl::OnPresentExchange,
                       weak_factory_.GetWeakPtr(), std::move(callback),
                       begin.presentation_id));
}

void ModeratedEndorsementServiceImpl::OnPresentExchange(
    ChallengeCallback callback,
    uint64_t presentation_id,
    std::optional<std::string> body,
    scoped_refptr<net::HttpResponseHeaders> headers) {
  if (!headers || headers->response_code() != 200) {
    // The credential was burned when drawn and stays burned — it may have
    // reached the moderator.
    holder().client().present_abort(presentation_id);
    holder().SchedulePersist();
    std::move(callback).Run(headers ? EndorsementStatus::kRejected
                                    : EndorsementStatus::kNetworkError,
                            std::string());
    return;
  }

  // Finalize the update into the successor credential. Failure here loses
  // the successor but the resource was served; the pool self-heals through
  // redemption.
  std::optional<std::string> credential_header =
      headers->GetNormalizedHeader(kMoleCredentialHeader);
  if (credential_header && !base::IsStringUTF8(*credential_header)) {
    credential_header.reset();
  }
  if (credential_header) {
    holder().client().present_finish(presentation_id,
                                     rust::Str(*credential_header));
  } else {
    holder().client().present_abort(presentation_id);
  }
  // The drawn credential's successor (or its removal) changed the pool; persist.
  holder().SchedulePersist();
  std::move(callback).Run(EndorsementStatus::kSuccess,
                          body ? *body : std::string());
}

}  // namespace content
