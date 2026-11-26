// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_

#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/containers/flat_set.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "content/browser/moderated_endorsements/mole_client_holder.h"
#include "content/public/browser/document_service.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "third_party/blink/public/mojom/moderated_endorsements/moderated_endorsements.mojom.h"

class GURL;

namespace net {
class HttpResponseHeaders;
}  // namespace net

namespace network {
class SimpleURLLoader;
class SharedURLLoaderFactory;
}  // namespace network

namespace content {

// Browser-process implementation of `navigator.endorsement` (`draft-jms-mole-protocols-01`
// and `draft-jms-mole-http-transport-01`).
//
// Owns the HTTPS exchanges with Anchors (`/.well-known/mole-anchor`,
// `POST <grant-uri>`) and Moderators (`/.well-known/mole-moderator`,
// `POST <issuance-uri>` for Redeem/Issue, Recovery, and Signoff, plus
// `GET <resource_url>` for Presentation & Update). All cryptographic state
// lives in the sans-I/O Rust crate behind `//components/moderated_endorsements`
// and is scoped per `BrowserContext` via `MoleClientHolder` (ephemeral in
// OffTheRecord profiles).
//
// Security & privacy properties:
// - Cookies are sent ONLY to the same-origin Anchor during `collect()`; all
//   Moderator requests (`GET <resource_url>`, `GET /.well-known/mole-moderator`,
//   `POST <issuance-uri>`) run with `CredentialsMode::kOmit`.
// - `challenge()` collapses "no usable endorsement" and protocol rejections to
//   a single opaque `kRejected` outcome and performs a dummy Moderator
//   directory fetch on the `needs_endorsement` branch so bare `401` probes
//   cannot act as cross-site endorsement-possession oracles.
// - Per-Moderator flight serialization (`MoleClientHolder::ScopedModeratorFlight`)
//   sequences `Settle -> Probe -> [Redeem & Issue] -> Present -> Update` per
//   Moderator origin so concurrent requests reuse a single EC-ACT credential
//   chain (`Spend -> Refund`) without head-of-line blocking across distinct
//   Moderators.
// - Write-ahead persistence (`MoleClientHolder::PersistBeforeSend`) flushes
//   `PendingSpend` before transmitting `presentation-0001`, and `Mole-Credential`
//   headers are processed regardless of HTTP status code (`draft-jms-mole-http-transport-01`
//   §4).
class ModeratedEndorsementServiceImpl final
    : public DocumentService<blink::mojom::ModeratedEndorsementService> {
 public:
  static void Create(
      RenderFrameHost*,
      mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService>);

  ModeratedEndorsementServiceImpl(const ModeratedEndorsementServiceImpl&) =
      delete;
  ModeratedEndorsementServiceImpl& operator=(
      const ModeratedEndorsementServiceImpl&) = delete;

  // blink::mojom::ModeratedEndorsementService:
  void Collect(const GURL& endorse_url, CollectCallback) final;
  void Challenge(const GURL& resource_url, ChallengeCallback) final;

 private:
  using UrlLoaderList = std::list<std::unique_ptr<network::SimpleURLLoader>>;
  using ScopedFlight = MoleClientHolder::ScopedModeratorFlight;
  using FetchCallback =
      base::OnceCallback<void(std::optional<std::string>,
                              scoped_refptr<net::HttpResponseHeaders>)>;

  ModeratedEndorsementServiceImpl(
      RenderFrameHost&,
      mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService>);
  ~ModeratedEndorsementServiceImpl() override;

  void Fetch(const GURL& url,
             const std::string& method,
             const std::string& authorization,
             const std::string& upload_content_type,
             std::optional<std::string> upload_body,
             bool send_credentials,
             FetchCallback);
  void OnFetchComplete(UrlLoaderList::iterator,
                       FetchCallback,
                       std::optional<std::string> body);

  // `collect()` steps:
  void CollectImpl(const GURL& endorse_url, CollectCallback);
  void OnAnchorDirectory(const GURL& endorse_url,
                         CollectCallback,
                         std::optional<std::string> body,
                         scoped_refptr<net::HttpResponseHeaders>);
  void OnGrantExchange(const GURL& grant_url,
                       uint64_t grant_id,
                       CollectCallback,
                       std::optional<std::string> body,
                       scoped_refptr<net::HttpResponseHeaders>);
  void AbortGrant(uint64_t grant_id);

  // `challenge()` steps:
  void AcquireFlightAndStartChallenge(const GURL& resource_url,
                                      ChallengeCallback,
                                      int attempt);
  void SettleOrProbeChallenge(const GURL& resource_url,
                              ScopedFlight flight,
                              ChallengeCallback,
                              int attempt);
  void OnSettlementExchange(const GURL& resource_url,
                            ScopedFlight flight,
                            uint64_t pending_id,
                            ChallengeCallback,
                            int attempt,
                            std::optional<std::string> body,
                            scoped_refptr<net::HttpResponseHeaders>);
  void OnChallengeProbe(const GURL& resource_url,
                        ScopedFlight flight,
                        ChallengeCallback,
                        int attempt,
                        std::optional<std::string> body,
                        scoped_refptr<net::HttpResponseHeaders>);
  void OnNoEndorsementDirectory(ScopedFlight flight,
                                ChallengeCallback,
                                std::optional<std::string> body,
                                scoped_refptr<net::HttpResponseHeaders>);
  void OnModeratorDirectory(const GURL& resource_url,
                            ScopedFlight flight,
                            ChallengeCallback,
                            int attempt,
                            std::vector<std::string> www_authenticate,
                            std::optional<std::string> body,
                            scoped_refptr<net::HttpResponseHeaders>);
  void OnRedeemExchange(const GURL& resource_url,
                        ScopedFlight flight,
                        uint64_t redeem_id,
                        ChallengeCallback,
                        int attempt,
                        std::vector<std::string> www_authenticate,
                        std::optional<std::string> body,
                        scoped_refptr<net::HttpResponseHeaders>);
  void AbortRedeem(uint64_t redeem_id);

  void Present(const GURL& resource_url,
               ScopedFlight flight,
               ChallengeCallback,
               int attempt,
               const std::vector<std::string>& www_authenticate);
  void SendPresentAfterPersist(const GURL& resource_url,
                               ScopedFlight flight,
                               ChallengeCallback,
                               uint64_t presentation_id,
                               std::string authorization_header);
  void OnPresentExchange(ScopedFlight flight,
                         ChallengeCallback,
                         uint64_t presentation_id,
                         std::optional<std::string> body,
                         scoped_refptr<net::HttpResponseHeaders>);

  MoleClientHolder& holder();

  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;
  UrlLoaderList loaders_in_progress_;
  base::flat_set<uint64_t> active_grant_ids_;
  base::flat_set<uint64_t> active_redeem_ids_;

  base::WeakPtrFactory<ModeratedEndorsementServiceImpl> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_
