// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
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

class MoleClientHolder;

// The browser-process side of navigator.endorsement: the MoLE user-agent
// Client. Owns the HTTP exchanges with Anchors and Moderators; the
// cryptographic state machine (endorsements, per-policy ACT credential
// pools) lives in the Rust crate behind
// //components/moderated_endorsements and is shared per BrowserContext, so
// an endorsement collected on one site can answer a moderator challenge on
// another.
//
// Cross-site privacy model:
//  - Credentials go to the Anchor (which authenticates the user) but never to
//    the Moderator; challenge() presentations are cookieless and unlinkable.
//  - challenge() never distinguishes "no endorsement" from any other failure
//    (all collapse to an opaque rejection), and its no-endorsement path fetches
//    the Moderator directory first, so possession is observable only to a
//    caller that actually acts as a Moderator, not via a bare 401 probe.
//  - Residual timing channel (documented, not closed here): a challenge that
//    must Redeem & Issue makes more round-trips than one served from a warm
//    pool, and the Moderator's Redeem & Issue is inherently heavier (more
//    server time, a larger batched-credential response) than any
//    client-forgeable decoy. Padding the client's round-trip COUNT would cost
//    ~2x latency on the common warm-pool path and still not equalize the
//    server-side work an end-to-end timer sees, so full uniformity requires a
//    Moderator-side change (constant-time, fixed-size responses, or folding
//    redeem+present into one exchange) rather than a client-only mitigation.
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
  // (body, headers): body is nullopt on transport failure; headers are null
  // when no response arrived at all.
  using FetchCallback =
      base::OnceCallback<void(std::optional<std::string>,
                              scoped_refptr<net::HttpResponseHeaders>)>;

  ModeratedEndorsementServiceImpl(
      RenderFrameHost&,
      mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService>);
  // Releases a held redemption flight so BrowserContext-wide challenge
  // coordination cannot wedge when a document dies mid-redemption.
  ~ModeratedEndorsementServiceImpl() override;

  // Issues one HTTP request. `authorization` (if non-empty) becomes the
  // Authorization header; `post_body` (if non-null) makes it a POST with
  // the MoLE endorsement-request media type.
  void Fetch(const GURL& url,
             const std::string& authorization,
             std::unique_ptr<std::string> post_body,
             bool send_credentials,
             FetchCallback);
  void OnFetchComplete(UrlLoaderList::iterator,
                       FetchCallback,
                       std::optional<std::string> body);

  // collect() steps. CollectImpl runs once the persisted state has loaded.
  void CollectImpl(const GURL& endorse_url, CollectCallback);
  void OnAnchorDirectory(const GURL& endorse_url,
                         CollectCallback,
                         std::optional<std::string> body,
                         scoped_refptr<net::HttpResponseHeaders>);
  void OnGrantExchange(const GURL& endorse_url,
                       CollectCallback,
                       std::optional<std::string> body,
                       scoped_refptr<net::HttpResponseHeaders>);

  // challenge() steps. `attempt` bounds pool-race retries.
  void StartChallenge(const GURL& resource_url, ChallengeCallback, int attempt);
  void OnChallengeProbe(const GURL& resource_url,
                        ChallengeCallback,
                        int attempt,
                        std::optional<std::string> body,
                        scoped_refptr<net::HttpResponseHeaders>);
  void OnModeratorDirectory(const GURL& resource_url,
                            ChallengeCallback,
                            int attempt,
                            std::vector<std::string> www_authenticate,
                            std::optional<std::string> body,
                            scoped_refptr<net::HttpResponseHeaders>);
  // The "no usable endorsement" branch. It fetches the Moderator directory
  // before returning the opaque rejection, so that reaching a
  // possession-revealing outcome requires the caller to serve a genuine
  // Moderator directory (i.e. act as a Moderator) — never a bare 401 probe.
  // This equalizes the first round-trip with the redeem path and keeps
  // endorsement possession observable only through real moderation.
  void OnNoEndorsementDirectory(ChallengeCallback,
                                std::optional<std::string> body,
                                scoped_refptr<net::HttpResponseHeaders>);
  void OnRedeemExchange(const GURL& resource_url,
                        ChallengeCallback,
                        int attempt,
                        std::vector<std::string> www_authenticate,
                        std::optional<std::string> body,
                        scoped_refptr<net::HttpResponseHeaders>);
  void Present(const GURL& resource_url,
               ChallengeCallback,
               int attempt,
               const std::vector<std::string>& www_authenticate);
  void OnPresentExchange(ChallengeCallback,
                         uint64_t presentation_id,
                         std::optional<std::string> body,
                         scoped_refptr<net::HttpResponseHeaders>);

  // Ends a redemption (success or failure): wakes challenges that queued
  // behind it.
  void FinishRedeemFlight();

  MoleClientHolder& holder();

  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;
  UrlLoaderList loaders_in_progress_;

  // True while this document's challenge flow holds the BrowserContext-wide
  // Redeem & Issue slot.
  bool owns_redeem_flight_ = false;

  base::WeakPtrFactory<ModeratedEndorsementServiceImpl> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_
