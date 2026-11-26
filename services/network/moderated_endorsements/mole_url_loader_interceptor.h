// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_MODERATED_ENDORSEMENTS_MOLE_URL_LOADER_INTERCEPTOR_H_
#define SERVICES_NETWORK_MODERATED_ENDORSEMENTS_MOLE_URL_LOADER_INTERCEPTOR_H_

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/component_export.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "services/network/public/cpp/optional_mole_params.h"
#include "services/network/public/mojom/moderated_endorsements.mojom.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace network {

// Canonical HTTP header names used by Moderated Endorsements (MOLE).
inline constexpr std::string_view kSecMoleAuthorizationHeader =
    "Sec-Mole-Authorization";
inline constexpr std::string_view kSecMoleGreaseHeader = "Sec-Mole-Grease";
inline constexpr std::string_view kSecWantEndorsementHeader =
    "Sec-Want-Endorsement";
inline constexpr std::string_view kMoleChallengeHeader = "Mole-Challenge";
inline constexpr std::string_view kMoleInfoHeader = "Mole-Info";
inline constexpr std::string_view kMoleCredentialHeader = "Mole-Credential";

// Returns true iff `auth_header_value`'s trimmed authentication scheme token is
// ASCII case-insensitively `"mole"`. Never matches `"Bearer"`, `"Basic"`, etc.
COMPONENT_EXPORT(NETWORK_SERVICE)
bool IsMoleAuthorizationScheme(std::string_view auth_header_value);

// Returns true if an untrusted renderer process attempted to inject any
// browser-only MOLE request header (`Sec-Mole-*`, `Sec-Want-Endorsement`, or
// `Authorization: Mole ...`).
COMPONENT_EXPORT(NETWORK_SERVICE)
bool ContainsForbiddenMoleHeaderFromRenderer(
    const net::HttpRequestHeaders& headers,
    std::string* offending_header_out = nullptr);

// Strips single-use MOLE request headers (`Sec-Mole-Authorization`,
// `Sec-Mole-Grease`, `Sec-Want-Endorsement`, and `Authorization` iff its scheme
// is `Mole`) across redirects or `407` proxy restarts while preserving
// non-MOLE `Authorization` headers (e.g. `Authorization: Bearer ...`).
COMPONENT_EXPORT(NETWORK_SERVICE)
void StripMoleRequestHeaders(net::HttpRequestHeaders* headers);

// Enforces `TrustedHeaderClient` invariants in `URLLoader::OnBeforeSendHeadersComplete`:
// 1. Preserves `fallback_headers` when `header_client_` returns `std::nullopt`
//    after `URLLoader` already modified headers (fixing PVT Issue 2).
// 2. Strips any `Cookie` header injected by `header_client_` whenever the
//    request disallows cookies (`CredentialsMode::kOmit` or
//    `kURLLoadOptionBlockAllCookies`) (fixing PVT Issue 1).
COMPONENT_EXPORT(NETWORK_SERVICE)
std::optional<net::HttpRequestHeaders> SanitizeHeaderClientResult(
    const std::optional<net::HttpRequestHeaders>& header_client_headers,
    const std::optional<net::HttpRequestHeaders>& fallback_headers,
    const net::HttpRequestHeaders& pre_header_client_headers,
    bool disallow_cookies);

struct COMPONENT_EXPORT(NETWORK_SERVICE) ExtractedMoleResponseHeaders {
  ExtractedMoleResponseHeaders();
  ExtractedMoleResponseHeaders(ExtractedMoleResponseHeaders&&);
  ExtractedMoleResponseHeaders& operator=(ExtractedMoleResponseHeaders&&);
  ~ExtractedMoleResponseHeaders();

  std::optional<std::string> mole_challenge;
  std::optional<std::string> mole_info;
  std::optional<std::string> mole_credential;
  std::vector<std::string> www_authenticate_mole;
};

// Extracts and strips all MOLE protocol headers (`Mole-Challenge`, `Mole-Info`,
// `Mole-Credential`, and `WWW-Authenticate` values using the `Mole` scheme)
// from `response_headers` before `URLResponseHead` is exposed to Blink or
// Service Workers. Non-`Mole` `WWW-Authenticate` challenges (e.g. `Bearer`) on
// the same response are preserved untouched.
COMPONENT_EXPORT(NETWORK_SERVICE)
ExtractedMoleResponseHeaders ExtractAndStripMoleResponseHeaders(
    net::HttpResponseHeaders& response_headers);

// Downstream-of-Service-Worker interceptor owned by `network::URLLoader` for
// requests carrying `ResourceRequest::mole_params`.
class COMPONENT_EXPORT(NETWORK_SERVICE) MoleUrlLoaderInterceptor {
 public:
  struct ResponseAction {
    ResponseAction();
    ResponseAction(ResponseAction&&);
    ResponseAction& operator=(ResponseAction&&);
    ~ResponseAction();

    bool should_retry = false;
    net::HttpRequestHeaders retry_headers;
  };

  static std::unique_ptr<MoleUrlLoaderInterceptor> MaybeCreate(
      const OptionalMoleParams& mole_params,
      mojom::MoleAuthObserver* observer);

  MoleUrlLoaderInterceptor(mojom::MoleRequestParamsPtr mole_params,
                           mojom::MoleAuthObserver* observer);
  ~MoleUrlLoaderInterceptor();

  MoleUrlLoaderInterceptor(const MoleUrlLoaderInterceptor&) = delete;
  MoleUrlLoaderInterceptor& operator=(const MoleUrlLoaderInterceptor&) = delete;

  int GetAdditionalLoadFlags() const;

  void BeginOutboundRequest(
      const GURL& request_url,
      const std::string& method,
      const url::Origin& top_frame_origin,
      base::OnceCallback<void(net::HttpRequestHeaders)> callback);

  void OnWireBytesSent() { wire_bytes_sent_ = true; }
  bool wire_bytes_sent() const { return wire_bytes_sent_; }

  void OnRedirect(int http_status, ExtractedMoleResponseHeaders extracted);

  void ProcessOriginResponse(
      const GURL& request_url,
      const std::string& method,
      const url::Origin& top_frame_origin,
      int http_status,
      ExtractedMoleResponseHeaders extracted,
      bool allow_challenge_retry,
      base::OnceCallback<void(ResponseAction)> callback);

  void OnLoaderCompleted(int net_error);

 private:
  void OnOutboundReply(
      base::OnceCallback<void(net::HttpRequestHeaders)> callback,
      const net::HttpRequestHeaders& headers_to_attach,
      mojo::PendingRemote<mojom::MoleResponseFinalizer> finalizer);

  void ContinueProcessOriginResponseAfterFinalizer(
      const GURL& request_url,
      const std::string& method,
      const url::Origin& top_frame_origin,
      int http_status,
      ExtractedMoleResponseHeaders extracted,
      bool allow_challenge_retry,
      base::OnceCallback<void(ResponseAction)> callback);

  void OnChallengeReply(
      base::OnceCallback<void(ResponseAction)> callback,
      bool should_retry,
      const net::HttpRequestHeaders& retry_headers,
      mojo::PendingRemote<mojom::MoleResponseFinalizer> finalizer);

  mojom::MoleRequestParamsPtr mole_params_;
  raw_ptr<mojom::MoleAuthObserver> observer_;
  mojo::Remote<mojom::MoleResponseFinalizer> finalizer_;
  bool wire_bytes_sent_ = false;
  bool has_retried_challenge_ = false;

  base::WeakPtrFactory<MoleUrlLoaderInterceptor> weak_ptr_factory_{this};
};

}  // namespace network

#endif  // SERVICES_NETWORK_MODERATED_ENDORSEMENTS_MOLE_URL_LOADER_INTERCEPTOR_H_
