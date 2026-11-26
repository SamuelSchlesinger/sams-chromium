// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/moderated_endorsements/mole_url_loader_interceptor.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/strings/string_util.h"
#include "net/base/load_flags.h"
#include "net/http/http_util.h"

namespace network {

namespace {

constexpr std::string_view kMoleScheme = "mole";
constexpr std::string_view kWwwAuthenticateHeader = "WWW-Authenticate";

bool StartsWithMoleAuthScheme(std::string_view raw_value) {
  std::string_view trimmed = net::HttpUtil::TrimLWS(raw_value);
  if (trimmed.size() < kMoleScheme.size()) {
    return false;
  }
  if (!base::EqualsCaseInsensitiveASCII(trimmed.substr(0, kMoleScheme.size()),
                                        kMoleScheme)) {
    return false;
  }
  return trimmed.size() == kMoleScheme.size() ||
         net::HttpUtil::IsLWS(trimmed[kMoleScheme.size()]);
}

bool IsHttpTokenChar(char c) {
  const auto u = static_cast<unsigned char>(c);
  if (u >= '0' && u <= '9') {
    return true;
  }
  if ((u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z')) {
    return true;
  }
  switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
      return true;
    default:
      return false;
  }
}

// Splits a single un-coalesced `WWW-Authenticate` header line into individual
// RFC 9110 auth-challenges (`scheme [token68 / auth-params]`) at unquoted
// `, <auth-scheme>` boundaries without splitting comma-separated `auth-params`
// (`token BWS "=" ...`).
std::vector<std::string_view> SplitWwwAuthenticateChallenges(
    std::string_view line) {
  std::vector<std::string_view> challenges;
  size_t challenge_start = 0;
  bool in_quotes = false;
  bool seen_first_token = false;

  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (in_quotes) {
      if (c == '\\' && i + 1 < line.size()) {
        ++i;
      } else if (c == '"') {
        in_quotes = false;
      }
      continue;
    }
    if (c == '"') {
      in_quotes = true;
      continue;
    }
    if (!seen_first_token && IsHttpTokenChar(c)) {
      seen_first_token = true;
    }
    if (c == ',' && seen_first_token) {
      size_t p = i + 1;
      while (p < line.size() && net::HttpUtil::IsLWS(line[p])) {
        ++p;
      }
      size_t tok_start = p;
      while (p < line.size() && IsHttpTokenChar(line[p])) {
        ++p;
      }
      if (p > tok_start) {
        size_t after_tok = p;
        while (after_tok < line.size() &&
               net::HttpUtil::IsLWS(line[after_tok])) {
          ++after_tok;
        }
        // An `auth-param` has `'='` immediately after `token *LWS`; a new
        // `auth-scheme` does NOT!
        if (after_tok == line.size() || line[after_tok] != '=') {
          std::string_view prev = net::HttpUtil::TrimLWS(
              line.substr(challenge_start, i - challenge_start));
          if (!prev.empty()) {
            challenges.push_back(prev);
          }
          challenge_start = tok_start;
          i = tok_start - 1;
        }
      }
    }
  }

  std::string_view tail =
      net::HttpUtil::TrimLWS(line.substr(challenge_start));
  if (!tail.empty()) {
    challenges.push_back(tail);
  }
  return challenges;
}

}  // namespace

bool IsMoleAuthorizationScheme(std::string_view auth_header_value) {
  return StartsWithMoleAuthScheme(auth_header_value);
}

bool ContainsForbiddenMoleHeaderFromRenderer(
    const net::HttpRequestHeaders& headers,
    std::string* offending_header_out) {
  for (const auto& pair : headers.GetHeaderVector()) {
    if (base::StartsWith(pair.key, "sec-mole-",
                         base::CompareCase::INSENSITIVE_ASCII) ||
        base::EqualsCaseInsensitiveASCII(pair.key, kSecWantEndorsementHeader)) {
      if (offending_header_out) {
        *offending_header_out = pair.key;
      }
      return true;
    }
    if (base::EqualsCaseInsensitiveASCII(
            pair.key, net::HttpRequestHeaders::kAuthorization) &&
        IsMoleAuthorizationScheme(pair.value)) {
      if (offending_header_out) {
        *offending_header_out = pair.key;
      }
      return true;
    }
  }
  return false;
}

void StripMoleRequestHeaders(net::HttpRequestHeaders* headers) {
  if (!headers) {
    return;
  }
  std::vector<std::string> to_remove;
  for (const auto& pair : headers->GetHeaderVector()) {
    if (base::StartsWith(pair.key, "sec-mole-",
                         base::CompareCase::INSENSITIVE_ASCII) ||
        base::EqualsCaseInsensitiveASCII(pair.key, kSecWantEndorsementHeader)) {
      to_remove.push_back(pair.key);
    } else if (base::EqualsCaseInsensitiveASCII(
                   pair.key, net::HttpRequestHeaders::kAuthorization) &&
               IsMoleAuthorizationScheme(pair.value)) {
      to_remove.push_back(pair.key);
    }
  }
  for (const std::string& name : to_remove) {
    headers->RemoveHeader(name);
  }
}

std::optional<net::HttpRequestHeaders> SanitizeHeaderClientResult(
    const std::optional<net::HttpRequestHeaders>& header_client_headers,
    const std::optional<net::HttpRequestHeaders>& fallback_headers,
    const net::HttpRequestHeaders& pre_header_client_headers,
    bool disallow_cookies) {
  std::optional<net::HttpRequestHeaders> effective =
      header_client_headers ? header_client_headers : fallback_headers;
  if (!disallow_cookies) {
    return effective;
  }

  if (effective.has_value()) {
    effective->RemoveHeader(net::HttpRequestHeaders::kCookie);
    return effective;
  }
  if (pre_header_client_headers.HasHeader(net::HttpRequestHeaders::kCookie)) {
    net::HttpRequestHeaders stripped = pre_header_client_headers;
    stripped.RemoveHeader(net::HttpRequestHeaders::kCookie);
    return stripped;
  }
  return std::nullopt;
}

ExtractedMoleResponseHeaders::ExtractedMoleResponseHeaders() = default;
ExtractedMoleResponseHeaders::ExtractedMoleResponseHeaders(
    ExtractedMoleResponseHeaders&&) = default;
ExtractedMoleResponseHeaders& ExtractedMoleResponseHeaders::operator=(
    ExtractedMoleResponseHeaders&&) = default;
ExtractedMoleResponseHeaders::~ExtractedMoleResponseHeaders() = default;

ExtractedMoleResponseHeaders ExtractAndStripMoleResponseHeaders(
    net::HttpResponseHeaders& response_headers) {
  ExtractedMoleResponseHeaders out;
  out.mole_challenge =
      response_headers.GetNormalizedHeader(kMoleChallengeHeader);
  out.mole_info = response_headers.GetNormalizedHeader(kMoleInfoHeader);
  out.mole_credential =
      response_headers.GetNormalizedHeader(kMoleCredentialHeader);

  response_headers.RemoveHeader(kMoleChallengeHeader);
  response_headers.RemoveHeader(kMoleInfoHeader);
  response_headers.RemoveHeader(kMoleCredentialHeader);

  // Inspect un-coalesced `WWW-Authenticate` lines (`IsNonCoalescingHeader` is
  // true for `WWW-Authenticate` in `net::HttpUtil`), splitting multi-scheme
  // lines only at RFC 9110 `, <auth-scheme>` boundaries so comma-separated
  // `Mole` parameters (`redeem-0002=..., challenge-0001=...`) are extracted
  // intact without leaving orphan parameter fragments in `response_headers`.
  size_t iter = 0;
  std::vector<std::string> kept_www_auth;
  while (std::optional<std::string_view> line =
             response_headers.EnumerateHeader(&iter, kWwwAuthenticateHeader)) {
    for (std::string_view challenge : SplitWwwAuthenticateChallenges(*line)) {
      if (StartsWithMoleAuthScheme(challenge)) {
        out.www_authenticate_mole.emplace_back(challenge);
      } else {
        kept_www_auth.emplace_back(challenge);
      }
    }
  }
  if (!out.www_authenticate_mole.empty()) {
    response_headers.RemoveHeader(kWwwAuthenticateHeader);
    for (const std::string& kept : kept_www_auth) {
      response_headers.AddHeader(kWwwAuthenticateHeader, kept);
    }
  }

  return out;
}

MoleUrlLoaderInterceptor::ResponseAction::ResponseAction() = default;
MoleUrlLoaderInterceptor::ResponseAction::ResponseAction(ResponseAction&&) =
    default;
MoleUrlLoaderInterceptor::ResponseAction&
MoleUrlLoaderInterceptor::ResponseAction::operator=(ResponseAction&&) = default;
MoleUrlLoaderInterceptor::ResponseAction::~ResponseAction() = default;

// static
std::unique_ptr<MoleUrlLoaderInterceptor> MoleUrlLoaderInterceptor::MaybeCreate(
    const OptionalMoleParams& mole_params,
    mojom::MoleAuthObserver* observer) {
  if (!mole_params.has_value() || !observer) {
    return nullptr;
  }
  return std::make_unique<MoleUrlLoaderInterceptor>(
      mole_params.value().Clone(), observer);
}

MoleUrlLoaderInterceptor::MoleUrlLoaderInterceptor(
    mojom::MoleRequestParamsPtr mole_params,
    mojom::MoleAuthObserver* observer)
    : mole_params_(std::move(mole_params)), observer_(observer) {}

MoleUrlLoaderInterceptor::~MoleUrlLoaderInterceptor() {
  OnLoaderCompleted(net::ERR_ABORTED);
}

int MoleUrlLoaderInterceptor::GetAdditionalLoadFlags() const {
  return net::LOAD_BYPASS_CACHE | net::LOAD_DISABLE_CACHE;
}

void MoleUrlLoaderInterceptor::BeginOutboundRequest(
    const GURL& request_url,
    const std::string& method,
    const url::Origin& top_frame_origin,
    base::OnceCallback<void(net::HttpRequestHeaders)> callback) {
  if (!observer_) {
    std::move(callback).Run(net::HttpRequestHeaders());
    return;
  }
  observer_->OnMoleOutboundRequest(
      request_url, method, top_frame_origin, mole_params_->Clone(),
      base::BindOnce(&MoleUrlLoaderInterceptor::OnOutboundReply,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void MoleUrlLoaderInterceptor::OnOutboundReply(
    base::OnceCallback<void(net::HttpRequestHeaders)> callback,
    const net::HttpRequestHeaders& headers_to_attach,
    mojo::PendingRemote<mojom::MoleResponseFinalizer> finalizer) {
  finalizer_.reset();
  if (finalizer.is_valid()) {
    finalizer_.Bind(std::move(finalizer));
  }
  std::move(callback).Run(headers_to_attach);
}

void MoleUrlLoaderInterceptor::OnRedirect(
    int http_status,
    ExtractedMoleResponseHeaders extracted) {
  if (finalizer_.is_bound()) {
    if (extracted.mole_info.has_value() ||
        extracted.mole_credential.has_value()) {
      // Post/Redirect/Get (`302`/`303 See Other`) responses carrying `Mole-Info`
      // or `Mole-Credential` must settle the active presentation before
      // resetting `finalizer_` for the redirected hop!
      auto active_finalizer =
          std::make_unique<mojo::Remote<mojom::MoleResponseFinalizer>>(
              std::move(finalizer_));
      mojom::MoleResponseFinalizer* raw_finalizer = active_finalizer->get();
      raw_finalizer->OnOriginResponse(
          http_status, extracted.mole_info, extracted.mole_credential,
          wire_bytes_sent_,
          base::BindOnce(
              [](std::unique_ptr<mojo::Remote<mojom::MoleResponseFinalizer>>) {
              },
              std::move(active_finalizer)));
    } else {
      finalizer_->OnAbortedOrCompleted(net::ERR_ABORTED, wire_bytes_sent_);
      finalizer_.reset();
    }
  }
  wire_bytes_sent_ = false;
}

void MoleUrlLoaderInterceptor::ProcessOriginResponse(
    const GURL& request_url,
    const std::string& method,
    const url::Origin& top_frame_origin,
    int http_status,
    ExtractedMoleResponseHeaders extracted,
    bool allow_challenge_retry,
    base::OnceCallback<void(ResponseAction)> callback) {
  if (finalizer_.is_bound()) {
    // Move `finalizer_` into a local Remote bound into the continuation so it
    // stays alive until `OnOriginResponse` completes and cannot also fire in
    // `OnLoaderCompleted`.
    auto active_finalizer =
        std::make_unique<mojo::Remote<mojom::MoleResponseFinalizer>>(
            std::move(finalizer_));
    mojom::MoleResponseFinalizer* raw_finalizer = active_finalizer->get();
    const std::optional<std::string> mole_info = extracted.mole_info;
    const std::optional<std::string> mole_cred = extracted.mole_credential;
    raw_finalizer->OnOriginResponse(
        http_status, mole_info, mole_cred, wire_bytes_sent_,
        base::BindOnce(
            [](std::unique_ptr<mojo::Remote<mojom::MoleResponseFinalizer>>
                   keep_alive,
               base::WeakPtr<MoleUrlLoaderInterceptor> self, GURL url,
               std::string m, url::Origin top_origin, int status,
               ExtractedMoleResponseHeaders ext, bool allow_retry,
               base::OnceCallback<void(ResponseAction)> cb) {
              keep_alive.reset();
              if (!self) {
                return;
              }
              self->ContinueProcessOriginResponseAfterFinalizer(
                  url, m, top_origin, status, std::move(ext), allow_retry,
                  std::move(cb));
            },
            std::move(active_finalizer), weak_ptr_factory_.GetWeakPtr(),
            request_url, method, top_frame_origin, http_status,
            std::move(extracted), allow_challenge_retry, std::move(callback)));
    return;
  }

  ContinueProcessOriginResponseAfterFinalizer(
      request_url, method, top_frame_origin, http_status, std::move(extracted),
      allow_challenge_retry, std::move(callback));
}

void MoleUrlLoaderInterceptor::ContinueProcessOriginResponseAfterFinalizer(
    const GURL& request_url,
    const std::string& method,
    const url::Origin& top_frame_origin,
    int http_status,
    ExtractedMoleResponseHeaders extracted,
    bool allow_challenge_retry,
    base::OnceCallback<void(ResponseAction)> callback) {
  const bool is_challenge_status =
      http_status == 401 || http_status == 403 || http_status == 429;
  const bool has_challenge_header = extracted.mole_challenge.has_value() ||
                                    !extracted.www_authenticate_mole.empty();

  if (!observer_ || !allow_challenge_retry || has_retried_challenge_ ||
      !is_challenge_status || !has_challenge_header) {
    std::move(callback).Run(ResponseAction());
    return;
  }

  has_retried_challenge_ = true;
  wire_bytes_sent_ = false;
  observer_->OnMoleChallengeReceived(
      request_url, method, top_frame_origin, mole_params_->Clone(), http_status,
      extracted.mole_challenge, std::move(extracted.www_authenticate_mole),
      base::BindOnce(&MoleUrlLoaderInterceptor::OnChallengeReply,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void MoleUrlLoaderInterceptor::OnChallengeReply(
    base::OnceCallback<void(ResponseAction)> callback,
    bool should_retry,
    const net::HttpRequestHeaders& retry_headers,
    mojo::PendingRemote<mojom::MoleResponseFinalizer> finalizer) {
  finalizer_.reset();
  if (should_retry && finalizer.is_valid()) {
    finalizer_.Bind(std::move(finalizer));
  }
  ResponseAction action;
  action.should_retry = should_retry;
  action.retry_headers = retry_headers;
  std::move(callback).Run(std::move(action));
}

void MoleUrlLoaderInterceptor::OnLoaderCompleted(int net_error) {
  if (finalizer_.is_bound()) {
    finalizer_->OnAbortedOrCompleted(net_error, wire_bytes_sent_);
    finalizer_.reset();
  }
}

}  // namespace network
