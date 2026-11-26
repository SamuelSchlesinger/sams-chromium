// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/moderated_endorsements/mole_url_loader_interceptor.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_log_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/log/net_log_capture_mode.h"
#include "services/network/public/cpp/header_util.h"
#include "services/network/public/mojom/moderated_endorsements.mojom.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace network {
namespace {

class RecordingFinalizer : public mojom::MoleResponseFinalizer {
 public:
  struct ResponseRecord {
    int32_t http_status = 0;
    std::optional<std::string> mole_info;
    std::optional<std::string> mole_credential;
    bool wire_bytes_sent = false;
  };
  struct AbortRecord {
    int32_t net_error = 0;
    bool wire_bytes_sent = false;
  };

  mojo::PendingRemote<mojom::MoleResponseFinalizer> BindNewPipe() {
    mojo::PendingRemote<mojom::MoleResponseFinalizer> remote;
    receivers_.Add(this, remote.InitWithNewPipeAndPassReceiver());
    return remote;
  }

  void OnOriginResponse(int32_t http_status,
                        const std::optional<std::string>& mole_info_header,
                        const std::optional<std::string>& mole_credential_header,
                        bool wire_bytes_sent,
                        OnOriginResponseCallback callback) override {
    responses_.push_back(ResponseRecord{http_status, mole_info_header,
                                        mole_credential_header,
                                        wire_bytes_sent});
    std::move(callback).Run();
  }

  void OnAbortedOrCompleted(int32_t net_error, bool wire_bytes_sent) override {
    aborts_.push_back(AbortRecord{net_error, wire_bytes_sent});
  }

  const std::vector<ResponseRecord>& responses() const { return responses_; }
  const std::vector<AbortRecord>& aborts() const { return aborts_; }

 private:
  mojo::ReceiverSet<mojom::MoleResponseFinalizer> receivers_;
  std::vector<ResponseRecord> responses_;
  std::vector<AbortRecord> aborts_;
};

class FakeMoleAuthObserver : public mojom::MoleAuthObserver {
 public:
  explicit FakeMoleAuthObserver(RecordingFinalizer* finalizer)
      : finalizer_(finalizer) {}

  void set_outbound_headers(net::HttpRequestHeaders headers) {
    outbound_headers_ = std::move(headers);
  }
  void set_bind_outbound_finalizer(bool bind) {
    bind_outbound_finalizer_ = bind;
  }
  void set_challenge_retry_headers(net::HttpRequestHeaders headers) {
    challenge_retry_headers_ = std::move(headers);
  }
  void set_should_retry_challenge(bool should_retry) {
    should_retry_challenge_ = should_retry;
  }

  int outbound_calls() const { return outbound_calls_; }
  int challenge_calls() const { return challenge_calls_; }
  const std::optional<std::string>& last_mole_challenge() const {
    return last_mole_challenge_;
  }

  void OnMoleOutboundRequest(const GURL& /*request_url*/,
                             const std::string& /*method*/,
                             const url::Origin& /*top_frame_origin*/,
                             mojom::MoleRequestParamsPtr /*params*/,
                             OnMoleOutboundRequestCallback callback) override {
    ++outbound_calls_;
    mojo::PendingRemote<mojom::MoleResponseFinalizer> fin;
    if (bind_outbound_finalizer_ && finalizer_) {
      fin = finalizer_->BindNewPipe();
    }
    std::move(callback).Run(outbound_headers_, std::move(fin));
  }

  void OnMoleChallengeReceived(
      const GURL& /*request_url*/,
      const std::string& /*method*/,
      const url::Origin& /*top_frame_origin*/,
      mojom::MoleRequestParamsPtr /*params*/,
      int32_t /*http_status*/,
      const std::optional<std::string>& mole_challenge_header,
      const std::vector<std::string>& /*www_authenticate_mole_headers*/,
      OnMoleChallengeReceivedCallback callback) override {
    ++challenge_calls_;
    last_mole_challenge_ = mole_challenge_header;
    mojo::PendingRemote<mojom::MoleResponseFinalizer> fin;
    if (should_retry_challenge_ && finalizer_) {
      fin = finalizer_->BindNewPipe();
    }
    std::move(callback).Run(should_retry_challenge_, challenge_retry_headers_,
                            std::move(fin));
  }

  void Clone(mojo::PendingReceiver<mojom::MoleAuthObserver> listener) override {
    receivers_.Add(this, std::move(listener));
  }

 private:
  raw_ptr<RecordingFinalizer> finalizer_;
  mojo::ReceiverSet<mojom::MoleAuthObserver> receivers_;
  net::HttpRequestHeaders outbound_headers_;
  net::HttpRequestHeaders challenge_retry_headers_;
  bool bind_outbound_finalizer_ = false;
  bool should_retry_challenge_ = true;
  int outbound_calls_ = 0;
  int challenge_calls_ = 0;
  std::optional<std::string> last_mole_challenge_;
};

class MoleUrlLoaderInterceptorTest : public testing::Test {
 protected:
  base::test::TaskEnvironment task_environment_;
};

TEST_F(MoleUrlLoaderInterceptorTest,
       TrustedHeaderClientPreservesFallbackAndStripsCookiesWhenDisallowed) {
  net::HttpRequestHeaders pre_headers;
  pre_headers.SetHeader("Sec-Mole-Authorization", "clearance=:AQID:");

  net::HttpRequestHeaders fallback = pre_headers;
  fallback.SetHeader("X-Modified-Before-HeaderClient", "1");

  // PVT Issue 2: when `header_client_` returns `std::nullopt`, `fallback` must
  // not be discarded.
  std::optional<net::HttpRequestHeaders> preserved = SanitizeHeaderClientResult(
      /*header_client_headers=*/std::nullopt, fallback, pre_headers,
      /*disallow_cookies=*/true);
  ASSERT_TRUE(preserved.has_value());
  EXPECT_EQ(preserved->GetHeader("X-Modified-Before-HeaderClient"), "1");
  EXPECT_FALSE(preserved->HasHeader(net::HttpRequestHeaders::kCookie));

  // PVT Issue 1: when `disallow_cookies` is true (`CredentialsMode::kOmit` or
  // `kURLLoadOptionBlockAllCookies`), any `Cookie` header injected by
  // `header_client_` must be stripped before hitting the wire.
  net::HttpRequestHeaders injected = fallback;
  injected.SetHeader(net::HttpRequestHeaders::kCookie, "uid=track-me");
  std::optional<net::HttpRequestHeaders> stripped = SanitizeHeaderClientResult(
      injected, fallback, pre_headers, /*disallow_cookies=*/true);
  ASSERT_TRUE(stripped.has_value());
  EXPECT_FALSE(stripped->HasHeader(net::HttpRequestHeaders::kCookie));
  EXPECT_EQ(stripped->GetHeader("Sec-Mole-Authorization"), "clearance=:AQID:");

  // When cookies ARE allowed (e.g. credentialed first-party Origin fetch),
  // cookies remain intact.
  std::optional<net::HttpRequestHeaders> allowed = SanitizeHeaderClientResult(
      injected, fallback, pre_headers, /*disallow_cookies=*/false);
  ASSERT_TRUE(allowed.has_value());
  EXPECT_EQ(allowed->GetHeader(net::HttpRequestHeaders::kCookie),
            "uid=track-me");
}

TEST_F(MoleUrlLoaderInterceptorTest,
       RendererForbiddenHeaderDetectionBlocksSpoofingPreservesBearer) {
  {
    net::HttpRequestHeaders safe_headers;
    safe_headers.SetHeader(net::HttpRequestHeaders::kAuthorization,
                           "Bearer demo-jwt-token");
    safe_headers.SetHeader("X-Custom", "Mole");
    EXPECT_FALSE(ContainsForbiddenMoleHeader(safe_headers));
    EXPECT_FALSE(ContainsForbiddenMoleHeaderFromRenderer(safe_headers));
  }
  {
    // Prefix collision ("Molehill") must NOT be misclassified as `Mole` scheme.
    net::HttpRequestHeaders non_mole_scheme;
    non_mole_scheme.SetHeader(net::HttpRequestHeaders::kAuthorization,
                              "Molehill token=123");
    EXPECT_FALSE(ContainsForbiddenMoleHeader(non_mole_scheme));
    EXPECT_FALSE(ContainsForbiddenMoleHeaderFromRenderer(non_mole_scheme));
  }
  for (const auto& [name, val] :
       std::vector<std::pair<std::string, std::string>>{
           {"Sec-Mole-Authorization", "clearance=:AQID:"},
           {"sec-mole-grease", "suite=0x1a1a"},
           {"Sec-Want-Endorsement", "?1"},
           {"Authorization", "Mole token=abc"},
           {"authorization", "  mOlE\ttoken=abc"},
       }) {
    net::HttpRequestHeaders spoofed;
    spoofed.SetHeader(name, val);
    std::string offending;
    EXPECT_TRUE(ContainsForbiddenMoleHeader(spoofed, &offending)) << name;
    EXPECT_FALSE(offending.empty());
    EXPECT_TRUE(ContainsForbiddenMoleHeaderFromRenderer(spoofed)) << name;
  }
}

TEST_F(MoleUrlLoaderInterceptorTest,
       StripMoleRequestHeadersForRedirectAnd407RestartPreservesBearer) {
  net::HttpRequestHeaders headers;
  headers.SetHeader("Sec-Mole-Authorization", "clearance=:AQID:");
  headers.SetHeader("Sec-Mole-Grease", "suite=0x2a2a");
  headers.SetHeader("Sec-Want-Endorsement", "?1");
  headers.SetHeader(net::HttpRequestHeaders::kAuthorization,
                    "Bearer session-jwt");
  headers.SetHeader("Content-Type", "application/json");

  StripMoleRequestHeaders(&headers);
  EXPECT_FALSE(headers.HasHeader("Sec-Mole-Authorization"));
  EXPECT_FALSE(headers.HasHeader("Sec-Mole-Grease"));
  EXPECT_FALSE(headers.HasHeader("Sec-Want-Endorsement"));
  EXPECT_EQ(headers.GetHeader(net::HttpRequestHeaders::kAuthorization),
            "Bearer session-jwt");
  EXPECT_EQ(headers.GetHeader("Content-Type"), "application/json");

  // If `Authorization` uses the `Mole` scheme (`-01` inline mode), it IS
  // stripped across redirects / 407 restarts.
  headers.SetHeader(net::HttpRequestHeaders::kAuthorization,
                    "Mole token=:AQID:");
  StripMoleRequestHeaders(&headers);
  EXPECT_FALSE(headers.HasHeader(net::HttpRequestHeaders::kAuthorization));
}

TEST_F(MoleUrlLoaderInterceptorTest,
       ExtractAndStripMoleResponseHeadersBeforeBuildResponseHead) {
  auto raw = net::HttpUtil::AssembleRawHeaders(
      "HTTP/1.1 401 Unauthorized\r\n"
      "Mole-Challenge: moderator=\"https://mod.example\", policy=\"p1\", "
      "cost=2, nonce=:AQIDBA==:\r\n"
      "Mole-Info: session=\"s1\", settle-ready=?1\r\n"
      "Mole-Credential: :BQYH:\r\n"
      "WWW-Authenticate: Bearer realm=\"origin-api\", Mole "
      "redeem-0002=\"abc\", challenge-0001=\"def\"\r\n"
      "WWW-Authenticate: Mole challenge-0001=\"ghi\", realm=\"api\"\r\n"
      "Content-Type: application/json\r\n\r\n");
  auto response_headers =
      base::MakeRefCounted<net::HttpResponseHeaders>(raw);

  ExtractedMoleResponseHeaders extracted =
      ExtractAndStripMoleResponseHeaders(*response_headers);

  ASSERT_TRUE(extracted.mole_challenge.has_value());
  EXPECT_NE(extracted.mole_challenge->find("https://mod.example"),
            std::string::npos);
  EXPECT_EQ(extracted.mole_info, "session=\"s1\", settle-ready=?1");
  EXPECT_EQ(extracted.mole_credential, ":BQYH:");
  ASSERT_EQ(extracted.www_authenticate_mole.size(), 2u);
  EXPECT_EQ(extracted.www_authenticate_mole[0],
            "Mole redeem-0002=\"abc\", challenge-0001=\"def\"");
  EXPECT_EQ(extracted.www_authenticate_mole[1],
            "Mole challenge-0001=\"ghi\", realm=\"api\"");

  // Stripped headers must be completely absent from `response_headers`.
  EXPECT_FALSE(response_headers->HasHeader("Mole-Challenge"));
  EXPECT_FALSE(response_headers->HasHeader("Mole-Info"));
  EXPECT_FALSE(response_headers->HasHeader("Mole-Credential"));

  // Non-MOLE `WWW-Authenticate: Bearer` must remain untouched for web apps,
  // with zero orphan `realm="api"` parameter fragments!
  size_t iter = 0;
  std::vector<std::string> remaining_www;
  while (std::optional<std::string_view> v =
             response_headers->EnumerateHeader(&iter, "WWW-Authenticate")) {
    remaining_www.emplace_back(*v);
  }
  ASSERT_EQ(remaining_www.size(), 1u);
  EXPECT_EQ(remaining_www[0], "Bearer realm=\"origin-api\"");
}

TEST_F(MoleUrlLoaderInterceptorTest,
       NetLogRedactsCommaChallengesAndMoleHeaders) {
  const auto mode = net::NetLogCaptureMode::kDefault;

  // Direct MOLE headers must be redacted in default NetLog capture mode.
  for (const char* hdr : {"Sec-Mole-Authorization", "Mole-Credential",
                          "Mole-Challenge", "Mole-Info"}) {
    std::string elided =
        net::ElideHeaderValueForNetLog(mode, hdr, "secret-token-payload");
    EXPECT_EQ(elided.find("secret-token-payload"), std::string::npos) << hdr;
    EXPECT_NE(elided.find("bytes were stripped"), std::string::npos) << hdr;
  }

  // `-01` `WWW-Authenticate: Mole` contains commas and previously bypassed
  // `ShouldRedactChallenge`; verify secret params are stripped.
  std::string mole_www = net::ElideHeaderValueForNetLog(
      mode, "WWW-Authenticate", "Mole challenge=\"secret123\", token-type=3");
  EXPECT_EQ(mole_www.find("secret123"), std::string::npos);
  EXPECT_NE(mole_www.find("bytes were stripped"), std::string::npos);

  // Multi-scheme comma-separated `WWW-Authenticate` with trailing `Mole`
  // challenge must also redact the `Mole` parameters while keeping `Basic`.
  std::string mixed_www = net::ElideHeaderValueForNetLog(
      mode, "WWW-Authenticate",
      "Basic realm=\"public\", Mole challenge=\"secret456\", version=1");
  EXPECT_NE(mixed_www.find("Basic realm=\"public\""), std::string::npos);
  EXPECT_EQ(mixed_www.find("secret456"), std::string::npos);

  // Pure `Basic` challenge remains public/unredacted as expected by `net/`.
  std::string basic_www = net::ElideHeaderValueForNetLog(
      mode, "WWW-Authenticate", "Basic realm=\"public\"");
  EXPECT_EQ(basic_www, "Basic realm=\"public\"");
}

TEST_F(MoleUrlLoaderInterceptorTest,
       ChallengeRetryExactlyOncePreventsInfinite401Loop) {
  RecordingFinalizer finalizer;
  FakeMoleAuthObserver observer(&finalizer);

  net::HttpRequestHeaders retry_hdrs;
  retry_hdrs.SetHeader("Sec-Mole-Authorization",
                       "clearance=:AQID:; session=\"sess-1\"");
  observer.set_challenge_retry_headers(retry_hdrs);

  auto params = mojom::MoleRequestParams::New();
  params->behavior = mojom::MoleModerationBehavior::kAuto;
  MoleUrlLoaderInterceptor interceptor(std::move(params), &observer);

  EXPECT_EQ(interceptor.GetAdditionalLoadFlags(),
            net::LOAD_BYPASS_CACHE | net::LOAD_DISABLE_CACHE);

  const GURL url("https://shoes.example/api/purchase");
  const url::Origin top_origin =
      url::Origin::Create(GURL("https://shoes.example"));

  // Outbound step (no cached policy yet -> empty headers).
  net::HttpRequestHeaders initial_attached;
  interceptor.BeginOutboundRequest(
      url, "POST", top_origin,
      base::BindLambdaForTesting(
          [&](net::HttpRequestHeaders hdrs) { initial_attached = hdrs; }));
  EXPECT_TRUE(initial_attached.IsEmpty());

  // First `401` with `Mole-Challenge` triggers exactly one retry.
  ExtractedMoleResponseHeaders first_401;
  first_401.mole_challenge =
      "moderator=\"https://mod.example\", policy=\"p1\", cost=1, nonce=:AAEC:";
  MoleUrlLoaderInterceptor::ResponseAction first_action;
  interceptor.ProcessOriginResponse(
      url, "POST", top_origin, 401, std::move(first_401),
      /*allow_challenge_retry=*/true,
      base::BindLambdaForTesting(
          [&](MoleUrlLoaderInterceptor::ResponseAction action) {
            first_action = std::move(action);
          }));
  EXPECT_TRUE(first_action.should_retry);
  EXPECT_EQ(first_action.retry_headers.GetHeader("Sec-Mole-Authorization"),
            "clearance=:AQID:; session=\"sess-1\"");
  EXPECT_EQ(observer.challenge_calls(), 1);

  // Simulate wire bytes sent on the retried request, followed by a second `401`
  // from a misconfigured Origin: interceptor settles the retry's finalizer and
  // refuses to retry a second time (preventing an infinite 401 loop).
  interceptor.OnWireBytesSent();
  ExtractedMoleResponseHeaders second_401;
  second_401.mole_challenge =
      "moderator=\"https://mod.example\", policy=\"p1\", cost=1, nonce=:BAUG:";
  MoleUrlLoaderInterceptor::ResponseAction second_action;
  base::RunLoop loop;
  interceptor.ProcessOriginResponse(
      url, "POST", top_origin, 401, std::move(second_401),
      /*allow_challenge_retry=*/true,
      base::BindLambdaForTesting(
          [&](MoleUrlLoaderInterceptor::ResponseAction action) {
            second_action = std::move(action);
            loop.Quit();
          }));
  loop.Run();

  EXPECT_FALSE(second_action.should_retry);
  EXPECT_EQ(observer.challenge_calls(), 1);
  ASSERT_EQ(finalizer.responses().size(), 1u);
  EXPECT_EQ(finalizer.responses()[0].http_status, 401);
  EXPECT_TRUE(finalizer.responses()[0].wire_bytes_sent);
}

TEST_F(MoleUrlLoaderInterceptorTest,
       WireBytesSentStickyFinalizerSettlementPreAndPostSend) {
  RecordingFinalizer finalizer;
  FakeMoleAuthObserver observer(&finalizer);
  observer.set_bind_outbound_finalizer(true);

  const GURL url("https://shoes.example/api/purchase");
  const url::Origin top_origin =
      url::Origin::Create(GURL("https://shoes.example"));

  // Case 1: Loader fails before `OnWireBytesSent()` (e.g. DNS failure).
  {
    auto params = mojom::MoleRequestParams::New();
    MoleUrlLoaderInterceptor interceptor(std::move(params), &observer);
    interceptor.BeginOutboundRequest(
        url, "POST", top_origin,
        base::BindOnce([](net::HttpRequestHeaders) {}));
    interceptor.OnLoaderCompleted(net::ERR_NAME_NOT_RESOLVED);
    task_environment_.RunUntilIdle();
  }
  ASSERT_EQ(finalizer.aborts().size(), 1u);
  EXPECT_EQ(finalizer.aborts()[0].net_error, net::ERR_NAME_NOT_RESOLVED);
  EXPECT_FALSE(finalizer.aborts()[0].wire_bytes_sent);

  // Case 2: Loader aborts AFTER `OnWireBytesSent()` (e.g. connection reset
  // mid-response) -> `wire_bytes_sent` is true.
  {
    auto params = mojom::MoleRequestParams::New();
    MoleUrlLoaderInterceptor interceptor(std::move(params), &observer);
    interceptor.BeginOutboundRequest(
        url, "POST", top_origin,
        base::BindOnce([](net::HttpRequestHeaders) {}));
    interceptor.OnWireBytesSent();
    interceptor.OnLoaderCompleted(net::ERR_CONNECTION_RESET);
    task_environment_.RunUntilIdle();
  }
  ASSERT_EQ(finalizer.aborts().size(), 2u);
  EXPECT_EQ(finalizer.aborts()[1].net_error, net::ERR_CONNECTION_RESET);
  EXPECT_TRUE(finalizer.aborts()[1].wire_bytes_sent);
}

TEST_F(MoleUrlLoaderInterceptorTest,
       RedirectAbortsActiveFinalizerAndResetsWireBytesFlag) {
  RecordingFinalizer finalizer;
  FakeMoleAuthObserver observer(&finalizer);
  observer.set_bind_outbound_finalizer(true);

  const GURL url("https://shoes.example/api/purchase");
  const url::Origin top_origin =
      url::Origin::Create(GURL("https://shoes.example"));

  auto params = mojom::MoleRequestParams::New();
  MoleUrlLoaderInterceptor interceptor(std::move(params), &observer);
  interceptor.BeginOutboundRequest(url, "POST", top_origin,
                                   base::BindOnce([](net::HttpRequestHeaders) {}));
  interceptor.OnWireBytesSent();
  EXPECT_TRUE(interceptor.wire_bytes_sent());

  interceptor.OnRedirect(302, ExtractedMoleResponseHeaders());
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(interceptor.wire_bytes_sent());
  ASSERT_EQ(finalizer.aborts().size(), 1u);
  EXPECT_EQ(finalizer.aborts()[0].net_error, net::ERR_ABORTED);
  EXPECT_TRUE(finalizer.aborts()[0].wire_bytes_sent);
}

TEST_F(MoleUrlLoaderInterceptorTest,
       PostRedirectGet303SettlesMoleInfoAndCredentialInsteadOfAborting) {
  RecordingFinalizer finalizer;
  FakeMoleAuthObserver observer(&finalizer);
  observer.set_bind_outbound_finalizer(true);

  const GURL url("https://shoes.example/api/purchase");
  const url::Origin top_origin =
      url::Origin::Create(GURL("https://shoes.example"));

  auto params = mojom::MoleRequestParams::New();
  MoleUrlLoaderInterceptor interceptor(std::move(params), &observer);
  interceptor.BeginOutboundRequest(url, "POST", top_origin,
                                   base::BindOnce([](net::HttpRequestHeaders) {}));
  interceptor.OnWireBytesSent();

  ExtractedMoleResponseHeaders prg_headers;
  prg_headers.mole_info = "session=\"sess-prg\", settle-ready=?1";
  interceptor.OnRedirect(303, std::move(prg_headers));
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(interceptor.wire_bytes_sent());
  EXPECT_TRUE(finalizer.aborts().empty());
  ASSERT_EQ(finalizer.responses().size(), 1u);
  EXPECT_EQ(finalizer.responses()[0].http_status, 303);
  EXPECT_EQ(finalizer.responses()[0].mole_info,
            "session=\"sess-prg\", settle-ready=?1");
  EXPECT_TRUE(finalizer.responses()[0].wire_bytes_sent);
}

TEST_F(MoleUrlLoaderInterceptorTest,
       MaybeCreateReturnsNullptrWhenFactoryLacksObserverWithoutCrashing) {
  OptionalMoleParams mole_params = *mojom::MoleRequestParams::New();
  EXPECT_EQ(MoleUrlLoaderInterceptor::MaybeCreate(mole_params,
                                                  /*observer=*/nullptr),
            nullptr);
}

}  // namespace
}  // namespace network
