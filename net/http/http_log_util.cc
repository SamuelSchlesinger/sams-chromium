// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_log_util.h"

#include <string_view>

#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/log/net_log_with_source.h"

namespace net {

namespace {

// Scans a `WWW-Authenticate` or `Proxy-Authenticate` header value for a
// comma-separated `Mole` challenge (e.g. `Basic realm="api", Mole challenge=...`).
// If found, returns the substring slice starting at the `Mole` parameters (or
// the `Mole` token itself if parameterless) so `ElideHeaderValueForNetLog`
// redacts everything from `Mole` onward.
std::string_view FindTrailingMoleChallengeParams(std::string_view value) {
  constexpr std::string_view kMoleScheme = "mole";
  size_t pos = 0;
  while (pos < value.size()) {
    size_t comma = value.find(',', pos);
    if (comma == std::string_view::npos) {
      break;
    }
    size_t token_start = comma + 1;
    while (token_start < value.size() && HttpUtil::IsLWS(value[token_start])) {
      ++token_start;
    }
    if (value.size() - token_start >= kMoleScheme.size() &&
        base::EqualsCaseInsensitiveASCII(
            value.substr(token_start, kMoleScheme.size()), kMoleScheme)) {
      size_t after_scheme = token_start + kMoleScheme.size();
      if (after_scheme == value.size()) {
        return value.substr(token_start);
      }
      if (HttpUtil::IsLWS(value[after_scheme])) {
        while (after_scheme < value.size() &&
               HttpUtil::IsLWS(value[after_scheme])) {
          ++after_scheme;
        }
        return after_scheme < value.size() ? value.substr(after_scheme)
                                           : value.substr(token_start);
      }
    }
    pos = comma + 1;
  }
  return {};
}

bool ShouldRedactChallenge(HttpAuthChallengeTokenizer* challenge) {
  const std::string& scheme = challenge->auth_scheme();
  // Invalid input.
  if (scheme.empty())
    return false;

  // Always redact `Mole` challenges, which carry comma-separated RFC 9110
  // auth-params (`WWW-Authenticate: Mole challenge=..., ...`).
  if (scheme == "mole")
    return true;

  // Ignore lines with commas, as they may contain lists of schemes, and
  // the information we want to hide is Base64 encoded, so has no commas.
  if (challenge->challenge_text().find(',') != std::string::npos)
    return false;

  // Ignore Basic and Digest authentication challenges, as they contain
  // public information.
  if (scheme == kBasicAuthScheme || scheme == kDigestAuthScheme)
    return false;

  return true;
}

}  // namespace

std::string ElideHeaderValueForNetLog(NetLogCaptureMode capture_mode,
                                      std::string_view header,
                                      std::string_view value) {
  std::string_view redact;

  if (!NetLogCaptureIncludesSensitive(capture_mode)) {
    if (base::EqualsCaseInsensitiveASCII(header, "set-cookie") ||
        base::EqualsCaseInsensitiveASCII(header, "set-cookie2") ||
        base::EqualsCaseInsensitiveASCII(header, "cookie") ||
        base::EqualsCaseInsensitiveASCII(header, "authorization") ||
        base::EqualsCaseInsensitiveASCII(header, "proxy-authorization") ||
        base::EqualsCaseInsensitiveASCII(header, "sec-mole-authorization") ||
        base::EqualsCaseInsensitiveASCII(header, "mole-credential") ||
        base::EqualsCaseInsensitiveASCII(header, "mole-challenge") ||
        base::EqualsCaseInsensitiveASCII(header, "mole-info")) {
      redact = value;
    } else if (base::EqualsCaseInsensitiveASCII(header, "www-authenticate") ||
               base::EqualsCaseInsensitiveASCII(header, "proxy-authenticate")) {
      // Look for authentication information from data received from the server
      // in multi-round Negotiate authentication or MOLE challenges.
      HttpAuthChallengeTokenizer challenge(value);
      if (ShouldRedactChallenge(&challenge)) {
        redact = challenge.params();
        if (redact.empty()) {
          redact = value;
        }
      } else {
        redact = FindTrailingMoleChallengeParams(value);
      }
    }
  }

  if (redact.empty()) {
    return std::string(value);
  }

  // Create string_views that contain the part of `value` before the `redact`
  // substring, and the value after it. Need to use the data() field of the two
  // string_views to figure out where `redact` appears within `value`.
  size_t redact_offset = redact.data() - value.data();
  std::string_view value_before_redact = value.substr(0, redact_offset);
  std::string_view value_after_redact =
      value.substr(redact_offset + redact.length());

  return base::StrCat({value_before_redact,
                       base::StringPrintf("[%ld bytes were stripped]",
                                          static_cast<long>(redact.length())),
                       value_after_redact});
}

NET_EXPORT void NetLogResponseHeaders(const NetLogWithSource& net_log,
                                      NetLogEventType type,
                                      const HttpResponseHeaders* headers) {
  net_log.AddEvent(type, [&](NetLogCaptureMode capture_mode) {
    return headers->NetLogParams(capture_mode);
  });
}

void NetLogRequestHeaders(const NetLogWithSource& net_log,
                          NetLogEventType type,
                          const std::string& request_line,
                          const HttpRequestHeaders* headers) {
  net_log.AddEvent(type, [&](NetLogCaptureMode capture_mode) {
    return headers->NetLogParams(request_line, capture_mode);
  });
}

}  // namespace net
