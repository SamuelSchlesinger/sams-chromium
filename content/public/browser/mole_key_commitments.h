// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_MOLE_KEY_COMMITMENTS_H_
#define CONTENT_PUBLIC_BROWSER_MOLE_KEY_COMMITMENTS_H_

#include <string_view>

#include "content/common/content_export.h"

namespace content {

// Replaces the browser's MoLE key-commitment registry from a component's JSON
// document (see mole_commitment_registry.cc for the schema). Called on the UI
// thread by the embedder's component-updater integration whenever a new version
// of the registry component is delivered; malformed input is ignored (the
// previous contents stay in place). Returns true on a successful parse.
//
// This is the content-layer analogue of Private State Tokens'
// NetworkService::SetTrustTokenKeyCommitments: MoLE's exchanges run in the
// browser process, so the registry lives here rather than in the network
// service, and the embedder feeds it directly instead of over Mojo.
CONTENT_EXPORT bool SetMoleKeyCommitments(std::string_view json);

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_MOLE_KEY_COMMITMENTS_H_
