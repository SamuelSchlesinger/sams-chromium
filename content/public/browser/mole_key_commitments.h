// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_MOLE_KEY_COMMITMENTS_H_
#define CONTENT_PUBLIC_BROWSER_MOLE_KEY_COMMITMENTS_H_

#include <string_view>

#include "content/common/content_export.h"

namespace content {

// Replaces the Browser Process Moderated Endorsements (MOLE) key-commitment
// registry from a signed Component Updater JSON document. Malformed input is
// rejected atomically without modifying existing commitments.
CONTENT_EXPORT bool SetMoleKeyCommitments(std::string_view json);

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_MOLE_KEY_COMMITMENTS_H_
