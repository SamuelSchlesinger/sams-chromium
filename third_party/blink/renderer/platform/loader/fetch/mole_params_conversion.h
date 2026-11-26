// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_PLATFORM_LOADER_FETCH_MOLE_PARAMS_CONVERSION_H_
#define THIRD_PARTY_BLINK_RENDERER_PLATFORM_LOADER_FETCH_MOLE_PARAMS_CONVERSION_H_

#include <optional>

#include "services/network/public/cpp/optional_mole_params.h"
#include "third_party/blink/public/platform/web_common.h"

namespace network::mojom::blink {
class MoleRequestParams;
}  // namespace network::mojom::blink

namespace blink {

BLINK_PLATFORM_EXPORT network::OptionalMoleParams ConvertMoleParams(
    const std::optional<network::mojom::blink::MoleRequestParams>& maybe_in);

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_PLATFORM_LOADER_FETCH_MOLE_PARAMS_CONVERSION_H_
