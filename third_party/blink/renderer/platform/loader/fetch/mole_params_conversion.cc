// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/mole_params_conversion.h"

#include <utility>

#include "services/network/public/mojom/moderated_endorsements.mojom-blink.h"

namespace blink {

network::OptionalMoleParams ConvertMoleParams(
    const std::optional<network::mojom::blink::MoleRequestParams>& maybe_in) {
  if (!maybe_in) {
    return std::nullopt;
  }
  const network::mojom::blink::MoleRequestParams& in = *maybe_in;

  network::mojom::MoleRequestParamsPtr out =
      network::mojom::MoleRequestParams::New();
  if (in.moderator) {
    out->moderator = in.moderator->ToUrlOrigin();
  }
  out->behavior = in.behavior;
  out->max_cost = in.max_cost;
  out->allow_deferred_update = in.allow_deferred_update;
  return network::OptionalMoleParams(std::move(out));
}

}  // namespace blink
