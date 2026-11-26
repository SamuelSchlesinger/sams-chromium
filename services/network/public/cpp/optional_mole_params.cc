// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/public/cpp/optional_mole_params.h"

#include <utility>

namespace network {

OptionalMoleParams::OptionalMoleParams() = default;
OptionalMoleParams::OptionalMoleParams(std::nullopt_t) {}
OptionalMoleParams::OptionalMoleParams(mojom::MoleRequestParamsPtr ptr)
    : ptr_(std::move(ptr)) {}
OptionalMoleParams::OptionalMoleParams(const mojom::MoleRequestParams& params)
    : ptr_(params.Clone()) {}
OptionalMoleParams::OptionalMoleParams(const OptionalMoleParams& other) {
  ptr_ = other.as_ptr().Clone();
}
OptionalMoleParams& OptionalMoleParams::operator=(
    const OptionalMoleParams& other) {
  ptr_ = other.as_ptr().Clone();
  return *this;
}
OptionalMoleParams::OptionalMoleParams(OptionalMoleParams&& other) = default;
OptionalMoleParams& OptionalMoleParams::operator=(OptionalMoleParams&& other) =
    default;
OptionalMoleParams::~OptionalMoleParams() = default;
bool OptionalMoleParams::operator==(const OptionalMoleParams& other) const {
  return mojo::Equals(ptr_, other.ptr_);
}

}  // namespace network
