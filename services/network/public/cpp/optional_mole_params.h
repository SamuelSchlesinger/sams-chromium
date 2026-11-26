// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_PUBLIC_CPP_OPTIONAL_MOLE_PARAMS_H_
#define SERVICES_NETWORK_PUBLIC_CPP_OPTIONAL_MOLE_PARAMS_H_

#include <optional>

#include "base/check.h"
#include "base/component_export.h"
#include "services/network/public/mojom/moderated_endorsements.mojom.h"

namespace network {

// Copyable wrapper around `mojom::MoleRequestParamsPtr` for use in
// `network::ResourceRequest` (mirroring `OptionalTrustTokenParams`).
class COMPONENT_EXPORT(NETWORK_CPP_BASE) OptionalMoleParams {
 public:
  OptionalMoleParams();
  OptionalMoleParams(std::nullopt_t);  // NOLINT
  explicit OptionalMoleParams(mojom::MoleRequestParamsPtr);

  OptionalMoleParams(const mojom::MoleRequestParams&);  // NOLINT
  OptionalMoleParams(const OptionalMoleParams&);
  OptionalMoleParams& operator=(const OptionalMoleParams&);
  OptionalMoleParams(OptionalMoleParams&&);
  OptionalMoleParams& operator=(OptionalMoleParams&&);

  ~OptionalMoleParams();

  bool operator==(const OptionalMoleParams&) const;

  explicit operator bool() const { return has_value(); }
  bool has_value() const { return !!ptr_; }

  mojom::MoleRequestParams& value() {
    CHECK(has_value());
    return *ptr_;
  }

  const mojom::MoleRequestParams& value() const {
    CHECK(has_value());
    return *ptr_;
  }

  const mojom::MoleRequestParams* operator->() const {
    CHECK(has_value());
    return ptr_.get();
  }

  mojom::MoleRequestParams* operator->() {
    CHECK(has_value());
    return ptr_.get();
  }

  const mojom::MoleRequestParamsPtr& as_ptr() const { return ptr_; }
  mojom::MoleRequestParamsPtr& as_ptr() { return ptr_; }

 private:
  mojom::MoleRequestParamsPtr ptr_;
};

}  // namespace network

#endif  // SERVICES_NETWORK_PUBLIC_CPP_OPTIONAL_MOLE_PARAMS_H_
