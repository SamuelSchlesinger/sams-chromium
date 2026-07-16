// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// MoLE crypto exposure shim: BoringSSL's Keccak-f1600 permutation is a
// `static inline` template inside the FIPS module translation unit and is not
// an exported symbol. The MoLE sigma-protocol layer needs the *raw*
// permutation (spongefish's duplex sponge runs the bare permutation, not
// SHAKE-with-padding), so this shim gives itself a copy by including the
// permutation source and re-exports it under a stable ABI.
//
// This is scoped to the sigma target's use only (see visibility on the
// `mole_crypto_shim` source_set). NEEDS BORINGSSL OWNERS SIGN-OFF.

#include <stdint.h>

// Pulls in the `static inline` Keccak-f1600 permutation (keccak_f). The .inc's
// relative includes resolve against its own directory; only this file's
// include path needs to reach `src/`. It carries a file-scope
// `using namespace bssl;` that -Wheader-hygiene flags when pulled in as an
// include, so the warning is suppressed just across the include.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wheader-hygiene"
#include "crypto/fipsmodule/keccak/keccak.cc.inc"
#pragma clang diagnostic pop

extern "C" {

// Applies the Keccak-f1600 permutation in place to a 25-word (1600-bit) state,
// the scalar (uint64_t) instantiation. Byte-for-byte the FIPS-202 permutation.
// Default visibility so the sigma static library can link it across the
// component-build boundary.
__attribute__((visibility("default"))) void MOLE_keccak_f1600(
    uint64_t state[25]) {
  keccak_f(state);
}

}  // extern "C"
