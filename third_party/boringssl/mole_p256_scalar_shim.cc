// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// MoLE crypto exposure shim: a C-ABI, byte-in / byte-out wrapper over
// BoringSSL's constant-time P-256 EC_SCALAR arithmetic, for the MoLE sigma
// layer (//third_party/mole/sigma_boring). Scalars cross this boundary as
// 32-byte big-endian canonical (< n) values; EC_SCALAR and Montgomery form
// stay on the C++ side. Every operation is constant-time in the scalar value
// (`ec_scalar_*` + `ec_scalar_from/to_bytes` are fixed-width), replacing the
// variable-time BIGNUM path (BN_mod_*, BN_mod_inverse) the module used before.
//
// The internal `bssl::ec_scalar_*` symbols are not exported from libcrypto, so
// this file is compiled INTO the boringssl component (see the component target
// in BUILD.gn) and re-exports only the `MOLE_p256_scalar_*` wrappers with the
// stable default-visibility ABI. Scoped to the one sigma consumer. NEEDS
// BORINGSSL OWNERS SIGN-OFF (the upstreamable path is exposing EC_SCALAR
// through bssl-sys directly, which David Benjamin has discussed).

#include <openssl/base.h>
#include <openssl/ec.h>

#include <stddef.h>
#include <stdint.h>

#include "crypto/fipsmodule/bn/internal.h"  // bn_big_endian_to_words
#include "crypto/fipsmodule/ec/internal.h"  // bssl::EC_SCALAR, bssl::ec_scalar_*

using namespace bssl;

namespace {

// P-256 order is 256 bits; a value < order^2 (< 512 bits) fits in 2*width
// BN_ULONG words. Computed without touching EC_GROUP internals.
constexpr size_t kOrderWords = 256 / (sizeof(BN_ULONG) * 8);

// Decode a 32-byte big-endian value known to be canonical (< n). Inputs always
// originate from an already-canonical Scalar, so this cannot fail.
void ToScalar(const EC_GROUP* group, EC_SCALAR* out, const uint8_t in[32]) {
  ec_scalar_from_bytes(group, out, in, 32);
}

void ToBytes(const EC_GROUP* group, uint8_t out[32], const EC_SCALAR* in) {
  size_t len;
  ec_scalar_to_bytes(group, out, &len, in);
}

}  // namespace

extern "C" {

// Canonical decode: writes `out` and returns 1 iff `in` < n; returns 0
// (leaving `out` untouched) otherwise. Constant-time in the value.
OPENSSL_EXPORT int MOLE_p256_scalar_from_bytes(uint8_t out[32],
                                               const uint8_t in[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR s;
  if (!ec_scalar_from_bytes(group, &s, in, 32)) {
    return 0;
  }
  ToBytes(group, out, &s);
  return 1;
}

// Reduce a big-endian value (`in_len` <= 48) modulo n. Safe because such inputs
// are < n^2, the precondition of ec_scalar_reduce. Used for the 32-byte reduced
// decode.
OPENSSL_EXPORT void MOLE_p256_scalar_reduce(uint8_t out[32],
                                            const uint8_t* in,
                                            size_t in_len) {
  const EC_GROUP* group = EC_group_p256();
  BN_ULONG words[kOrderWords * 2] = {0};
  bn_big_endian_to_words(words, kOrderWords * 2, in, in_len);
  EC_SCALAR s;
  ec_scalar_reduce(group, &s, words, kOrderWords * 2);
  ToBytes(group, out, &s);
}

OPENSSL_EXPORT void MOLE_p256_scalar_add(uint8_t out[32],
                                         const uint8_t a[32],
                                         const uint8_t b[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa, sb, r;
  ToScalar(group, &sa, a);
  ToScalar(group, &sb, b);
  ec_scalar_add(group, &r, &sa, &sb);
  ToBytes(group, out, &r);
}

OPENSSL_EXPORT void MOLE_p256_scalar_sub(uint8_t out[32],
                                         const uint8_t a[32],
                                         const uint8_t b[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa, sb, r;
  ToScalar(group, &sa, a);
  ToScalar(group, &sb, b);
  ec_scalar_sub(group, &r, &sa, &sb);
  ToBytes(group, out, &r);
}

OPENSSL_EXPORT void MOLE_p256_scalar_neg(uint8_t out[32], const uint8_t a[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa, r;
  ToScalar(group, &sa, a);
  ec_scalar_neg(group, &r, &sa);
  ToBytes(group, out, &r);
}

// r = a * b mod n. mul_montgomery(mont(a), b_plain) = a*b in plain form.
OPENSSL_EXPORT void MOLE_p256_scalar_mul(uint8_t out[32],
                                         const uint8_t a[32],
                                         const uint8_t b[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa, sb, r;
  ToScalar(group, &sa, a);
  ToScalar(group, &sb, b);
  ec_scalar_to_montgomery(group, &sa, &sa);
  ec_scalar_mul_montgomery(group, &r, &sa, &sb);
  ToBytes(group, out, &r);
}

// r = a^-1 mod n. Returns 0 if a == 0 (out set to 0), else 1.
// from_montgomery(inv0_montgomery(to_montgomery(a))) = a^-1 in plain form.
OPENSSL_EXPORT int MOLE_p256_scalar_invert(uint8_t out[32],
                                           const uint8_t a[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa, r;
  ToScalar(group, &sa, a);
  int nonzero = !ec_scalar_is_zero(group, &sa);
  ec_scalar_to_montgomery(group, &sa, &sa);
  ec_scalar_inv0_montgomery(group, &r, &sa);
  ec_scalar_from_montgomery(group, &r, &r);
  ToBytes(group, out, &r);
  return nonzero;
}

OPENSSL_EXPORT int MOLE_p256_scalar_is_zero(const uint8_t a[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa;
  ToScalar(group, &sa, a);
  return ec_scalar_is_zero(group, &sa);
}

// out = (mask ? a : b), constant-time. `mask` is 0x00 or 0x01, broadcast to a
// full-width word here.
OPENSSL_EXPORT void MOLE_p256_scalar_select(uint8_t out[32],
                                            uint8_t mask,
                                            const uint8_t a[32],
                                            const uint8_t b[32]) {
  const EC_GROUP* group = EC_group_p256();
  EC_SCALAR sa, sb, r;
  ToScalar(group, &sa, a);
  ToScalar(group, &sb, b);
  BN_ULONG m = (BN_ULONG)0 - (BN_ULONG)(mask & 1);
  ec_scalar_select(group, &r, m, &sa, &sb);
  ToBytes(group, out, &r);
}

// Uniform in [0, n). Returns 1 on success, 0 on RNG failure.
OPENSSL_EXPORT int MOLE_p256_scalar_random(uint8_t out[32]) {
  const EC_GROUP* group = EC_group_p256();
  uint8_t zero[32] = {0};
  EC_SCALAR s;
  if (!ec_random_scalar(group, &s, zero)) {
    return 0;
  }
  ToBytes(group, out, &s);
  return 1;
}

}  // extern "C"
