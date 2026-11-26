// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_MODERATED_ENDORSEMENTS_MOLE_PLATFORM_H_
#define COMPONENTS_MODERATED_ENDORSEMENTS_MOLE_PLATFORM_H_

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#if defined(MOLE_STANDALONE_BUILD)
#include <charconv>
#include <openssl/aead.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#else
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/functional/function_ref.h"
#include "base/strings/cstring_view.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/schemeful_site.h"
#include "sql/database.h"
#include "sql/statement.h"
#include "sql/transaction.h"
#include "third_party/boringssl/src/include/openssl/aead.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/rand.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "url/gurl.h"
#include "url/origin.h"
#endif

namespace moderated_endorsements {

#if !defined(MOLE_STANDALONE_BUILD)
using ByteSpan = base::span<const uint8_t>;
using MutableByteSpan = base::span<uint8_t>;
template <typename Signature>
using FunctionRef = base::FunctionRef<Signature>;

inline std::string IntToDecimalString(int64_t val) {
  return base::NumberToString(val);
}

inline std::string UintToDecimalString(uint64_t val) {
  return base::NumberToString(val);
}
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
template <typename T>
class StandaloneSpan {
 public:
  constexpr StandaloneSpan() = default;
  constexpr StandaloneSpan(T* ptr, size_t len) : data_(ptr), size_(len) {}

  template <typename Container>
    requires(!std::is_same_v<std::remove_cvref_t<Container>, StandaloneSpan> &&
             requires(Container& c) {
               { c.data() } -> std::convertible_to<T*>;
               { c.size() } -> std::convertible_to<size_t>;
             })
  // NOLINTNEXTLINE(google-explicit-constructor)
  constexpr StandaloneSpan(Container&& c)
      : data_(c.data()), size_(c.size()) {}

  constexpr T* data() const { return data_; }
  constexpr size_t size() const { return size_; }
  constexpr bool empty() const { return size_ == 0; }
  constexpr T* begin() const { return data_; }
  constexpr T* end() const { return data_ + size_; }
  constexpr T& operator[](size_t i) const { return data_[i]; }

  template <size_t N>
  constexpr StandaloneSpan<T> first() const {
    return StandaloneSpan<T>(data_, N);
  }

  constexpr StandaloneSpan<T> first(size_t count) const {
    return StandaloneSpan<T>(data_, count);
  }

  constexpr StandaloneSpan<T> subspan(
      size_t offset,
      size_t count = static_cast<size_t>(-1)) const {
    const size_t n =
        count == static_cast<size_t>(-1) ? (size_ - offset) : count;
    return StandaloneSpan<T>(data_ + offset, n);
  }

 private:
  T* data_ = nullptr;
  size_t size_ = 0;
};

using ByteSpan = StandaloneSpan<const uint8_t>;
using MutableByteSpan = StandaloneSpan<uint8_t>;

inline std::string IntToDecimalString(int64_t val) {
  std::array<char, 32> buf{};
  auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), val);
  return ec == std::errc()
             ? std::string(buf.data(), static_cast<size_t>(ptr - buf.data()))
             : std::string();
}

inline std::string UintToDecimalString(uint64_t val) {
  std::array<char, 32> buf{};
  auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), val);
  return ec == std::errc()
             ? std::string(buf.data(), static_cast<size_t>(ptr - buf.data()))
             : std::string();
}
#pragma clang diagnostic pop

template <typename Signature>
class FunctionRef;

template <typename R, typename... Args>
class FunctionRef<R(Args...)> {
 public:
  template <typename F>
    requires(!std::is_same_v<std::remove_cvref_t<F>, FunctionRef>)
  // NOLINTNEXTLINE(google-explicit-constructor)
  FunctionRef(const F& fn)
      : obj_(static_cast<const void*>(std::addressof(fn))),
        thunk_([](const void* ptr, Args... args) -> R {
          return (*static_cast<const F*>(ptr))(std::forward<Args>(args)...);
        }) {}

  R operator()(Args... args) const {
    return thunk_(obj_, std::forward<Args>(args)...);
  }

 private:
  const void* obj_ = nullptr;
  R (*thunk_)(const void*, Args...) = nullptr;
};
#endif

// RAII secret byte buffer that unconditionally wipes heap memory via BoringSSL
// `OPENSSL_cleanse` before deallocation or overwrite.
// All constructors and destructor are out-of-line in `mole_platform.cc` per
// `[chromium-style]`.
class ZeroizingBytes {
 public:
  ZeroizingBytes();
  explicit ZeroizingBytes(std::vector<uint8_t> bytes);
  explicit ZeroizingBytes(ByteSpan bytes);

  ZeroizingBytes(const ZeroizingBytes& other);
  ZeroizingBytes& operator=(const ZeroizingBytes& other);

  ZeroizingBytes(ZeroizingBytes&& other) noexcept;
  ZeroizingBytes& operator=(ZeroizingBytes&& other) noexcept;

  ~ZeroizingBytes();

  void Wipe();

  const uint8_t* data() const { return bytes_.data(); }
  size_t size() const { return bytes_.size(); }
  bool empty() const { return bytes_.empty(); }
  const std::vector<uint8_t>& vec() const { return bytes_; }
  ByteSpan span() const { return ByteSpan(bytes_); }

 private:
  std::vector<uint8_t> bytes_;
};

// BoringSSL AES-256-GCM AEAD wrapper for encrypting secret BLOB columns at rest
// with explicit table + row AAD binding so ciphertexts cannot be swapped across
// rows, origins, or tables.
class MoleAead {
 public:
  static constexpr size_t kKeyLength = 32;
  static constexpr size_t kNonceLength = 12;
  static constexpr size_t kTagLength = 16;

  MoleAead();
  explicit MoleAead(const std::array<uint8_t, kKeyLength>& key);

  MoleAead(const MoleAead&) = delete;
  MoleAead& operator=(const MoleAead&) = delete;

  ~MoleAead();

  std::optional<std::vector<uint8_t>> Seal(ByteSpan plaintext,
                                           std::string_view aad) const;
  std::optional<ZeroizingBytes> Open(ByteSpan sealed,
                                     std::string_view aad) const;

 private:
  void Init(const std::array<uint8_t, kKeyLength>& key);

  EVP_AEAD_CTX ctx_{};
  bool initialized_ = false;
};

std::array<uint8_t, 32> Sha256Digest(ByteSpan data);
bool FillRandom(MutableByteSpan out);

#if defined(MOLE_STANDALONE_BUILD)
std::string CreateStandaloneTempDir();
void RemoveStandaloneTempDir(const std::string& dir_path);
std::vector<uint8_t> ReadStandaloneFileBytes(const std::string& path);
bool StandalonePathExists(const std::string& path);
#endif

// ---------------------------------------------------------------------------
// Origin & SchemefulSite Canonicalization
// ---------------------------------------------------------------------------

#if !defined(MOLE_STANDALONE_BUILD)

inline std::string CanonicalHttpsOrigin(std::string_view raw) {
  GURL url(raw);
  if (!url.is_valid() || !url.SchemeIs("https")) {
    return std::string();
  }
  url::Origin origin = url::Origin::Create(url);
  if (origin.opaque() || origin.scheme() != "https") {
    return std::string();
  }
  return origin.Serialize();
}

inline std::string CanonicalSchemefulSite(std::string_view raw) {
  GURL url(raw);
  if (!url.is_valid() || !url.SchemeIs("https")) {
    return std::string();
  }
  url::Origin origin = url::Origin::Create(url);
  if (origin.opaque() || origin.scheme() != "https") {
    return std::string();
  }
  net::SchemefulSite site(origin);
  if (site.opaque()) {
    return std::string();
  }
  return site.Serialize();
}

inline std::string ExtractRegistrableDomainOrHost(std::string_view raw) {
  std::string site = CanonicalSchemefulSite(raw);
  constexpr std::string_view kPrefix = "https://";
  if (site.starts_with(kPrefix)) {
    return site.substr(kPrefix.size());
  }
  return std::string();
}

#else  // defined(MOLE_STANDALONE_BUILD)

std::string CanonicalHttpsOrigin(std::string_view raw);
std::string CanonicalSchemefulSite(std::string_view raw);
std::string ExtractRegistrableDomainOrHost(std::string_view raw);

#endif  // !defined(MOLE_STANDALONE_BUILD)

// ---------------------------------------------------------------------------
// Thin SQLite Adapter (`//sql` in Chromium GN, `<sqlite3.h>` in Standalone)
// ---------------------------------------------------------------------------

#if !defined(MOLE_STANDALONE_BUILD)

class SqlDb {
 public:
  SqlDb()
      : db_(sql::DatabaseOptions().set_wal_mode(true),
            sql::Database::Tag("ModeratedEndorsements")) {}

  bool OpenDisk(const std::string& path) {
    return db_.Open(base::FilePath::FromUTF8Unsafe(path));
  }

  bool OpenMemory() { return db_.OpenInMemory(); }

  void Close() { db_.Close(); }
  bool is_open() const { return db_.is_open(); }

  bool Execute(const char* sql) { return db_.Execute(sql); }

  int64_t LastInsertRowId() const { return db_.GetLastInsertRowId(); }

  sql::Database* raw() { return &db_; }

 private:
  sql::Database db_;
};

class SqlStmt {
 public:
  SqlStmt(SqlDb& db, const char* sql)
      : stmt_(db.raw()->GetUniqueStatement(sql)) {}

  bool is_valid() const { return stmt_.is_valid(); }

  void BindInt64(int idx, int64_t val) { stmt_.BindInt64(idx, val); }
  void BindString(int idx, std::string_view val) { stmt_.BindString(idx, val); }
  void BindBlob(int idx, ByteSpan data) { stmt_.BindBlob(idx, data); }

  bool Step() { return stmt_.Step(); }
  bool Run() { return stmt_.Run(); }

  int64_t ColumnInt64(int col) { return stmt_.ColumnInt64(col); }
  std::string ColumnString(int col) { return stmt_.ColumnString(col); }
  std::vector<uint8_t> ColumnBlob(int col) {
    return stmt_.ColumnBlobAsVector(col);
  }

 private:
  sql::Statement stmt_;
};

class SqlTransaction {
 public:
  explicit SqlTransaction(SqlDb& db) : tx_(db.raw()) {}
  bool Begin() { return tx_.Begin(); }
  bool Commit() { return tx_.Commit(); }

 private:
  sql::Transaction tx_;
};

#else  // defined(MOLE_STANDALONE_BUILD)

class SqlDb {
 public:
  SqlDb() = default;
  ~SqlDb() { Close(); }

  SqlDb(const SqlDb&) = delete;
  SqlDb& operator=(const SqlDb&) = delete;

  bool OpenDisk(const std::string& path);
  bool OpenMemory();
  void Close();
  bool is_open() const { return db_ != nullptr; }
  bool Execute(const char* sql);
  int64_t LastInsertRowId() const;
  sqlite3* raw() const { return db_; }

 private:
  sqlite3* db_ = nullptr;
};

class SqlStmt {
 public:
  SqlStmt(SqlDb& db, const char* sql);
  ~SqlStmt();

  SqlStmt(const SqlStmt&) = delete;
  SqlStmt& operator=(const SqlStmt&) = delete;

  bool is_valid() const { return stmt_ != nullptr; }

  void BindInt64(int idx, int64_t val);
  void BindString(int idx, std::string_view val);
  void BindBlob(int idx, ByteSpan data);

  bool Step();
  bool Run();

  int64_t ColumnInt64(int col);
  std::string ColumnString(int col);
  std::vector<uint8_t> ColumnBlob(int col);

 private:
  sqlite3_stmt* stmt_ = nullptr;
};

class SqlTransaction {
 public:
  explicit SqlTransaction(SqlDb& db) : db_(db) {}
  ~SqlTransaction() {
    if (active_) {
      db_.Execute("ROLLBACK;");
    }
  }

  bool Begin() {
    if (!db_.Execute("BEGIN IMMEDIATE;")) {
      return false;
    }
    active_ = true;
    return true;
  }

  bool Commit() {
    if (!active_) {
      return false;
    }
    active_ = false;
    return db_.Execute("COMMIT;");
  }

 private:
  SqlDb& db_;
  bool active_ = false;
};

#endif  // !defined(MOLE_STANDALONE_BUILD)

}  // namespace moderated_endorsements

#endif  // COMPONENTS_MODERATED_ENDORSEMENTS_MOLE_PLATFORM_H_
