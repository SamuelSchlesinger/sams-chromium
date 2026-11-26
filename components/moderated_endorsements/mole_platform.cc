// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/moderated_endorsements/mole_platform.h"

#if defined(MOLE_STANDALONE_BUILD)
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace moderated_endorsements {

ZeroizingBytes::ZeroizingBytes() = default;

ZeroizingBytes::ZeroizingBytes(std::vector<uint8_t> bytes)
    : bytes_(std::move(bytes)) {}

ZeroizingBytes::ZeroizingBytes(ByteSpan bytes)
    : bytes_(bytes.begin(), bytes.end()) {}

ZeroizingBytes::ZeroizingBytes(const ZeroizingBytes& other) = default;

ZeroizingBytes& ZeroizingBytes::operator=(const ZeroizingBytes& other) {
  if (this != &other) {
    Wipe();
    bytes_ = other.bytes_;
  }
  return *this;
}

ZeroizingBytes::ZeroizingBytes(ZeroizingBytes&& other) noexcept
    : bytes_(std::move(other.bytes_)) {}

ZeroizingBytes& ZeroizingBytes::operator=(ZeroizingBytes&& other) noexcept {
  if (this != &other) {
    Wipe();
    bytes_ = std::move(other.bytes_);
  }
  return *this;
}

ZeroizingBytes::~ZeroizingBytes() {
  Wipe();
}

void ZeroizingBytes::Wipe() {
  if (!bytes_.empty()) {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
    bytes_.clear();
  }
}

MoleAead::MoleAead() {
  std::array<uint8_t, kKeyLength> random_key{};
  RAND_bytes(random_key.data(), random_key.size());
  Init(random_key);
  OPENSSL_cleanse(random_key.data(), random_key.size());
}

MoleAead::MoleAead(const std::array<uint8_t, kKeyLength>& key) {
  Init(key);
}

MoleAead::~MoleAead() {
  if (initialized_) {
    EVP_AEAD_CTX_cleanup(&ctx_);
  }
}

void MoleAead::Init(const std::array<uint8_t, kKeyLength>& key) {
  EVP_AEAD_CTX_zero(&ctx_);
  initialized_ = EVP_AEAD_CTX_init(&ctx_, EVP_aead_aes_256_gcm(), key.data(),
                                   key.size(), kTagLength, nullptr) == 1;
}

std::optional<std::vector<uint8_t>> MoleAead::Seal(ByteSpan plaintext,
                                                   std::string_view aad) const {
  if (!initialized_) {
    return std::nullopt;
  }
  std::array<uint8_t, kNonceLength> nonce{};
  if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
    return std::nullopt;
  }
  std::vector<uint8_t> out(kNonceLength + plaintext.size() + kTagLength);
  MutableByteSpan out_span(out);
  std::ranges::copy(nonce, out_span.first<kNonceLength>().begin());
  MutableByteSpan ct_span = out_span.subspan(kNonceLength);
  size_t ciphertext_len = 0;
  if (EVP_AEAD_CTX_seal(
          &ctx_, ct_span.data(), &ciphertext_len, ct_span.size(), nonce.data(),
          nonce.size(), plaintext.data(), plaintext.size(),
          reinterpret_cast<const uint8_t*>(aad.data()), aad.size()) != 1) {
    return std::nullopt;
  }
  out.resize(kNonceLength + ciphertext_len);
  return out;
}

std::optional<ZeroizingBytes> MoleAead::Open(ByteSpan sealed,
                                             std::string_view aad) const {
  if (!initialized_ || sealed.size() < kNonceLength + kTagLength) {
    return std::nullopt;
  }
  ByteSpan nonce = sealed.first<kNonceLength>();
  ByteSpan ciphertext = sealed.subspan(kNonceLength);

  std::vector<uint8_t> plain(ciphertext.size() - kTagLength);
  size_t out_len = 0;
  if (EVP_AEAD_CTX_open(
          &ctx_, plain.data(), &out_len, plain.size(), nonce.data(),
          nonce.size(), ciphertext.data(), ciphertext.size(),
          reinterpret_cast<const uint8_t*>(aad.data()), aad.size()) != 1) {
    OPENSSL_cleanse(plain.data(), plain.size());
    return std::nullopt;
  }
  plain.resize(out_len);
  return ZeroizingBytes(std::move(plain));
}

std::array<uint8_t, 32> Sha256Digest(ByteSpan data) {
  std::array<uint8_t, 32> out{};
  SHA256(data.data(), data.size(), out.data());
  return out;
}

bool FillRandom(MutableByteSpan out) {
  return RAND_bytes(out.data(), out.size()) == 1;
}

#if defined(MOLE_STANDALONE_BUILD)

namespace {

constexpr bool IsAsciiDigit(char c) {
  return c >= '0' && c <= '9';
}

constexpr char ToAsciiLower(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool IsMultiLabelPublicSuffix(std::string_view two_labels) {
  static constexpr std::array<std::string_view, 8> kKnownTwoPartTlds = {
      "co.uk",  "org.uk", "ac.uk",  "gov.uk",
      "com.au", "net.au", "org.au", "co.jp",
  };
  return std::ranges::find(kKnownTwoPartTlds, two_labels) !=
         kKnownTwoPartTlds.end();
}

bool IsIpOrLocalhost(std::string_view host) {
  if (host == "localhost" || host.starts_with('[')) {
    return true;
  }
  bool all_digits_or_dots = !host.empty();
  for (char c : host) {
    if (!IsAsciiDigit(c) && c != '.') {
      all_digits_or_dots = false;
      break;
    }
  }
  return all_digits_or_dots;
}

std::optional<std::pair<std::string, uint16_t>> ParseHttpsHostPort(
    std::string_view raw) {
  constexpr std::string_view kScheme = "https://";
  if (raw.size() <= kScheme.size()) {
    return std::nullopt;
  }
  for (size_t i = 0; i < kScheme.size(); ++i) {
    if (ToAsciiLower(raw[i]) != kScheme[i]) {
      return std::nullopt;
    }
  }
  std::string_view rest = raw.substr(kScheme.size());
  size_t authority_end = rest.find_first_of("/?#");
  std::string_view authority = authority_end == std::string_view::npos
                                   ? rest
                                   : rest.substr(0, authority_end);
  if (authority.empty() || authority.find('@') != std::string_view::npos ||
      authority.find('\\') != std::string_view::npos) {
    return std::nullopt;
  }

  std::string host;
  uint16_t port = 443;
  if (authority.starts_with('[')) {
    size_t close = authority.find(']');
    if (close == std::string_view::npos) {
      return std::nullopt;
    }
    host.assign(authority.substr(0, close + 1));
    std::string_view after = authority.substr(close + 1);
    if (!after.empty()) {
      if (!after.starts_with(':') || after.size() == 1) {
        return std::nullopt;
      }
      int parsed_port = 0;
      for (char c : after.substr(1)) {
        if (!IsAsciiDigit(c)) {
          return std::nullopt;
        }
        parsed_port = parsed_port * 10 + (c - '0');
        if (parsed_port > 65535) {
          return std::nullopt;
        }
      }
      if (parsed_port == 0) {
        return std::nullopt;
      }
      port = static_cast<uint16_t>(parsed_port);
    }
  } else {
    size_t colon = authority.find(':');
    std::string_view host_part =
        colon == std::string_view::npos ? authority : authority.substr(0, colon);
    if (host_part.empty()) {
      return std::nullopt;
    }
    host.reserve(host_part.size());
    for (char c : host_part) {
      if (c <= 0x20 || c >= 0x7f) {
        return std::nullopt;
      }
      host.push_back(ToAsciiLower(c));
    }
    if (colon != std::string_view::npos) {
      std::string_view port_str = authority.substr(colon + 1);
      if (port_str.empty()) {
        return std::nullopt;
      }
      int parsed_port = 0;
      for (char c : port_str) {
        if (!IsAsciiDigit(c)) {
          return std::nullopt;
        }
        parsed_port = parsed_port * 10 + (c - '0');
        if (parsed_port > 65535) {
          return std::nullopt;
        }
      }
      if (parsed_port == 0) {
        return std::nullopt;
      }
      port = static_cast<uint16_t>(parsed_port);
    }
  }

  for (char& c : host) {
    c = ToAsciiLower(c);
  }
  return std::make_pair(std::move(host), port);
}

std::string RegistrableDomain(std::string_view host) {
  if (IsIpOrLocalhost(host)) {
    return std::string(host);
  }
  std::vector<std::string_view> labels;
  size_t start = 0;
  while (start <= host.size()) {
    size_t dot = host.find('.', start);
    if (dot == std::string_view::npos) {
      labels.push_back(host.substr(start));
      break;
    }
    labels.push_back(host.substr(start, dot - start));
    start = dot + 1;
  }
  if (labels.size() <= 2) {
    return std::string(host);
  }
  std::string last_two =
      std::string(labels[labels.size() - 2]) + "." + std::string(labels.back());
  if (IsMultiLabelPublicSuffix(last_two) && labels.size() >= 3) {
    return std::string(labels[labels.size() - 3]) + "." + last_two;
  }
  return last_two;
}

}  // namespace

std::string CanonicalHttpsOrigin(std::string_view raw) {
  auto parsed = ParseHttpsHostPort(raw);
  if (!parsed) {
    return std::string();
  }
  if (parsed->second == 443) {
    return "https://" + parsed->first;
  }
  return "https://" + parsed->first + ":" +
         UintToDecimalString(parsed->second);
}

std::string CanonicalSchemefulSite(std::string_view raw) {
  auto parsed = ParseHttpsHostPort(raw);
  if (!parsed) {
    return std::string();
  }
  return "https://" + RegistrableDomain(parsed->first);
}

std::string ExtractRegistrableDomainOrHost(std::string_view raw) {
  auto parsed = ParseHttpsHostPort(raw);
  if (!parsed) {
    return std::string();
  }
  return RegistrableDomain(parsed->first);
}

std::string CreateStandaloneTempDir() {
  const char* env_tmp = getenv("TMPDIR");
  std::string base_dir = (env_tmp && env_tmp[0] != '\0') ? env_tmp : "/tmp";
  std::string tmpl = base_dir + "/mole_test_XXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  if (mkdtemp(buf.data()) == nullptr) {
    return std::string();
  }
  return std::string(buf.data());
}

void RemoveStandaloneTempDir(const std::string& dir_path) {
  if (dir_path.empty()) {
    return;
  }
  DIR* d = opendir(dir_path.c_str());
  if (d != nullptr) {
    while (struct dirent* ent = readdir(d)) {
      std::string_view name(ent->d_name);
      if (name == "." || name == "..") {
        continue;
      }
      std::string child = dir_path + "/" + std::string(name);
      unlink(child.c_str());
    }
    closedir(d);
  }
  rmdir(dir_path.c_str());
}

std::vector<uint8_t> ReadStandaloneFileBytes(const std::string& path) {
  FILE* f = fopen(path.c_str(), "rb");
  if (f == nullptr) {
    return {};
  }
  std::vector<uint8_t> out;
  int ch = 0;
  while ((ch = fgetc(f)) != EOF) {
    out.push_back(static_cast<uint8_t>(ch));
  }
  fclose(f);
  return out;
}

bool StandalonePathExists(const std::string& path) {
  struct stat st{};
  return stat(path.c_str(), &st) == 0;
}

bool SqlDb::OpenDisk(const std::string& path) {
  Close();
  if (sqlite3_open_v2(path.c_str(), &db_,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                          SQLITE_OPEN_FULLMUTEX,
                      nullptr) != SQLITE_OK) {
    Close();
    return false;
  }
  return Execute("PRAGMA journal_mode=WAL;") &&
         Execute("PRAGMA synchronous=NORMAL;") &&
         Execute("PRAGMA foreign_keys=ON;");
}

bool SqlDb::OpenMemory() {
  Close();
  if (sqlite3_open_v2(":memory:", &db_,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                          SQLITE_OPEN_MEMORY | SQLITE_OPEN_FULLMUTEX,
                      nullptr) != SQLITE_OK) {
    Close();
    return false;
  }
  return Execute("PRAGMA foreign_keys=ON;");
}

void SqlDb::Close() {
  if (db_ != nullptr) {
    sqlite3_close_v2(db_);
    db_ = nullptr;
  }
}

bool SqlDb::Execute(const char* sql) {
  if (db_ == nullptr) {
    return false;
  }
  char* errmsg = nullptr;
  int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
  if (errmsg != nullptr) {
    sqlite3_free(errmsg);
  }
  return rc == SQLITE_OK;
}

int64_t SqlDb::LastInsertRowId() const {
  return db_ != nullptr ? sqlite3_last_insert_rowid(db_) : 0;
}

SqlStmt::SqlStmt(SqlDb& db, const char* sql) {
  if (db.raw() != nullptr) {
    if (sqlite3_prepare_v2(db.raw(), sql, -1, &stmt_, nullptr) != SQLITE_OK) {
      if (stmt_ != nullptr) {
        sqlite3_finalize(stmt_);
        stmt_ = nullptr;
      }
    }
  }
}

SqlStmt::~SqlStmt() {
  if (stmt_ != nullptr) {
    sqlite3_finalize(stmt_);
  }
}

void SqlStmt::BindInt64(int idx, int64_t val) {
  if (stmt_ != nullptr) {
    sqlite3_bind_int64(stmt_, idx + 1, val);
  }
}

void SqlStmt::BindString(int idx, std::string_view val) {
  if (stmt_ != nullptr) {
    sqlite3_bind_text(stmt_, idx + 1, val.empty() ? "" : val.data(),
                      static_cast<int>(val.size()), SQLITE_TRANSIENT);
  }
}

void SqlStmt::BindBlob(int idx, ByteSpan data) {
  if (stmt_ != nullptr) {
    static const uint8_t kEmptyByte = 0;
    sqlite3_bind_blob(stmt_, idx + 1, data.empty() ? &kEmptyByte : data.data(),
                      static_cast<int>(data.size()), SQLITE_TRANSIENT);
  }
}

bool SqlStmt::Step() {
  if (stmt_ == nullptr) {
    return false;
  }
  return sqlite3_step(stmt_) == SQLITE_ROW;
}

bool SqlStmt::Run() {
  if (stmt_ == nullptr) {
    return false;
  }
  int rc = sqlite3_step(stmt_);
  return rc == SQLITE_DONE || rc == SQLITE_ROW;
}

int64_t SqlStmt::ColumnInt64(int col) {
  return stmt_ != nullptr ? sqlite3_column_int64(stmt_, col) : 0;
}

std::string SqlStmt::ColumnString(int col) {
  if (stmt_ == nullptr) {
    return std::string();
  }
  const unsigned char* txt = sqlite3_column_text(stmt_, col);
  int len = sqlite3_column_bytes(stmt_, col);
  if (txt == nullptr || len <= 0) {
    return std::string();
  }
  return std::string(reinterpret_cast<const char*>(txt),
                     static_cast<size_t>(len));
}

std::vector<uint8_t> SqlStmt::ColumnBlob(int col) {
  if (stmt_ == nullptr) {
    return {};
  }
  const void* ptr = sqlite3_column_blob(stmt_, col);
  int len = sqlite3_column_bytes(stmt_, col);
  if (ptr == nullptr || len <= 0) {
    return {};
  }
  std::vector<uint8_t> out(static_cast<size_t>(len));
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
  const auto* src = static_cast<const uint8_t*>(ptr);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = src[i];
  }
#pragma clang diagnostic pop
  return out;
}

#endif  // defined(MOLE_STANDALONE_BUILD)

}  // namespace moderated_endorsements
