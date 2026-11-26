// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/moderated_endorsements/moderated_endorsements_database.h"

#include <algorithm>
#include <array>
#include <utility>

namespace moderated_endorsements {

namespace {

constexpr char kHoldoutSeedMetaKey[] = "holdout_seed_v1";
constexpr std::array<uint8_t, 1> kPlaceholderBlob = {0};

std::string MakeRowAad(std::string_view table,
                       std::string_view origin,
                       int64_t id) {
  return "MOLE-DB-v1|" + std::string(table) + "|" + std::string(origin) + "|" +
         IntToDecimalString(id);
}

std::vector<uint8_t> PackIssueBundle(const std::vector<uint8_t>& request_body,
                                     const ZeroizingBytes& state_bundle) {
  std::vector<uint8_t> packed;
  const uint32_t req_len = static_cast<uint32_t>(request_body.size());
  packed.reserve(4 + request_body.size() + state_bundle.size());
  packed.push_back(static_cast<uint8_t>((req_len >> 24) & 0xff));
  packed.push_back(static_cast<uint8_t>((req_len >> 16) & 0xff));
  packed.push_back(static_cast<uint8_t>((req_len >> 8) & 0xff));
  packed.push_back(static_cast<uint8_t>(req_len & 0xff));
  packed.insert(packed.end(), request_body.begin(), request_body.end());
  const auto& sb = state_bundle.vec();
  packed.insert(packed.end(), sb.begin(), sb.end());
  return packed;
}

bool UnpackIssueBundle(const ZeroizingBytes& plain,
                       std::vector<uint8_t>* request_body_out,
                       ZeroizingBytes* state_bundle_out) {
  ByteSpan s = plain.span();
  if (s.size() < 4u) {
    return false;
  }
  ByteSpan hdr = s.first<4>();
  const size_t req_len = (static_cast<size_t>(hdr[0]) << 24) |
                         (static_cast<size_t>(hdr[1]) << 16) |
                         (static_cast<size_t>(hdr[2]) << 8) |
                         static_cast<size_t>(hdr[3]);
  if (s.size() - 4u < req_len) {
    return false;
  }
  ByteSpan body = s.subspan(4u, req_len);
  request_body_out->assign(body.begin(), body.end());
  *state_bundle_out = ZeroizingBytes(s.subspan(4u + req_len));
  return true;
}

}  // namespace

ModeratedEndorsementsDatabase::ModeratedEndorsementsDatabase(
    bool is_off_the_record,
    std::string db_file_path,
    const std::array<uint8_t, MoleAead::kKeyLength>& aead_key)
    : is_off_the_record_(is_off_the_record),
      db_file_path_(std::move(db_file_path)),
      aead_(aead_key) {}

ModeratedEndorsementsDatabase::~ModeratedEndorsementsDatabase() {
  Close();
}

bool ModeratedEndorsementsDatabase::Initialize() {
  const bool opened = is_off_the_record_ || db_file_path_.empty()
                          ? db_.OpenMemory()
                          : db_.OpenDisk(db_file_path_);
  if (!opened) {
    return false;
  }
  return CreateSchema();
}

void ModeratedEndorsementsDatabase::Close() {
  db_.Close();
}

bool ModeratedEndorsementsDatabase::CreateSchema() {
  SqlTransaction tx(db_);
  if (!tx.Begin()) {
    return false;
  }

  static constexpr const char* kDdlStatements[] = {
      "CREATE TABLE IF NOT EXISTS meta ("
      "key TEXT PRIMARY KEY NOT NULL,"
      "value BLOB NOT NULL)",

      "CREATE TABLE IF NOT EXISTS ec_ihat_endorsements ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "anchor_origin TEXT NOT NULL,"
      "anchor_key BLOB NOT NULL,"
      "issuance_epoch BLOB NOT NULL,"
      "state INTEGER NOT NULL,"
      "created_at_us INTEGER NOT NULL,"
      "encrypted_endorsement BLOB NOT NULL)",

      "CREATE INDEX IF NOT EXISTS idx_endorsements_anchor "
      "ON ec_ihat_endorsements(anchor_origin, state, id)",

      "CREATE TABLE IF NOT EXISTS ec_act_credentials ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "moderator_origin TEXT NOT NULL,"
      "credential_context BLOB NOT NULL,"
      "key_id BLOB NOT NULL,"
      "balance_width INTEGER NOT NULL,"
      "balance INTEGER NOT NULL,"
      "presentations_used INTEGER NOT NULL,"
      "state INTEGER NOT NULL,"
      "created_at_us INTEGER NOT NULL,"
      "last_used_at_us INTEGER NOT NULL,"
      "encrypted_credential BLOB NOT NULL)",

      "CREATE INDEX IF NOT EXISTS idx_credentials_moderator "
      "ON ec_act_credentials(moderator_origin, state, id)",

      "CREATE TABLE IF NOT EXISTS pending_spends ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "top_frame_site TEXT NOT NULL,"
      "moderator_origin TEXT NOT NULL,"
      "credential_context BLOB NOT NULL,"
      "key_id BLOB NOT NULL,"
      "balance_width INTEGER NOT NULL,"
      "presentations_used INTEGER NOT NULL DEFAULT 0,"
      "status INTEGER NOT NULL,"
      "hold_until_us INTEGER NOT NULL,"
      "session_handle TEXT NOT NULL,"
      "recovery_handle BLOB NOT NULL,"
      "settle_uri TEXT NOT NULL,"
      "is_split INTEGER NOT NULL,"
      "created_at_us INTEGER NOT NULL,"
      "encrypted_spend_bundle BLOB NOT NULL)",

      "CREATE INDEX IF NOT EXISTS idx_pending_spends_site_mod "
      "ON pending_spends(top_frame_site, moderator_origin)",

      "CREATE TABLE IF NOT EXISTS pending_issues ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "moderator_origin TEXT NOT NULL,"
      "policy_id TEXT NOT NULL,"
      "endorsement_id INTEGER NOT NULL,"
      "idempotency_key BLOB NOT NULL,"
      "issue_uri TEXT NOT NULL,"
      "wire_bytes_sent INTEGER NOT NULL,"
      "expires_at_us INTEGER NOT NULL,"
      "created_at_us INTEGER NOT NULL,"
      "encrypted_issue_bundle BLOB NOT NULL)",

      "CREATE TABLE IF NOT EXISTS site_moderator_associations ("
      "top_frame_site TEXT NOT NULL,"
      "moderator_origin TEXT NOT NULL,"
      "first_associated_at_us INTEGER NOT NULL,"
      "PRIMARY KEY(top_frame_site, moderator_origin))",

      "CREATE TABLE IF NOT EXISTS site_bootstrap_budget ("
      "top_frame_site TEXT PRIMARY KEY NOT NULL,"
      "last_bootstrap_at_us INTEGER NOT NULL)",
  };

  for (const char* ddl : kDdlStatements) {
    if (!db_.Execute(ddl)) {
      return false;
    }
  }
  return tx.Commit();
}

std::optional<std::array<uint8_t, 32>>
ModeratedEndorsementsDatabase::LoadOrCreateHoldoutSeed() {
  static constexpr std::string_view kSeedAad = "MOLE-DB-v1|meta|holdout_seed";
  {
    SqlStmt sel(db_, "SELECT value FROM meta WHERE key = ?");
    if (!sel.is_valid()) {
      return std::nullopt;
    }
    sel.BindString(0, kHoldoutSeedMetaKey);
    if (sel.Step()) {
      std::vector<uint8_t> sealed = sel.ColumnBlob(0);
      auto opened = aead_.Open(sealed, kSeedAad);
      if (opened && opened->size() == 32) {
        std::array<uint8_t, 32> seed{};
        std::ranges::copy(opened->span().first<32>(), seed.begin());
        return seed;
      }
    }
  }
  std::array<uint8_t, 32> fresh{};
  if (!RotateHoldoutSeed(&fresh)) {
    return std::nullopt;
  }
  return fresh;
}

bool ModeratedEndorsementsDatabase::RotateHoldoutSeed(
    std::array<uint8_t, 32>* new_seed_out) {
  static constexpr std::string_view kSeedAad = "MOLE-DB-v1|meta|holdout_seed";
  std::array<uint8_t, 32> seed{};
  if (!FillRandom(seed)) {
    return false;
  }
  auto sealed = aead_.Seal(seed, kSeedAad);
  if (!sealed) {
    OPENSSL_cleanse(seed.data(), seed.size());
    return false;
  }
  SqlStmt ins(db_, "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)");
  if (!ins.is_valid()) {
    OPENSSL_cleanse(seed.data(), seed.size());
    return false;
  }
  ins.BindString(0, kHoldoutSeedMetaKey);
  ins.BindBlob(1, *sealed);
  if (!ins.Run()) {
    OPENSSL_cleanse(seed.data(), seed.size());
    return false;
  }
  if (new_seed_out != nullptr) {
    *new_seed_out = seed;
  }
  OPENSSL_cleanse(seed.data(), seed.size());
  return true;
}

std::optional<int64_t> ModeratedEndorsementsDatabase::InsertEndorsement(
    const EndorsementRecord& record) {
  SqlTransaction tx(db_);
  if (!tx.Begin()) {
    return std::nullopt;
  }

  SqlStmt ins(db_,
              "INSERT INTO ec_ihat_endorsements("
              "anchor_origin, anchor_key, issuance_epoch, state, "
              "created_at_us, encrypted_endorsement) "
              "VALUES(?, ?, ?, ?, ?, ?)");
  if (!ins.is_valid()) {
    return std::nullopt;
  }
  ins.BindString(0, record.anchor_origin);
  ins.BindBlob(1, record.anchor_key);
  ins.BindBlob(2, record.issuance_epoch);
  ins.BindInt64(3, static_cast<int64_t>(record.state));
  ins.BindInt64(4, record.created_at_us);
  ins.BindBlob(5, kPlaceholderBlob);
  if (!ins.Run()) {
    return std::nullopt;
  }

  const int64_t row_id = db_.LastInsertRowId();
  const std::string aad =
      MakeRowAad("ec_ihat_endorsements", record.anchor_origin, row_id);
  auto sealed = aead_.Seal(record.endorsement_bytes.span(), aad);
  if (!sealed) {
    return std::nullopt;
  }

  SqlStmt upd(db_,
              "UPDATE ec_ihat_endorsements SET encrypted_endorsement = ? "
              "WHERE id = ?");
  if (!upd.is_valid()) {
    return std::nullopt;
  }
  upd.BindBlob(0, *sealed);
  upd.BindInt64(1, row_id);
  if (!upd.Run() || !tx.Commit()) {
    return std::nullopt;
  }
  return row_id;
}

bool ModeratedEndorsementsDatabase::UpdateEndorsementState(
    int64_t id,
    EndorsementRowState state) {
  SqlStmt stmt(db_, "UPDATE ec_ihat_endorsements SET state = ? WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, static_cast<int64_t>(state));
  stmt.BindInt64(1, id);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeleteEndorsement(int64_t id) {
  SqlStmt stmt(db_, "DELETE FROM ec_ihat_endorsements WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, id);
  return stmt.Run();
}

std::vector<EndorsementRecord>
ModeratedEndorsementsDatabase::LoadAllEndorsements() {
  std::vector<EndorsementRecord> out;
  std::vector<int64_t> corrupted_ids;
  {
    SqlStmt sel(db_,
                "SELECT id, anchor_origin, anchor_key, issuance_epoch, state, "
                "created_at_us, encrypted_endorsement "
                "FROM ec_ihat_endorsements ORDER BY id ASC");
    if (!sel.is_valid()) {
      return out;
    }
    while (sel.Step()) {
      EndorsementRecord rec;
      rec.id = sel.ColumnInt64(0);
      rec.anchor_origin = sel.ColumnString(1);
      rec.anchor_key = sel.ColumnBlob(2);
      rec.issuance_epoch = sel.ColumnBlob(3);
      rec.state = static_cast<EndorsementRowState>(sel.ColumnInt64(4));
      rec.created_at_us = sel.ColumnInt64(5);
      std::vector<uint8_t> sealed = sel.ColumnBlob(6);
      const std::string aad =
          MakeRowAad("ec_ihat_endorsements", rec.anchor_origin, rec.id);
      auto opened = aead_.Open(sealed, aad);
      if (!opened) {
        corrupted_ids.push_back(rec.id);
        continue;
      }
      rec.endorsement_bytes = std::move(*opened);
      out.push_back(std::move(rec));
    }
  }
  for (int64_t bad_id : corrupted_ids) {
    DeleteEndorsement(bad_id);
  }
  return out;
}

std::optional<int64_t> ModeratedEndorsementsDatabase::InsertCredential(
    const CredentialRecord& record) {
  SqlTransaction tx(db_);
  if (!tx.Begin()) {
    return std::nullopt;
  }

  SqlStmt ins(db_,
              "INSERT INTO ec_act_credentials("
              "moderator_origin, credential_context, key_id, balance_width, "
              "balance, presentations_used, state, created_at_us, "
              "last_used_at_us, encrypted_credential) "
              "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  if (!ins.is_valid()) {
    return std::nullopt;
  }
  ins.BindString(0, record.moderator_origin);
  ins.BindBlob(1, record.credential_context);
  ins.BindBlob(2, record.key_id);
  ins.BindInt64(3, record.balance_width);
  ins.BindInt64(4, static_cast<int64_t>(record.balance));
  ins.BindInt64(5, record.presentations_used);
  ins.BindInt64(6, static_cast<int64_t>(record.state));
  ins.BindInt64(7, record.created_at_us);
  ins.BindInt64(8, record.last_used_at_us);
  ins.BindBlob(9, kPlaceholderBlob);
  if (!ins.Run()) {
    return std::nullopt;
  }

  const int64_t row_id = db_.LastInsertRowId();
  const std::string aad =
      MakeRowAad("ec_act_credentials", record.moderator_origin, row_id);
  auto sealed = aead_.Seal(record.credential_bytes.span(), aad);
  if (!sealed) {
    return std::nullopt;
  }

  SqlStmt upd(db_,
              "UPDATE ec_act_credentials SET encrypted_credential = ? "
              "WHERE id = ?");
  if (!upd.is_valid()) {
    return std::nullopt;
  }
  upd.BindBlob(0, *sealed);
  upd.BindInt64(1, row_id);
  if (!upd.Run() || !tx.Commit()) {
    return std::nullopt;
  }
  return row_id;
}

bool ModeratedEndorsementsDatabase::UpdateCredentialState(
    int64_t id,
    CredentialRowState state,
    int64_t last_used_at_us) {
  SqlStmt stmt(db_,
                "UPDATE ec_act_credentials "
                "SET state = ?, last_used_at_us = ? WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, static_cast<int64_t>(state));
  stmt.BindInt64(1, last_used_at_us);
  stmt.BindInt64(2, id);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeleteCredential(int64_t id) {
  SqlStmt stmt(db_, "DELETE FROM ec_act_credentials WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, id);
  return stmt.Run();
}

std::vector<CredentialRecord>
ModeratedEndorsementsDatabase::LoadAllCredentials() {
  std::vector<CredentialRecord> out;
  std::vector<int64_t> corrupted_ids;
  {
    SqlStmt sel(db_,
                "SELECT id, moderator_origin, credential_context, key_id, "
                "balance_width, balance, presentations_used, state, "
                "created_at_us, last_used_at_us, encrypted_credential "
                "FROM ec_act_credentials ORDER BY id ASC");
    if (!sel.is_valid()) {
      return out;
    }
    while (sel.Step()) {
      CredentialRecord rec;
      rec.id = sel.ColumnInt64(0);
      rec.moderator_origin = sel.ColumnString(1);
      rec.credential_context = sel.ColumnBlob(2);
      rec.key_id = sel.ColumnBlob(3);
      rec.balance_width = static_cast<uint8_t>(sel.ColumnInt64(4));
      rec.balance = static_cast<uint64_t>(sel.ColumnInt64(5));
      rec.presentations_used = static_cast<uint32_t>(sel.ColumnInt64(6));
      rec.state = static_cast<CredentialRowState>(sel.ColumnInt64(7));
      rec.created_at_us = sel.ColumnInt64(8);
      rec.last_used_at_us = sel.ColumnInt64(9);
      std::vector<uint8_t> sealed = sel.ColumnBlob(10);
      const std::string aad =
          MakeRowAad("ec_act_credentials", rec.moderator_origin, rec.id);
      auto opened = aead_.Open(sealed, aad);
      if (!opened) {
        corrupted_ids.push_back(rec.id);
        continue;
      }
      rec.credential_bytes = std::move(*opened);
      out.push_back(std::move(rec));
    }
  }
  for (int64_t bad_id : corrupted_ids) {
    DeleteCredential(bad_id);
  }
  return out;
}

std::optional<int64_t> ModeratedEndorsementsDatabase::InsertPendingSpend(
    const PendingSpendRecord& record) {
  SqlTransaction tx(db_);
  if (!tx.Begin()) {
    return std::nullopt;
  }

  SqlStmt ins(db_,
              "INSERT INTO pending_spends("
              "top_frame_site, moderator_origin, credential_context, key_id, "
              "balance_width, presentations_used, status, hold_until_us, "
              "session_handle, recovery_handle, settle_uri, is_split, "
              "created_at_us, encrypted_spend_bundle) "
              "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  if (!ins.is_valid()) {
    return std::nullopt;
  }
  ins.BindString(0, record.top_frame_site);
  ins.BindString(1, record.moderator_origin);
  ins.BindBlob(2, record.credential_context);
  ins.BindBlob(3, record.key_id);
  ins.BindInt64(4, record.balance_width);
  ins.BindInt64(5, record.presentations_used);
  ins.BindInt64(6, static_cast<int64_t>(record.status));
  ins.BindInt64(7, record.hold_until_us);
  ins.BindString(8, record.session_handle);
  ins.BindBlob(9, record.recovery_handle);
  ins.BindString(10, record.settle_uri);
  ins.BindInt64(11, record.is_split ? 1 : 0);
  ins.BindInt64(12, record.created_at_us);
  ins.BindBlob(13, kPlaceholderBlob);
  if (!ins.Run()) {
    return std::nullopt;
  }

  const int64_t row_id = db_.LastInsertRowId();
  const std::string aad =
      MakeRowAad("pending_spends",
                 record.top_frame_site + "|" + record.moderator_origin, row_id);
  auto sealed = aead_.Seal(record.spend_bundle.span(), aad);
  if (!sealed) {
    return std::nullopt;
  }

  SqlStmt upd(db_,
              "UPDATE pending_spends SET encrypted_spend_bundle = ? "
              "WHERE id = ?");
  if (!upd.is_valid()) {
    return std::nullopt;
  }
  upd.BindBlob(0, *sealed);
  upd.BindInt64(1, row_id);
  if (!upd.Run() || !tx.Commit()) {
    return std::nullopt;
  }
  return row_id;
}

bool ModeratedEndorsementsDatabase::UpdatePendingSpendStatus(
    int64_t id,
    PendingSpendRowStatus status,
    int64_t hold_until_us,
    const std::string& session_handle) {
  SqlStmt stmt(db_,
               "UPDATE pending_spends "
               "SET status = ?, hold_until_us = ?, session_handle = ? "
               "WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, static_cast<int64_t>(status));
  stmt.BindInt64(1, hold_until_us);
  stmt.BindString(2, session_handle);
  stmt.BindInt64(3, id);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeletePendingSpend(int64_t id) {
  SqlStmt stmt(db_, "DELETE FROM pending_spends WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, id);
  return stmt.Run();
}

std::vector<PendingSpendRecord>
ModeratedEndorsementsDatabase::LoadAllPendingSpends() {
  std::vector<PendingSpendRecord> out;
  std::vector<int64_t> corrupted_ids;
  {
    SqlStmt sel(db_,
                "SELECT id, top_frame_site, moderator_origin, "
                "credential_context, key_id, balance_width, "
                "presentations_used, status, hold_until_us, session_handle, "
                "recovery_handle, settle_uri, is_split, created_at_us, "
                "encrypted_spend_bundle "
                "FROM pending_spends ORDER BY id ASC");
    if (!sel.is_valid()) {
      return out;
    }
    while (sel.Step()) {
      PendingSpendRecord rec;
      rec.id = sel.ColumnInt64(0);
      rec.top_frame_site = sel.ColumnString(1);
      rec.moderator_origin = sel.ColumnString(2);
      rec.credential_context = sel.ColumnBlob(3);
      rec.key_id = sel.ColumnBlob(4);
      rec.balance_width = static_cast<uint8_t>(sel.ColumnInt64(5));
      rec.presentations_used = static_cast<uint32_t>(sel.ColumnInt64(6));
      rec.status = static_cast<PendingSpendRowStatus>(sel.ColumnInt64(7));
      rec.hold_until_us = sel.ColumnInt64(8);
      rec.session_handle = sel.ColumnString(9);
      rec.recovery_handle = sel.ColumnBlob(10);
      rec.settle_uri = sel.ColumnString(11);
      rec.is_split = sel.ColumnInt64(12) != 0;
      rec.created_at_us = sel.ColumnInt64(13);
      std::vector<uint8_t> sealed = sel.ColumnBlob(14);
      const std::string aad = MakeRowAad(
          "pending_spends", rec.top_frame_site + "|" + rec.moderator_origin,
          rec.id);
      auto opened = aead_.Open(sealed, aad);
      if (!opened) {
        corrupted_ids.push_back(rec.id);
        continue;
      }
      rec.spend_bundle = std::move(*opened);
      out.push_back(std::move(rec));
    }
  }
  for (int64_t bad_id : corrupted_ids) {
    DeletePendingSpend(bad_id);
  }
  return out;
}

std::optional<int64_t> ModeratedEndorsementsDatabase::InsertPendingIssue(
    const PendingIssueRecord& record) {
  SqlTransaction tx(db_);
  if (!tx.Begin()) {
    return std::nullopt;
  }

  SqlStmt ins(db_,
              "INSERT INTO pending_issues("
              "moderator_origin, policy_id, endorsement_id, idempotency_key, "
              "issue_uri, wire_bytes_sent, expires_at_us, created_at_us, "
              "encrypted_issue_bundle) "
              "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)");
  if (!ins.is_valid()) {
    return std::nullopt;
  }
  ins.BindString(0, record.moderator_origin);
  ins.BindString(1, record.policy_id);
  ins.BindInt64(2, record.endorsement_id);
  ins.BindBlob(3, record.idempotency_key);
  ins.BindString(4, record.issue_uri);
  ins.BindInt64(5, record.wire_bytes_sent ? 1 : 0);
  ins.BindInt64(6, record.expires_at_us);
  ins.BindInt64(7, record.created_at_us);
  ins.BindBlob(8, kPlaceholderBlob);
  if (!ins.Run()) {
    return std::nullopt;
  }

  const int64_t row_id = db_.LastInsertRowId();
  std::vector<uint8_t> plain_packed =
      PackIssueBundle(record.request_body, record.issuance_state_bundle);
  const std::string aad =
      MakeRowAad("pending_issues", record.moderator_origin, row_id);
  auto sealed = aead_.Seal(plain_packed, aad);
  OPENSSL_cleanse(plain_packed.data(), plain_packed.size());
  if (!sealed) {
    return std::nullopt;
  }

  SqlStmt upd(db_,
              "UPDATE pending_issues SET encrypted_issue_bundle = ? "
              "WHERE id = ?");
  if (!upd.is_valid()) {
    return std::nullopt;
  }
  upd.BindBlob(0, *sealed);
  upd.BindInt64(1, row_id);
  if (!upd.Run() || !tx.Commit()) {
    return std::nullopt;
  }
  return row_id;
}

bool ModeratedEndorsementsDatabase::MarkPendingIssueWireSent(int64_t id) {
  SqlStmt stmt(db_,
               "UPDATE pending_issues SET wire_bytes_sent = 1 WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, id);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeletePendingIssue(int64_t id) {
  SqlStmt stmt(db_, "DELETE FROM pending_issues WHERE id = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, id);
  return stmt.Run();
}

std::vector<PendingIssueRecord>
ModeratedEndorsementsDatabase::LoadAllPendingIssues() {
  std::vector<PendingIssueRecord> out;
  std::vector<int64_t> corrupted_ids;
  {
    SqlStmt sel(db_,
                "SELECT id, moderator_origin, policy_id, endorsement_id, "
                "idempotency_key, issue_uri, wire_bytes_sent, expires_at_us, "
                "created_at_us, encrypted_issue_bundle "
                "FROM pending_issues ORDER BY id ASC");
    if (!sel.is_valid()) {
      return out;
    }
    while (sel.Step()) {
      PendingIssueRecord rec;
      rec.id = sel.ColumnInt64(0);
      rec.moderator_origin = sel.ColumnString(1);
      rec.policy_id = sel.ColumnString(2);
      rec.endorsement_id = sel.ColumnInt64(3);
      rec.idempotency_key = sel.ColumnBlob(4);
      rec.issue_uri = sel.ColumnString(5);
      rec.wire_bytes_sent = sel.ColumnInt64(6) != 0;
      rec.expires_at_us = sel.ColumnInt64(7);
      rec.created_at_us = sel.ColumnInt64(8);
      std::vector<uint8_t> sealed = sel.ColumnBlob(9);
      const std::string aad =
          MakeRowAad("pending_issues", rec.moderator_origin, rec.id);
      auto opened = aead_.Open(sealed, aad);
      if (!opened || !UnpackIssueBundle(*opened, &rec.request_body,
                                        &rec.issuance_state_bundle)) {
        corrupted_ids.push_back(rec.id);
        continue;
      }
      out.push_back(std::move(rec));
    }
  }
  for (int64_t bad_id : corrupted_ids) {
    DeletePendingIssue(bad_id);
  }
  return out;
}

bool ModeratedEndorsementsDatabase::UpsertSiteModeratorAssociation(
    const SiteModeratorAssociation& assoc) {
  SqlStmt stmt(db_,
               "INSERT OR IGNORE INTO site_moderator_associations("
               "top_frame_site, moderator_origin, first_associated_at_us) "
               "VALUES(?, ?, ?)");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindString(0, assoc.top_frame_site);
  stmt.BindString(1, assoc.moderator_origin);
  stmt.BindInt64(2, assoc.first_associated_at_us);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeleteSiteModeratorAssociationsBefore(
    int64_t cutoff_us) {
  SqlStmt stmt(db_,
               "DELETE FROM site_moderator_associations "
               "WHERE first_associated_at_us < ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindInt64(0, cutoff_us);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeleteSiteModeratorAssociation(
    const std::string& top_frame_site,
    const std::string& moderator_origin) {
  SqlStmt stmt(db_,
               "DELETE FROM site_moderator_associations "
               "WHERE top_frame_site = ? AND moderator_origin = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindString(0, top_frame_site);
  stmt.BindString(1, moderator_origin);
  return stmt.Run();
}

std::vector<SiteModeratorAssociation>
ModeratedEndorsementsDatabase::LoadAllSiteModeratorAssociations() {
  std::vector<SiteModeratorAssociation> out;
  SqlStmt sel(db_,
              "SELECT top_frame_site, moderator_origin, first_associated_at_us "
              "FROM site_moderator_associations");
  if (!sel.is_valid()) {
    return out;
  }
  while (sel.Step()) {
    SiteModeratorAssociation a;
    a.top_frame_site = sel.ColumnString(0);
    a.moderator_origin = sel.ColumnString(1);
    a.first_associated_at_us = sel.ColumnInt64(2);
    out.push_back(std::move(a));
  }
  return out;
}

bool ModeratedEndorsementsDatabase::UpsertSiteBootstrapBudget(
    const SiteBootstrapBudget& budget) {
  SqlStmt stmt(db_,
               "INSERT OR REPLACE INTO site_bootstrap_budget("
               "top_frame_site, last_bootstrap_at_us) "
               "VALUES(?, ?)");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindString(0, budget.top_frame_site);
  stmt.BindInt64(1, budget.last_bootstrap_at_us);
  return stmt.Run();
}

bool ModeratedEndorsementsDatabase::DeleteSiteBootstrapBudget(
    const std::string& top_frame_site) {
  SqlStmt stmt(db_,
               "DELETE FROM site_bootstrap_budget WHERE top_frame_site = ?");
  if (!stmt.is_valid()) {
    return false;
  }
  stmt.BindString(0, top_frame_site);
  return stmt.Run();
}

std::vector<SiteBootstrapBudget>
ModeratedEndorsementsDatabase::LoadAllSiteBootstrapBudgets() {
  std::vector<SiteBootstrapBudget> out;
  SqlStmt sel(db_,
              "SELECT top_frame_site, last_bootstrap_at_us "
              "FROM site_bootstrap_budget");
  if (!sel.is_valid()) {
    return out;
  }
  while (sel.Step()) {
    SiteBootstrapBudget b;
    b.top_frame_site = sel.ColumnString(0);
    b.last_bootstrap_at_us = sel.ColumnInt64(1);
    out.push_back(std::move(b));
  }
  return out;
}

}  // namespace moderated_endorsements
