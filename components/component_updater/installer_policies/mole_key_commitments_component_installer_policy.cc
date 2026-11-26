// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/component_updater/installer_policies/mole_key_commitments_component_installer_policy.h"

#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/task/thread_pool.h"
#include "base/values.h"
#include "base/version.h"
#include "components/component_updater/component_updater_switches.h"

namespace {

// Placeholder SHA-256 of the SubjectPublicKeyInfo signing the component CRX.
// Until published, no remote component matches and the registry remains
// fail-closed unless overridden in tests/demos.
constexpr std::array<uint8_t, 32> kMoleKeyCommitmentsPublicKeySHA256 = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

const char kMoleKeyCommitmentsManifestName[] = "MoLE Key Commitments";

std::optional<std::string> LoadCommitmentsFromDisk(const base::FilePath& path) {
  if (path.empty()) {
    return std::nullopt;
  }
  std::string ret;
  if (!base::ReadFileToString(path, &ret)) {
    return std::nullopt;
  }
  return ret;
}

}  // namespace

namespace component_updater {

MoleKeyCommitmentsComponentInstallerPolicy::
    MoleKeyCommitmentsComponentInstallerPolicy(
        base::RepeatingCallback<void(const std::string&)> on_commitments_ready)
    : on_commitments_ready_(std::move(on_commitments_ready)) {}

MoleKeyCommitmentsComponentInstallerPolicy::
    ~MoleKeyCommitmentsComponentInstallerPolicy() = default;

bool MoleKeyCommitmentsComponentInstallerPolicy::
    SupportsGroupPolicyEnabledComponentUpdates() const {
  return true;
}

bool MoleKeyCommitmentsComponentInstallerPolicy::RequiresNetworkEncryption()
    const {
  return false;
}

update_client::CrxInstaller::Result
MoleKeyCommitmentsComponentInstallerPolicy::OnCustomInstall(
    const base::DictValue& manifest,
    const base::FilePath& install_dir) {
  return update_client::CrxInstaller::Result(0);
}

void MoleKeyCommitmentsComponentInstallerPolicy::OnCustomUninstall() {}

// static
base::FilePath MoleKeyCommitmentsComponentInstallerPolicy::GetInstalledPath(
    const base::FilePath& base) {
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kComponentUpdaterMoleKeyCommitmentsPath)) {
    return base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
        switches::kComponentUpdaterMoleKeyCommitmentsPath);
  }
  return base.Append(kMoleKeyCommitmentsFileName);
}

void MoleKeyCommitmentsComponentInstallerPolicy::ComponentReady(
    const base::Version& version,
    const base::FilePath& install_dir,
    base::DictValue manifest) {
  LoadCommitmentsFromString(
      base::BindOnce(&LoadCommitmentsFromDisk, GetInstalledPath(install_dir)),
      on_commitments_ready_);
}

bool MoleKeyCommitmentsComponentInstallerPolicy::VerifyInstallation(
    const base::DictValue& manifest,
    const base::FilePath& install_dir) const {
  return base::PathExists(GetInstalledPath(install_dir));
}

base::FilePath
MoleKeyCommitmentsComponentInstallerPolicy::GetRelativeInstallDir() const {
  return base::FilePath(FILE_PATH_LITERAL("MoleKeyCommitments"));
}

void MoleKeyCommitmentsComponentInstallerPolicy::GetHash(
    std::vector<uint8_t>* hash) const {
  GetPublicKeyHash(hash);
}

std::string MoleKeyCommitmentsComponentInstallerPolicy::GetName() const {
  return kMoleKeyCommitmentsManifestName;
}

update_client::InstallerAttributes
MoleKeyCommitmentsComponentInstallerPolicy::GetInstallerAttributes() const {
  return update_client::InstallerAttributes();
}

// static
void MoleKeyCommitmentsComponentInstallerPolicy::GetPublicKeyHash(
    std::vector<uint8_t>* hash) {
  DCHECK(hash);
  hash->assign_range(kMoleKeyCommitmentsPublicKeySHA256);
}

// static
void MoleKeyCommitmentsComponentInstallerPolicy::LoadCommitmentsFromString(
    base::OnceCallback<std::optional<std::string>()> load_from_disk,
    base::OnceCallback<void(const std::string&)> on_commitments_ready) {
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::BEST_EFFORT},
      std::move(load_from_disk),
      base::BindOnce(
          [](base::OnceCallback<void(const std::string&)> on_commitments_ready,
             std::optional<std::string> loaded) {
            if (loaded.has_value()) {
              std::move(on_commitments_ready).Run(loaded.value());
            }
          },
          std::move(on_commitments_ready)));
}

}  // namespace component_updater
