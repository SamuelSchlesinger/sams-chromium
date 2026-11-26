// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_COMPONENT_UPDATER_INSTALLER_POLICIES_MOLE_KEY_COMMITMENTS_COMPONENT_INSTALLER_POLICY_H_
#define COMPONENTS_COMPONENT_UPDATER_INSTALLER_POLICIES_MOLE_KEY_COMMITMENTS_COMPONENT_INSTALLER_POLICY_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/functional/callback.h"
#include "base/values.h"
#include "components/component_updater/component_installer.h"

namespace component_updater {

inline constexpr base::FilePath::CharType kMoleKeyCommitmentsFileName[] =
    FILE_PATH_LITERAL("commitments.json");

// Delivers signed, anti-split-view Moderated Endorsements (MOLE) Anchor and
// Moderator key commitments from Component Updater to `content::SetMoleKeyCommitments`.
class MoleKeyCommitmentsComponentInstallerPolicy
    : public ComponentInstallerPolicy {
 public:
  explicit MoleKeyCommitmentsComponentInstallerPolicy(
      base::RepeatingCallback<void(const std::string&)> on_commitments_ready);
  ~MoleKeyCommitmentsComponentInstallerPolicy() override;

  MoleKeyCommitmentsComponentInstallerPolicy(
      const MoleKeyCommitmentsComponentInstallerPolicy&) = delete;
  MoleKeyCommitmentsComponentInstallerPolicy& operator=(
      const MoleKeyCommitmentsComponentInstallerPolicy&) = delete;

  static void GetPublicKeyHash(std::vector<uint8_t>* hash);

  static void LoadCommitmentsFromString(
      base::OnceCallback<std::optional<std::string>()> load_from_disk,
      base::OnceCallback<void(const std::string&)> on_commitments_ready);

 private:
  // ComponentInstallerPolicy:
  bool SupportsGroupPolicyEnabledComponentUpdates() const override;
  bool RequiresNetworkEncryption() const override;
  update_client::CrxInstaller::Result OnCustomInstall(
      const base::DictValue& manifest,
      const base::FilePath& install_dir) override;
  void OnCustomUninstall() override;
  bool VerifyInstallation(const base::DictValue& manifest,
                          const base::FilePath& install_dir) const override;
  void ComponentReady(const base::Version& version,
                      const base::FilePath& install_dir,
                      base::DictValue manifest) override;
  base::FilePath GetRelativeInstallDir() const override;
  void GetHash(std::vector<uint8_t>* hash) const override;
  std::string GetName() const override;
  update_client::InstallerAttributes GetInstallerAttributes() const override;

  static base::FilePath GetInstalledPath(const base::FilePath& base);

  base::RepeatingCallback<void(const std::string&)> on_commitments_ready_;
};

}  // namespace component_updater

#endif  // COMPONENTS_COMPONENT_UPDATER_INSTALLER_POLICIES_MOLE_KEY_COMMITMENTS_COMPONENT_INSTALLER_POLICY_H_
