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

// Must stay in sync with the server-side component configuration.
inline constexpr base::FilePath::CharType kMoleKeyCommitmentsFileName[] =
    FILE_PATH_LITERAL("commitments.json");

// Receives updated MoLE (Moderation of unLinkable Endorsements) key
// commitments from the component updater and hands the raw JSON to a consumer
// callback. Directly parallels TrustTokenKeyCommitmentsComponentInstallerPolicy
// — same shape, same "delivered identically to every browser so a server
// cannot split-view its keys" rationale — except MoLE's consumer lives in the
// browser process (content::SetMoleKeyCommitments) rather than the network
// service, so the callback is a plain C++ call, not a Mojo method.
class MoleKeyCommitmentsComponentInstallerPolicy
    : public ComponentInstallerPolicy {
 public:
  // `on_commitments_ready` runs on the UI thread when new commitments load.
  explicit MoleKeyCommitmentsComponentInstallerPolicy(
      base::RepeatingCallback<void(const std::string&)> on_commitments_ready);
  ~MoleKeyCommitmentsComponentInstallerPolicy() override;

  MoleKeyCommitmentsComponentInstallerPolicy(
      const MoleKeyCommitmentsComponentInstallerPolicy&) = delete;
  MoleKeyCommitmentsComponentInstallerPolicy& operator=(
      const MoleKeyCommitmentsComponentInstallerPolicy&) = delete;

  // The component's SHA256 public-key hash as raw bytes.
  static void GetPublicKeyHash(std::vector<uint8_t>* hash);

  // Reads the file via `load_from_disk` on a background sequence and, on
  // success, runs `on_commitments_ready` on the calling sequence. Static so an
  // Android ComponentLoaderPolicy could share it, matching the PST seam.
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

  // The installed file, honoring the testing path-override switch.
  static base::FilePath GetInstalledPath(const base::FilePath& base);

  base::RepeatingCallback<void(const std::string&)> on_commitments_ready_;
};

}  // namespace component_updater

#endif  // COMPONENTS_COMPONENT_UPDATER_INSTALLER_POLICIES_MOLE_KEY_COMMITMENTS_COMPONENT_INSTALLER_POLICY_H_
