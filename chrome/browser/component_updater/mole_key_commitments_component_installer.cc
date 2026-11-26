// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/component_updater/mole_key_commitments_component_installer.h"

#include <memory>
#include <string>

#include "base/functional/bind.h"
#include "components/component_updater/installer_policies/mole_key_commitments_component_installer_policy.h"
#include "content/public/browser/mole_key_commitments.h"

namespace component_updater {

void RegisterMoleKeyCommitmentsComponent(ComponentUpdateService* cus) {
  auto installer = base::MakeRefCounted<ComponentInstaller>(
      std::make_unique<MoleKeyCommitmentsComponentInstallerPolicy>(
          base::BindRepeating([](const std::string& raw_commitments) {
            content::SetMoleKeyCommitments(raw_commitments);
          })));
  installer->Register(cus, base::OnceClosure());
}

}  // namespace component_updater
