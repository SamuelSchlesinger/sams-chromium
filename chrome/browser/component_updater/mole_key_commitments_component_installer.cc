// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/component_updater/mole_key_commitments_component_installer.h"

#include <memory>
#include <string>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "components/component_updater/installer_policies/mole_key_commitments_component_installer_policy.h"
#include "content/public/browser/mole_key_commitments.h"

namespace component_updater {

void RegisterMoleKeyCommitmentsComponent(ComponentUpdateService* cus) {
  VLOG(1) << "Registering MoLE Key Commitments component.";
  auto installer = base::MakeRefCounted<ComponentInstaller>(
      std::make_unique<MoleKeyCommitmentsComponentInstallerPolicy>(
          // MoLE's consumer is a browser-process content-layer singleton, not
          // the network service, so this is a direct call rather than a Mojo
          // method. ComponentReady delivers on the UI thread already.
          /*on_commitments_ready=*/base::BindRepeating(
              [](const std::string& raw_commitments) {
                content::SetMoleKeyCommitments(raw_commitments);
              })));

  installer->Register(cus, base::OnceClosure());
}

}  // namespace component_updater
