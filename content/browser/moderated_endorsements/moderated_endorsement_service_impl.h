// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_
#define CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_

#include <optional>
#include <string>

#include "base/memory/self_deleting.h"
#include "content/public/browser/document_service.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "third_party/blink/public/mojom/moderated_endorsements/moderated_endorsements.mojom.h"
#include "url/origin.h"

namespace content {

class ModeratedEndorsementsManager;

// Document-scoped Browser Process service backing `navigator.endorsement`.
// Enforces primary main frame, non-fenced-frame, active lifecycle state (never
// prerender or BFCache), `PermissionsPolicyFeature::kModeratedEndorsements`,
// non-opaque HTTPS origin, and user-activation / 24h bootstrap gating before
// delegating to the `StoragePartition`'s `ModeratedEndorsementsManager`.
class ModeratedEndorsementServiceImpl final
    : public DocumentService<blink::mojom::ModeratedEndorsementService> {
 public:
  static void Create(
      RenderFrameHost* render_frame_host,
      mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService>
          receiver);

  ModeratedEndorsementServiceImpl(
      RenderFrameHost& render_frame_host,
      mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver,
      base::SelfDeletingPassKey key);

  ModeratedEndorsementServiceImpl(const ModeratedEndorsementServiceImpl&) =
      delete;
  ModeratedEndorsementServiceImpl& operator=(
      const ModeratedEndorsementServiceImpl&) = delete;

  // blink::mojom::ModeratedEndorsementService:
  void Endorse(const std::optional<std::string>& authorization,
               EndorseCallback callback) final;
  void Settle(const std::optional<url::Origin>& moderator,
              SettleCallback callback) final;

 private:
  ~ModeratedEndorsementServiceImpl() override;

  ModeratedEndorsementsManager* GetManagerIfAllowed();

  url::Origin registered_origin_;
  bool registered_with_manager_ = false;
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENT_SERVICE_IMPL_H_
