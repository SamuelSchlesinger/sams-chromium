// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/moderated_endorsements/moderated_endorsement_service_impl.h"

#include <utility>

#include "base/strings/string_util.h"
#include "content/browser/moderated_endorsements/moderated_endorsements_manager.h"
#include "content/browser/storage_partition_impl.h"
#include "content/public/browser/render_frame_host.h"
#include "net/http/http_util.h"
#include "services/network/public/cpp/header_util.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "services/network/public/mojom/permissions_policy/permissions_policy_feature.mojom.h"

namespace content {

// static
void ModeratedEndorsementServiceImpl::Create(
    RenderFrameHost* render_frame_host,
    mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver) {
  CHECK(render_frame_host);
  base::MakeSelfDeleting<ModeratedEndorsementServiceImpl>(*render_frame_host,
                                                          std::move(receiver));
}

ModeratedEndorsementServiceImpl::ModeratedEndorsementServiceImpl(
    RenderFrameHost& render_frame_host,
    mojo::PendingReceiver<blink::mojom::ModeratedEndorsementService> receiver,
    base::SelfDeletingPassKey key)
    : DocumentService(render_frame_host, std::move(receiver), key),
      registered_origin_(render_frame_host.GetLastCommittedOrigin()) {
  if (auto* mgr = GetManagerIfAllowed()) {
    mgr->OnTopLevelDocumentActivated(registered_origin_);
    registered_with_manager_ = true;
  }
}

ModeratedEndorsementServiceImpl::~ModeratedEndorsementServiceImpl() {
  if (registered_with_manager_) {
    auto* partition = static_cast<StoragePartitionImpl*>(
        render_frame_host().GetStoragePartition());
    if (partition && partition->GetModeratedEndorsementsManager()) {
      partition->GetModeratedEndorsementsManager()->OnTopLevelDocumentDestroyed(
          registered_origin_);
    }
  }
}

ModeratedEndorsementsManager*
ModeratedEndorsementServiceImpl::GetManagerIfAllowed() {
  RenderFrameHost& rfh = render_frame_host();
  if (!rfh.IsInPrimaryMainFrame() || rfh.IsInFencedFrameTree() ||
      rfh.GetLifecycleState() != RenderFrameHost::LifecycleState::kActive ||
      !rfh.IsFeatureEnabled(
          network::mojom::PermissionsPolicyFeature::kModeratedEndorsements)) {
    return nullptr;
  }

  const url::Origin& origin = rfh.GetLastCommittedOrigin();
  if (origin.opaque() || origin.scheme() != "https" ||
      !network::IsOriginPotentiallyTrustworthy(origin)) {
    return nullptr;
  }

  auto* partition =
      static_cast<StoragePartitionImpl*>(rfh.GetStoragePartition());
  return partition ? partition->GetModeratedEndorsementsManager() : nullptr;
}

void ModeratedEndorsementServiceImpl::Endorse(
    const std::optional<std::string>& authorization,
    EndorseCallback callback) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (authorization.has_value() &&
      (authorization->size() > 4096 || !base::IsStringUTF8(*authorization) ||
       !net::HttpUtil::IsValidHeaderValue(*authorization) ||
       network::IsMoleAuthorizationHeaderValue(*authorization))) {
    std::move(callback).Run(Status::kInvalidArgument);
    return;
  }

  auto* mgr = GetManagerIfAllowed();
  if (!mgr) {
    std::move(callback).Run(Status::kNotAllowed);
    return;
  }

  const bool had_user_activation =
      render_frame_host().ConsumeTransientUserActivation();
  mgr->Endorse(render_frame_host().GetLastCommittedOrigin(),
               had_user_activation, authorization, std::move(callback));
}

void ModeratedEndorsementServiceImpl::Settle(
    const std::optional<url::Origin>& moderator,
    SettleCallback callback) {
  using Status = blink::mojom::ModeratedEndorsementStatus;
  if (moderator.has_value() &&
      (moderator->opaque() || moderator->scheme() != "https" ||
       !network::IsOriginPotentiallyTrustworthy(*moderator))) {
    std::move(callback).Run(Status::kInvalidArgument);
    return;
  }

  auto* mgr = GetManagerIfAllowed();
  if (!mgr) {
    std::move(callback).Run(Status::kNotAllowed);
    return;
  }

  mgr->Settle(render_frame_host().GetLastCommittedOrigin(), moderator,
              std::move(callback));
}

}  // namespace content
