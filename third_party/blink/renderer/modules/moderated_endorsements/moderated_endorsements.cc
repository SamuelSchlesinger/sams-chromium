// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/moderated_endorsements/moderated_endorsements.h"

#include "services/network/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_endorse_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_settle_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

bool IsMoleAuthorizationSchemeInBlink(const String& raw) {
  unsigned start = 0;
  unsigned end = raw.length();
  while (start < end && (raw[start] == ' ' || raw[start] == '\t')) {
    ++start;
  }
  while (end > start && (raw[end - 1] == ' ' || raw[end - 1] == '\t')) {
    --end;
  }
  if (end - start < 4) {
    return false;
  }
  auto to_lower_ascii = [](UChar c) -> UChar {
    return (c >= 'A' && c <= 'Z') ? static_cast<UChar>(c + ('a' - 'A')) : c;
  };
  if (to_lower_ascii(raw[start]) != 'm' ||
      to_lower_ascii(raw[start + 1]) != 'o' ||
      to_lower_ascii(raw[start + 2]) != 'l' ||
      to_lower_ascii(raw[start + 3]) != 'e') {
    return false;
  }
  if (end - start == 4) {
    return true;
  }
  UChar next = raw[start + 4];
  return next == ' ' || next == '\t';
}

}  // namespace

// static
const char ModeratedEndorsements::kSupplementName[] = "ModeratedEndorsements";

// static
ModeratedEndorsements* ModeratedEndorsements::endorsement(
    NavigatorBase& navigator) {
  auto* supplement =
      Supplement<NavigatorBase>::From<ModeratedEndorsements>(navigator);
  if (!supplement && navigator.GetExecutionContext()) {
    supplement = MakeGarbageCollected<ModeratedEndorsements>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

ModeratedEndorsements::ModeratedEndorsements(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      service_(navigator.GetExecutionContext()) {}

mojom::blink::ModeratedEndorsementService* ModeratedEndorsements::GetService() {
  if (!service_.is_bound()) {
    auto* context = GetSupplementable()->GetExecutionContext();
    context->GetBrowserInterfaceBroker().GetInterface(
        service_.BindNewPipeAndPassReceiver(
            context->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    service_.set_disconnect_handler(
        BindOnce(&ModeratedEndorsements::OnServiceDisconnected,
                 WrapWeakPersistent(this)));
  }
  return service_.get();
}

ScriptPromise<IDLUndefined> ModeratedEndorsements::endorse(
    ScriptState* script_state,
    const EndorseOptions* options,
    ExceptionState& exception_state) {
  auto* context = GetSupplementable()->GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The context is detached");
    return EmptyPromise();
  }
  if (!context->IsFeatureEnabled(
          network::mojom::blink::PermissionsPolicyFeature::
              kModeratedEndorsements)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "The 'moderated-endorsements' Permissions Policy is disabled in this "
        "context");
    return EmptyPromise();
  }

  String authorization;
  if (options && options->hasAuthorization()) {
    if (options->authorization().length() > 4096) {
      exception_state.ThrowTypeError(
          "endorse: authorization exceeds maximum length (4096 bytes)");
      return EmptyPromise();
    }
    if (!IsValidHTTPHeaderValue(options->authorization()) ||
        IsMoleAuthorizationSchemeInBlink(options->authorization())) {
      exception_state.ThrowTypeError(
          "endorse: authorization must be a valid non-Mole HTTP Authorization "
          "header value");
      return EmptyPromise();
    }
    authorization = options->authorization();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  pending_resolvers_.insert(resolver);
  GetService()->Endorse(
      authorization,
      BindOnce(&ModeratedEndorsements::OnOperationComplete,
               WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> ModeratedEndorsements::settle(
    ScriptState* script_state,
    const SettleOptions* options,
    ExceptionState& exception_state) {
  auto* context = GetSupplementable()->GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The context is detached");
    return EmptyPromise();
  }
  if (!context->IsFeatureEnabled(
          network::mojom::blink::PermissionsPolicyFeature::
              kModeratedEndorsements)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "The 'moderated-endorsements' Permissions Policy is disabled in this "
        "context");
    return EmptyPromise();
  }

  scoped_refptr<const SecurityOrigin> moderator_origin;
  if (options && options->hasModerator()) {
    KURL mod_url(options->moderator());
    moderator_origin = SecurityOrigin::Create(mod_url);
    if (!mod_url.IsValid() || !mod_url.ProtocolIsInHttpFamily() ||
        !moderator_origin || moderator_origin->IsOpaque() ||
        !moderator_origin->IsPotentiallyTrustworthy()) {
      exception_state.ThrowTypeError(
          "settle: moderator must be a valid potentially trustworthy HTTPS "
          "URL");
      return EmptyPromise();
    }
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  pending_resolvers_.insert(resolver);
  GetService()->Settle(
      std::move(moderator_origin),
      BindOnce(&ModeratedEndorsements::OnOperationComplete,
               WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

void ModeratedEndorsements::OnOperationComplete(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::ModeratedEndorsementStatus status) {
  pending_resolvers_.erase(resolver);
  switch (status) {
    case mojom::blink::ModeratedEndorsementStatus::kOk:
      resolver->Resolve();
      return;
    case mojom::blink::ModeratedEndorsementStatus::kInvalidArgument:
      resolver->RejectWithTypeError("Invalid Moderated Endorsement request");
      return;
    case mojom::blink::ModeratedEndorsementStatus::kNotAllowed:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kNotAllowedError,
          "The Moderated Endorsement operation was not permitted");
      return;
    case mojom::blink::ModeratedEndorsementStatus::kNetworkError:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kNetworkError,
          "The Moderated Endorsement network exchange failed");
      return;
  }
}

void ModeratedEndorsements::OnServiceDisconnected() {
  HeapHashSet<Member<ScriptPromiseResolverBase>> resolvers =
      std::move(pending_resolvers_);
  pending_resolvers_.clear();
  for (auto& resolver : resolvers) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kNetworkError,
        "The endorsement service was disconnected");
  }
}

void ModeratedEndorsements::Trace(Visitor* visitor) const {
  visitor->Trace(service_);
  visitor->Trace(pending_resolvers_);
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
}

}  // namespace blink
