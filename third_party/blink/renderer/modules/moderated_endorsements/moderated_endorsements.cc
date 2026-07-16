// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/moderated_endorsements/moderated_endorsements.h"

#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

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

ScriptPromise<IDLUndefined> ModeratedEndorsements::collect(
    ScriptState* script_state,
    const String& url,
    ExceptionState& exception_state) {
  auto* context = GetSupplementable()->GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The context is detached");
    return EmptyPromise();
  }

  KURL endorse_url = context->CompleteURL(url);
  if (!endorse_url.IsValid() || !endorse_url.ProtocolIsInHttpFamily()) {
    exception_state.ThrowTypeError("Invalid endorsement URL");
    return EmptyPromise();
  }
  // An endorsement is a statement by the site the user is visiting; only
  // that site may direct the user agent to collect one.
  if (!context->GetSecurityOrigin()->IsSameOriginWith(
          SecurityOrigin::Create(endorse_url).get())) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSecurityError,
        "The endorsement URL must be same-origin with the document");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  pending_resolvers_.insert(resolver);
  GetService()->Collect(
      endorse_url,
      BindOnce(&ModeratedEndorsements::OnCollect, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLString> ModeratedEndorsements::challenge(
    ScriptState* script_state,
    const String& url,
    ExceptionState& exception_state) {
  auto* context = GetSupplementable()->GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The context is detached");
    return EmptyPromise();
  }

  KURL resource_url = context->CompleteURL(url);
  if (!resource_url.IsValid() || !resource_url.ProtocolIsInHttpFamily()) {
    exception_state.ThrowTypeError("Invalid resource URL");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  pending_resolvers_.insert(resolver);
  GetService()->Challenge(
      resource_url,
      BindOnce(&ModeratedEndorsements::OnChallenge, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

void ModeratedEndorsements::OnCollect(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::EndorsementStatus status) {
  pending_resolvers_.erase(resolver);
  switch (status) {
    case mojom::blink::EndorsementStatus::kSuccess:
      resolver->Resolve();
      return;
    case mojom::blink::EndorsementStatus::kRejected:
      resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                       "The endorsement was not granted");
      return;
    case mojom::blink::EndorsementStatus::kNetworkError:
      resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                       "The anchor could not be reached");
      return;
  }
}

void ModeratedEndorsements::OnChallenge(
    ScriptPromiseResolver<IDLString>* resolver,
    mojom::blink::EndorsementStatus status,
    const String& body) {
  pending_resolvers_.erase(resolver);
  switch (status) {
    case mojom::blink::EndorsementStatus::kSuccess:
      resolver->Resolve(body);
      return;
    case mojom::blink::EndorsementStatus::kRejected:
      // Intentionally opaque: challenge() must not distinguish "no endorsement"
      // from any other rejection, or it becomes a cross-site possession oracle
      // (see EndorsementStatus in the mojom).
      resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                       "The presentation was rejected");
      return;
    case mojom::blink::EndorsementStatus::kNetworkError:
      resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                       "The moderator could not be reached");
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
