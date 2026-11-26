// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_H_

#include "third_party/blink/public/mojom/moderated_endorsements/moderated_endorsements.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/modules/modules_export.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/supplementable.h"

namespace blink {

class EndorseOptions;
class ExceptionState;
class NavigatorBase;
class ScriptState;
class SettleOptions;

// Backing implementation for `navigator.endorsement.{endorse, settle}()`.
// All cryptographic state, EC-IHAT endorsements, and EC-ACT credentials remain
// strictly isolated inside the Browser Process (`ModeratedEndorsementsStore`).
class MODULES_EXPORT ModeratedEndorsements final
    : public ScriptWrappable,
      public Supplement<NavigatorBase> {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static const char kSupplementName[];

  static ModeratedEndorsements* endorsement(NavigatorBase&);

  explicit ModeratedEndorsements(NavigatorBase&);

  ScriptPromise<IDLUndefined> endorse(ScriptState*,
                                      const EndorseOptions*,
                                      ExceptionState&);
  ScriptPromise<IDLUndefined> settle(ScriptState*,
                                     const SettleOptions*,
                                     ExceptionState&);

  void Trace(Visitor*) const override;

 private:
  mojom::blink::ModeratedEndorsementService* GetService();

  void OnOperationComplete(ScriptPromiseResolver<IDLUndefined>*,
                           mojom::blink::ModeratedEndorsementStatus);
  void OnServiceDisconnected();

  HeapMojoRemote<mojom::blink::ModeratedEndorsementService> service_;
  HeapHashSet<Member<ScriptPromiseResolverBase>> pending_resolvers_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_H_
