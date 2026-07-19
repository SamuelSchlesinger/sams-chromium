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

class ExceptionState;
class NavigatorBase;
class ScriptState;

// navigator.endorsement: the renderer-side surface of the MoLE (Moderation
// of unLinkable Endorsements) client. Every operation is forwarded to the
// browser process, which holds the endorsement store and per-policy
// credential pools; the page only learns success or a coarse failure.
class MODULES_EXPORT ModeratedEndorsements final
    : public ScriptWrappable,
      public Supplement<NavigatorBase> {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static const char kSupplementName[];

  // Getter for navigator.endorsement.
  static ModeratedEndorsements* endorsement(NavigatorBase&);

  explicit ModeratedEndorsements(NavigatorBase&);

  ScriptPromise<IDLUndefined> collect(ScriptState*,
                                      const String& url,
                                      ExceptionState&);
  ScriptPromise<IDLString> challenge(ScriptState*,
                                     const String& url,
                                     ExceptionState&);

  void Trace(Visitor*) const override;

 private:
  mojom::blink::ModeratedEndorsementService* GetService();

  void OnCollect(ScriptPromiseResolver<IDLUndefined>*,
                 mojom::blink::EndorsementStatus);
  void OnChallenge(ScriptPromiseResolver<IDLString>*,
                   mojom::blink::EndorsementStatus,
                   const String& body);
  // Settles every pending promise when the browser side closes the pipe;
  // abandoned resolvers would otherwise never settle (and crash on GC in
  // DCHECK builds).
  void OnServiceDisconnected();

  HeapMojoRemote<mojom::blink::ModeratedEndorsementService> service_;
  HeapHashSet<Member<ScriptPromiseResolverBase>> pending_resolvers_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_MODERATED_ENDORSEMENTS_MODERATED_ENDORSEMENTS_H_
