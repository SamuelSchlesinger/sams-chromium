# MOLE 4-Origin Split Moderation & Redemption Demo (`mole_demo`)

`//third_party/mole/mole_demo` provides standalone BoringSSL TLS 1.3 servers and
an end-to-end integration test suite exercising Chromium's Moderated
Endorsements (MOLE) Split Moderation & Redemption architecture.

## Topology

1. **Identity Anchors (`mole_demo_anchor` — `anchor.com`, `anchor2.com`, `anchor3.com`)**:
   - Serve `GET /.well-known/mole-anchor` and 2-RTT `POST /mole/grant` issuing
     batches of unlinkable `EC-IHAT` endorsements (`navigator.endorsement.endorse()`).
   - Running 3 distinct Anchors satisfies the `>= 3` Anchor Set ring-signature
     k-anonymity invariant enforced by both the Moderator and Chromium's
     `MoleCommitmentRegistry`.
2. **Split Moderator (`mole_demo_moderator` — `antifraud.com`)**:
   - Serves `GET /.well-known/mole-moderator`, `POST /mole/v1/issue`,
     `POST /mole/v1/present`, `POST /mole/v1/settle`, and `POST /mole/v1/feedback`.
   - Enforces a 5-minute `(nullifier_A, idempotency_key)` cache on `/issue` so
     transient network drops recover without burning an `EC-IHAT` endorsement.
   - Verifies zero-knowledge `EC-ACT` range/spend proofs (`L = 8` or `L = 16`)
     and mints short-lived, request-bound P-256 ECDSA `ClearanceToken`s in both
     immediate (`200 OK`) and deferred behavioral (`202 Accepted`) modes,
     without ever seeing Origin cookies or `Authorization: Bearer` headers.
3. **Relying-Party Origins (`mole_demo_origin` — `shoes.com`, `socks.com`)**:
   - Challenge unauthenticated requests with `401 Unauthorized` +
     `Mole-Challenge: moderator="https://antifraud.com", policy="antifraud-v2", cost=1, nonce="..."`.
   - Verify `Sec-Mole-Authorization` `ClearanceToken` signatures locally using
     the Moderator's public key alongside first-party `Authorization: Bearer`
     headers (`0` Origin <-> Moderator synchronous latency).
   - Optionally report behavioral rewards to `POST /mole/v1/feedback` and emit
     `Mole-Info: session="..."; settle-ready=?1` for automatic background
     credential top-up.

## Web API Surfaces Exercised (`web/shoes/index.html`, `web/socks/index.html`)

- **Anchor Issuance**: `navigator.endorsement.endorse({ authorization })` (requires
  top-level secure context + transient user activation).
- **Fetch Integration**: `fetch(url, { moderated: true })` and
  `fetch(url, { moderated: { moderator, policy, allowDeferredUpdate } })`.
- **Declarative HTML**: `<form action="/api/purchase" method="POST" moderated>`.
- **Deferred Settlement**: `navigator.endorsement.settle({ moderator, policy })`
  (returns `Promise<undefined>` with jittered delay so settlement outcomes or
  balance bits never leak to JavaScript).

## Building & Running

```bash
autoninja -C out/Default chrome mole_demo_anchor mole_demo_moderator mole_demo_origin
./third_party/mole/mole_demo/run_demo.sh
```
