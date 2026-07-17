# MoLE demo: anchor.com / antifraud.com / shoes.com / socks.com

A runnable, click-through demo of the cross-site, unlinkable endorsement flow.

- **anchor.com** — an identity provider (Anchor). Issues one unlinkable IHAT
  endorsement.
- **antifraud.com** — a shared anti-fraud service (Moderator). Redeems the
  endorsement into a pool of anonymous ACT credentials and verifies one on each
  visit.
- **shoes.com**, **socks.com** — two sites that both verify visitors through
  antifraud.com.

The Anchor and Moderator are standalone HTTP servers (`mole_demo_anchor`,
`mole_demo_moderator`) built on the **same first-party BoringSSL crypto the
browser uses** (`act_boring`/`ihat_boring`/`mole_core`), so their wire format is
byte-compatible with `//components/moderated_endorsements` — no ristretto/P-256
mismatch. Not production code: single-threaded, plaintext HTTP, no TLS.

## Build + run

```sh
autoninja -C out/athm content_shell mole_demo_anchor mole_demo_moderator
third_party/mole/mole_demo/run_demo.sh out/athm
```

The script starts all four origins on localhost (mapped via
`--host-resolver-rules`), generates the browser's key-commitment registry from
the servers' runtime keys (`--mole-key-commitments`), enables the feature
(`--enable-blink-features=ModeratedEndorsements`), and opens the browser at
anchor.com.

## The walk-through

1. **anchor.com** → "Get my endorsement" (`collect()` — same-origin).
2. **shoes.com** → "Verify me" (`challenge("https://antifraud.com/gate")`): the
   browser redeems the endorsement (once) and presents a credential.
3. **socks.com** → "Verify me": presents from the *same pool*, no re-redeem.
4. **antifraud.com** → watch the counters: **one redemption, two+ unlinkable
   presentations**. Neither antifraud.com nor the two sites can link the visits.

Try clicking "Verify me" on shoes.com *before* visiting anchor.com: it declines
opaquely and the browser does **not** bounce you to the Anchor — that would be a
possession oracle and a cross-site linkage. You collect an endorsement only by
deliberately visiting the Anchor.
