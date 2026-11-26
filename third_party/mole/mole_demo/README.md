# MOLE demo: anchor.com / antifraud.com / shoes.com / socks.com

A runnable, click-through HTTPS demonstration of the cross-site, unlinkable
endorsement and anonymous-credential flow (`draft-jms-mole-protocols-01`,
`draft-jms-mole-http-transport-01`, `draft-ladd-mole-ec-ihat-00`, and
`draft-schlesinger-mole-ec-act-00`).

- **anchor.com** — an identity provider (Anchor). Grants a batch of blind
  EC-IHAT (`0x0002`) endorsements at `POST /mole/grant`.
- **antifraud.com** — a shared anti-fraud service (Moderator). Redeems one
  endorsement at `POST /mole/issue` for an EC-ACT (`0x0001`) credential (`2^L`
  range proof) and verifies/refunds presentations on `GET /gate` (plus
  `recovery-0001` / `signoff-0001` settlement on `POST /mole/issue`).
- **shoes.com**, **socks.com** — two distinct origins that both verify visitors
  through `antifraud.com`.

The Anchor and Moderator are standalone HTTPS servers (`mole_demo_anchor`,
`mole_demo_moderator`) built on BoringSSL TLS (`bssl_sys`) and the same
BoringSSL-backed crates (`mole_p256`, `ec_ihat`, `ec_act`, `mole_core`) used by
`//components/moderated_endorsements`.

## Build + run

```sh
autoninja -C out/athm content_shell mole_demo_anchor mole_demo_moderator
third_party/mole/mole_demo/run_demo.sh out/athm
```

The script mints an ephemeral self-signed SAN certificate pinned via
`--ignore-certificate-errors-spki-list`, starts all four HTTPS origins on
localhost (`--host-resolver-rules`), generates the browser's key-commitment
registry (`--mole-key-commitments`), enables `ModeratedEndorsements`, and opens
`https://anchor.com`.

## Walk-through

1. **anchor.com** → `navigator.endorsement.collect("https://anchor.com")` runs
   the two-round EC-IHAT batch grant at `POST https://anchor.com/mole/grant`.
2. **shoes.com** → `navigator.endorsement.challenge("https://antifraud.com/gate")`
   redeems one endorsement at `POST https://antifraud.com/mole/issue` (`200 OK`
   `Mole-Credential: response-0001="..."`) and presents the issued EC-ACT
   credential at `GET /gate` (`Mole-Credential: update-0001="..."`).
3. **socks.com** → presents the refunded successor EC-ACT credential with zero
   additional endorsement redemptions.
4. **antifraud.com** → shows **one redemption** and **two+ unlinkable
   presentations**, each exposing only a fresh one-time nullifier.
