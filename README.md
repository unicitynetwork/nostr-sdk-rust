# unicity-nostr (nostr-sdk-rust)

A Rust port of the Unicity Nostr protocol, **wire-compatible with the deployed
TypeScript SDK** ([`@unicitylabs/nostr-js-sdk`](https://github.com/unicitynetwork/nostr-js-sdk)
v0.6.0). Built for the AOS/Astrid Unicity communication capsule.

Two design rules make this crate reusable across the planned wallet/messaging
capsule split:

- **Transport-free** — no relay/WebSocket code. The protocol layer is pure
  computation over a `Signer`; the capsule supplies the socket.
- **Custody-agnostic** — protocol code depends only on the [`Signer`] trait,
  never a raw private key. A wallet capsule uses `LocalSigner`; a messaging
  capsule uses a remote signer that proxies to the wallet over the bus.

## Status

Everything below is validated **byte-for-byte against golden vectors generated
from the reference TypeScript SDK** (`cargo test`, 7 tests):

| Area | Module | Interop check |
|---|---|---|
| NIP-01 event id + signing | `event` | id serialization byte-exact (unicode/escapes), sign→verify |
| BIP-340 Schnorr | `crypto::schnorr` | pubkey + deterministic sig (aux=0) byte-exact, verify |
| NIP-04 (Unicity variant) | `crypto::nip04` | shared secret + byte-exact encrypt, decrypt, gzip round-trip |
| NIP-44 (TS AEAD variant) | `crypto::nip44` | conversation key + symmetry + byte-exact AEAD encrypt/decrypt |
| NIP-19 bech32 | `crypto::bech32` | npub/nsec encode + decode round-trip |
| Keys / Signer seam | `keys`, `signer` | key derivation, `LocalSigner`, end-to-end event |
| NIP-17 gift-wrap DMs | `nip17` | Rust unwraps TS-produced gift wraps (+ reply), non-recipient rejection, round-trip |
| UNIP-01 nametag utils | `nametag` | salted hashing, normalize, validation, byte-exact `encrypted_nametag`, marker |
| UNIP-01 bindings + resolution | `binding` | verify JS binding events, `queryWithFirstSeenWins` (marker/ambiguity/bad-sig/legacy) |
| NIP-01 filters | `filter` | filter JSON shapes match the reference SDK, local `matches` |
| Relay client + transport | `client` | **live e2e: publish + read-back a NIP-17 DM through the deployed testnet relay** |

### Not yet ported (roadmap)

Multi-relay fan-out (broadcast + cross-relay query settlement) · keepalive/reconnect
supervision · the in-capsule wasm TLS+WebSocket transport (rustls + tungstenite over
Astrid `net`) · token/payment protocols. (NIP-29 group chat is out of scope for now.)

## Relay client & transport

`client` provides a transport-agnostic single-relay client: relay-message parsing,
publish, subscribe/query, and NIP-42 AUTH — driven by a `RelayConnection` the caller
supplies. The capsule will implement that over Astrid `net`; the `native-transport`
feature ships a std/`tungstenite`+rustls implementation for host tools and the e2e tests.

## Compatibility caveats

The Unicity wire format is intentionally **non-standard** — a generic `nostr` /
`nip44` crate will not interoperate:

- **NIP-44** is a ChaCha20-**Poly1305 AEAD** variant with a 24-byte nonce and no
  separate HMAC — not official NIP-44 v2. (It is also incompatible with the Java
  SDK's NIP-44; see [nostr-sdk#7](https://github.com/unicitynetwork/nostr-sdk/issues/7).)
- **NIP-04** derives the AES-256-CBC key as `SHA-256(ECDH_x)` (canonical NIP-04
  uses the raw x) and adds a `gz:` GZIP extension for messages over 1 KiB.
- **ECDH** reconstructs a peer's x-only key as an even-y point before the key
  agreement.

## Testing

```sh
cargo test          # interop vector tests (no network)
cargo clippy --all-targets --all-features

# End-to-end against the deployed testnet relay (network; opt-in):
cargo test --features native-transport --test e2e -- --ignored --nocapture
```

The vectors in `tests/vectors/nostr-vectors.json` are generated from the
reference SDK, not hand-written. To regenerate (needs a `nostr-js-sdk` checkout
with `node_modules`):

```sh
tools/regen-vectors.sh [path-to-nostr-js-sdk]   # default ../nostr-js-sdk
```

This temporarily drops `tools/gen-vectors.test.ts` into the JS SDK, runs it under
that repo's own vitest + `@noble` deps, writes the JSON here, and cleans up.

## wasm note

The crypto/protocol core is pure-Rust and `alloc`-based, targeting
`wasm32-unknown-unknown` for the capsule. The one std dependency today is
`flate2` (NIP-04 GZIP); it will be feature-gated for the wasm build (NIP-04 gzip
is only needed on the deferred token/payment path, not for DMs).

## License

MIT OR Apache-2.0.
