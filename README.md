# UBC — Universal Bot Communication

A free, open protocol for secure bot-to-human and bot-to-bot communication.

UBC gives every bot a self-generated, cryptographically verifiable address —
no central registry, no gatekeeper — and a standard way to open encrypted
tunnels to humans and to each other. One singular layer, free for everyone,
so the next hundred assistants don't each invent their own incompatible way
to talk.

## What this is

- **A protocol** — [`spec/UBC-v0.1.md`](spec/UBC-v0.1.md) is the source of
  truth: address format, identity, tunnel types, encryption, relay behavior.
- **A reference implementation** — [`core/`](core/) is `ubc-core`, a Rust
  crate implementing identity, address derivation, tunnel state, crypto,
  message envelopes, and QR pairing. 13/13 tests green.
- **A starting point** — `cli/`, `sdks/ios/`, and `sdks/android/` are
  scaffolded and waiting for contributors.

## The sixty-second version

- **Addresses** are 16 characters (15 base-36 digits + 1 checksum letter),
  derived from an Ed25519 public key. Owning the address *is* owning the
  keypair — proof is a signature, not a password.
- **Tunnels** come in three flavors: `ephemeral` (one session),
  `session` (hours/days, both parties approve), and `persistent` (until
  revoked, explicit + audited). Communication permissions are negotiated per
  tunnel.
- **Encryption** is end-to-end: X25519 key exchange, ChaCha20-Poly1305,
  Ed25519 signatures, forward secrecy per session.
- **Relays are untrusted.** They route encrypted signaling traffic and see
  timing metadata — never message content.

## Build and test

```bash
cd core
cargo build --release
cargo test
```

## Using the crate

```rust
use ubc_core::{Identity, Tunnel, TunnelConfig};

let identity = Identity::generate();
println!("Address: {}", identity.address());

let config = TunnelConfig::session()
    .with_file_transfer(true)
    .with_max_duration_hours(24);

let tunnel = Tunnel::open(&identity, &config, peer_address).await?;
```

## Project layout

```
spec/     Protocol specification (start here)
core/     ubc-core — Rust reference implementation
docs/     Design notes and guides
cli/      ubc-cli — command-line testing tool (planned)
sdks/     iOS (Swift) and Android (Kotlin) SDKs (planned)
```

## Status

v0.1 — early. The core crate works; the relay server and SDKs are
unwritten. The spec is the stable contract; expect implementations to
chase it.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The bar is
simple: spec changes need discussion, implementation changes need tests.

## License

[MIT](LICENSE) — free for all uses, forever. That is the point of the
project.
