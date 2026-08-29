# UBC Core

Rust implementation of the UBC protocol.

## Structure

- `src/identity.rs` — Keypair generation, address derivation
- `src/tunnel.rs` — Tunnel state machine, preferences
- `src/crypto.rs` — Encryption, signatures
- `src/message.rs` — Message envelope, serialization
- `src/qr.rs` — QR code generation/parsing

## Usage

```rust
use ubc_core::{Identity, Tunnel, TunnelConfig};

// Generate identity
let identity = Identity::generate();
println!("Address: {}", identity.address());

// Create tunnel config
let config = TunnelConfig::session()
    .with_file_transfer(true)
    .with_max_duration_hours(24);

// Open tunnel
let tunnel = Tunnel::open(&identity, &config, peer_address).await?;
```

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```
