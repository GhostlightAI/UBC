# UBC Protocol Specification v0.1

Universal Bot Communication — a free, open protocol for secure bot-human and bot-bot communication.

## Address Format

UBC addresses are 16 characters: 15 digits + 1 letter (base-36: 0-9, A-Z).

```
Example: 7K9M2N4P8Q3R5T1B
```

### Derivation

1. Generate Ed25519 keypair
2. Take first 12 bytes of public key
3. Encode as base-36 (15 characters)
4. Append checksum letter (CRC8 of the body, mapped into the 26 letter slots — the final character is always A-Z)

### Properties

- **Self-generated**: No central registry
- **Collision-resistant**: ~2.2 × 10²⁴ possible addresses
- **Verifiable**: Address cryptographically bound to keypair

## Identity

Each UBC identity is an Ed25519 keypair:

- **Private key**: 32 bytes, kept secret
- **Public key**: 32 bytes, shared
- **Address**: Derived from public key (above)

Proof of ownership: Sign challenges with private key.

## Tunnel Types

| Type | Duration | Use Case | Approval |
|------|----------|----------|----------|
| `ephemeral` | Single session | One-time exchange | Auto-expire |
| `session` | Hours/days | Conversation | Both parties |
| `persistent` | Until revoked | Ongoing relationship | Explicit + audit |

## Communication Preferences

Negotiated per tunnel via `TunnelConfig`:

```json
{
  "version": "0.1",
  "address": "7K9M2N4P8Q3R5T1B",
  "type": "session",
  "permissions": {
    "human_to_bot": true,
    "bot_to_bot": false,
    "file_transfer": true,
    "voice": false
  },
  "privacy": {
    "log_retention": "none",
    "forward_secrecy": true,
    "metadata_minimization": true
  },
  "limits": {
    "max_duration_hours": 24,
    "max_messages": 1000,
    "rate_limit_per_minute": 60
  }
}
```

## QR Code Format

```
ubc:<address>?t=<type>&r=<relay>&exp=<expiry>&sig=<signature>
```

Parameters:
- `address`: 16-char UBC address
- `t`: Tunnel type (ephemeral|session|persistent)
- `r`: Relay URL (optional, for signaling)
- `exp`: Unix timestamp expiry (optional)
- `sig`: Ed25519 signature of above params

Example:
```
ubc:7K9M2N4P8Q3R5T1B?t=session&r=wss://relay.ubc.network&exp=1724860800&sig=abc123...
```

## Message Envelope

All messages encrypted end-to-end. Envelope:

```json
{
  "from": "7K9M2N4P8Q3R5T1B",
  "to": "3X8K2M9P4Q7R1T5C",
  "tunnel_id": "550e8400-e29b-41d4-a716-446655440000",
  "seq": 42,
  "type": "text|file|voice|control",
  "payload": "<encrypted-bytes>",
  "timestamp": 1724860800,
  "signature": "<ed25519-signature>"
}
```

## Transport

### Signaling

Initial connection via relay (WebRTC SDP exchange):

1. Alice scans Bob's QR → gets address + relay hint
2. Alice connects to relay, sends `ConnectRequest` for Bob's address
3. Relay forwards to Bob (if online) or queues
4. WebRTC handshake via relay
5. Direct P2P tunnel established
6. Relay drops out (optional: keep as fallback)

### Encryption

- **Key exchange**: X25519 (ECDH)
- **Cipher**: ChaCha20-Poly1305
- **Forward secrecy**: New key per session
- **Authentication**: Ed25519 signatures

## Relay Protocol

Relays are untrusted signaling servers. They see:
- Connection requests (encrypted payload)
- Timing metadata
- No message content

Relay API:
- `POST /announce` — Register online status
- `POST /connect` — Request connection to address
- `GET /pending` — Poll for incoming connections
- `WebSocket /signal` — Real-time signaling

## Security Properties

- **End-to-end encryption**: Relays cannot read messages
- **Forward secrecy**: Past sessions safe if keys compromised
- **Deniability**: No persistent message logs (optional)
- **Metadata minimization**: Only necessary routing data exposed

## Reference Implementation

- `ubc-core`: Rust crate — identity, crypto, tunnel state
- `ubc-relay`: Rust server — signaling, optional TURN
- `ubc-ios`: Swift SDK
- `ubc-android`: Kotlin SDK
- `ubc-cli`: Rust CLI for testing

## License

MIT — free for all uses.
