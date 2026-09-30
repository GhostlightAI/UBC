# UBC experimental v0.2 development profile

Created by Ryan Sloan. MIT licensed. **Experimental and not yet audited for production use.** The v0.1 specification remains unchanged; this document proposes a successor profile for discussion. The Python implementation is a runnable reference prototype, not an interoperable implementation of every v0.1 transport or a completed standard.

## Running the appliance demonstration

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e 'python[dev]'
.venv/bin/ubc-demo
.venv/bin/python -m pytest tests -q
cargo test --manifest-path core/Cargo.toml
```

The demonstration creates synthetic identities, verifies a manufacturer-signed simulated appliance identity, proves control of the owner's key and a physical pairing secret, opens a mutually approved encrypted relay conversation, reads a diagnostic result, obtains a separate repair grant and resets a simulated filter alert. Reusing the grant fails. Nothing touches a real appliance, sends mail or charges a customer.

Run a separate local relay with `.venv/bin/ubc-relay --data work/relay.sqlite3 --port 9450`. It binds to loopback. Internet deployment requires TLS, operation and abuse controls and further review; changing a bind address does not make it production ready.

## Implemented

- Ed25519 identities with v0.1-compatible display addresses; authorization pins the full 32-byte public key, not a short address or a brand name.
- Signed ephemeral X25519 handshakes; HKDF-SHA256 binds both identities, ephemeral keys, tunnel ID and expiry. Direction-specific ChaCha20-Poly1305 keys prevent reflecting a sent frame as an incoming one.
- Encrypted messages whose signatures and AEAD authentication cover type, sender, recipient, tunnel, sequence and expiry. Replays and altered headers fail.
- An independent SQLite relay: challenge-authenticated announcement, invitation, mutual acceptance, bounded opaque mailboxes, receipt acknowledgements, expiry, quotas and revocation. It sees public keys, timing and routing metadata, not plaintext.
- A simulated appliance: manufacturer certificate, temporary physical pairing, owner signatures, expiring single-use grants, operation allowlist, safety interlocks, revocation and signed receipts. No shell or firmware execution.
- Hash-linked custody records signed by the device. Transfers require the current owner and proposed new owner to sign the same device, key, previous head, sequence and owner epoch. The device commits one transition and invalidates old grants.
- A separately operated witness prototype that stores and signs custody heads and rejects an observed rollback or fork. This is not global consensus.

The original Rust v0.1 verifier now checks that the claimed sender address derives from the supplied signing key. Its legacy signature does not cover the message type; do not use v0.1 envelopes as device or financial authorization. v0.2 experimental frames deliberately use a distinct domain and wire shape.

## Ownership, warranty and custody

Ownership remains with the registered controller until a verified transfer or explicit release. Warranty expiry changes service entitlements, not ownership. The simulator's three-year warranty is illustrative; a manufacturer must supply actual signed warranty terms and start dates.

First pairing demonstrates **key control plus physical possession**, not conclusive legal title. Real products need a manufacturer-supported claim: a signed sale voucher, verified purchase account or protected one-time claim credential, plus a physical challenge. A serial number, email address, public QR sticker or receipt image alone is insufficient.

For resale, a new owner requests transfer. The existing owner's agent presents the exact device and new recipient for approval. Both parties sign, and the device validates and commits the change. A request arriving does not automatically count as approval. The first owner's offline status, loss of a key, theft, death and ownership disputes require a documented recovery process with notification and delay; they are not solved by silently timing out the old owner.

Every prior owner approval becomes invalid for new operations after an owner-epoch change. Shared household access should use revocable delegated grants, not duplicate ownership transfers.

## Decentralization model

Identity, transport, custody and business authority are separate:

1. People, companies and manufacturers generate their own keys. Independent clients can verify signatures without a Ghostlight account.
2. A relay is replaceable delivery infrastructure. Multiple independently operated relays and local direct transports are planned; the current reference relay uses HTTP polling, not WebRTC or relay federation.
3. Devices enforce one current owner epoch and retain their custody head. Production hardware needs a non-exportable device key and rollback-resistant monotonic state. The in-memory simulator does not provide either hardware guarantee.
4. Independent witnesses compare signed heads. A hash chain alone cannot stop a compromised device from signing two forks. Witness diversity, gossip and a defined quorum/finality rule are needed to resolve that threat. A partitioned client must not invent finality.
5. Company agents independently enforce company permissions, customer authority and monetary budgets. Possession of a UBC key never grants general access to an ERP system.

No token, mining reward or global ledger is required to demonstrate these flows. Bitcoin's consensus solves adversarial agreement over a public transaction history; UBC's current witness is not equivalent. If the protocol later needs trustless global ownership finality even when devices are compromised or offline, consensus and its governance/economics become a separate design project.

Keep personal names, addresses, chat content and diagnostic logs out of public custody logs. Share encrypted custody proofs only with authorized parties. Public witness anchors still carry correlation risks and need a privacy design.

## Boundaries and remaining work

- The simulator keeps identities, ownership, replay state and grants in memory. It must not be treated as durable authorization across restarts. The relay's SQLite queue and witness heads persist; their caller-supplied private identities need secure storage and recovery.
- Add encrypted key storage / platform keychain support, rotation certificates, revocation distribution, recovery, manufacturer voucher validation and rollback-resistant device persistence.
- Add conformance vectors and independent Rust/Swift/TypeScript implementations. Current Python-to-Python tests do not establish cross-vendor interoperability.
- Implement direct transports, authenticated discovery, relay portability/federation, delivery failure semantics, background mobile delivery, abuse controls and encrypted attachment limits.
- Add a versioned capability manifest, structured application errors and agent task status/cancellation. Business messages are untrusted requests, never instructions to widen an agent's authority.
- Connect a consent screen and adapter in Ghostlight Personal. A company-scoped request/review inbox now exists in the local Ghostlight Business source, with encrypted sessions, pinned peers, idempotent intake, employee replies and revocation. Its Service integration tests pass. The Business policy editor performs simulations; neither it nor the review inbox executes refunds, orders, emails or repairs. This source work is not a claim that the public preview or the Personal app is connected.
- Add reviewed transaction adapters that load trusted records, validate ownership/authority, enforce cumulative limits atomically, recheck policy immediately before execution and return idempotent receipts.
- Complete a threat model, external cryptographic review, hostile-peer testing and deployment hardening before public operational use. No financial, clinical or physical safety certification is claimed.

## Related work and interoperability

The recommended direction is to reuse established designs and make adapters where useful, not require every company to replace its agent stack.

- [FIDO Device Onboard](https://fidoalliance.org/fido-device-onboarding/) provides a relevant device-credential and ownership-voucher ecosystem. UBC's simulator is not FDO certified or FDO compatible yet.
- [FDO voucher double-extension guidance](https://fidoalliance.org/specs/fidoiot/appnote1-ov-guidance-v1.0-fd-20230306.html) is directly relevant to ownership forks.
- [W3C DID Core](https://www.w3.org/TR/did-core/) describes independently verifiable identifiers and controller relationships. A UBC display address is not automatically a conforming DID method.
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) provides append-only transparency-log techniques. Witness monitoring can reveal inconsistent views; it does not itself supply a global consensus rule.
- [A2A](https://a2a-protocol.org/) is a relevant agent interoperability target. A capability/task adapter is planned; compatibility is not yet implemented.
- [Bitcoin consensus](https://developer.bitcoin.org/devguide/block_chain.html) illustrates the additional consensus machinery behind public ownership history, beyond merely linking hashes.
