# ADR-0016: Federation signature exchange over gRPC

- Status: Accepted (owner direction, 2026-07-31)
- Phase: 7c
- Refines: ADR-0014 §6. Retires ADR-0012's R2 bootstrap key topology.
- Preserves: ADR-0015's designated-quorum model.

## Context

Two phases shipped deliberately unsafe key topologies. ADR-0012 (R2) had one
relayer process load **every** validator's ed25519 key and sign with all of
them; it was labelled bootstrap-only from the day it landed. Phase 7c
replaces it with one key per process and a network that moves signatures
between them.

## Decision

### 1. Transport: gRPC (tonic). libp2p rejected.

Per ADR-0014 §6.1: with ≤16 known, static, mutually-identified operators,
libp2p's value (discovery, NAT traversal, transport agility) is unneeded
while its dependency surface is large against a `deny.toml` already strained
by `solana-client`. Verified before adoption — tonic + prost resolve under
MSRV 1.85 and `cargo-deny` passes on both workspaces.

**TLS is deliberately not enabled yet.** tonic's `tls` feature pulls
`rustls-pemfile`, which carries an unmaintained advisory
(RUSTSEC-2025-0134) with no safe upgrade available. Rather than carry an
advisory for a feature not yet used, the feature is off and mTLS lands with
the transport hardening that actually exercises it.

### 2. The layer moves signatures, never truth

This is the load-bearing property, and it is what makes a compromised
requester harmless.

A responder **never trusts the requester's description of the world**. The
request carries the bytes it wants signed, but those are only ever
*compared*: the responder independently re-derives the canonical message
from its **own** chain observations (`policy::LocalView`) and refuses unless
the two are byte-identical. It then signs the bytes **it derived**, not the
bytes it was sent.

This makes concrete the constraint recorded in `p2p/mod.rs` since Phase 0.

### 3. Refusals are alarms

Every refusal means this validator's view of the chain disagrees with a
peer's — a bug or an attack, never routine. All refusals are logged with
their reason and surfaced as `failed_precondition`.

### 4. Replay, expiry, and equivocation

- Requests carry a `request_id` nonce and an `expiry_unix`.
- The signed message binds the epoch; a responder whose own view disagrees
  refuses rather than signing under a federation revision it does not hold.
- A `SeenSet` keyed by `(action, identity)` makes a retry **idempotent** —
  the same signature is returned — while a *different* message for the same
  identity is refused as `ConflictingRequest`. A validator therefore cannot
  be induced to equivocate.
- Cheap checks run before the derivation, so an attacker cannot amplify work
  beyond their rate limit.

### 5. Identity is checked on both sides

A peer endpoint is registered with the validator pubkey it must answer as.
The collector discards a response that claims a different identity, and
discards any signature that does not verify over the message actually asked
about — so a peer can neither impersonate another validator nor contribute a
signature over different bytes.

### 6. The designated quorum survives (ADR-0015)

A payout request carries `withdrawal_index` **and** `quorum_attempt`, and
those together form the signing identity. A signature for a superseded
designation therefore neither satisfies nor conflicts with its replacement,
which is exactly the auditable-reassignment property 7b established.

### 7. Structural key separation

`signer::load_validator_keypairs` is **deleted**; the only loader returns a
single identity. `Orchestrator::new` no longer takes keys at all — it takes
a `SignatureCollector`. Holding several federation identities in one process
is now something that would have to be built deliberately rather than
something that happens by default.

### 8. The build ships its own protobuf compiler

`tonic-build` needs `protoc`. Relying on a system install made the build
pass locally and fail in CI, where no protobuf compiler exists. The build
script uses `protoc-bin-vendored` unless `PROTOC` is explicitly set, so the
build is self-contained: no contributor or runner needs a toolchain that
happens to be present. A build that only works on machines with the right
tools installed is not a reproducible build, which matters for the verified
builds ADR-0014 §12 requires before launch.

## Consequences

- The mint path no longer signs locally; a validator that has not itself
  observed a deposit simply refuses, so a lagging peer stalls rather than
  rubber-stamping.
- Falling short of threshold is a normal tick outcome, retried later — not
  an error that strands a deposit.
- `InProcessCollector` exists for end-to-end tests and is labelled
  test-only. It reintroduces multi-key holding on purpose so tests can reach
  threshold without N processes; production wiring uses `GrpcCollector`
  exclusively.
- **Not yet delivered in 7c:** mTLS and peer certificate pinning; the
  server binary that hosts `SignerService`; rate limiting; and routing the
  *vault payout* signature exchange (which needs partial-signature
  aggregation, not single-signature collection) through the same path. The
  protocol and policy already model payouts, so that is wiring rather than
  redesign.
