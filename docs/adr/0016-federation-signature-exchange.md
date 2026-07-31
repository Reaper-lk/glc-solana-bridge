# ADR-0016: Federation signature exchange over gRPC

- Status: Accepted (owner direction, 2026-07-31); extended by Phase 7d
- Phase: 7c, extended 7d
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

### 8. Identity is bound twice, at the transport and at the application (7d)

Transport identity is mutual TLS against a **pinned federation CA**. The
public web PKI is deliberately not trusted: without pinning, any publicly
issued certificate for a matching name would be accepted. The server
requires a client certificate, so a validator will not even converse with a
caller who lacks one.

Application identity remains the on-chain ed25519 validator key, checked on
every response (§5). Neither check is redundant:

- a **stolen certificate** cannot impersonate a validator, because the
  thief cannot produce that validator's ed25519 signatures;
- **certificate rotation** cannot silently change which federation member a
  peer believes it is talking to, because the on-chain key is what the
  application compares.

The certificate name is pinned by configuration (`GLC_FEDERATION_TLS_DOMAIN`)
rather than derived from each peer's URI, so a peer cannot present a
certificate for a name it merely happens to control.

`GLC_FEDERATION_TLS=off` exists for loopback and regtest. It logs a warning
on every start and is the only way to run without transport authentication.

### 9. Timeouts and failover are policy, not transport detail (7d)

`p2p::aggregation` holds the collection rules, free of gRPC types, so they
are testable without a network — the same separation `policy.rs` uses for
the signing decision:

- **per-peer timeout (5s)** and a **round ceiling (20s)**. With an M-of-N
  threshold, waiting on one unresponsive peer can stall a mint that M others
  were ready to authorize;
- **every peer is asked**, not just the first M, rotating the starting point
  deterministically by deposit identity. Asking only the minimum costs a
  full round-trip timeout before anything can proceed when one is down;
- collection **stops as soon as threshold is reached**, so a healthy round
  does not cost N round-trips;
- a **refusal is not retriable**. It means that peer independently
  disagreed about what should be signed; retrying asks the same question and
  gets the same answer. Only unavailability justifies another round, and a
  shortfall larger than the unavailable set is reported as hopeless rather
  than spun on.

Throttling is reported as `resource_exhausted`, never `failed_precondition`,
precisely so it is classified as retriable rather than as a disagreement.

For **payouts**, only the designated quorum is asked (§6). A designated
signer that is unavailable produces a shortfall requiring explicit, audited
reassignment — never an implicit substitution, because the txid depends on
which quorum signs.

### 10. A signer that cannot see the chain refuses everything (7d)

`Refusal::StaleView` is a new guard. A validator whose link to the chain has
been down cannot distinguish a *current* epoch from a *superseded* one: it
would keep answering with a remembered value and keep agreeing with anyone
quoting it back. `signer-server` polls the on-chain ValidatorSet, and if
those polls stop succeeding for longer than the staleness bound, every
request is refused until the link recovers. Startup also blocks on a first
successful observation, so a signer never begins serving with no epoch at
all.

A failed poll deliberately does **not** refresh the observation timestamp;
that is what makes staleness accumulate rather than be papered over.

### 11. Rate limiting is per peer, keyed by certificate (7d)

`Refusal::RateLimited` existed in 7c but was never enforced. It is now, as a
token bucket (30 burst, 10/s sustained) charged **before** the re-derivation
work that makes signing expensive.

Buckets are keyed by a fingerprint of the client certificate, falling back
to the remote address without its port. The certificate is fingerprinted,
never parsed — no X.509 parser is on the request path, and authenticating
the certificate is already TLS's job. Keying per certificate matters because
federation members can legitimately share an apparent address (NAT, proxy,
co-location); an address-keyed bucket would let one member starve the
others, which is the exact failure a per-peer limit exists to prevent.

The limit protects the *availability* of the signing service. It protects no
key, and is not a substitute for any check.

### 12. The relayer no longer configures validator keys at all (7d)

`SolanaConfig::validator_keypair_paths` is **removed**. The relayer holds no
validator key, so requiring it to be configured with paths to them was worse
than redundant: it invited operators to place federation key material in the
relayer's environment — exactly the topology 7c retired. A validator key is
configured only for `signer-server`, singular, via
`GLC_SIGNER_VALIDATOR_KEYPAIR_PATH`.

### 13. The build ships its own protobuf compiler

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
- Phase 7d delivers what 7c deferred: mTLS with a pinned CA, the
  `signer-server` binary, timeout/failover, and rate-limit enforcement. The
  transport is verified against real certificates in
  `tests/federation_transport.rs` rather than assumed correct from reading
  configuration code.
- The signer answers from its own database through the **same**
  reload-and-recompute safeguards the locally-driven pipelines use. So a
  signer whose persisted state has drifted does not merely decline: it halts
  that deposit or withdrawal as an integrity anomaly, exactly as the local
  paths do.
- **Still not delivered:** the *vault payout* path does not yet route its
  Goldcoin-level signing through the federation. `signer-server` can attest
  to a canonical payout intent, and `GrpcCollector::collect_payout_signatures`
  collects those attestations from the designated quorum, but the P2SH
  multisig transaction itself is still assembled by the Goldcoin node
  (ADR-0013). Distributing that requires partial-ECDSA aggregation, which is
  a change to the *signing model* and therefore explicitly outside 7d's
  remit. Until it lands, the payout attestation path is plumbed but not
  driven by the executor.
