# Federation deployment (Phase 7d)

How a validator operator runs their half of the bridge. See
[ADR-0016](adr/0016-federation-signature-exchange.md) for why it is shaped
this way.

## Two processes, one key

Each operator runs **two** processes:

> **Phase 7f:** withdrawals are now marked `Completed` on Solana under an
> M-of-N federation proof, so a relayer starting from an **empty database**
> can tell paid from unpaid by reading chain state
> ([ADR-0018](adr/0018-withdrawal-completion.md)). Completion is
> **irreversible**: there is no un-complete instruction, deliberately.

| process | holds | listens | talks to |
|---|---|---|---|
| `signer-server` | **the** validator ed25519 key **and this operator's single vault key** — the only keys in the deployment | mTLS gRPC | its **own** Solana RPC and its **own** Goldcoin RPC |
| `glc-relayer` | no validator key, no vault key | nothing | Goldcoin RPC, Solana RPC, and every peer's `signer-server` |

The relayer builds, assembles, submits, and pays fees; it cannot authorize
anything. Authority lives only in the signer processes, and only signatures
cross the network. A fully compromised relayer can waste fees and stall
progress — it cannot mint **or move vault funds**, because every signer
independently re-derives what it is asked to sign and refuses anything it did
not derive itself.

> **Phase 7e:** the Goldcoin payout path is now distributed too. The
> operator's Goldcoin node no longer needs enough vault keys to satisfy the
> M-of-N — it holds **one**, in the signer process. See
> [ADR-0017](adr/0017-distributed-payout-signing.md).

Both processes read the same SQLite file. That is deliberate: the signer's
answers come from **this operator's own** chain observations, written by
their own indexer. A signer must never be pointed at a database some other
party populates.

## Certificates

Generate one CA for the federation, and one leaf certificate per process
(both the signer and the relayer need one — the relayer authenticates
itself to peers just as they authenticate to it).

- All leaves must be issued for the **same name**, configured as
  `GLC_FEDERATION_TLS_DOMAIN` and pinned by every relayer. Peers are
  identified by their on-chain key, not by their hostname, so per-host names
  would buy nothing and complicate rotation.
- Only the federation CA is trusted. The public web PKI is not: without
  pinning, any publicly issued certificate for a matching name would be
  accepted at the transport layer.
- Rotating a certificate does **not** change which validator a peer is:
  identity at the application layer is the on-chain ed25519 key. Rotate
  freely; the peer list does not change.

A missing or unreadable certificate file aborts startup. It never degrades
to running without authentication.

## `signer-server` configuration

| variable | meaning |
|---|---|
| `GLC_SIGNER_VALIDATOR_KEYPAIR_PATH` | this validator's ed25519 key. **Singular** — a process holding several federation identities is the topology Phase 7c retired |
| `GLC_SIGNER_LISTEN_ADDR` | `host:port` to serve on |
| `GLC_FEDERATION_CA_CERT_PATH` | the federation CA; client certificates are required against it |
| `GLC_SIGNER_TLS_CERT_PATH` / `GLC_SIGNER_TLS_KEY_PATH` | this process's leaf certificate and key |
| `GLC_DB_PATH` | this operator's own indexer database |
| `GLC_PROGRAM_ID_HEX` | the on-chain program, hex-encoded |
| `GLC_SOLANA_RPC_URL` | for observing the validator epoch |
| `GLC_SOLANA_COMMITMENT` | `processed` \| `confirmed` \| `finalized`; no default, by design |

### Vault signing (Phase 7e) — optional, but all-or-nothing

Set these only if this signer holds a vault key. If `GLC_VAULT_REDEEM_SCRIPT_HEX`
is unset the signer serves mint requests only and **refuses every payout
request**; if it is set, all of the following are required.

| variable | meaning |
|---|---|
| `GLC_VAULT_REDEEM_SCRIPT_HEX` | the vault's redeem script |
| `GLC_SIGNER_VAULT_INDEX` | this signer's position in the vault's ordered signer list |
| `GLC_SIGNER_VAULT_KEY_PATH` | file containing this signer's WIF vault key — **one key** |
| `GLC_SIGNER_GLC_RPC_URL` / `_USER` / `_PASSWORD` | **this signer's own Goldcoin node** |

### Completion attestation (Phase 7f)

`GLC_WITHDRAWAL_CONFIRMATION_DEPTH` and `GLC_PROTOCOL_VERSION` enable the
completion arm. Without the depth set, the signer **refuses every completion
request** and logs a warning at startup.

There is deliberately **no separate completion depth** (ADR-0018 Q2): the
depth that governs treating a payout as confirmed locally is the same one
that gates a completion signature. Two knobs could be configured
inconsistently, and the dangerous direction is silent — an operator could
complete on-chain something they do not consider confirmed locally, and
nothing would report the contradiction.

The completion arm uses the **same** Goldcoin node as the payout arm, and
for the same reason: a completion attestation is the last word on whether a
payment happened, so inheriting the requester's view would make the check
circular.

Startup **proves** the key on disk is the key the vault expects at
`GLC_SIGNER_VAULT_INDEX`, and aborts on any mismatch. A misconfigured
operator cannot silently participate — that check is what makes it safe to
keep the identity-to-position mapping in configuration rather than on-chain
(ADR-0017 E1).

> ### The signer's Goldcoin node MUST NOT be the relayer's
>
> This is a **hard requirement**, not a tuning choice (ADR-0017 E2).
>
> A signer validates a payout against its **own** UTXO view. That is the
> only defence that exists: the legacy Goldcoin sighash does **not** commit
> to input amounts, so a signature proves nothing about what an input was
> worth. A signer pointed at the relayer's node inherits the requester's
> view of the chain and the check becomes circular.
>
> The process cannot detect a shared endpoint, so it logs the Goldcoin RPC
> URL at startup. Check it in deployment review.

Startup **fails closed**: it aborts unless every value is present and valid,
the TLS material loads, and the on-chain validator epoch can actually be
read. A signer that has never observed the epoch has nothing meaningful to
compare a request against.

At runtime the epoch is re-polled every 10s. If polling fails for longer
than 60s the view goes stale and **every** request is refused until the link
recovers — a validator that cannot see the chain cannot tell a current epoch
from a superseded one, and must not authorize under a federation revision it
may have fallen behind.

## `glc-relayer` federation configuration

| variable | meaning |
|---|---|
| `GLC_FEDERATION_PEERS` | comma-separated `base58pubkey@uri` |
| `GLC_FEDERATION_CA_CERT_PATH` | the federation CA |
| `GLC_RELAYER_TLS_CERT_PATH` / `GLC_RELAYER_TLS_KEY_PATH` | this relayer's client certificate and key |
| `GLC_FEDERATION_TLS_DOMAIN` | the name peer certificates must be issued for |
| `GLC_FEDERATION_TLS` | set to `off` for loopback/regtest only; logs a warning every start |
| `GLC_VAULT_SIGNER_MAP` | `index:base58pubkey,...` — which validator holds which vault position (Phase 7e) |
| `GLC_RELAYER_VALIDATOR_PUBKEY` | **this** relayer's federation identity (Phase 7g) |
| `GLC_PAYOUT_BUILD_TIMEOUT_SECS` | failover: seconds before a non-designated operator may build (default 120) |
| `GLC_MINT_SUBMIT_TIMEOUT_SECS` | failover: seconds before a non-designated operator may submit a mint (default 60) |

`GLC_VAULT_SIGNER_MAP` is validated against the configured redeem script at
startup and **fails closed**: every vault position must be mapped, no
position may be claimed twice, and no validator may hold two positions. A
gap would make some designated quorum resolve to nobody and look like a
permanent outage; one validator holding two positions would let it satisfy
an M-of-N by itself, which is the entire property the vault exists to
prevent.

The pubkey in each peer entry is the on-chain identity that endpoint must
answer as. A response claiming any other identity is discarded even if its
TLS handshake was perfect, so a compromised endpoint cannot impersonate
another member.

The peer list must not contain this validator's own identity, and must not
contain duplicates. Both are rejected at startup: either would inflate
apparent agreement by counting one party twice.

> **Note:** `GLC_SOLANA_VALIDATOR_KEYPAIR_PATHS` no longer exists. The
> relayer holds no validator key; configuring it with paths to them invited
> operators to place federation key material in the wrong process.

## Running several relayers at once (Phase 7g)

`GLC_RELAYER_VALIDATOR_PUBKEY` states which federation member this relayer
acts as. It is **never derived**, and startup fails closed if it appears in
`GLC_FEDERATION_PEERS` (peers are the *others*) or is absent from
`GLC_VAULT_SIGNER_MAP` (which is what gives this relayer its operator index).

Work is assigned by arithmetic — `index mod N` — so every operator computes
the same answer without exchanging a message. There is no election, no lock,
and no shared database.

**Only the designated operator builds a payout.** Others stay passive: they
do not build and therefore do not reserve UTXOs, then adopt the designated
builder's proposal when asked to sign it — after independently validating
every field against their own state. This is not politeness. Phase 7g
measured two operators building *different* transactions purely because they
observed withdrawals in a different order, and speculative reservation was
the cause ([ADR-0019](adr/0019-multi-relayer-operation.md) §2.1).

If the designated operator is down, the others take over after the failover
window, so one dead operator cannot strand a withdrawal.

> ### Duplicate payouts are NOT harmless
>
> Duplicate *mints* are — the claim PDA's `init` prevents a double-mint and
> only fees are wasted. Duplicate *payouts* are not: Phase 7g measured two
> operators paying the same withdrawal twice. ADR-0014 §10 previously said
> otherwise and has been corrected in place (§10.1).
>
> Three things stop it, in order: Phase 7e's signer check (**primary**),
> Phase 7f's completion plus the discovery filter, and Phase 7g's
> pre-broadcast on-chain status check. The first lives in the *signer*
> process — a different process from the executor that would cause the harm.

## Health and metrics (Phase 7h)

Set `GLC_OPS_LISTEN_ADDR` to expose two read-only endpoints:

| path | purpose |
|---|---|
| `/health` | one line per invariant; **503** when any is breached |
| `/metrics` | Prometheus text exposition |

The relayer **exposes state and pages nobody**. There is no SMTP, PagerDuty,
webhook, or vendor SDK in it, and it holds no alerting credentials. Point
your existing uptime monitoring at `/health` — a breach turns it 503.

> ### Bind it privately
>
> There is **no authentication**, because adding one would mean this process
> holding another secret. The endpoint reveals balances, supply and
> per-state counts. Bind it to a loopback or private interface behind your
> own proxy. The relayer logs the bind address at startup with a warning so
> a mistake is visible in review.
>
> Leaving `GLC_OPS_LISTEN_ADDR` unset is allowed but logged loudly: a bridge
> nobody can observe should not be live.

### The two numbers that must be zero

| metric | meaning |
|---|---|
| `glc_solvency_breach_atomic` | wrapped supply beyond `deposits − payouts`. Measured to have **zero normal slack**, so any value here is real |
| `glc_vault_unexplained_drift_atomic` | vault shortfall that recorded fees do **not** explain |

### The number that grows on purpose

`glc_vault_fee_drift_atomic` tracks `glc_vault_fees_paid_atomic`. ADR-0013 D3
makes the vault absorb payout fees, so the vault sits below the backing bound
by the cumulative fee and **that gap grows with every payout**. It is not a
solvency failure ([ADR-0020](adr/0020-solvency-monitoring-and-fee-drift.md)) —
it is the amount you replenish from an external fee reserve. Watch its slope,
not its existence.

## What a peer's answer means

| outcome | meaning | retry? |
|---|---|---|
| signature | that validator independently derived the same bytes | — |
| **refusal** | that validator's view of the chain **disagrees with yours** | **no** — asking again gets the same answer |
| payout shortfall | a designated signer did not answer | yes, but see below |
| completion shortfall | peers have not yet confirmed the payout at depth | yes — ordinary, not an alarm |
| unavailable | unreachable, timed out, throttled, or answered unusably | yes, next tick |

A refusal is an alarm, not noise. It means two operators' independent views
of the chain have diverged, which is a bug, an outage, or an attack. Falling
short of threshold, by contrast, is an ordinary outcome that the next tick
retries.

**Payouts differ in one important way.** Only the *designated* quorum is
asked, because the Goldcoin txid depends on which quorum signs. If a
designated signer stays unavailable, the payout does **not** silently move to
another signer — it waits until an operator performs an explicit, audited
quorum reassignment (ADR-0015). That is deliberate: substituting a signer
would change the txid, and the txid is what the recovery model reconciles
against.

## Operational bounds

- **per-peer timeout** 5s, **round ceiling** 20s. One slow peer cannot stall
  a mint that the others were ready to authorize.
- **rate limit** 30 burst, 10/s sustained, per peer. The burst allowance
  matters: a relayer catching up after a restart legitimately asks about
  every pending deposit at once.
- Collection **stops as soon as threshold is reached**, and asks **every**
  peer rather than only the first M, so one dead peer does not cost a round.

## Verifying a deployment

The transport is covered end-to-end in
`relayer/tests/federation_transport.rs`, which stands up real servers with
real certificates and proves — by observation, not inspection — that a
client with no certificate, a client certificate from another CA, and a
server certificate from another CA are all rejected, and that a peer
answering as a different validator is discarded despite a valid handshake.

Run it before trusting a change to this path:

```
cd relayer && cargo test --test federation_transport
```
