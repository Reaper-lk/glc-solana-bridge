# ADR-0014: Phase 7 — production federation, custody, and deployment model

- Status: **Proposed** (design only — awaiting owner approval; no code written)
- Phase: 7
- Supersedes: nothing. Constrains ADR-0005, ADR-0007, ADR-0010, ADR-0012, ADR-0013.

## Context

Phases 0–6 delivered a complete bridge flow that works end to end against a
real Goldcoin regtest node and a real `solana-test-validator`: deposit →
mint → burn → payout. Every value-moving path is implemented and tested.

None of it is safe for real funds. Three phases deliberately shipped
test-only stand-ins for the parts that custody decisions were blocking:

- **ADR-0012 (R2)** — one relayer process holds *every* validator private
  key and signs with all of them. Explicitly documented as bootstrap
  topology, not the production federation design.
- **ADR-0013 (D2)** — the Goldcoin vault is a single-key P2PKH address whose
  key lives in the node wallet. One key can drain it.
- **ADR-0013 (D1)** — withdrawal completion is tracked off-chain only;
  `WithdrawalRequest.status` stays `Pending` forever.

Phase 7 designs what replaces them, plus the governance, operational, and
deployment model required before any public or real-fund launch.

This ADR is a **specification**. It commits to no implementation.

---

## 1. Findings that constrain this design

Four facts were established by reviewing the existing ADRs, program source,
and relayer implementation. Each materially shapes what follows, and each
contradicts something a reasonable reader might otherwise assume.

### F1 — Governance was never hardened, and an ADR claims it was

ADR-0007 states that threshold-gated + timelocked governance "arrives with
proof verification in Phase 3." **It did not arrive.** Phase 3 delivered
proof verification for `mint_wrapped` only. Governance today is unchanged
from Phase 1:

- `update_validator_set` is gated by `bridge_config.admin == admin.key()`
  (`programs/glc-bridge/src/instructions/admin.rs`);
- no timelock construct exists anywhere in the program;
- `set_paused`, `transfer_admin` and rotation are all single-key.

Because the validator set *is* the mint authority, **the admin key is an
indirect infinite-mint capability**. An attacker holding it rotates the
federation to keys they control and mints without limit. This is live in
the current code and is the single most severe pre-launch gap. It also
means the project's "federated, not custodial" description is not yet
accurate.

`docs/threat-model.md` already lists this ("Admin rotates validator set to
attacker keys") as an *unchanged interim risk since Phase 1*. Phase 7 must
close it.

### F2 — The signing threshold has a hard protocol ceiling

ADR-0010 measured, rather than estimated, the transaction-size bound: each
ed25519 signature entry costs **110 bytes** in the precompile payload
(64 signature + 32 pubkey + 14 offsets), plus a fixed ~168 bytes of header
and shared message. With `mint_wrapped`'s account keys:

- a **legacy transaction fits M ≤ 4** signatures;
- **v0 transactions with address lookup tables reach M ≈ 6–7**.

`MAX_VALIDATORS = 16` bounds N, but **M is bounded far more tightly than N**.
A 5-of-9 federation cannot submit a mint in a legacy transaction at all.

This is a liveness bound, not a safety bound (too-large M means mints stall,
never mint wrongly), but it constrains the production topology before any
other decision. Federation size must be chosen inside this envelope, or
ADR-0005's documented fallback (on-chain vote accumulation) must be
revisited — which would supersede ADR-0005 and is a protocol redesign, not
a configuration change.

### F3 — Withdrawal completion needs no account migration

`WithdrawalRequest.reserved` is 48 bytes, and `state.rs` records that it was
sized deliberately: *"Expansion space — sized so the future payout record
(GLC payout txid 32B + confirmation slot/depth 8B) fits without migration."*

Further, the pieces already exist:

- `WithdrawalStatus` has `Pending` / `Broadcast` / `Completed` with stable
  borsh tags 0/1/2, pinned by a unit test;
- `shared::claim::ACTION_MINT_DEPOSIT = 0x01` is documented as leaving room
  for new action types, with `0x00` deliberately never valid.

Completion therefore slots into existing structure using the existing
ed25519-precompile verification machinery. It is additive, not a migration.

### F4 — The P2SH multisig spend path is unverified  *(CLOSED in 7b)*

`docs/goldcoin-rpc-notes.md` lists P2SH multisig vault construction under
"Not yet verified / explicitly out of scope." What *is* verified is that
`createmultisig` exists and produces **Goldcoin-specific `Q`-prefixed**
addresses — neither Bitcoin mainnet's `3` nor testnet's `2`.

Goldcoin is a Litecoin-lineage fork that has already produced several
non-obvious divergences from Bitcoin assumptions (undocumented regtest,
non-standard ports, boolean-only `getblock` verbosity, absent
`scantxoutset`, absent `signrawtransactionwithwallet`, unusable regtest fee
estimation). **No production vault design may be finalised on the
assumption that P2SH multisig spending behaves as it does in Bitcoin.** A
real M-of-N spend must be executed on regtest first.

**Resolved 2026-07-31 (Phase 7b).** A real 2-of-3 P2SH spend was executed
against a live regtest node with independently-held keys: partial signing
returns `complete: false`, the partial is rejected by the network (`-26`), a
second independent signature completes it, and the payout confirms. Full
observations are recorded in `goldcoin-rpc-notes.md`. Three of them changed
this design and are captured in §8.8 below.

---

## 2. Proposed scope

**The Phase 7 objective as stated is too large for a single phase.** It
spans on-chain program changes, a new network service, a key-generation
ceremony, operational tooling, an external audit, and a staged mainnet
rollout. Delivering them as one unit means the audit reviews a moving
target, and the riskiest item (custody) competes for attention with the
most mechanical one (metrics).

### Recommendation: five gated sub-phases

| Sub-phase | Deliverable | Exit gate |
|---|---|---|
| **7a — Governance** | Threshold-gated + timelocked governance; single-admin rotation removed | F1 closed: no single key can rotate validators or unpause |
| **7b — Vault custody** | Real P2SH M-of-N spend verified on regtest; ceremony design; isolated signer | F4 closed: a real multisig payout confirmed on regtest |
| **7c — Federation networking** | mTLS gRPC signature exchange; one key per operator; R2 and D2 retired | No process holds more than one validator key |
| **7d — Completion + multi-relayer** | `complete_withdrawal`; deterministic executor assignment | On-chain status advances; two executors provably cannot diverge |
| **7e — Operations + rollout** | Monitoring, runbooks, reconciliation, canary stages | External audit passed and remediated |

Ordering rationale: **7a first** because F1 is live today, is self-contained,
and every later stage's threat model assumes it is already fixed. **7b
second** because F4 blocks the ceremony, which has the longest lead time.
7c and 7d may proceed in parallel once 7a lands. 7e gates launch.

### Explicitly out of scope for Phase 7

- Any change to the deposit claim message format (ADR-0010) — it is a
  signature-breaking protocol event and nothing here requires it.
- Migration of `MAX_VALIDATORS` beyond 16.
- Non-P2PKH deposit vault matching (Phase 4 owner decision U5 stands).

---

## 3. Files that would change

### New — on-chain program

| File | Purpose |
|---|---|
| `programs/glc-bridge/src/instructions/governance.rs` | Timelocked, threshold-gated validator rotation, pause, and admin handover |
| `programs/glc-bridge/src/instructions/complete_withdrawal.rs` | Federation-signed withdrawal completion |
| `shared/src/governance.rs` | Canonical governance-action message (`ACTION_ROTATE_VALIDATORS`) |

### Modified — on-chain program

| File | Change |
|---|---|
| `programs/glc-bridge/src/state.rs` | New `PendingGovernanceAction` PDA; consume `WithdrawalRequest.reserved` for the payout record; `BridgeConfig` TVL-cap field |
| `programs/glc-bridge/src/instructions/admin.rs` | Single-key rotation path deleted; replaced by the governance flow |
| `programs/glc-bridge/src/instructions/mint_wrapped.rs` | Enforce total-supply (TVL) cap |
| `shared/src/claim.rs` | `ACTION_COMPLETE_WITHDRAWAL = 0x02`; completion message builder + golden vector |
| `programs/glc-bridge/src/lib.rs`, `errors.rs`, `events.rs` | New instruction surface, errors, events |

### New — relayer

| File | Purpose |
|---|---|
| `relayer/src/p2p/{server,client,proto,identity}.rs` | mTLS gRPC signature exchange (replaces the Phase 0 placeholder) |
| `relayer/src/signer/isolated.rs` | Vault signing via an isolated signer process, not the node wallet |
| `relayer/src/coordination.rs` | Deterministic submitter/executor assignment with timeout failover |
| `relayer/src/ops/metrics.rs` | Prometheus metrics surface |
| `relayer/src/ops/reconcile.rs` | Vault-balance and wrapped-supply invariant reconciliation |
| `relayer/src/ops/integrity.rs` | Offline database auditor (re-verifies stored commitments) |

### Modified — relayer

| File | Change |
|---|---|
| `relayer/src/signer/mod.rs` | **Delete multi-key loading (R2)**; one key per process |
| `relayer/src/withdrawal/adapter.rs` | **Delete `signrawtransaction` node-wallet path (D2)**; call the isolated signer |
| `relayer/src/orchestrator.rs` | Submitter assignment; request peer signatures instead of signing locally |
| `relayer/src/withdrawal/executor.rs` | Federation-signed payout intent; submit `complete_withdrawal` |
| `relayer/src/main.rs` | Wire p2p server, isolated signer, metrics |
| `relayer/Cargo.toml`, `deny.toml` | gRPC/TLS dependencies and their licence/advisory review |

### Documentation

New: ADR-0015 (vault custody), ADR-0016 (federation networking), ADR-0017
(completion instruction), ADR-0018 (multi-relayer coordination),
`docs/ceremony.md`, `docs/production-config.md`, `docs/runbooks/*.md`.

Updated: `custody.md` (decisions #1–#5, #7, #9), `threat-model.md`,
`architecture.md` (phase table and topology), `goldcoin-rpc-notes.md`
(P2SH multisig spend facts once verified).

---

## 4. Architecture

### 4.1 Production topology

Each operator runs an independent stack. No shared secrets, no shared
database, no shared node.

```
        Operator A                Operator B                Operator C
  ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
  │ goldcoind (own)  │      │ goldcoind (own)  │      │ goldcoind (own)  │
  │ solana RPC (own) │      │ solana RPC (own) │      │ solana RPC (own) │
  │ relayer          │      │ relayer          │      │ relayer          │
  │  ├ indexer       │      │  ├ indexer       │      │  ├ indexer       │
  │  ├ orchestrator  │      │  ├ orchestrator  │      │  ├ orchestrator  │
  │  ├ executor      │      │  ├ executor      │      │  ├ executor      │
  │  └ sqlite (own)  │      │  └ sqlite (own)  │      │  └ sqlite (own)  │
  │        │         │      │        │         │      │        │         │
  │  ┌─────▼──────┐  │      │  ┌─────▼──────┐  │      │  ┌─────▼──────┐  │
  │  │ ISOLATED   │  │      │  │ ISOLATED   │  │      │  │ ISOLATED   │  │
  │  │ SIGNER     │  │      │  │ SIGNER     │  │      │  │ SIGNER     │  │
  │  │ ed25519 #A │  │      │  │ ed25519 #B │  │      │  │ ed25519 #C │  │
  │  │ vault sk#A │  │      │  │ vault sk#B │  │      │  │ vault sk#C │  │
  │  └────────────┘  │      │  └────────────┘  │      │  └────────────┘  │
  └────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
           │                         │                         │
           └───────── mTLS gRPC: signatures only ──────────────┘
                                    │
                   ┌────────────────▼─────────────────┐
                   │ ARBITERS (never the p2p layer):  │
                   │  • the Goldcoin UTXO set          │
                   │  • the Anchor program's threshold │
                   └───────────────────────────────────┘
```

### 4.2 The trust boundary

This is the load-bearing property of the whole federation design:

```
  peer request ──► "please sign message M"
                        │
                        ▼
          ┌──────────────────────────────┐
          │ Validator INDEPENDENTLY       │ ◄── its OWN goldcoind
          │ derives M' from its own chain │ ◄── its OWN Solana RPC
          │ observations. It does not     │
          │ parse or trust the requester's│
          │ claim about the world.        │
          └───────────────┬───────────────┘
                    M' == M ?
                  ┌────────┴────────┐
                yes                 no
                 │                   │
            sign M'          refuse + ALARM
```

The p2p layer **moves signatures, never truth** — the constraint already
recorded in `relayer/src/p2p/mod.rs` from Phase 0. A fully compromised
requester cannot induce a signature over anything a validator has not
independently verified against its own nodes. A refusal is therefore an
alarm, not noise: it means two operators' views of the chain disagree,
which is either a bug or an attack.

### 4.3 Signing separation

```
  relayer (network-facing, holds no keys)
      │  canonical intent (domain-tagged, deterministic)
      ▼
  isolated signer (no inbound network, holds one key)
      │  1. re-derives the transaction from the intent
      │  2. verifies destination / amount / change against its OWN node
      │  3. refuses on any mismatch
      ▼
  partial signature
```

The relayer never holds the vault key. Phase 6's
`signrawtransaction`-on-the-node-wallet path is deleted.

---

## 5. Production validator topology

### 5.1 One key per operator

`signer::load_validator_keypairs` accepting multiple keys (ADR-0012, R2)
is deleted. Each relayer process loads exactly one validator identity, and
that key lives in the isolated signer, not the relayer.

### 5.2 Federation size

Bounded by F2. Candidate shapes, all within `MAX_VALIDATORS = 16`:

| Shape | Legacy tx | v0 + ALT | Notes |
|---|---|---|---|
| 3-of-5 | ✅ | ✅ | Fits everywhere; modest collusion resistance |
| 4-of-7 | ✅ (at the limit) | ✅ | Maximum M for legacy transactions |
| 5-of-9 | ❌ | ✅ | **Requires v0 + address lookup tables** |
| 7-of-11 | ❌ | ✅ (at the limit) | At the measured v0 ceiling |

M and N are owner decisions (custody #1). The transaction format is a
coupled decision that must be made at the same time.

### 5.3 Signature request/response protocol

1. A validator observes a mintable deposit (or a payable withdrawal) on its
   own nodes and derives the canonical message itself.
2. The designated submitter requests signatures from peers.
3. Each peer independently re-derives the message and signs **only** if it
   matches byte for byte.
4. The submitter aggregates and submits once the threshold is met.

The relayer already performs the local half of step 3 correctly: ADR-0012's
reload-and-recompute safeguard and ADR-0013's pre-signing guard sequence
both recompute canonical bytes from persisted state and refuse on
mismatch. Phase 7 extends the same discipline across the network boundary.

### 5.4 Replay protection

Four independent layers:

1. the canonical message binds protocol version, program id, **epoch**,
   action type, and the full claim identity (ADR-0010) — a signature
   authorises exactly one action on one identity under one federation
   revision;
2. `request_id` nonce per request;
3. `expiry` bounds the acceptance window;
4. a persistent per-validator seen-set keyed by message hash: an identical
   re-request returns the *same* signature idempotently, while a *different*
   message for the same logical identity is refused and alarmed.

### 5.5 Validator-set rotation

Rotation remains the epoch-bumping singleton PDA of ADR-0007, but its
**authority changes** (see §7). Because epoch is inside the signed bytes, a
rotation strictly invalidates every in-flight proof — already implemented
and tested since Phase 3. Rotation procedure:

1. propose (threshold-signed) → 2. timelock elapses → 3. execute →
4. epoch increments → 5. in-flight proofs die → 6. relayers re-sign.

### 5.6 Offline validators, quorum, and liveness

- Fewer than M available ⇒ **mints and payouts stall**. They never proceed
  incorrectly. This is the intended failure mode.
- N − M is the outage budget. `3-of-5` tolerates 2 offline; `4-of-7`
  tolerates 3.
- A returning validator catches up **from chain state alone** — never from
  peers. This is the Phase 0 p2p constraint and is what makes an offline
  operator recoverable without trusting anyone.
- Sustained inability to reach threshold is an alerting condition, and at
  extended duration a pause condition.

---

## 6. Validator networking

### 6.1 Transport: gRPC over mTLS. libp2p rejected.

| Option | Assessment |
|---|---|
| **gRPC + mTLS** ✅ | Static, known, ≤16 peers. Standard ops tooling, pinned certificates, straightforward audit. Adds `tonic`/`rustls` to the dependency graph. |
| libp2p ❌ | Its value (discovery, NAT traversal, transport agility) is unneeded for a fixed known set, while its dependency surface is large against a `deny.toml` already strained by `solana-client`. Adds a second peer-identity model to reason about. |
| Plain HTTPS ❌ | Would work, but loses the schema discipline gRPC gives the message contract. |

Dependency review is a required part of 7c: `cargo-deny` must pass, and the
existing `webpki-roots` caveat from Phase 5 (feature unification pulling the
bundled CA list into the shared `reqwest` build) should be revisited at the
same time.

### 6.2 Peer authentication — dual binding

Identity is bound twice, and both must agree:

1. **Transport**: mTLS with pinned client certificates.
2. **Application**: every request and response carries a signature by the
   peer's **on-chain ed25519 validator key**.

Certificate rotation therefore cannot silently change which federation
member a peer believes it is talking to, and a stolen certificate alone
does not let an attacker impersonate a validator.

### 6.3 Message formats

```
SignRequest {
    request_id:        [u8; 16],
    epoch:             u64,
    action:            u8,            // 0x01 mint, 0x02 completion, 0x03 governance
    canonical_message: bytes,         // exact bytes to be signed
    context:           bytes,         // identity hints for independent re-derivation
    expiry_unix:       i64,
    requester_sig:     [u8; 64],
}

SignResponse { request_id, validator_pubkey, signature }
Refusal      { request_id, reason_code, detail }
```

`canonical_message` is **checked, never trusted**: the responder re-derives
it and compares. `context` only helps the responder locate the same facts.

### 6.4 Retries, deduplication, rate limiting, DoS

- Retries are safe by construction: an identical request returns the same
  signature (seen-set), so retry storms cost verification, not correctness.
- Per-peer token-bucket rate limits; bounded concurrent verifications;
  request size caps.
- Unknown peers are rejected at the TLS layer before any application work.
- Signing is cheap only *after* independent verification, and verification
  is bounded by the validator's own chain access — so an attacker cannot
  amplify work beyond that peer's rate limit.

### 6.5 Audit logging

Every request, decision, and refusal is appended with its message hash,
peer identity, epoch, and outcome, shipped off-host. Refusals page.

---

## 7. Governance (closes F1)

### 7.1 Decision

Replace single-key governance with **threshold-signed + timelocked**
governance. Both properties, not either:

- **threshold-signed** so no single key is an indirect mint capability;
- **timelocked** so a rotation is publicly visible before it takes effect,
  giving users and operators a window to react to a hostile proposal.

### 7.2 Mechanism

A new `PendingGovernanceAction` PDA holds a proposed action, the earliest
execution timestamp, and the epoch it was proposed under.

```
propose_governance_action(action, params)   // M-of-N proof, ACTION_ROTATE_VALIDATORS
        │  creates PendingGovernanceAction { eta = now + TIMELOCK }
        ▼
   ... timelock window (publicly observable) ...
        │
execute_governance_action()                  // permissionless once eta passes
        │  applies the action, increments epoch, closes the PDA
        ▼
cancel_governance_action()                   // M-of-N proof, any time before eta
```

The proof mechanism is exactly ADR-0010's: an ed25519-precompile
instruction immediately preceding, verified against the *current*
`ValidatorSet`. This reuses audited machinery rather than inventing a
second authorization path.

### 7.3 Pause is deliberately asymmetric

- **Pausing** should be fast — a lower threshold, no timelock, because a
  false pause is recoverable and a slow pause during an incident is not.
- **Unpausing** should be slow — full threshold plus timelock, because a
  hostile unpause is how an attacker resumes draining.

Exact thresholds are custody decision #7 and remain open.

---

## 8. Goldcoin vault custody

### 8.1 Decision: P2SH M-of-N script multisig. TSS rejected for now.

| Option | Assessment |
|---|---|
| **P2SH multisig** ✅ | `createmultisig` verified present. Script-level and auditable; recoverable by any operator from seeds + the redeem script; no novel cryptography. Costs: larger transactions, N visible on-chain. |
| Threshold ECDSA (GG20 / FROST) ❌ | Smaller footprint and better privacy, but introduces a large, hard-to-audit cryptographic dependency, a distributed key-generation ceremony, and share-refresh procedures. Recovery from partial share loss is materially harder. Not justified while script multisig works. |
| Single key ❌ | The Phase 6 D2 stand-in. Not viable for real funds. |

### 8.2 Blocking prerequisite (F4)

Before any ceremony is planned, 7b must execute on regtest:

1. `createmultisig` an M-of-N script and confirm the `Q`-prefixed address;
2. fund it;
3. construct a spend, partially sign it on **separate** signers, combine;
4. broadcast, confirm, and verify the funds arrived;
5. record every observed fact in `goldcoin-rpc-notes.md`.

Until this is done, the vault design is unvalidated.

### 8.3 Key generation ceremony

- Air-gapped machines; per-operator BIP32 seeds generated offline and never
  transmitted in any form.
- Each operator publishes an xpub **plus an attestation signed by their
  on-chain validator key**, binding the two identities.
- The redeem script is assembled from published xpubs and independently
  re-derived by every operator; the resulting address must be confirmed
  byte-identical by all before any funds move.
- Video-witnessed with a signed transcript retained by every operator.

### 8.4 Backup and recovery

- Shamir 2-of-3 per operator, geographically separated, tamper-evident.
- **Annual restore drills that actually reconstruct a key and sign a test
  transaction.** A backup that has never been restored is not a backup.
- The redeem script itself is published and archived — losing it makes
  otherwise-recoverable keys useless.

### 8.5 HSM and isolated signers

Hardware signers (YubiHSM 2, Ledger, or equivalent) per operator, with one
caveat that must not be assumed away: **Goldcoin's derivation paths and
address version bytes must be verified against the chosen device**, not
inferred from Bitcoin support. This lineage has already produced multiple
non-obvious divergences (F4). If no device supports it correctly, the
fallback is an air-gapped signer machine with the same isolation
properties.

### 8.6 Separation of duties

Deposit observation (indexer, network-facing) and payout signing (isolated,
no inbound network) are separate processes with separate trust levels. The
signer accepts only a canonical payout intent and independently verifies it
against its own node before signing.

### 8.7 Compromise response

- **One key**: pause → rotate the validator set (§7) → sweep the vault to a
  freshly generated script → post-mortem.
- **M keys**: funds are gone. This is the irreducible risk of a federated
  bridge and must be stated plainly in user-facing material.
- Rotation and sweep procedures must be **rehearsed on testnet**, not
  written and filed.

#### 8.7.1 Executability (Phase 7i-0, 2026-08-01)

When this section was written, none of "rotate" or "sweep" could actually be
performed by the running system: `signer-server` had no governance RPC, and
the vault sweep had no implementation anywhere. The response above was
therefore documented but not available.

Both are implemented as of Phases 7i-0 and 7i-1 (**ADR-0021**, **ADR-0022**):
`SignGovernance` plus `glc-admin approve-rotation` / `submit-rotation` /
`execute-rotation` for the rotation, and `SignSweep` plus `glc-admin
sweep-plan` / `sweep-approve` / `sweep-execute` for the sweep. The pause step
is `glc-admin pause`, which had no caller at all until 7i-1 and remains
gated by the interim single admin key (ADR-0022 §6, custody #7 OPEN). Authorisation for
both is by **operator-staged approval** rather than derivation, because
neither has an on-chain fact to derive from — see ADR-0021 §4.

The rehearsal requirement stands and is not yet met.

---

### 8.8 Designated signing quorum (owner decision, 2026-07-31)

Verifying F4 surfaced a direct contradiction with the shipped Phase 6
recovery model, which ADR-0014 had not anticipated.

**The problem.** ADR-0013 persists a payout's txid *before* broadcasting it,
and that durable txid is the only mechanism for reconciling a lost broadcast
response. With a single-key vault the txid is known the moment the
transaction is built. With M-of-N it is not: measured on a real node, the
same inputs and outputs signed by different quorums produce different txids
(signing *order* is irrelevant; signing *set* is not). If two overlapping
quorums each complete, two valid transactions exist spending the same
inputs — only one can confirm, and the executor may have persisted the
other.

**Decision: the signing quorum is designated explicitly inside the signed
payout intent.** The intent names exactly which M validators will sign, so
the resulting txid is determined before any signature is collected and the
Phase 5/6 "persist the txid before broadcast" model survives unchanged.

**Reassignment is explicit, never implicit.** If a designated signer is
unavailable, the executor does not silently fall back to another quorum. A
**new** intent is issued, carrying an incremented `quorum_attempt`, which
produces a different commitment and therefore a different set of signatures.
The superseded intent is recorded, not overwritten, so the reassignment is
auditable; and because the attempt counter is part of the committed bytes, a
signature gathered for one quorum can never be replayed into another.

Options rejected:

- *First-M-to-respond*: simpler collection, but erodes the durable-txid
  invariant that Phases 5 and 6 were built and mutation-tested around, and
  admits a window in which two quorums both complete.
- *Deterministic quorum by rule* (e.g. lowest M indices to respond within a
  timeout): avoids negotiation but makes failover semantics subtle and
  leaves the txid undetermined until the timeout resolves.

### 8.9 Consequences for the Phase 6 executor

Three shipped behaviours are incompatible with a production vault and must
change in 7b:

1. `RealPayoutRpc::list_unspent` filters on `spendable`. For a vault the
   local node cannot solve alone this is always false, so the executor would
   see an empty vault and never pay out. The correct filter is `solvable`.
2. `sign_raw_transaction` is called as `signrawtransaction(hex)`. Signing
   for a P2SH vault requires explicit `prevtxs` carrying the `redeemScript`.
3. The vault is configured as a single P2PKH address. It becomes a multisig
   descriptor: redeem script, M, N, and the ordered signer pubkeys.

## 9. Withdrawal completion (closes D1)

### 9.1 Instruction

```rust
complete_withdrawal(
    index:          u64,
    payout_txid:    [u8; 32],
    payout_height:  u64,
    epoch:          u64,
)
```

Authorised by the same ed25519-precompile M-of-N proof as `mint_wrapped`
(ADR-0010). No new authorization mechanism is introduced.

### 9.2 Canonical message

`shared::claim`, with `ACTION_COMPLETE_WITHDRAWAL = 0x02` (0x01 remains
deposit mint; 0x00 stays permanently invalid):

```
"GLC_BRIDGE_CLAIM"(16) ‖ protocol_version(1) ‖ program_id(32) ‖ epoch(8)
  ‖ action = 0x02 (1) ‖ withdrawal_index(8) ‖ payout_txid(32)
  ‖ payout_height(8) ‖ amount(8) ‖ dest_hash160(20)
```

Binding `amount` and `dest_hash160` means a signature authorises completion
of **one specific payout**, not merely "index N is finished." Pinned by a
golden-vector test, as the deposit message already is.

### 9.3 Status transitions — append-only

```
Pending ──(M-of-N proof)──► Completed          [terminal]
Pending ──(M-of-N proof)──► Broadcast ──► Completed
```

Any call against a record already `Completed` fails. **The status field is
itself the replay guard**, structurally identical to the claim PDA's `init`
constraint (ADR-0003) — no lookup table, no scan.

### 9.4 Storage (F3)

`payout_txid` (32B) and `payout_height` (8B) are written into the pre-sized
`reserved` field. **No account migration, no `PROTOCOL_VERSION` bump.**

### 9.5 Completion is irreversible, deliberately

A reversal path would let anyone able to force a Goldcoin reorg
*un-complete* a withdrawal and induce a second payout — strictly worse than
the problem it solves.

Instead: validators sign completion only at or beyond the production
withdrawal confirmation depth, and a reorg deeper than that **after**
completion is a halt-and-reconcile incident requiring operator judgement,
not an automatic on-chain state change.

### 9.6 What this does and does not fix

It restores ADR-0006's "reconstruct the outstanding queue from chain state
alone" property for the payout half, which D1 had weakened: a fresh relayer
with no database can once again distinguish paid from unpaid withdrawals.

It does **not** make the relayer database disposable — local state remains
the record of in-flight work between broadcast and completion.

---

## 10. Multiple relayers and executors (closes D8)

**Leaderless, with deterministic assignment and timeout failover.** No
election protocol, no distributed lock, no shared database.

| Concern | Mechanism |
|---|---|
| Observation and signing | Fully parallel — every validator independently observes and signs. This *is* the federation model. |
| Mint submission | Designated submitter = `deposit_id mod N`; others wait `T_submit` then any may submit. Duplicate **mints** are harmless — the claim PDA's `init` prevents double-mint (ADR-0003); only fees are wasted. |
| Payout construction | Designated builder = `withdrawal_index mod N`, with `T_build` failover. |
| **Two executors building different payouts** | ~~Prevented by construction by deterministic coin selection.~~ **CORRECTED — see §10.1.** Determinism is necessary but NOT sufficient: selection runs over each operator's *locally reserved* UTXO set, so discovery-order skew alone produces different transactions. Measured, not argued. |
| UTXO reservation | Local to each validator's own database. Cross-validator agreement comes from the signed intent; the **UTXO set is the final arbiter** (`-25 Missing inputs`, verified in Phase 6). |
| Database independence | Each validator keeps its own SQLite. No shared state, no cross-node locking, no consensus. |
| Failover | Timeout-based promotion. Worst case is a duplicate broadcast of the **identical** transaction, which Phase 6 verified is idempotent (`-27` = already in chain). |

### 10.1 CORRECTION (Phase 7g, 2026-08-01) — measured, and worse than stated

Two claims above were wrong. Both were corrected only because Phase 7g
measured them against a real regtest node instead of reasoning about them
(`docs/experiments/` harness; results in ADR-0019 §2).

**Wrong claim 1 — "prevented by construction".** Deterministic coin
selection does not make two executors agree. Selection runs over
`available_utxos`, which filters on `state = 'Available'` — **local
reservation state**. Two operators that observe withdrawals in a different
order reserve different UTXOs and then build genuinely different
transactions from identical, deterministic rules.

Measured with two executors and one shared node, nothing broadcast:

| discovery order | withdrawal 5 | withdrawal 7 |
|---|---|---|
| identical | AGREE | AGREE |
| staggered | **DIVERGED** | **DIVERGED** |

**Wrong claim 2 — "duplicates are already harmless".** True of mints. **Not
true of payouts**, and the original wording generalised it. With the Phase
7e signer check bypassed, two operators paid the same withdrawal twice —
three confirmed payments totalling 90 GLC where 60 was owed:

```
A w5: 30 GLC   A w7: 30 GLC   B w7: 30 GLC   <- w7 paid twice
```

The sequence needs no adversary: B pays w7, A never learns, the vault is
refunded, A still believes w7 unpaid and pays it again.

**The corrected safety model.** Nothing in the *executor* prevented this.
The guards that do, in order:

1. **Phase 7e's signer check (primary).** A second payout needs quorum
   signatures, and a peer whose own executor has that withdrawal past the
   Building/Signing window refuses. This is load-bearing, and it lives in a
   **different process** from the one that would cause the harm.
2. **Phase 7f completion + discovery filter (secondary).** Stops a fresh or
   restarted relayer re-queuing a paid withdrawal; does nothing for one
   that already ingested it.
3. **Phase 7g's pre-broadcast check (added because of this measurement).**
   The executor re-reads the on-chain withdrawal status immediately before
   broadcasting and refuses if it is already `Completed` — restoring the
   defence in depth this section originally implied but did not have.

ADR-0019 supersedes this section's mechanism table for payouts.

This closes D8 without introducing consensus of its own — consistent with
the Phase 0 p2p constraint.

---

## 11. Production chain policy

Every value below is currently undecided **by design** (owner decision U6 —
the code has no built-in defaults and refuses to start without explicit
configuration). This section proposes a *method*, not numbers.

| Parameter | Approach |
|---|---|
| Deposit confirmation depth | **Derive from economics, do not guess.** Choose depth such that the cost of renting enough hashrate to reorg it substantially exceeds the per-deposit cap. Requires measured Goldcoin hashrate and rentable-hashrate pricing. |
| Withdrawal confirmation depth | May be lower than deposit depth: a vault→user payout is not attacker-profitable in the same way an unwind-the-deposit reorg is. |
| Max reorg depth | ≥ 2× deposit depth; beyond it the indexer halts rather than guessing a fork point (already implemented, Phase 4). |
| Per-deposit cap | Start deliberately small in canary; raise only against reorg-cost evidence. |
| Rolling-window cap | Bounds loss *rate* under sustained attack. Already implemented (Phase 4). |
| **Total TVL cap** | **DELIVERED in Phase 7h-0 — see §11.1.** A hard ceiling on wrapped supply, enforced in `mint_wrapped`. `BridgeConfig.max_wrapped_supply`, taken out of `reserved` (23 → 15 bytes; the field was verified all-zero on a live account first). No migration, no `PROTOCOL_VERSION` bump. |
| Halt conditions | Reorg beyond max depth; TVL invariant breach; any `IntegrityHalted` deposit or withdrawal; validator-set epoch mismatch between peers; vault balance reconciliation mismatch. |
| Recovery | Every halt requires explicit operator action. The existing `operator_clear_integrity_halt` pattern (audited, non-empty note, restricted targets) is the model. |

---

### 11.1 The TVL cap is deliberately ASYMMETRIC (Phase 7h-0)

| direction | authority | delay | why |
|---|---|---|---|
| **Lower** the cap | admin alone | **immediate** | reduces exposure; this is incident response, and incident response cannot wait out a timelock |
| **Raise** the cap | M-of-N threshold approval | **full governance timelock** | increases exposure; this is exactly what an attacker holding a stolen admin key would want |

This mirrors §7.3's deliberate asymmetry for pausing rather than introducing
a second authority model. The raise path reuses the Phase 7a machinery
wholesale — same `PendingGovernanceAction` singleton, same message shape,
same `require_federation_approval`, same timelock, same cancellation path.
Only the action byte (`ACTION_PROPOSE_TVL_RAISE = 0x05`) and the parameter
set differ.

**Why the asymmetry rather than symmetry.** Gating both directions behind
governance would be simpler to describe, but it would mean an operator
watching an incident unfold could not reduce the bridge's maximum exposure
without waiting out the timelock — precisely when speed matters and
precisely in the direction that is safe. Conversely, letting the admin raise
the cap would hand a single key the power to increase exposure, which is the
shape of authority §7 exists to remove. The risk is not symmetric, so the
controls are not either.

**Two consequences worth stating.** A queued raise is re-checked at
execution, so a raise proposed before an incident cannot silently undo an
admin lowering that happened during it. And a cap of zero is invalid in
every path: it would have to mean "no minting" or "unlimited" depending on
how it were read, and the second is the exact wrong default for a bound on
exposure — `initialize` refuses it, following the `governance_timelock_seconds`
precedent rather than `min_deposit`'s "0 = disabled" convention.

**What it does and does not do.** It bounds *absolute* exposure on-chain.
It does not verify the solvency invariant itself — threat-model invariant #1
compares wrapped supply against confirmed vault deposits minus completed
payouts, and the vault side is not visible to the program. That remains a
monitoring responsibility (§13.1), delivered in Phase 7h.

---

## 12. Deployment security

| Area | Requirement |
|---|---|
| Upgrade authority | Move to a multisig (e.g. Squads) immediately; publish an immutability timeline. Until then it is an infinite-mint capability equal in severity to F1 (custody #5). |
| Immutability | Publish the criteria and date for revoking upgrade authority. Bridges that stay upgradeable indefinitely are custodial in practice. |
| Verified builds | Reproducible SBF builds; publish the program hash; every operator independently verifies the deployed hash matches the audited source. |
| Deterministic deployment | Scripted, reviewed, dry-run on devnet; no interactive one-off deploys. |
| Environment separation | Distinct keys, RPC endpoints, and databases per environment. No shared credentials between devnet and mainnet. |
| Secret management | No secrets in the repo (already enforced by `.gitignore` and cargo-deny discipline). Node credentials via cookie-file or `rpcauth`, **not** plaintext `rpcuser`/`rpcpassword` — the node itself warns these are deprecated. |
| Release signing | Tagged, signed releases; operators verify signatures before deploying. |
| Rollback | Program rollback is constrained by state compatibility; the rollback plan must be written **before** launch, not during an incident. Pausing is the first-line response, not rollback. |

---

## 13. Monitoring and operations

### 13.1 Invariant monitors (page immediately)

1. **`wrapped_supply ≤ confirmed_vault_deposits − completed_payouts`** —
   the master solvency invariant (threat-model #1). Computed independently
   by every operator; alarm on breach **and on disagreement between
   operators**, because divergence itself is a signal.
2. Vault balance reconciliation: on-chain UTXO sum versus expected.
3. Any deposit or withdrawal in `IntegrityHalted`.
4. Validator-set epoch mismatch between peers.
5. Goldcoin reorg depth approaching `max_reorg_depth`.

### 13.2 Metrics

Per-state deposit and withdrawal counts and ages; signature request,
response, and **refusal** rates per peer; RPC error-class rates (the
transport/method split already exists); vault UTXO count and fragmentation;
time-to-mint and time-to-payout distributions; database size and WAL growth.

### 13.3 Audit logs

Append-only, shipped off-host: every signature decision, every state
transition (`deposit_state_log` and `withdrawal_state_log` already exist
with forensic columns), every operator recovery action.

### 13.4 Backup, restore, and integrity

- Hourly SQLite snapshots with **periodic restore drills**.
- `PRAGMA integrity_check` plus an application-level offline auditor that
  re-verifies stored commitments using the same recompute-and-compare logic
  the signing guards already implement (ADR-0012, ADR-0013).

### 13.5 Runbooks

Deep reorg; integrity halt; vault key compromise; validator offline;
Solana outage; Goldcoin outage; stuck withdrawal; TVL breach; emergency
pause and unpause; key rotation; vault sweep. Each rehearsed at least once
on testnet before launch.

**Split into three phases (owner decision, 2026-08-01).** Verifying the
current state found that integrity-halt recovery, key rotation, the TVL
raise and the vault sweep had no executable form — see ADR-0021 §2. A
second survey then found that even after 7i-0 the federation could *produce*
governance signatures but nothing could *submit* them, and that pause and
the supply-cap controls had no caller either (ADR-0022 §2).

- **7i-0** (ADR-0021): `glc-admin`, `SignGovernance`, `SignSweep`.
- **7i-1** (ADR-0022): on-chain submission — pause/unpause, supply-cap
  controls, the rotation lifecycle, and `sweep-execute`.
- **7i**: the runbooks, documenting **only** procedures an operator can
  carry out with supported tools.

---

## 14. Security review

### 14.1 Trust assumptions

- Users trust that fewer than M validators collude. This is a **federated,
  not trustless** bridge and must be stated plainly in all user-facing
  material.
- Each validator trusts only its **own** Goldcoin node and Solana RPC.
- The Anchor program is the final arbiter of mint legitimacy; the Goldcoin
  UTXO set is the final arbiter of payout uniqueness.

### 14.2 Risk register

| Risk | Status after Phase 7 |
|---|---|
| **Single-key governance (F1)** | **Live today.** Closed by 7a. Highest severity. |
| **Upgrade authority = infinite mint** | Open (custody #5). Closed by multisig + immutability timeline. |
| **M-of-N collusion** | Irreducible. Bounded by TVL cap; disclosed to users. |
| **Goldcoin deep reorg / 51%** | Dominant external risk. Bounded by depth + caps + halt; never eliminated. |
| **Vault key compromise** | Single key today (D2) → M keys after 7b; rotation and sweep rehearsed. |
| **Relayer compromise** | Cannot forge signatures — validators verify independently. Can withhold or spam ⇒ liveness only. |
| **Malicious operator** | Bounded by threshold; detectable via cross-operator invariant disagreement. |
| **Stale validator epoch** | Already mitigated: epoch is inside the signed bytes, so rotation kills in-flight proofs (tested since Phase 3). |
| **Database corruption** | Halt-and-audit (ADR-0012/0013); extended by an offline auditor. |
| **Network partition** | Degrades to liveness loss. Never produces a wrong mint. |
| **Solana program compromise** | Mitigated by verified builds, upgrade-authority multisig, and eventual immutability. |
| **Denial of service** | Rate limits, size caps, TLS-level rejection of unknown peers; verification cost bounded by own-node access. |
| **Supply chain** | `cargo-deny` in CI on both workspaces. gRPC/TLS adds surface requiring review. The **Phase 5 `webpki-roots` feature-unification caveat remains unresolved**. |
| **Ed25519 introspection** | ADR-0010 states focused external review is still required. Must be in audit scope. |

---

## 15. Testing and rollout

| Stage | Gate to proceed |
|---|---|
| 1. Local multi-validator simulation | 3 relayers + 3 isolated signers against real regtest and a local validator; **no process holds two keys** |
| 2. Devnet + regtest soak | Multi-day run with deliberate fault injection: kill signers, partition peers, force reorgs, corrupt a database |
| 3. **Real P2SH multisig verification** | **Blocks every later stage (F4)** — a real M-of-N spend confirmed on regtest |
| 4. Private team canary | Team funds only, hard-capped, full monitoring live |
| 5. External audit | On-chain program, custody model, and networking. Frozen scope. |
| 6. Remediation | All critical and high findings resolved; fixes re-reviewed |
| 7. Capped mainnet canary | Small TVL and per-deposit caps, published; staffed on-call |
| 8. Public beta | Caps raised only on evidence; ≥30 days incident-free at the prior cap |
| 9. Production | Governance timelocked; upgrade authority under multisig; immutability timeline published |

### Launch criteria — all must hold

- F1 closed: no single key can rotate validators or unpause.
- F4 closed: P2SH multisig spending verified against a real node.
- No process holds more than one validator private key.
- TVL cap and per-deposit cap enforced **on-chain**.
- `complete_withdrawal` live; on-chain status advances.
- External audit passed with remediation verified.
- Backup restore drill executed successfully.
- Runbooks rehearsed by the operators who would run them.

---

## 16. Unresolved decisions

| # | Decision | Why it blocks |
|---|---|---|
| **P1** | Split Phase 7 into 7a–7e? | Determines sequencing and audit scope of everything above |
| **P2** | M and N (custody #1) | F2 caps M at 4 (legacy) / ~6–7 (v0+ALT). Must be chosen inside that envelope or ADR-0005 revisited |
| **P3** | Legacy vs v0 + address lookup tables | Coupled to P2; determines whether M > 4 is possible at all |
| **P4** | Governance: threshold and timelock durations, and asymmetric pause thresholds | F1 — the most severe open gap |
| **P5** | Who operates the N validators (custody #1) | Blocks the ceremony, which has the longest lead time |
| **P6** | Upgrade-authority custody and immutability timeline (custody #5) | Currently an infinite-mint capability |
| **P7** | Hardware signer choice — **verified against Goldcoin**, not assumed | Lineage divergence has caused repeated surprises |
| **P8** | Production confirmation depths and caps (U6) | Needs hashrate and reorg-cost data |
| **P9** | TVL cap value, and confirmation it is enforced on-chain | New requirement introduced here |
| **P10** | Pause authority and unpause quorum (custody #7) | Still the interim admin key |
| **P11** | Production fee bearer (custody #9; Phase 6 chose vault, regtest-scoped) | Economic policy |
| **P12** | External auditor selection and budget | Long lead time — should start now |

---

## Consequences

- Phases 5 and 6 shipped deliberately unsafe key topologies (R2, D2) that
  this design deletes rather than extends. That is the intended lifecycle,
  but it means 7b and 7c are **removals of working code**, and the
  end-to-end tests that depend on them must be rewritten against the
  isolated-signer model.
- Adding gRPC and TLS materially expands the dependency graph and the
  `cargo-deny` surface, in a workspace where that policy is already
  strained. The `webpki-roots` question from Phase 5 should be resolved in
  the same pass.
- Closing D1 restores ADR-0006's chain-state-recovery property for the
  payout half, but does not make the relayer database disposable.
- ADR-0007's claim that governance hardening arrived in Phase 3 is
  **incorrect and should be corrected** when 7a lands, so the ADR record
  does not misrepresent what shipped.
- The federation's maximum threshold is a protocol property (F2), not a
  deployment tunable. If governance ever wants M > ~7, that is an ADR-0005
  redesign, not a configuration change.
