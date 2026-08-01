# ADR-0018: Withdrawal completion (`complete_withdrawal`)

- Status: **Accepted** (owner approval, 2026-08-01). Q1/Q2/Q3 resolved — see §7.
- Phase: 7f
- Scope: **withdrawal completion only.** Multi-relayer / multi-executor
  (ADR-0014 D8, §10) is deferred to Phase 7g by owner decision.
- Implements: ADR-0014 §9. Closes **D1**.
- Builds on: ADR-0003 (claim PDA replay prevention), ADR-0006 (persistent
  withdrawal records), ADR-0010 (federation proof verification), ADR-0013
  (withdrawal executor), ADR-0017 (distributed payout signing).
- Empirical basis: §2 below. Every number was measured, not estimated.

---

## 1. Context

### 1.1 What is broken today

`WithdrawalStatus` has existed since Phase 3 with three variants —
`Pending`, `Broadcast`, `Completed` — and **nothing has ever advanced it
past `Pending`**. There is no instruction that can.

The relayer half mirrors this. `relayer/src/withdrawal/discovery.rs:117`
decodes `status_tag` out of the account body, and **no code reads it**.
`scan_withdrawals` ingests every withdrawal it finds, paid or not.

So the only record distinguishing a paid withdrawal from an unpaid one is
the relayer's local SQLite database. ADR-0006 states the property that
justified persistent on-chain withdrawal records in the first place —
*reconstruct the outstanding queue from chain state alone* — and that
property currently holds for deposits (the claim PDA's existence is the
mint record, ADR-0003) but **not** for payouts. D1 recorded this as an
accepted Phase 6 gap. Phase 7f closes it.

### 1.2 Why now

Phases 7a–7e removed every place a single key could act unilaterally. What
remains before launch is the operational half, and the first item is
recoverability: an operator who loses the relayer database today cannot
tell which withdrawals were already paid, and the only safe response is
manual reconciliation against the Goldcoin chain. That is a bad position to
be in during an incident, which is exactly when it would happen.

### 1.3 What this does NOT fix

It does not make the relayer database disposable. Local state remains the
record of in-flight work between broadcast and completion — a payout that
has been broadcast but not yet confirmed is still known only locally. What
completion restores is the ability to answer *"is this withdrawal
finished?"* from the chain.

---

## 2. Measured facts this design rests on

Measured on 2026-08-01 against the real program and a live litesvm account.
Nothing here is inferred from the struct definitions.

### 2.1 The signature ceiling is NOT tightened by completion

ADR-0014 F2 warned that the ed25519 precompile's per-signature cost bounds
`M` far more tightly than `MAX_VALIDATORS = 16` bounds `N`, and that
federation size must be chosen inside that envelope. The concern was that
completion might be tighter still.

The harness was first calibrated against ADR-0010's already-measured
figures, and reproduced them exactly — **`mint_wrapped` legacy M ≤ 4**, and
**110 bytes per signature**:

| configuration | accounts | max M | bytes at max M |
|---|---|---|---|
| `mint_wrapped` legacy | 11 | **4** | 1204 |
| `mint_wrapped` v0 + LUT | 11 | **6** | 1150 |
| `complete_withdrawal` legacy | 5 | **6** | 1210 |
| `complete_withdrawal` v0 + LUT | 5 | **7** | **1232** |

`complete_withdrawal` needs six fewer accounts (≈192 bytes) and a shorter
message, which buys **two extra signatures**.

**Consequence: `mint_wrapped` remains the binding constraint on federation
size. Phase 7f introduces no new limit and no owner decision.**

> **Re-measured after D2 changed.** The first measurement assumed a 20-byte
> `dest_hash160` and a 134-byte message. D2 was corrected during
> implementation to a 32-byte `dest_commitment` (message 146 bytes), so the
> table above is the **re-measured** result, not the original one.
>
> The ceilings are unchanged, but the v0+LUT figure moved from 1220 to
> **exactly 1232 bytes — the hard packet limit, with zero headroom**. M=7
> over a lookup table therefore fits only by a single byte's grace. Any
> future addition to this instruction — one account, one argument — breaks
> it. The legacy path at M≤6 has 22 bytes spare and is the one to rely on.

### 2.2 `reserved` is genuinely all-zero on a live account (F3)

From an account created by an actual `burn_wrapped` under litesvm:

```
actual length : 180  (= WithdrawalRequest::SPACE)
status byte   : offset 121 (8 discriminator + 113), value 0 = Pending
reserved      : offset 132, len 48, all zero = true
payout_txid(32) + payout_height(8) = 40  →  8 bytes spare
```

**No account migration. No `PROTOCOL_VERSION` bump.** F3 confirmed against a
live account rather than the struct definition.

### 2.3 The status byte round-trips into the relayer's decoder

The real account bytes, fed to `relayer::withdrawal::discovery::decode_withdrawal`:

```
Pending   : decoded index=0 amount=30000 status_tag=0
Completed : decoded index=0 amount=30000 status_tag=2
```

The relayer reads the status byte at exactly the offset the program writes,
and a change to `Completed` survives the round trip. Discriminants:
`Pending = 0`, `Broadcast = 1`, `Completed = 2`.

### 2.4 An incidental finding, recorded rather than fixed

The first capture used the on-chain test suite's placeholder destination
(`GLCtestDestinationAddress…`), and the relayer **rejected it**: *"address
contains a non-base58 character."* That is Phase 6 validation behaving
correctly, but it means **the on-chain test suite creates withdrawals the
relayer would refuse to process**. Neither component is wrong; they simply
hold different notions of a valid address, and an on-chain test passing
tells you nothing about relayer acceptance.

Out of scope for 7f. Recorded here so it is not rediscovered as a bug.

---

## 3. Decisions

### D1. One new instruction, authorised by the existing M-of-N proof

```rust
complete_withdrawal(
    index:         u64,
    payout_txid:   [u8; 32],
    payout_height: u64,
    epoch:         u64,
)
```

Authorised exactly as `mint_wrapped` is: the immediately preceding
instruction must be the ed25519 precompile carrying ≥ threshold unique
current validators over the canonical completion message
(`verification::count_unique_validator_signers`, unchanged).

**No new authorization mechanism is introduced.** Reusing the audited path
verbatim is the point: a second mechanism would double the surface that
Phase 7's threat model has to cover.

### D2. A new action under the existing claim domain

`shared::claim` gains `ACTION_COMPLETE_WITHDRAWAL = 0x02`. `0x01` remains
deposit mint; `0x00` stays permanently invalid.

```
| offset | len | field                                    |
|--------|-----|------------------------------------------|
| 0      | 16  | domain tag b"GLC_BRIDGE_CLAIM"           |
| 16     | 1   | protocol version                         |
| 17     | 32  | Solana program id                        |
| 49     | 8   | validator-set epoch (u64 LE)             |
| 57     | 1   | action = 0x02                            |
| 58     | 8   | withdrawal_index (u64 LE)                |
| 66     | 32  | payout_txid ([u8;32] verbatim)           |
| 98     | 8   | payout_height (u64 LE)                   |
| 106    | 8   | amount, atomic GLC units (u64 LE)        |
| 114    | 32  | dest_commitment                          |
```

`COMPLETION_MESSAGE_LEN = 146`.

> **Corrected during implementation.** The design originally specified a
> 20-byte `dest_hash160`. The on-chain program has no way to produce one:
> it stores the Goldcoin address as opaque ASCII and **never decodes
> base58** — there is no `glc_address_hash160` anywhere in the program, and
> the assumption that there was is mine, not the codebase's.
>
> Adding a base58 decoder plus checksum verification inside the program
> would be real code and real risk for no benefit, since both sides already
> agree on the stored bytes. So the destination is committed as
> `dest_commitment = sha256(glc_address[..glc_address_len])` — a hash of the
> address **exactly as stored**, which assumes nothing about address format
> and requires the program to learn none.
>
> The security property is unchanged: the signature still names one specific
> destination, and a signer still checks it against its own chain
> observation. Only the encoding differs.

The first 58 bytes are **byte-identical in layout** to the deposit claim, so
the action byte at offset 57 is what separates the two families. A
signature for one action can never be replayed as the other, because the
byte strings differ at a fixed, verified position.

**`amount` and the destination are bound deliberately.** Without them a
signature would authorise "index N is finished" — an assertion a validator
cannot actually verify, since it would not name the payment it refers to.
With them, a signature authorises completion of **one specific payout to one
specific destination for one specific amount**, which is a claim the signer
can check against its own chain observations.

Pinned by a golden-vector test, as the deposit message already is.

### D3. The status field is itself the replay guard

```
Pending ──(M-of-N proof)──► Completed          [terminal]
Pending ──(M-of-N proof)──► Broadcast ──► Completed
```

A call against a record already `Completed` fails with a dedicated error.
No lookup table, no scan, no second account — structurally identical to the
claim PDA's `init` constraint (ADR-0003), and for the same reason: the
cheapest replay guard is one that is a side effect of the state you already
must store.

Phase 7f writes only `Pending → Completed`. The `Broadcast` variant remains
reachable-in-principle and unused; introducing a second instruction to set
it would add surface for no recoverability benefit, since a broadcast payout
is exactly the in-flight state §1.3 says stays local.

### D4. Completion is irreversible

There is no un-complete path, and this is deliberate. A reversal instruction
would let anyone able to force a Goldcoin reorg *un-complete* a withdrawal
and induce a second payout — strictly worse than the problem it solves.

Instead:

- validators sign completion only at or beyond the production withdrawal
  confirmation depth (D6);
- a reorg deeper than that **after** completion is a halt-and-reconcile
  incident requiring operator judgement, not an automatic on-chain state
  change.

### D5. The payout record goes in `reserved`, with the spare left zero

`payout_txid` (32) then `payout_height` (8) are written at the start of
`reserved`; the remaining 8 bytes stay zero and stay reserved. Measured
capacity confirms this fits (§2.2).

The struct's public shape does not change, so the relayer's existing decoder
keeps working unmodified; it simply gains meaning for bytes it already
tolerates.

### D6. A validator signs completion only from its own confirmed observation

The payout analogue of every other signing decision in this bridge. A
validator will produce a completion signature only when **its own** Goldcoin
node reports that `payout_txid`:

1. exists and is confirmed at or beyond the configured withdrawal
   confirmation depth;
2. pays exactly `amount` to exactly `dest_hash160`;
3. corresponds to the withdrawal at `index` in its own database, in a state
   consistent with having been paid.

The requester's assertion is compared, never adopted — the same discipline
as `p2p::payout_view` (ADR-0017 D3). A validator that has not itself seen
the payout confirmed simply refuses, and refusing is always preferred to
signing something unverified.

**This is why `amount` and the destination commitment are in the message (D2):** they
are precisely the facts a signer can independently check against the chain.

### D7. Discovery finally uses the status byte

`scan_withdrawals` skips withdrawals whose on-chain status is `Completed`.
That is the recoverability payoff: a relayer with an empty database
reconstructs only the genuinely outstanding queue.

The local database remains authoritative for in-flight work; the on-chain
status is a **floor**, not a replacement. A withdrawal the chain says is
`Completed` is definitely finished; one the chain says is `Pending` may
still be locally in flight.

---

## 4. What changes

| file | change |
|---|---|
| `shared/src/claim.rs` | `ACTION_COMPLETE_WITHDRAWAL`, `completion_message()`, `COMPLETION_MESSAGE_LEN` |
| `programs/glc-bridge/src/instructions/complete_withdrawal.rs` | **new** — the instruction |
| `programs/glc-bridge/src/instructions/mod.rs` | register it |
| `programs/glc-bridge/src/lib.rs` | entrypoint |
| `programs/glc-bridge/src/state.rs` | accessors for the payout record inside `reserved`; no layout change |
| `programs/glc-bridge/src/errors.rs` | `WithdrawalAlreadyCompleted`, `WithdrawalNotPending`, `PayoutRecordAlreadySet` |
| `programs/glc-bridge/src/events.rs` | `WithdrawalCompleted` |
| `relayer/src/solana/instruction.rs` | hand-built `complete_withdrawal` instruction (owner decision R1: no anchor-lang dependency) |
| `relayer/src/p2p/completion_view.rs` | **new** — what a validator will attest completion for (D6) |
| `relayer/src/p2p/service.rs`, `collector.rs`, `proto` | a `SignCompletion` RPC, mirroring `SignPayout` |
| `relayer/src/withdrawal/executor.rs` | a completion step after confirmation |
| `relayer/src/withdrawal/discovery.rs` | use `status_tag` (D7) |

Deliberately unchanged: `verification.rs`, the ed25519 proof path, the
deposit claim message, `WithdrawalRequest`'s layout, and the withdrawal
state machine's existing transitions.

---

## 5. Required tests

### 5.1 Mutation tests

| # | mutant | guard |
|---|---|---|
| M1 | accept a completion for a withdrawal already `Completed` | D3 replay guard |
| M2 | accept a message whose action byte is `0x01` (deposit mint) | D2 domain separation |
| M3 | drop `amount` from the completion message | D2 — a signature would stop naming the payment |
| M4 | drop `dest_commitment` from the message | D2 |
| M5 | drop `payout_txid` from the message | D2 |
| M6 | accept fewer than threshold signatures | ADR-0010 |
| M7 | accept a stale `epoch` | ADR-0010 |
| M8 | accept the proof from an instruction other than the immediately preceding one | ADR-0010 |
| M9 | write the payout record without checking `reserved` is zero | D5 |
| M10 | sign completion without checking confirmation depth | D6 |
| M11 | sign completion without checking the payout pays `amount` to the withdrawal's destination | D6 |
| M12 | sign completion for a txid the validator's own node does not have | D6 |
| M13 | ingest a `Completed` withdrawal during discovery | D7 |
| M14 | treat on-chain `Pending` as authoritative over local in-flight state | D7 — would re-pay an in-flight withdrawal |

### 5.2 Failure cases

| case | expected |
|---|---|
| double completion | second call fails; state and payout record unchanged |
| completion of a never-broadcast withdrawal | refused by signers (D6); no valid proof can be assembled |
| signature for a different `payout_txid` / `amount` / destination | message differs → proof verification fails on-chain |
| wrong epoch | `StaleValidatorEpoch`, as `mint_wrapped` |
| below threshold | `InsufficientSignatures`; nothing written |
| reorg unconfirming a completed payout | on-chain state unchanged (D4); relayer raises a halt-and-reconcile incident |
| signer asked to complete a payout it has not confirmed at depth | refusal, surfaced as an alarm |
| `reserved` unexpectedly non-zero | refuse rather than overwrite — it would mean an unknown migration ran |

### 5.3 Golden vectors

1. `completion_message()` byte layout pinned, as the deposit claim is.
2. A real completed account's bytes, captured from litesvm, decoded by the
   **relayer's** decoder — the cross-workspace check §2.3 prototyped.

### 5.4 Real-node / real-validator

1. End-to-end on a local Solana validator: burn → payout → confirm →
   collect completion signatures → submit → account reads `Completed`.
2. Extend the existing Goldcoin-regtest e2e so the payout it already makes
   is then completed on-chain.
3. **A restart test that is the whole point of the phase:** delete the
   relayer database, rescan, and confirm the completed withdrawal is not
   re-paid and not re-queued.

### 5.5 Regression

The full existing suite must pass unchanged — in particular Phase 6's
never-double-pay layers and Phase 7e's distributed payout signing.

---

## 6. Consequences

- **A relayer can rebuild its outstanding queue from chain state**, closing
  D1 and restoring ADR-0006's stated property for the payout half.
- **Completion requires federation agreement**, so no single operator can
  mark a withdrawal paid — including to hide a payout that never happened.
- **The bridge gains an auditable on-chain payout record**: txid and height,
  bound to the withdrawal by a threshold signature.
- **No migration, no protocol-version bump**, so deployment is an ordinary
  program upgrade.
- Federation size is unaffected (§2.1).

---

## 7. Owner decisions — RESOLVED

### Q1. Completion is **automatic**

The relayer submits `complete_withdrawal` on its own, once it has
**independently confirmed** the payout at the required confirmation depth.
No operator action is required in the normal path.

Unattended recoverability is the primary goal of this phase: a completion
that waited for a human would leave exactly the gap D1 describes open for
however long nobody was looking.

### Q2. One confirmation policy: reuse `GLC_WITHDRAWAL_CONFIRMATION_DEPTH`

No second confirmation-depth setting is introduced. The depth that governs
treating a payout as confirmed locally (ADR-0013) is the same depth that
gates a completion signature.

Two knobs could be configured inconsistently, and the dangerous direction is
silent: an operator could complete on-chain something they do not consider
confirmed locally, and nothing would report the contradiction.

### Q3. `Broadcast` stays unused — `Pending → Completed` directly

Populating an intermediate state would cost a second instruction and a
second federation proof, and buys no recovery or safety benefit: a
broadcast-but-unconfirmed payout is precisely the in-flight state §1.3 says
remains local. The variant stays in the enum as reachable-in-principle
history rather than being removed, since removing it would change the
discriminant of `Completed`.

## 8. Explicitly out of scope

- **Multi-relayer / multi-executor (D8, ADR-0014 §10)** — deferred to Phase
  7g by owner decision.
- Any change to the deposit claim message layout (ADR-0010) — a
  signature-breaking protocol event, and nothing here requires it.
- Reversal or re-opening of a completed withdrawal (D4).
- Fee policy on payouts (custody.md #9).
- The address-validation divergence between the two test suites (§2.4).
