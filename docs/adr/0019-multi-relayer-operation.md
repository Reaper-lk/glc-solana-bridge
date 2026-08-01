# ADR-0019: Multi-relayer / multi-executor operation

- Status: **Accepted** (owner approval, 2026-08-01). G1/G2/G3 and the
  pre-broadcast decision resolved.
- Phase: 7g
- Closes: **D8**. Supersedes ADR-0014 §10's mechanism table for payouts; see
  ADR-0014 §10.1 for the corrected safety model.
- Builds on: ADR-0013 (executor), ADR-0015 (designated quorum), ADR-0017
  (distributed payout signing), ADR-0018 (completion).
- Empirical basis: §2. Measured against a real `goldcoind` regtest node
  before the design was finalised, per owner decision G3.

---

## 1. Context

Every phase so far assumed **one** relayer per federation in practice, even
though the federation model has always had N operators. D8 asks what happens
when several run at once.

ADR-0014 §10 answered it with two claims — that deterministic coin selection
prevents divergent payouts, and that duplicates are harmless. Phase 7g
measured both. **Both were wrong.** The measurements are in §2 and the
corrected safety model is recorded in ADR-0014 §10.1 rather than left to
stand.

---

## 2. Measured facts

Two executors, separate databases, one shared Goldcoin regtest node.

### 2.1 Build divergence is caused by reservation order, not by selection

With neither operator able to sign — so nothing was broadcast and the chain
never moved — the only variable was discovery order:

| discovery order | withdrawal 5 | withdrawal 7 |
|---|---|---|
| identical | **AGREE** | **AGREE** |
| B observes 7 before 5 | **DIVERGED** | **DIVERGED** |

`available_utxos` filters on `state = 'Available'`, which is **local
reservation state**. Deterministic selection over different available sets
gives different transactions. No adversary, no nondeterminism, no bug.

### 2.2 The executor alone permits a double payment

With the Phase 7e signer check deliberately bypassed (the test-only
in-process collector holds every vault key), the same two operators paid one
withdrawal twice:

```
A w5: 30 GLC via 9c46a492…
A w7: 30 GLC via 0a21573b…
B w7: 30 GLC via b79da74f…   <- same withdrawal, second payment

DISTINCT CONFIRMED PAYMENTS = 3 totalling 90 GLC (expected 2 / 60 GLC)
```

Sequence: B pays w7; A never learns; the vault is refunded; A still believes
w7 unpaid and pays it again. Both transactions confirmed.

> **Measurement note, recorded because it nearly produced a false clean
> bill.** The first two runs reported *"no overpayment"* using
> `listunspent` on the destination. That metric is unusable here: the
> regtest wallet also holds the destination and spends its outputs to fund
> later sends, so real payments vanish from the balance. The result above
> decodes each transaction's outputs instead. A metric that under-reports
> the exact failure being tested is worse than no metric.

### 2.3 What actually prevents the double payment today

Nothing in the executor. In production the second payout needs quorum
signatures, and Phase 7e's signer refuses because its own executor has that
withdrawal past the Building/Signing window (already covered by
`payout_signer_view.rs`). Phase 7f's completion stops a *fresh* relayer
re-queuing a paid withdrawal but does nothing for one that already ingested
it.

So the guarantee rested on **one** guard, living in a **different process**
from the one that would cause the harm. That is a defensible position but
not the defence-in-depth ADR-0014 implied.

---

## 3. Decisions

### D1. Relayer identity is explicit (owner decision G1)

A new `GLC_RELAYER_VALIDATOR_PUBKEY` names which federation member this
relayer acts as. It is **not derived** from anything.

Validated at startup against the federation configuration, failing closed:

- it must **not** appear in `GLC_FEDERATION_PEERS` (peers are the *others*;
  the existing self-in-peer-list guard finally has a caller);
- it must appear in `GLC_VAULT_SIGNER_MAP`, which is what gives this relayer
  its operator index and the operator count.

Derivation was rejected because this value decides **who acts first**.
Inferring it from the shape of a different setting is exactly how two
configurations drift apart without anyone noticing.

### D2. Deterministic assignment with timeout failover

| work | designated operator | failover |
|---|---|---|
| mint submission | `deposit_id mod N` | after `T_submit`, any operator may submit |
| payout building | `withdrawal_index mod N` | after `T_build`, any operator may build |

Leaderless, as ADR-0014 intended: no election, no lock, no shared state.
Assignment only decides *who goes first*; the failover keeps liveness when
that operator is down.

Duplicate **mints** remain harmless (the claim PDA's `init`), so assignment
there is purely a fee optimisation. Duplicate **payouts** are not harmless
(§2.2), which is why payouts get D3 and D4 as well.

### D3. Builder-authoritative reservation (owner decision G2, option A)

**Only the designated builder reserves UTXOs and proposes a payout.** Other
executors stay passive: they do not build, do not reserve, and therefore
cannot diverge — §2.1's cause is removed structurally rather than
mitigated.

A passive operator adopts a proposal only when asked to sign it, and only
after **independently validating every field** against its own state:

1. the requester is the **designated builder** for that index (or `T_build`
   has elapsed, making any operator eligible);
2. the withdrawal exists locally and is not already built, broadcast, or
   completed;
3. every proposed input is in **this operator's own** `vault_utxos`,
   `Available`, at the required confirmation depth, with a matching amount;
4. the outputs pay exactly the withdrawal's amount to its recorded
   destination, with change to the configured vault change address;
5. the fee is exactly what this operator's own fee policy computes for that
   shape;
6. the designated **signing quorum** matches this operator's own
   deterministic designation (ADR-0015).

Only then does it reserve those inputs, persist the payout, and sign.

This is adoption-after-verification, not trust: a proposal that fails any
check is refused, and a refusal is an alarm exactly as elsewhere. What it
removes is the *speculative* reservation that made two honest operators
disagree.

### D4. Pre-broadcast on-chain status check (owner decision, restores depth)

Immediately before broadcasting, the executor re-reads the withdrawal's
**on-chain status** and refuses to broadcast if it is already `Completed`.

Cheap — one account read, using machinery Phase 7f already built — and it
puts a guard in the process that would otherwise cause the harm. It does not
catch a payment made but not yet completed on-chain, so it is defence in
depth, not a replacement for D3 or for Phase 7e's signer check.

Stated plainly so nobody mistakes its reach: **the signer check remains the
primary protection.** D4 exists because §2.2 showed the executor had nothing
at all.

---

## 4. Failure modes and required tests

### 4.1 Mutation tests

| # | mutant | guard |
|---|---|---|
| M1 | accept a relayer pubkey that appears in the peer list | D1 fail-closed |
| M2 | accept a relayer pubkey absent from the vault signer map | D1 |
| M3 | build when not the designated builder and before `T_build` | D3 |
| M4 | ignore `T_build`, never failing over | D2 liveness |
| M5 | adopt a proposal whose input is not in the local UTXO set | D3 (3) |
| M6 | adopt a proposal whose input amount differs locally | D3 (3) |
| M7 | adopt a proposal paying a different destination | D3 (4) |
| M8 | adopt a proposal paying a different amount | D3 (4) |
| M9 | adopt a proposal with a different fee | D3 (5) |
| M10 | adopt a proposal whose quorum differs from the local designation | D3 (6) |
| M11 | adopt a proposal from a non-designated builder before `T_build` | D3 (1) |
| M12 | skip the pre-broadcast on-chain status check | **D4** |
| M13 | treat a non-`Completed` status as `Completed` (and vice versa) | D4 |

### 4.2 Regression tests promoted from the measurement harness

The harness that produced §2 becomes permanent:

1. **Build convergence** — two executors, staggered discovery, must now
   agree, where §2.1 measured them diverging.
2. **No double payment** — the §2.2 scenario, replayed, must now pay each
   withdrawal exactly once.

Both assert on **decoded transaction outputs**, never on `listunspent`
(§2.2's note).

---

## 5. Consequences

- Two honest operators no longer diverge, because the cause — speculative
  reservation — is gone rather than mitigated.
- The executor gains a Solana RPC dependency on its broadcast path. That is
  a real coupling change, accepted deliberately for D4.
- A passive operator does strictly less work: it builds nothing until asked.
- ADR-0014 §10's incorrect guarantees are corrected in place rather than
  quietly superseded.

---

## 6. Explicitly out of scope

- Operations, monitoring, runbooks, and canary rollout (ADR-0014 §13) — the
  remaining pre-launch stage.
- Any change to the deposit claim or completion message formats.
- Consensus of any kind between relayers. Assignment is arithmetic, not
  agreement.
