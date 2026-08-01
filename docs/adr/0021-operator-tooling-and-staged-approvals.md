# ADR-0021: Operator tooling, and authorisation by staged approval

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7i-0
- Implements: the executable half of ADR-0014 §13.5. Makes ADR-0014 §8.7's
  compromise response performable for the first time.
- Verification basis: §2, a survey of what the running system could actually
  be made to do before this phase, and §7, hand-applied mutation testing of
  every new guard.

---

## 1. Context

Phase 7i was to be the runbooks. Verifying the current operational state
first — as the workflow requires — found that three of the eleven procedures
ADR-0014 §13.5 calls for **could not be carried out at all** with the code
that existed. Writing them down would have produced documentation that reads
as a capability and is not one.

## 2. What verification found

| capability | status before this phase |
|---|---|
| `operator_clear_integrity_halt` | implemented, guarded, audited — **no caller outside tests** |
| `operator_clear_withdrawal_halt` | same |
| `reassign_payout_quorum` | same |
| governance signing (rotation, cancel, TVL raise) | **impossible**: `DbLocalView::derive_message` returns `None` for `Action::Governance`, and `signer-server` had no governance RPC |
| vault sweep (ADR-0014 §8.7) | **no implementation anywhere** |

The middle row is the one that matters most. ADR-0014 §8 makes key rotation
the response to a validator compromise, and Phase 7h-0 made a threshold-plus-
timelock TVL raise the only way to increase exposure. Neither could be
executed by the running federation: there was no path by which M validators
could produce M governance signatures.

The last row is worse in kind. §8.7 documents "pause → rotate → sweep" as the
response to a suspected *vault key* compromise. The first two steps were
executable; the third had never been built. A documented incident response
whose final step cannot be performed is more dangerous than none, because it
is believed.

## 3. Decision

Split Phase 7i. Build the tooling first (this ADR); write only runbooks whose
every step is executable with it (Phase 7i).

The tooling comprises:

1. **`glc-admin`** — the operator utility. Recovery, governance staging,
   sweep planning and staging.
2. **`SignGovernance`** — the federation RPC that makes governance actions
   executable, plus `p2p::governance_view`.
3. **`SignSweep`** and `withdrawal::sweep` / `p2p::sweep_view` — the vault
   sweep, plus the collection path that assembles one.

## 4. The architectural decision: authorisation by staged approval

Everything this bridge signed before this phase was **derivable**. A deposit
mint corresponds to a Goldcoin transaction; a payout corresponds to a burn on
Solana; a completion corresponds to a confirmed payout. In every case a
signer re-derives the canonical message from its *own* observations and
refuses anything that does not match byte for byte (ADR-0016). A fully
compromised requester can induce nothing.

**Governance and sweeps are not derivable.** "Should the federation rotate to
this validator set?" and "should the vault move to this address?" have no
on-chain answer to check against. There is nothing to re-derive.

Pretending otherwise would be the worst available option, so the trust model
is different and says so plainly:

> A governance or sweep signature requires **explicit intent from that
> validator's own operator**, staged out of band, naming the exact action and
> its exact parameters.

The signer will sign that and nothing else. M signatures therefore mean **M
humans each decided**, rather than M processes agreeing with whoever asked
first — which is the only meaning worth having for an action that changes
federation policy or moves the whole vault.

### 4.1 What the staging file is and is not

It is an instruction from an operator to their own signer. It is **not** a
defence against a compromised host: an attacker who can write it can read the
key beside it. Its purpose is to make these signatures *deliberate*.

It is plain text (`action hex_commitment epoch expiry note`, one per line)
because it is meant to be read by a human during an incident, without tooling.

It is **re-read on every request**, never cached, so revocation takes effect
immediately without a restart. That is a property an operator needs
mid-incident and a cached copy would silently deny them.

### 4.2 Guards on a staged approval

| guard | why |
|---|---|
| exact commitment match | the operator approved one parameter set, not "a rotation" |
| action must be a governance action | signing 0x01 under the governance domain tag would produce a governance signature for a mint |
| requested epoch == observed epoch | a governance signature must not outlive the federation revision it was made under |
| approval epoch == observed epoch | an approval does not survive a rotation, for the same reason |
| 24h TTL (governance), 6h (sweep) | an approval staged for one incident must not be usable weeks later for a different one |
| equivocation guard | having signed one proposal for an action, a validator must never sign a different one; a retry of the *same* one is free |

## 5. The vault sweep

A sweep spends the entire vault to an address chosen by a human. It is the
most dangerous operation in the system, and it passes **two independent
gates**:

1. **The operator approved this exact sweep.** The commitment covers the
   source vault, the destination script, the fee, the swept amount, and every
   outpoint and amount spent — so an approval to sweep to A cannot authorise
   a sweep to B, and an approval stops matching the moment the vault receives
   anything new.
2. **This validator has itself observed every input as vault-owned.** Input
   amounts are read from the signer's *own* `vault_utxos` rows. The request
   carries the transaction and nothing else — no amounts, no destination
   label, no input descriptions — so there is no field a proposer can use to
   influence what the sweep is worth.

Gate 1 without gate 2 would let a proposer supply invented amounts; gate 2
without gate 1 would let anyone with a transport identity drain the vault.

### 5.1 Design points

- **A separate RPC and a separate arm from payouts**, even though both return
  partial signatures over the same vault key — *because* they do. A payout is
  authorised by a burn on Solana, a sweep only by an operator's say-so.
  Sharing a path would create one place where the stronger condition could be
  reached through the weaker check.
- **Exactly one output.** A "sweep" with change leaves value under the key the
  sweep exists to abandon, so a second output is refused.
- **Sweeping a vault to itself is refused.** It spends everything, pays a fee,
  and returns the funds to the same possibly-compromised key.
- **A fee ceiling of 10× the policy fee.** Explicitly *not* a security
  boundary — the approval already commits to the exact fee. It guards against
  operator error, because misreading a fee field donates vault funds to a
  miner irreversibly.
- **No designated quorum.** A sweep is not derived from a withdrawal index, so
  there is nothing to designate from; every vault signer is asked and the
  first M that answer are the quorum. Sound here precisely because the
  operators, not the protocol, decide a sweep.
- **Semantic, not byte-level, commitment.** Consistent with the ADR-0015
  payout intent: a signer recomputes the commitment from its own view rather
  than hashing bytes it was handed.

### 5.2 A sweep can be partial, and says so

`available_utxos` excludes outputs reserved for in-flight payouts, so a sweep
planned while payouts are in flight does not move them. `glc-admin sweep-plan`
prints a warning naming how many outputs are excluded. Left silent, an
operator would believe a partial sweep was total and leave funds under the key
they meant to abandon.

## 6. `glc-admin` design points

- **It holds no keys.** Not a validator key, not a vault key, not the admin
  key. Recovery commands touch only this operator's own database; governance
  and sweep commands only stage an approval for this operator's own signer.
  Nothing in it can move value or change policy on its own.
- **`--note` is mandatory on every mutating command** and is written to the
  audit trail. An operator action with no recorded reason is
  indistinguishable from an intrusion six months later.
- **`sweep-approve --commitment` is checked, not trusted.** The operator
  states what they believe they are approving; the tool re-derives the plan
  locally and refuses to stage if the two differ. This is what catches "the
  number on my screen is not the number on yours" *before* signatures are
  collected rather than when they fail to combine.
- **`reassign-quorum` takes the new quorum explicitly.** ADR-0015 forbids
  implicit substitution, and the operator is the one who knows which signer is
  unavailable. It refuses outright if the payout is already signed, since
  reassignment changes the txid and the existing one may be in a mempool.
- **Vault configuration comes from the same environment the relayer and
  signer read.** A sweep planned against a vault the pipeline does not agree
  with is a sweep of the wrong vault.

## 7. Mutation testing

Twenty-three mutants were hand-applied to the new guards
(`docs/experiments/phase7i0-mutants.py`); all twenty-three are killed.

One **survived on the first run**: removing the sweep equivocation guard. No
test covered a signer that had already signed one sweep being asked to sign a
second, different one — two conflicting spends of the same outputs, which is
exactly what the guard exists to prevent. A test was added
(`having_signed_one_sweep_it_refuses_a_second_different_one`) and the mutant
now dies.

The first harness run also produced nineteen false survivors, from
`cargo test --lib a b c` silently being a usage error rather than three
filters, and from a restore that left the file's mtime older than the build
so cargo kept the mutant's artifact. Both are recorded in the script, because
a mutation harness that reports everything as killed for mechanical reasons
is worse than no harness at all.

## 8. Consequences

- ADR-0014 §8's rotation response and §8.7's compromise response are
  executable for the first time.
- Phase 7h-0's TVL raise is executable for the first time.
- The three operator recovery paths have supported callers.
- A new trust model exists in the system — operator intent as an
  authorisation source — confined to the two operations that cannot be
  derived, and stated as such rather than disguised as verification.
- Every arm remains **fail-closed**: a signer with no approvals path
  configured refuses every governance request, and one with no sweep path
  refuses every sweep.

## 9. What this ADR does not decide

- The runbook text itself (Phase 7i).
- Whether the relayer should ever *initiate* a sweep automatically. It should
  not, and nothing here can: there is no automatic path to a sweep, by
  construction.
- Canary rollout and launch readiness (Phase 7j).
