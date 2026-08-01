# Operator runbooks

Phase 7i. Implements ADR-0014 §13.5.

**Every command here has been checked against the shipped binaries.** Where a
procedure has no executable form, this document says so plainly instead of
describing one. That constraint is why Phases 7i-0 (ADR-0021) and 7i-1
(ADR-0022) exist: three of these eleven procedures could not be carried out
at all when they were first written down, and a runbook step that cannot be
performed is worse than none, because it is believed.

## Before an incident

Read this section now, not during one.

### The two processes

| process | holds | serves |
|---|---|---|
| `glc-relayer` | no keys except the Solana fee payer | `/health`, `/metrics` on `GLC_OPS_LISTEN_ADDR` |
| `signer-server` | **one** validator ed25519 key, and optionally one vault key | the federation gRPC over mTLS |

`glc-admin` is a one-shot tool, not a daemon. It holds no validator key, no
vault key and no admin key.

### The health endpoint

`GET /health` returns **200** when every invariant holds and **503** when any
is breached. `GET /metrics` is **always 200** — a scrape that fails because
the bridge is unhealthy destroys the data you need to diagnose it.

Five invariants:

| invariant | breached when |
|---|---|
| `solvency` | `wrapped_supply > confirmed_deposits − completed_payouts` |
| `vault_reconciliation` | vault drift exceeds the fees we know we paid |
| `no_integrity_halts` | any deposit or withdrawal is `IntegrityHalted` |
| `validator_epoch_fresh` | this process has stopped observing the validator epoch |
| `indexer_not_halted` | the indexer stopped on an over-deep reorg |

The endpoint has **no authentication**. Bind it to a private interface.

### Every mutating command demands `--note`

It is written to the audit trail. An operator action with no recorded reason
is indistinguishable from an intrusion six months later.

### What "approve" does and does not mean

`glc-admin approve-*` and `sweep-approve` **stage an approval for this
operator's own signer**. They perform nothing. The action happens only once M
operators have each independently run the matching command on their own host
(ADR-0021 §4). If you are coordinating an incident, you are asking each
operator to run a command — you cannot run it for them.

---

## 1. Integrity halt

**What it means.** A safeguard found that persisted state no longer matches
what was committed to. This is never routine: it means a bug, database
corruption, or tampering. It is never retried automatically.

**Detect.** `/health` reports `BREACH no_integrity_halts`, and
`glc_integrity_halted_deposits` / `glc_integrity_halted_withdrawals` are
non-zero.

**Diagnose.**

```
glc-admin status --db "$GLC_DB_PATH"
```

This prints every halted deposit and withdrawal with the recorded reason.

**Decide.** There are exactly two destinations, and the tooling enforces
them:

- a deposit may go to `ReadyForSignature` (re-verify and, if genuinely sound,
  proceed — the reload-and-recompute safeguard runs again from scratch and
  will halt it right back if the anomaly persists) or to `Failed`;
- a withdrawal may go to `Validated` or `Failed`.

Neither can be moved to a state that implies a payment happened. **Establish
why the anomaly occurred before clearing it.** Clearing a halt whose cause you
have not found re-runs the same path that detected it.

**Act.**

```
glc-admin clear-deposit-halt    --db "$GLC_DB_PATH" --id 41   --to Failed --note "INC-12: ..."
glc-admin clear-withdrawal-halt --db "$GLC_DB_PATH" --index 7 --to Validated --note "INC-12: ..."
```

The halt record is never deleted; the recovery is appended beside it.

**Verify.** `glc-admin status` shows no halts and `/health` returns 200.

---

## 2. Deep reorg

**What it means.** Goldcoin reorganised. Two cases, and they are very
different.

**Case A — within `max_reorg_depth`.** Handled automatically: the indexer
rolls back every affected block and moves active deposits
(`Candidate`, `Confirming`, `ReadyForSignature`, `Submitted`) to `Orphaned`,
transactionally, recording `reorg_rollback` in the state log. **No operator
action is required.** You will see `reorg detected and rolled back` in the
logs.

**Case B — deeper than `max_reorg_depth`.** The indexer **halts**. It makes no
writes and refuses to progress on any future tick, because guessing a fork
point is a security failure (ADR-0011). The process stays alive so
orchestration does not restart-loop it.

**Detect.** `/health` reports `BREACH indexer_not_halted` and
`glc_indexer_halted` is `1`. The log line is
`reorg deeper than max_reorg_depth: indexer halted`.

**Act.** This requires a human decision, not a command:

1. **Establish the true chain state** from your Goldcoin node independently.
2. **Check for minted deposits in the reorged range.** A deposit already in
   `Minted` is **not** rolled back — the wrapped tokens exist on Solana and
   the mint cannot be undone. If the Goldcoin transaction backing a minted
   deposit is gone, the solvency invariant is genuinely broken and you are in
   §3, not here.
3. Decide whether the reorg is legitimate. If it is not, **pause** (§9).
4. If it is, restart `glc-relayer` with a wider `GLC_MAX_REORG_DEPTH`. The
   halt is only cleared by a restart — deliberately, so no in-process logic
   can decide the halt is over.

**There is no `glc-admin` command for this.** Widening the depth is a
configuration change and a restart, and pretending otherwise would be exactly
the aspirational documentation this phase exists to remove.

---

## 3. Solvency breach

**What it means.** `wrapped_supply` exceeds `confirmed_deposits −
completed_payouts`. Measured to hold with **exactly zero slack** in normal
operation (ADR-0020 §2), so any positive breach is real — there is no normal
drift to discount.

**Detect.** `/health` reports `BREACH solvency`; `glc_solvency_breach_atomic`
is the size of the shortfall.

**Act, in this order:**

1. **Pause immediately** (§9). Every further mint enlarges the breach.
2. **Lower the supply cap** to the current supply, so nothing can be minted
   even if the pause is lifted before the cause is found:
   ```
   glc-admin lower-tvl-cap --new-max <current_supply> --note "INC-n: solvency breach"
   ```
   This is admin-only, immediate, and cannot be reversed without a
   threshold-approved, timelocked raise (§8).
3. **Find the cause.** The breach is arithmetic on three numbers; check each
   against its source. `glc_wrapped_supply_atomic` comes from the SPL mint,
   `glc_confirmed_deposits_atomic` and `glc_completed_payouts_atomic` from
   this operator's database. Compare with another operator's endpoint — if
   they disagree, one database is wrong, which is a different problem from an
   actual breach.
4. Do not unpause until the numbers reconcile.

**Note:** vault *fee* drift is **not** a solvency breach. It has its own
invariant (`vault_reconciliation`) and its own metric
(`glc_vault_fee_drift_atomic`), because ADR-0013 D3 makes the vault absorb
Goldcoin fees by design. See §4.

---

## 4. Vault reconciliation breach

**What it means.** Value left the vault that no payout of ours accounts for,
beyond the fees we know we paid.

**Detect.** `/health` reports `BREACH vault_reconciliation`;
`glc_vault_unexplained_drift_atomic` is non-zero.

**Act.** Treat as a possible vault-key compromise until proven otherwise:
pause (§9), then work §5. A benign explanation — an operator spending vault
outputs manually, a misconfigured node — must be *established*, not assumed.

**Expected, and not this alarm:** `glc_vault_fee_drift_atomic` grows with
every payout. Operators replenish the vault from an external fee reserve
(ADR-0020). Drift *equal to* known fees is healthy.

---

## 5. Vault key compromise

ADR-0014 §8.7. This is the procedure with the most moving parts; every step
below is executable.

> **Not yet rehearsed.** ADR-0014 §8.7 requires this be rehearsed on testnet
> before launch. That requirement is **not met**. Rehearse before relying on
> the timings here.

**1. Pause.** (§9.) Stops new mints and payouts.

**2. Rotate the federation** if validator keys are also suspect (§7). If only
the *vault* keys are suspect, skip to step 3.

**3. Generate the new vault** out of band, following the key ceremony in
ADR-0014 §8.3. You need its `hash160` and its address.

**4. Every operator plans the sweep independently:**

```
glc-admin sweep-plan --db "$GLC_DB_PATH" \
  --dest-hash160 <20-byte hex> --dest-address <Q...>
```

Each prints a `commitment`. **Compare them across operators before anyone
approves.** Differing commitments mean differing views of the vault contents,
not a tooling problem — reconcile first.

Note the warning `sweep-plan` prints if outputs are reserved for in-flight
payouts: those will **not** be swept. Release or complete them for a total
sweep.

**5. Every operator approves the same commitment:**

```
glc-admin sweep-approve --db "$GLC_DB_PATH" \
  --sweep-approvals "$GLC_SIGNER_SWEEP_APPROVALS_PATH" \
  --dest-hash160 <hex> --dest-address <Q...> \
  --commitment <32-byte hex> --note "INC-n: vault compromise"
```

`--commitment` is **checked, not trusted**: the tool re-derives the plan
locally and refuses to stage if it disagrees. Approvals expire after 6 hours.

**6. One operator executes:**

```
glc-admin sweep-execute --db "$GLC_DB_PATH" \
  --dest-hash160 <hex> --dest-address <Q...> --note "INC-n: vault compromise"
```

It collects partials, assembles (verifying every signature against its
input's sighash), and broadcasts. If fewer than M operators have approved it
broadcasts nothing and tells you who is missing.

**7. Reconfigure** every relayer and signer with the new vault
(`GLC_VAULT_REDEEM_SCRIPT_HEX`, `GLC_VAULT_ADDRESS`,
`GLC_VAULT_CHANGE_ADDRESS`) and restart.

**8. Revoke any leftover approval:**
`glc-admin sweep-revoke --sweep-approvals "$GLC_SIGNER_SWEEP_APPROVALS_PATH"`

**If M vault keys are compromised, the funds are gone.** This is the
irreducible risk of a federated bridge (ADR-0014 §8.7) and no procedure
recovers from it.

---

## 6. Validator offline

**What it means.** One federation member is unreachable.

**Detect.** Collection rounds log `unreachable <pubkey>`. That peer's own
`/health` is unreachable or reports a stale epoch.

**Impact, by path:**

- **Mints and completions** — no designated quorum: *any* M validators may
  sign. Below M they simply retry next tick. No action needed unless you are
  persistently below threshold.
- **Payouts** — a quorum is *designated* per withdrawal (ADR-0015), so an
  offline designated signer blocks that specific payout.

**Act (payouts only).** Bring the signer back if you can. If you cannot,
reassign — explicitly, because implicit substitution is forbidden:

```
glc-admin reassign-quorum --db "$GLC_DB_PATH" --index 7 --quorum 1,2 \
  --note "INC-n: signer 0 unavailable"
```

**Reassignment changes the payout txid.** Every operator must reassign to the
same attempt and the same quorum before signatures can be collected. The
command refuses if the payout is already signed — rebroadcast that instead.

---

## 7. Key rotation

Threshold-approved and timelocked (ADR-0014 §7). No admin-gated path exists.

**1. Agree the new set and its order.** Order is significant: it fixes each
validator's bitmask index, and two orderings are different proposals with
different commitments.

**2. Every operator stages an approval,** on their own host:

```
glc-admin approve-rotation --approvals "$GLC_SIGNER_GOVERNANCE_APPROVALS_PATH" \
  --epoch <current> --threshold 3 --validators <A>,<B>,<C>,<D>,<E> \
  --note "planned rotation, ticket OPS-n"
```

Approvals last 24 hours and **do not survive a rotation** — one applying
elsewhere invalidates them. Check and withdraw with:

```
glc-admin list-approvals  --approvals "$GLC_SIGNER_GOVERNANCE_APPROVALS_PATH"
glc-admin revoke-approval --approvals "$GLC_SIGNER_GOVERNANCE_APPROVALS_PATH" --action 3
```

Revocation takes effect immediately — the signer re-reads the file on every
request, so no restart is needed.

**3. One operator submits:**

```
glc-admin submit-rotation --threshold 3 --validators <A>,<B>,<C>,<D>,<E> \
  --note "planned rotation, ticket OPS-n"
```

This collects M signatures and queues the rotation behind the timelock. If
fewer than M operators have approved, it submits nothing and names who is
missing. Refusals here are **ordinary** — an operator who has not approved is
behaving as designed.

**4. Wait for the timelock.** `glc-admin show-pending` reports the eta and
the seconds remaining.

**5. Execute** once elapsed:

```
glc-admin execute-rotation --note "planned rotation, ticket OPS-n"
```

Permissionless — the threshold proof at proposal time was the authorization.

**6. Reconfigure** `GLC_FEDERATION_PEERS` on every host and restart.

**To abandon a queued rotation.** Read the pending action's type and eta
from `glc-admin show-pending`, then every operator stages a cancellation:

```
glc-admin approve-cancel --approvals "$GLC_SIGNER_GOVERNANCE_APPROVALS_PATH" \
  --epoch <current> --pending-action <N> --pending-eta <N> --note "OPS-n: abandoned"
```

and one operator submits it:

```
glc-admin submit-cancel --note "OPS-n: abandoned"
```

`glc-admin submit-cancel` takes **no eta argument**: it reads the action and
its eta from the chain, because `cancel_params` commits to both and a
remembered eta produces a proof the program rejects after everyone has
already signed it.

---

## 8. TVL breach, and changing the cap

**Lowering is immediate and admin-only.** Raising needs threshold plus
timelock. The asymmetry is deliberate: reducing exposure is incident
response, increasing it is a federation decision (ADR-0014 §11.1).

**Detect.** Mints begin failing against the cap; `glc_wrapped_supply_atomic`
is at or near the configured ceiling.

**To lower** (incident):

```
glc-admin lower-tvl-cap --new-max <atomic> --note "INC-n: ..."
```

Immediate, irreversible without §8's raise path. Zero is rejected.

**To raise** (planned): the same three-step shape as a rotation —

```
glc-admin approve-tvl-raise --approvals "$GLC_SIGNER_GOVERNANCE_APPROVALS_PATH" \
  --epoch <current> --new-max <atomic> --note "OPS-n"      # every operator
glc-admin submit-tvl-raise --new-max <atomic> --note "OPS-n"   # one operator
glc-admin show-pending                                          # wait for the eta
glc-admin execute-tvl-raise --note "OPS-n"                      # one operator
```

The program **re-checks the ceiling at execution**, so a supply change during
the timelock can still refuse it.

---

## 9. Emergency pause and unpause

> **Interim single-key model — `custody.md` #7 is OPEN.**
> Pause and unpause are gated by **one admin key**, not a threshold. One
> holder can pause; one holder can unpause; **losing that key removes the
> circuit breaker entirely.** Whether pause should require a quorum is a
> launch-time governance decision that has not been made (ADR-0022 §6). This
> section documents what the program enforces today.

**Pause:**

```
glc-admin pause --note "INC-n: reason"
```

**Unpause:**

```
glc-admin unpause --note "INC-n: cause resolved, ticket ..."
```

The program rejects a no-op, so pausing an already-paused bridge errors —
that is a safe failure, not a problem.

**Unpausing does not re-check anything.** The bridge resumes minting and
payouts immediately. Confirm the original condition is actually resolved
first; nothing verifies that for you.

---

## 10. Solana outage

**What it means.** The Solana RPC is unreachable or lagging.

**Detect.** `validator_epoch_fresh` breaches once the epoch observation goes
stale. Logs show retries.

**Impact.** Fails closed. Deposits accumulate in `ReadyForSignature`;
signers refuse everything while their view is stale, rather than authorizing
under a federation revision they may have fallen behind. Nothing is lost.

**Act.** Restore RPC access, or point `GLC_SOLANA_RPC_URL` at another
endpoint and restart. **No recovery command is needed** — the pipeline
resumes on its own, and every deposit is re-derived from its frozen
commitment rather than from anything cached.

---

## 11. Goldcoin outage

**What it means.** This operator's Goldcoin node is unreachable.

**Detect.** `glc_indexer_seconds_since_tick` climbs. Logs show
`Goldcoin node unavailable, retrying`.

This is a **gauge, not an alarm** — a quiet chain also produces no blocks, and
the bridge has no basis for choosing your threshold. Alert on it in your own
monitoring, at a value that suits your deployment.

**Impact.** Fails closed. Deposit discovery stops; payout building stops;
signers refuse payouts they cannot verify against their own node (ADR-0017
E2). Nothing is lost and nothing is double-paid.

**Act.** Restore the node. Indexing resumes from the last indexed block.
**No recovery command is needed.** If the node was restored from a snapshot
behind the bridge's last indexed height, treat it as §2.

---

## 12. Stuck withdrawal

**Detect.** `glc_withdrawals_by_state` shows a withdrawal sitting in one
state; `glc-admin status --db "$GLC_DB_PATH"` names it.

**By state:**

| state | meaning | action |
|---|---|---|
| `AwaitingFunds` | the vault cannot cover it | fund the vault; it proceeds on its own |
| `Building` / `Signing` | quorum incomplete | §6 — reassign if a designated signer is down |
| `Broadcast` / `Confirming` | waiting on Goldcoin | wait; check the node and the fee rate |
| `IntegrityHalted` | a safeguard fired | §1 |

**Never** resolve a stuck withdrawal by paying it manually from the vault.
That spends outputs the executor believes are reserved, and it is exactly the
condition §4 alarms on.

---

## What is deliberately absent

- **Proof-of-reserves / attestation cadence** — `custody.md` #8, OPEN; no procedure exists.
- **Program upgrade** — `custody.md` #5 (upgrade-authority custody), OPEN.
- **Pause quorum** — `custody.md` #7, OPEN; see §9.
- **Testnet rehearsal of §5 and §7** — required by ADR-0014 §8.7 and **not
  yet performed**.
- **Production confirmation depths and value caps** — no built-in defaults
  exist, by design (owner decision U6). These are live security decisions.
