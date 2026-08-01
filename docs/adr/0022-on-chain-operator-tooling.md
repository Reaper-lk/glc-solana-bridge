# ADR-0022: On-chain operator tooling, and the cross-workspace encoding contract

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7i-1
- Extends: ADR-0021. Completes the executable surface ADR-0014 §13.5's
  runbooks depend on.
- Verification basis: §2, a second executability survey; §5, mutation testing
  of every new guard.

---

## 1. Context

ADR-0021 made the federation able to **produce** governance signatures. Going
to write the runbooks, a second survey found that nothing could **submit**
them, and that four more procedures were still not executable.

## 2. What the second survey found

`set_paused`, `lower_wrapped_supply_cap` and the whole rotation lifecycle
have existed on-chain since Phases 7a and 7h-0. Every builder for them lives
in `programs/glc-bridge/tests/common/mod.rs` — **the program's own test
suite**. The relayer builds exactly two instructions, `mint_wrapped` and
`complete_withdrawal`. `tests/bridge-e2e.ts` is a 19-line placeholder.

| runbook | before this phase |
|---|---|
| emergency pause and unpause | nothing submits `set_paused` |
| TVL breach | nothing submits `lower_wrapped_supply_cap` |
| key rotation | signatures yes (7i-0); no submission of propose/execute/cancel |
| vault key compromise | depends on all of the above |
| vault sweep | signing yes (7i-0); no collect-assemble-broadcast command |

So Phase 7i-0 closed the signing half of a gap whose submission half was
still open. That is worth stating plainly: the phase was verified against
"can a signature be produced?" rather than "can the procedure be completed?",
and the narrower question passed while the real one did not.

## 3. Decision

Add the missing submission tooling before writing any runbook that depends on
it — the same rule the owner set for the vault sweep in Phase 7i-0, applied
to the rest.

`glc-admin` gains:

- `pause`, `unpause`, `lower-tvl-cap` — admin-key actions;
- `show-pending`, `submit-rotation`, `submit-tvl-raise`, `submit-cancel`,
  `execute-rotation`, `execute-tvl-raise` — governance, collecting M
  signatures from the federation and submitting;
- `sweep-execute` — collects partials, assembles, broadcasts.

## 4. The cross-workspace encoding contract

ADR-0001 keeps the relayer in its own workspace with no dependency on
`anchor-lang` or the program crate, so these instructions are hand-encoded
(owner decision R1). The isolation is deliberate; its cost is that **nothing
mechanically links the two sides**. A renamed instruction or a reordered
accounts struct compiles cleanly on both and fails only at runtime, against a
real deployment, during the incident the tool exists to resolve.

Rather than weaken the isolation, both sides are pinned to the same literal
spec:

- `programs/glc-bridge/tests/admin_governance_encoding.rs` asserts that
  **Anchor generates** that spec — discriminators, argument layout, account
  order, mutability flags, and the `PendingGovernanceAction` byte offsets.
- `relayer/src/solana/instruction.rs`'s tests assert that the relayer
  **produces** it.

A change on either side now breaks a test on that side.

### 4.1 What the contract caught immediately

The two execute paths have **mirror-image writability**: a rotation writes the
validator set and only reads the config; a cap raise is the reverse. Both are
pinned, in both workspaces.

`PendingGovernanceAction`'s `proposed_max_wrapped_supply` sits at a **computed
offset**, not a fixed one — a cap raise carries no validators, so the field
lands 64 bytes earlier than for a two-validator rotation. Decoding it at a
fixed offset would silently return part of the reserved bytes.

## 5. Preflight checks, and why they are not the security boundary

`ops::preflight` holds the checks made before submitting: enough approvals,
nothing already pending, the right action type, the epoch unchanged, the
timelock elapsed.

**Every one is also enforced on-chain.** Nothing here can authorise something
the program would refuse. What they buy is a clear refusal instead of an
obscure one: an operator running `execute-rotation` four minutes early should
read "236 seconds remain", not a transaction signature and a program error
code to decode at 3am.

They live in the library rather than in `glc-admin` for the same reason
`p2p::policy` does: logic reachable only by standing up a cluster is logic
nothing tests.

### 5.1 A cancellation reads its target from the chain

`shared::governance::cancel_params` commits to the cancelled action **and its
eta**. An operator typing a remembered eta produces a proof the program
rejects — after the entire federation has been asked to sign it. So
`submit-cancel` takes no eta argument at all: it reads the pending action and
derives both.

## 6. The interim admin key (owner decision, 2026-08-01)

`pause`, `unpause` and `lower-tvl-cap` are gated by a **single admin key**,
not a threshold. One key holder can pause the bridge; one key holder can
unpause it; and losing that key removes the circuit breaker entirely.

The owner's decision for this phase is to **keep the model as implemented**,
document it clearly, and flag it as a launch-time governance consideration
rather than redesign it here. So:

- `custody.md` #7 ("who can pause, what quorum un-pauses") stays **OPEN** and
  is now cross-referenced from the code that depends on it;
- `glc-admin`'s pause commands state the single-key model in their help and
  in their doc comments, rather than implying a threshold exists;
- the pause runbook (Phase 7i) will document what is enforced today and name
  the open question.

This is recorded as a **known pre-launch gap**, not as a resolved design.

## 7. Mutation testing

Twenty-two mutants across `ops::preflight`, `decode_pending_action` and the
instruction encoders (`docs/experiments/phase7i1-mutants.py`); all killed.

**I6 initially reported "broken" rather than surviving**, and it was a real
survivor: changing `SEED_GOVERNANCE_ACTION` from `governance_action` to
`governance-action` broke no test. A wrong seed derives a different PDA, so
every governance transaction would address an account the program never
touches — silent, and visible only against a live cluster. A test now pins
every seed to its literal bytes.

The harness misreported it because `cargo test -p glc-bridge` was being run
from the *relayer* directory, which is a separate workspace, so the command
exited non-zero having run nothing and the mutant looked un-runnable rather
than un-caught. The harness now runs each side from its own root, and the
trap is documented in the script.

## 8. Consequences

- All eleven ADR-0014 §13.5 runbooks now describe procedures an operator can
  actually carry out. Phase 7i can be written.
- The relayer's workspace isolation is preserved, with its cost made explicit
  and tested rather than implicit and untested.
- The single-key pause model is documented as an open governance item.

## 9. What this ADR does not decide

- Whether pause should move to a threshold before launch (custody #7, open).
- The runbook text itself (Phase 7i).
- Canary rollout and launch readiness (Phase 7j).
- Testnet rehearsal, which ADR-0014 §8.7 requires and which remains unmet.
