# ADR-0024: Launch readiness, and rehearsal as automation

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7j
- Delivers: ADR-0014 §8.7's rehearsal requirement, §13/§14's pre-launch
  checklist, and a verified deployment configuration reference.

---

## 1. Context

Every phase since 7 has carried the same outstanding item: ADR-0014 §8.7
requires key rotation and the compromise response to be "rehearsed on
testnet, not written and filed". Phase 7j closes it, and takes stock of what
else remains before launch.

## 2. Decision: rehearsal as a test, not an event

A rehearsal performed once, by hand, on a particular afternoon, verifies the
code as it was that afternoon. Both procedures here are instead **executable
suites** that run the documented runbook steps against real nodes:

| suite | runs against | covers |
|---|---|---|
| `rehearsal_rotation.rs` | real `solana-test-validator`, real program | runbook §7 (rotation), §9 (pause) |
| `rehearsal_compromise.rs` | real `goldcoind` regtest | runbook §5 steps 4–6 (sweep) |

Both follow the operator's sequence — stage, collect, submit, wait, execute —
through the same `SignerService` and `SweepView` decision paths production
uses, and assert the outcomes the runbooks promise rather than merely that
nothing errored.

### 2.1 What they assert that a unit test cannot

- the governance timelock is enforced **by the program**, not only by the
  client-side preflight: executing early fails on chain;
- a rotation bumps the epoch, installs the proposed set in the proposed
  order, and frees the singleton slot;
- **approvals do not survive a rotation** — the staged files are untouched
  and still name the old epoch, and under the new one they authorise nothing;
- two of three approvals suffice, so M is genuinely the threshold rather than
  unanimity by accident;
- a sweep leaves the old vault **empty** and pays the destination exactly the
  approved amount, with the txid predicted before broadcast;
- a signer with nothing staged refuses a *real* transaction.

### 2.2 They self-skip, and that is stated everywhere it matters

Both suites skip when `GOLDCOIND_BIN` / `GLC_BRIDGE_SO` /
`solana-test-validator` are absent, which is how CI runs them. **A green CI
run is therefore not evidence that the rehearsals passed.** Said in the
suites, in ADR-0014 §8.7.2, and in the launch checklist — and asserted by
test, because a caveat that can quietly disappear is worse than none.

## 3. What the rehearsal found

On its first run, the compromise rehearsal failed with `UnknownInput` on
every input.

Goldcoin serializes an input's previous-output txid in **internal** order.
`VaultUtxo::txid` holds **display** order, decoded straight from
`listunspent`. `verify_sweep_tx` and the signer's input lookup compared them
directly, so **`sweep-execute` would have refused every genuine sweep** — the
compromise response would have failed at the moment it was needed.

Every unit fixture built both sides from the same array, so 22 tests and 23
killed mutants all agreed with each other and with nothing else. This is the
same self-consistent-fixture trap recorded in Phase 7f, and it is the second
time it has produced a defect that only a real node could reveal.

Fixed with an explicit `sweep::internal_txid` conversion. The regression test
pins the convention against a **known-wrong value** rather than against the
fixture, and a companion test asserts the fixture txid is not a palindrome —
a uniform `[seed; 32]` array reverses to itself, which would have made every
byte-order assertion vacuous.

**This is the argument for §8.7 in one incident.** No amount of review or
unit testing would have found it; a real node has an opinion about byte order
and nothing else does.

## 4. Deployment configuration, verified

`docs/federation-deployment.md` dated from Phase 7d and had never been
updated. **Thirty-four variables the binaries read were undocumented.**

Two matter more than the rest, because they are *optional and fail closed*:
`GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` and
`GLC_SIGNER_SWEEP_APPROVALS_PATH`. An operator deploying from the previous
guide got a federation that started cleanly, served deposits and payouts
correctly, and **could not rotate its keys or escape a compromised vault** —
with nothing to indicate it until the day that mattered.

`deployment_config.rs` now asserts that every variable each binary reads is
documented, that nothing documented has stopped being read, that the two
fail-closed variables state their consequence, and that the guide says the
signer's Goldcoin node must be **its own** (ADR-0017 E2 — the natural
mistake, since both processes run on one host).

## 5. The launch checklist

`docs/launch-checklist.md` separates **verified** from **open**, and an item
is ticked only when something fails if it stops being true. Every "verified"
row names the test that verifies it, and a test asserts those files exist —
a cited test that has been renamed turns a tick into a claim nobody checks.

It opens by stating the bridge **is not launch-ready**, and that sentence is
asserted by test for as long as open items remain.

### 5.1 What is open

- **custody #1** (federation composition), **#5** (upgrade authority), **#7**
  (pause quorum — still a single interim admin key), **#8**
  (proof-of-reserves);
- **§13.4**: backup, restore drills, and the offline auditor — none built;
- **§13.1 (5)**: no early warning for a reorg *approaching*
  `max_reorg_depth`; only the halt is exposed;
- **§14**: no independent security audit has begun;
- every security parameter — confirmation depths, value caps, supply ceiling,
  governance timelock — is unset, deliberately (owner decision U6).

### 5.2 Rollback is "stop", not "reverse"

There is no un-mint and no un-complete instruction, by design. The checklist
states the consequence plainly: the maximum loss from a launch-day defect is
bounded by the supply ceiling in force when it fires, and by nothing else.
That is what makes `lower-tvl-cap` the load-bearing control during a canary,
and why the sequence starts paused with a low ceiling.

## 6. Consequences

- ADR-0014 §8.7 is satisfied, and re-satisfied on every deliberate run.
- A defect that would have broken the compromise response in production was
  found and fixed before launch rather than during an incident.
- The deployment guide cannot silently drift from the binaries.
- The remaining pre-launch work is enumerated in one place, with no item
  resting on "we reviewed it".

## 7. What this ADR does not decide

- Any of the open custody decisions — those are the owner's.
- Whether to build the §13.4 auditor before launch, or accept restore drills
  as a manual procedure.
- The production values for any capped or timelocked parameter.
- When the audit happens.
