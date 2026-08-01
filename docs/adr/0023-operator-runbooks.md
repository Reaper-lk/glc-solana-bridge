# ADR-0023: Operator runbooks, and keeping them executable

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7i
- Delivers: ADR-0014 §13.5, the eleven runbooks.
- Depends on: ADR-0021 (staged approvals, sweep) and ADR-0022 (on-chain
  submission), which exist because three of the eleven procedures had no
  executable form when §13.5 was written.

---

## 1. Context

`docs/runbooks.md` is read during incidents, by people under pressure, who
will type what it says. The governing constraint for this phase, set by the
owner: **document only procedures an operator can actually execute with
supported tools.**

## 2. What verification found this time

Writing the deep-reorg runbook exposed one more gap, of the same kind as the
previous two but in monitoring rather than tooling.

On a reorg deeper than `max_reorg_depth` the indexer **halts**: it stops
writing and refuses to progress until an operator intervenes, because
guessing a fork point is a security failure (ADR-0011). That behaviour is
correct. Its visibility was not:

- the halt lived in the indexer task's own memory;
- none of `/health`'s four invariants covered indexing;
- the process deliberately stays alive so orchestration does not
  restart-loop it, so liveness probes kept passing.

**A bridge that had stopped observing Goldcoin entirely reported healthy from
every angle an operator monitors.** The only evidence was a single
`tracing::error!` line, once, possibly hours earlier.

This is not a safety failure — a halted indexer mints nothing, so it fails
closed — but deposits silently stop being credited, and the runbook's
*detection* step had no honest answer beyond "grep the logs".

## 3. Decision

Add the visibility, then write the runbook — the same rule applied in 7i-0
and 7i-1.

`ops::indexer_status::IndexerStatus` is shared between the indexer loop and
the ops collector, exactly as `EpochObservation` is shared with the epoch
refresher.

### 3.1 One invariant, one gauge, and why not two invariants

| signal | kind | why |
|---|---|---|
| `indexer_not_halted` | **invariant** | unambiguous, requires an operator, never self-resolves |
| `glc_indexer_seconds_since_tick` | **gauge only** | a quiet chain produces no blocks and a brief node outage is retried |

The bridge has no basis for choosing the threshold that separates "slow" from
"broken" — that depends on the deployment's block rate and the operator's
tolerance. Exposing the number and paging on nothing is owner decision H2
applied consistently.

### 3.2 The halt is one-way in process

`record_halt` is never cleared by anything in-process. Clearing it means an
operator widened `max_reorg_depth` and restarted, which is a deliberate
human decision. A later successful tick must not decide the halt is over.

### 3.3 A report without an indexer omits the invariant

`build_report` takes `Option<IndexerSummary>`. Claiming an indexer is healthy
when the reporting process cannot see one would be worse than saying nothing.

## 4. The runbooks

Eleven sections, one per §13.5 procedure. Each states what the condition
means, how to **detect** it (a named invariant or metric, never "watch the
logs" where a signal exists), what to **do**, and how to **verify**.

Three properties were treated as load-bearing:

**Where no command exists, the document says so.** Widening
`max_reorg_depth` is a configuration change and a restart; §2 says that
plainly rather than inventing a `glc-admin` subcommand for it.

**Approval is per-operator and cannot be delegated.** §5 and §7 state that
the coordinator is *asking each operator to run a command*, not running it
for them. This is the property M-of-N exists to provide, and a runbook
written in the imperative can quietly obscure it.

**The irreversible cases are named.** A `Minted` deposit is not rolled back
by a reorg (§2). M compromised vault keys are unrecoverable (§5). Unpausing
re-checks nothing (§9). Manually paying a stuck withdrawal from the vault is
the exact condition §4 alarms on (§12).

## 5. The runbooks are tested

`relayer/tests/runbook_commands.rs` asserts, on every CI run, that:

- every `glc-admin` command the runbooks name exists in the binary;
- every command the binary offers is documented;
- every `GLC_*` variable the runbooks name is actually read;
- every `glc_*` metric they name is actually exposed;
- every invariant they name is actually reported;
- the honest limits (§6) are still recorded.

A renamed subcommand would otherwise turn a recovery step into "unknown
command" at the worst possible moment, and nothing would have failed. This is
the mechanism that stops the 7i-0/7i-1 problem recurring: documentation and
binary are checked against each other by CI, not by a reviewer's attention.

**It caught two real defects on its first run** — four commands referenced in
prose without a copyable form, and one command left undocumented.

Each extractor asserts it parsed something, so a broken extractor fails
loudly rather than passing vacuously. That failure mode — a check that
silently verifies nothing — has already appeared twice in this project's
mutation harnesses (ADR-0021 §7, ADR-0022 §7).

## 6. What the runbooks explicitly do not cover

Recorded in the document itself, and asserted by test:

- **Proof-of-reserves / attestation cadence** — custody #8, OPEN.
- **Program upgrade** — custody #5, OPEN.
- **Pause quorum** — custody #7, OPEN; pause remains single-admin-key
  (ADR-0022 §6).
- **Testnet rehearsal of the compromise response and key rotation** —
  required by ADR-0014 §8.7 and **not yet performed**.
- **Production confirmation depths and value caps** — no built-in defaults
  exist by design (owner decision U6).

## 7. Mutation testing

Ten mutants against the indexer-visibility guards
(`docs/experiments/phase7i-mutants.py`); all killed. They cover the one-way
halt, the staleness clamp and its overflow, the halt depth, the initial
state, the invariant's polarity, the gauge's polarity, and the
omit-rather-than-assume behaviour when no indexer is attached.

## 8. Consequences

- ADR-0014 §13.5 is delivered.
- A halted indexer is now an alarm rather than a log line.
- The runbooks cannot silently drift from the tooling.
- Phase 7j (canary rollout, launch checklist) is unblocked — with the
  rehearsal requirement still outstanding and now recorded in two places.
