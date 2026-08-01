# ADR-0025: The offline integrity auditor, and seeing a reorg coming

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7k
- Delivers: ADR-0014 §13.4 (integrity auditing) and §13.1 item 5 (reorg
  early warning) — two of the launch checklist's open items.

---

## 1. Why an auditor exists when the signing guards already check

`verify_and_load_signable_message` and `verify_and_load_signable_payout`
re-derive a record's commitment and compare, immediately before signing it
(ADR-0012, ADR-0015). That is the right place for a guard.

It is the wrong place for an audit. The guard checks **one record, once, at
signing time**. A deposit minted last month is never re-examined; corruption
in a row nothing is about to sign is invisible until something needs it, by
which point the useful backups have rotated away.

`glc-audit` walks **every** row, on demand, using the same
recompute-and-compare logic. It is what makes an hourly snapshot a backup
rather than a file.

## 2. Read-only, deliberately

The guards halt the record they find a problem in. The auditor does not, for
two reasons:

- it is meant to run against a **backup**, possibly on another host. Halting
  a copy achieves nothing, and writing to a file an operator is about to
  restore from is actively harmful;
- an auditor that mutates cannot be run casually, and one that cannot be run
  casually does not get run.

A test asserts the database file is byte-identical afterwards.

Findings are reported for a human to act on with `glc-admin`, which is where
the audit trail lives.

## 3. Two checks, because either alone is defeatable

| check | catches |
|---|---|
| `sha256(stored_message) == stored_hash` | one of the pair altered independently of the other |
| recompute from persisted fields `==` stored message | a field that drifted after the commitment was frozen |

An attacker who rewrites the message **and** recomputes its hash passes the
first and fails the second. A test does exactly that, because a check whose
bypass is never exercised is a check nobody knows the shape of.

### 3.1 Findings name the field, not an offset

A byte offset is not something an operator can act on at 3am, so a mismatch
is reported as `amount` or `recipient`. Every committed field has a test
asserting it is caught **and named as itself** — a mismatch reported against
the wrong field sends an operator to the wrong place, which is worse than an
unhelpful message.

### 3.2 It never reports a pass it did not earn

- `PayoutInputsMissing` is a finding, not a skip: silence about a record that
  could not be checked is indistinguishable from a pass.
- An undecodable change address is a finding, not a default to twenty zero
  bytes, which would make a corrupt row look like a no-change payout.
- Only the exact string `"ok"` passes `PRAGMA integrity_check` — everything
  else the audit reports is computed from a database it has just been told it
  cannot trust.
- The report always states what it checked, so "clean" over zero records
  cannot be mistaken for "clean" over ten thousand.
- Exit `0` clean, `1` findings, `2` could-not-run — distinct, because an
  audit that could not run is not a passing audit, and collapsing the two
  makes a broken cron entry look like a clean bill of health.

## 4. Seeing a reorg coming (§13.1 item 5)

Phase 7i made the indexer **halt** visible. But the halt is the failure, not
the warning: by the time it fires the bridge has already stopped indexing.

`glc_reorg_deepest_observed` and `glc_reorg_max_depth_configured` are now
exposed together, so a scraper can read one as a fraction of the other
without knowing the deployment's configuration.

**Gauges, not an invariant.** A deep-but-survivable reorg is a fact about
Goldcoin, not a fault in the bridge, and the depth that should worry a given
deployment depends on its confirmation policy and risk appetite — the
operator's decision, not this crate's (owner decision H2).

The **deepest** reorg is kept rather than the most recent: a 40-block reorg
an hour ago is the fact an operator needs, and a later 1-block reorg must not
erase it.

## 5. Mutation testing

Seventeen mutants (`docs/experiments/phase7k-mutants.py`); all killed.

**Five survived the first run, and all five were in the payout half of the
auditor** — removing either payout check, silently skipping a payout whose
inputs were gone, defaulting an undecodable change address, and mis-handling
a failed `integrity_check`. That half had no tests at all: I wrote
`check_payout` and tested only `check_claim`.

The deposit side was thoroughly tested and the payout side was not, which is
not a distinction any reviewer would have drawn from reading the file — both
halves look equally deliberate. It took mutants to notice.

Fixing A9 also required a small design change: the integrity-check verdict is
now a pure `check_integrity` function rather than an inline comparison, so
the "only `ok` passes" rule is testable at all.

## 6. Consequences

- Two launch-checklist items move from open to verified.
- The remaining §13.4 item is the **restore drill**, whose procedure is now
  written (runbook §13) and which has still never been performed. Documented
  as such rather than ticked.
- `docs/runbooks.md` §13 gives operators a snapshot command, an audit
  command, and the instruction to alert on exit `2` as loudly as on `1`.

## 7. What this ADR does not decide

- Backup retention, destination, or encryption — deployment decisions.
- Whether to ship audit logs off-host (§13.3), still open.
- Any custody decision.
