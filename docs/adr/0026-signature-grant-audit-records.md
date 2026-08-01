# ADR-0026: Recording granted signatures

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7l
- Delivers: the signature half of ADR-0014 §13.3.

---

## 1. What was missing

§13.3 requires the audit trail to carry "every signature decision". Every
signing path logged its **refusals** from the day it was written — a refusal
means this validator disagrees with a peer, which is an alarm.

Three of the five paths logged nothing when they **granted**:

| path | refusal | grant (before) |
|---|---|---|
| mint | logged | **nothing** |
| payout | logged | **nothing** |
| completion | logged | **nothing** |
| governance | logged | logged |
| sweep | logged | logged (in the view) |

## 2. Why that is backwards

After an incident the question is rarely "what did we refuse"; it is "what
did we authorise, and when".

A refusal is recoverable from the peer that was refused. A grant, once
aggregated into someone else's transaction, is recoverable only from the
chain — and not at all when the question is whether **this signer** was
induced to sign something it should not have. The path that exercises a
validator's authority was the one path that left no trace.

## 3. Decision

One typed event, `signature_granted`, emitted at each of the five decision
points with a consistent shape: action, the identity of the thing signed,
and which validator signed it.

- **Level.** `info!` for mint, payout and completion — the bridge doing its
  job many times an hour. `warn!` for governance and sweep, which change who
  the federation is or move every coin the vault holds, and must not be
  filtered out with routine traffic.
- **Emitted at the decision point**, not in the transport layer, so a grant
  is recorded however the service was driven. The transport's peer logging
  sits alongside and answers a different question ("who asked").
- **Not recorded:** the signature bytes (the authoritative copy is on chain
  or in the transaction; a second copy invites treating the log as the source
  of truth), the canonical message (the identity determines it), and
  obviously no key material. A test asserts neither leaks.

### 3.1 A log, not a table

§13.3 describes the audit trail as "append-only, shipped off-host" — a
log-shipping model. The state-transition tables it names alongside exist
because those record *state*; a signature decision is an *event*.

The honest cost: **a log lost before shipping is gone.** Shipping remains an
open launch-checklist item. A row would survive log loss, at the price of a
database write on every signature, on a path where `Db` is `Send` but not
`Sync` and where the signer deliberately does as little as possible. The
trade is recorded rather than left to be rediscovered.

### 3.2 The sweep now reports what it authorised

The service did not know the swept amount — only the view did — so the first
draft logged `swept_atomic: 0`. A placeholder in an audit record is worse
than an absent field: it is a number that is not true. `SweepView` now
returns `SweepPartial { partial, swept_atomic, inputs }` so the record states
what actually left the vault.

## 4. Mutation testing

Sixteen mutants (`docs/experiments/phase7l-mutants.py`); all killed.

**Four survived the first run — the payout, completion, governance and sweep
call sites.** The audit suite exercised only `handle` (mint), so deleting the
record from any other path broke nothing. Testing one representative path and
assuming the rest is precisely the mistake Phase 7k found in the auditor, one
phase earlier, and I repeated it.

Fixed by covering all five: governance and sweep in the audit suite, payout
and completion beside the fixtures that already build those arms
(`tests/common/mod.rs` holds the shared capture helper).

**Two then still appeared to survive, and were a harness bug** — the payout
and completion tests live in suites the harness was not running. That is the
**third** time a mutation harness in this project has misreported a result
(ADR-0021 §7, ADR-0022 §7). Each instance has been a different mechanism and
each was caught only by disbelieving a suspiciously uniform result.

## 5. Consequences

- §13.3's signature half is delivered; off-host shipping remains open.
- Every audit record is asserted by a test that captures real `tracing`
  output, so a deleted call site fails CI rather than silently reducing the
  trail.

## 6. What this ADR does not decide

- Log shipping, retention, or the aggregation stack — deployment decisions.
- Whether to additionally persist grants to a table, should log loss prove a
  real operational problem.
