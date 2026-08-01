# ADR-0020: Solvency monitoring, and the vault fee drift

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7h
- Implements: ADR-0014 §13.1 / §13.2 for the solvency and reconciliation
  monitors. Records a consequence of ADR-0013 **D3** that had never been
  written down.
- Empirical basis: §2, measured against a real `goldcoind` regtest node
  before the monitor was designed.

---

## 1. Context

ADR-0014 §13.1 names the master solvency invariant as the first thing an
operator should be paged about. Phase 7h had to decide what the monitor
actually compares — and measurement showed the obvious two candidates are
**not the same**, and disagree from the very first payout.

## 2. What was measured

Four real payouts through the real executor against one regtest node.

| after N payouts | (A) `wrapped ≤ deposits − payouts` | (B) `wrapped ≤ vault_balance` |
|---|---|---|
| 1 | holds, slack **0** | **fails** by 0.000226 GLC |
| 2 | holds, slack **0** | **fails** by 0.000452 GLC |
| 3 | holds, slack **0** | **fails** by 0.000678 GLC |
| 4 | holds, slack **0** | **fails** by 0.000904 GLC |

```
cumulative fees paid from the vault = 0.000904 GLC
gap equals fees exactly: true
```

Two findings:

**(A) holds with exactly zero slack, always.** Each burn reduces supply by
precisely the amount later paid out. There is no normal drift to tune a
threshold against, which makes it an unusually good alarm: *any* positive
breach is real.

**(B) fails from the first payout, and the gap is exactly the fees.**
ADR-0013 **D3** makes the vault absorb the payout fee — "the fee is funded
from the vault's own inputs and reduces change" — so each payout removes
`amount + fee` from the vault while supply falls by only `amount`.

**The consequence had never been recorded.** A search of `docs/` for
*deficit*, *top-up*, *subsidy*, or *under-backed* found nothing. D3 was an
explicit owner decision; its effect on backing was not stated anywhere.

### 2.1 Operator agreement

Two operators read the same chain, so the only thing that can differ is
confirmation depth:

```
min_conf=0 -> 207 GLC   (includes an unconfirmed 7 GLC deposit)
min_conf=1 -> 200 GLC
```

Disagreement is therefore **fully explained by in-flight value**, not noise.
The monitor pins its confirmation depth and treats in-flight deposits as
expected slack. No threshold tuning was needed, which is why §13.1's "alarm
on disagreement between operators" needs no fuzz factor.

---

## 3. Decisions

### D1. The monitor asserts the protocol invariant, not backing

```text
wrapped_supply <= confirmed_deposits - completed_payouts
```

This is threat-model invariant #1 verbatim. It holds with zero slack, so the
alarm fires on any breach and never on normal operation.

### D2. Fee drift is an OPERATIONAL metric, not a solvency failure

The vault's shortfall against that bound is reported separately, as
`glc_vault_fee_drift_atomic`, alongside `glc_vault_fees_paid_atomic`.

Folding it into the invariant was rejected: it would make the alarm
permanently red from the first payout, and an alarm that is always on is not
an alarm. ADR-0013's economics are unchanged — users still receive exactly
the burned amount.

Operators replenish the vault from an **external fee reserve**. The drift is
therefore visible, bounded and auditable rather than invisible.

### D3. Drift BEYOND the known fees is a separate alarm

`glc_vault_unexplained_drift_atomic` is the shortfall that recorded fees do
**not** explain, and it must be zero. Ordinary drift is expected; value
leaving the vault that no payout of ours accounts for is not, and conflating
the two would hide the second inside the first.

### D4. Structured for a later protocol-level fee model

The invariant and the drift are computed and exposed independently
(`SolvencySnapshot::backing_bound` versus `fee_drift_atomic`). Moving to a
protocol-level fee — charging the user, a deposit-side spread, or any other
scheme — changes only the drift term and leaves the invariant untouched.

### D5. Expose; never page

No SMTP, no PagerDuty, no webhooks, no vendor SDK (owner decision H2).
`/health` returns **503** when any page-immediately invariant is breached and
operators point existing alerting at it. The relayer holds no alerting
credentials and makes no outbound calls on anyone's behalf.

Metrics are Prometheus text exposition (owner decision H3), hand-rendered so
the dependency graph gains nothing.

### D6. An unreadable quantity is omitted, never defaulted

A vault balance of "0 because the node is down" and "0 because it is empty"
mean opposite things. Unreadable quantities are left out of the report, and
`glc_*_readable` gauges say which. A report with **nothing** measured is 503,
not a cheerful empty OK.

---

## 4. Consequences

- The bridge has a runtime check for the one standing invariant that had
  none.
- The fee deficit is now a first-class, monitored quantity with a stated
  replenishment story, instead of an undocumented consequence of D3.
- `/health` is unauthenticated by design and **must be bound privately**; it
  reveals balances and supply. `main.rs` logs a warning with the bind
  address at startup.
- The endpoint is optional, but its absence is logged loudly: a bridge
  nobody can observe should not be live.

## 5. Out of scope

- Runbooks and operator procedures (Phase 7i).
- Canary rollout and the launch checklist (Phase 7j).
- Any change to ADR-0013's payout economics.
