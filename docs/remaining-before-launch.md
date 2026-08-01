# Remaining before launch

Final engineering report, 2026-08-01. Supersedes nothing; complements
`docs/launch-checklist.md`, which is the operational form of the same
information.

**Every launch step below was verified against the built binaries**, not
against the source and not from memory. Where a step depends on an external
tool, that tool was checked for on the host.

---

## 1. Verification method

The launch-day sequence in `launch-checklist.md` was walked step by step
against `target/release/{glc-relayer,signer-server,glc-admin,glc-audit}`:

| step | how it is performed | verified by |
|---|---|---|
| 1. Freeze the commit | process, no tooling | — |
| 2. Key ceremony | `solana-keygen`; `goldcoin-cli createmultisig`; `signer-server` proves it holds its vault key at its configured position before serving (ADR-0017 E1) | external tools present; E1 refusal is tested |
| 3. Deploy, initialize, create mint, verify | `anchor`/`solana`, then `glc-admin initialize` / `create-wrapped-mint` / `show-config` | **rehearsed end to end on a real validator** |
| 4. Start paused | `glc-admin pause` | rehearsed on a real validator |
| 5. Bring up operators | `glc-relayer`, `signer-server`; `/health` | both daemons fail closed naming the missing variable; endpoint covered by HTTP tests |
| 6. Cross-check operators | `curl` on `/metrics` | endpoint tested; disagreement is the documented alarm |
| 7. Rehearse on the real deployment | `glc-admin` rotation and sweep commands | **both rehearsed against a real validator and a real `goldcoind`** |
| 8. Set a low ceiling | `glc-admin lower-tvl-cap` | dispatches; zero rejected with a stated reason |
| 9. Unpause | `glc-admin unpause` | rehearsed; no-op flip rejected |
| 10. Raise the ceiling in steps | `submit-tvl-raise` / `execute-tvl-raise` | governance lifecycle rehearsed on a real validator |
| Rollback | `pause`, `lower-tvl-cap` | both rehearsed |

Every command named in `runbooks.md` and every environment variable named in
`federation-deployment.md` is asserted to exist by tests that run in CI
(`runbook_commands.rs`, `deployment_config.rs`).

**No further launch blocker was found.**

### 1.1 Two papercuts found during this pass

Neither prevents executing the launch process; both are recorded rather than
silently fixed or ignored.

- **`glc-admin --help` exits 2** instead of 0. The help text prints
  correctly. A CI job that runs `glc-admin --help` as a smoke test would see
  a failure.
- **`runbooks.md` §13's snapshot command needs the `sqlite3` CLI**, which the
  bridge does not ship. Now stated in the runbook as a host prerequisite.

---

## 2. Completed implementation

Twenty-seven ADRs, 61 commits on `main`, **688 relayer tests** across 27 test
binaries and **195 program tests**, plus six hand-applied mutation suites
(`docs/experiments/`) whose every mutant is killed.

| area | delivered |
|---|---|
| Deposit → mint | outpoint identity, replay-proof claim PDAs, M-of-N ed25519 proof verified on chain |
| Burn → payout | persistent withdrawal records, deterministic coin selection, P2SH M-of-N vault, distributed partial signing |
| Completion | terminal on-chain record under a federation proof; a relayer with an empty database can tell paid from unpaid |
| Federation transport | mTLS against a pinned CA, dual identity binding, rate limiting, timeout and failover |
| Multi-relayer | builder-authoritative reservation, designated quorums, pre-broadcast on-chain check |
| Governance | threshold + timelock rotation, cancel, TVL-cap raise; asymmetric cap lowering |
| Exposure bound | on-chain wrapped-supply ceiling enforced before minting |
| Monitoring | `/health`, `/metrics`, five invariants, solvency separated from fee drift |
| Operator tooling | `glc-admin` (27 commands), `glc-audit`, staged-approval governance and sweeps |
| Bootstrap | initialize, wrapped mint, config read-back, two-step admin handover |
| Audit trail | every signature **granted** as well as refused; offline integrity auditor |

### 2.1 What the rehearsals found

Rehearsal is not a formality here. Running the documented compromise response
against a real node found that **`sweep-execute` could not have worked at
all**: it compared previous-output txids in display order against a
transaction carrying internal order, so every genuine sweep would have been
refused. Twenty-two unit tests and twenty-three killed mutants had all agreed
with each other and with nothing else, because every fixture built both sides
from the same array.

That defect would have surfaced during a vault compromise, at the moment the
procedure was needed. It is the strongest available argument for ADR-0014
§8.7, and for treating a rehearsal finding as a production defect.

---

## 3. Owner decisions required

None of these can be closed by writing code.

| # | decision | consequence of leaving it open |
|---|---|---|
| custody #1 | **Federation composition** — who operates the N validators, and the values of M and N | there is no federation; nothing else can proceed |
| custody #5 | **Program upgrade-authority custody** (e.g. Squads multisig) and the immutability timeline | one key can replace the program and mint without limit. `glc-admin transfer-admin`/`accept-admin` execute the handover once the destination is chosen |
| custody #7 | **Emergency pause quorum** | pause and unpause are gated by a **single interim admin key**; losing it removes the circuit breaker entirely |
| custody #8 | **Proof-of-reserves / attestation cadence** | no procedure exists; the solvency invariant is computed per operator but never published |
| — | **Every security parameter** (below) | the bridge cannot be initialized without them, deliberately |

### 3.1 Parameters with no defaults, by design (owner decision U6)

`initialize` and the daemons refuse to run without these. There is no safe
default for any of them, and inventing one would be the wrong kind of
helpful:

- `GLC_CONFIRMATION_DEPTH`, `GLC_MAX_REORG_DEPTH` — Goldcoin is low-hashrate
  PoW and deposit double-spend is the dominant external risk;
- `GLC_MAX_DEPOSIT_ATOMIC`, `GLC_ROLLING_WINDOW_CAP_ATOMIC`,
  `GLC_ROLLING_WINDOW_SECONDS` — value caps;
- the initial **wrapped-supply ceiling** — the only bound on total exposure,
  and the only thing limiting loss from a launch-day defect;
- the **governance timelock** — the window in which a bad rotation can be
  cancelled;
- `GLC_VAULT_MIN_CONFIRMATIONS`, `GLC_WITHDRAWAL_CONFIRMATION_DEPTH`.

### 3.2 Already answered by implementation; sign-off outstanding

Recorded in `custody.md` on 2026-08-01. The work is done; writing the
decision into the register is the owner's act.

- **#2 vault construction** — P2SH M-of-N (ADR-0015).
- **#3 vault signing model** — script multisig with distributed partial
  signing; TSS rejected (ADR-0014 §8.1, ADR-0017).
- **#4 key rotation and vault migration** — implemented, documented and
  rehearsed (ADR-0021, ADR-0022, ADR-0024).

---

## 4. External security audit

ADR-0014 §14 requires independent review. **Not started.**

Scope that the risk register names explicitly, and that should be stated to
any auditor rather than left for them to find:

| item | why it needs external eyes |
|---|---|
| **Ed25519 precompile introspection** (ADR-0010) | the program parses the instructions sysvar to bind a preceding ed25519 instruction to the mint. ADR-0010 already states focused external review is required |
| **The Anchor program as a whole** | it is the final arbiter of mint legitimacy |
| **Relayer and signer** | independent re-derivation is the property everything rests on |
| **`webpki-roots` feature unification** | verified still present: three versions in the lock file, carried per-crate exceptions in `deny.toml`, and the Phase 5 caveat at `deny.toml:91` remains unresolved |
| **Canonical message discipline** | domain tags, byte pinning, and the golden vectors that freeze them |
| **The M-of-N trust assumption itself** | this is a **federated, not trustless** bridge and must be described that way in all user-facing material |

---

## 5. Rehearsal and deployment tasks

### 5.1 Automated, and passing

Run deliberately — **they self-skip when their binaries are absent, which is
how CI runs them, so a green CI run is not evidence they passed**:

```
export GOLDCOIND_BIN=... GOLDCOIN_CLI_BIN=... GLC_BRIDGE_SO=...
cd relayer && cargo test --test rehearsal_rotation --test rehearsal_compromise \
                        --test e2e_deposit_to_payout --test regtest_withdrawal
```

Covering: bootstrap and admin handover; key rotation with timelock
enforcement; pause/unpause; the vault sweep end to end; and deposit → mint →
burn → Goldcoin payout.

### 5.2 Not performed, and required

| task | why it cannot be automated away |
|---|---|
| **Restore drill** | procedure written (`runbooks.md` §13); no snapshot has ever been restored and audited. A backup nobody has restored is a file |
| **Rehearsal on the real deployment** | the suites prove the *mechanism*; running the runbooks with the actual operators, keys and hosts proves the *people and the configuration* |
| **Testnet soak** | no deployment has run for any length of time under real conditions |
| **Key ceremony** (ADR-0014 §8.3) | physical, and the point is that no test can perform it |

---

## 6. Production deployment and rollout

Operational work, none of it blocked on engineering.

**Prerequisites on each host:** the four binaries, a Goldcoin node **per
signer** (never shared with the relayer — ADR-0017 E2), a Solana RPC
endpoint, the `sqlite3` CLI for snapshots, and the federation CA material.

**Configuration:** `docs/federation-deployment.md` is the reference and is
verified against the binaries by CI. The two easiest mistakes are called out
there: pointing the signer at the relayer's Goldcoin node, and leaving
`GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` / `GLC_SIGNER_SWEEP_APPROVALS_PATH`
unset — both fail closed and silently, the second disabling key rotation and
the compromise response until the day they are needed.

**Rollout:**

1. Deploy the program; transfer upgrade authority per custody #5.
2. `glc-admin initialize` — **validator order is permanent**; it fixes each
   member's bitmask index for the life of the federation.
3. `glc-admin create-wrapped-mint`, then `glc-admin show-config` and read
   every value back.
4. `glc-admin pause` before any funds can move.
5. Bring operators up; confirm all five `/health` invariants on every host
   and that operators agree on wrapped supply, deposits and payouts.
6. Rehearse a rotation and a sweep on the real deployment, still paused.
7. `glc-admin lower-tvl-cap` to a canary ceiling.
8. `glc-admin unpause`. Watch one deposit and one withdrawal end to end.
9. Raise the ceiling in timelocked steps.

**Still to build operationally** (not code): log shipping off-host (§13.3),
the backup cron and its `glc-audit` check, and monitoring thresholds on
`glc_indexer_seconds_since_tick` and `glc_reorg_deepest_observed`, which are
deliberately exposed as gauges with no built-in alarm level.

### 6.1 Rollback is "stop", not "reverse"

There is no un-mint and no un-complete instruction, by design. `pause` halts
minting and payouts; `lower-tvl-cap` caps exposure even if the pause is
lifted. Anything already minted stays minted.

**The maximum loss from a launch-day defect is bounded by the supply ceiling
in force when it fires, and by nothing else.** Size the canary on that basis.

---

## 7. Launch readiness assessment

**The software is ready to be deployed. The bridge is not ready to launch.**

Those are different statements and the difference is not engineering work.

**Ready:** every documented procedure is executable with shipped tooling and
verified against real nodes. The invariants that matter are monitored, the
irreversible operations require M independent human approvals, and the
documentation cannot silently drift from the binaries because CI checks it.

**Not ready, in order of severity:**

1. **No federation exists** (custody #1). Nothing else matters until N
   operators with N hosts and N key ceremonies exist.
2. **No external audit has begun** (§14). This bridge moves user funds under
   an M-of-N trust assumption; shipping it unaudited would be indefensible
   regardless of internal test coverage.
3. **The upgrade authority is a single key** (custody #5) — it can replace
   the program and mint without limit. The largest single point of failure in
   the system, and larger than anything the code can fix.
4. **The pause quorum is a single key** (custody #7). Losing it removes the
   circuit breaker entirely.
5. **No parameter values are chosen** (U6). Confirmation depths, value caps,
   the supply ceiling and the timelock are all unset, and each is a live
   security judgement.
6. **Nothing has been rehearsed on a real deployment**, and no restore has
   ever been performed.

### 7.1 An honest note on internal verification

Six phases in a row (7i-0, 7i-1, 7i, 7j, 7l, 7m) each found a documented
capability that no shipped tool could perform — including, in the last case,
the bridge's own bootstrap. Every one was found by asking "does a binary do
this?" rather than "does the code look right?", and several were found only
by mutation testing or by running against a real node.

The tests that now guard against recurrence — `runbook_commands.rs`,
`deployment_config.rs`, the cross-workspace encoding pins, and the rehearsal
suites — exist because internal review repeatedly failed to catch this class
of gap. That is the strongest argument in this document for **not** treating
internal confidence as a substitute for the external audit in §4.
