# GLC ↔ Solana bridge — v1.0 release readiness

**Read this first.** It is the entry point for a security auditor evaluating
the system and for an operator about to run a validator. Everything else in
`docs/` is reachable from here.

> **Status: the software is complete and verified; the bridge is not ready to
> launch.** No federation exists, no external audit has been performed, and
> the upgrade authority and emergency pause are each still a single key.
> §9 states this precisely. Nothing in this document should be read as
> clearance to deploy to mainnet.

---

## 1. What this is, in one paragraph

A **federated** bridge between Goldcoin (a low-hashrate Bitcoin-derived PoW
chain, v0.17) and Solana. Depositing GLC to a federation-controlled vault
mints wrapped GLC on Solana; burning wrapped GLC pays out native GLC from the
vault. Any **M of N** validators can authorise a mint or a payout. There is
no fraud proof, no light client and no trustless verification: users trust
that fewer than M validators collude. That is the central assumption and it
is stated everywhere user-facing.

## 2. Architecture

### 2.1 Two workspaces, deliberately isolated (ADR-0001)

| workspace | contents | constraint |
|---|---|---|
| root | `programs/glc-bridge` (Anchor 0.31.1, Agave 2.1.21, SBF) and `shared/` | no network dependencies |
| `relayer/` | off-chain daemons and operator tools | never depends on `anchor-lang` or the program crate |

The relayer hand-encodes every instruction rather than importing the program.
The cost — nothing mechanically links the two — is paid by a
**cross-workspace encoding contract**: the program's tests assert Anchor
*generates* a byte-for-byte spec, and the relayer's assert it *produces* the
same one (ADR-0022 §4). Auditors should read those two files as a pair.

### 2.2 Processes

| process | holds | listens | talks to |
|---|---|---|---|
| `signer-server` | **one** validator ed25519 key and **one** vault secp256k1 key — the only keys in a deployment | mTLS gRPC | its **own** Goldcoin node and Solana RPC |
| `glc-relayer` | no validator key, no vault key; only a Solana fee payer | `/health`, `/metrics` | Goldcoin, Solana, and every peer's signer |
| `glc-admin` | nothing | — | Solana, Goldcoin, peers |
| `glc-audit` | nothing | — | a database file, read-only |

**A fully compromised relayer cannot mint or move vault funds.** It can waste
fees and stall progress — liveness only. Authority lives exclusively in the
signer processes, and only signatures cross the network.

### 2.3 Deposit flow

Goldcoin transaction pays the vault → each operator's indexer observes it
independently → confirmation depth → each validator **re-derives** the
canonical claim message from its own node and signs → M signatures are
aggregated into an ed25519 precompile instruction → `mint_wrapped` verifies
threshold, replay guard, and supply ceiling on chain.

### 2.4 Withdrawal flow

`burn_wrapped` creates a persistent `WithdrawalRequest` → the designated
builder selects vault UTXOs and constructs a P2SH payout → designated signers
each verify against their **own** node and return one partial signature →
the builder assembles the scriptSig in consensus-required order and
broadcasts → at depth, M validators attest and `complete_withdrawal` records
it on chain, terminally.

---

## 3. Completed ADRs

Twenty-seven, in `docs/adr/`. The ones an auditor should read, and why:

| ADR | why it matters |
|---|---|
| **0010** federation proof verification | ed25519 precompile introspection — historically the most bug-prone surface in this design, and named as required audit scope |
| **0003** claim-PDA replay prevention | the only thing preventing a deposit minting twice |
| **0015** vault custody | P2SH M-of-N; supersedes the single-key regtest vault |
| **0017** distributed payout signing | no process holds enough key material to spend the vault |
| **0016** federation signature exchange | why a responder re-derives instead of trusting |
| **0012 / 0013** signing, aggregation, executor | the reload-and-recompute safeguards and the four-layer double-payment defence |
| **0019** multi-relayer operation | builder-authoritative reservation and the pre-broadcast on-chain check |
| **0014** production hardening | the umbrella: governance, custody, monitoring, launch |
| **0021 / 0022** operator tooling | authorisation by *staged operator approval*, for the two things no chain fact can justify |
| **0024** rehearsal as automation | and the real defect the first rehearsal found |
| **0020 / 0025 / 0026** solvency, offline audit, grant records | what is monitored, re-verified, and recorded |

Full index: `ls docs/adr/`.

---

## 4. Implemented security properties

Each is enforced in code and covered by tests; the parenthetical says where.

**A validator never signs what it has not itself derived.** The request
carries the bytes it wants signed, but they are only ever *compared*: the
responder rebuilds them from its own chain observations and refuses on any
mismatch. A compromised requester cannot induce a signature over anything the
validator has not verified. (`p2p::policy`, ADR-0016.)

**A validator cannot be made to equivocate.** Having signed one message for
an identity, it refuses a different one for the same identity — on mints,
payouts, governance and sweeps alike.

**A deposit mints at most once, ever.** One PDA per `(txid, vout)`; its
existence is the guard. (ADR-0002, ADR-0003.)

**A withdrawal is paid at most once.** Four layers: one payout row per
withdrawal, one payout per outpoint, a pre-signing guard sequence, and the
Goldcoin UTXO set itself — only the last is a true security boundary.
(ADR-0013.)

**A payout pays exactly the burned amount.** The vault absorbs the fee, so a
user never receives less than they burned. (Owner decision D3.)

**Total exposure is bounded on chain.** `mint_wrapped` checks the
wrapped-supply ceiling *before* minting. Lowering it is immediate and
admin-only; raising it needs threshold plus timelock — the asymmetry is
deliberate. (ADR-0014 §11.1.)

**No single key can move the federation.** Rotation requires an M-of-N proof
over a canonical governance message plus a timelock; execution is
permissionless once matured. `update_validator_set` is deleted. (ADR-0014
§7.)

**Governance and vault sweeps require explicit human intent.** Neither has an
on-chain fact to derive from, so each signer signs only what its own operator
staged out of band. M signatures mean M humans each decided. (ADR-0021 §4.)

**Signing keys are structurally isolated.** One validator identity per
process; the plural key loader is deleted, so a process holding several
federation identities is impossible rather than discouraged.

**The bridge fails closed.** A stale epoch view, an unreachable node, an
over-deep reorg, an integrity anomaly, a missing approvals file — every one
refuses rather than proceeds.

**Every signature is recorded, granted as well as refused.** (ADR-0026.)

**Stored commitments are re-verifiable offline.** `glc-audit` re-runs the
signing guards' recompute-and-compare across every row, read-only, so a
backup can be checked before it is trusted. (ADR-0025.)

---

## 5. Known assumptions and limitations

State these to any auditor; do not let them be discovered.

1. **M-of-N collusion is unmitigated and irreducible.** M validators can mint
   without a deposit and drain the vault. Bounded only by the supply ceiling
   and by who the operators are. This is a federated bridge.
2. **The upgrade authority can replace the program**, and therefore mint
   without limit. Custody #5 is **open**; until it is a multisig with an
   immutability timeline, it is the largest single point of failure.
3. **The emergency pause is one key.** Custody #7 is **open**. Losing it
   removes the circuit breaker entirely.
4. **Goldcoin is low-hashrate PoW.** Deep reorg is the dominant external
   risk. Mitigated by confirmation depth, value caps, and an indexer that
   halts rather than guessing a fork point — never eliminated.
5. **A minted deposit is not rolled back by a reorg.** If a reorg deeper than
   the confirmation depth removes the funding transaction, wrapped tokens
   exist without backing and the solvency invariant genuinely breaks.
6. **Nothing is reversible.** There is no un-mint and no un-complete
   instruction, by design.
7. **The vault absorbs Goldcoin fees**, so its balance sits below the
   backing bound by the cumulative fee. Tracked as an operational quantity,
   not a solvency failure. Operators replenish from an external reserve.
   (ADR-0020.)
8. **Threshold is bounded by transaction capacity** — roughly 4 signatures
   legacy, ~7 with a lookup table. Exceeding it stalls mints; it never mints
   wrongly.
9. **The audit trail is logs**, not rows. A log lost before it is shipped is
   gone; shipping is the operator's responsibility. (ADR-0026 §3.1.)
10. **`webpki-roots` feature unification remains unresolved** (`deny.toml:91`)
    — carried as a per-crate exception and named as audit scope.

---

## 6. Operational requirements

**Per operator:** a host running `glc-relayer` and `signer-server`, a
**dedicated Goldcoin full node for the signer** (never shared with the
relayer — ADR-0017 E2; sharing it silently defeats the independent validation
that makes a refusal meaningful), a Solana RPC endpoint, the federation CA
material, and the `sqlite3` CLI for snapshots.

**Configuration** is `docs/federation-deployment.md`, which CI verifies
against the binaries. Two mistakes are easy and silent:

- pointing the signer at the relayer's Goldcoin node;
- leaving `GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` or
  `GLC_SIGNER_SWEEP_APPROVALS_PATH` unset — both fail closed, disabling key
  rotation and the compromise response until the day they are needed.

**No security parameter has a default** (owner decision U6). Confirmation
depths, value caps, the supply ceiling and the governance timelock must all
be chosen; the program refuses a zero timelock and a zero cap outright.

---

## 7. Launch checklist

Full form with evidence: `docs/launch-checklist.md`. Procedures:
`docs/runbooks.md` §14. Summary:

1. Freeze the audited commit; record its hash.
2. Key ceremony (ADR-0014 §8.3) — validator and vault keys, separate hosts.
3. Deploy; transfer upgrade authority per custody #5.
4. `glc-admin initialize` — **validator order is permanent**, it fixes each
   member's bitmask index for the life of the federation.
5. `glc-admin create-wrapped-mint`, then `glc-admin show-config` and read
   every value back.
6. `glc-admin pause` before any funds can move.
7. Bring operators up; confirm all five `/health` invariants on every host,
   and that operators **agree** on wrapped supply, deposits and payouts —
   disagreement between operators is itself an alarm.
8. Rehearse a rotation and a sweep on the real deployment, still paused.
9. `glc-admin lower-tvl-cap` to a canary ceiling.
10. `glc-admin unpause`; watch one deposit and one withdrawal end to end.
11. Raise the ceiling in timelocked steps.

---

## 8. Rollback, incident response, and monitoring

### 8.1 Rollback is "stop", not "reverse"

There is no un-mint and no un-complete. Rollback means:

- `glc-admin pause` — halts minting and payouts immediately;
- `glc-admin lower-tvl-cap` — caps exposure even if the pause is lifted;
- anything already minted stays minted; anything already paid stays paid.

**Maximum loss from a launch-day defect is bounded by the supply ceiling in
force when it fires, and by nothing else.** Size the canary accordingly.

### 8.2 Incident response

Fourteen procedures in `docs/runbooks.md`, each stating how to *detect*, what
to *do*, and how to *verify*. Every command is checked against the binaries
by CI. The ones to know before an incident:

| condition | runbook |
|---|---|
| Integrity halt | §1 — two permitted destinations; establish the cause before clearing |
| Deep reorg | §2 — automatic below `max_reorg_depth`; a halt above it needs a human |
| Solvency breach | §3 — pause, lower the cap, then find the cause |
| Vault compromise | §5 — pause, rotate, sweep. **M compromised vault keys are unrecoverable** |
| Key rotation | §7 — stage, collect, submit, wait out the timelock, execute |
| Emergency pause | §9 — single interim key; custody #7 open |
| Backup and restore | §13 — snapshot, then `glc-audit` every snapshot |

**Approval cannot be delegated.** In §5 and §7 the coordinator is *asking
each operator to run a command on their own host*, not running it for them.
That is the property M-of-N exists to provide.

### 8.3 Post-launch monitoring

`/health` returns **503** when any invariant is breached; `/metrics` is
**always 200**, because a scrape that fails when the bridge is unhealthy
destroys the data needed to diagnose it. Neither endpoint is authenticated —
bind them to a private interface.

**Five invariants — page on any of them:**

| invariant | breached when |
|---|---|
| `solvency` | `wrapped_supply > confirmed_deposits − completed_payouts`. Measured to hold with **exactly zero slack**, so any breach is real |
| `vault_reconciliation` | vault drift exceeds the fees we know we paid |
| `no_integrity_halts` | any deposit or withdrawal is `IntegrityHalted` |
| `validator_epoch_fresh` | this process has stopped observing the validator epoch |
| `indexer_not_halted` | the indexer stopped on an over-deep reorg |

**Gauges with no built-in threshold** — the bridge has no basis for choosing
one, so alert on them yourself:

- `glc_indexer_seconds_since_tick` — a quiet chain also produces no blocks;
- `glc_reorg_deepest_observed` against `glc_reorg_max_depth_configured` —
  the early warning before a halt;
- `glc_vault_fee_drift_atomic` — expected to grow; replenish from reserve.

**Cross-operator disagreement is itself an alarm** (ADR-0014 §13.1). Compare
`glc_wrapped_supply_atomic`, `glc_confirmed_deposits_atomic` and
`glc_completed_payouts_atomic` across every operator.

**Also required, and not yet built:** shipping logs off-host (§13.3), the
backup cron and its `glc-audit` check, and a rehearsed restore.

---

## 9. Readiness assessment

**Complete:** every documented procedure is executable with shipped tooling
and verified against a real `goldcoind` and a real `solana-test-validator`.
883 tests across both workspaces, six mutation suites with every mutant
killed, and CI checks that the runbooks, the deployment guide and the
instruction encodings cannot silently drift from the binaries.

**Blocking mainnet launch**, in severity order:

1. **No federation exists** — custody #1. Nothing else matters first.
2. **No external security audit has been performed** — ADR-0014 §14.
3. **Upgrade authority is a single key** — custody #5; it can replace the
   program and mint without limit.
4. **Pause authority is a single key** — custody #7.
5. **No security parameter has a chosen value** — owner decision U6.
6. **Nothing has been rehearsed on a real deployment**; no restore has ever
   been performed.

### 9.1 A note on the limits of internal verification

Six consecutive development phases each discovered a documented capability
that **no shipped tool could perform** — ending with the bridge's own
bootstrap, which could not be run at all. Every one was found by executing a
binary or by killing a mutant, never by reading code, and several were in
code reviewed in the same sitting by its author.

The consistency tests that now exist — runbook commands, deployment
variables, cross-workspace encodings, rehearsal suites — exist *because*
internal review repeatedly failed to catch that class of gap.

Auditors should weight this accordingly: it is direct evidence about how this
system's defects present themselves. They do not look like bad code. They
look like correct code that nothing calls, or a check whose fixtures agree
with each other and with nothing else. **The external audit in §9 item 2 is
load-bearing, not a formality.**

---

## 10. Where to go next

| you are | read |
|---|---|
| a security auditor | `threat-model.md`, then ADR-0010, ADR-0016, ADR-0017, then `remaining-before-launch.md` §4 |
| a new operator | `federation-deployment.md`, then `runbooks.md` |
| launching | `launch-checklist.md`, then `runbooks.md` §14 |
| deciding custody | `custody.md` |
| assessing readiness | `remaining-before-launch.md` |
