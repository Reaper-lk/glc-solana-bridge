# Pre-launch checklist

Phase 7j. Implements ADR-0014 §13/§14's pre-launch requirements.

**This bridge is not launch-ready.** The list below separates what has been
*verified* — with a pointer to the thing that verifies it — from what is
*open*. An item is only ticked if something fails when it stops being true.

Read `docs/runbooks.md` for incident procedures and
`docs/federation-deployment.md` for configuration.

---

## Verified

Each of these is asserted by a test that runs in CI, or by a rehearsal that
runs against real nodes. "Verified" here means *mechanically checked*, not
*reviewed and believed*.

### Protocol and safety

| item | verified by |
|---|---|
| Deposit identity is the Goldcoin outpoint; replay is impossible | `programs/glc-bridge/tests/deposit_mint.rs` |
| A mint requires an M-of-N federation proof over a canonical message | ADR-0010; `deposit_mint.rs`, `local_validator_e2e.rs` |
| Wrapped supply cannot exceed the configured ceiling | `supply_cap.rs` (22 tests) |
| A withdrawal pays exactly the burned amount, once | `regtest_withdrawal.rs`, `e2e_deposit_to_payout.rs` |
| Two operators cannot double-pay one withdrawal | `dual_executor.rs` |
| Completion is terminal and requires a federation proof | `complete_withdrawal.rs`, `completion_attestation.rs` |
| Signers refuse anything they did not independently derive | `signer_local_view.rs`, `payout_signer_view.rs` |
| A stale view refuses everything rather than answering from memory | `federation_transport.rs`, `operator_tooling.rs` |
| Signature ordering in a P2SH scriptSig is consensus-correct | `multisig_golden.rs`, against a mined transaction |

### Transport and identity

| item | verified by |
|---|---|
| mTLS against a pinned federation CA; no public PKI trust | `federation_transport.rs` (16 tests, real certs, real servers) |
| A peer answering as a different validator is discarded | same |
| Per-peer rate limiting cannot be bypassed by an unidentified caller | `p2p::ratelimit`, `p2p::service` tests |

### Operations

| item | verified by |
|---|---|
| Every runbook command exists and every variable/metric it names is real | `runbook_commands.rs` |
| Every variable the binaries read is documented | `deployment_config.rs` |
| Every granted signature leaves an audit record (§13.3) | `signature_audit_log.rs`, and the payout/completion suites |
| The bridge can be bootstrapped and the admin key handed over | `rehearsal_rotation.rs`, `admin_governance_encoding.rs` |
| A halted indexer is an alarm, not a log line | `ops::indexer_status`, `ops::health` |
| Reorg depth is visible *before* the halt (§13.1 (5)) | `ops::indexer_status`, `ops::health` |
| Every stored commitment re-verifies offline (§13.4) | `offline_audit.rs`, `ops::audit` |
| The solvency invariant and fee drift are reported separately | `ops::solvency`, `ops_endpoint.rs` |
| The instruction encoding matches Anchor's, across the workspace split | `admin_governance_encoding.rs` + `solana::instruction` tests |

### Rehearsals (ADR-0014 §8.7)

| procedure | rehearsed by |
|---|---|
| **Key rotation** — stage, collect, submit, timelock, execute | `rehearsal_rotation.rs`, real `solana-test-validator` |
| **Emergency pause / unpause**, including no-op and non-admin rejection | same |
| **Vault compromise response** — plan, approve, collect, assemble, broadcast | `rehearsal_compromise.rs`, real `goldcoind` |

The compromise rehearsal found a real defect on its first run: the sweep
compared txids in opposite byte orders and would have refused every genuine
sweep. That is what ADR-0014 §8.7 asks a rehearsal for, and it is the reason
"reviewed carefully" is not on this list as a form of verification.

**Running them:**

```
export GOLDCOIND_BIN=/path/to/goldcoind GOLDCOIN_CLI_BIN=/path/to/goldcoin-cli
export GLC_BRIDGE_SO=/path/to/target/deploy/glc_bridge.so
cd relayer && cargo test --test rehearsal_rotation --test rehearsal_compromise
```

Both self-skip when their binaries are absent, which is how CI runs today —
**so a green CI run does not mean the rehearsals passed.** Run them
deliberately before launch and record the result.

---

## Open — must be closed before launch

These are not "nice to have". Each is either an unmade decision or an
unbuilt capability, and each is recorded in the document that would
otherwise imply it exists.

### Custody decisions (`docs/custody.md`)

| # | decision | consequence of leaving it open |
|---|---|---|
| 1 | Federation composition — who the validators are | there is no federation |
| 5 | Program upgrade-authority custody (e.g. Squads) and immutability timeline | one key can replace the program |
| 7 | **Emergency pause quorum** | pause and unpause are gated by a single interim admin key; losing it removes the circuit breaker entirely (ADR-0022 §6, runbook §9) |
| 8 | Proof-of-reserves / attestation cadence | no procedure exists |

### Unbuilt operational capability

| item | ADR | status |
|---|---|---|
| **Restore drill** | §13.4 | the procedure is written (runbook §13); **it has never been performed** |
| Audit logs **shipped off-host**, append-only | §13.3 | every signature decision, state transition and operator action is now emitted (ADR-0026); **shipping them off-host has no procedure written** and a log lost before shipping is gone |

### Unset security parameters

No defaults exist for any of these, deliberately (owner decision U6). Each is
a live security and economic decision, not an implementation gap:

- `GLC_CONFIRMATION_DEPTH`, `GLC_MAX_REORG_DEPTH` — Goldcoin is low-hashrate
  PoW, and deposit double-spend is the dominant risk in the threat model;
- `GLC_MAX_DEPOSIT_ATOMIC`, `GLC_ROLLING_WINDOW_CAP_ATOMIC` — value caps;
- the initial wrapped-supply ceiling;
- the governance timelock.

### External review

| item | ADR | status |
|---|---|---|
| Independent security audit of the program | §14 | not started |
| Independent review of the relayer and signer | §14 | not started |

---

## Launch-day sequence

Only meaningful once the section above is empty. Written now so the order is
argued about in advance rather than at the time.

1. **Freeze.** No code changes after the audited commit; record its hash.
2. **Key ceremony** (ADR-0014 §8.3) — validator keys and vault keys, on
   separate hosts, with the vault redeem script recorded and each signer
   proving it holds its key at its configured position (the `signer-server`
   E1 check does this at startup and refuses to run otherwise).
3. **Deploy the program**, then transfer the upgrade authority per custody
   #5. Stand the bridge up and verify what landed — `runbooks.md` §14:
   ```
   glc-admin initialize --validators ... --threshold M --timelock-secs N \
     --max-supply ATOMIC --min-deposit N --min-withdrawal N --note "launch"
   glc-admin create-wrapped-mint --mint-keypair PATH --note "launch"
   glc-admin show-config
   ```
   Check the validator set **and its order**: it fixes each member's bitmask
   index for the life of the federation.
4. **Start paused.** `glc-admin pause` before any funds can move.
5. **Bring up each operator** and confirm, on every host:
   - `/health` returns 200 with all five invariants present;
   - `glc_indexer_seconds_since_tick` is advancing;
   - the signer's Goldcoin RPC is **its own**, not the relayer's;
   - `GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` and
     `GLC_SIGNER_SWEEP_APPROVALS_PATH` are set — unset, they fail closed and
     nothing complains until an incident.
6. **Cross-check.** Every operator's `/metrics` must agree on wrapped supply,
   confirmed deposits and completed payouts. Disagreement between operators
   is itself an alarm (ADR-0014 §13.1).
7. **Rehearse on the real deployment**, still paused: a rotation and a sweep,
   using the runbooks, with the actual operators typing the actual commands.
   The automated rehearsals prove the mechanism; this proves the people and
   the configuration.
8. **Set the supply ceiling low** for the canary, using
   `glc-admin lower-tvl-cap` — a ceiling is the only cap that binds without
   trusting the relayer.
9. **Unpause.** Watch one deposit and one withdrawal through end to end
   before widening anything.
10. **Raise the ceiling in steps**, each via the threshold-and-timelock path
    (`submit-tvl-raise` / `execute-tvl-raise`), never by lowering the
    guardrail.

## Rollback

There is no un-mint and no un-complete instruction, deliberately. Rollback
therefore means **stop, do not reverse**:

- `glc-admin pause` halts minting and payouts immediately;
- `glc-admin lower-tvl-cap` caps exposure even if the pause is lifted;
- anything already minted stays minted, and anything already paid stays paid.

Plan the canary sizing on that basis: the maximum loss from a launch-day
defect is bounded by the supply ceiling in force when it fires, and by
nothing else.
