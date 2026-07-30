# ADR-0011: Goldcoin indexer — persistence, state machine, and reorg handling

- Status: Accepted (owner decision, 2026-07-29)
- Phase: 4

## Context

Phase 4 builds the first piece of the off-chain relayer that touches real
chain data: a persistent indexer that watches Goldcoin regtest, detects
confirmed vault deposits, and produces unsigned canonical claim artifacts
(the exact Phase 3 message format) — without signing, aggregating
signatures, or submitting anything to Solana (all Phase 5+). Every RPC fact
this design depends on was verified empirically against a real Goldcoin
Core v0.15.0 binary before being relied upon (`docs/goldcoin-rpc-notes.md`),
per the explicit instruction not to assume modern Bitcoin Core behavior.

Several verified facts shaped the design directly:

- `getblock` has no numeric verbosity — only bare txid strings are
  returned, forcing a two-call-per-transaction ingestion pattern
  (`getblock` then `getrawtransaction` per txid).
- `getrawtransaction` is unreliable without `-txindex=1` (the node's own
  help text calls the fallback "deprecated"), making `-txindex=1` a
  mandatory node requirement.
- The genesis block's coinbase cannot be fetched via `getrawtransaction`
  even with `-txindex=1` — height 0 must be skipped entirely.
- The RPC-displayed txid is the byte-reversed hex of the raw double-SHA256
  digest (Bitcoin's convention, confirmed by direct computation).
- `getblock(hash)["confirmations"] == -1` is the reliable orphaned-block
  signal; `getblockhash(height)` is the reorg walk-back primitive.

## Decision

**Persistence (owner decision U1):** SQLite via `rusqlite` (bundled
feature) — real transactions, a single file, trivial schema-version
migrations. Schema (full DDL in `relayer/src/glc/db.rs`):
`schema_version`, `indexed_blocks`, `chain_state` (single-row tip cache),
`deposit_candidates`, `deposit_state_log`, `reorg_events`,
`claim_artifacts`. Indexes on deposit state, block height, `txid_hex`,
`block_hash`, and `deposit_state_log.deposit_id` (owner requirement 1).

**txid storage (owner decision U2):** both `txid BLOB` (32 canonical bytes,
used for protocol/PDA/message construction) and `txid_hex TEXT` (lowercase
64-char, used for RPC calls, logs, and ops) are stored, with a schema-level
`CHECK (txid_hex = lower(hex(txid)))` constraint proving the two
representations can never silently disagree — not just an application-level
convention. The canonical byte convention is the RPC-displayed hex decoded
directly, with no further reversal.

**Raw transaction persistence (owner requirement 2):** `raw_tx_hex` is
stored on every `deposit_candidates` row for audit and deterministic
reprocessing.

**Claim artifacts (owner requirement 3):** a `claim_artifacts` table
(`UNIQUE(deposit_id)`) holds the exact 166-byte canonical message
(`glc_bridge_shared::claim::deposit_claim_message`), its SHA-256
fingerprint, and the Solana-side values it was built from. Created
atomically with the `ReadyForSignature` transition — never separately, and
never signed or submitted by any Phase 4 code path.

**State machine:** the seven states `Candidate`, `Confirming`,
`ReadyForSignature`, `Orphaned`, `Submitted`, `Minted`, `Failed`.
`Candidate → Confirming` is unconditional and same-tick (a persisted state
only so a crash between discovery and depth-evaluation loses nothing).
`Confirming → ReadyForSignature` requires: depth ≥ `confirmation_depth`,
value caps clear, and a defensive `gettxout(..., include_mempool=false)`
re-check confirming the output is still unspent — if it's been spent by
anything other than a reorg, the row demotes to `Failed`
(`vault_output_spent`) instead, protecting the wrapped-supply invariant.
`Submitted`/`Minted` exist in the schema now but are never written by
Phase 4 (no Solana RPC exists yet, see below) — reserved so Phase 5 needs
no migration. History is never deleted (owner decision U7): rollback moves
rows to `Orphaned`, ingestion failures land directly in `Failed` with a
specific `failure_reason`, both logged to `deposit_state_log` with
`block_hash` and `reason` (owner requirement 4).

**Minimum deposit (owner decision U3):** a configured `min_deposit_atomic`
filters at ingestion — a vault-paying output below it is recorded as an
auditable `Failed` row (`below_min_deposit`), never silently dropped. The
on-chain program's own `min_deposit` check (Phase 3) remains the final
enforcement regardless of this local filter's value.

**Solana-side values (owner decision U4):** `protocol_version`,
`program_id`, `validator_epoch`, `wrapped_mint` are explicit, strictly
validated operator configuration in Phase 4. No Solana RPC client exists in
this workspace yet. A stale value fails safely — Phase 3's on-chain
verification rejects a wrong-epoch or wrong-program-id proof — at the cost
of a liveness inconvenience (operator must update config after a rotation),
never a security hole.

**Vault matching (owner decision U5):** exactly one configured P2PKH
`scriptPubKey`, matched byte-for-byte (never address-string comparison).
Validated strictly at startup against the real 25-byte P2PKH pattern. P2SH
and multisig vaults are not implemented — custody.md #2/#3 remain open.

**Confirmation depth / reorg depth (owner decision U6):** no built-in
production defaults. `confirmation_depth` must be `> 0`;
`max_reorg_depth` must be `>= confirmation_depth`; both validated at
startup with no fallback value. Tests use small explicit values. Production
values remain an open security/ops decision — Goldcoin's deep-reorg risk is
explicitly not resolved by this ADR.

**Reorg algorithm:** walk backward from the locally stored tip comparing
stored vs. live `getblockhash(height)` until a match (the fork point) is
found or `max_reorg_depth` is exceeded. Exceeding it **halts** the indexer
entirely (`TickOutcome::Halted`) — no further ticks touch the database or
network until the process is restarted with different configuration or
manual intervention; the indexer never guesses a fork point. The identical
algorithm handles restart-resume (a clean restart is a walk-back that
matches immediately) and steady-state reorg detection — one code path, not
two. Rollback (`Db::rollback_reorg`) is one transaction: mark blocks above
the fork point gone, transition affected active-state rows to `Orphaned`,
update the tip, log a `reorg_events` row. A deposit whose transaction is
re-mined after a reorg gets a **fresh** row (`UNIQUE(txid, vout,
block_hash)` — never `(txid, vout)` alone) rather than resurrecting the
orphaned one.

**Retry policy:** two failure classes, matching what was empirically
observed. Transport failures (connection refused/reset/timeout — the real
node's own failure shape when stopped) retry with bounded exponential
backoff inside one RPC call, then bubble up as `NodeUnavailable`; the outer
tick loop sleeps and retries the whole tick indefinitely. JSON-RPC method
errors (a valid response carrying an `"error"` object) are never retried —
the current tick aborts with no partial write, the next tick tries fresh.

## Consequences

- Every chain-state-changing database operation is one SQL transaction
  (`ingest_block`, `rollback_reorg`, `transition_state`) — verified by
  tests that idempotently re-run the same operation and assert identical
  resulting state.
- The indexer's ingestion loop makes one `getblock` call plus one
  `getrawtransaction`/`getrawtransactionhex` pair per transaction per
  block — a real, verified cost shape (not the single-call-per-block a
  modern-Bitcoin-Core assumption would predict), relevant to future
  performance tuning.
- Reconciliation against Solana claim-PDA existence (the `Minted`
  transition from any active state) is designed into the schema but not
  implemented in Phase 4 — it structurally requires a Solana RPC client,
  which owner decision U4 explicitly defers to Phase 5.
- No keys, RPC passwords, node data, databases, logs, or RPC captures are
  committed (owner requirement 7): regtest integration tests
  (`relayer/tests/regtest_indexer.rs`) use per-process throwaway
  credentials and `tempfile`-backed directories, torn down after every
  test; they are skipped (not failed) when `GOLDCOIND_BIN` is unset.
