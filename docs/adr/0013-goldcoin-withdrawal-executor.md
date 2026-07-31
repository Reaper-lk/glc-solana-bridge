# ADR-0013: Goldcoin withdrawal executor

- Status: Accepted (owner decisions D1–D10, 2026-07-30)
- Phase: 6

## Context

Phase 3 made `burn_wrapped` create a persistent `WithdrawalRequest` PDA
(ADR-0006) but deliberately stopped there: no payout, no status write-back.
Phase 6 builds the off-chain executor that turns those records into native
Goldcoin payments — regtest only, with no production custody.

Five facts were established empirically against a real Goldcoin v0.15.0
binary before any code was written; none were assumed from Bitcoin
documentation, and each changed the design:

| Fact | Consequence |
|---|---|
| **No on-chain status write-back exists.** `status` is set to `Pending` in `burn.rs` and never updated; no instruction can change it. | Completion is tracked off-chain only (D1). |
| **`scantxoutset` is absent**; `listunspent` is present. | Vault discovery is wallet-based (D6). |
| **`lockunspent` locks are in-memory and lost on node restart.** | Reservations must be persisted in SQLite; node locks are at best a second layer. |
| **Fee estimation is unusable on regtest** — `estimatefee`/`estimatesmartfee` both return `-1`. | The fee rate is explicitly configured, no default (D4). |
| **Broadcast semantics**: re-sending a mempool duplicate succeeds with the same txid; re-sending a mined transaction fails with `-27`; spending a spent outpoint fails with `-25`. | `-27` is normalised to success, `-25` to a conflict that is never retried. |

## Decision

**D1 — completion stays off-chain.** No admin-only completion instruction is
added. `WithdrawalRequest.status` remains `Pending` on-chain forever; the
relayer's database is the completion record. The state machine is a
data-driven transition table (`WithdrawalState::may_transition_to`) so a
future *threshold-authorized* on-chain completion instruction can append
states after `Completed` without restructuring the executor.

**D2 — single-key P2PKH regtest vault.** The vault key is held by the
Goldcoin node wallet; the relayer never reads, holds, or logs private keys
(`dumpprivkey` is never called). This is the withdrawal-side analogue of
Phase 5's R2 bootstrap topology and carries the same warning: **test-only,
not production custody.** custody.md #2/#3 remain OPEN.

**D3 — the vault absorbs the fee.** The payout output is *exactly* the
burned amount; the fee is funded from the vault's own inputs and reduces
change. Coin selection therefore targets `amount + fee`. The invariant
`payout_atomic == amount_atomic` is enforced in the pre-signing guards, not
merely assumed.

**D4/D5/D7 — no silent defaults.** Fee rate, withdrawal confirmation depth,
and discovery commitment must be configured explicitly. Commitment must be
exactly `finalized`: a payout must never be built from a burn that could
still be rolled back.

**D6 — `listunspent` for vault discovery.** Block-scan reconstruction is
later hardening.

**D8 — a single executor is assumed.** Two executors against one vault would
each build independent payouts; only L1 UTXO contention would prevent double
payment, and the loser would halt. Multi-executor coordination is undesigned.

**D10 — reservation timeout is configuration only.**

### Never-double-pay: four layers

1. `withdrawal_payouts` is keyed by `withdrawal_index` — at most one payout
   row per withdrawal, enforced by the schema.
2. `withdrawal_payout_inputs` carries `UNIQUE (txid, vout)` — an outpoint is
   committed to at most one payout, ever.
3. The pre-signing guard sequence (below).
4. The Goldcoin UTXO set itself — a spent input cannot be re-spent (`-25`),
   and an identical re-broadcast is a no-op (`-27`).

Only (4) is a true security boundary. (1)–(3) exist so the executor never
*attempts* something (4) would have to catch.

### The pre-signing guard sequence (owner requirement)

Inside one SQLite transaction, immediately before signing and never against
cached state, `Db::verify_and_load_signable_payout`:

1. reloads the live withdrawal row;
2. reloads the live payout row and its committed inputs;
3. refuses if a payout is already **completed**;
4. refuses if a payout transaction is already **confirmed**;
5. refuses if the payout is already **signed** (signed bytes and txid are
   durable and inseparable);
6. verifies every committed input **still exists** in `vault_utxos` at the
   committed amount;
7. verifies each input is still `Reserved` **by this withdrawal** — not
   released, not reassigned;
8. recomputes the canonical payout intent from the reloaded fields and
   requires (a) the stored commitment to be self-consistent
   (`sha256(stored intent) == stored hash`) and (b) the recomputed intent to
   be byte-identical to the stored one;
9. enforces `payout_atomic == amount_atomic` (D3).

Any failure transitions to `IntegrityHalted` with the expected and
recomputed commitments plus the differing field name(s) recorded, and
returns no signable material. **Every one of these guards is proven
load-bearing by mutation testing**: removing any single check causes a
specific named test to fail.

The commitment stores both the intent **preimage and its hash** — mirroring
`claim_artifacts`' `canonical_message`/`message_hash` on the deposit side.
Keeping only the hash makes field-level attribution impossible, which an
earlier iteration of this design got wrong and the tests caught.

### Output verification before signing

The node builds the transaction, but the relayer never trusts the result: it
decodes the unsigned transaction and proves exact destination script and
amount, exact change script (vault-owned) and amount, exact input set in
committed order, no extra outputs of any kind, and `Σ inputs = payout + change
+ fee` exactly. After signing it re-decodes and requires the outputs and
outpoints to be unchanged, so a wallet cannot quietly add or alter an output.

### Reconciliation

Every tick, before any action: look the payout's txid up on chain. Absent →
`Orphaned` and rebroadcast identical bytes. Present but in an orphaned block
(`confirmations == -1`) → `Orphaned`. Present at depth → `Completed`. A
dropped transaction self-heals within one tick; the payout is never rebuilt
and never re-signed.

## Consequences

- **Recovery of completion state depends on the relayer database.** Because
  on-chain status never advances (D1), a fresh relayer with no database
  could not distinguish paid from unpaid withdrawals from chain state alone.
  This weakens ADR-0006's stated "reconstruct the queue from chain state"
  property for the payout half, and is the most significant open issue.
- **The node wallet can spend vault outputs out from under the executor.**
  Verified empirically while building the regtest fixture: because the vault
  address belongs to the node's own wallet (D2), an unrelated
  `sendtoaddress` consumed a vault UTXO as an input and consolidated the
  vault's funds. Database reservations do not and cannot prevent this — the
  node does not know they exist. The `lockunspent` best-effort layer helps
  only until the node restarts. **Operational rule for Phase 6: the vault
  wallet must not be used for anything else.** A dedicated wallet, or real
  multisig custody, resolves it properly (custody.md #2/#3).
- `IntegrityHalted` is terminal; the only exit is
  `Db::operator_clear_withdrawal_halt`, reachable from no automatic path,
  requiring a non-empty operator note, restricted to `Validated`/`Failed`,
  and never able to place a withdrawal into a state implying payment. The
  audit trail is append-only.
- A withdrawal below the dust threshold is `Failed` permanently — it can
  never be paid.
- Change below dust is folded into the fee rather than created as an
  unspendable output.
- Phase 6 deliberately does not implement the Solana-side discovery loop
  wiring or the full deposit→mint→burn→payout end-to-end harness; see the
  phase report for exactly what is and is not covered.
