# Goldcoin Core RPC notes

Verified facts about the Goldcoin node interface, established Phase 4 by
building and running a real Goldcoin Core binary against `-regtest`,
broadcasting real transactions, mining real blocks, and simulating real
reorgs (`invalidateblock`/`reconsiderblock`). **No fact below was assumed
from Bitcoin documentation** — Goldcoin is a divergent fork, and several
facts below explicitly contradict what a modern Bitcoin Core assumption
would predict.

Binary used: `goldcoin/goldcoin` release `v0.15.0`,
`goldcoin-0.15.0-x86_64-linux-gnu.tar.gz` (prebuilt, from the project's
GitHub releases).

## Verified facts

### Version and lineage

- `goldcoind --version`: **Goldcoin Core Daemon version v0.15.0.0-04a946fd8**.
- `getnetworkinfo`: `protocolversion: 70015`, `subversion:
  "/GoldcoinCore:0.15.0/"`.
- Copyright banner lists **Bitcoin Core → Litecoin Core → Goldcoin Core**,
  in that order — Goldcoin descends through **Litecoin**, not directly from
  Bitcoin. This is a genuine lineage correction versus the "~Bitcoin 0.14
  era" assumption this file previously carried.

### Regtest mode

- **Works via `-regtest`**, but is **completely undocumented**: zero
  mentions of "regtest" anywhere in `goldcoind --help` output. Confirmed
  functional regardless — `getblockchaininfo` correctly reports
  `"chain": "regtest"`.

### Ports

- Documented defaults (`--help`): mainnet P2P **8121** / RPC **8122**;
  testnet P2P **18121** / RPC **18122**.
- **Empirically observed regtest**: P2P **18130**, RPC **18122** (regtest
  shares testnet's documented RPC port; P2P uses a distinct base not stated
  anywhere in `--help`).
- The blueprint's assumed `18332` (Bitcoin *testnet's* port) is **confirmed
  wrong** for Goldcoin.
- One `--help` usage example shows RPC port `9332` — verified to be stale
  boilerplate text, contradicted by both the documented default and live
  observation. Do not trust example text in this codebase's `--help` output.

### RPC method availability and shapes

All required methods are present: `getblockchaininfo`, `getblockcount`,
`getblockhash`, `getblock`, `getrawtransaction`, `decoderawtransaction`,
`gettxout`, `generatetoaddress`. Also present and used for reorg testing:
`getchaintips`, `invalidateblock`, `reconsiderblock`. Also present:
`createmultisig`.

- **`getblock(hash, verbose)` accepts only a BOOLEAN `verbose`** — there is
  **no numeric verbosity level 0/1/2** as in modern Bitcoin Core (added in
  Bitcoin Core 0.16; this Goldcoin lineage predates it). `verbose=true`
  returns header fields plus `"tx"` as an **array of bare txid strings
  only** — never embedded decoded transaction objects. **Consequence for
  the indexer**: full transaction data requires a separate
  `getrawtransaction(txid, true)` call per txid; there is no single-call
  full-block decode.
- **`getrawtransaction(txid, verbose)` without `-txindex`**: the RPC's own
  help text states *"By default this function only works for mempool
  transactions. If -txindex is enabled, it also works for blockchain
  transactions. **DEPRECATED**: for now, it also works for transactions
  with unspent outputs."* Confirmed empirically. **No blockhash-hint 3rd
  parameter exists** (unlike modern Bitcoin Core) — passing one raises an
  RPC usage error. **Consequence: `-txindex=1` is a mandatory node
  configuration** for reliable historical transaction lookup; the indexer
  requires it and refuses to rely on the deprecated unspent-output
  fallback.
- **The genesis block's coinbase transaction is unretrievable via
  `getrawtransaction` even with `-txindex=1`** — a real, empirically
  confirmed Bitcoin-lineage quirk (the genesis coinbase is permanently
  unspendable and excluded from indexing). Every other block's coinbase
  (height ≥ 1) resolves normally with `-txindex=1`. **Consequence: the
  indexer must skip height 0 entirely** rather than attempt (and fail) to
  fetch its transactions — genesis never carries a real deposit anyway.

### Decimal precision

- **Exactly 8 decimals**, confirmed by direct boundary testing: a
  9th-decimal-digit amount (`12.345678911`) and a half-atomic-unit amount
  (`0.000000005`) are both rejected by the node with `error code -3:
  Invalid amount`. Matches the `WRAPPED_GLC_DECIMALS = 8` assumption
  exactly.

### txid byte order

- **The RPC-displayed txid string is the byte-reversed hex of the raw
  double-SHA256 digest of the transaction** — identical to Bitcoin's
  convention. Verified directly: `sha256(sha256(raw_tx_bytes))[::-1].hex()
  == rpc_txid` on a real broadcast-and-mined transaction (golden vector
  pinned in `relayer/src/glc/deposit.rs`'s
  `txid_byte_order_regression_against_real_captured_transaction` test).
- **Chosen convention (owner decision U2)**: the indexer stores the
  RPC-displayed hex, decoded directly into 32 bytes with **no further
  reversal**, as the canonical `txid` fed into
  `glc_bridge_shared::claim::deposit_claim_message` and the on-chain claim
  PDA seed. The on-chain program treats `txid` as fully opaque (never
  reorders it), so this choice is safe as long as it is applied with
  100% consistency — which the byte-order regression test guards.

### vout representation

- Plain zero-based index into the `vout` array. **Output ordering is not
  fixed**: the same logical payment (vault + change) landed at different
  `vout` indices across different constructed transactions, depending on
  the wallet's chosen change position. `(txid, vout)` must never be
  assumed positional — confirmed, not just theorized.

### Address formats

- P2PKH regtest addresses use a **Bitcoin-testnet-style version byte**
  (`m`/`n` prefix, e.g. `mimgHRXobzhMFWkXH46awwtiAQLhKRxxbt`), standard
  `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG` script
  (25 bytes: `76a914<20-byte-hash>88ac`).
- **`createmultisig` (P2SH) produces a Goldcoin-specific version byte**,
  yielding **`Q`-prefixed** addresses — neither Bitcoin mainnet's `3` nor
  testnet's `2`. A genuine, non-obvious divergence, directly relevant to
  custody.md #2 (vault construction) once a multisig vault is designed.

### OP_RETURN / recipient binding

- **Confirmed viable as the recipient-binding mechanism**: a 32-byte
  payload (exact size for a Solana pubkey) was created, broadcast, mined,
  and fetched back byte-identical via `decoderawtransaction`.
- **Standardness/relay ceiling not precisely pinned**: this regtest node
  accepted OP_RETURN payloads up to at least 10,000 bytes via
  `sendrawtransaction` — a known Bitcoin-lineage regtest default of
  permissive/non-standard-transaction policy. The **true mainnet relay
  ceiling remains unverified**. Not a blocker for Phase 4: the fixed need
  (32 bytes) is comfortably within every known Bitcoin-family default,
  including the classic 80-byte limit.
- **Chosen shape (Phase 4 indexer)**: exactly one OP_RETURN output per
  transaction, pushing exactly 32 bytes via a direct push opcode
  (`6a20<32 bytes>`). Zero, multiple, or wrong-size OP_RETURN outputs are
  treated as an unusable binding (never guessed) — see
  `relayer/src/glc/deposit.rs`.

### Mempool vs. confirmed

- `getrawtransaction(txid, true)` on an **unconfirmed** (mempool-only)
  transaction has **no `confirmations` field at all** (absent, not present
  with value 0).
- `gettxout(txid, vout)` **includes mempool by default**.
  `gettxout(txid, vout, false)` with `include_mempool=false` **correctly
  excludes** a mempool-only output (returns null) — this is the tool the
  indexer uses for its defensive "still genuinely on-chain and unspent"
  re-check before promoting a deposit to `ReadyForSignature`.
- The indexer never calls `getrawmempool`/mempool-inspecting methods at
  all: it only ever processes transactions reached via `getblock(hash)`,
  which structurally cannot include unconfirmed transactions.

### Reorg mechanics

- `invalidateblock(hash)` immediately rolls back the active chain tip.
  Mining past the invalidated block on the remaining (now-shorter) chain
  permanently orphans it.
- `getblock(orphaned_hash, true)["confirmations"]` becomes **exactly
  `-1`** — the RPC's own documented signal for "not on the main chain."
- `reconsiderblock(hash)` correctly does **not** force reactivation of a
  branch that is no longer the most-work chain (confirmed: confirmations
  stayed `-1` after reconsidering a branch a competing chain had already
  surpassed).
- `getblockhash(height)` returns the live canonical hash at that height —
  the primitive the indexer's reorg walk-back algorithm compares against
  its own locally stored hash.
- A transaction still in the mempool after `invalidateblock` is commonly
  re-mined into the very next generated block — the indexer's reorg
  rollback must create a **fresh** row for it rather than resurrecting the
  orphaned one (verified both against the mock and the real node; see
  `deposit_candidates`'s `UNIQUE(txid, vout, block_hash)` key).

### Node-unavailable behavior

- Stopping the daemon produces a clean, **non-JSON** connection failure
  from `goldcoin-cli` (`error: couldn't connect to server: unknown (code
  -1)`, exit code 1) — cleanly distinguishable from a JSON-RPC
  method-error response (a valid JSON object with an `"error"` field).
  The relayer's RPC client (`relayer/src/glc/rpc.rs`) relies on exactly
  this distinction to separate retriable transport failures from
  non-retriable method errors.

### RPC authentication

- `rpcuser`/`rpcpassword` work but the node warns: *"Config options
  rpcuser and rpcpassword will soon be deprecated. Locally-run instances
  may remove rpcuser to use cookie-based auth, or may be replaced with
  rpcauth."* Phase 4's regtest integration tests use fresh, throwaway,
  per-test-process credentials (never committed, never reused). Production
  deployments should prefer cookie-file or `rpcauth` authentication over
  plaintext `rpcuser`/`rpcpassword` in a config file.

### Wallet / payout RPCs (verified Phase 6)

Established by probing a real v0.15.0 regtest node; all directly shape the
withdrawal executor (ADR-0013).

- **Present**: `listunspent`, `createrawtransaction`, `fundrawtransaction`,
  `signrawtransaction`, `sendrawtransaction`, `estimatefee`,
  `estimatesmartfee`, `getnewaddress`, `importaddress`, `importprivkey`,
  `getbalance`, `settxfee`, `gettransaction`, `listtransactions`,
  `getmempoolentry`, `dumpprivkey`, `getrawchangeaddress`, `lockunspent`,
  `listlockunspent`.
- **ABSENT**: `scantxoutset` (no wallet-less UTXO scan — vault discovery
  must go through the wallet), and `signrawtransactionwithwallet` (this
  lineage predates the Bitcoin Core 0.17 split; the method is the older
  `signrawtransaction`).
- **Fee estimation is unusable on regtest**: `estimatefee 6` returns `-1`
  and `estimatesmartfee 6` returns `{"feerate":-1,"blocks":25}`. A payout
  fee rate must therefore be configured explicitly; there is no node-derived
  default to fall back on.
- **`lockunspent` locks are in-memory only** — confirmed lost across a node
  restart (`listlockunspent` returns `[]` afterwards). Reservations that must
  survive a restart have to be persisted by the relayer.
- **Broadcast semantics** (the basis of restart-safe payouts):
  - re-sending a transaction already in the mempool **succeeds** and returns
    the same txid — rebroadcast is idempotent;
  - re-sending one already mined fails with **code -27**, which means
    "already in block chain" and must be treated as success;
  - spending an already-spent outpoint fails at signing (`complete: false`)
    and at broadcast with **code -25 "Missing inputs"** — a conflict, never
    a retry. `gettxout` on that outpoint returns null.
- **The wallet does not treat a vault address as special.** With the vault
  address in the node's own wallet, an unrelated `sendtoaddress` will consume
  vault outputs as inputs and consolidate them. Relevant to custody.md #2/#3
  and to any single-wallet vault arrangement.
- Regtest block subsidy observed at **10000 GLC**; coinbase maturity 100
  blocks, as in the Bitcoin lineage.

### P2SH M-of-N multisig vault (verified Phase 7b)

The spend path custody.md #2 depended on, verified end to end against a real
v0.15.0 regtest node with three independently-held keys. This closes what
ADR-0014 recorded as finding **F4**.

- **`createmultisig 2 [pk1,pk2,pk3]`** returns a `Q`-prefixed P2SH address
  and its `redeemScript`. The `Q` prefix (Goldcoin-specific version byte,
  neither Bitcoin mainnet `3` nor testnet `2`) is confirmed again here.
- **The wallet does not see the vault at all** until `importaddress`. After
  importing the *address* only, its UTXOs appear with **`spendable: false`
  and `solvable: false`**. Importing the **redeemScript** with the `p2sh`
  flag makes them `solvable`. **Consequence: a relayer that filters
  `listunspent` on `spendable` will see an empty vault** whenever the local
  node does not hold enough keys to sign alone — which is the normal case
  for production custody. `solvable` is the correct filter.
- **Partial signing works and partials are unspendable.** Signing with one
  key of a 2-of-3 returns `complete: false` with
  `"Operation not valid with the current stack size"`, and broadcasting that
  partial is rejected with **`-26 mandatory-script-verify-flag-failed`**. A
  second independent signature over the first signer's partial returns
  `complete: true` and broadcasts normally.
- **`signrawtransaction` requires explicit `prevtxs` carrying the
  `redeemScript`** (plus the signer's own WIF key) to sign for a vault the
  wallet cannot solve on its own. The bare `signrawtransaction(hex)` form
  used for a wallet-owned P2PKH vault is not sufficient.
- **Signature order does not matter**: any M of N, in any order, produces a
  valid transaction (verified with signers {3,1} as well as {1,2}).
- **The txid is stable across signing ORDER but not across signing SET.**
  The same quorum signing in either order yields an identical txid
  (deterministic ECDSA), but different quorums over identical inputs and
  outputs yield different txids:

  ```
  signers {1,2}: cc21b040eec6803c1a9ae71409a57e45e311e28e898e88f75c2db828f443ffd5
  signers {1,3}: 13edc8c3b9b1a6b2d0844812446c965ea02fff6fc93fd13b08a8698248a50fe8
  signers {2,3}: 7c76b400b178027b9fd3513efdbc7045da23c4315252b6d4e46ddce9af5d0ef7
  ```

  **Consequence:** ADR-0013's "persist the txid before broadcasting"
  recovery model only survives multisig if the signing quorum is fixed in
  advance. This is why ADR-0014 now specifies an explicitly designated
  quorum inside the signed payout intent (owner decision, 2026-07-31).

## Not yet verified / explicitly out of scope for Phase 4

- P2SH multisig vault construction end-to-end (spend path) — custody.md #2
  is still open; Phase 4 supports P2PKH vault matching only (owner decision
  U5).
- The true mainnet OP_RETURN standardness ceiling (see above).
- Goldcoin-specific consensus/anti-51% rules, if any, beyond standard
  most-work-chain-wins reorg semantics already exercised here.
