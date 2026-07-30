# Glossary

Terms as used in this repository. Where a term has multiple industry
meanings, only the meaning used here is given.

| Term | Meaning here |
|---|---|
| **Bridge** | The whole system letting GLC holders obtain wrapped GLC on Solana and redeem it back 1:1. Federated — trust-minimized, not trustless. |
| **Federation / validator set** | The N operators whose M-of-N approval authorizes mints (and eventually vault spends). Registered as public keys in the `ValidatorSet` PDA (ADR-0007), at most `MAX_VALIDATORS` (16). |
| **Epoch** | Revision counter of the validator set, incremented on every rotation. Phase 3 proofs bind to the epoch they were signed under, so a rotation invalidates in-flight proofs (ADR-0007). |
| **M-of-N / threshold** | Minimum number of validator signatures (M) out of the registered set (N) required for a federation action. |
| **Relayer** | The off-chain daemon (`relayer/`) each federation member runs beside their own Goldcoin full node: watches deposits, signs claims, aggregates signatures, submits Solana transactions, tracks withdrawals. |
| **Vault** | The Goldcoin address/script holding all native GLC backing the wrapped supply. Construction and signing model are unresolved (`custody.md`). |
| **Wrapped GLC** | The SPL token on Solana, minted 1:1 against confirmed vault deposits, burned on withdrawal. |
| **Deposit** | A confirmed Goldcoin transaction output paying the vault, identified canonically by `(txid, vout)` (ADR-0002). |
| **`(txid, vout)`** | Goldcoin transaction id (32 bytes) + output index — the unique, L1-derived identity of one deposit. |
| **Claim / `InboundClaim`** | The payload the federation signs asserting "deposit `(txid, vout)` of amount X is confirmed; mint to recipient R". |
| **Deposit claim PDA (`DepositClaim`)** | Per-deposit Solana account seeded by `(txid, vout little-endian)`; its existence is the replay guard (ADR-0003). Records amount, recipient, validator epoch, protocol version, and creation slot (ADR-0009). |
| **Claim message** | The canonical 166-byte payload validators sign for a deposit (`shared::claim`, ADR-0010): domain tag, protocol version, program id, epoch, action, `(txid, vout)`, amount, recipient, wrapped mint. Byte-exact between relayer and program. |
| **Federation proof** | One ed25519-precompile instruction, immediately before `mint_wrapped`, carrying ≥ threshold distinct current validators' signatures over the claim message. Verified by the runtime, then structurally checked by the program via the Instructions sysvar (ADR-0010). |
| **Withdrawal request (`WithdrawalRequest`)** | Persistent Solana account created atomically with a burn; the authoritative payout obligation record (ADR-0006). Status: `Pending → Broadcast → Completed`. |
| **Replay** | Attempting to mint twice for the same deposit; structurally rejected by claim-PDA creation. |
| **PDA (program-derived address)** | A Solana address derived from seeds + program id with no private key. Used for the mint authority (ADR-0004), config, claims, and withdrawal records. |
| **Mint authority** | The PDA that alone can mint wrapped GLC; the program signs via `invoke_signed`. No keypair exists. |
| **Confirmation depth (N confirmations)** | Number of Goldcoin blocks on top of a deposit before it may reach `ReadyForSignature`. A required, strictly validated indexer config value with no built-in default (`confirmation_depth > 0`, owner decision U6, ADR-0011) — the production number remains an open security/ops decision given GLC's PoW hashrate (`threat-model.md`). |
| **Reorg** | Replacement of recent Goldcoin blocks by a longer chain; can erase an observed deposit. The indexer's walk-back algorithm (ADR-0011) rolls affected rows back to `Orphaned` and halts (no further writes) if the reorg exceeds `max_reorg_depth`. |
| **Recipient binding** | The mechanism tying a Solana recipient pubkey to a GLC deposit: exactly one `OP_RETURN` output pushing exactly 32 bytes. Confirmed working Phase 4 against a real node; zero, multiple, or wrong-size OP_RETURNs are treated as unusable, never guessed (`relayer/src/glc/deposit.rs`, ADR-0011). |
| **`OP_RETURN`** | Bitcoin-family script opcode embedding small arbitrary data in a transaction; the recipient-binding carrier (see above). |
| **Goldcoin Core** | The unmodified C++ node the bridge talks to over JSON-RPC only. Verified lineage (Phase 4): Bitcoin Core → Litecoin Core → Goldcoin Core; version v0.15.0 tested. Never forked or patched by this project. |
| **Regtest** | Private, locally-mined Goldcoin network mode used by the test harness. Undocumented in `goldcoind --help` but confirmed functional (Phase 4, `goldcoin-rpc-notes.md`). |
| **Deposit candidate** | One row in the indexer's `deposit_candidates` table: a vault-paying output plus its (possibly invalid) recipient binding, tracked through the state machine `Candidate → Confirming → ReadyForSignature` (or `Orphaned`/`Failed`) — never deleted (ADR-0011). |
| **Indexer** | The Phase 4 `relayer` component (`relayer/src/glc/indexer.rs`) that follows the Goldcoin chain block-by-block, detects deposits, tracks confirmations, handles reorgs, and produces unsigned claim artifacts. Never signs or submits anything. |
| **Claim artifact** | The unsigned, exact 166-byte canonical claim message produced once a deposit reaches `ReadyForSignature`, stored in `claim_artifacts` (ADR-0011). Not signed or transmitted until Phase 5. |
| **Chain tip / fork point** | The indexer's locally recorded highest indexed block; the fork point is the highest height at which the indexer's stored hash still matches the live node's `getblockhash` during reorg detection (ADR-0011). |
| **Localnet** | Local `solana-test-validator` instance used by the test harness. |
| **Anchor** | Rust framework used for the Solana program (`programs/glc-bridge`). |
| **Agave** | The Solana validator client lineage (successor to the Solana Labs client) whose tooling builds and runs the program. |
| **SBF** | Solana Binary Format — the constrained compilation target for on-chain code; `shared/` must always remain SBF-compatible. |
| **Signature aggregation** | Off-chain collection of M validator signatures into a single proof submitted with `mint_wrapped` (ADR-0005). |
| **TSS** | Threshold signature scheme — a candidate vault-signing model; explicitly out of scope until custody is decided (`custody.md`). |
