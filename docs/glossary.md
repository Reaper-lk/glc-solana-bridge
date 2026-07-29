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
| **Deposit claim PDA (`DepositClaim`)** | Per-deposit Solana account seeded by `(txid, vout)`; its existence is the replay guard (ADR-0003). |
| **Withdrawal request (`WithdrawalRequest`)** | Persistent Solana account created atomically with a burn; the authoritative payout obligation record (ADR-0006). Status: `Pending → Broadcast → Completed`. |
| **Replay** | Attempting to mint twice for the same deposit; structurally rejected by claim-PDA creation. |
| **PDA (program-derived address)** | A Solana address derived from seeds + program id with no private key. Used for the mint authority (ADR-0004), config, claims, and withdrawal records. |
| **Mint authority** | The PDA that alone can mint wrapped GLC; the program signs via `invoke_signed`. No keypair exists. |
| **Confirmation depth (N confirmations)** | Number of Goldcoin blocks on top of a deposit before the federation may sign its claim. Value unresolved; the dominant safety parameter given GLC's PoW hashrate (`threat-model.md`). |
| **Reorg** | Replacement of recent Goldcoin blocks by a longer chain; can erase an observed deposit. The indexer must roll back and re-scan, and halt beyond a safety bound. |
| **Recipient binding** | The mechanism tying a Solana recipient pubkey to a GLC deposit (leading option: `OP_RETURN` payload) — open Phase 1 decision (`deposit-flow.md`). |
| **`OP_RETURN`** | Bitcoin-family script opcode embedding small arbitrary data in a transaction; candidate carrier for recipient binding. |
| **Goldcoin Core** | The unmodified C++ node (~Bitcoin 0.14-era fork) the bridge talks to over JSON-RPC only. Never forked or patched by this project. |
| **Regtest** | Private, locally-mined Goldcoin network mode used by the test harness. |
| **Localnet** | Local `solana-test-validator` instance used by the test harness. |
| **Anchor** | Rust framework used for the Solana program (`programs/glc-bridge`). |
| **Agave** | The Solana validator client lineage (successor to the Solana Labs client) whose tooling builds and runs the program. |
| **SBF** | Solana Binary Format — the constrained compilation target for on-chain code; `shared/` must always remain SBF-compatible. |
| **Signature aggregation** | Off-chain collection of M validator signatures into a single proof submitted with `mint_wrapped` (ADR-0005). |
| **TSS** | Threshold signature scheme — a candidate vault-signing model; explicitly out of scope until custody is decided (`custody.md`). |
