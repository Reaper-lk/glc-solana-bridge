# Custody — open questions & decision log

Deliberately unresolved. Nothing below may be silently assumed by code; each
decision gets a dated entry and, where design-relevant, an ADR. **All items
open as of 2026-07-28 (Phase 0).**

| # | Question | Constrains |
|---|---|---|
| 1 | Federation composition: who operates the N validators; values of M and N | program config, p2p design |
| 2 | GLC vault construction: P2SH multisig? script capabilities of Goldcoin (~Bitcoin 0.14 era) to be verified; timelocked recovery path? | withdrawal signing, Phase 2 RPC notes |
| 3 | Vault signing model: script multisig vs TSS (both explicitly out of scope now) | relayer `signer`, `WithdrawalRequest` schema stays signing-agnostic |
| 4 | Key rotation & vault migration procedure (UTXO sweep to new vault) | operations runbook |
| 5 | Program upgrade-authority custody (e.g., Squads multisig) and immutability timeline | deployment gating |
| 6 | ~~Freeze authority on wrapped mint~~ — **DECIDED 2026-07-29**, see decision log | `create_wrapped_mint` (ADR-0009) |
| 7 | Emergency pause: who can pause, what quorum un-pauses | admin instructions |
| 8 | Proof-of-reserves / attestation cadence | operations |
| 9 | Withdrawal payout policy: deterministic UTXO selection, fee bearer, min amount | `WithdrawalRequest` schema reserves fields |

Interim note (Phase 1, not a custody decision): a single `admin` pubkey —
the initializer, i.e. the program upgrade authority — gates pause,
validator-set rotation, and its own two-step handover until #1/#7 are
decided. See ADR-0008.

## Decision log

- **2026-07-30 — #9 (partial) Withdrawal payout policy, Phase 6 only**
  (owner decisions D3/D4/D6, ADR-0013). Deterministic coin selection
  (exact-match → smallest-covering → greedy largest-first, tie-broken on
  `(txid, vout)`); **the vault bears the fee** so the user receives exactly
  the burned amount; the fee rate is explicitly configured with no default
  (node fee estimation is unusable on regtest). Scoped to regtest; the
  production policy remains open.
- **2026-07-30 — #2/#3 remain OPEN; Phase 6 uses a test-only stand-in.**
  The regtest vault is a single-key P2PKH address held by the Goldcoin node
  wallet (owner decision D2). One key can drain it, and the node wallet will
  spend vault outputs for unrelated transactions (verified). Explicitly not
  production custody; do not deploy beyond regtest.
- **2026-07-29 — #6 Freeze authority: `None`** (owner decision, Phase 2,
  ADR-0009). The federation must not be able to freeze user funds;
  censorship-resistance chosen over a governance-held freeze. Irreversible
  per mint; costless to revisit until a persistent deployment exists.
