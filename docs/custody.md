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
| 6 | Freeze authority on wrapped mint: `None` (censorship-resistant) vs governance-held | `initialize` design |
| 7 | Emergency pause: who can pause, what quorum un-pauses | admin instructions |
| 8 | Proof-of-reserves / attestation cadence | operations |
| 9 | Withdrawal payout policy: deterministic UTXO selection, fee bearer, min amount | `WithdrawalRequest` schema reserves fields |

Interim note (Phase 1, not a custody decision): a single `admin` pubkey —
the initializer, i.e. the program upgrade authority — gates pause,
validator-set rotation, and its own two-step handover until #1/#7 are
decided. See ADR-0008.

## Decision log

*(empty — no custody decisions have been made)*
