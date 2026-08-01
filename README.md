# Goldcoin (GLC) ↔ Solana Federated Bridge

Standalone infrastructure bridging native Goldcoin (PoW L1) and Solana via a
wrapped SPL token, operated by an M-of-N federation of validators.

**Status: Phase 0 — scaffold only.** No bridge logic, no minting, no signing,
no RPC clients, no deployments. Everything value-bearing is unimplemented by
design; see [docs/architecture.md](docs/architecture.md) for the phase plan.

## Design principles (fixed in Phase 0)

- **Goldcoin Core is never modified.** The bridge talks to a stock Goldcoin
  node over JSON-RPC only. This repository is not a fork of
  `goldcoin/goldcoin`.
- **Deposits are identified by `(txid, vout)`** — the canonical, L1-derived
  identity of a vault payment ([ADR-0002](docs/adr/0002-deposit-identity-txid-vout.md)).
- **Replay prevention is one PDA per processed claim** — account existence is
  the guard ([ADR-0003](docs/adr/0003-claim-pda-replay-prevention.md)).
- **Withdrawals are persistent on-chain records**, not log events
  ([ADR-0006](docs/adr/0006-persistent-withdrawal-records.md)).
- **The wrapped mint's authority is a PDA** — no mint keypair exists
  ([ADR-0004](docs/adr/0004-pda-mint-authority.md)).
- **M-of-N federation proof is aggregated off-chain** by relayers and verified
  by the program ([ADR-0005](docs/adr/0005-offchain-signature-aggregation.md)).
- **On-chain and off-chain dependency graphs never mix**: the repository root
  is the on-chain Cargo workspace; `relayer/` is a separate workspace
  ([ADR-0001](docs/adr/0001-repo-layout-and-workspace-split.md)).

## Repository map

| Path | Contents |
|---|---|
| `programs/glc-bridge/` | Solana Anchor program (placeholder) |
| `shared/` | Types shared on-chain/off-chain; SBF-safe, dependency-minimal |
| `relayer/` | Federated validator daemon (placeholder; own Cargo workspace) |
| `tests/` | E2E integration harness (arrives Phase 6) |
| `docker/` | Test-harness documentation; implementation arrives Phase 4/6 |
| `docs/` | Architecture, security model, custody questions, ADRs |
| `.github/workflows/` | CI: on-chain build, off-chain build, supply-chain audit |

## Toolchain

Host Rust is pinned in `rust-toolchain.toml`; Anchor version in `Anchor.toml`.
The exact Anchor ↔ Agave ↔ platform-tools pairing is finalized in Phase 1 —
CI is the compilation authority.

## Security

This project moves user funds when complete; until audits and the custody
decisions in [docs/custody.md](docs/custody.md) are resolved, nothing here is
deployable. No keys or secrets exist in this repository — report anything that
looks like one (see [SECURITY.md](SECURITY.md) for how). Threat model:
[docs/threat-model.md](docs/threat-model.md); operator procedures:
[docs/runbooks.md](docs/runbooks.md); terminology:
[docs/glossary.md](docs/glossary.md).
