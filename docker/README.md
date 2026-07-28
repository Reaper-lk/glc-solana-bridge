# Local test harness (documentation only — implementation arrives Phase 4/6)

Phase 0 ships **no Docker implementation**: earlier placeholder files
(`docker-compose.yml`, `Dockerfile.goldcoin`, `Dockerfile.relayer`,
`goldcoin.conf`) were removed in favor of this document, because every one of
them depended on facts not yet verified (Goldcoin ports, node build recipe,
maintained Agave image). Implementation returns when those facts are pinned.

## Planned composition (Phase 4: GLC side; Phase 6: full e2e)

| Service | Source | Notes |
|---|---|---|
| `goldcoin-regtest` | Built from `goldcoin/goldcoin` source at a **pinned tag** | No official Goldcoin Docker image is assumed to exist. Build deps (autotools, boost, libevent, bdb) depend on the exact Core lineage → verified in Phase 4, recorded in `docs/goldcoin-rpc-notes.md` |
| `solana-localnet` | Agave-based image or release binaries running `solana-test-validator --reset` | Old `solanalabs/solana` images are deprecated (Solana Labs → Anza); exact sourcing pinned with the toolchain pairing |
| `relayer-node-1..N` | Multi-stage `rust:slim` build of `relayer/`, non-root runtime user | Recipe is straightforward once the daemon does something |

## Goldcoin regtest node configuration (sketch)

Flag names below are Bitcoin-0.14-era conventions — every one must be
verified against actual Goldcoin Core before use:

```ini
regtest=1
server=1
txindex=1
rpcuser=<throwaway>          # regtest-only, never reused anywhere
rpcpassword=<throwaway>
rpcallowip=<compose-network-only>
# rpcport: UNKNOWN — the blueprint's 18332 is Bitcoin *testnet's* port;
# Goldcoin's real default is a Phase 4 verification item.
```

## Rules carried into the implementation

- Regtest/localnet only; nothing in this directory ever targets a public
  network.
- Throwaway credentials only; compose networks not exposed beyond localhost.
- Image references pinned to digests or reviewed tags — never `latest`.
