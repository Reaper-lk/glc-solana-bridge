# Local test harness (documentation only — full compose file arrives Phase 6)

Phase 4 verified the Goldcoin node facts this directory previously listed as
unknown (see `docs/goldcoin-rpc-notes.md`), by building and running a real
`goldcoin/goldcoin v0.15.0` binary. Phase 4's own relayer integration tests
(`relayer/tests/regtest_indexer.rs`) already start/stop a throwaway regtest
node per test directly via `std::process::Command` — no Docker Compose file
exists yet. A full multi-service compose file (Goldcoin + Solana localnet +
N relayers) remains Phase 6 work.

## Planned composition (Phase 6: full e2e)

| Service | Source | Notes |
|---|---|---|
| `goldcoin-regtest` | Built from `goldcoin/goldcoin` source at a **pinned tag** (`v0.15.0` verified working; prebuilt `x86_64-linux-gnu` release tarball exists) | No official Goldcoin Docker image is assumed to exist. See `docs/goldcoin-rpc-notes.md` for the verified binary/version |
| `solana-localnet` | Agave-based image or release binaries running `solana-test-validator --reset` | Old `solanalabs/solana` images are deprecated (Solana Labs → Anza); exact sourcing pinned with the toolchain pairing |
| `relayer-node-1..N` | Multi-stage `rust:slim` build of `relayer/`, non-root runtime user | Recipe is straightforward once the daemon does something |

## Goldcoin regtest node configuration (verified, Phase 4)

```ini
regtest=1
server=1
txindex=1                    # MANDATORY — see docs/goldcoin-rpc-notes.md;
                              # getrawtransaction is unreliable without it
rpcuser=<throwaway>          # regtest-only, never reused anywhere
rpcpassword=<throwaway>
rpcbind=127.0.0.1
rpcallowip=127.0.0.1         # or <compose-network-only> once containerized
bind=127.0.0.1
fallbackfee=0.0001
```

Verified port facts (do NOT assume Bitcoin defaults — confirmed genuinely
different, see `docs/goldcoin-rpc-notes.md`):

- Documented mainnet defaults: P2P **8121**, RPC **8122**.
- Documented testnet defaults: P2P **18121**, RPC **18122**.
- Empirically observed regtest (this build): P2P **18130**, RPC **18122**
  (regtest is otherwise **undocumented** in `--help` despite working).
- The blueprint's assumed `18332` (Bitcoin testnet's port) is confirmed
  **wrong** for Goldcoin.
- `-rpcport`/`-port` should be set explicitly rather than relied upon by
  default, exactly as `relayer/tests/regtest_indexer.rs` does (binds to a
  freshly allocated free port per test to avoid collisions).

The genesis block's coinbase cannot be fetched via `getrawtransaction` even
with `-txindex=1` — any tooling that walks blocks from height 0 must skip
it (the indexer does; see `docs/goldcoin-rpc-notes.md`).

## Rules carried into the implementation

- Regtest/localnet only; nothing in this directory ever targets a public
  network.
- Throwaway credentials only; compose networks not exposed beyond localhost.
- Image references pinned to digests or reviewed tags — never `latest`.
