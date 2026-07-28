//! glc-relayer — federated validator daemon (Phase 0 placeholder).
//!
//! Eventual responsibilities (docs/architecture.md):
//! 1. Follow the Goldcoin chain, detect vault deposits, wait N confirmations
//!    with reorg rollback (`glc` module — Phase 2/4).
//! 2. Sign `InboundClaim`s and aggregate M-of-N federation signatures with
//!    peer relayers (`signer` + `p2p` modules — Phase 3/5).
//! 3. Submit `mint_wrapped` with the aggregated proof; scan persistent
//!    `WithdrawalRequest` accounts for payouts (`solana` module — Phase 5).
//!
//! Phase 0 does none of this: it initializes logging, prints its status, and
//! exits so the binary, CI, and Docker plumbing are provable end-to-end.

mod glc;
mod p2p;
mod signer;
mod solana;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("glc-relayer Phase 0 scaffold: no bridge logic implemented; exiting");
    Ok(())
}
