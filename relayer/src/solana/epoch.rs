//! Observing the on-chain validator epoch (Phase 7d/7e).
//!
//! Both long-running binaries need this and must agree about it, so it lives
//! here rather than being written twice: `signer-server` refuses to sign
//! under an epoch it cannot currently confirm, and `glc-relayer` stamps the
//! epoch it observes onto every signing request it sends.
//!
//! # A failed poll must not look like a successful one
//!
//! [`EpochObservation::record`] is called **only** on success. A failed poll
//! deliberately leaves the previous observation and its timestamp untouched,
//! so staleness accumulates and [`EpochObservation::is_fresh_at`] goes false
//! on its own. Papering over an outage by refreshing the timestamp — or by
//! substituting a guess — would let a partitioned node keep answering with a
//! remembered value forever.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;

use crate::solana::instruction;
use crate::solana::rpc::{self, SolanaRpc};

/// How long an epoch observation stays usable without a successful refresh.
///
/// Bounded by how quickly a validator-set rotation must stop a lagging node
/// from acting under the old set. Longer than several poll intervals so a
/// brief RPC blip does not take a node offline, short enough that a real
/// outage does.
pub const MAX_VIEW_STALENESS: Duration = Duration::from_secs(60);

/// How often the epoch is re-observed from the chain.
pub const EPOCH_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The shared, atomically-updated result of epoch polling.
#[derive(Debug)]
pub struct EpochObservation {
    epoch: AtomicU64,
    /// Unix seconds of the last **successful** observation.
    observed_at: AtomicI64,
}

impl EpochObservation {
    /// Seeds the observation from a first successful read.
    ///
    /// There is deliberately no constructor producing an *unobserved* state:
    /// a process with no epoch at all has nothing meaningful to compare
    /// against, so startup blocks on this instead.
    pub fn seeded(epoch: u64, at_unix: i64) -> Self {
        EpochObservation {
            epoch: AtomicU64::new(epoch),
            observed_at: AtomicI64::new(at_unix),
        }
    }

    pub fn record(&self, epoch: u64, at_unix: i64) {
        // Order matters: publish the epoch before the timestamp that vouches
        // for it, so a concurrent reader can never see a fresh timestamp
        // attached to a stale epoch.
        self.epoch.store(epoch, Ordering::SeqCst);
        self.observed_at.store(at_unix, Ordering::SeqCst);
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    pub fn observed_at(&self) -> i64 {
        self.observed_at.load(Ordering::SeqCst)
    }

    pub fn is_fresh_at(&self, now_unix: i64) -> bool {
        let age = now_unix.saturating_sub(self.observed_at());
        // A negative age (clock stepped backwards) is not treated as extra
        // freshness; only a genuinely recent observation counts.
        (0..=MAX_VIEW_STALENESS.as_secs() as i64).contains(&age)
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reads the on-chain validator epoch — this node's own observation, never a
/// configured constant.
pub async fn observe_epoch<R: SolanaRpc>(
    solana_rpc: &R,
    program_id: &Pubkey,
) -> anyhow::Result<u64> {
    let (validator_set_pda, _) = instruction::validator_set_pda(program_id);
    let account = solana_rpc
        .get_account(&validator_set_pda)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the on-chain ValidatorSet account was not found — has the bridge been initialized?"
            )
        })?;
    Ok(rpc::decode_validator_set(&account.data)?.epoch)
}

/// Re-observes the epoch until shutdown.
pub async fn run_epoch_refresher<R: SolanaRpc>(
    solana_rpc: R,
    program_id: Pubkey,
    observation: Arc<EpochObservation>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("epoch refresher: shutdown signal received, exiting");
                return;
            }
            _ = tokio::time::sleep(EPOCH_POLL_INTERVAL) => {
                match observe_epoch(&solana_rpc, &program_id).await {
                    Ok(epoch) => {
                        let previous = observation.epoch();
                        observation.record(epoch, now_unix());
                        if epoch != previous {
                            tracing::warn!(
                                previous,
                                observed = epoch,
                                "validator set epoch changed — requests quoting the old epoch will now be refused"
                            );
                        }
                    }
                    Err(e) => {
                        // Not an error to exit on: the staleness bound is
                        // what protects correctness here, and a node that
                        // died on a transient RPC blip would be worse for
                        // availability than one that briefly refuses.
                        tracing::warn!(
                            error = %e,
                            "failed to re-observe the validator epoch; this node will stop acting once its view goes stale"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_observation_is_usable() {
        let o = EpochObservation::seeded(7, 1_000);
        assert!(o.is_fresh_at(1_000));
        assert!(o.is_fresh_at(1_000 + MAX_VIEW_STALENESS.as_secs() as i64));
        assert_eq!(o.epoch(), 7);
    }

    #[test]
    fn an_observation_goes_stale_once_past_the_bound() {
        let o = EpochObservation::seeded(7, 1_000);
        assert!(
            !o.is_fresh_at(1_001 + MAX_VIEW_STALENESS.as_secs() as i64),
            "a node that stopped hearing from the chain must stop acting"
        );
    }

    #[test]
    fn a_failed_poll_does_not_refresh_the_observation() {
        // The refresher only calls `record` on success, so staleness
        // accumulates across an outage instead of being papered over.
        let o = EpochObservation::seeded(7, 1_000);
        let far_future = 1_000 + 10 * MAX_VIEW_STALENESS.as_secs() as i64;
        assert!(!o.is_fresh_at(far_future));
        o.record(7, far_future);
        assert!(o.is_fresh_at(far_future), "a successful poll restores it");
    }

    #[test]
    fn an_observation_timestamped_in_the_future_does_not_read_as_fresh() {
        // Both a small and a large backwards step: the small one is the
        // interesting case, because taking the magnitude of the difference
        // would still land inside the staleness bound and silently pass.
        let o = EpochObservation::seeded(7, 1_000);
        assert!(
            !o.is_fresh_at(1_000 - (MAX_VIEW_STALENESS.as_secs() as i64 / 2)),
            "a clock that stepped backwards must not read as a recent observation"
        );
        assert!(!o.is_fresh_at(500));
    }

    #[test]
    fn a_rotation_is_picked_up_by_the_next_successful_poll() {
        let o = EpochObservation::seeded(7, 1_000);
        o.record(8, 1_005);
        assert_eq!(o.epoch(), 8);
        assert_eq!(o.observed_at(), 1_005);
    }
}
