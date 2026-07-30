//! The indexer tick loop (ADR-0011): forward indexing, reorg detection and
//! rollback, and deposit state-machine transitions. Ties `rpc` + `db` +
//! `deposit` together.
//!
//! [`GoldcoinRpc`] is a trait covering the exact RPC surface the indexer
//! needs, implemented for the real [`RpcClient`](super::rpc::RpcClient) and
//! for a test-only mock — so the tick/reorg/state-machine logic itself is
//! unit-testable without a live node, while separate integration tests
//! (`tests/regtest_indexer.rs`) exercise the real client end-to-end.

use std::future::Future;

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::config::IndexerConfig;
use super::db::{Db, DbError, DepositState, NewBlock, NewCandidate, NewClaimArtifact};
use super::deposit::{extract_recipient_binding, vault_output_candidates};
use super::hex;
use super::rpc::{BlockHeader, DecodedTransaction, RpcClient, RpcError, TxOut};

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("Goldcoin node unavailable: {0}")]
    NodeUnavailable(RpcError),
    #[error("Goldcoin RPC method error: {0}")]
    Rpc(RpcError),
    #[error("database error: {0}")]
    Db(#[from] DbError),
}

#[derive(Debug, Clone)]
pub struct ReorgSummary {
    pub fork_height: i64,
    pub old_tip_height: i64,
    pub orphaned_count: i64,
}

#[derive(Debug, Clone)]
pub enum TickOutcome {
    /// Normal progress; `blocks_indexed` may be 0 (already at the live tip).
    Progressed {
        blocks_indexed: i64,
        reorg: Option<ReorgSummary>,
    },
    /// A reorg deeper than `max_reorg_depth` was detected. The indexer made
    /// NO database writes for this tick and will refuse to progress on any
    /// future tick until restarted with a wider `max_reorg_depth` or manual
    /// operator intervention — never guesses a fork point (security
    /// requirement).
    Halted { attempted_depth: i64 },
}

/// The exact RPC surface the indexer consumes. A trait (not a concrete
/// type) so tick/reorg logic is unit-testable against a mock.
pub trait GoldcoinRpc {
    fn get_block_count(&self) -> impl Future<Output = Result<i64, RpcError>> + Send;
    fn get_block_hash(&self, height: i64) -> impl Future<Output = Result<String, RpcError>> + Send;
    fn get_block(&self, hash: &str) -> impl Future<Output = Result<BlockHeader, RpcError>> + Send;
    fn get_raw_transaction(
        &self,
        txid_hex: &str,
    ) -> impl Future<Output = Result<DecodedTransaction, RpcError>> + Send;
    fn get_raw_transaction_hex(
        &self,
        txid_hex: &str,
    ) -> impl Future<Output = Result<String, RpcError>> + Send;
    fn get_tx_out_confirmed(
        &self,
        txid_hex: &str,
        vout: u32,
    ) -> impl Future<Output = Result<Option<TxOut>, RpcError>> + Send;
}

impl GoldcoinRpc for RpcClient {
    async fn get_block_count(&self) -> Result<i64, RpcError> {
        RpcClient::get_block_count(self).await
    }
    async fn get_block_hash(&self, height: i64) -> Result<String, RpcError> {
        RpcClient::get_block_hash(self, height).await
    }
    async fn get_block(&self, hash: &str) -> Result<BlockHeader, RpcError> {
        RpcClient::get_block(self, hash).await
    }
    async fn get_raw_transaction(&self, txid_hex: &str) -> Result<DecodedTransaction, RpcError> {
        RpcClient::get_raw_transaction(self, txid_hex).await
    }
    async fn get_raw_transaction_hex(&self, txid_hex: &str) -> Result<String, RpcError> {
        RpcClient::get_raw_transaction_hex(self, txid_hex).await
    }
    async fn get_tx_out_confirmed(
        &self,
        txid_hex: &str,
        vout: u32,
    ) -> Result<Option<TxOut>, RpcError> {
        RpcClient::get_tx_out_confirmed(self, txid_hex, vout).await
    }
}

/// Retry attempts absorbed per RPC call before a tick reports the node
/// unavailable (module docs on the two-tier retry policy: this is the inner,
/// short tier; the outer tier is the caller's tick-to-tick sleep).
const INNER_RETRY_ATTEMPTS: u32 = 3;

pub struct Indexer<R: GoldcoinRpc> {
    rpc: R,
    db: Db,
    config: IndexerConfig,
    vault_script_hex: String,
    /// Set once a deep reorg halts the indexer; every subsequent tick then
    /// immediately reports `Halted` again without touching the database or
    /// the network, until the process is restarted.
    halted: bool,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl<R: GoldcoinRpc> Indexer<R> {
    pub fn new(rpc: R, db: Db, config: IndexerConfig) -> Self {
        let vault_script_hex = hex::encode(&config.vault_script_pubkey);
        Indexer {
            rpc,
            db,
            config,
            vault_script_hex,
            halted: false,
        }
    }

    // A free function, not a method: taking `&self` here would let a
    // shared `&Indexer` reference get held across an `.await` (since call
    // sites' closures separately borrow `self.rpc`), which requires
    // `Indexer: Sync` — it isn't, because `rusqlite::Connection`'s
    // statement cache uses a `RefCell`. Now that this runs inside
    // `tokio::spawn` (Phase 5, alongside the orchestrator's own loop), the
    // whole future must be `Send`, which a `&self` method here would break.
    async fn call<T, F, Fut>(f: F) -> Result<T, IndexerError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, RpcError>>,
    {
        super::rpc::call_with_retry(INNER_RETRY_ATTEMPTS, f)
            .await
            .map_err(|e| {
                if e.is_retriable() {
                    IndexerError::NodeUnavailable(e)
                } else {
                    IndexerError::Rpc(e)
                }
            })
    }

    /// Runs one indexer tick: reorg detection/rollback (if needed), forward
    /// indexing to the live chain tip, and confirmation-depth promotion.
    pub async fn tick(&mut self) -> Result<TickOutcome, IndexerError> {
        if self.halted {
            return Ok(TickOutcome::Halted {
                attempted_depth: self.config.max_reorg_depth as i64 + 1,
            });
        }

        let live_tip_height = Self::call(|| self.rpc.get_block_count()).await?;

        let (start_height, reorg) = match self.db.chain_tip()? {
            None => (0i64, None),
            Some((local_height, local_hash)) => match self.find_fork_point(local_height).await? {
                None => {
                    self.halted = true;
                    return Ok(TickOutcome::Halted {
                        attempted_depth: self.config.max_reorg_depth as i64 + 1,
                    });
                }
                Some(fork_height) if fork_height == local_height => (local_height + 1, None),
                Some(fork_height) => {
                    let fork_hash_hex = Self::call(|| self.rpc.get_block_hash(fork_height)).await?;
                    let fork_hash: [u8; 32] = hex::decode_exact(&fork_hash_hex)
                        .map_err(|e| IndexerError::Rpc(RpcError::Malformed(e.to_string())))?;
                    let orphaned_count = self.db.rollback_reorg(
                        fork_height,
                        fork_height,
                        fork_hash,
                        local_height,
                        local_hash,
                        now_unix(),
                    )?;
                    (
                        fork_height + 1,
                        Some(ReorgSummary {
                            fork_height,
                            old_tip_height: local_height,
                            orphaned_count,
                        }),
                    )
                }
            },
        };

        let mut blocks_indexed = 0i64;
        for height in start_height..=live_tip_height {
            self.index_block(height).await?;
            blocks_indexed += 1;
        }

        self.advance_new_candidates_to_confirming()?;
        self.promote_confirming(live_tip_height).await?;

        Ok(TickOutcome::Progressed {
            blocks_indexed,
            reorg,
        })
    }

    /// Walks backward from `from_height` comparing the locally stored hash
    /// against the live chain, returning the fork point (the highest height
    /// at which they agree), or `None` if no agreement is found within
    /// `max_reorg_depth` — the caller must halt in that case, never guess.
    // `&mut self`, not `&self` — see `call`'s doc comment above: a shared
    // `&Indexer` held across `.await` would require `Indexer: Sync`.
    async fn find_fork_point(&mut self, from_height: i64) -> Result<Option<i64>, IndexerError> {
        let mut h = from_height;
        loop {
            if h < 0 {
                return Ok(None);
            }
            let live_hash_hex = Self::call(|| self.rpc.get_block_hash(h)).await?;
            let live_hash: [u8; 32] = hex::decode_exact(&live_hash_hex)
                .map_err(|e| IndexerError::Rpc(RpcError::Malformed(e.to_string())))?;
            let local_hash = self.db.block_hash_at_height(h)?;
            if local_hash == Some(live_hash) {
                return Ok(Some(h));
            }
            let depth = from_height - (h - 1);
            if depth > self.config.max_reorg_depth as i64 {
                return Ok(None);
            }
            h -= 1;
        }
    }

    async fn index_block(&mut self, height: i64) -> Result<(), IndexerError> {
        let hash_hex = Self::call(|| self.rpc.get_block_hash(height)).await?;
        let hash: [u8; 32] = hex::decode_exact(&hash_hex)
            .map_err(|e| IndexerError::Rpc(RpcError::Malformed(e.to_string())))?;
        let header = Self::call(|| self.rpc.get_block(&hash_hex)).await?;
        let prev_hash: [u8; 32] = match &header.previousblockhash {
            Some(p) => hex::decode_exact(p)
                .map_err(|e| IndexerError::Rpc(RpcError::Malformed(e.to_string())))?,
            None => [0u8; 32], // genesis
        };

        let discovered_at = now_unix();
        let mut candidates = Vec::new();
        // The genesis block's coinbase is permanently unspendable and,
        // verified empirically, unretrievable via getrawtransaction even
        // with -txindex=1 (docs/goldcoin-rpc-notes.md). It can never carry a
        // vault deposit, so height 0 is skipped entirely rather than special
        // -cased per-transaction.
        let is_genesis = height == 0;
        for txid_hex in &header.tx {
            if is_genesis {
                break;
            }
            let decoded = Self::call(|| self.rpc.get_raw_transaction(txid_hex)).await?;
            let raw_tx_hex = Self::call(|| self.rpc.get_raw_transaction_hex(txid_hex)).await?;
            let vault_outputs = vault_output_candidates(&decoded, &self.vault_script_hex);
            if vault_outputs.is_empty() {
                continue;
            }
            let txid: [u8; 32] = hex::decode_exact(txid_hex)
                .map_err(|e| IndexerError::Rpc(RpcError::Malformed(e.to_string())))?;
            let binding = extract_recipient_binding(&decoded);
            for out in &vault_outputs {
                let (initial_state, failure_reason, recipient) = match &binding {
                    Err(e) => (
                        DepositState::Failed,
                        Some(e.reason_code().to_string()),
                        [0u8; 32],
                    ),
                    Ok(recipient) if out.amount_atomic < self.config.min_deposit_atomic => (
                        DepositState::Failed,
                        Some("below_min_deposit".to_string()),
                        *recipient,
                    ),
                    Ok(recipient) => (DepositState::Candidate, None, *recipient),
                };
                if initial_state == DepositState::Failed {
                    tracing::warn!(
                        txid_hex,
                        vout = out.vout,
                        amount_atomic = out.amount_atomic,
                        block_height = height,
                        reason = failure_reason.as_deref().unwrap_or("unknown"),
                        "vault payment recorded as Failed at ingestion (auditable, not silently ignored)"
                    );
                }
                candidates.push(NewCandidate {
                    txid,
                    vout: out.vout as i64,
                    amount_atomic: out.amount_atomic,
                    recipient,
                    block_height: height,
                    block_hash: hash,
                    raw_tx_hex: raw_tx_hex.clone(),
                    discovered_at,
                    initial_state,
                    failure_reason,
                });
            }
        }

        self.db.ingest_block(
            &NewBlock {
                height,
                hash,
                prev_hash,
                block_time: header.time,
                indexed_at: discovered_at,
            },
            &candidates,
        )?;
        Ok(())
    }

    /// `Candidate -> Confirming` is unconditional and immediate (state
    /// machine: "same tick" — see docs/reviews/phase4-design.md); it exists
    /// as its own persisted state only so a crash between discovery and
    /// depth-evaluation loses nothing. Every ingestion-fresh `Candidate` row
    /// is advanced here, once per tick, before `promote_confirming`
    /// evaluates depth/caps/spent-status on the (now-)`Confirming` set.
    fn advance_new_candidates_to_confirming(&mut self) -> Result<(), DbError> {
        let fresh = self.db.candidates_by_state(DepositState::Candidate)?;
        let at = now_unix();
        for row in fresh {
            tracing::debug!(
                deposit_id = row.id,
                txid_hex = %row.txid_hex,
                vout = row.vout,
                block_height = row.block_height,
                discovered_at = row.discovered_at,
                "deposit candidate now confirming"
            );
            self.db
                .transition_state(row.id, DepositState::Confirming, at, None, None)?;
        }
        Ok(())
    }

    /// Re-evaluates every `Confirming` deposit against the current tip:
    /// promotes to `ReadyForSignature` when depth/value-caps/unspent-status
    /// all clear, demotes to `Failed` if the vault output has been spent by
    /// something other than a reorg, or leaves it in `Confirming` (value
    /// caps breached, or depth not yet reached) for a later tick.
    async fn promote_confirming(&mut self, tip_height: i64) -> Result<(), IndexerError> {
        let confirming = self.db.candidates_by_state(DepositState::Confirming)?;
        for row in confirming {
            let depth = tip_height - row.block_height + 1;
            if depth < self.config.confirmation_depth as i64 {
                continue;
            }

            let still_unspent = Self::call(|| {
                self.rpc
                    .get_tx_out_confirmed(&row.txid_hex, row.vout as u32)
            })
            .await?
            .is_some();
            if !still_unspent {
                tracing::warn!(
                    deposit_id = row.id,
                    txid_hex = %row.txid_hex,
                    vout = row.vout,
                    block_hash = %hex::encode(&row.block_hash),
                    "vault output spent before reaching ReadyForSignature; demoting to Failed"
                );
                self.db.transition_state(
                    row.id,
                    DepositState::Failed,
                    now_unix(),
                    Some("vault_output_spent"),
                    None,
                )?;
                continue;
            }

            if let Some(cap) = self.config.value_caps.max_deposit_atomic {
                if row.amount_atomic > cap {
                    continue; // over the flat cap; re-evaluated later, never Failed for this alone
                }
            }
            if let Some(window) = self.config.value_caps.rolling_window {
                let since = now_unix() - window.window_seconds as i64;
                let already_ready_sum = self.db.ready_amount_sum_since(since)?;
                if already_ready_sum.saturating_add(row.amount_atomic) > window.cap_atomic {
                    continue; // rolling cap currently full; retried on a later tick
                }
            }

            let message = super::deposit::build_claim_message(
                self.config.protocol_version,
                &self.config.program_id,
                self.config.validator_epoch,
                &row.txid,
                row.vout as u32,
                row.amount_atomic,
                &row.recipient,
                &self.config.wrapped_mint,
            );
            let message_hash: [u8; 32] = Sha256::digest(message).into();
            let artifact = NewClaimArtifact {
                deposit_id: row.id,
                canonical_message: message,
                message_hash,
                protocol_version: self.config.protocol_version,
                validator_epoch: self.config.validator_epoch,
                program_id: self.config.program_id,
                wrapped_mint: self.config.wrapped_mint,
                created_at: now_unix(),
            };
            self.db.transition_state(
                row.id,
                DepositState::ReadyForSignature,
                now_unix(),
                None,
                Some(&artifact),
            )?;
            tracing::info!(
                deposit_id = row.id,
                txid_hex = %row.txid_hex,
                vout = row.vout,
                amount_atomic = row.amount_atomic,
                block_hash = %hex::encode(&row.block_hash),
                message_hash = %hex::encode(&message_hash),
                raw_tx_len = row.raw_tx_hex.len(),
                "deposit ready for signature: unsigned claim artifact produced (not signed or submitted — Phase 5+)"
            );
        }
        Ok(())
    }

    /// Read-only access to the underlying database — for tests
    /// (unit and real-node integration, `tests/regtest_indexer.rs`) and
    /// future read-only observability/reporting surfaces.
    pub fn db(&self) -> &Db {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use crate::glc::config::{RawIndexerConfig, RpcConfig, ValueCaps};
    use crate::glc::rpc::{DecodedScriptPubKey, DecodedVout};

    const VAULT_SCRIPT_HEX: &str = "76a9145a7ab7adf8185c27b3f54104cdccfe1ff0cd54cf88ac";

    /// A tiny in-memory blockchain the mock RPC serves, plus a script to
    /// mutate it mid-test (simulate reorgs, spend outputs).
    #[derive(Default)]
    struct FakeChain {
        blocks: Vec<FakeBlock>,
        txs: HashMap<String, DecodedTransaction>,
        spent: std::collections::HashSet<(String, u32)>,
    }

    struct FakeBlock {
        hash: String,
        prev_hash: Option<String>,
        time: i64,
        tx_ids: Vec<String>,
    }

    struct MockRpc {
        chain: Mutex<FakeChain>,
    }

    impl MockRpc {
        fn new() -> Self {
            MockRpc {
                chain: Mutex::new(FakeChain::default()),
            }
        }

        /// `hash`/`prev` are short human-readable labels (e.g. "h0", "h1")
        /// transformed into valid 64-char hex block hashes internally, so
        /// every RPC method that must round-trip through
        /// `hex::decode_exact` (as the real indexer code does) works
        /// exactly as it would against a live node.
        fn push_block(&self, hash: &str, prev: Option<&str>, txs: Vec<DecodedTransaction>) {
            let mut chain = self.chain.lock().unwrap();
            let mut tx_ids = Vec::new();
            for tx in txs {
                tx_ids.push(tx.txid.clone());
                chain.txs.insert(tx.txid.clone(), tx);
            }
            let time = 1_000 + chain.blocks.len() as i64;
            chain.blocks.push(FakeBlock {
                hash: label_hex(hash),
                prev_hash: prev.map(label_hex),
                time,
                tx_ids,
            });
        }

        /// Pushes a block whose single "transaction" (standing in for a
        /// genesis coinbase) is listed in `getblock`'s `tx` array but
        /// deliberately absent from `chain.txs` — `get_raw_transaction` on
        /// it errors exactly like the real, empirically verified
        /// genesis-coinbase-is-unindexed behavior (docs/goldcoin-rpc-notes.md).
        fn push_block_with_unfetchable_tx(
            &self,
            hash: &str,
            prev: Option<&str>,
            poison_txid_label: &str,
        ) {
            let mut chain = self.chain.lock().unwrap();
            let time = 1_000 + chain.blocks.len() as i64;
            chain.blocks.push(FakeBlock {
                hash: label_hex(hash),
                prev_hash: prev.map(label_hex),
                time,
                tx_ids: vec![label_hex(poison_txid_label)],
            });
        }

        /// `txid_label` is the same short label passed to [`vault_tx`].
        fn spend(&self, txid_label: &str, vout: u32) {
            self.chain
                .lock()
                .unwrap()
                .spent
                .insert((label_hex(txid_label), vout));
        }
    }

    impl GoldcoinRpc for MockRpc {
        async fn get_block_count(&self) -> Result<i64, RpcError> {
            Ok(self.chain.lock().unwrap().blocks.len() as i64 - 1)
        }
        async fn get_block_hash(&self, height: i64) -> Result<String, RpcError> {
            let chain = self.chain.lock().unwrap();
            chain
                .blocks
                .get(height as usize)
                .map(|b| b.hash.clone())
                .ok_or_else(|| RpcError::Method {
                    code: -8,
                    message: "height out of range".into(),
                })
        }
        async fn get_block(&self, hash: &str) -> Result<BlockHeader, RpcError> {
            let chain = self.chain.lock().unwrap();
            let (height, block) = chain
                .blocks
                .iter()
                .enumerate()
                .find(|(_, b)| b.hash == hash)
                .ok_or_else(|| RpcError::Method {
                    code: -5,
                    message: "block not found".into(),
                })?;
            Ok(BlockHeader {
                hash: block.hash.clone(),
                confirmations: 1,
                height: height as i64,
                time: block.time,
                previousblockhash: block.prev_hash.clone(),
                tx: block.tx_ids.clone(),
            })
        }
        async fn get_raw_transaction(
            &self,
            txid_hex: &str,
        ) -> Result<DecodedTransaction, RpcError> {
            self.chain
                .lock()
                .unwrap()
                .txs
                .get(txid_hex)
                .cloned()
                .ok_or_else(|| RpcError::Method {
                    code: -5,
                    message: "tx not found".into(),
                })
        }
        async fn get_raw_transaction_hex(&self, _txid_hex: &str) -> Result<String, RpcError> {
            Ok("deadbeef".to_string())
        }
        async fn get_tx_out_confirmed(
            &self,
            txid_hex: &str,
            vout: u32,
        ) -> Result<Option<TxOut>, RpcError> {
            let chain = self.chain.lock().unwrap();
            if chain.spent.contains(&(txid_hex.to_string(), vout)) {
                return Ok(None);
            }
            Ok(Some(TxOut { confirmations: 1 }))
        }
    }

    /// Lets a test keep a handle to the chain (to grow it / mark outputs
    /// spent between ticks) while an `Arc`-cloned handle is moved into the
    /// `Indexer` itself.
    impl GoldcoinRpc for Arc<MockRpc> {
        async fn get_block_count(&self) -> Result<i64, RpcError> {
            MockRpc::get_block_count(self).await
        }
        async fn get_block_hash(&self, height: i64) -> Result<String, RpcError> {
            MockRpc::get_block_hash(self, height).await
        }
        async fn get_block(&self, hash: &str) -> Result<BlockHeader, RpcError> {
            MockRpc::get_block(self, hash).await
        }
        async fn get_raw_transaction(
            &self,
            txid_hex: &str,
        ) -> Result<DecodedTransaction, RpcError> {
            MockRpc::get_raw_transaction(self, txid_hex).await
        }
        async fn get_raw_transaction_hex(&self, txid_hex: &str) -> Result<String, RpcError> {
            MockRpc::get_raw_transaction_hex(self, txid_hex).await
        }
        async fn get_tx_out_confirmed(
            &self,
            txid_hex: &str,
            vout: u32,
        ) -> Result<Option<TxOut>, RpcError> {
            MockRpc::get_tx_out_confirmed(self, txid_hex, vout).await
        }
    }

    /// Deterministic 32-byte-hex value from a short test label, so mock
    /// txids/block-hashes are realistic, `hex::decode_exact`-compatible
    /// strings without every test spelling out 64 hex chars by hand.
    fn label_hex(label: &str) -> String {
        let mut bytes = [0u8; 32];
        for (i, b) in label.bytes().enumerate().take(32) {
            bytes[i] = b;
        }
        hex::encode(&bytes)
    }

    fn vault_tx(
        txid_label: &str,
        vout_n: u32,
        value: f64,
        recipient: [u8; 32],
    ) -> DecodedTransaction {
        let txid = label_hex(txid_label);
        let mut op_return = vec![0x6a, 32u8];
        op_return.extend_from_slice(&recipient);
        DecodedTransaction {
            txid: txid.to_string(),
            confirmations: Some(1),
            vout: vec![
                DecodedVout {
                    value,
                    n: vout_n,
                    script_pub_key: DecodedScriptPubKey {
                        hex: VAULT_SCRIPT_HEX.to_string(),
                        kind: "pubkeyhash".to_string(),
                    },
                },
                DecodedVout {
                    value: 0.0,
                    n: vout_n + 1,
                    script_pub_key: DecodedScriptPubKey {
                        hex: hex::encode(&op_return),
                        kind: "nulldata".to_string(),
                    },
                },
            ],
        }
    }

    fn test_config(confirmation_depth: u32, max_reorg_depth: u32) -> IndexerConfig {
        IndexerConfig::validate(RawIndexerConfig {
            rpc: RpcConfig {
                url: "http://unused".into(),
                user: "u".into(),
                password: "p".into(),
                connect_timeout_ms: 1000,
                read_timeout_ms: 1000,
            },
            db_path: PathBuf::from(":memory:"),
            vault_script_pubkey_hex: VAULT_SCRIPT_HEX.to_string(),
            confirmation_depth,
            max_reorg_depth,
            min_deposit_atomic: 1_000,
            value_caps: ValueCaps {
                max_deposit_atomic: None,
                rolling_window: None,
            },
            protocol_version: 1,
            program_id_hex: "11".repeat(32),
            validator_epoch: 0,
            wrapped_mint_hex: "22".repeat(32),
            node_unavailable_retry_interval_ms: 100,
            poll_interval_ms: 100,
        })
        .unwrap()
    }

    fn indexer_with(
        chain: MockRpc,
        confirmation_depth: u32,
        max_reorg_depth: u32,
    ) -> Indexer<MockRpc> {
        let db = Db::open(&PathBuf::from(":memory:")).unwrap();
        Indexer::new(chain, db, test_config(confirmation_depth, max_reorg_depth))
    }

    #[tokio::test]
    async fn genesis_block_transactions_are_never_fetched() {
        // Verified empirically against a real Goldcoin Core v0.15.0 node:
        // the genesis coinbase cannot be retrieved via getrawtransaction
        // even with -txindex=1. index_block must skip height 0 entirely
        // rather than attempting (and failing) to fetch it.
        let chain = Arc::new(MockRpc::new());
        chain.push_block_with_unfetchable_tx("h0", None, "poison-coinbase");
        chain.push_block("h1", Some("h0"), vec![vault_tx("t1", 0, 5.0, [0xAB; 32])]);
        let db = Db::open(&PathBuf::from(":memory:")).unwrap();
        let mut idx = Indexer::new(chain, db, test_config(1, 10));

        // Would return Err if index_block tried to fetch the genesis
        // "transaction" (MockRpc::get_raw_transaction errors on unknown ids).
        idx.tick()
            .await
            .expect("genesis must be skipped, not fetched");
        assert_eq!(
            idx.db()
                .candidates_by_state(DepositState::ReadyForSignature)
                .unwrap()
                .len(),
            1,
            "the real deposit at height 1 must still be found"
        );
    }

    #[tokio::test]
    async fn deposit_is_confirming_immediately_after_the_block_that_introduced_it() {
        let chain = Arc::new(MockRpc::new());
        chain.push_block("h0", None, vec![]); // genesis
        chain.push_block("h1", Some("h0"), vec![vault_tx("t1", 0, 5.0, [0xAB; 32])]);
        let db = Db::open(&PathBuf::from(":memory:")).unwrap();
        let mut idx = Indexer::new(chain.clone(), db, test_config(3, 10));

        idx.tick().await.unwrap();
        // Candidate -> Confirming is unconditional and same-tick (state
        // machine spec); nothing observable stays in Candidate afterward.
        assert_eq!(
            idx.db()
                .candidates_by_state(DepositState::Candidate)
                .unwrap()
                .len(),
            0
        );
        let confirming = idx
            .db()
            .candidates_by_state(DepositState::Confirming)
            .unwrap();
        assert_eq!(confirming.len(), 1);
        assert_eq!(confirming[0].amount_atomic, 500_000_000);
        assert_eq!(confirming[0].recipient, [0xAB; 32]);
    }

    #[tokio::test]
    async fn candidate_promotes_through_confirming_to_ready_at_configured_depth() {
        let chain = Arc::new(MockRpc::new());
        chain.push_block("h0", None, vec![]);
        chain.push_block("h1", Some("h0"), vec![vault_tx("t1", 0, 5.0, [0xAB; 32])]);
        let db = Db::open(&PathBuf::from(":memory:")).unwrap();
        let mut idx = Indexer::new(chain.clone(), db, test_config(3, 10));

        idx.tick().await.unwrap(); // depth 1 (the block itself)
        assert!(idx
            .db()
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap()
            .is_empty());

        chain.push_block("h2", Some("h1"), vec![]);
        idx.tick().await.unwrap(); // depth 2 — still below confirmation_depth=3
        assert!(idx
            .db()
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap()
            .is_empty());
        assert_eq!(
            idx.db()
                .candidates_by_state(DepositState::Confirming)
                .unwrap()
                .len(),
            1,
            "must remain Confirming, not silently disappear, while awaiting depth"
        );

        chain.push_block("h3", Some("h2"), vec![]);
        idx.tick().await.unwrap(); // depth 3 == confirmation_depth: promotes
        let ready = idx
            .db()
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap();
        assert_eq!(ready.len(), 1);
        assert!(ready[0].ready_at.is_some());

        // The claim artifact is exactly the shared Phase 3 message format,
        // created atomically with the ReadyForSignature transition, and
        // Phase 4 never signs or submits it (no such code path exists here).
        let (message, program_id_bytes, epoch_bytes): (Vec<u8>, Vec<u8>, Vec<u8>) = idx
            .db()
            .raw()
            .query_row(
                "SELECT canonical_message, program_id, validator_epoch FROM claim_artifacts WHERE deposit_id = ?1",
                rusqlite::params![ready[0].id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let expected = super::super::deposit::build_claim_message(
            1,
            &[0x11; 32],
            0,
            &ready[0].txid,
            ready[0].vout as u32,
            ready[0].amount_atomic,
            &ready[0].recipient,
            &[0x22; 32],
        );
        assert_eq!(message, expected.to_vec());
        assert_eq!(program_id_bytes, vec![0x11u8; 32]);
        assert_eq!(u64::from_le_bytes(epoch_bytes.try_into().unwrap()), 0);
    }

    #[tokio::test]
    async fn vault_output_spent_before_ready_demotes_to_failed() {
        let chain = Arc::new(MockRpc::new());
        chain.push_block("h0", None, vec![]);
        chain.push_block("h1", Some("h0"), vec![vault_tx("t1", 0, 5.0, [0xAB; 32])]);
        let db = Db::open(&PathBuf::from(":memory:")).unwrap();
        let mut idx = Indexer::new(chain.clone(), db, test_config(1, 10));

        // Something (anomalous — not a reorg) spends the vault output
        // before the indexer promotes it.
        chain.spend("t1", 0);
        idx.tick().await.unwrap();

        let failed = idx.db().candidates_by_state(DepositState::Failed).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0].failure_reason.as_deref(),
            Some("vault_output_spent")
        );
        assert!(idx
            .db()
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn deep_reorg_halts_and_makes_no_writes() {
        let chain = MockRpc::new();
        chain.push_block("h0", None, vec![]);
        chain.push_block("h1", Some("h0"), vec![]);
        chain.push_block("h2", Some("h1"), vec![]);
        let mut idx = indexer_with(chain, 1, 1); // max_reorg_depth = 1

        idx.tick().await.unwrap();
        let (tip_before, _) = idx.db().chain_tip().unwrap().unwrap();
        assert_eq!(tip_before, 2);

        // Simulate a reorg deeper than max_reorg_depth=1: replace ALL
        // blocks including height 0? Genesis never changes in practice, so
        // simulate depth-2 reorg by replacing h1 and h2 with different
        // hashes while keeping a DIFFERENT h0 too, forcing the walk-back
        // past what 1 step can resolve.
        // Rebuild the underlying chain from scratch with different hashes
        // at every height including genesis, which is unresolvable within
        // max_reorg_depth=1 from height 2.
        // We access the same MockRpc instance still referenced by `idx`
        // indirectly is not possible (idx owns it); instead construct a
        // fresh Indexer sharing the same Db to simulate "the node's chain
        // changed under us" between ticks.
        let new_chain = MockRpc::new();
        new_chain.push_block("g0", None, vec![]);
        new_chain.push_block("g1", Some("g0"), vec![]);
        new_chain.push_block("g2", Some("g1"), vec![]);
        new_chain.push_block("g3", Some("g2"), vec![]);
        let mut db = Db::open(&PathBuf::from(":memory:")).unwrap();
        // Re-seed db to the same state idx had (tip at height 2, unrelated
        // hashes to new_chain) to simulate the mismatch.
        db.ingest_block(
            &NewBlock {
                height: 0,
                hash: [0u8; 32],
                prev_hash: [0u8; 32],
                block_time: 0,
                indexed_at: 0,
            },
            &[],
        )
        .unwrap();
        db.ingest_block(
            &NewBlock {
                height: 1,
                hash: [1u8; 32],
                prev_hash: [0u8; 32],
                block_time: 0,
                indexed_at: 0,
            },
            &[],
        )
        .unwrap();
        db.ingest_block(
            &NewBlock {
                height: 2,
                hash: [2u8; 32],
                prev_hash: [1u8; 32],
                block_time: 0,
                indexed_at: 0,
            },
            &[],
        )
        .unwrap();
        let mut idx2 = Indexer::new(new_chain, db, test_config(1, 1));
        let outcome = idx2.tick().await.unwrap();
        assert!(matches!(outcome, TickOutcome::Halted { .. }));
        // No writes: tip is still the pre-halt (fabricated) state.
        let (tip_after, _) = idx2.db().chain_tip().unwrap().unwrap();
        assert_eq!(tip_after, 2);

        // Once halted, further ticks immediately report Halted again
        // without touching anything else.
        let outcome2 = idx2.tick().await.unwrap();
        assert!(matches!(outcome2, TickOutcome::Halted { .. }));
    }

    #[tokio::test]
    async fn one_block_reorg_orphans_and_reindexes() {
        let chain = MockRpc::new();
        chain.push_block("h0", None, vec![]);
        chain.push_block("h1", Some("h0"), vec![vault_tx("t1", 0, 5.0, [0xAB; 32])]);
        let db = Db::open(&PathBuf::from(":memory:")).unwrap();
        let mut idx = Indexer::new(chain, db, test_config(1, 5));
        idx.tick().await.unwrap();
        // confirmation_depth=1 and the deposit is already at depth 1 (tip
        // height == its own block height), so in this single tick it
        // advances all the way Candidate -> Confirming -> ReadyForSignature.
        // Rollback must still orphan it regardless of which active state
        // it's in (db.rs's rollback query covers all of them).
        assert_eq!(
            idx.db()
                .candidates_by_state(DepositState::ReadyForSignature)
                .unwrap()
                .len(),
            1
        );

        // Build a fresh mock representing "the node after a 1-block reorg":
        // same genesis, but height 1 replaced by a different block, deposit
        // tx not re-mined.
        let reorged = MockRpc::new();
        reorged.push_block("h0", None, vec![]);
        reorged.push_block("h1b", Some("h0"), vec![]);
        let mut idx2 = Indexer::new(reorged, idx.db, test_config(1, 5));
        let outcome = idx2.tick().await.unwrap();
        match outcome {
            TickOutcome::Progressed { reorg: Some(r), .. } => {
                assert_eq!(r.fork_height, 0);
                assert_eq!(r.orphaned_count, 1);
            }
            other => panic!("expected a detected reorg, got {other:?}"),
        }
        let history = idx2.db().history_for(&decode_txid("t1"), 0).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].state, DepositState::Orphaned);
    }

    fn decode_txid(s: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let b = s.as_bytes();
        bytes[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
        bytes
    }
}
