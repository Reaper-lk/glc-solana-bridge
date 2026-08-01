//! Recording completed payouts on Solana (Phase 7f, ADR-0018).
//!
//! A separate service rather than a step inside `WithdrawalExecutor`,
//! because it needs things the executor deliberately does not have: Solana
//! RPC, a fee-paying submitter, and federation signature collection. The
//! same separation the mint orchestrator has from the indexer.
//!
//! # Reconciliation before action, always
//!
//! Every pass, for every locally-completed payout, the **first** thing
//! checked is whether the on-chain account already reads `Completed` — by
//! this relayer or any other. If it does, the local row is marked and
//! nothing else happens. This single check is what makes the service
//! idempotent, restart-safe, and safe to run alongside other operators'
//! relayers: completion is terminal on-chain, so a second attempt would
//! simply fail, and checking first means we do not waste a fee discovering
//! that.
//!
//! It mirrors the mint pipeline's claim-PDA check (ADR-0012) exactly.
//!
//! # Why this is worth doing at all
//!
//! Until a completion is recorded, the only evidence a withdrawal was paid
//! lives in one relayer's database. Afterwards, any operator — including one
//! starting from an empty database — can tell paid from unpaid by reading
//! chain state (ADR-0006, D1).

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::transaction::Transaction;
use thiserror::Error;

use crate::glc::db::Db;
use crate::glc::db::DbError;
use crate::solana::instruction::{
    self, complete_withdrawal_instruction, destination_commitment, CompleteWithdrawalAccounts,
};
use crate::solana::rpc::{self, SolanaRpc, SolanaRpcError};

/// Byte offset of `status` inside a `WithdrawalRequest` account, including
/// the 8-byte Anchor discriminator. Verified against a live account
/// (ADR-0018 §2.2/§2.3) rather than derived from the struct.
const STATUS_OFFSET: usize = 8 + 113;
/// The on-chain `WithdrawalStatus::Completed` discriminant.
pub const STATUS_COMPLETED: u8 = 2;

#[derive(Debug, Error)]
pub enum CompletionError {
    #[error("Solana node unavailable: {0}")]
    NodeUnavailable(SolanaRpcError),
    #[error("Solana RPC error: {0}")]
    Rpc(SolanaRpcError),
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("the on-chain ValidatorSet account was not found — has the bridge been initialized?")]
    ValidatorSetMissing,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CompletionReport {
    /// Observed already complete on-chain (by us or another operator).
    pub reconciled: u32,
    /// A completion transaction was submitted this pass.
    pub submitted: u32,
    /// Below threshold this pass — retried later, never an error.
    pub insufficient: u32,
    /// The local record was inconsistent; skipped and logged.
    pub skipped: u32,
}

/// Collects federation attestations that a withdrawal was paid.
///
/// A trait so the pipeline stays testable without a network, mirroring
/// `SignatureCollector` and `PayoutPartialCollector`.
pub trait CompletionSignatureCollector {
    fn collect_completion_signatures(
        &self,
        epoch: u64,
        withdrawal_index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
        message: &[u8],
    ) -> impl std::future::Future<Output = Vec<(Pubkey, Signature)>> + Send;
}

pub struct CompletionSubmitter<R: SolanaRpc, C: CompletionSignatureCollector> {
    db: Db,
    rpc: R,
    collector: C,
    program_id: Pubkey,
    /// Pays fees only; confers no authority (the federation proof does).
    submitter: Keypair,
    protocol_version: u8,
    epoch: std::sync::Arc<crate::solana::epoch::EpochObservation>,
}

const INNER_RETRY_ATTEMPTS: u32 = 3;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl<R: SolanaRpc, C: CompletionSignatureCollector> CompletionSubmitter<R, C> {
    pub fn new(
        db: Db,
        rpc: R,
        collector: C,
        program_id: Pubkey,
        submitter: Keypair,
        protocol_version: u8,
        epoch: std::sync::Arc<crate::solana::epoch::EpochObservation>,
    ) -> Self {
        CompletionSubmitter {
            db,
            rpc,
            collector,
            program_id,
            submitter,
            protocol_version,
            epoch,
        }
    }

    async fn call<T, F, Fut>(f: F) -> Result<T, CompletionError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, SolanaRpcError>>,
    {
        rpc::call_with_retry(INNER_RETRY_ATTEMPTS, f)
            .await
            .map_err(|e| {
                if e.is_retriable() {
                    CompletionError::NodeUnavailable(e)
                } else {
                    CompletionError::Rpc(e)
                }
            })
    }

    pub async fn tick(&mut self) -> Result<CompletionReport, CompletionError> {
        let pending = self.db.payouts_awaiting_onchain_completion()?;
        let mut report = CompletionReport::default();
        for index in pending {
            self.process_one(index, &mut report).await?;
        }
        Ok(report)
    }

    async fn process_one(
        &mut self,
        index: i64,
        report: &mut CompletionReport,
    ) -> Result<(), CompletionError> {
        let (withdrawal_pda, _) = instruction::withdrawal_pda(&self.program_id, index as u64);

        // Reconciliation FIRST. The on-chain status is authoritative
        // regardless of which operator recorded it.
        let account = Self::call(|| self.rpc.get_account(&withdrawal_pda)).await?;
        let Some(account) = account else {
            tracing::warn!(
                withdrawal_index = index,
                "no on-chain withdrawal account; skipping completion"
            );
            report.skipped += 1;
            return Ok(());
        };
        if account
            .data
            .get(STATUS_OFFSET)
            .is_some_and(|b| *b == STATUS_COMPLETED)
        {
            self.db.record_onchain_completion(index, None, now_unix())?;
            tracing::info!(
                withdrawal_index = index,
                "withdrawal already completed on-chain; recorded locally"
            );
            report.reconciled += 1;
            return Ok(());
        }

        // A relayer whose own view of the validator set has gone stale must
        // not stamp an epoch it cannot currently confirm onto a request.
        if !self.epoch.is_fresh_at(now_unix()) {
            tracing::warn!(
                withdrawal_index = index,
                "validator epoch observation is stale — not requesting completion signatures"
            );
            return Ok(());
        }

        let Some((payout_txid, payout_height, amount, dest_commitment)) =
            self.local_completion_facts(index)?
        else {
            report.skipped += 1;
            return Ok(());
        };

        let epoch = self.epoch.epoch();
        let message = glc_bridge_shared::claim::withdrawal_completion_message(
            self.protocol_version,
            &self.program_id.to_bytes(),
            epoch,
            index as u64,
            &payout_txid,
            payout_height,
            amount,
            &dest_commitment,
        );

        let sigs = self
            .collector
            .collect_completion_signatures(
                epoch,
                index as u64,
                payout_txid,
                payout_height,
                &message,
            )
            .await;

        let (validator_set_pda, _) = instruction::validator_set_pda(&self.program_id);
        let validator_set_account = Self::call(|| self.rpc.get_account(&validator_set_pda))
            .await?
            .ok_or(CompletionError::ValidatorSetMissing)?;
        let snapshot =
            rpc::decode_validator_set(&validator_set_account.data).map_err(CompletionError::Rpc)?;

        if crate::signer::aggregate::count_unique_threshold_signers(
            &sigs,
            &snapshot.validators,
            snapshot.threshold,
        )
        .is_err()
        {
            // Below threshold is NORMAL: peers that have not yet confirmed
            // the payout at depth correctly refuse. Retried next pass.
            tracing::info!(
                withdrawal_index = index,
                collected = sigs.len(),
                threshold = snapshot.threshold,
                "insufficient completion attestations this pass"
            );
            report.insufficient += 1;
            return Ok(());
        }

        let ed25519_ix = crate::signer::aggregate::build_ed25519_instruction(&sigs, &message);
        let (bridge_config, _) = instruction::bridge_config_pda(&self.program_id);
        let complete_ix = complete_withdrawal_instruction(
            &self.program_id,
            &CompleteWithdrawalAccounts {
                submitter: self.submitter.pubkey(),
                bridge_config,
                validator_set: validator_set_pda,
                withdrawal: withdrawal_pda,
            },
            index as u64,
            payout_txid,
            payout_height,
            epoch,
        );

        let blockhash = Self::call(|| self.rpc.get_latest_blockhash()).await?;
        let tx = Transaction::new_signed_with_payer(
            &[ed25519_ix, complete_ix],
            Some(&self.submitter.pubkey()),
            &[&self.submitter],
            blockhash,
        );
        let signature = Self::call(|| self.rpc.send_transaction(&tx)).await?;

        self.db
            .record_onchain_completion(index, Some(&signature.to_string()), now_unix())?;
        tracing::info!(
            withdrawal_index = index,
            %signature,
            "withdrawal completion submitted on-chain"
        );
        report.submitted += 1;
        Ok(())
    }

    /// The facts this relayer will ask the federation to attest, drawn
    /// entirely from its own database.
    #[allow(clippy::type_complexity)]
    fn local_completion_facts(
        &self,
        index: i64,
    ) -> Result<Option<([u8; 32], u64, u64, [u8; 32])>, CompletionError> {
        let Some(w) = self.db.get_withdrawal(index)? else {
            return Ok(None);
        };
        let Some(p) = self.db.get_payout(index)? else {
            return Ok(None);
        };
        let Some(txid_hex) = p.txid_hex else {
            tracing::warn!(
                withdrawal_index = index,
                "completed payout has no txid; cannot request completion"
            );
            return Ok(None);
        };
        let Ok(mut txid) = crate::glc::hex::decode_exact::<32>(&txid_hex) else {
            tracing::warn!(withdrawal_index = index, "payout txid is not 32 hex bytes");
            return Ok(None);
        };
        // Stored display-order (reversed); the canonical message uses
        // internal byte order, as the deposit claim does.
        txid.reverse();

        let Some(height) = p.mined_height else {
            tracing::warn!(
                withdrawal_index = index,
                "completed payout has no mined height; cannot request completion"
            );
            return Ok(None);
        };

        Ok(Some((
            txid,
            height as u64,
            w.amount_atomic,
            destination_commitment(w.glc_address.as_bytes()),
        )))
    }
}
