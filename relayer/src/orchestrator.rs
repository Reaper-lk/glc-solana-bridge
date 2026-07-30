//! The Phase 5 mint pipeline (ADR-0012): monitors `ReadyForSignature`
//! deposits, signs, aggregates, verifies threshold, submits `mint_wrapped`,
//! and reconciles to `Minted` — tying `glc::db` + `signer` + `solana`
//! together, the Phase 5 counterpart to `glc::indexer`'s tick loop.
//!
//! # Idempotent, restart-safe, retry-safe, never double-mint
//!
//! Every tick, for every `ReadyForSignature` OR `Submitted` deposit, the
//! **first** thing checked is whether the on-chain claim PDA already
//! exists (ADR-0003: its existence IS the mint record, authoritative
//! regardless of which relayer instance submitted it). If it exists, the
//! row is marked `Minted` immediately and nothing else happens for it this
//! tick — this single check is what makes the whole pipeline idempotent,
//! restart-safe, and retry-safe simultaneously: a crash after submission
//! but before confirmation is recovered by simply re-checking next tick; a
//! stale retry can never double-mint because the claim account's `init`
//! constraint makes a second creation attempt fail on-chain regardless of
//! what this relayer believes its own state to be.
//!
//! Only if the claim PDA does NOT yet exist does the pipeline proceed to
//! (re-)sign and (re-)submit — going through the reload-and-recompute
//! safeguard (`Db::verify_and_load_signable_message`) fresh every time.

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use thiserror::Error;

use crate::glc::db::Db;
use crate::glc::db::{DbError, DepositRow, DepositState};
use crate::signer;
use crate::solana::instruction::{self, MintWrappedAccounts};
use crate::solana::rpc::{self, SolanaRpc, SolanaRpcError};

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("Solana node unavailable: {0}")]
    NodeUnavailable(SolanaRpcError),
    #[error("Solana RPC error: {0}")]
    Rpc(SolanaRpcError),
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("the on-chain ValidatorSet account was not found — has the bridge been initialized?")]
    ValidatorSetMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositOutcome {
    /// The claim PDA already existed (or now does after submission);
    /// marked `Minted`.
    Minted,
    /// A mint_wrapped transaction was sent; marked `Submitted`.
    Submitted,
    /// Below threshold this tick — no action, retried next tick.
    InsufficientSignatures,
    /// The reload-and-recompute safeguard detected drift; the deposit was
    /// transitioned to `IntegrityHalted` by the DB layer. Never retried
    /// automatically.
    IntegrityHalted,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TickReport {
    pub minted: u32,
    pub submitted: u32,
    pub insufficient: u32,
    pub halted: u32,
}

/// Retry attempts absorbed per RPC call before bubbling up as
/// `NodeUnavailable` — the inner tier of the two-tier retry policy (mirrors
/// `glc::indexer`'s `INNER_RETRY_ATTEMPTS`).
const INNER_RETRY_ATTEMPTS: u32 = 3;

pub struct Orchestrator<R: SolanaRpc> {
    db: Db,
    rpc: R,
    program_id: Pubkey,
    submitter: Keypair,
    validator_keys: Vec<Keypair>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl<R: SolanaRpc> Orchestrator<R> {
    pub fn new(
        db: Db,
        rpc: R,
        program_id: Pubkey,
        submitter: Keypair,
        validator_keys: Vec<Keypair>,
    ) -> Self {
        Orchestrator {
            db,
            rpc,
            program_id,
            submitter,
            validator_keys,
        }
    }

    // A free function, not a method: closures at call sites need to
    // borrow `self.rpc` while a method call here would need to (re-)borrow
    // all of `self` at the same time — those conflict. Not taking `self`
    // at all sidesteps it, and also keeps this from ever holding a shared
    // `&Orchestrator` across an `.await` (which would require
    // `Orchestrator: Sync`, which it isn't: `rusqlite::Connection`'s
    // statement cache uses a `RefCell`) — `tokio::spawn` requires the
    // whole future to be `Send`.
    async fn call<T, F, Fut>(f: F) -> Result<T, OrchestratorError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, SolanaRpcError>>,
    {
        rpc::call_with_retry(INNER_RETRY_ATTEMPTS, f)
            .await
            .map_err(|e| {
                if e.is_retriable() {
                    OrchestratorError::NodeUnavailable(e)
                } else {
                    OrchestratorError::Rpc(e)
                }
            })
    }

    pub async fn tick(&mut self) -> Result<TickReport, OrchestratorError> {
        let mut rows = self
            .db
            .candidates_by_state(DepositState::ReadyForSignature)?;
        rows.extend(self.db.candidates_by_state(DepositState::Submitted)?);

        let mut report = TickReport::default();
        for row in rows {
            match self.process_one(&row).await? {
                DepositOutcome::Minted => report.minted += 1,
                DepositOutcome::Submitted => report.submitted += 1,
                DepositOutcome::InsufficientSignatures => report.insufficient += 1,
                DepositOutcome::IntegrityHalted => report.halted += 1,
            }
        }
        Ok(report)
    }

    async fn process_one(&mut self, row: &DepositRow) -> Result<DepositOutcome, OrchestratorError> {
        let (claim_pda, _) =
            instruction::deposit_claim_pda(&self.program_id, &row.txid, row.vout as u32);

        // Reconciliation FIRST, always: the claim PDA's existence is
        // authoritative and is checked before any signing/submission is
        // even considered — this is what makes every retry/restart safe.
        if Self::call(|| self.rpc.get_account(&claim_pda))
            .await?
            .is_some()
        {
            self.db.mark_minted(row.id, now_unix())?;
            tracing::info!(deposit_id = row.id, txid_hex = %row.txid_hex, "claim PDA exists on-chain: marked Minted");
            return Ok(DepositOutcome::Minted);
        }

        // Reload-and-recompute safeguard: never sign a cached message.
        let claim = match self.db.verify_and_load_signable_message(row.id, now_unix()) {
            Ok(c) => c,
            Err(DbError::MessageIntegrityMismatch { deposit_id, field }) => {
                tracing::error!(
                    deposit_id,
                    field,
                    "claim message integrity mismatch — halted, NOT signed, NOT submitted; manual investigation required"
                );
                return Ok(DepositOutcome::IntegrityHalted);
            }
            Err(e) => return Err(e.into()),
        };

        // Defense-in-depth: the claim must have been built for THIS
        // deployment, never silently trusted otherwise.
        if claim.program_id != self.program_id.to_bytes() {
            tracing::error!(
                deposit_id = row.id,
                "claim artifact's program_id does not match this orchestrator's configured program_id — refusing to sign"
            );
            return Ok(DepositOutcome::IntegrityHalted);
        }

        let sigs = signer::sign_with_all(&self.validator_keys, &claim.message);

        let (validator_set_pda, _) = instruction::validator_set_pda(&self.program_id);
        let validator_set_account = Self::call(|| self.rpc.get_account(&validator_set_pda))
            .await?
            .ok_or(OrchestratorError::ValidatorSetMissing)?;
        let snapshot = rpc::decode_validator_set(&validator_set_account.data)
            .map_err(OrchestratorError::Rpc)?;

        if signer::aggregate::count_unique_threshold_signers(
            &sigs,
            &snapshot.validators,
            snapshot.threshold,
        )
        .is_err()
        {
            tracing::warn!(
                deposit_id = row.id,
                "insufficient unique validator signatures this tick; retried next tick"
            );
            return Ok(DepositOutcome::InsufficientSignatures);
        }

        let ed25519_ix = signer::aggregate::build_ed25519_instruction(&sigs, &claim.message);

        let (bridge_config, _) = instruction::bridge_config_pda(&self.program_id);
        let (mint_authority, _) = instruction::mint_authority_pda(&self.program_id);
        let recipient = Pubkey::from(claim.recipient);
        let wrapped_mint = Pubkey::from(claim.wrapped_mint);
        let recipient_ata =
            spl_associated_token_account::get_associated_token_address(&recipient, &wrapped_mint);

        let accounts = MintWrappedAccounts {
            submitter: self.submitter.pubkey(),
            bridge_config,
            validator_set: validator_set_pda,
            deposit_claim: claim_pda,
            wrapped_mint,
            mint_authority,
            recipient,
            recipient_token_account: recipient_ata,
        };
        let mint_ix = instruction::mint_wrapped_instruction(
            &self.program_id,
            &accounts,
            claim.txid,
            claim.vout,
            claim.amount_atomic,
            claim.validator_epoch,
        );

        let blockhash = Self::call(|| self.rpc.get_latest_blockhash()).await?;
        let tx = Transaction::new_signed_with_payer(
            &[ed25519_ix, mint_ix],
            Some(&self.submitter.pubkey()),
            &[&self.submitter],
            blockhash,
        );

        let signature = Self::call(|| self.rpc.send_transaction(&tx)).await?;
        self.db
            .mark_submitted(row.id, &signature.to_string(), now_unix())?;
        tracing::info!(
            deposit_id = row.id,
            txid_hex = %row.txid_hex,
            signature = %signature,
            "mint_wrapped submitted"
        );
        Ok(DepositOutcome::Submitted)
    }
}
