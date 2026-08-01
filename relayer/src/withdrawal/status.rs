//! Reading a withdrawal's on-chain status (Phase 7g, ADR-0019 D4).
//!
//! The concrete [`OnChainWithdrawalStatus`] the executor consults
//! immediately before broadcasting. Phase 7g measured two operators paying
//! the same withdrawal twice with nothing in the executor to stop it
//! (ADR-0019 §2.2); this closes that gap in the process that would otherwise
//! cause the harm.
//!
//! It is **defence in depth, not the primary protection** — Phase 7e's
//! signer check remains that — and it cannot catch a payment made but not
//! yet completed on-chain.

use solana_sdk::pubkey::Pubkey;

use crate::solana::instruction;
use crate::solana::rpc::SolanaRpc;
use crate::withdrawal::completion::STATUS_COMPLETED;
use crate::withdrawal::executor::OnChainWithdrawalStatus;

/// Byte offset of `status` inside a `WithdrawalRequest` account, including
/// the 8-byte Anchor discriminator. Verified against a live account
/// (ADR-0018 §2.2/§2.3).
const STATUS_OFFSET: usize = 8 + 113;

pub struct SolanaWithdrawalStatus<R: SolanaRpc> {
    rpc: R,
    program_id: Pubkey,
}

impl<R: SolanaRpc> SolanaWithdrawalStatus<R> {
    pub fn new(rpc: R, program_id: Pubkey) -> Self {
        SolanaWithdrawalStatus { rpc, program_id }
    }
}

#[tonic::async_trait]
impl<R: SolanaRpc + Send + Sync + 'static> OnChainWithdrawalStatus for SolanaWithdrawalStatus<R> {
    async fn is_completed(&self, withdrawal_index: u64) -> Result<bool, String> {
        let (pda, _) = instruction::withdrawal_pda(&self.program_id, withdrawal_index);
        let account = self
            .rpc
            .get_account(&pda)
            .await
            .map_err(|e| e.to_string())?;
        // A missing account is NOT "not completed" — it is a state this
        // relayer cannot explain, and the caller treats any error as a
        // reason to wait rather than permission to broadcast.
        let account = account
            .ok_or_else(|| format!("no on-chain account for withdrawal {withdrawal_index}"))?;
        let status = account
            .data
            .get(STATUS_OFFSET)
            .copied()
            .ok_or_else(|| "withdrawal account is too short to carry a status".to_string())?;
        Ok(status == STATUS_COMPLETED)
    }
}
