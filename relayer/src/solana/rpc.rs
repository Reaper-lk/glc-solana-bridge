//! Thin Solana JSON-RPC client wrapper (Phase 5, ADR-0012).
//!
//! Unlike Goldcoin (ADR-0011), there IS a canonical, well-maintained
//! official Rust client for Solana (`solana-client`) — no reason to
//! hand-roll JSON-RPC here the way the Goldcoin client had to. [`SolanaRpc`]
//! is a thin trait over the exact surface the orchestrator needs, so the
//! orchestration/reconciliation logic is unit-testable against a mock,
//! mirroring `glc::indexer::GoldcoinRpc`'s pattern.

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcSendTransactionConfig;
use solana_sdk::account::Account;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolanaRpcError {
    #[error("transport error contacting Solana RPC: {0}")]
    Transport(String),
    #[error("Solana RPC returned an error: {0}")]
    Method(String),
    #[error("malformed account data: {0}")]
    Malformed(String),
}

impl SolanaRpcError {
    /// Mirrors `glc::rpc::RpcError::is_retriable`'s two-class split: only
    /// transport-level failures are meaningfully retriable.
    pub fn is_retriable(&self) -> bool {
        matches!(self, SolanaRpcError::Transport(_))
    }
}

/// The current on-chain federation, decoded from the raw `ValidatorSet`
/// account (ADR-0007). Used only for the client-side threshold pre-check
/// (`signer::aggregate`) — never to build the signed message itself, which
/// always comes from the frozen `claim_artifacts` commitment (ADR-0012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetSnapshot {
    pub epoch: u64,
    pub threshold: u8,
    pub validators: Vec<Pubkey>,
}

/// Manually decodes a `ValidatorSet` account's Borsh body (ADR-0007 layout:
/// `epoch: u64, threshold: u8, bump: u8, validators: Vec<Pubkey>, reserved:
/// [u8; 32]`), skipping the 8-byte Anchor discriminator. No anchor-lang
/// dependency (owner decision R1) — Borsh's integer/Vec encoding is a fixed,
/// well-known wire format, hand-decoded here exactly like every other
/// account shape this relayer already parses by hand.
pub fn decode_validator_set(data: &[u8]) -> Result<ValidatorSetSnapshot, SolanaRpcError> {
    const DISCRIMINATOR_LEN: usize = 8;
    let body = data
        .get(DISCRIMINATOR_LEN..)
        .ok_or_else(|| SolanaRpcError::Malformed("account shorter than discriminator".into()))?;
    let epoch_bytes = body
        .get(0..8)
        .ok_or_else(|| SolanaRpcError::Malformed("missing epoch".into()))?;
    let epoch = u64::from_le_bytes(epoch_bytes.try_into().unwrap());
    let threshold = *body
        .get(8)
        .ok_or_else(|| SolanaRpcError::Malformed("missing threshold".into()))?;
    // body[9] is `bump` — unused here.
    let vec_len_bytes = body
        .get(10..14)
        .ok_or_else(|| SolanaRpcError::Malformed("missing validators length".into()))?;
    let vec_len = u32::from_le_bytes(vec_len_bytes.try_into().unwrap()) as usize;
    let mut validators = Vec::with_capacity(vec_len);
    let mut offset = 14;
    for _ in 0..vec_len {
        let pk_bytes = body
            .get(offset..offset + 32)
            .ok_or_else(|| SolanaRpcError::Malformed("truncated validators list".into()))?;
        validators.push(Pubkey::try_from(pk_bytes).unwrap());
        offset += 32;
    }
    Ok(ValidatorSetSnapshot {
        epoch,
        threshold,
        validators,
    })
}

/// A queued governance action, decoded from the singleton
/// `PendingGovernanceAction` account (Phase 7a, extended 7h-0).
///
/// Read by `glc-admin` so an operator can see what is pending, and — more
/// importantly — so a **cancellation** derives its parameters from the chain
/// rather than from what the operator remembers. `cancel_params` commits to
/// the exact action and eta being cancelled, and a mistyped eta produces a
/// signature the program rejects after the whole federation has been asked
/// to sign it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingActionSnapshot {
    pub action: u8,
    pub proposed_under_epoch: u64,
    pub eta: i64,
    pub threshold: u8,
    pub validators: Vec<Pubkey>,
    pub proposed_max_wrapped_supply: u64,
}

/// Manually decodes the `PendingGovernanceAction` Borsh body, skipping the
/// 8-byte Anchor discriminator. Layout is a verbatim copy of
/// `programs/glc-bridge/src/state.rs`: `action: u8, proposed_under_epoch:
/// u64, eta: i64, threshold: u8, validators: Vec<Pubkey>, bump: u8,
/// proposed_max_wrapped_supply: u64, reserved: [u8; 24]`.
///
/// Hand-decoded for the same reason `decode_validator_set` is: ADR-0001 and
/// owner decision R1 keep this workspace free of `anchor-lang`.
pub fn decode_pending_action(data: &[u8]) -> Result<PendingActionSnapshot, SolanaRpcError> {
    const DISCRIMINATOR_LEN: usize = 8;
    let body = data
        .get(DISCRIMINATOR_LEN..)
        .ok_or_else(|| SolanaRpcError::Malformed("account shorter than discriminator".into()))?;
    let need = |what: &str| SolanaRpcError::Malformed(format!("pending action: missing {what}"));

    let action = *body.first().ok_or_else(|| need("action"))?;
    let proposed_under_epoch = u64::from_le_bytes(
        body.get(1..9)
            .ok_or_else(|| need("epoch"))?
            .try_into()
            .unwrap(),
    );
    let eta = i64::from_le_bytes(
        body.get(9..17)
            .ok_or_else(|| need("eta"))?
            .try_into()
            .unwrap(),
    );
    let threshold = *body.get(17).ok_or_else(|| need("threshold"))?;
    let vec_len = u32::from_le_bytes(
        body.get(18..22)
            .ok_or_else(|| need("validators length"))?
            .try_into()
            .unwrap(),
    ) as usize;
    // A length prefix read off an account is attacker-influenced only if the
    // account is not the program's own PDA — but it is still bounded here
    // rather than used to reserve memory, because a corrupt account must
    // produce an error, not an allocation.
    let mut validators = Vec::new();
    let mut offset = 22usize;
    for _ in 0..vec_len {
        let pk = body
            .get(offset..offset + 32)
            .ok_or_else(|| need("a validator"))?;
        validators.push(Pubkey::try_from(pk).unwrap());
        offset += 32;
    }
    // Skip `bump`.
    offset += 1;
    let proposed_max_wrapped_supply = u64::from_le_bytes(
        body.get(offset..offset + 8)
            .ok_or_else(|| need("proposed max wrapped supply"))?
            .try_into()
            .unwrap(),
    );

    Ok(PendingActionSnapshot {
        action,
        proposed_under_epoch,
        eta,
        threshold,
        validators,
        proposed_max_wrapped_supply,
    })
}

/// The exact RPC surface the orchestrator needs. A trait so orchestration
/// logic is unit-testable against a mock (mirrors `glc::indexer::GoldcoinRpc`).
pub trait SolanaRpc {
    fn get_account(
        &self,
        pubkey: &Pubkey,
    ) -> impl std::future::Future<Output = Result<Option<Account>, SolanaRpcError>> + Send;
    fn get_latest_blockhash(
        &self,
    ) -> impl std::future::Future<Output = Result<Hash, SolanaRpcError>> + Send;
    fn send_transaction(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Signature, SolanaRpcError>> + Send;

    /// Every account owned by `program_id` whose data is exactly `data_len`
    /// bytes, at the given commitment. Used by the Phase 6 withdrawal
    /// executor to enumerate `WithdrawalRequest` PDAs (ADR-0013).
    ///
    /// The size filter is a cheap server-side narrowing only — it is never
    /// treated as validation. Every returned account still goes through the
    /// full `withdrawal::discovery::decode_withdrawal` checks (owner,
    /// length, PDA re-derivation, canonical bump, address decoding).
    fn get_program_accounts_sized(
        &self,
        program_id: &Pubkey,
        data_len: u64,
        commitment: CommitmentLevel,
    ) -> impl std::future::Future<Output = Result<Vec<(Pubkey, Account)>, SolanaRpcError>> + Send;
}

pub struct RealSolanaRpc {
    client: RpcClient,
    commitment: CommitmentLevel,
}

impl RealSolanaRpc {
    pub fn new(url: String, commitment: CommitmentLevel) -> Self {
        let client = RpcClient::new_with_commitment(url, CommitmentConfig { commitment });
        RealSolanaRpc { client, commitment }
    }
}

impl SolanaRpc for RealSolanaRpc {
    async fn get_account(&self, pubkey: &Pubkey) -> Result<Option<Account>, SolanaRpcError> {
        match self.client.get_account(pubkey).await {
            Ok(acc) => Ok(Some(acc)),
            // The official client surfaces "account not found" as an Err
            // variant, not Ok(None) — normalize it here so callers only
            // ever see "does this account currently exist" as an Option.
            Err(e) if e.to_string().contains("AccountNotFound") => Ok(None),
            Err(e) => Err(classify_client_error(e)),
        }
    }

    async fn get_latest_blockhash(&self) -> Result<Hash, SolanaRpcError> {
        self.client
            .get_latest_blockhash()
            .await
            .map_err(classify_client_error)
    }

    async fn get_program_accounts_sized(
        &self,
        program_id: &Pubkey,
        data_len: u64,
        commitment: CommitmentLevel,
    ) -> Result<Vec<(Pubkey, Account)>, SolanaRpcError> {
        use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
        use solana_client::rpc_filter::RpcFilterType;
        let config = RpcProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::DataSize(data_len)]),
            account_config: RpcAccountInfoConfig {
                // Base64 is mandatory here, not a preference: the node
                // rejects base58 (the default) for accounts over 128 bytes,
                // and a WithdrawalRequest is 180.
                encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
                commitment: Some(CommitmentConfig { commitment }),
                ..Default::default()
            },
            ..Default::default()
        };
        self.client
            .get_program_accounts_with_config(program_id, config)
            .await
            .map_err(classify_client_error)
    }

    async fn send_transaction(&self, tx: &Transaction) -> Result<Signature, SolanaRpcError> {
        self.client
            .send_transaction_with_config(
                tx,
                RpcSendTransactionConfig {
                    skip_preflight: false,
                    preflight_commitment: Some(self.commitment),
                    ..Default::default()
                },
            )
            .await
            .map_err(classify_client_error)
    }
}

fn classify_client_error(e: solana_client::client_error::ClientError) -> SolanaRpcError {
    use solana_client::client_error::ClientErrorKind;
    match e.kind() {
        ClientErrorKind::Io(_) | ClientErrorKind::Reqwest(_) => {
            SolanaRpcError::Transport(e.to_string())
        }
        _ => SolanaRpcError::Method(e.to_string()),
    }
}

/// Bounded exponential-backoff retry for transient transport blips only —
/// mirrors `glc::rpc::call_with_retry`'s two-tier policy exactly (bounded
/// inner retry here; the orchestrator's outer tick-to-tick sleep handles
/// sustained outages).
pub async fn call_with_retry<T, F, Fut>(max_attempts: u32, mut f: F) -> Result<T, SolanaRpcError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, SolanaRpcError>>,
{
    let mut attempt = 0;
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if e.is_retriable() && attempt + 1 < max_attempts => {
                let delay_ms = 200u64 * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `PendingGovernanceAction` body an operator's node would return.
    fn pending_action_bytes(
        action: u8,
        epoch: u64,
        eta: i64,
        threshold: u8,
        validators: &[Pubkey],
        new_max: u64,
    ) -> Vec<u8> {
        let mut d = vec![0u8; 8]; // discriminator
        d.push(action);
        d.extend_from_slice(&epoch.to_le_bytes());
        d.extend_from_slice(&eta.to_le_bytes());
        d.push(threshold);
        d.extend_from_slice(&(validators.len() as u32).to_le_bytes());
        for v in validators {
            d.extend_from_slice(v.as_ref());
        }
        d.push(0xFE); // bump
        d.extend_from_slice(&new_max.to_le_bytes());
        d.extend_from_slice(&[0u8; 24]); // reserved
        d
    }

    #[test]
    fn decodes_a_pending_rotation() {
        let v1 = Pubkey::new_unique();
        let v2 = Pubkey::new_unique();
        let data = pending_action_bytes(0x03, 9, 1_800_000_000, 2, &[v1, v2], 0);
        assert_eq!(
            decode_pending_action(&data).unwrap(),
            PendingActionSnapshot {
                action: 0x03,
                proposed_under_epoch: 9,
                eta: 1_800_000_000,
                threshold: 2,
                validators: vec![v1, v2],
                proposed_max_wrapped_supply: 0,
            }
        );
    }

    #[test]
    fn decodes_a_pending_cap_raise_whose_validator_list_is_empty() {
        // A TVL raise carries no validators, so the u64 that follows sits at
        // a different offset than it does for a rotation. Reading it from a
        // fixed offset would silently return part of the reserved bytes.
        let data = pending_action_bytes(0x05, 4, 123, 0, &[], 21_000_000_000_000);
        let got = decode_pending_action(&data).unwrap();
        assert_eq!(got.action, 0x05);
        assert_eq!(got.proposed_max_wrapped_supply, 21_000_000_000_000);
        assert!(got.validators.is_empty());
    }

    #[test]
    fn the_eta_round_trips_exactly_because_a_cancel_commits_to_it() {
        // `cancel_params(action, eta)` is hashed into the message the whole
        // federation signs. An eta off by one produces a signature the
        // program rejects, after everyone has been asked.
        for eta in [0i64, 1, -1, i64::MIN, i64::MAX, 1_800_000_000] {
            let data = pending_action_bytes(0x03, 1, eta, 1, &[Pubkey::new_unique()], 0);
            assert_eq!(decode_pending_action(&data).unwrap().eta, eta);
        }
    }

    #[test]
    fn a_truncated_pending_action_is_an_error_rather_than_a_guess() {
        let full = pending_action_bytes(0x03, 1, 2, 1, &[Pubkey::new_unique()], 0);
        for cut in [0, 4, 8, 12, 20, 30, 50] {
            assert!(
                decode_pending_action(&full[..cut.min(full.len())]).is_err(),
                "a {cut}-byte account must not decode"
            );
        }
        // And a validator list whose length prefix overruns the account.
        let mut lying = full.clone();
        lying[8 + 18..8 + 22].copy_from_slice(&9_999u32.to_le_bytes());
        assert!(decode_pending_action(&lying).is_err());
    }

    #[test]
    fn decodes_validator_set_account_layout() {
        let v1 = Pubkey::new_unique();
        let v2 = Pubkey::new_unique();
        let mut data = vec![0u8; 8]; // discriminator (contents irrelevant here)
        data.extend_from_slice(&42u64.to_le_bytes()); // epoch
        data.push(2); // threshold
        data.push(0xFF); // bump (unused)
        data.extend_from_slice(&2u32.to_le_bytes()); // vec len
        data.extend_from_slice(v1.as_ref());
        data.extend_from_slice(v2.as_ref());
        data.extend_from_slice(&[0u8; 32]); // reserved

        let snapshot = decode_validator_set(&data).unwrap();
        assert_eq!(snapshot.epoch, 42);
        assert_eq!(snapshot.threshold, 2);
        assert_eq!(snapshot.validators, vec![v1, v2]);
    }

    #[test]
    fn decodes_empty_validator_set_account() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&0u64.to_le_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        let snapshot = decode_validator_set(&data).unwrap();
        assert!(snapshot.validators.is_empty());
    }

    #[test]
    fn rejects_truncated_account_data() {
        let data = vec![0u8; 10];
        assert!(matches!(
            decode_validator_set(&data).unwrap_err(),
            SolanaRpcError::Malformed(_)
        ));
    }

    #[test]
    fn transport_error_is_retriable_method_error_is_not() {
        assert!(SolanaRpcError::Transport("x".into()).is_retriable());
        assert!(!SolanaRpcError::Method("x".into()).is_retriable());
        assert!(!SolanaRpcError::Malformed("x".into()).is_retriable());
    }

    #[tokio::test]
    async fn call_with_retry_retries_transport_and_gives_up_on_method_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        let result: Result<i32, SolanaRpcError> = call_with_retry(3, || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(SolanaRpcError::Transport("blip".into()))
                } else {
                    Ok(7)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        let attempts2 = AtomicU32::new(0);
        let result2: Result<i32, SolanaRpcError> = call_with_retry(5, || {
            attempts2.fetch_add(1, Ordering::SeqCst);
            async move { Err(SolanaRpcError::Method("nope".into())) }
        })
        .await;
        assert!(result2.is_err());
        assert_eq!(attempts2.load(Ordering::SeqCst), 1);
    }
}
