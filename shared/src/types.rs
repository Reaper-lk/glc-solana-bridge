//! Core bridge types — Phase 0 skeletons, no serialization derives yet
//! (see Cargo.toml for why).

/// Canonical identity of a Goldcoin deposit.
///
/// A single Goldcoin transaction can pay the vault in several outputs, so the
/// `txid` alone under-identifies a deposit; `(txid, vout)` is unique and
/// L1-derived (unlike a relayer-chosen nonce). This pair is also the seed of
/// the on-chain `DepositClaim` replay-guard PDA.
pub struct DepositId {
    /// Goldcoin transaction id, internal (little-endian) byte order.
    /// Byte-order convention re-confirmed against Goldcoin RPC output in
    /// Phase 2 and recorded in docs/goldcoin-rpc-notes.md.
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
}

/// Claim submitted to `mint_wrapped` after federation signing (Phase 2–3).
///
/// Planned fields: `deposit: DepositId`, `amount: u64` (base units, 8
/// decimals), `recipient: [u8; 32]` (Solana pubkey), plus the aggregated
/// M-of-N federation proof whose exact encoding is Phase 3 work.
pub struct InboundClaim {
    pub deposit: DepositId,
}

/// Lifecycle of a withdrawal record (mirrors on-chain `WithdrawalRequest`).
pub enum WithdrawalStatus {
    /// Burn executed on Solana; GLC payout not yet broadcast.
    Pending,
    /// Payout transaction broadcast to the Goldcoin network.
    Broadcast,
    /// Payout confirmed at the required Goldcoin depth.
    Completed,
}
