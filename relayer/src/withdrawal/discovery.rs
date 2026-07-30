//! Discovery and validation of on-chain `WithdrawalRequest` accounts
//! (Phase 6, ADR-0013).
//!
//! Accounts are the source of truth, never events (ADR-0006): scanning
//! program accounts is fully recoverable after arbitrary downtime, whereas
//! log subscriptions are best-effort and age out.
//!
//! Discovery runs at **finalized** commitment only (owner decision D5) — a
//! payout must never be built from a burn that could still be rolled back.

use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

use super::address::{decode_p2pkh_hash160, AddressError};

/// Verbatim copy of `programs/glc-bridge/src/constants.rs`. Same rationale
/// as `solana::instruction`: the relayer deliberately does not depend on the
/// on-chain crate (owner decision R1), so this is the one place the copy
/// must be kept in sync.
pub const SEED_WITHDRAWAL: &[u8] = b"withdrawal";

/// `WithdrawalRequest` borsh body layout, after the 8-byte Anchor
/// discriminator (`programs/glc-bridge/src/state.rs`):
///
/// | offset | len | field |
/// |--------|-----|-------|
/// | 0      | 8   | index (u64 LE) |
/// | 8      | 8   | amount (u64 LE) |
/// | 16     | 32  | requester |
/// | 48     | 64  | glc_address (zero-padded ASCII) |
/// | 112    | 1   | glc_address_len |
/// | 113    | 1   | status |
/// | 114    | 8   | requested_at_slot (u64 LE) |
/// | 122    | 1   | protocol_version |
/// | 123    | 1   | bump |
/// | 124    | 48  | reserved |
///
/// Total 172 body + 8 discriminator = 180 = `WithdrawalRequest::SPACE`.
pub const WITHDRAWAL_ACCOUNT_LEN: usize = 180;
const DISCRIMINATOR_LEN: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("account data is {0} bytes, expected {WITHDRAWAL_ACCOUNT_LEN}")]
    WrongLength(usize),
    #[error("account is owned by {owner}, not the bridge program {expected}")]
    WrongOwner { owner: Pubkey, expected: Pubkey },
    #[error(
        "account address {actual} does not match the PDA {expected} derived from index {index} — \
         refusing to treat it as a withdrawal"
    )]
    PdaMismatch {
        actual: Pubkey,
        expected: Pubkey,
        index: u64,
    },
    #[error("stored bump {stored} does not match the canonical bump {canonical}")]
    BumpMismatch { stored: u8, canonical: u8 },
    #[error("glc_address_len {0} is outside 1..=64")]
    AddressLengthOutOfRange(u8),
    #[error("glc_address is not valid ASCII")]
    NonAsciiAddress,
    #[error("glc_address padding beyond glc_address_len is not zeroed")]
    NonZeroAddressPadding,
    #[error("destination address is unusable: {0}")]
    UnusableAddress(#[from] AddressError),
    #[error("withdrawal amount is zero")]
    ZeroAmount,
}

/// A validated, decoded withdrawal request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedWithdrawal {
    pub index: u64,
    pub pda: Pubkey,
    pub amount_atomic: u64,
    pub requester: Pubkey,
    pub glc_address: String,
    pub glc_address_hash160: [u8; 20],
    pub requested_at_slot: u64,
    pub protocol_version: u8,
    pub status_tag: u8,
}

pub fn withdrawal_pda(program_id: &Pubkey, index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_WITHDRAWAL, &index.to_le_bytes()], program_id)
}

/// Decodes and fully validates one `WithdrawalRequest` account.
///
/// Validation is deliberately exhaustive and fails closed. Nothing about a
/// payout destination or amount is ever inferred, defaulted, or repaired: a
/// malformed account is either a program bug or an attack, and in both cases
/// the only safe action is to refuse it.
pub fn decode_withdrawal(
    program_id: &Pubkey,
    address: &Pubkey,
    owner: &Pubkey,
    data: &[u8],
) -> Result<DecodedWithdrawal, DiscoveryError> {
    if owner != program_id {
        return Err(DiscoveryError::WrongOwner {
            owner: *owner,
            expected: *program_id,
        });
    }
    if data.len() != WITHDRAWAL_ACCOUNT_LEN {
        return Err(DiscoveryError::WrongLength(data.len()));
    }
    let body = &data[DISCRIMINATOR_LEN..];

    let index = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let amount_atomic = u64::from_le_bytes(body[8..16].try_into().unwrap());
    let requester = Pubkey::try_from(&body[16..48]).unwrap();
    let addr_bytes = &body[48..112];
    let addr_len = body[112];
    let status_tag = body[113];
    let requested_at_slot = u64::from_le_bytes(body[114..122].try_into().unwrap());
    let protocol_version = body[122];
    let stored_bump = body[123];

    // The account's address must be exactly the PDA its own index derives.
    // Without this, any account the attacker can create and fund could
    // masquerade as a payout obligation.
    let (expected_pda, canonical_bump) = withdrawal_pda(program_id, index);
    if *address != expected_pda {
        return Err(DiscoveryError::PdaMismatch {
            actual: *address,
            expected: expected_pda,
            index,
        });
    }
    if stored_bump != canonical_bump {
        return Err(DiscoveryError::BumpMismatch {
            stored: stored_bump,
            canonical: canonical_bump,
        });
    }
    if amount_atomic == 0 {
        return Err(DiscoveryError::ZeroAmount);
    }
    if addr_len == 0 || addr_len as usize > 64 {
        return Err(DiscoveryError::AddressLengthOutOfRange(addr_len));
    }
    let used = &addr_bytes[..addr_len as usize];
    if !used.is_ascii() {
        return Err(DiscoveryError::NonAsciiAddress);
    }
    // Padding must be zeroed: a non-zero tail means the account is not the
    // shape burn_wrapped produces.
    if addr_bytes[addr_len as usize..].iter().any(|&b| b != 0) {
        return Err(DiscoveryError::NonZeroAddressPadding);
    }
    let glc_address =
        String::from_utf8(used.to_vec()).map_err(|_| DiscoveryError::NonAsciiAddress)?;
    let glc_address_hash160 = decode_p2pkh_hash160(&glc_address)?;

    Ok(DecodedWithdrawal {
        index,
        pda: *address,
        amount_atomic,
        requester,
        glc_address,
        glc_address_hash160,
        requested_at_slot,
        protocol_version,
        status_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::address::encode_p2pkh;

    fn build_account(
        program_id: &Pubkey,
        index: u64,
        amount: u64,
        addr: &str,
    ) -> (Pubkey, Vec<u8>) {
        let (pda, bump) = withdrawal_pda(program_id, index);
        let mut d = vec![0u8; WITHDRAWAL_ACCOUNT_LEN];
        d[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // discriminator
        let b = &mut d[8..];
        b[0..8].copy_from_slice(&index.to_le_bytes());
        b[8..16].copy_from_slice(&amount.to_le_bytes());
        b[16..48].copy_from_slice(Pubkey::new_unique().as_ref());
        b[48..48 + addr.len()].copy_from_slice(addr.as_bytes());
        b[112] = addr.len() as u8;
        b[113] = 0; // Pending
        b[114..122].copy_from_slice(&42u64.to_le_bytes());
        b[122] = 1;
        b[123] = bump;
        (pda, d)
    }

    fn addr() -> String {
        encode_p2pkh(&[0xAB; 20])
    }

    #[test]
    fn decodes_a_well_formed_account() {
        let pid = Pubkey::new_unique();
        let (pda, data) = build_account(&pid, 7, 500_000, &addr());
        let w = decode_withdrawal(&pid, &pda, &pid, &data).unwrap();
        assert_eq!(w.index, 7);
        assert_eq!(w.amount_atomic, 500_000);
        assert_eq!(w.glc_address, addr());
        assert_eq!(w.glc_address_hash160, [0xAB; 20]);
        assert_eq!(w.requested_at_slot, 42);
        assert_eq!(w.protocol_version, 1);
    }

    #[test]
    fn layout_offsets_match_the_onchain_space_constant() {
        assert_eq!(WITHDRAWAL_ACCOUNT_LEN, 180, "WithdrawalRequest::SPACE");
        assert_eq!(DISCRIMINATOR_LEN + 172, WITHDRAWAL_ACCOUNT_LEN);
    }

    #[test]
    fn rejects_wrong_owner() {
        let pid = Pubkey::new_unique();
        let (pda, data) = build_account(&pid, 1, 100, &addr());
        let attacker = Pubkey::new_unique();
        assert!(matches!(
            decode_withdrawal(&pid, &pda, &attacker, &data).unwrap_err(),
            DiscoveryError::WrongOwner { .. }
        ));
    }

    #[test]
    fn rejects_an_account_whose_address_is_not_its_own_pda() {
        let pid = Pubkey::new_unique();
        let (_pda, data) = build_account(&pid, 1, 100, &addr());
        let impostor = Pubkey::new_unique();
        assert!(matches!(
            decode_withdrawal(&pid, &impostor, &pid, &data).unwrap_err(),
            DiscoveryError::PdaMismatch { .. }
        ));
    }

    #[test]
    fn rejects_a_tampered_index_because_the_pda_no_longer_derives() {
        let pid = Pubkey::new_unique();
        let (pda, mut data) = build_account(&pid, 5, 100, &addr());
        data[8..16].copy_from_slice(&9u64.to_le_bytes()); // index 5 -> 9
        assert!(matches!(
            decode_withdrawal(&pid, &pda, &pid, &data).unwrap_err(),
            DiscoveryError::PdaMismatch { .. }
        ));
    }

    #[test]
    fn rejects_wrong_length_and_zero_amount() {
        let pid = Pubkey::new_unique();
        let (pda, data) = build_account(&pid, 1, 100, &addr());
        assert!(matches!(
            decode_withdrawal(&pid, &pda, &pid, &data[..170]).unwrap_err(),
            DiscoveryError::WrongLength(170)
        ));

        let (pda0, d0) = build_account(&pid, 2, 0, &addr());
        assert_eq!(
            decode_withdrawal(&pid, &pda0, &pid, &d0).unwrap_err(),
            DiscoveryError::ZeroAmount
        );
    }

    #[test]
    fn rejects_bad_address_length_and_non_zero_padding() {
        let pid = Pubkey::new_unique();
        let (pda, mut data) = build_account(&pid, 1, 100, &addr());
        data[8 + 112] = 0;
        assert_eq!(
            decode_withdrawal(&pid, &pda, &pid, &data).unwrap_err(),
            DiscoveryError::AddressLengthOutOfRange(0)
        );

        let (pda2, mut d2) = build_account(&pid, 1, 100, &addr());
        let len = addr().len();
        d2[8 + 48 + len] = 0xFF; // dirty padding byte
        assert_eq!(
            decode_withdrawal(&pid, &pda2, &pid, &d2).unwrap_err(),
            DiscoveryError::NonZeroAddressPadding
        );
    }

    #[test]
    fn rejects_an_undecodable_destination_address() {
        let pid = Pubkey::new_unique();
        let (pda, data) = build_account(&pid, 1, 100, "not-a-valid-address");
        assert!(matches!(
            decode_withdrawal(&pid, &pda, &pid, &data).unwrap_err(),
            DiscoveryError::UnusableAddress(_)
        ));
    }

    #[test]
    fn rejects_a_tampered_bump() {
        let pid = Pubkey::new_unique();
        let (pda, mut data) = build_account(&pid, 3, 100, &addr());
        data[8 + 123] = data[8 + 123].wrapping_add(1);
        assert!(matches!(
            decode_withdrawal(&pid, &pda, &pid, &data).unwrap_err(),
            DiscoveryError::BumpMismatch { .. }
        ));
    }
}
