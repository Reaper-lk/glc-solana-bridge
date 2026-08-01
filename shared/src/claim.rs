//! Canonical federation-signed claim message (ADR-0010).
//!
//! This is THE byte layout validators sign and the on-chain program verifies
//! — the single source of truth for both worlds, which is why it lives in
//! the shared crate. Any change to this layout invalidates every outstanding
//! signature and is a protocol-version event.
//!
//! Layout (166 bytes, all integers little-endian, txid verbatim):
//!
//! | offset | len | field                                   |
//! |--------|-----|-----------------------------------------|
//! | 0      | 16  | domain tag `b"GLC_BRIDGE_CLAIM"`        |
//! | 16     | 1   | protocol version (`u8`)                 |
//! | 17     | 32  | Solana program id                       |
//! | 49     | 8   | validator-set epoch (`u64` LE)          |
//! | 57     | 1   | action type (`ACTION_MINT_DEPOSIT`)     |
//! | 58     | 32  | Goldcoin txid (`[u8; 32]` verbatim)     |
//! | 90     | 4   | vout (`u32` LE)                         |
//! | 94     | 8   | amount, atomic GLC units (`u64` LE)     |
//! | 102    | 32  | Solana recipient pubkey                 |
//! | 134    | 32  | wrapped mint pubkey                     |
//!
//! Domain separation: the tag, program id, protocol version, epoch, and
//! action type together guarantee a signature authorizes exactly one action
//! on one deposit for one recipient/amount, on one deployment, under one
//! validator-set revision. A signature produced for any other bridge,
//! program, epoch, action, or claim field is a different byte string and
//! verifies against nothing here.

/// 16-byte ASCII domain tag; never reused by any other message family.
pub const CLAIM_DOMAIN_TAG: &[u8; 16] = b"GLC_BRIDGE_CLAIM";

/// Action discriminator for deposit-mint claims. Future federation-signed
/// actions (if any) take new values; 0x00 is deliberately never valid.
pub const ACTION_MINT_DEPOSIT: u8 = 0x01;

/// Action discriminator for withdrawal-completion claims (ADR-0018).
///
/// Shares the domain tag and the first 58 bytes of layout with a deposit
/// claim, so this byte at offset 57 is the sole separator between the two
/// families — which is exactly why it is verified rather than assumed. A
/// signature for one action is a different byte string from a signature for
/// the other and verifies against nothing across the boundary.
pub const ACTION_COMPLETE_WITHDRAWAL: u8 = 0x02;

/// Exact length of a deposit-claim message.
pub const CLAIM_MESSAGE_LEN: usize = 166;

/// Exact length of a withdrawal-completion message.
pub const COMPLETION_MESSAGE_LEN: usize = 146;

/// Builds the canonical deposit-claim message. Pure and allocation-free so
/// it is identical under SBF and on the host.
#[allow(clippy::too_many_arguments)]
pub fn deposit_claim_message(
    protocol_version: u8,
    program_id: &[u8; 32],
    epoch: u64,
    txid: &[u8; 32],
    vout: u32,
    amount: u64,
    recipient: &[u8; 32],
    wrapped_mint: &[u8; 32],
) -> [u8; CLAIM_MESSAGE_LEN] {
    let mut m = [0u8; CLAIM_MESSAGE_LEN];
    m[0..16].copy_from_slice(CLAIM_DOMAIN_TAG);
    m[16] = protocol_version;
    m[17..49].copy_from_slice(program_id);
    m[49..57].copy_from_slice(&epoch.to_le_bytes());
    m[57] = ACTION_MINT_DEPOSIT;
    m[58..90].copy_from_slice(txid);
    m[90..94].copy_from_slice(&vout.to_le_bytes());
    m[94..102].copy_from_slice(&amount.to_le_bytes());
    m[102..134].copy_from_slice(recipient);
    m[134..166].copy_from_slice(wrapped_mint);
    m
}

/// Builds the canonical withdrawal-completion message (ADR-0018 D2).
///
/// Layout (134 bytes, all integers little-endian, txid verbatim):
///
/// | offset | len | field                                    |
/// |--------|-----|------------------------------------------|
/// | 0      | 16  | domain tag `b"GLC_BRIDGE_CLAIM"`         |
/// | 16     | 1   | protocol version (`u8`)                  |
/// | 17     | 32  | Solana program id                        |
/// | 49     | 8   | validator-set epoch (`u64` LE)           |
/// | 57     | 1   | action (`ACTION_COMPLETE_WITHDRAWAL`)    |
/// | 58     | 8   | withdrawal index (`u64` LE)              |
/// | 66     | 32  | Goldcoin payout txid (`[u8; 32]`)        |
/// | 98     | 8   | payout block height (`u64` LE)           |
/// | 106    | 8   | amount, atomic GLC units (`u64` LE)      |
/// | 114    | 32  | destination commitment (see below)        |
///
/// # The destination is committed by hash, not decoded
///
/// `dest_commitment` is `sha256` over the withdrawal's Goldcoin address
/// **exactly as stored on-chain** — `glc_address[..glc_address_len]`, the
/// opaque ASCII bytes.
///
/// It is deliberately not the `hash160` the Goldcoin side uses. Producing
/// that on-chain would require base58 decoding and checksum verification
/// inside the program: real code, real risk, and no benefit, since both
/// sides already agree on the stored bytes. Hashing what is stored assumes
/// nothing about address format, so the program never needs to learn one.
///
/// # Why `amount` and the destination are bound
///
/// Without them a signature would authorise "withdrawal N is finished" — an
/// assertion a validator cannot actually verify, because it does not name
/// the payment it refers to. With them a signature authorises completion of
/// **one specific payout, to one specific destination, for one specific
/// amount**, which is a claim a signer can check against its own Goldcoin
/// node before signing (ADR-0018 D6).
///
/// Pure and allocation-free so it is identical under SBF and on the host.
#[allow(clippy::too_many_arguments)]
pub fn withdrawal_completion_message(
    protocol_version: u8,
    program_id: &[u8; 32],
    epoch: u64,
    withdrawal_index: u64,
    payout_txid: &[u8; 32],
    payout_height: u64,
    amount: u64,
    dest_commitment: &[u8; 32],
) -> [u8; COMPLETION_MESSAGE_LEN] {
    let mut m = [0u8; COMPLETION_MESSAGE_LEN];
    m[0..16].copy_from_slice(CLAIM_DOMAIN_TAG);
    m[16] = protocol_version;
    m[17..49].copy_from_slice(program_id);
    m[49..57].copy_from_slice(&epoch.to_le_bytes());
    m[57] = ACTION_COMPLETE_WITHDRAWAL;
    m[58..66].copy_from_slice(&withdrawal_index.to_le_bytes());
    m[66..98].copy_from_slice(payout_txid);
    m[98..106].copy_from_slice(&payout_height.to_le_bytes());
    m[106..114].copy_from_slice(&amount.to_le_bytes());
    m[114..146].copy_from_slice(dest_commitment);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; CLAIM_MESSAGE_LEN] {
        deposit_claim_message(
            1,
            &[0x11; 32],
            0x0102030405060708,
            &[0x22; 32],
            0xAABBCCDD,
            0x1122334455667788,
            &[0x33; 32],
            &[0x44; 32],
        )
    }

    /// Golden vector: pins every byte of the encoding. A change here is a
    /// signature-breaking protocol change and must be deliberate.
    #[test]
    fn golden_vector() {
        let m = sample();
        let mut expected = Vec::with_capacity(CLAIM_MESSAGE_LEN);
        expected.extend_from_slice(b"GLC_BRIDGE_CLAIM");
        expected.push(1);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]); // LE
        expected.push(ACTION_MINT_DEPOSIT);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&[0xDD, 0xCC, 0xBB, 0xAA]); // LE
        expected.extend_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]); // LE
        expected.extend_from_slice(&[0x33; 32]);
        expected.extend_from_slice(&[0x44; 32]);
        assert_eq!(expected.len(), CLAIM_MESSAGE_LEN);
        assert_eq!(m.as_slice(), expected.as_slice());
    }

    #[test]
    fn differing_program_id_changes_exactly_offsets_17_to_49() {
        let a = sample();
        let b = deposit_claim_message(
            1,
            &[0x99; 32], // only the program id differs
            0x0102030405060708,
            &[0x22; 32],
            0xAABBCCDD,
            0x1122334455667788,
            &[0x33; 32],
            &[0x44; 32],
        );
        assert_eq!(a[..17], b[..17]);
        assert_ne!(a[17..49], b[17..49]);
        assert_eq!(a[49..], b[49..]);
    }

    #[test]
    fn differing_epoch_changes_exactly_offsets_49_to_57() {
        let a = sample();
        let b = deposit_claim_message(
            1,
            &[0x11; 32],
            0x0102030405060709, // only the epoch differs
            &[0x22; 32],
            0xAABBCCDD,
            0x1122334455667788,
            &[0x33; 32],
            &[0x44; 32],
        );
        assert_eq!(a[..49], b[..49]);
        assert_ne!(a[49..57], b[49..57]);
        assert_eq!(a[57..], b[57..]);
    }

    #[test]
    fn domain_tag_is_sixteen_bytes_and_stable() {
        assert_eq!(CLAIM_DOMAIN_TAG.len(), 16);
        assert_eq!(&sample()[0..16], b"GLC_BRIDGE_CLAIM");
    }

    // ---------------------------------------------------------------
    // Withdrawal completion (ADR-0018)
    // ---------------------------------------------------------------

    fn completion_sample() -> [u8; COMPLETION_MESSAGE_LEN] {
        withdrawal_completion_message(
            1,
            &[0x11; 32],
            0x0102030405060708,
            0x1122334455667788,
            &[0x55; 32],
            0x00000000DEADBEEF,
            0x0A0B0C0D0E0F1011,
            &[0x66; 32],
        )
    }

    /// Golden vector: pins every byte. A change here invalidates every
    /// outstanding completion signature and must be deliberate.
    #[test]
    fn completion_golden_vector() {
        let m = completion_sample();
        let mut expected = Vec::with_capacity(COMPLETION_MESSAGE_LEN);
        expected.extend_from_slice(b"GLC_BRIDGE_CLAIM");
        expected.push(1);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]); // LE
        expected.push(ACTION_COMPLETE_WITHDRAWAL);
        expected.extend_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]); // LE
        expected.extend_from_slice(&[0x55; 32]);
        expected.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00]); // LE
        expected.extend_from_slice(&[0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A]); // LE
        expected.extend_from_slice(&[0x66; 32]);
        assert_eq!(expected.len(), COMPLETION_MESSAGE_LEN);
        assert_eq!(m.as_slice(), expected.as_slice());
    }

    #[test]
    fn the_action_byte_is_what_separates_the_two_message_families() {
        // The load-bearing property of sharing a domain tag: offset 57 is
        // the sole separator, so a deposit signature can never be replayed
        // as a completion or vice versa.
        let deposit = sample();
        let completion = completion_sample();
        assert_eq!(deposit[57], ACTION_MINT_DEPOSIT);
        assert_eq!(completion[57], ACTION_COMPLETE_WITHDRAWAL);
        assert_ne!(ACTION_MINT_DEPOSIT, ACTION_COMPLETE_WITHDRAWAL);
        assert_ne!(deposit[57], 0x00, "0x00 is never a valid action");
    }

    #[test]
    fn the_two_families_share_their_first_57_bytes_of_layout() {
        // Same tag, version, program id, and epoch — deliberately, so a
        // deployment and a federation revision bind identically for both.
        let deposit = deposit_claim_message(
            1,
            &[0x11; 32],
            0x0102030405060708,
            &[0x22; 32],
            0,
            0,
            &[0x33; 32],
            &[0x44; 32],
        );
        let completion = completion_sample();
        assert_eq!(deposit[..57], completion[..57]);
    }

    #[test]
    fn every_completion_field_changes_only_its_own_bytes() {
        let base = completion_sample();
        let cases: [(&str, [u8; COMPLETION_MESSAGE_LEN], usize, usize); 6] = [
            (
                "epoch",
                withdrawal_completion_message(
                    1,
                    &[0x11; 32],
                    9,
                    0x1122334455667788,
                    &[0x55; 32],
                    0x00000000DEADBEEF,
                    0x0A0B0C0D0E0F1011,
                    &[0x66; 32],
                ),
                49,
                57,
            ),
            (
                "index",
                withdrawal_completion_message(
                    1,
                    &[0x11; 32],
                    0x0102030405060708,
                    9,
                    &[0x55; 32],
                    0x00000000DEADBEEF,
                    0x0A0B0C0D0E0F1011,
                    &[0x66; 32],
                ),
                58,
                66,
            ),
            (
                "payout_txid",
                withdrawal_completion_message(
                    1,
                    &[0x11; 32],
                    0x0102030405060708,
                    0x1122334455667788,
                    &[0x77; 32],
                    0x00000000DEADBEEF,
                    0x0A0B0C0D0E0F1011,
                    &[0x66; 32],
                ),
                66,
                98,
            ),
            (
                "payout_height",
                withdrawal_completion_message(
                    1,
                    &[0x11; 32],
                    0x0102030405060708,
                    0x1122334455667788,
                    &[0x55; 32],
                    9,
                    0x0A0B0C0D0E0F1011,
                    &[0x66; 32],
                ),
                98,
                106,
            ),
            (
                "amount",
                withdrawal_completion_message(
                    1,
                    &[0x11; 32],
                    0x0102030405060708,
                    0x1122334455667788,
                    &[0x55; 32],
                    0x00000000DEADBEEF,
                    9,
                    &[0x66; 32],
                ),
                106,
                114,
            ),
            (
                "dest_commitment",
                withdrawal_completion_message(
                    1,
                    &[0x11; 32],
                    0x0102030405060708,
                    0x1122334455667788,
                    &[0x55; 32],
                    0x00000000DEADBEEF,
                    0x0A0B0C0D0E0F1011,
                    &[0x88; 32],
                ),
                114,
                146,
            ),
        ];
        for (name, other, from, to) in cases {
            assert_eq!(
                base[..from],
                other[..from],
                "{name}: prefix must be unchanged"
            );
            assert_ne!(
                base[from..to],
                other[from..to],
                "{name}: its own bytes must change"
            );
            assert_eq!(base[to..], other[to..], "{name}: suffix must be unchanged");
        }
    }

    #[test]
    fn a_completion_message_is_never_a_prefix_of_a_deposit_claim() {
        // Length alone must not be load-bearing, but it is worth pinning
        // that the two families cannot be confused by truncation.
        let d = sample();
        let c = completion_sample();
        assert_ne!(COMPLETION_MESSAGE_LEN, CLAIM_MESSAGE_LEN);
        assert_ne!(d[..COMPLETION_MESSAGE_LEN], c[..]);
    }
}
