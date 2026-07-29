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

/// Exact length of a deposit-claim message.
pub const CLAIM_MESSAGE_LEN: usize = 166;

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
}
