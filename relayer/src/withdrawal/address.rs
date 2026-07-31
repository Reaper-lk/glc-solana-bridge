//! Base58Check address handling for Goldcoin P2PKH payouts (Phase 6,
//! ADR-0013).
//!
//! Hand-rolled rather than pulling a Bitcoin crate, for the same reason the
//! Goldcoin RPC client is hand-rolled (ADR-0011): Goldcoin is a divergent
//! Litecoin-lineage fork whose version bytes are NOT Bitcoin's. Verified
//! empirically (docs/goldcoin-rpc-notes.md): regtest P2PKH uses a
//! Bitcoin-testnet-style version byte (`m`/`n` prefix), while
//! `createmultisig` P2SH yields a Goldcoin-specific `Q` prefix that matches
//! neither Bitcoin mainnet nor testnet. A crate tuned to Bitcoin's constants
//! would silently mis-decode.
//!
//! Only P2PKH is supported: Phase 4 matches P2PKH vault outputs only (owner
//! decision U5) and the P2SH multisig spend path is unverified
//! (custody.md #2).

use thiserror::Error;

/// The Bitcoin-family base58 alphabet: digits and letters minus the four
/// visually ambiguous characters `0`, `O`, `I`, `l`.
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Regtest/testnet P2PKH version byte, empirically confirmed (`m`/`n`
/// addresses). Mainnet is deliberately absent: Phase 6 is regtest-only.
pub const P2PKH_VERSION_REGTEST: u8 = 0x6f;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("address contains a non-base58 character")]
    InvalidCharacter,
    #[error("address does not decode to 25 bytes (got {0})")]
    WrongLength(usize),
    #[error("address checksum mismatch — the address is corrupt or mistyped")]
    BadChecksum,
    #[error("unsupported address version byte 0x{0:02x}; only regtest P2PKH (0x6f) is supported")]
    UnsupportedVersion(u8),
    #[error("address is empty")]
    Empty,
}

fn base58_decode(s: &str) -> Result<Vec<u8>, AddressError> {
    if s.is_empty() {
        return Err(AddressError::Empty);
    }
    let mut num: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let digit = B58
            .iter()
            .position(|&c| c == ch)
            .ok_or(AddressError::InvalidCharacter)? as u32;
        let mut carry = digit;
        for byte in num.iter_mut().rev() {
            let v = (*byte as u32) * 58 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1's are leading zero bytes.
    let leading_zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; leading_zeros];
    out.extend_from_slice(&num);
    Ok(out)
}

fn base58_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut s = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        s.push('1');
    }
    for d in digits.iter().rev() {
        s.push(B58[*d as usize] as char);
    }
    s
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut c = [0u8; 4];
    c.copy_from_slice(&second[..4]);
    c
}

/// Decodes any base58check address into `(version_byte, 20-byte payload)`.
///
/// Version-agnostic on purpose: P2PKH and P2SH differ only in that byte, and
/// the Phase 7b vault (ADR-0015) needs the P2SH form. Callers decide which
/// versions they accept — this never guesses.
pub fn base58check_decode(addr: &str) -> Result<(u8, [u8; 20]), AddressError> {
    let raw = base58_decode(addr)?;
    if raw.len() != 25 {
        return Err(AddressError::WrongLength(raw.len()));
    }
    let (payload, given) = raw.split_at(21);
    if checksum(payload) != given {
        return Err(AddressError::BadChecksum);
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&payload[1..21]);
    Ok((payload[0], h))
}

/// Encodes `(version, payload)` as a base58check address.
pub fn base58check_encode(version: u8, hash160: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(version);
    payload.extend_from_slice(hash160);
    let c = checksum(&payload);
    payload.extend_from_slice(&c);
    base58_encode(&payload)
}

/// Decodes a regtest P2PKH address to its 20-byte hash160.
///
/// Fails closed on every malformed input: the payout destination comes from
/// user-supplied on-chain bytes and is never guessed at.
pub fn decode_p2pkh_hash160(addr: &str) -> Result<[u8; 20], AddressError> {
    let (version, h) = base58check_decode(addr)?;
    if version != P2PKH_VERSION_REGTEST {
        return Err(AddressError::UnsupportedVersion(version));
    }
    Ok(h)
}

/// Encodes a hash160 back to a regtest P2PKH address (used by tests and by
/// change-address verification).
pub fn encode_p2pkh(hash160: &[u8; 20]) -> String {
    base58check_encode(P2PKH_VERSION_REGTEST, hash160)
}

/// The canonical P2PKH `scriptPubKey` for a hash160:
/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` — the exact 25-byte
/// shape confirmed against a real node in Phase 4.
pub fn p2pkh_script_hex(hash160: &[u8; 20]) -> String {
    format!("76a914{}88ac", crate::glc::hex::encode(hash160))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real regtest address captured from a live Goldcoin node in Phase 4
    /// (docs/goldcoin-rpc-notes.md), with its real scriptPubKey.
    const REAL_ADDR: &str = "mimgHRXobzhMFWkXH46awwtiAQLhKRxxbt";

    #[test]
    fn decodes_and_reencodes_a_real_captured_regtest_address() {
        let h = decode_p2pkh_hash160(REAL_ADDR).unwrap();
        assert_eq!(encode_p2pkh(&h), REAL_ADDR, "round trip must be exact");
        assert_eq!(p2pkh_script_hex(&h).len(), 50, "25-byte script as hex");
        assert!(p2pkh_script_hex(&h).starts_with("76a914"));
        assert!(p2pkh_script_hex(&h).ends_with("88ac"));
    }

    #[test]
    fn script_matches_the_shape_verified_against_a_real_node() {
        // From goldcoin-rpc-notes.md: a real listunspent scriptPubKey.
        let script = "76a914379c580ed8ff3dedd601a5948c11d0a6e10f98dd88ac";
        let h160 = &script[6..46];
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&crate::glc::hex::decode_vec(h160).unwrap());
        assert_eq!(p2pkh_script_hex(&bytes), script);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut bad: Vec<char> = REAL_ADDR.chars().collect();
        // Flip a character in the checksum region.
        let last = bad.len() - 1;
        bad[last] = if bad[last] == 'a' { 'b' } else { 'a' };
        let s: String = bad.into_iter().collect();
        assert_eq!(
            decode_p2pkh_hash160(&s).unwrap_err(),
            AddressError::BadChecksum
        );
    }

    #[test]
    fn rejects_non_base58_characters() {
        assert_eq!(
            decode_p2pkh_hash160("mimgHRXobzhMFWkXH46awwtiAQLhKRxxb0").unwrap_err(),
            AddressError::InvalidCharacter,
            "'0' is not in the base58 alphabet"
        );
    }

    #[test]
    fn rejects_empty_and_short_addresses() {
        assert_eq!(decode_p2pkh_hash160("").unwrap_err(), AddressError::Empty);
        assert!(matches!(
            decode_p2pkh_hash160("1111").unwrap_err(),
            AddressError::WrongLength(_)
        ));
    }

    #[test]
    fn rejects_a_valid_address_of_an_unsupported_version() {
        // Same hash160, Bitcoin-mainnet version byte 0x00 — a well-formed,
        // correctly-checksummed address that must still be refused.
        let h = decode_p2pkh_hash160(REAL_ADDR).unwrap();
        let mut payload = vec![0x00u8];
        payload.extend_from_slice(&h);
        let c = checksum(&payload);
        payload.extend_from_slice(&c);
        let foreign = base58_encode(&payload);
        assert_eq!(
            decode_p2pkh_hash160(&foreign).unwrap_err(),
            AddressError::UnsupportedVersion(0x00)
        );
    }

    #[test]
    fn hash160_round_trips_for_arbitrary_values() {
        for seed in [0u8, 1, 0x7f, 0x80, 0xff] {
            let h = [seed; 20];
            assert_eq!(decode_p2pkh_hash160(&encode_p2pkh(&h)).unwrap(), h);
        }
    }
}
