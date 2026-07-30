//! Minimal hex codec shared by config, database, and deposit-extraction
//! code. Hand-rolled rather than a dependency: the surface needed
//! (lowercase encode, exact-length decode) is small enough that a dedicated
//! crate would be pure overhead, and this project already prefers
//! hand-rolled parsers over trusting external shapes it hasn't verified
//! (see the RPC client, `verification.rs` on-chain).

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HexError {
    #[error("hex string has odd length {0}")]
    OddLength(usize),
    #[error("expected {expected} hex chars ({expected_bytes} bytes), got {actual}")]
    WrongLength {
        expected: usize,
        expected_bytes: usize,
        actual: usize,
    },
    #[error("invalid hex digit in {0:?}")]
    InvalidDigit(String),
}

/// Lowercase hex encoding of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decodes `s` into exactly `N` bytes, or a [`HexError`].
pub fn decode_exact<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength(s.len()));
    }
    if s.len() != N * 2 {
        return Err(HexError::WrongLength {
            expected: N * 2,
            expected_bytes: N,
            actual: s.len(),
        });
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let byte_str = &s[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| HexError::InvalidDigit(byte_str.to_string()))?;
    }
    Ok(out)
}

/// Decodes `s` into a `Vec<u8>` of any even length, or a [`HexError`].
pub fn decode_vec(s: &str) -> Result<Vec<u8>, HexError> {
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength(s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte_str = &s[i..i + 2];
        out.push(
            u8::from_str_radix(byte_str, 16)
                .map_err(|_| HexError::InvalidDigit(byte_str.to_string()))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0xAAu8, 0xBB, 0x00, 0xFF];
        let s = encode(&bytes);
        assert_eq!(s, "aabb00ff");
        assert_eq!(decode_exact::<4>(&s).unwrap(), bytes);
    }

    #[test]
    fn lowercase_output_even_for_high_nibbles() {
        assert_eq!(encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn rejects_odd_length() {
        assert_eq!(
            decode_exact::<2>("abc").unwrap_err(),
            HexError::OddLength(3)
        );
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            decode_exact::<32>("aabb").unwrap_err(),
            HexError::WrongLength {
                expected: 64,
                expected_bytes: 32,
                actual: 4,
            }
        );
    }

    #[test]
    fn rejects_invalid_digit() {
        assert!(matches!(
            decode_exact::<1>("zz").unwrap_err(),
            HexError::InvalidDigit(_)
        ));
    }

    #[test]
    fn decode_vec_handles_arbitrary_even_length() {
        assert_eq!(decode_vec("aabbcc").unwrap(), vec![0xaa, 0xbb, 0xcc]);
        assert!(decode_vec("aabbc").is_err());
    }

    #[test]
    fn real_txid_from_regtest_session_round_trips() {
        // Captured against a real Goldcoin Core v0.15.0 regtest node in the
        // Phase 4 design session (see docs/goldcoin-rpc-notes.md): the RPC
        // txid of a broadcast-and-mined deposit transaction, independently
        // verified to equal the byte-reversed double-SHA256 of the raw tx.
        let txid_hex = "4e327700bf5064c1ab0093a6e288edf3e5fb3f7b605ad6f53e4dd18787965bf3";
        assert_eq!(txid_hex.len(), 64, "must be 64 hex chars = 32 bytes");
        let bytes = decode_exact::<32>(txid_hex).unwrap();
        assert_eq!(encode(&bytes), txid_hex);
    }
}
