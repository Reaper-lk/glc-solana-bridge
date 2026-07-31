//! P2SH M-of-N multisig vault construction and validation (Phase 7b,
//! ADR-0015).
//!
//! Every fact encoded here was verified against a real Goldcoin v0.15.0
//! regtest node, not inferred from Bitcoin (`goldcoin-rpc-notes.md`): the
//! `Q`-prefixed P2SH version byte, the redeem-script layout `createmultisig`
//! produces, and the fact that a partial signature is rejected by the
//! network until a full quorum signs.
//!
//! The vault's P2SH address is always **re-derived from the redeem script**
//! rather than trusted from configuration. A mismatch between the two is an
//! operator error that would otherwise send funds somewhere unrecoverable.

use thiserror::Error;

use super::address::{base58check_decode, base58check_encode};
use crate::glc::hex;

/// Goldcoin's P2SH version byte, **derived from a real `createmultisig`
/// address**, not assumed: `0x3a` (58), which renders as a `Q` prefix.
///
/// This is unrelated to Bitcoin mainnet's `0x05` (`3`) or testnet's `0xc4`
/// (`2`), and is not guessable from the prefix character alone — an earlier
/// draft of this module guessed `0x1c` and produced `C`-prefixed addresses
/// that would have sent vault funds to an address nobody controls. The
/// golden-vector test below pins it against the address a real node
/// produced.
pub const P2SH_VERSION_REGTEST: u8 = 0x3a;

/// Compressed SEC1 public key length. Uncompressed keys are rejected: they
/// change the redeem script and therefore the vault address, and mixing the
/// two forms is a classic way to derive the wrong vault.
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Hard cap on N, mirroring the on-chain `MAX_VALIDATORS`. A redeem script
/// is also bounded by consensus limits well below this.
pub const MAX_VAULT_SIGNERS: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("threshold M must be at least 1")]
    ZeroThreshold,
    #[error("threshold M ({m}) exceeds the number of signers N ({n})")]
    ThresholdExceedsSigners { m: usize, n: usize },
    #[error("vault must have at least one signer")]
    NoSigners,
    #[error("vault has {0} signers, exceeding the maximum of {MAX_VAULT_SIGNERS}")]
    TooManySigners(usize),
    #[error(
        "signer {index} public key is {len} bytes; only 33-byte compressed keys are supported"
    )]
    UncompressedPubkey { index: usize, len: usize },
    #[error("signer {index} public key has invalid prefix 0x{prefix:02x}; expected 0x02 or 0x03")]
    BadPubkeyPrefix { index: usize, prefix: u8 },
    #[error("duplicate signer public key at index {0}")]
    DuplicateSigner(usize),
    #[error("redeem script is malformed: {0}")]
    MalformedRedeemScript(&'static str),
    #[error(
        "configured vault address {configured} does not match the address derived from the \
         redeem script ({derived}) — refusing to use a vault whose script and address disagree"
    )]
    AddressMismatch { configured: String, derived: String },
}

/// A validated P2SH M-of-N vault descriptor.
///
/// Signer **order is significant**: it is the order inside the redeem
/// script, it determines the address, and it is what a quorum index in a
/// payout intent refers to (ADR-0015 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigVault {
    pub threshold: usize,
    pub signer_pubkeys: Vec<[u8; COMPRESSED_PUBKEY_LEN]>,
    pub redeem_script: Vec<u8>,
    pub script_hash160: [u8; 20],
    pub address: String,
}

fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// `OP_1`..`OP_16` for a small integer.
fn op_n(n: usize) -> u8 {
    0x50 + n as u8
}

impl MultisigVault {
    /// Builds and validates a vault from its threshold and ordered signer
    /// keys, deriving the redeem script and P2SH address exactly as
    /// `createmultisig` does.
    pub fn new(
        threshold: usize,
        signer_pubkeys: Vec<[u8; COMPRESSED_PUBKEY_LEN]>,
    ) -> Result<Self, VaultError> {
        if signer_pubkeys.is_empty() {
            return Err(VaultError::NoSigners);
        }
        if signer_pubkeys.len() > MAX_VAULT_SIGNERS {
            return Err(VaultError::TooManySigners(signer_pubkeys.len()));
        }
        if threshold == 0 {
            return Err(VaultError::ZeroThreshold);
        }
        if threshold > signer_pubkeys.len() {
            return Err(VaultError::ThresholdExceedsSigners {
                m: threshold,
                n: signer_pubkeys.len(),
            });
        }
        for (i, pk) in signer_pubkeys.iter().enumerate() {
            // Only compressed keys: an uncompressed key would silently
            // produce a different script and therefore a different vault.
            if pk[0] != 0x02 && pk[0] != 0x03 {
                return Err(VaultError::BadPubkeyPrefix {
                    index: i,
                    prefix: pk[0],
                });
            }
            if signer_pubkeys[..i].contains(pk) {
                return Err(VaultError::DuplicateSigner(i));
            }
        }

        // OP_M <33-byte push> * N OP_N OP_CHECKMULTISIG
        let mut redeem_script = Vec::with_capacity(3 + signer_pubkeys.len() * 34);
        redeem_script.push(op_n(threshold));
        for pk in &signer_pubkeys {
            redeem_script.push(COMPRESSED_PUBKEY_LEN as u8);
            redeem_script.extend_from_slice(pk);
        }
        redeem_script.push(op_n(signer_pubkeys.len()));
        redeem_script.push(0xae); // OP_CHECKMULTISIG

        let script_hash160 = hash160(&redeem_script);
        let address = base58check_encode(P2SH_VERSION_REGTEST, &script_hash160);

        Ok(MultisigVault {
            threshold,
            signer_pubkeys,
            redeem_script,
            script_hash160,
            address,
        })
    }

    /// Parses a hex redeem script (as returned by `createmultisig`) and
    /// rebuilds the vault, re-deriving the address rather than trusting one.
    pub fn from_redeem_script_hex(script_hex: &str) -> Result<Self, VaultError> {
        let script = hex::decode_vec(script_hex)
            .map_err(|_| VaultError::MalformedRedeemScript("not valid hex"))?;
        if script.len() < 3 {
            return Err(VaultError::MalformedRedeemScript("too short"));
        }
        if *script.last().unwrap() != 0xae {
            return Err(VaultError::MalformedRedeemScript(
                "does not end in OP_CHECKMULTISIG",
            ));
        }
        let m = script[0]
            .checked_sub(0x50)
            .ok_or(VaultError::MalformedRedeemScript(
                "leading opcode is not OP_1..OP_16",
            ))? as usize;
        let n =
            script[script.len() - 2]
                .checked_sub(0x50)
                .ok_or(VaultError::MalformedRedeemScript(
                    "signer count opcode is not OP_1..OP_16",
                ))? as usize;
        if m == 0 || n == 0 || m > 16 || n > 16 {
            return Err(VaultError::MalformedRedeemScript("M or N out of range"));
        }

        let mut keys = Vec::with_capacity(n);
        let mut i = 1usize;
        let body_end = script.len() - 2;
        while i < body_end {
            let len = script[i] as usize;
            if len != COMPRESSED_PUBKEY_LEN {
                return Err(VaultError::MalformedRedeemScript(
                    "expected a 33-byte compressed pubkey push",
                ));
            }
            let start = i + 1;
            let end = start
                .checked_add(COMPRESSED_PUBKEY_LEN)
                .ok_or(VaultError::MalformedRedeemScript("length overflow"))?;
            if end > body_end {
                return Err(VaultError::MalformedRedeemScript(
                    "pubkey push runs past the script",
                ));
            }
            let mut pk = [0u8; COMPRESSED_PUBKEY_LEN];
            pk.copy_from_slice(&script[start..end]);
            keys.push(pk);
            i = end;
        }
        if keys.len() != n {
            return Err(VaultError::MalformedRedeemScript(
                "declared signer count does not match the number of pubkeys",
            ));
        }
        Self::new(m, keys)
    }

    /// Confirms an operator-configured address matches the one this script
    /// actually derives. Guards against a transposed or stale address in
    /// configuration sending funds somewhere unrecoverable.
    pub fn require_address(&self, configured: &str) -> Result<(), VaultError> {
        if configured != self.address {
            return Err(VaultError::AddressMismatch {
                configured: configured.to_string(),
                derived: self.address.clone(),
            });
        }
        Ok(())
    }

    /// The `scriptPubKey` a vault output carries: `OP_HASH160 <20> OP_EQUAL`.
    pub fn script_pubkey_hex(&self) -> String {
        format!("a914{}87", hex::encode(&self.script_hash160))
    }

    pub fn redeem_script_hex(&self) -> String {
        hex::encode(&self.redeem_script)
    }

    pub fn signer_count(&self) -> usize {
        self.signer_pubkeys.len()
    }

    /// Validates a designated quorum against this vault: exactly `threshold`
    /// signers, all in range, no duplicates, in ascending order.
    ///
    /// Ascending order is required so a quorum has exactly one canonical
    /// encoding — otherwise the same set of signers could produce several
    /// different intent commitments (ADR-0015 §2).
    pub fn validate_quorum(&self, indices: &[u8]) -> Result<(), VaultError> {
        if indices.len() != self.threshold {
            return Err(VaultError::ThresholdExceedsSigners {
                m: indices.len(),
                n: self.threshold,
            });
        }
        let mut last: Option<u8> = None;
        for &i in indices {
            if i as usize >= self.signer_count() {
                return Err(VaultError::MalformedRedeemScript(
                    "quorum index is outside the signer set",
                ));
            }
            match last {
                Some(prev) if i <= prev => {
                    return Err(VaultError::MalformedRedeemScript(
                        "quorum indices must be strictly ascending and unique",
                    ))
                }
                _ => last = Some(i),
            }
        }
        Ok(())
    }
}

/// Decodes a `Q`-prefixed P2SH address to its script hash160.
pub fn decode_p2sh_hash160(addr: &str) -> Result<[u8; 20], super::address::AddressError> {
    let (version, payload) = base58check_decode(addr)?;
    if version != P2SH_VERSION_REGTEST {
        return Err(super::address::AddressError::UnsupportedVersion(version));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact 2-of-3 vault produced by `createmultisig` on a real regtest
    /// node during Phase 7b verification. This is a golden vector: if our
    /// derivation ever diverges from the node's, this test fails.
    const REAL_REDEEM_SCRIPT: &str = "5221028e7147e643d67093dc8ca6a8fb888f1a452dddc62de991c7ed72080d65a421e42102f1c88ca7176c3ffee952ee6fae697991b257b6d53c3bc88e81cfe99adbcdbee5210256220bb7865197a40c4590ac80f12ef18e9063eac2eff92c4476ec27034042f953ae";
    const REAL_ADDRESS: &str = "QY9YcpypWD91BEZ37TjNHYoqrquhcnVBYV";

    #[test]
    fn derives_the_exact_address_a_real_node_produced() {
        let v = MultisigVault::from_redeem_script_hex(REAL_REDEEM_SCRIPT).unwrap();
        assert_eq!(v.threshold, 2);
        assert_eq!(v.signer_count(), 3);
        assert_eq!(
            v.address, REAL_ADDRESS,
            "our P2SH derivation must match createmultisig byte for byte"
        );
        assert_eq!(v.redeem_script_hex(), REAL_REDEEM_SCRIPT);
    }

    #[test]
    fn rebuilding_from_parsed_keys_reproduces_the_same_script() {
        let v = MultisigVault::from_redeem_script_hex(REAL_REDEEM_SCRIPT).unwrap();
        let rebuilt = MultisigVault::new(v.threshold, v.signer_pubkeys.clone()).unwrap();
        assert_eq!(rebuilt, v, "parse and build must be exact inverses");
    }

    #[test]
    fn script_pubkey_matches_the_p2sh_shape() {
        let v = MultisigVault::from_redeem_script_hex(REAL_REDEEM_SCRIPT).unwrap();
        let spk = v.script_pubkey_hex();
        assert!(spk.starts_with("a914") && spk.ends_with("87"));
        assert_eq!(spk.len(), 46, "OP_HASH160 <20> OP_EQUAL is 23 bytes");
        // Real node value observed for this vault.
        assert!(spk.starts_with("a9147ea16a6a71d5a70d89ad"));
    }

    #[test]
    fn address_round_trips_through_decode() {
        let v = MultisigVault::from_redeem_script_hex(REAL_REDEEM_SCRIPT).unwrap();
        assert_eq!(decode_p2sh_hash160(&v.address).unwrap(), v.script_hash160);
    }

    #[test]
    fn a_configured_address_that_disagrees_with_the_script_is_refused() {
        let v = MultisigVault::from_redeem_script_hex(REAL_REDEEM_SCRIPT).unwrap();
        v.require_address(REAL_ADDRESS).unwrap();
        let err = v
            .require_address("QYwrongwrongwrongwrongwrongwrongwr")
            .unwrap_err();
        assert!(matches!(err, VaultError::AddressMismatch { .. }));
    }

    fn pk(seed: u8) -> [u8; 33] {
        let mut k = [seed; 33];
        k[0] = 0x02;
        k
    }

    #[test]
    fn rejects_invalid_thresholds_and_signer_sets() {
        assert_eq!(
            MultisigVault::new(1, vec![]).unwrap_err(),
            VaultError::NoSigners
        );
        assert_eq!(
            MultisigVault::new(0, vec![pk(1)]).unwrap_err(),
            VaultError::ZeroThreshold
        );
        assert_eq!(
            MultisigVault::new(3, vec![pk(1), pk(2)]).unwrap_err(),
            VaultError::ThresholdExceedsSigners { m: 3, n: 2 }
        );
        assert_eq!(
            MultisigVault::new(2, vec![pk(1), pk(1)]).unwrap_err(),
            VaultError::DuplicateSigner(1)
        );
        let too_many: Vec<[u8; 33]> = (0..17).map(pk).collect();
        assert_eq!(
            MultisigVault::new(2, too_many).unwrap_err(),
            VaultError::TooManySigners(17)
        );
    }

    #[test]
    fn rejects_uncompressed_or_malformed_pubkeys() {
        let mut bad = pk(1);
        bad[0] = 0x04; // uncompressed prefix
        assert_eq!(
            MultisigVault::new(1, vec![bad]).unwrap_err(),
            VaultError::BadPubkeyPrefix {
                index: 0,
                prefix: 0x04
            }
        );
    }

    #[test]
    fn rejects_malformed_redeem_scripts() {
        for bad in [
            "",
            "52",
            "5221028e7147e643d67093dc8ca6a8fb888f1a452dddc62de991c7ed72080d65a421e453ae", // 1 key, says 3
            "0021028e7147e643d67093dc8ca6a8fb888f1a452dddc62de991c7ed72080d65a421e451ae", // OP_0 threshold
            "zz",
        ] {
            assert!(
                MultisigVault::from_redeem_script_hex(bad).is_err(),
                "must reject {bad:?}"
            );
        }
        // Right shape but not ending in OP_CHECKMULTISIG.
        let mut s = REAL_REDEEM_SCRIPT.to_string();
        s.truncate(s.len() - 2);
        s.push_str("ff");
        assert!(MultisigVault::from_redeem_script_hex(&s).is_err());
    }

    #[test]
    fn quorum_must_be_exactly_threshold_sized_in_range_and_ascending() {
        let v = MultisigVault::from_redeem_script_hex(REAL_REDEEM_SCRIPT).unwrap(); // 2-of-3
        v.validate_quorum(&[0, 1]).unwrap();
        v.validate_quorum(&[0, 2]).unwrap();
        v.validate_quorum(&[1, 2]).unwrap();

        assert!(v.validate_quorum(&[0]).is_err(), "too few");
        assert!(v.validate_quorum(&[0, 1, 2]).is_err(), "too many");
        assert!(v.validate_quorum(&[0, 3]).is_err(), "index out of range");
        assert!(v.validate_quorum(&[1, 0]).is_err(), "descending");
        assert!(v.validate_quorum(&[1, 1]).is_err(), "duplicate");
    }
}
