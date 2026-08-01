//! Wiring the payout path to the federation transport (Phase 7e, ADR-0017).
//!
//! Resolves a designated quorum — expressed as positions in the vault's
//! ordered signer list (ADR-0015) — into the federation peers that hold
//! those vault keys, asks exactly those peers, and returns their partials.
//!
//! # The mapping, and why configuration is a safe home for it
//!
//! ADR-0017 E1 binds a federation ed25519 identity to a vault secp256k1
//! position by **configuration**, not on-chain. That is only safe because
//! the mapping is validated at startup and **fails closed**:
//!
//! - every index must be inside the vault's signer set;
//! - no index may be claimed twice, and no validator may claim two indices;
//! - the map must cover every vault position, so a designated quorum can
//!   never resolve to "nobody";
//! - and on the signer side, the process proves it actually holds the key at
//!   its configured position ([`MultisigVault::require_signer_at`]).
//!
//! A misconfigured operator therefore cannot silently participate — which is
//! the property that made on-chain binding unnecessary for this phase.

use std::collections::HashMap;

use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

use crate::p2p::collector::{DesignatedSigner, GrpcCollector};
use crate::withdrawal::executor::PayoutPartialCollector;
use crate::withdrawal::multisig::PartialSignature;
use crate::withdrawal::vault::MultisigVault;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultSignerMapError {
    #[error("vault signer map entry {0:?} must be formatted index:base58pubkey")]
    Malformed(String),
    #[error("vault signer map entry {entry:?} has an invalid validator pubkey: {reason}")]
    BadPubkey { entry: String, reason: String },
    #[error(
        "vault signer index {index} is outside this vault's {signers} signers — refusing to start \
         with a mapping that could route a signing request to no key at all"
    )]
    IndexOutOfRange { index: u8, signers: usize },
    #[error("vault signer index {0} is claimed by more than one validator")]
    DuplicateIndex(u8),
    #[error("validator {0} claims more than one vault signer position")]
    DuplicateValidator(Pubkey),
    #[error(
        "vault signer map covers {covered} of {signers} vault positions — every position must be \
         mapped, or a designated quorum could resolve to nobody"
    )]
    Incomplete { covered: usize, signers: usize },
    #[error("vault signer map is empty")]
    Empty,
}

/// Vault signer position → the federation validator that holds that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSignerMap {
    by_index: HashMap<u8, Pubkey>,
}

impl VaultSignerMap {
    /// Parses `index:base58pubkey[,index:base58pubkey...]` and validates it
    /// against the vault, **failing closed** on anything inconsistent
    /// (ADR-0017 E1).
    pub fn parse(raw: &str, vault: &MultisigVault) -> Result<Self, VaultSignerMapError> {
        let mut by_index: HashMap<u8, Pubkey> = HashMap::new();
        let mut seen_validators: Vec<Pubkey> = Vec::new();

        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (idx, pk) = entry
                .split_once(':')
                .ok_or_else(|| VaultSignerMapError::Malformed(entry.to_string()))?;
            let index: u8 = idx
                .trim()
                .parse()
                .map_err(|_| VaultSignerMapError::Malformed(entry.to_string()))?;
            let validator: Pubkey =
                pk.trim()
                    .parse()
                    .map_err(|e: solana_sdk::pubkey::ParsePubkeyError| {
                        VaultSignerMapError::BadPubkey {
                            entry: entry.to_string(),
                            reason: e.to_string(),
                        }
                    })?;

            if index as usize >= vault.signer_pubkeys.len() {
                return Err(VaultSignerMapError::IndexOutOfRange {
                    index,
                    signers: vault.signer_pubkeys.len(),
                });
            }
            if by_index.contains_key(&index) {
                return Err(VaultSignerMapError::DuplicateIndex(index));
            }
            if seen_validators.contains(&validator) {
                return Err(VaultSignerMapError::DuplicateValidator(validator));
            }
            seen_validators.push(validator);
            by_index.insert(index, validator);
        }

        if by_index.is_empty() {
            return Err(VaultSignerMapError::Empty);
        }
        if by_index.len() != vault.signer_pubkeys.len() {
            return Err(VaultSignerMapError::Incomplete {
                covered: by_index.len(),
                signers: vault.signer_pubkeys.len(),
            });
        }
        Ok(VaultSignerMap { by_index })
    }

    pub fn validator_at(&self, index: u8) -> Option<Pubkey> {
        self.by_index.get(&index).copied()
    }

    pub fn len(&self) -> usize {
        self.by_index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }
}

/// Collects payout partials from the designated quorum over the federation
/// transport.
pub struct FederationPayoutCollector {
    collector: GrpcCollector,
    vault: MultisigVault,
    map: VaultSignerMap,
}

impl FederationPayoutCollector {
    pub fn new(collector: GrpcCollector, vault: MultisigVault, map: VaultSignerMap) -> Self {
        FederationPayoutCollector {
            collector,
            vault,
            map,
        }
    }

    /// Resolves quorum positions into the peers that must answer.
    ///
    /// A position that does not resolve is **dropped rather than
    /// substituted**: the resulting shortfall forces an explicit, audited
    /// reassignment, which is exactly what ADR-0015 requires. Silently
    /// asking somebody else would change the txid.
    fn resolve(&self, quorum_indices: &[u8]) -> Vec<DesignatedSigner> {
        quorum_indices
            .iter()
            .filter_map(|&i| {
                let validator = self.map.validator_at(i).or_else(|| {
                    tracing::error!(
                        vault_signer_index = i,
                        "designated vault signer position has no mapped validator — this quorum \
                         cannot be satisfied and requires explicit reassignment"
                    );
                    None
                })?;
                let vault_pubkey = *self.vault.signer_pubkeys.get(i as usize)?;
                Some(DesignatedSigner {
                    validator_pubkey: validator,
                    vault_pubkey,
                })
            })
            .collect()
    }
}

impl PayoutPartialCollector for FederationPayoutCollector {
    async fn collect_payout_partials(
        &self,
        epoch: u64,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        quorum_indices: &[u8],
    ) -> Vec<PartialSignature> {
        let designated = self.resolve(quorum_indices);
        if designated.len() != quorum_indices.len() {
            tracing::error!(
                withdrawal_index,
                designated = designated.len(),
                required = quorum_indices.len(),
                "not every designated signer could be resolved to a peer"
            );
        }
        self.collector
            .collect_payout_partials(
                epoch,
                withdrawal_index,
                quorum_attempt,
                canonical_intent,
                unsigned_tx_hex,
                &designated,
            )
            .await
            .partials
    }
}

/// ⚠️ **TEST-ONLY.** Produces vault partial signatures in-process.
///
/// This deliberately reintroduces the very property Phase 7e removes — one
/// process holding several vault keys — so tests can reach threshold without
/// standing up N signer processes and a Goldcoin node for each.
///
/// It must never be constructed by a deployed relayer. Production wiring
/// uses [`FederationPayoutCollector`] exclusively, and
/// `WithdrawalExecutor::new` takes no key parameter, so reaching for this in
/// production would be a deliberate act rather than an accident.
///
/// The signatures it produces are **real**: RFC6979-deterministic ECDSA over
/// the genuine sighash, so tests exercise the same assembly and verification
/// path production does rather than a stub that would hide a bug in it.
pub struct InProcessPayoutCollector {
    vault: MultisigVault,
    /// `(vault signer index, secret key)` for every key this holds.
    keys: Vec<(u8, libsecp256k1::SecretKey)>,
}

impl InProcessPayoutCollector {
    /// Builds from raw secret keys, for tests that never involve a node.
    pub fn from_secret_keys(
        vault: MultisigVault,
        keys: Vec<(u8, libsecp256k1::SecretKey)>,
    ) -> Self {
        InProcessPayoutCollector { vault, keys }
    }

    /// A deterministic N-of-M vault plus a collector holding every key.
    ///
    /// Deterministic so a failing test reproduces exactly, and so the vault
    /// address is stable across runs.
    pub fn deterministic_test_vault(n: usize, m: usize) -> (MultisigVault, Self) {
        let mut secrets = Vec::with_capacity(n);
        let mut pubkeys = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[31] = i as u8 + 1;
            seed[0] = 0x42;
            let sk = libsecp256k1::SecretKey::parse(&seed).expect("valid test secret");
            pubkeys.push(libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed());
            secrets.push(sk);
        }
        let vault = MultisigVault::new(m, pubkeys).expect("valid test vault");
        let keys = secrets
            .into_iter()
            .enumerate()
            .map(|(i, sk)| (i as u8, sk))
            .collect();
        let collector = InProcessPayoutCollector::from_secret_keys(vault.clone(), keys);
        (vault, collector)
    }

    /// Builds from WIF-encoded keys, as a Goldcoin node's `dumpprivkey`
    /// returns them.
    pub fn from_wifs(vault: MultisigVault, wifs: &[(u8, String)]) -> Result<Self, String> {
        let mut keys = Vec::with_capacity(wifs.len());
        for (index, wif) in wifs {
            vault
                .require_signer_at(*index, wif)
                .map_err(|e| format!("key for vault index {index} is wrong: {e}"))?;
            keys.push((*index, decode_wif_secret(wif)?));
        }
        Ok(InProcessPayoutCollector { vault, keys })
    }
}

fn decode_wif_secret(wif: &str) -> Result<libsecp256k1::SecretKey, String> {
    use crate::withdrawal::address::{base58_decode, checksum};
    let raw = base58_decode(wif.trim()).map_err(|_| "WIF is not base58".to_string())?;
    if raw.len() != 38 {
        return Err("WIF is not a compressed-key encoding".to_string());
    }
    let (payload, given) = raw.split_at(34);
    if checksum(payload) != given {
        return Err("WIF checksum is wrong".to_string());
    }
    libsecp256k1::SecretKey::parse_slice(&payload[1..33])
        .map_err(|_| "WIF does not encode a valid key".to_string())
}

impl PayoutPartialCollector for InProcessPayoutCollector {
    async fn collect_payout_partials(
        &self,
        _epoch: u64,
        _withdrawal_index: u64,
        _quorum_attempt: u32,
        _canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        quorum_indices: &[u8],
    ) -> Vec<PartialSignature> {
        use crate::withdrawal::multisig::{Transaction, SIGHASH_ALL};

        let Ok(tx) = Transaction::parse_hex(unsigned_tx_hex) else {
            return Vec::new();
        };
        let sighashes: Vec<[u8; 32]> = (0..tx.inputs.len())
            .map(|i| tx.sighash_all(i, &self.vault.redeem_script))
            .collect();

        quorum_indices
            .iter()
            .filter_map(|idx| {
                let (_, secret) = self.keys.iter().find(|(i, _)| i == idx)?;
                let signatures = sighashes
                    .iter()
                    .map(|h| {
                        let msg = libsecp256k1::Message::parse(h);
                        let (sig, _) = libsecp256k1::sign(&msg, secret);
                        let mut der = sig.serialize_der().as_ref().to_vec();
                        der.push(SIGHASH_ALL);
                        der
                    })
                    .collect();
                Some(PartialSignature {
                    vault_pubkey: self.vault.signer_pubkeys[*idx as usize],
                    signatures,
                })
            })
            .collect()
    }
}

/// Collects completion attestations over the federation transport
/// (Phase 7f, ADR-0018).
///
/// Unlike payouts, completion has no designated quorum: the on-chain proof
/// does not depend on which M validators signed, so any M who have
/// independently confirmed the payout may attest.
pub struct FederationCompletionCollector {
    collector: GrpcCollector,
}

impl FederationCompletionCollector {
    pub fn new(collector: GrpcCollector) -> Self {
        FederationCompletionCollector { collector }
    }
}

impl crate::withdrawal::completion::CompletionSignatureCollector for FederationCompletionCollector {
    async fn collect_completion_signatures(
        &self,
        epoch: u64,
        withdrawal_index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
        message: &[u8],
    ) -> Vec<(Pubkey, solana_sdk::signature::Signature)> {
        self.collector
            .collect_completion_signatures(
                epoch,
                withdrawal_index,
                payout_txid,
                payout_height,
                message,
            )
            .await
            .signatures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};

    fn vault_of(n: usize, m: usize) -> MultisigVault {
        let keys: Vec<[u8; 33]> = (0..n)
            .map(|i| {
                let mut k = [0u8; 33];
                k[0] = 0x02;
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        MultisigVault::new(m, keys).unwrap()
    }

    fn pk() -> Pubkey {
        Keypair::new().pubkey()
    }

    #[test]
    fn parses_a_complete_well_formed_map() {
        let v = vault_of(3, 2);
        let (a, b, c) = (pk(), pk(), pk());
        let raw = format!("0:{a},1:{b},2:{c}");
        let m = VaultSignerMap::parse(&raw, &v).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m.validator_at(0), Some(a));
        assert_eq!(m.validator_at(2), Some(c));
    }

    #[test]
    fn rejects_an_index_outside_the_vault() {
        // A designated quorum must never resolve to a position that does not
        // exist; failing at startup is the whole point of E1.
        let v = vault_of(3, 2);
        let raw = format!("0:{},1:{},3:{}", pk(), pk(), pk());
        assert!(matches!(
            VaultSignerMap::parse(&raw, &v).unwrap_err(),
            VaultSignerMapError::IndexOutOfRange {
                index: 3,
                signers: 3
            }
        ));
    }

    #[test]
    fn rejects_an_incomplete_map() {
        // A gap means some designated quorum resolves to nobody, which would
        // look like an outage forever rather than a misconfiguration.
        let v = vault_of(3, 2);
        let raw = format!("0:{},1:{}", pk(), pk());
        assert!(matches!(
            VaultSignerMap::parse(&raw, &v).unwrap_err(),
            VaultSignerMapError::Incomplete {
                covered: 2,
                signers: 3
            }
        ));
    }

    #[test]
    fn rejects_two_validators_claiming_one_position() {
        let v = vault_of(3, 2);
        let raw = format!("0:{},0:{},2:{}", pk(), pk(), pk());
        assert!(matches!(
            VaultSignerMap::parse(&raw, &v).unwrap_err(),
            VaultSignerMapError::DuplicateIndex(0)
        ));
    }

    #[test]
    fn rejects_one_validator_claiming_two_positions() {
        // Otherwise one compromised validator could satisfy an M-of-N by
        // itself, which is the entire property the vault exists to prevent.
        let v = vault_of(3, 2);
        let a = pk();
        let raw = format!("0:{a},1:{a},2:{}", pk());
        assert!(matches!(
            VaultSignerMap::parse(&raw, &v).unwrap_err(),
            VaultSignerMapError::DuplicateValidator(_)
        ));
    }

    #[test]
    fn rejects_empty_and_malformed_entries() {
        let v = vault_of(3, 2);
        assert!(matches!(
            VaultSignerMap::parse("", &v).unwrap_err(),
            VaultSignerMapError::Empty
        ));
        for raw in ["notanindex:x", "0", &format!("0:{},1:notapubkey,2:x", pk())] {
            assert!(
                VaultSignerMap::parse(raw, &v).is_err(),
                "must reject {raw:?}"
            );
        }
    }

    #[test]
    fn a_gap_in_the_map_yields_a_shortfall_never_a_substitution() {
        // `parse` enforces completeness, so this constructs the struct
        // directly to exercise the defensive branch behind that invariant.
        // If completeness were ever relaxed, substituting a different
        // validator would silently change the txid — the one thing ADR-0015
        // exists to prevent — so the branch is tested rather than trusted.
        let v = vault_of(3, 2);
        let (a, c) = (pk(), pk());
        let mut by_index = HashMap::new();
        by_index.insert(0u8, a);
        by_index.insert(2u8, c);
        let map = VaultSignerMap { by_index };

        let fc = FederationPayoutCollector::new(
            GrpcCollector::insecure_without_tls(vec![crate::p2p::identity::PeerEndpoint {
                validator_pubkey: a,
                uri: "http://127.0.0.1:1".into(),
            }]),
            v,
            map,
        );
        // Position 1 is unmapped.
        let resolved = fc.resolve(&[0, 1]);
        assert_eq!(
            resolved.len(),
            1,
            "an unmapped position must be DROPPED, producing a shortfall"
        );
        assert_eq!(resolved[0].validator_pubkey, a);
        assert!(
            !resolved.iter().any(|d| d.validator_pubkey == c),
            "another validator must never be substituted in"
        );
    }

    #[test]
    fn resolve_drops_rather_than_substitutes_an_unmapped_position() {
        // ADR-0015: the txid depends on which quorum signs, so a missing
        // designated signer must produce a shortfall, never a substitution.
        let v = vault_of(3, 2);
        let (a, b, c) = (pk(), pk(), pk());
        let map = VaultSignerMap::parse(&format!("0:{a},1:{b},2:{c}"), &v).unwrap();
        let fc = FederationPayoutCollector::new(
            GrpcCollector::insecure_without_tls(vec![crate::p2p::identity::PeerEndpoint {
                validator_pubkey: a,
                uri: "http://127.0.0.1:1".into(),
            }]),
            v.clone(),
            map,
        );
        let resolved = fc.resolve(&[0, 2]);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].validator_pubkey, a);
        assert_eq!(resolved[0].vault_pubkey, v.signer_pubkeys[0]);
        assert_eq!(resolved[1].validator_pubkey, c);
        assert_eq!(
            resolved[1].vault_pubkey, v.signer_pubkeys[2],
            "each resolved signer carries the vault key for ITS OWN position"
        );
    }
}
