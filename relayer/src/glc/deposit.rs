//! Pure deposit-extraction logic (ADR-0011): vault-script matching,
//! OP_RETURN recipient-binding extraction, and canonical claim-message
//! construction. No I/O — fully unit-testable against fabricated RPC
//! responses, mirroring the on-chain program's own pure-logic modules
//! (`validation.rs`, `verification.rs`).

use glc_bridge_shared::claim::deposit_claim_message;

use super::hex;
use super::rpc::DecodedTransaction;

#[derive(Debug, PartialEq, Eq)]
pub enum BindingError {
    /// No OP_RETURN output in the transaction at all.
    NoOpReturn,
    /// More than one OP_RETURN output — which one binds which vault output
    /// is undecidable, so the whole transaction's vault outputs are
    /// rejected rather than guessed.
    MultipleOpReturn,
    /// An OP_RETURN was found but its pushed data is not exactly 32 bytes.
    WrongPushSize { actual: usize },
}

impl BindingError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            BindingError::NoOpReturn => "no_recipient_binding",
            BindingError::MultipleOpReturn => "ambiguous_recipient_binding",
            BindingError::WrongPushSize { .. } => "malformed_recipient_binding",
        }
    }
}

/// A vault-paying output found in a transaction, paired with its (already
/// validated) recipient binding. Produced by [`find_vault_outputs`] (see its
/// docs for why production ingestion doesn't use it directly).
#[derive(Debug)]
#[allow(dead_code)]
pub struct VaultDeposit {
    pub vout: u32,
    pub amount_atomic: u64,
    pub recipient: [u8; 32],
}

/// A vault-paying output found in a transaction, independent of whether the
/// transaction's recipient binding is valid — used by the indexer so that
/// even a malformed-binding transaction still gets an auditable `Failed`
/// row per vault output (owner requirement: never silently ignore a
/// below-minimum or malformed-binding vault payment).
#[derive(Debug, Clone, Copy)]
pub struct VaultOutputCandidate {
    pub vout: u32,
    pub amount_atomic: u64,
}

/// Exact byte-for-byte `scriptPubKey` match against the configured vault
/// script — never an address-string comparison (base58/version-byte
/// ambiguity risk).
fn is_vault_output(script_pub_key_hex: &str, vault_script_hex: &str) -> bool {
    script_pub_key_hex.eq_ignore_ascii_case(vault_script_hex)
}

/// `OP_RETURN` opcode.
const OP_RETURN: u8 = 0x6a;

/// Extracts the transaction's single valid 32-byte OP_RETURN recipient
/// binding, or the specific reason it can't be used (never guessed).
pub fn extract_recipient_binding(tx: &DecodedTransaction) -> Result<[u8; 32], BindingError> {
    let mut found: Option<[u8; 32]> = None;
    let mut count = 0usize;
    for vout in &tx.vout {
        let script = match hex::decode_vec(&vout.script_pub_key.hex) {
            Ok(s) => s,
            Err(_) => continue, // unparseable script: not a valid OP_RETURN candidate
        };
        if script.first() != Some(&OP_RETURN) {
            continue;
        }
        count += 1;
        if count > 1 {
            return Err(BindingError::MultipleOpReturn);
        }
        // Minimal push-data parse sufficient for our fixed 32-byte need:
        // OP_RETURN (1) + direct push opcode (1, value = length for
        // lengths <= 0x4b) + payload. Anything else (OP_PUSHDATA1/2/4,
        // or a push whose stated length doesn't match the remaining
        // bytes) is treated as a wrong-size push rather than parsed
        // further — Phase 4 needs exactly one shape and rejects the rest.
        let payload_len = script.get(1).copied().unwrap_or(0) as usize;
        let payload = script.get(2..);
        let actual_len = payload.map(<[u8]>::len).unwrap_or(0);
        if payload_len != 32 || actual_len != 32 {
            return Err(BindingError::WrongPushSize { actual: actual_len });
        }
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(payload.unwrap());
        found = Some(recipient);
    }
    found.ok_or(BindingError::NoOpReturn)
}

/// Every vault-paying output in `tx`, regardless of whether the
/// transaction's recipient binding is valid — the primitive
/// [`find_vault_outputs`] and the indexer's ingestion path both build on.
pub fn vault_output_candidates(
    tx: &DecodedTransaction,
    vault_script_hex: &str,
) -> Vec<VaultOutputCandidate> {
    tx.vout
        .iter()
        .filter(|v| is_vault_output(&v.script_pub_key.hex, vault_script_hex))
        .map(|v| VaultOutputCandidate {
            vout: v.n,
            amount_atomic: glc_to_atomic(v.value),
        })
        .collect()
}

/// Every vault-paying output in `tx`, each amount converted from the RPC's
/// decimal GLC value to atomic units (8 decimals, verified empirically —
/// docs/goldcoin-rpc-notes.md). Recipient binding is resolved once for the
/// whole transaction and applied to every vault output in it (ADR-0002:
/// multi-output vault payments are independent claims sharing one binding).
///
/// This is the tested reference composition of [`vault_output_candidates`]
/// and [`extract_recipient_binding`] for the success path.
///
/// `indexer.rs`'s ingestion loop calls those two primitives directly
/// instead: on a binding error it must still record a `Failed` row per
/// vault output, and this function's `Result` discards which outputs were
/// vault-matched on error. Kept as its own unit-tested function so the
/// composed happy-path semantics stay pinned independently of the
/// indexer's error-preserving version.
#[allow(dead_code)]
pub fn find_vault_outputs(
    tx: &DecodedTransaction,
    vault_script_hex: &str,
) -> Result<Vec<VaultDeposit>, BindingError> {
    let vault_vouts: Vec<&super::rpc::DecodedVout> = tx
        .vout
        .iter()
        .filter(|v| is_vault_output(&v.script_pub_key.hex, vault_script_hex))
        .collect();
    if vault_vouts.is_empty() {
        return Ok(Vec::new());
    }
    let recipient = extract_recipient_binding(tx)?;
    Ok(vault_vouts
        .into_iter()
        .map(|v| VaultDeposit {
            vout: v.n,
            amount_atomic: glc_to_atomic(v.value),
            recipient,
        })
        .collect())
}

/// Converts an RPC decimal GLC value to atomic units. Goldcoin's decimal
/// precision was verified empirically at exactly 8 (docs/goldcoin-rpc-notes.md:
/// a 9th-decimal-digit amount and a half-atomic-unit amount were both
/// rejected by the node with "Invalid amount"). Rounds to the nearest
/// atomic unit to absorb IEEE-754 f64 representation noise in the RPC's
/// JSON number (the node itself only ever produces exact multiples of
/// 1e-8, so this never masks a real fractional discrepancy).
fn glc_to_atomic(value: f64) -> u64 {
    (value * 100_000_000.0).round() as u64
}

/// Builds the exact Phase 3 canonical claim message
/// (`glc_bridge_shared::claim::deposit_claim_message`) for a deposit that
/// has reached `ReadyForSignature`. Returns the message only — Phase 4 never
/// signs or submits it.
#[allow(clippy::too_many_arguments)]
pub fn build_claim_message(
    protocol_version: u8,
    program_id: &[u8; 32],
    epoch: u64,
    txid: &[u8; 32],
    vout: u32,
    amount_atomic: u64,
    recipient: &[u8; 32],
    wrapped_mint: &[u8; 32],
) -> [u8; 166] {
    deposit_claim_message(
        protocol_version,
        program_id,
        epoch,
        txid,
        vout,
        amount_atomic,
        recipient,
        wrapped_mint,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glc::rpc::{DecodedScriptPubKey, DecodedVout};

    const VAULT_SCRIPT: &str = "76a9145a7ab7adf8185c27b3f54104cdccfe1ff0cd54cf88ac";
    const OTHER_SCRIPT: &str = "76a9147ea48c12a683774fc49e51a97e85440cbd5daf8d88ac";

    fn vout(n: u32, value: f64, script_hex: &str) -> DecodedVout {
        DecodedVout {
            value,
            n,
            script_pub_key: DecodedScriptPubKey {
                hex: script_hex.to_string(),
                kind: "pubkeyhash".to_string(),
            },
        }
    }

    fn op_return_vout(n: u32, payload: &[u8]) -> DecodedVout {
        let mut script = vec![0x6a, payload.len() as u8];
        script.extend_from_slice(payload);
        DecodedVout {
            value: 0.0,
            n,
            script_pub_key: DecodedScriptPubKey {
                hex: hex::encode(&script),
                kind: "nulldata".to_string(),
            },
        }
    }

    fn tx(vouts: Vec<DecodedVout>) -> DecodedTransaction {
        DecodedTransaction {
            txid: "0".repeat(64),
            vout: vouts,
            confirmations: Some(1),
        }
    }

    #[test]
    fn real_32_byte_op_return_extracted_exactly() {
        // The exact real payload broadcast/mined in the Phase 4 design
        // session, byte-for-byte.
        let payload: Vec<u8> = (0u8..32).collect();
        let recipient = extract_recipient_binding(&tx(vec![
            vout(0, 5.0, VAULT_SCRIPT),
            op_return_vout(1, &payload),
        ]))
        .unwrap();
        assert_eq!(recipient.to_vec(), payload);
    }

    #[test]
    fn rejects_zero_op_return_outputs() {
        let err = extract_recipient_binding(&tx(vec![vout(0, 5.0, VAULT_SCRIPT)])).unwrap_err();
        assert_eq!(err, BindingError::NoOpReturn);
        assert_eq!(err.reason_code(), "no_recipient_binding");
    }

    #[test]
    fn rejects_multiple_op_return_outputs() {
        let payload = [0u8; 32];
        let err = extract_recipient_binding(&tx(vec![
            vout(0, 5.0, VAULT_SCRIPT),
            op_return_vout(1, &payload),
            op_return_vout(2, &payload),
        ]))
        .unwrap_err();
        assert_eq!(err, BindingError::MultipleOpReturn);
        assert_eq!(err.reason_code(), "ambiguous_recipient_binding");
    }

    #[test]
    fn rejects_31_byte_push() {
        let payload = [0u8; 31];
        let err = extract_recipient_binding(&tx(vec![
            vout(0, 5.0, VAULT_SCRIPT),
            op_return_vout(1, &payload),
        ]))
        .unwrap_err();
        assert_eq!(err, BindingError::WrongPushSize { actual: 31 });
        assert_eq!(err.reason_code(), "malformed_recipient_binding");
    }

    #[test]
    fn rejects_33_byte_push() {
        let payload = [0u8; 33];
        let err = extract_recipient_binding(&tx(vec![
            vout(0, 5.0, VAULT_SCRIPT),
            op_return_vout(1, &payload),
        ]))
        .unwrap_err();
        assert_eq!(err, BindingError::WrongPushSize { actual: 33 });
    }

    #[test]
    fn wrong_vault_output_is_ignored() {
        let deposits = find_vault_outputs(
            &tx(vec![
                vout(0, 5.0, OTHER_SCRIPT),
                op_return_vout(1, &[0u8; 32]),
            ]),
            VAULT_SCRIPT,
        )
        .unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn no_vault_output_short_circuits_before_binding_check_even_if_binding_is_malformed() {
        // Two OP_RETURNs would normally be ambiguous, but since there is no
        // vault-paying output at all, nothing should even attempt to bind —
        // this transaction is simply irrelevant to the bridge.
        let deposits = find_vault_outputs(
            &tx(vec![
                vout(0, 5.0, OTHER_SCRIPT),
                op_return_vout(1, &[0u8; 32]),
                op_return_vout(2, &[0u8; 32]),
            ]),
            VAULT_SCRIPT,
        )
        .unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn multiple_vault_outputs_share_one_recipient_binding() {
        let payload = [0xAB; 32];
        let deposits = find_vault_outputs(
            &tx(vec![
                vout(0, 5.0, VAULT_SCRIPT),
                vout(1, 3.0, VAULT_SCRIPT),
                op_return_vout(2, &payload),
            ]),
            VAULT_SCRIPT,
        )
        .unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].vout, 0);
        assert_eq!(deposits[1].vout, 1);
        assert_eq!(deposits[0].recipient, payload);
        assert_eq!(deposits[1].recipient, payload);
        assert_eq!(deposits[0].amount_atomic, 500_000_000);
        assert_eq!(deposits[1].amount_atomic, 300_000_000);
    }

    #[test]
    fn ambiguous_binding_fails_all_vault_outputs_in_the_transaction() {
        let payload = [0u8; 32];
        let err = find_vault_outputs(
            &tx(vec![
                vout(0, 5.0, VAULT_SCRIPT),
                vout(1, 3.0, VAULT_SCRIPT),
                op_return_vout(2, &payload),
                op_return_vout(3, &payload),
            ]),
            VAULT_SCRIPT,
        )
        .unwrap_err();
        assert_eq!(err, BindingError::MultipleOpReturn);
    }

    #[test]
    fn glc_to_atomic_matches_verified_8_decimal_precision() {
        assert_eq!(glc_to_atomic(1.0), 100_000_000);
        assert_eq!(glc_to_atomic(0.00000001), 1);
        assert_eq!(glc_to_atomic(12.34567891), 1_234_567_891);
        assert_eq!(glc_to_atomic(9962.65382709), 996_265_382_709);
    }

    #[test]
    fn build_claim_message_matches_shared_crate_byte_for_byte() {
        let program_id = [0x11; 32];
        let txid = [0x22; 32];
        let recipient = [0x33; 32];
        let wrapped_mint = [0x44; 32];
        let ours = build_claim_message(
            1,
            &program_id,
            7,
            &txid,
            3,
            555_000,
            &recipient,
            &wrapped_mint,
        );
        let direct = deposit_claim_message(
            1,
            &program_id,
            7,
            &txid,
            3,
            555_000,
            &recipient,
            &wrapped_mint,
        );
        assert_eq!(ours, direct);
    }

    /// Txid byte-order regression: the exact real raw-tx-hex / RPC-txid pair
    /// captured against a live Goldcoin Core v0.15.0 regtest node in the
    /// Phase 4 design session, and INDEPENDENTLY cross-checked there via
    /// `sha256(sha256(raw))[::-1].hex() == rpc_txid` (verified fact A6,
    /// docs/goldcoin-rpc-notes.md). Pins this crate's txid-bytes convention
    /// (owner decision U2: RPC-displayed hex, decoded directly, no further
    /// reversal) forever — this must never silently start disagreeing with
    /// the empirically verified Bitcoin-style byte-reversal convention.
    #[test]
    fn txid_byte_order_regression_against_real_captured_transaction() {
        let raw_tx_hex = "0100000001eb8eccdba6190ef38bb6dbc6f1ac918ab971a439921f7337ee3e6698e8bf656e000000006b483045022100c742e15db97b674794a33ccbae46c7f3737d5bf0426ed6417f2144cc61a703de02205e4ffbf0f5525658d0313084d4953526a50d74c62836615c398daf4fcd5a4a2c012102e036e7852151a6f2bc6401c5bb004d9d60844206a0c301826d7c47e3a78e33d9feffffff030065cd1d000000001976a9145a7ab7adf8185c27b3f54104cdccfe1ff0cd54cf88ac0000000000000000226a20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fbf34c82b000000001976a9147ea48c12a683774fc49e51a97e85440cbd5daf8d88ac00000000";
        let expected_rpc_txid = "4e327700bf5064c1ab0093a6e288edf3e5fb3f7b605ad6f53e4dd18787965bf3";
        assert_eq!(expected_rpc_txid.len(), 64);

        let raw_bytes = hex::decode_vec(raw_tx_hex).unwrap();
        let h1 = sha256(&raw_bytes);
        let h2 = sha256(&h1);
        let mut reversed = h2;
        reversed.reverse();
        let computed_txid = hex::encode(&reversed);

        assert_eq!(
            computed_txid, expected_rpc_txid,
            "RPC-displayed txid must equal the byte-reversed double-SHA256 of the raw tx"
        );
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).to_vec()
    }
}
