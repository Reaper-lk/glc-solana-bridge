//! Payout transaction construction and output verification (Phase 6,
//! ADR-0013).
//!
//! **Every output is verified before signing.** The node builds the raw
//! transaction (`createrawtransaction`), but the relayer never trusts what
//! comes back: it decodes the result and proves, field by field, that the
//! transaction pays exactly the intended destination exactly the intended
//! amount, returns exactly the intended change to a vault-owned address,
//! spends exactly the reserved inputs, and contains nothing else.
//!
//! A payout is the only place in this system where the bridge moves native
//! value with no on-chain program to check its work, so verification here is
//! the whole safety boundary.

use thiserror::Error;

use super::address::p2pkh_script_hex;
use crate::glc::withdrawal_db::VaultUtxo;

/// A decoded transaction output, as returned by `decoderawtransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedOutput {
    pub value_atomic: u64,
    pub script_pubkey_hex: String,
}

/// A decoded transaction input (outpoint only — that is all we verify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInput {
    pub txid_hex: String,
    pub vout: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTx {
    pub txid_hex: String,
    pub inputs: Vec<DecodedInput>,
    pub outputs: Vec<DecodedOutput>,
}

/// What the payout is supposed to be. Derived from persisted state only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutPlan {
    pub dest_hash160: [u8; 20],
    pub payout_atomic: u64,
    pub change_hash160: Option<[u8; 20]>,
    pub change_atomic: u64,
    pub fee_atomic: u64,
    pub inputs: Vec<VaultUtxo>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("expected {expected} outputs, transaction has {actual}")]
    OutputCount { expected: usize, actual: usize },
    #[error("expected {expected} inputs, transaction has {actual}")]
    InputCount { expected: usize, actual: usize },
    #[error(
        "input {position} is {actual_txid}:{actual_vout}, expected the reserved outpoint \
         {expected_txid}:{expected_vout}"
    )]
    InputMismatch {
        position: usize,
        actual_txid: String,
        actual_vout: i64,
        expected_txid: String,
        expected_vout: i64,
    },
    #[error("no output pays the destination script {0}")]
    MissingDestinationOutput(String),
    #[error("destination output pays {actual} atomic, expected exactly {expected}")]
    DestinationAmount { actual: u64, expected: u64 },
    #[error("no output pays the expected change script {0}")]
    MissingChangeOutput(String),
    #[error("change output pays {actual} atomic, expected exactly {expected}")]
    ChangeAmount { actual: u64, expected: u64 },
    #[error("transaction contains an unexpected output paying {value} to script {script}")]
    UnexpectedOutput { value: u64, script: String },
    #[error(
        "value is not conserved: inputs {total_in} != payout {payout} + change {change} + fee {fee}"
    )]
    ValueNotConserved {
        total_in: u64,
        payout: u64,
        change: u64,
        fee: u64,
    },
    #[error("a change output is present but the plan expects none")]
    UnexpectedChange,
    #[error("signing altered the transaction outputs — refusing to broadcast")]
    OutputsAlteredBySigning,
}

/// Verifies a decoded transaction against the plan. Returns `Ok(())` only if
/// every check passes; there is no partial-confidence result.
pub fn verify_payout_tx(tx: &DecodedTx, plan: &PayoutPlan) -> Result<(), VerifyError> {
    // --- inputs: exactly the reserved outpoints, in committed order ---
    if tx.inputs.len() != plan.inputs.len() {
        return Err(VerifyError::InputCount {
            expected: plan.inputs.len(),
            actual: tx.inputs.len(),
        });
    }
    for (i, (actual, expected)) in tx.inputs.iter().zip(plan.inputs.iter()).enumerate() {
        if actual.txid_hex != expected.txid_hex || actual.vout != expected.vout {
            return Err(VerifyError::InputMismatch {
                position: i,
                actual_txid: actual.txid_hex.clone(),
                actual_vout: actual.vout,
                expected_txid: expected.txid_hex.clone(),
                expected_vout: expected.vout,
            });
        }
    }

    // --- outputs: exact count ---
    let expected_outputs = if plan.change_atomic > 0 { 2 } else { 1 };
    if tx.outputs.len() != expected_outputs {
        return Err(VerifyError::OutputCount {
            expected: expected_outputs,
            actual: tx.outputs.len(),
        });
    }

    // --- destination: exact script, exact amount ---
    let dest_script = p2pkh_script_hex(&plan.dest_hash160);
    let dest = tx
        .outputs
        .iter()
        .find(|o| o.script_pubkey_hex.eq_ignore_ascii_case(&dest_script))
        .ok_or_else(|| VerifyError::MissingDestinationOutput(dest_script.clone()))?;
    if dest.value_atomic != plan.payout_atomic {
        return Err(VerifyError::DestinationAmount {
            actual: dest.value_atomic,
            expected: plan.payout_atomic,
        });
    }

    // --- change: present iff planned, to a vault-owned script, exact ---
    let change_script = plan.change_hash160.map(|h| p2pkh_script_hex(&h));
    if plan.change_atomic > 0 {
        let script = change_script.clone().ok_or(VerifyError::UnexpectedChange)?;
        let change = tx
            .outputs
            .iter()
            .find(|o| o.script_pubkey_hex.eq_ignore_ascii_case(&script) && !std::ptr::eq(*o, dest))
            .ok_or_else(|| VerifyError::MissingChangeOutput(script.clone()))?;
        if change.value_atomic != plan.change_atomic {
            return Err(VerifyError::ChangeAmount {
                actual: change.value_atomic,
                expected: plan.change_atomic,
            });
        }
    }

    // --- nothing else may be present ---
    for o in &tx.outputs {
        let is_dest = o.script_pubkey_hex.eq_ignore_ascii_case(&dest_script);
        let is_change = change_script
            .as_ref()
            .is_some_and(|s| o.script_pubkey_hex.eq_ignore_ascii_case(s));
        if !is_dest && !is_change {
            return Err(VerifyError::UnexpectedOutput {
                value: o.value_atomic,
                script: o.script_pubkey_hex.clone(),
            });
        }
    }

    // --- conservation: inputs == payout + change + fee, exactly ---
    let total_in: u64 = plan.inputs.iter().map(|u| u.amount_atomic).sum();
    let accounted = plan
        .payout_atomic
        .saturating_add(plan.change_atomic)
        .saturating_add(plan.fee_atomic);
    if total_in != accounted {
        return Err(VerifyError::ValueNotConserved {
            total_in,
            payout: plan.payout_atomic,
            change: plan.change_atomic,
            fee: plan.fee_atomic,
        });
    }

    Ok(())
}

/// Confirms that signing changed nothing but the scriptSigs: the outputs and
/// outpoints of the signed transaction must be identical to the unsigned
/// one. Guards against a wallet that "helpfully" adds a change output or
/// re-orders anything.
pub fn verify_signing_preserved_outputs(
    unsigned: &DecodedTx,
    signed: &DecodedTx,
) -> Result<(), VerifyError> {
    if unsigned.outputs != signed.outputs {
        return Err(VerifyError::OutputsAlteredBySigning);
    }
    if unsigned.inputs != signed.inputs {
        return Err(VerifyError::OutputsAlteredBySigning);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: [u8; 20] = [0xAA; 20];
    const CHANGE: [u8; 20] = [0xBB; 20];
    const FOREIGN: [u8; 20] = [0xCC; 20];

    fn utxo(seed: u8, vout: i64, amount: u64) -> VaultUtxo {
        let txid = [seed; 32];
        VaultUtxo {
            txid,
            txid_hex: crate::glc::hex::encode(&txid),
            vout,
            amount_atomic: amount,
            script_pubkey_hex: p2pkh_script_hex(&CHANGE),
            confirmations: 6,
        }
    }

    fn plan() -> PayoutPlan {
        PayoutPlan {
            dest_hash160: DEST,
            payout_atomic: 100_000,
            change_hash160: Some(CHANGE),
            change_atomic: 880_000,
            fee_atomic: 20_000,
            inputs: vec![utxo(1, 0, 1_000_000)],
        }
    }

    fn good_tx(p: &PayoutPlan) -> DecodedTx {
        let mut outputs = vec![DecodedOutput {
            value_atomic: p.payout_atomic,
            script_pubkey_hex: p2pkh_script_hex(&p.dest_hash160),
        }];
        if p.change_atomic > 0 {
            outputs.push(DecodedOutput {
                value_atomic: p.change_atomic,
                script_pubkey_hex: p2pkh_script_hex(&p.change_hash160.unwrap()),
            });
        }
        DecodedTx {
            txid_hex: "ab".repeat(32),
            inputs: p
                .inputs
                .iter()
                .map(|u| DecodedInput {
                    txid_hex: u.txid_hex.clone(),
                    vout: u.vout,
                })
                .collect(),
            outputs,
        }
    }

    #[test]
    fn accepts_a_correct_transaction() {
        let p = plan();
        verify_payout_tx(&good_tx(&p), &p).unwrap();
    }

    #[test]
    fn accepts_a_correct_no_change_transaction() {
        let mut p = plan();
        p.change_atomic = 0;
        p.change_hash160 = None;
        p.fee_atomic = 900_000;
        verify_payout_tx(&good_tx(&p), &p).unwrap();
    }

    #[test]
    fn rejects_wrong_destination_amount() {
        let p = plan();
        let mut tx = good_tx(&p);
        tx.outputs[0].value_atomic += 1;
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::DestinationAmount { .. }
        ));
    }

    #[test]
    fn rejects_a_payout_redirected_to_another_address() {
        let p = plan();
        let mut tx = good_tx(&p);
        tx.outputs[0].script_pubkey_hex = p2pkh_script_hex(&FOREIGN);
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::MissingDestinationOutput(_)
        ));
    }

    #[test]
    fn rejects_change_redirected_to_a_non_vault_address() {
        let p = plan();
        let mut tx = good_tx(&p);
        tx.outputs[1].script_pubkey_hex = p2pkh_script_hex(&FOREIGN);
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::MissingChangeOutput(_)
        ));
    }

    #[test]
    fn rejects_wrong_change_amount() {
        let p = plan();
        let mut tx = good_tx(&p);
        tx.outputs[1].value_atomic -= 1;
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::ChangeAmount { .. }
        ));
    }

    #[test]
    fn rejects_an_extra_output_even_when_the_intended_ones_are_correct() {
        let p = plan();
        let mut tx = good_tx(&p);
        tx.outputs.push(DecodedOutput {
            value_atomic: 1,
            script_pubkey_hex: p2pkh_script_hex(&FOREIGN),
        });
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::OutputCount {
                expected: 2,
                actual: 3
            }
        ));
    }

    #[test]
    fn rejects_a_surprise_change_output_when_none_was_planned() {
        let mut p = plan();
        p.change_atomic = 0;
        p.change_hash160 = None;
        p.fee_atomic = 900_000;
        let mut tx = good_tx(&p);
        tx.outputs.push(DecodedOutput {
            value_atomic: 500_000,
            script_pubkey_hex: p2pkh_script_hex(&CHANGE),
        });
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::OutputCount {
                expected: 1,
                actual: 2
            }
        ));
    }

    #[test]
    fn rejects_substituted_or_reordered_inputs() {
        let p = plan();
        let mut tx = good_tx(&p);
        tx.inputs[0].vout = 9;
        assert!(matches!(
            verify_payout_tx(&tx, &p).unwrap_err(),
            VerifyError::InputMismatch { .. }
        ));

        let mut tx2 = good_tx(&p);
        tx2.inputs.push(DecodedInput {
            txid_hex: "ff".repeat(32),
            vout: 0,
        });
        assert!(matches!(
            verify_payout_tx(&tx2, &p).unwrap_err(),
            VerifyError::InputCount { .. }
        ));
    }

    #[test]
    fn rejects_a_plan_whose_value_is_not_conserved() {
        let mut p = plan();
        p.fee_atomic += 1; // now inputs != payout + change + fee
        assert!(matches!(
            verify_payout_tx(&good_tx(&p), &p).unwrap_err(),
            VerifyError::ValueNotConserved { .. }
        ));
    }

    #[test]
    fn detects_outputs_altered_during_signing() {
        let p = plan();
        let unsigned = good_tx(&p);
        let mut signed = unsigned.clone();
        signed.outputs[0].value_atomic -= 1;
        assert_eq!(
            verify_signing_preserved_outputs(&unsigned, &signed).unwrap_err(),
            VerifyError::OutputsAlteredBySigning
        );
        // Identical outputs/inputs are fine even if the txid string differs
        // (it will, once witnesses/scriptSigs are filled in).
        let mut ok = unsigned.clone();
        ok.txid_hex = "cd".repeat(32);
        verify_signing_preserved_outputs(&unsigned, &ok).unwrap();
    }
}
