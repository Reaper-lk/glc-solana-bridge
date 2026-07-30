//! Fee policy and deterministic coin selection (Phase 6, ADR-0013).
//!
//! # Owner decision D3: the vault absorbs the fee
//!
//! The user receives **exactly** the burned amount — the payout output is
//! always `amount_atomic`, never reduced. The fee is therefore funded by the
//! vault's own inputs and comes out of the change, which makes the selection
//! target `amount + fee` rather than `amount`. A shortfall is
//! `AwaitingFunds`, never a partial payment.
//!
//! # Owner decision D4: the fee rate is configured, never estimated
//!
//! Goldcoin's fee estimators are unusable on regtest — verified: both
//! `estimatefee 6` and `estimatesmartfee 6` return `-1`
//! (docs/goldcoin-rpc-notes.md). There is no silent default; the operator
//! must configure a rate explicitly.

use crate::glc::withdrawal_db::VaultUtxo;

/// Serialized size contributions, in bytes, for a P2PKH transaction. These
/// are the standard Bitcoin-lineage sizes; Goldcoin inherits the same
/// transaction serialization.
const TX_OVERHEAD_BYTES: u64 = 10;
/// A signed P2PKH input: 32 txid + 4 vout + 1 script len + ~107 scriptSig
/// + 4 sequence.
const INPUT_BYTES: u64 = 148;
/// A P2PKH output: 8 value + 1 script len + 25 script.
const OUTPUT_BYTES: u64 = 34;

/// Estimated serialized size of a payout with the given shape.
pub fn estimated_size_bytes(num_inputs: u64, num_outputs: u64) -> u64 {
    TX_OVERHEAD_BYTES + INPUT_BYTES * num_inputs + OUTPUT_BYTES * num_outputs
}

/// Fee for a given shape, at a configured rate in atomic units per 1000
/// bytes. Rounds UP, so an under-paying transaction is never produced.
pub fn fee_for(num_inputs: u64, num_outputs: u64, fee_rate_per_kb: u64) -> u64 {
    let size = estimated_size_bytes(num_inputs, num_outputs);
    size.saturating_mul(fee_rate_per_kb).div_ceil(1000)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub inputs: Vec<VaultUtxo>,
    pub fee_atomic: u64,
    /// 0 means no change output is created.
    pub change_atomic: u64,
    pub total_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    /// Not enough spendable value to cover `amount + fee`.
    Insufficient { required: u64, available: u64 },
    /// Would need more inputs than the configured cap.
    TooManyInputs { needed: usize, max: usize },
}

/// Deterministic coin selection.
///
/// `candidates` must already be ordered by `(amount DESC, txid_hex ASC,
/// vout ASC)` — `Db::available_utxos` guarantees exactly that — so the
/// result is reproducible on any replay and auditable after the fact.
///
/// Strategy, in order:
/// 1. an exact match for `amount + fee(1 input, 1 output)` — spends a UTXO
///    whole with no change at all;
/// 2. the *smallest* single UTXO that covers the target, minimising change;
/// 3. greedy largest-first accumulation, recomputing the fee as each input
///    is added (every extra input costs ~148 bytes).
///
/// Change below `dust_threshold` is never created as an output: it is added
/// to the fee instead, because a sub-dust output is economically unspendable
/// and would permanently strand vault value.
pub fn select(
    candidates: &[VaultUtxo],
    amount_atomic: u64,
    fee_rate_per_kb: u64,
    dust_threshold: u64,
    max_inputs: usize,
) -> Result<Selection, SelectionError> {
    let available: u64 = candidates.iter().map(|u| u.amount_atomic).sum();

    // (1) exact match, single input, single output (no change).
    let no_change_fee = fee_for(1, 1, fee_rate_per_kb);
    let exact_target = amount_atomic.saturating_add(no_change_fee);
    if let Some(u) = candidates.iter().find(|u| u.amount_atomic == exact_target) {
        return Ok(Selection {
            inputs: vec![u.clone()],
            fee_atomic: no_change_fee,
            change_atomic: 0,
            total_in: u.amount_atomic,
        });
    }

    // (2) smallest single covering UTXO (two outputs: payout + change).
    let two_out_fee = fee_for(1, 2, fee_rate_per_kb);
    let target_2 = amount_atomic.saturating_add(two_out_fee);
    let smallest_covering = candidates
        .iter()
        .filter(|u| u.amount_atomic >= target_2)
        .min_by(|a, b| {
            a.amount_atomic
                .cmp(&b.amount_atomic)
                .then_with(|| a.txid_hex.cmp(&b.txid_hex))
                .then_with(|| a.vout.cmp(&b.vout))
        });
    if let Some(u) = smallest_covering {
        return Ok(finalize(
            vec![u.clone()],
            amount_atomic,
            fee_rate_per_kb,
            dust_threshold,
        ));
    }

    // (3) greedy largest-first.
    let mut acc: Vec<VaultUtxo> = Vec::new();
    let mut total: u64 = 0;
    for u in candidates {
        acc.push(u.clone());
        total = total.saturating_add(u.amount_atomic);
        let fee = fee_for(acc.len() as u64, 2, fee_rate_per_kb);
        if total >= amount_atomic.saturating_add(fee) {
            if acc.len() > max_inputs {
                return Err(SelectionError::TooManyInputs {
                    needed: acc.len(),
                    max: max_inputs,
                });
            }
            return Ok(finalize(
                acc,
                amount_atomic,
                fee_rate_per_kb,
                dust_threshold,
            ));
        }
        if acc.len() > max_inputs {
            return Err(SelectionError::TooManyInputs {
                needed: acc.len(),
                max: max_inputs,
            });
        }
    }

    Err(SelectionError::Insufficient {
        required: amount_atomic.saturating_add(fee_for(
            candidates.len().max(1) as u64,
            2,
            fee_rate_per_kb,
        )),
        available,
    })
}

/// Computes the final fee/change split for a chosen input set, folding
/// sub-dust change into the fee.
fn finalize(
    inputs: Vec<VaultUtxo>,
    amount_atomic: u64,
    fee_rate_per_kb: u64,
    dust_threshold: u64,
) -> Selection {
    let total_in: u64 = inputs.iter().map(|u| u.amount_atomic).sum();
    let n = inputs.len() as u64;

    let fee_with_change = fee_for(n, 2, fee_rate_per_kb);
    let change = total_in
        .saturating_sub(amount_atomic)
        .saturating_sub(fee_with_change);

    if change == 0 {
        // Exactly covered with a two-output fee: drop the change output and
        // let the (smaller, one-output) transaction pay the remainder as fee.
        let fee = total_in.saturating_sub(amount_atomic);
        return Selection {
            inputs,
            fee_atomic: fee,
            change_atomic: 0,
            total_in,
        };
    }
    if change < dust_threshold {
        // Never create an unspendable output: the dust becomes fee.
        let fee = total_in.saturating_sub(amount_atomic);
        return Selection {
            inputs,
            fee_atomic: fee,
            change_atomic: 0,
            total_in,
        };
    }
    Selection {
        inputs,
        fee_atomic: fee_with_change,
        change_atomic: change,
        total_in,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(seed: u8, vout: i64, amount: u64) -> VaultUtxo {
        let txid = [seed; 32];
        VaultUtxo {
            txid,
            txid_hex: crate::glc::hex::encode(&txid),
            vout,
            amount_atomic: amount,
            script_pubkey_hex: "76a914".to_string() + &"11".repeat(20) + "88ac",
            confirmations: 10,
        }
    }

    /// `available_utxos` returns this order; the tests mirror it so they
    /// exercise the real input ordering.
    fn sorted(mut v: Vec<VaultUtxo>) -> Vec<VaultUtxo> {
        v.sort_by(|a, b| {
            b.amount_atomic
                .cmp(&a.amount_atomic)
                .then_with(|| a.txid_hex.cmp(&b.txid_hex))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        v
    }

    const RATE: u64 = 10_000; // atomic units per KB
    const DUST: u64 = 5_400;
    const MAX_IN: usize = 20;

    #[test]
    fn fee_grows_with_inputs_and_rounds_up() {
        assert_eq!(estimated_size_bytes(1, 2), 10 + 148 + 68);
        assert!(fee_for(2, 2, RATE) > fee_for(1, 2, RATE));
        // 226 bytes * 1 per KB = 0.226 -> rounds UP to 1, never 0.
        assert_eq!(fee_for(1, 2, 1), 1);
    }

    #[test]
    fn exact_match_spends_one_utxo_with_no_change() {
        let fee = fee_for(1, 1, RATE);
        let target = 100_000 + fee;
        let c = sorted(vec![utxo(1, 0, target), utxo(2, 0, 999_999)]);
        let s = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        assert_eq!(s.inputs.len(), 1);
        assert_eq!(s.inputs[0].amount_atomic, target);
        assert_eq!(s.change_atomic, 0, "exact match creates no change");
        assert_eq!(s.fee_atomic, fee);
        assert_eq!(s.total_in, s.fee_atomic + 100_000);
    }

    #[test]
    fn prefers_the_smallest_covering_utxo_to_minimise_change() {
        let c = sorted(vec![
            utxo(1, 0, 10_000_000),
            utxo(2, 0, 200_000),
            utxo(3, 0, 5_000_000),
        ]);
        let s = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        assert_eq!(s.inputs.len(), 1);
        assert_eq!(
            s.inputs[0].amount_atomic, 200_000,
            "must pick the smallest covering UTXO, not the largest"
        );
    }

    #[test]
    fn accumulates_greedily_when_no_single_utxo_covers() {
        let c = sorted(vec![
            utxo(1, 0, 60_000),
            utxo(2, 0, 50_000),
            utxo(3, 0, 40_000),
        ]);
        let s = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        assert!(s.inputs.len() >= 2);
        assert!(s.total_in >= 100_000 + s.fee_atomic);
        assert_eq!(s.total_in, 100_000 + s.fee_atomic + s.change_atomic);
    }

    #[test]
    fn vault_absorbs_the_fee_payout_is_always_the_full_amount() {
        // D3: the payout equals the burned amount exactly; the fee is taken
        // from the vault's own inputs, i.e. out of change.
        let c = sorted(vec![utxo(1, 0, 5_000_000)]);
        let amount = 1_000_000;
        let s = select(&c, amount, RATE, DUST, MAX_IN).unwrap();
        assert_eq!(
            s.total_in - s.fee_atomic - s.change_atomic,
            amount,
            "exactly `amount` reaches the destination"
        );
    }

    #[test]
    fn sub_dust_change_is_folded_into_the_fee_never_created_as_an_output() {
        let base_fee = fee_for(1, 2, RATE);
        // Leave 1 unit less than dust as change.
        let total = 100_000 + base_fee + (DUST - 1);
        let c = sorted(vec![utxo(1, 0, total)]);
        let s = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        assert_eq!(s.change_atomic, 0, "no dust output is ever created");
        assert_eq!(
            s.fee_atomic,
            total - 100_000,
            "the dust is absorbed into the fee"
        );
        assert_eq!(s.total_in - s.fee_atomic, 100_000);
    }

    #[test]
    fn change_at_exactly_the_dust_threshold_is_kept() {
        let base_fee = fee_for(1, 2, RATE);
        let total = 100_000 + base_fee + DUST;
        let c = sorted(vec![utxo(1, 0, total)]);
        let s = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        assert_eq!(s.change_atomic, DUST, "dust threshold is inclusive-keep");
    }

    #[test]
    fn insufficient_funds_are_reported_not_partially_paid() {
        let c = sorted(vec![utxo(1, 0, 10_000), utxo(2, 0, 5_000)]);
        let err = select(&c, 1_000_000, RATE, DUST, MAX_IN).unwrap_err();
        match err {
            SelectionError::Insufficient { available, .. } => assert_eq!(available, 15_000),
            other => panic!("expected Insufficient, got {other:?}"),
        }
    }

    #[test]
    fn empty_candidate_set_is_insufficient() {
        assert!(matches!(
            select(&[], 1, RATE, DUST, MAX_IN).unwrap_err(),
            SelectionError::Insufficient { .. }
        ));
    }

    #[test]
    fn respects_the_max_inputs_cap() {
        let c = sorted((0..10).map(|i| utxo(i as u8, 0, 10_000)).collect());
        let err = select(&c, 90_000, RATE, DUST, 3).unwrap_err();
        assert!(matches!(err, SelectionError::TooManyInputs { max: 3, .. }));
    }

    #[test]
    fn selection_is_deterministic_across_repeated_runs() {
        let c = sorted(vec![
            utxo(3, 1, 500_000),
            utxo(1, 0, 500_000),
            utxo(2, 7, 500_000),
        ]);
        let a = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        let b = select(&c, 100_000, RATE, DUST, MAX_IN).unwrap();
        assert_eq!(a, b);
        // Equal amounts must tie-break on (txid_hex, vout), deterministically.
        assert_eq!(a.inputs[0].txid_hex, crate::glc::hex::encode(&[1u8; 32]));
    }

    #[test]
    fn conservation_holds_for_every_successful_selection() {
        for amount in [1u64, 999, 100_000, 1_000_000, 7_777_777] {
            let c = sorted(vec![
                utxo(1, 0, 4_000_000),
                utxo(2, 0, 3_000_000),
                utxo(3, 0, 2_000_000),
            ]);
            if let Ok(s) = select(&c, amount, RATE, DUST, MAX_IN) {
                assert_eq!(
                    s.total_in,
                    amount + s.fee_atomic + s.change_atomic,
                    "inputs must equal payout + fee + change exactly"
                );
                assert!(s.fee_atomic > 0, "a fee is always paid");
            }
        }
    }
}
