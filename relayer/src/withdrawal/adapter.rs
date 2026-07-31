//! Real-node implementation of [`PayoutRpc`] over the Goldcoin JSON-RPC
//! client (Phase 6, ADR-0013).
//!
//! Kept separate from the executor so the pipeline stays testable against a
//! mock, exactly as `glc::indexer::GoldcoinRpc` and `solana::rpc::SolanaRpc`
//! are.

use serde_json::json;

use crate::glc::rpc::{BroadcastOutcome, RpcClient, RpcError};
use crate::glc::withdrawal_db::ObservedUtxo;
use crate::withdrawal::builder::{DecodedInput, DecodedOutput, DecodedTx};
use crate::withdrawal::executor::{PayoutRpc, TxStatus};

/// Converts a node-reported GLC amount to atomic units.
///
/// Goldcoin is exactly 8 decimals, verified by boundary testing against a
/// real node (a 9th decimal digit and a half-atomic amount are both
/// rejected with "Invalid amount"). Rounds to absorb IEEE-754 noise in the
/// RPC's JSON number, exactly as the deposit side does.
pub fn glc_to_atomic(value: f64) -> u64 {
    (value * 100_000_000.0).round() as u64
}

pub struct RealPayoutRpc {
    client: RpcClient,
}

impl RealPayoutRpc {
    pub fn new(client: RpcClient) -> Self {
        RealPayoutRpc { client }
    }
}

impl PayoutRpc for RealPayoutRpc {
    async fn list_unspent(
        &self,
        min_conf: i64,
        addresses: &[String],
    ) -> Result<Vec<ObservedUtxo>, RpcError> {
        let entries = self.client.list_unspent(min_conf, addresses).await?;
        entries
            .into_iter()
            // `solvable`, not `spendable`: for a P2SH multisig vault the
            // local wallet usually cannot sign alone, so `spendable` is
            // false for every vault output and filtering on it would make
            // the executor see an empty vault and silently never pay out
            // (verified on a real node — ADR-0015).
            .filter(|e| e.solvable)
            .map(|e| {
                let txid = crate::glc::hex::decode_exact::<32>(&e.txid)
                    .map_err(|err| RpcError::Malformed(err.to_string()))?;
                Ok(ObservedUtxo {
                    txid,
                    vout: e.vout,
                    amount_atomic: glc_to_atomic(e.amount),
                    script_pubkey_hex: e.script_pub_key,
                    confirmations: e.confirmations,
                })
            })
            .collect()
    }

    async fn create_raw_transaction(
        &self,
        inputs: &[(String, i64)],
        outputs: &[(String, u64)],
    ) -> Result<String, RpcError> {
        // The node takes outputs as {address: decimal GLC}. Formatting with
        // exactly 8 decimals keeps the value exact — the node rejects any
        // finer precision.
        let mut map = serde_json::Map::new();
        for (addr, atomic) in outputs {
            let whole = atomic / 100_000_000;
            let frac = atomic % 100_000_000;
            let s = format!("{whole}.{frac:08}");
            map.insert(
                addr.clone(),
                serde_json::Value::Number(
                    serde_json::Number::from_f64(s.parse::<f64>().unwrap()).ok_or_else(|| {
                        RpcError::Malformed(format!("unrepresentable amount {s}"))
                    })?,
                ),
            );
        }
        self.client.create_raw_transaction(inputs, &map).await
    }

    async fn decode_raw_transaction(&self, hex: &str) -> Result<DecodedTx, RpcError> {
        let raw = self
            .client
            .call_raw("decoderawtransaction", json!([hex]))
            .await?;
        let txid = raw
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::Malformed("decoderawtransaction: no txid".into()))?
            .to_string();
        let inputs = raw
            .get("vin")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::Malformed("decoderawtransaction: no vin".into()))?
            .iter()
            .map(|v| {
                Ok(DecodedInput {
                    txid_hex: v
                        .get("txid")
                        .and_then(|t| t.as_str())
                        .ok_or_else(|| RpcError::Malformed("vin without txid".into()))?
                        .to_string(),
                    vout: v
                        .get("vout")
                        .and_then(|t| t.as_i64())
                        .ok_or_else(|| RpcError::Malformed("vin without vout".into()))?,
                })
            })
            .collect::<Result<Vec<_>, RpcError>>()?;
        let outputs = raw
            .get("vout")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::Malformed("decoderawtransaction: no vout".into()))?
            .iter()
            .map(|v| {
                let value = v
                    .get("value")
                    .and_then(|x| x.as_f64())
                    .ok_or_else(|| RpcError::Malformed("vout without value".into()))?;
                let script = v
                    .get("scriptPubKey")
                    .and_then(|s| s.get("hex"))
                    .and_then(|h| h.as_str())
                    .ok_or_else(|| RpcError::Malformed("vout without scriptPubKey.hex".into()))?
                    .to_string();
                Ok(DecodedOutput {
                    value_atomic: glc_to_atomic(value),
                    script_pubkey_hex: script,
                })
            })
            .collect::<Result<Vec<_>, RpcError>>()?;
        Ok(DecodedTx {
            txid_hex: txid,
            inputs,
            outputs,
        })
    }

    async fn sign_raw_transaction(
        &self,
        hex: &str,
        prevtxs: &[crate::glc::rpc::PrevTx],
    ) -> Result<(String, bool), RpcError> {
        let r = self
            .client
            .sign_raw_transaction_with_prevtxs(hex, prevtxs, None)
            .await?;
        Ok((r.hex, r.complete))
    }

    async fn send_raw_transaction(&self, hex: &str) -> Result<BroadcastOutcome, RpcError> {
        self.client.send_raw_transaction(hex).await
    }

    async fn transaction_confirmations(
        &self,
        txid_hex: &str,
    ) -> Result<Option<TxStatus>, RpcError> {
        match self
            .client
            .call_raw("getrawtransaction", json!([txid_hex, true]))
            .await
        {
            Ok(v) => {
                // Verified Goldcoin quirk: a mempool-only transaction has NO
                // `confirmations` field at all (absent, not zero).
                let confirmations = v.get("confirmations").and_then(|c| c.as_i64()).unwrap_or(0);
                let block_hash_hex = v
                    .get("blockhash")
                    .and_then(|b| b.as_str())
                    .map(|s| s.to_string());
                Ok(Some(TxStatus {
                    confirmations,
                    block_hash_hex,
                    block_height: None,
                }))
            }
            // "No such mempool or blockchain transaction" — the node has
            // never seen it.
            Err(RpcError::Method { code: -5, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn block_on_main_chain(&self, block_hash_hex: &str) -> Result<bool, RpcError> {
        match self
            .client
            .call_raw("getblock", json!([block_hash_hex, true]))
            .await
        {
            // Verified Phase 4 fact: an orphaned block reports exactly -1.
            Ok(v) => Ok(v
                .get("confirmations")
                .and_then(|c| c.as_i64())
                .is_some_and(|c| c >= 0)),
            Err(RpcError::Method { code: -5, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glc_to_atomic_matches_the_verified_8_decimal_precision() {
        assert_eq!(glc_to_atomic(1.0), 100_000_000);
        assert_eq!(glc_to_atomic(0.00000001), 1);
        assert_eq!(glc_to_atomic(12345.6789), 1_234_567_890_000);
        // IEEE-754 noise must not shift the atomic value.
        assert_eq!(glc_to_atomic(0.1 + 0.2), 30_000_000);
    }
}
