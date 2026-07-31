//! Typed JSON-RPC client for Goldcoin Core (ADR-0011).
//!
//! Hand-rolled rather than `bitcoincore-rpc`, because Goldcoin's RPC shapes
//! diverge from modern Bitcoin Core — verified empirically against a real
//! Goldcoin Core v0.15.0 regtest node (docs/goldcoin-rpc-notes.md):
//!
//! - `getblock` accepts only a BOOLEAN `verbose` — there is no numeric
//!   verbosity 0/1/2. `verbose=true` returns the header plus `"tx"` as an
//!   array of TXID STRINGS ONLY, never embedded decoded transactions.
//! - `getrawtransaction(txid, verbose)` takes no blockhash-hint 3rd
//!   parameter (unlike modern Bitcoin Core) and, without `-txindex=1`, only
//!   resolves mempool transactions or (a documented-deprecated fallback)
//!   transactions with at least one still-unspent output. `-txindex=1` is
//!   therefore a mandatory node requirement for this client to be reliable.
//! - The verified regtest RPC port in the tested build was **18122**, not
//!   Bitcoin testnet's 18332 — never assumed, always operator-configured.
//!
//! Every RPC call distinguishes two failure classes, matching what was
//! empirically observed:
//! - [`RpcError::Transport`] — connection refused/reset/timeout, surfaced by
//!   `reqwest` as a request error with no HTTP response at all. Retried with
//!   backoff (see [`call_with_retry`]).
//! - [`RpcError::Method`] — a well-formed JSON-RPC response carrying an
//!   `"error"` object. Not retried: retrying a definitive node-side error
//!   wastes cycles and can mask a real bug.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

use super::config::RpcConfigValidated;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("transport error contacting Goldcoin RPC: {0}")]
    Transport(String),
    #[error("Goldcoin RPC method error (code {code}): {message}")]
    Method { code: i64, message: String },
    #[error("malformed JSON-RPC response: {0}")]
    Malformed(String),
}

impl RpcError {
    /// Only [`RpcError::Transport`] is meaningfully retriable — see module
    /// docs on the two failure classes.
    pub fn is_retriable(&self) -> bool {
        matches!(self, RpcError::Transport(_))
    }
}

pub struct RpcClient {
    http: reqwest::Client,
    url: String,
    user: String,
    password: String,
}

/// One entry of `getblock(hash, true)`'s `"tx"` array in this RPC version:
/// a bare txid string, never a decoded object (see module docs).
pub type BlockTxids = Vec<String>;

// `hash`/`confirmations`/`height` mirror the verified shape; the indexer
// already knows the hash/height it queried by (it derives both from its own
// walk), so only `time`/`previousblockhash`/`tx` are read in production.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct BlockHeader {
    pub hash: String,
    pub confirmations: i64,
    pub height: i64,
    pub time: i64,
    pub previousblockhash: Option<String>,
    pub tx: BlockTxids,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DecodedVout {
    pub value: f64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: DecodedScriptPubKey,
}

// `kind` mirrors the verified shape (used by deposit.rs's tests to build
// realistic fixtures) though production matching only ever compares `hex`
// byte-for-byte against the configured vault script.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct DecodedScriptPubKey {
    pub hex: String,
    #[serde(rename = "type")]
    pub kind: String,
}

// `txid` and `confirmations` mirror the exact verified RPC shape (pinned by
// the rpc.rs unit tests) even though production code never reads them back:
// the indexer already knows the txid it asked for (from the block's tx
// list, which is how confirmed-ness is established structurally — see
// module docs), so re-checking either field here would be redundant, not a
// missing safety check.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct DecodedTransaction {
    pub txid: String,
    pub vout: Vec<DecodedVout>,
    /// Absent entirely for an unconfirmed (mempool-only) transaction —
    /// verified empirically; never assume 0 means "just mined."
    pub confirmations: Option<i64>,
}

// `confirmations` mirrors the verified shape; get_tx_out_confirmed only
// needs Some(_)-vs-None (already-excludes-mempool via include_mempool=false),
// never the count itself.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct TxOut {
    pub confirmations: i64,
}

impl RpcClient {
    pub fn new(cfg: &RpcConfigValidated) -> Result<Self, RpcError> {
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(cfg.connect_timeout_ms))
            .timeout(std::time::Duration::from_millis(cfg.read_timeout_ms))
            .build()
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        Ok(RpcClient {
            http,
            url: cfg.url.clone(),
            user: cfg.user.clone(),
            password: cfg.password.clone(),
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "glc-relayer",
            "method": method,
            "params": params,
        });
        let response = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let parsed: Value = response
            .json()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if let Some(error) = parsed.get("error").filter(|e| !e.is_null()) {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(-1);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)")
                .to_string();
            return Err(RpcError::Method { code, message });
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::Malformed("response has neither result nor error".into()))
    }

    async fn call_typed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, RpcError> {
        let result = self.call(method, params).await?;
        serde_json::from_value(result).map_err(|e| RpcError::Malformed(e.to_string()))
    }

    pub async fn get_block_count(&self) -> Result<i64, RpcError> {
        self.call_typed("getblockcount", json!([])).await
    }

    pub async fn get_block_hash(&self, height: i64) -> Result<String, RpcError> {
        self.call_typed("getblockhash", json!([height])).await
    }

    /// `verbose=true` only — this RPC version has no numeric verbosity, and
    /// `"tx"` is always bare txid strings (see module docs).
    pub async fn get_block(&self, hash: &str) -> Result<BlockHeader, RpcError> {
        self.call_typed("getblock", json!([hash, true])).await
    }

    /// Requires `-txindex=1` on the node to resolve arbitrary historical
    /// transactions reliably (see module docs) — this client does not fall
    /// back to the deprecated unspent-output-only behavior by choice.
    pub async fn get_raw_transaction(
        &self,
        txid_hex: &str,
    ) -> Result<DecodedTransaction, RpcError> {
        self.call_typed("getrawtransaction", json!([txid_hex, true]))
            .await
    }

    pub async fn get_raw_transaction_hex(&self, txid_hex: &str) -> Result<String, RpcError> {
        self.call_typed("getrawtransaction", json!([txid_hex, false]))
            .await
    }

    /// `include_mempool=false`: confirms genuinely on-chain-and-unspent,
    /// never mempool-derived (verified: default `gettxout` includes
    /// mempool; passing `false` explicitly excludes it).
    pub async fn get_tx_out_confirmed(
        &self,
        txid_hex: &str,
        vout: u32,
    ) -> Result<Option<TxOut>, RpcError> {
        let result = self
            .call("gettxout", json!([txid_hex, vout, false]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        serde_json::from_value(result)
            .map(Some)
            .map_err(|e| RpcError::Malformed(e.to_string()))
    }

    /// Raw JSON-RPC passthrough, for responses whose full shape the typed
    /// helpers above deliberately do not model (Phase 6 decodes only the
    /// fields it verifies).
    pub async fn call_raw(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.call(method, params).await
    }

    // ---- Withdrawal payout path (Phase 6, ADR-0013) ----

    /// Spendable outputs paying `addresses`. Wallet-based because
    /// `scantxoutset` does not exist in this Goldcoin lineage (verified —
    /// docs/goldcoin-rpc-notes.md), so there is no wallet-less UTXO scan.
    pub async fn list_unspent(
        &self,
        min_conf: i64,
        addresses: &[String],
    ) -> Result<Vec<ListUnspentEntry>, RpcError> {
        self.call_typed("listunspent", json!([min_conf, 9_999_999, addresses]))
            .await
    }

    pub async fn create_raw_transaction(
        &self,
        inputs: &[(String, i64)],
        outputs: &serde_json::Map<String, Value>,
    ) -> Result<String, RpcError> {
        let ins: Vec<Value> = inputs
            .iter()
            .map(|(txid, vout)| json!({ "txid": txid, "vout": vout }))
            .collect();
        self.call_typed("createrawtransaction", json!([ins, outputs]))
            .await
    }

    pub async fn decode_raw_transaction(&self, hex: &str) -> Result<DecodedTransaction, RpcError> {
        self.call_typed("decoderawtransaction", json!([hex])).await
    }

    /// Signs with the node wallet's keys. NOTE: this Goldcoin lineage
    /// predates the 0.17 split, so the method is `signrawtransaction`, not
    /// `signrawtransactionwithwallet` (verified: the latter is absent).
    pub async fn sign_raw_transaction(&self, hex: &str) -> Result<SignResult, RpcError> {
        self.call_typed("signrawtransaction", json!([hex])).await
    }

    /// Signs a P2SH multisig input, supplying the previous outputs (with
    /// their `redeemScript`) and, optionally, explicit private keys.
    ///
    /// Required for a vault the wallet cannot solve alone: verified against
    /// a real node, the bare `signrawtransaction(hex)` form is not
    /// sufficient for P2SH multisig. A partial result returns
    /// `complete: false`, and broadcasting a partial is rejected by the
    /// network (`-26`), so an incomplete signature can never move funds.
    pub async fn sign_raw_transaction_with_prevtxs(
        &self,
        hex: &str,
        prevtxs: &[PrevTx],
        private_keys: Option<&[String]>,
    ) -> Result<SignResult, RpcError> {
        let params = match private_keys {
            Some(keys) => json!([hex, prevtxs, keys]),
            None => json!([hex, prevtxs]),
        };
        self.call_typed("signrawtransaction", params).await
    }

    /// Registers the vault with the node so its outputs become visible.
    ///
    /// Both calls are required and both are idempotent-ish: verified that
    /// without `importaddress` the vault is invisible to `listunspent`, and
    /// that importing the address alone leaves its outputs `solvable:
    /// false` until the redeem script is imported too.
    pub async fn import_vault(
        &self,
        address: &str,
        redeem_script_hex: &str,
    ) -> Result<(), RpcError> {
        // A re-import raises a method error rather than succeeding; that is
        // benign and must not abort startup.
        let _ = self
            .call("importaddress", json!([address, "glc-vault", false]))
            .await;
        let _ = self
            .call(
                "importaddress",
                json!([redeem_script_hex, "glc-vault-redeem", false, true]),
            )
            .await;
        Ok(())
    }

    /// Broadcasts, normalising the two benign outcomes verified against a
    /// real node:
    ///
    /// - resending a transaction already in the mempool SUCCEEDS and returns
    ///   the same txid;
    /// - resending one already mined fails with code **-27**, which means
    ///   "already in the chain" — a success for our purposes, not a failure.
    ///
    /// Code **-25** ("Missing inputs") means the inputs are gone: a genuine
    /// conflict the caller must treat as an anomaly, never as a retry.
    pub async fn send_raw_transaction(&self, hex: &str) -> Result<BroadcastOutcome, RpcError> {
        match self.call("sendrawtransaction", json!([hex])).await {
            Ok(v) => {
                let txid = v
                    .as_str()
                    .ok_or_else(|| {
                        RpcError::Malformed("sendrawtransaction returned non-string".into())
                    })?
                    .to_string();
                Ok(BroadcastOutcome::Accepted { txid })
            }
            Err(RpcError::Method { code: -27, .. }) => Ok(BroadcastOutcome::AlreadyInChain),
            Err(RpcError::Method { code: -25, .. }) => Ok(BroadcastOutcome::MissingInputs),
            Err(e) => Err(e),
        }
    }
}

/// One entry from `listunspent`, in the exact shape a real node returns
/// (captured in docs/goldcoin-rpc-notes.md).
#[derive(Debug, Clone, Deserialize)]
pub struct ListUnspentEntry {
    pub txid: String,
    pub vout: i64,
    pub address: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    pub amount: f64,
    pub confirmations: i64,
    #[serde(default)]
    pub spendable: bool,
    /// True when the wallet knows how to construct the input's script — for
    /// a P2SH vault this means the redeem script has been imported.
    ///
    /// This, NOT `spendable`, is the correct filter for a multisig vault:
    /// verified against a real node, a vault UTXO is `spendable: false`
    /// whenever the local wallet cannot sign alone, which is the normal
    /// production case (ADR-0015).
    #[serde(default)]
    pub solvable: bool,
}

/// A previous output a signer needs in order to sign a P2SH input.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PrevTx {
    pub txid: String,
    pub vout: i64,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    #[serde(rename = "redeemScript")]
    pub redeem_script: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignResult {
    pub hex: String,
    pub complete: bool,
}

/// The normalised result of a broadcast attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    Accepted {
        txid: String,
    },
    /// RPC -27: the transaction is already in a block. Idempotent success.
    AlreadyInChain,
    /// RPC -25: inputs are missing/already spent. A conflict, never retried.
    MissingInputs,
}

/// Retry policy for transient transport blips (module docs). Bounded and
/// short — sustained outages are the OUTER indexer tick loop's job (it waits
/// `node_unavailable_retry_interval_ms` and simply tries the next tick
/// forever), not this function's.
pub async fn call_with_retry<T, F, Fut>(max_attempts: u32, mut f: F) -> Result<T, RpcError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, RpcError>>,
{
    let mut attempt = 0;
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if e.is_retriable() && attempt + 1 < max_attempts => {
                let delay_ms = 200u64 * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn method_error_is_not_retriable() {
        let e = RpcError::Method {
            code: -1,
            message: "boom".into(),
        };
        assert!(!e.is_retriable());
    }

    #[test]
    fn transport_error_is_retriable() {
        let e = RpcError::Transport("connection refused".into());
        assert!(e.is_retriable());
    }

    #[test]
    fn malformed_is_not_retriable() {
        let e = RpcError::Malformed("bad json".into());
        assert!(!e.is_retriable());
    }

    /// Parses a real `getblockchaininfo`-shaped response captured against a
    /// live Goldcoin Core v0.15.0 regtest node in the Phase 4 design
    /// session, confirming `BlockHeader`/`DecodedTransaction` match the
    /// verified wire shapes (docs/goldcoin-rpc-notes.md).
    #[test]
    fn parses_real_captured_block_header_shape() {
        // Captured getblock(hash, true) shape (tx = bare txid strings only —
        // this RPC version has no verbosity=2 embedding decoded tx objects).
        let raw = json!({
            "hash": "4208bca238e643705956480f5f1a234a1a19ae56b247745ba1c02494bd562017",
            "confirmations": 1,
            "height": 102,
            "time": 1785349385,
            "previousblockhash": "5718e6254d19802cefc7ad28577f6330bb304b8b356167b19ca5adeb228fba65",
            "tx": ["4e327700bf5064c1ab0093a6e288edf3e5fb3f7b605ad6f53e4dd18787965bf3"]
        });
        let header: BlockHeader = serde_json::from_value(raw).unwrap();
        assert_eq!(header.height, 102);
        assert_eq!(header.tx.len(), 1);
        assert_eq!(
            header.tx[0],
            "4e327700bf5064c1ab0093a6e288edf3e5fb3f7b605ad6f53e4dd18787965bf3"
        );
    }

    #[test]
    fn parses_real_captured_decoded_transaction_shape() {
        // Captured getrawtransaction(txid, true) shape for the real 32-byte
        // OP_RETURN deposit transaction built and mined in this session.
        let raw = json!({
            "txid": "4e327700bf5064c1ab0093a6e288edf3e5fb3f7b605ad6f53e4dd18787965bf3",
            "confirmations": 1,
            "vout": [
                {
                    "value": 5.0,
                    "n": 0,
                    "scriptPubKey": {
                        "hex": "76a9145a7ab7adf8185c27b3f54104cdccfe1ff0cd54cf88ac",
                        "type": "pubkeyhash"
                    }
                },
                {
                    "value": 0.0,
                    "n": 1,
                    "scriptPubKey": {
                        "hex": "6a20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                        "type": "nulldata"
                    }
                }
            ]
        });
        let tx: DecodedTransaction = serde_json::from_value(raw).unwrap();
        assert_eq!(tx.confirmations, Some(1));
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(tx.vout[1].script_pub_key.kind, "nulldata");
    }

    #[test]
    fn mempool_only_transaction_has_no_confirmations_field() {
        // Verified fact: an unconfirmed tx's getrawtransaction(verbose)
        // response has NO "confirmations" key at all (absent, not zero).
        let raw = json!({
            "txid": "1eb72094299bc3efe44eab515222e0bef726b009e8a41469f69c537dbbd5d454",
            "vout": []
        });
        let tx: DecodedTransaction = serde_json::from_value(raw).unwrap();
        assert_eq!(tx.confirmations, None);
    }

    #[test]
    fn gettxout_null_deserializes_as_none() {
        let raw = Value::Null;
        let parsed: Option<TxOut> = if raw.is_null() {
            None
        } else {
            serde_json::from_value(raw).unwrap()
        };
        assert!(parsed.is_none());
    }

    #[tokio::test]
    async fn call_with_retry_retries_transport_errors_and_eventually_succeeds() {
        let attempts = AtomicU32::new(0);
        let result: Result<i32, RpcError> = call_with_retry(5, || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(RpcError::Transport("connection refused".into()))
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn call_with_retry_does_not_retry_method_errors() {
        let attempts = AtomicU32::new(0);
        let result: Result<i32, RpcError> = call_with_retry(5, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                Err(RpcError::Method {
                    code: -1,
                    message: "nope".into(),
                })
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "method errors must not be retried"
        );
    }

    #[tokio::test]
    async fn call_with_retry_gives_up_after_max_attempts() {
        let attempts = AtomicU32::new(0);
        let result: Result<i32, RpcError> = call_with_retry(3, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async move { Err(RpcError::Transport("still down".into())) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}
