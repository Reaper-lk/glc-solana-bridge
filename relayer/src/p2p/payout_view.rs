//! What a signer will and will not sign for a vault payout (Phase 7e,
//! ADR-0017).
//!
//! This is where the payout path's trust boundary lives, and it is the exact
//! analogue of [`super::view::DbLocalView`] on the mint side: the answer is
//! derived from **this** validator's persisted observations, never from
//! anything the requester supplied.
//!
//! # Three independent things must agree
//!
//! 1. the **canonical intent** this validator recomputes (ADR-0015);
//! 2. the **unsigned transaction** this validator's own executor built from
//!    its own UTXO view;
//! 3. the **quorum attempt** this validator has itself designated.
//!
//! Any disagreement is a refusal, and a refusal is an alarm — it means two
//! operators' independent views of the Goldcoin chain have diverged.
//!
//! # Why amounts come only from local state
//!
//! The legacy sighash does **not** commit to input amounts (ADR-0017 §2.5,
//! verified on a real node): signing with falsified amounts produces a
//! byte-identical, network-accepted transaction. A signature is therefore no
//! evidence whatsoever about what an input was worth.
//!
//! So the `prevtxs` this module hands to its own Goldcoin node are built
//! **entirely** from rows in this validator's own `vault_utxos` table. The
//! request contributes the withdrawal index, the quorum attempt, and two
//! blobs that are only ever *compared*. It contributes no amount, no script,
//! and no outpoint that is used as-is.

use thiserror::Error;

use crate::glc::db::Db;
use crate::glc::rpc::PrevTx;
use crate::glc::withdrawal_db::WithdrawalState;
use crate::withdrawal::multisig::{extract_signatures, MultisigError, Transaction};
use crate::withdrawal::vault::MultisigVault;

/// Why a payout signing request was refused.
///
/// Every variant is an **alarm**: this validator's view of the Goldcoin
/// chain disagrees with a peer's, which is a bug, an outage, or an attack.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PayoutRefusal {
    #[error("this validator has no record of withdrawal {0}")]
    UnknownWithdrawal(u64),
    #[error(
        "withdrawal {index} is in state {state} — this validator will not sign a payout outside \
         the building/signing window"
    )]
    NotSignable { index: u64, state: String },
    #[error(
        "requester asked for quorum attempt {requested}, this validator has designated {local} — \
         refusing to sign for a designation it has not made (ADR-0015)"
    )]
    QuorumAttemptMismatch { requested: u32, local: u32 },
    #[error(
        "the requested payout intent is not what this validator independently recomputes for \
         withdrawal {index}"
    )]
    IntentMismatch { index: u64 },
    #[error(
        "the requested unsigned transaction is not the one this validator's own executor built \
         for withdrawal {index}"
    )]
    UnsignedTxMismatch { index: u64 },
    #[error("this validator is not a designated signer for withdrawal {index} attempt {attempt}")]
    NotDesignated { index: u64, attempt: u32 },
    #[error("integrity safeguard halted withdrawal {index}: {reason}")]
    IntegrityHalted { index: u64, reason: String },
    #[error("local Goldcoin node could not produce a partial signature: {0}")]
    SigningFailed(String),
    #[error("local partial signature is unusable: {0}")]
    MalformedPartial(String),
    #[error("withdrawal index {0} is out of range")]
    IndexOutOfRange(u64),
}

/// What this validator will contribute, once it agrees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutPartial {
    /// This signer's vault key (compressed secp256k1) — the one that must
    /// appear in the redeem script. A different key from the ed25519
    /// federation identity, in a different cryptosystem.
    pub vault_pubkey: [u8; 33],
    /// One DER signature per input, in input order.
    pub signatures: Vec<Vec<u8>>,
}

/// The Goldcoin RPC surface a payout signer needs.
///
/// A trait so the decision logic is testable without a node, mirroring
/// `PayoutRpc` and `SolanaRpc`. In production this is backed by **this
/// signer's own** Goldcoin node: sharing the relayer's node would mean
/// inheriting the requester's view, which defeats the entire purpose
/// (ADR-0017 E2).
pub trait PartialSigner {
    /// Signs with **this signer's single vault key only**, returning the
    /// partially-signed transaction hex.
    ///
    /// A partial M-of-N signature legitimately returns `complete: false`
    /// with `Operation not valid with the current stack size` — that is the
    /// expected result, not a failure (ADR-0017 §2.3).
    fn sign_partial(
        &self,
        unsigned_tx_hex: &str,
        prevtxs: &[PrevTx],
    ) -> impl std::future::Future<Output = Result<String, String>> + Send;
}

/// A validator's payout signing view, over its own database and its own node.
pub struct PayoutView<S: PartialSigner> {
    vault: MultisigVault,
    /// This signer's position in the vault's ordered signer list.
    vault_signer_index: u8,
    signer: S,
}

impl<S: PartialSigner> PayoutView<S> {
    /// Constructs the view, **failing closed** if this signer's configured
    /// vault position does not resolve to a key actually in the vault
    /// (ADR-0017 E1).
    pub fn new(vault: MultisigVault, vault_signer_index: u8, signer: S) -> Result<Self, String> {
        if vault_signer_index as usize >= vault.signer_pubkeys.len() {
            return Err(format!(
                "configured vault signer index {vault_signer_index} is out of range for a vault \
                 with {} signers — refusing to start",
                vault.signer_pubkeys.len()
            ));
        }
        Ok(PayoutView {
            vault,
            vault_signer_index,
            signer,
        })
    }

    pub fn vault_pubkey(&self) -> [u8; 33] {
        self.vault.signer_pubkeys[self.vault_signer_index as usize]
    }

    /// Decides whether to sign, and if so produces the partial.
    ///
    /// The order of checks is deliberate: cheap local state first, then the
    /// integrity safeguard, then the two byte-for-byte comparisons, and only
    /// then the node round-trip. An attacker cannot make this validator do
    /// expensive work by sending nonsense.
    pub async fn sign_payout(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        now_unix: i64,
    ) -> Result<PayoutPartial, PayoutRefusal> {
        let index = i64::try_from(withdrawal_index)
            .map_err(|_| PayoutRefusal::IndexOutOfRange(withdrawal_index))?;

        let w = db
            .get_withdrawal(index)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: withdrawal_index,
                reason: e.to_string(),
            })?
            .ok_or(PayoutRefusal::UnknownWithdrawal(withdrawal_index))?;

        // Only inside the signing window. Signing a Broadcast or Completed
        // payout could only serve a replay or a conflicting spend.
        if !matches!(
            w.state,
            WithdrawalState::Building | WithdrawalState::Signing
        ) {
            return Err(PayoutRefusal::NotSignable {
                index: withdrawal_index,
                state: w.state.as_str().to_string(),
            });
        }

        // The reload-and-recompute safeguard. On drift this HALTS the
        // withdrawal as an integrity anomaly rather than returning anything.
        let signable = db
            .verify_and_load_signable_payout(index, now_unix)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: withdrawal_index,
                reason: e.to_string(),
            })?;

        // ADR-0015: a superseded designation is a DIFFERENT thing to sign
        // for, because the txid depends on which quorum signs.
        if signable.quorum_attempt != quorum_attempt {
            return Err(PayoutRefusal::QuorumAttemptMismatch {
                requested: quorum_attempt,
                local: signable.quorum_attempt,
            });
        }

        // This validator must actually be in the designated quorum. Signing
        // when not designated would produce a signature that cannot be used
        // and, worse, could be collected into a quorum nobody designated.
        if !signable.quorum_indices.contains(&self.vault_signer_index) {
            return Err(PayoutRefusal::NotDesignated {
                index: withdrawal_index,
                attempt: quorum_attempt,
            });
        }

        // The two byte-for-byte comparisons. `intent_bytes` is the FRESHLY
        // RECOMPUTED intent, not the stored blob.
        if signable.intent_bytes != canonical_intent {
            return Err(PayoutRefusal::IntentMismatch {
                index: withdrawal_index,
            });
        }
        if signable.unsigned_tx_hex != unsigned_tx_hex {
            return Err(PayoutRefusal::UnsignedTxMismatch {
                index: withdrawal_index,
            });
        }

        // D4: prevtxs are built ENTIRELY from local rows. Nothing about the
        // inputs — outpoint or script — comes from the request.
        //
        // Note `PrevTx` carries no amount at all. That is not an omission:
        // the legacy sighash does not commit to input amounts (ADR-0017
        // §2.5), so an amount here would influence nothing while creating a
        // channel for a requester-supplied value to appear trusted. The
        // amounts that DO matter were already checked against this
        // validator's own `vault_utxos` rows inside
        // `verify_and_load_signable_payout`, which halts on any drift.
        let prevtxs: Vec<PrevTx> = signable
            .inputs
            .iter()
            .map(|u| PrevTx {
                txid: u.txid_hex.clone(),
                vout: u.vout,
                script_pub_key: u.script_pubkey_hex.clone(),
                redeem_script: self.vault.redeem_script_hex(),
            })
            .collect();

        // Sign on THIS signer's own node, with THIS signer's single key.
        let partial_hex = self
            .signer
            .sign_partial(&signable.unsigned_tx_hex, &prevtxs)
            .await
            .map_err(PayoutRefusal::SigningFailed)?;

        let partial = Transaction::parse_hex(&partial_hex)
            .map_err(|e: MultisigError| PayoutRefusal::MalformedPartial(e.to_string()))?;
        let signatures = extract_signatures(&partial, &self.vault.redeem_script)
            .map_err(|e| PayoutRefusal::MalformedPartial(e.to_string()))?;

        Ok(PayoutPartial {
            vault_pubkey: self.vault_pubkey(),
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::vault::MultisigVault;

    struct NeverCalled;
    impl PartialSigner for NeverCalled {
        async fn sign_partial(&self, _: &str, _: &[PrevTx]) -> Result<String, String> {
            panic!("the node must not be reached for a request refused on local state");
        }
    }

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

    #[test]
    fn refuses_to_construct_with_a_vault_index_out_of_range() {
        // ADR-0017 E1: fail closed rather than run with a mapping that could
        // route a signing request to the wrong key.
        let err = match PayoutView::new(vault_of(3, 2), 3, NeverCalled) {
            Err(e) => e,
            Ok(_) => panic!("a vault index outside the signer set must be refused"),
        };
        assert!(err.contains("out of range"), "{err}");
        assert!(PayoutView::new(vault_of(3, 2), 2, NeverCalled).is_ok());
    }

    #[test]
    fn reports_the_vault_pubkey_at_its_configured_position() {
        let v = vault_of(3, 2);
        for i in 0..3u8 {
            let view = PayoutView::new(v.clone(), i, NeverCalled).unwrap();
            assert_eq!(view.vault_pubkey(), v.signer_pubkeys[i as usize]);
        }
    }
}
