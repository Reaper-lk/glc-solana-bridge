//! Deterministic P2SH multisig scriptSig assembly (Phase 7e, ADR-0017).
//!
//! # Why this exists in Rust at all
//!
//! Goldcoin 0.17 has **no `combinerawtransaction` and no PSBT**
//! (`goldcoin-rpc-notes.md` §"Distributed multisig signing"). There is no
//! node-side way to merge independently produced partial signatures, so the
//! relayer must assemble the final `scriptSig` itself. Everything the node
//! used to do implicitly is now our responsibility, and is pinned by a
//! golden vector against real node output rather than assumed.
//!
//! # The consensus-critical invariant
//!
//! `OP_CHECKMULTISIG` requires signatures in the **same relative order as
//! the pubkeys in the redeem script**. A wrong order is rejected by
//! consensus (`mandatory-script-verify-flag-failed`), verified on a real
//! node against a separate funded UTXO per ordering.
//!
//! This refines the Phase 7b note "signature order does not matter": that is
//! true of the order signers are *asked* in, but not of the order signatures
//! are *placed* in the scriptSig — the node was sorting them silently, and
//! code that assembles a scriptSig does not get that for free.
//!
//! # What a signature does and does not cover
//!
//! The legacy (non-segwit) sighash does **not** commit to input amounts:
//! signing with deliberately falsified amounts produced a byte-identical
//! transaction that the network accepted. A signature is therefore no
//! evidence at all about what an input was worth, which is why every signer
//! validates amounts against its own UTXO view ([`crate::p2p::payout_view`])
//! and why nothing here trusts a requester-supplied amount.
//!
//! This module is pure: no I/O, no RPC, no clock. It parses a legacy
//! transaction, splices scriptSigs, and computes txids.

use thiserror::Error;

use super::vault::{MultisigVault, COMPRESSED_PUBKEY_LEN};

/// `SIGHASH_ALL`, the only sighash type this bridge produces or accepts.
///
/// Anything else changes which parts of the transaction are committed to —
/// `SIGHASH_NONE` or `SIGHASH_SINGLE` would let outputs be altered after
/// signing, which for a payout means the destination could change.
pub const SIGHASH_ALL: u8 = 0x01;

/// `OP_CHECKMULTISIG`'s well-known off-by-one: it pops one item too many, so
/// every multisig scriptSig begins with a dummy push.
const OP_0: u8 = 0x00;

/// Largest DER-encoded ECDSA signature plus the trailing sighash byte.
const MAX_DER_SIG_LEN: usize = 73;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultisigError {
    #[error("transaction hex is not valid hex")]
    NotHex,
    #[error("transaction is truncated at byte {0}")]
    Truncated(usize),
    #[error("transaction has {0} inputs but signatures were supplied for a different count")]
    InputCountMismatch(usize),
    #[error(
        "signer public key {pubkey_hex} is not present in the vault redeem script — refusing to \
         place a signature that cannot satisfy this vault"
    )]
    SignerNotInVault { pubkey_hex: String },
    #[error(
        "signer {pubkey_hex} contributed {count} signatures for one input; a signer counts once"
    )]
    DuplicateSigner { pubkey_hex: String, count: usize },
    #[error(
        "input {input} has {got} signatures but the vault threshold is {threshold} — refusing to \
         assemble a scriptSig that cannot spend"
    )]
    ThresholdNotMet {
        input: usize,
        got: usize,
        threshold: usize,
    },
    #[error("input {input} has {got} signatures, more than the vault threshold {threshold}")]
    TooManySignatures {
        input: usize,
        got: usize,
        threshold: usize,
    },
    #[error("signature for input {input} from {pubkey_hex} is malformed: {reason}")]
    MalformedSignature {
        input: usize,
        pubkey_hex: String,
        reason: &'static str,
    },
    #[error("signature for input {input} from {pubkey_hex} does not verify over the sighash")]
    SignatureDoesNotVerify { input: usize, pubkey_hex: String },
    #[error("varint at byte {0} is too large for this transaction shape")]
    VarIntTooLarge(usize),
    #[error("transaction has no inputs")]
    NoInputs,
}

// ---------------------------------------------------------------------------
// Minimal legacy transaction parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// A parsed legacy (non-segwit) transaction.
///
/// Deliberately minimal and non-generic: this bridge only ever constructs
/// P2SH-spending, non-witness transactions, and a parser that accepted more
/// shapes than that would be accepting shapes nothing verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MultisigError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(MultisigError::Truncated(self.pos))?;
        if end > self.data.len() {
            return Err(MultisigError::Truncated(self.pos));
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32_le(&mut self) -> Result<u32, MultisigError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64_le(&mut self) -> Result<u64, MultisigError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn varint(&mut self) -> Result<u64, MultisigError> {
        let first = self.take(1)?[0];
        Ok(match first {
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
            0xfe => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64,
            0xff => u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
            n => n as u64,
        })
    }
}

fn put_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Pushes `data` onto a script using the minimal encoding the reference
/// implementation produces. Non-minimal pushes would change the scriptSig
/// bytes and therefore the txid, so this must match exactly.
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x4c);
        out.push(n as u8);
    } else {
        out.push(0x4d);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    }
    out.extend_from_slice(data);
}

impl Transaction {
    pub fn parse(raw: &[u8]) -> Result<Self, MultisigError> {
        let mut c = Cursor { data: raw, pos: 0 };
        let version = c.u32_le()? as i32;

        let n_in = c.varint()?;
        if n_in == 0 {
            // A zero input count is how segwit marks its flag byte. This
            // bridge never builds witness transactions, so rather than
            // silently mis-parsing one, refuse.
            return Err(MultisigError::NoInputs);
        }
        if n_in > 10_000 {
            return Err(MultisigError::VarIntTooLarge(c.pos));
        }
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            let prev_txid: [u8; 32] = c.take(32)?.try_into().unwrap();
            let prev_vout = c.u32_le()?;
            let slen = c.varint()? as usize;
            let script_sig = c.take(slen)?.to_vec();
            let sequence = c.u32_le()?;
            inputs.push(TxInput {
                prev_txid,
                prev_vout,
                script_sig,
                sequence,
            });
        }

        let n_out = c.varint()?;
        if n_out > 10_000 {
            return Err(MultisigError::VarIntTooLarge(c.pos));
        }
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            let value = c.u64_le()?;
            let slen = c.varint()? as usize;
            let script_pubkey = c.take(slen)?.to_vec();
            outputs.push(TxOutput {
                value,
                script_pubkey,
            });
        }

        let lock_time = c.u32_le()?;
        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    pub fn parse_hex(hex_str: &str) -> Result<Self, MultisigError> {
        let raw = crate::glc::hex::decode_vec(hex_str).map_err(|_| MultisigError::NotHex)?;
        Self::parse(&raw)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.version as u32).to_le_bytes());
        put_varint(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prev_txid);
            out.extend_from_slice(&i.prev_vout.to_le_bytes());
            put_varint(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(&i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        put_varint(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            out.extend_from_slice(&o.value.to_le_bytes());
            put_varint(&mut out, o.script_pubkey.len() as u64);
            out.extend_from_slice(&o.script_pubkey);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    pub fn serialize_hex(&self) -> String {
        crate::glc::hex::encode(&self.serialize())
    }

    /// The transaction id: double-SHA256 of the serialization, byte-reversed
    /// for display (`goldcoin-rpc-notes.md` §"txid byte order").
    pub fn txid(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let once = Sha256::digest(self.serialize());
        let twice = Sha256::digest(once);
        let mut out = [0u8; 32];
        out.copy_from_slice(&twice);
        out
    }

    pub fn txid_hex(&self) -> String {
        let mut t = self.txid();
        t.reverse();
        crate::glc::hex::encode(&t)
    }

    /// The legacy `SIGHASH_ALL` digest for one input.
    ///
    /// Every other input's scriptSig is emptied and this input's is replaced
    /// by the redeem script — the standard pre-segwit construction. Note
    /// what is absent: the input's **amount**, which is why a signature
    /// proves nothing about value (ADR-0017 §2.5).
    pub fn sighash_all(&self, input_index: usize, redeem_script: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut tx = self.clone();
        for (i, inp) in tx.inputs.iter_mut().enumerate() {
            inp.script_sig = if i == input_index {
                redeem_script.to_vec()
            } else {
                Vec::new()
            };
        }
        let mut data = tx.serialize();
        data.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());
        let once = Sha256::digest(&data);
        let twice = Sha256::digest(once);
        let mut out = [0u8; 32];
        out.copy_from_slice(&twice);
        out
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// One signer's contribution: its vault public key and one DER signature per
/// input, in input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature {
    pub vault_pubkey: [u8; COMPRESSED_PUBKEY_LEN],
    /// DER-encoded ECDSA signature **including** the trailing sighash byte,
    /// exactly as it appears in a scriptSig.
    pub signatures: Vec<Vec<u8>>,
}

fn hexs(pk: &[u8]) -> String {
    crate::glc::hex::encode(pk)
}

/// Verifies one DER signature against a vault pubkey over an input's sighash.
///
/// A partial is **self-authenticating**: nothing else needs to vouch for it,
/// because a signature that verifies under the expected vault key over the
/// exact sighash could only have been produced by the holder of that key.
/// This is a stronger guarantee than any transport-level attestation, and it
/// is what the assembler relies on.
fn verify_partial(
    input: usize,
    pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
    der_with_hashtype: &[u8],
    sighash: &[u8; 32],
) -> Result<(), MultisigError> {
    let pubkey_hex = hexs(pubkey);
    if der_with_hashtype.is_empty() || der_with_hashtype.len() > MAX_DER_SIG_LEN {
        return Err(MultisigError::MalformedSignature {
            input,
            pubkey_hex,
            reason: "implausible signature length",
        });
    }
    let (der, hashtype) = der_with_hashtype.split_at(der_with_hashtype.len() - 1);
    if hashtype[0] != SIGHASH_ALL {
        return Err(MultisigError::MalformedSignature {
            input,
            pubkey_hex,
            reason: "sighash type is not SIGHASH_ALL",
        });
    }
    let sig =
        libsecp256k1::Signature::parse_der(der).map_err(|_| MultisigError::MalformedSignature {
            input,
            pubkey_hex: hexs(pubkey),
            reason: "not a valid DER ECDSA signature",
        })?;
    let pk = libsecp256k1::PublicKey::parse_compressed(pubkey).map_err(|_| {
        MultisigError::MalformedSignature {
            input,
            pubkey_hex: hexs(pubkey),
            reason: "not a valid compressed secp256k1 public key",
        }
    })?;
    let msg = libsecp256k1::Message::parse(sighash);
    if !libsecp256k1::verify(&msg, &sig, &pk) {
        return Err(MultisigError::SignatureDoesNotVerify {
            input,
            pubkey_hex: hexs(pubkey),
        });
    }
    Ok(())
}

/// Assembles a fully-signed transaction from independently produced partials.
///
/// Every check here exists because the node is no longer doing it for us:
///
/// - each signer must be **in the vault** (a signature from a stranger can
///   never satisfy the script, and placing one produces an unspendable
///   transaction that would only fail at broadcast);
/// - each signer counts **once** — a peer answering twice must not look like
///   two approvals;
/// - each signature must **verify** over that input's sighash;
/// - exactly `threshold` signatures per input — fewer cannot spend, more is
///   rejected by `OP_CHECKMULTISIG`;
/// - signatures are ordered by **redeem-script pubkey position**, the
///   consensus-critical invariant (ADR-0017 D2).
pub fn assemble(
    unsigned: &Transaction,
    vault: &MultisigVault,
    partials: &[PartialSignature],
) -> Result<Transaction, MultisigError> {
    if unsigned.inputs.is_empty() {
        return Err(MultisigError::NoInputs);
    }
    for p in partials {
        if p.signatures.len() != unsigned.inputs.len() {
            return Err(MultisigError::InputCountMismatch(p.signatures.len()));
        }
    }

    // Resolve every contributor to its position in the redeem script. This
    // is both the vault-membership check and the ordering key.
    let mut placed: Vec<(usize, &PartialSignature)> = Vec::with_capacity(partials.len());
    for p in partials {
        let pos = vault
            .signer_pubkeys
            .iter()
            .position(|k| k == &p.vault_pubkey)
            .ok_or_else(|| MultisigError::SignerNotInVault {
                pubkey_hex: hexs(&p.vault_pubkey),
            })?;
        if let Some((_, prev)) = placed.iter().find(|(i, _)| *i == pos) {
            return Err(MultisigError::DuplicateSigner {
                pubkey_hex: hexs(&prev.vault_pubkey),
                count: 2,
            });
        }
        placed.push((pos, p));
    }

    // THE invariant: ascending redeem-script position, never collection
    // order and never quorum index (which coincide only by accident).
    placed.sort_by_key(|(pos, _)| *pos);

    let mut signed = unsigned.clone();
    for (input_index, inp) in signed.inputs.iter_mut().enumerate() {
        if placed.len() < vault.threshold {
            return Err(MultisigError::ThresholdNotMet {
                input: input_index,
                got: placed.len(),
                threshold: vault.threshold,
            });
        }
        if placed.len() > vault.threshold {
            return Err(MultisigError::TooManySignatures {
                input: input_index,
                got: placed.len(),
                threshold: vault.threshold,
            });
        }

        let sighash = unsigned.sighash_all(input_index, &vault.redeem_script);
        let mut script = vec![OP_0];
        for (_, p) in &placed {
            let sig = &p.signatures[input_index];
            verify_partial(input_index, &p.vault_pubkey, sig, &sighash)?;
            push_data(&mut script, sig);
        }
        push_data(&mut script, &vault.redeem_script);
        inp.script_sig = script;
    }

    Ok(signed)
}

/// Extracts one signer's DER signature per input from a partially-signed
/// transaction as `signrawtransaction` returns it.
///
/// The node hands back a whole transaction rather than a bare signature, so
/// the signature has to be recovered from the scriptSig it built:
/// `OP_0 <sig> <redeemScript>`.
pub fn extract_signatures(
    partial: &Transaction,
    redeem_script: &[u8],
) -> Result<Vec<Vec<u8>>, MultisigError> {
    let mut out = Vec::with_capacity(partial.inputs.len());
    for (i, inp) in partial.inputs.iter().enumerate() {
        let items = parse_script_pushes(&inp.script_sig)?;
        let sig = items
            .into_iter()
            .find(|it| !it.is_empty() && it.as_slice() != redeem_script)
            .ok_or(MultisigError::MalformedSignature {
                input: i,
                pubkey_hex: String::new(),
                reason: "partial scriptSig contains no signature",
            })?;
        out.push(sig);
    }
    Ok(out)
}

/// Returns the data items pushed by a script, ignoring non-push opcodes.
fn parse_script_pushes(script: &[u8]) -> Result<Vec<Vec<u8>>, MultisigError> {
    let mut items = Vec::new();
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let n = match op {
            0 => 0usize,
            1..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i).ok_or(MultisigError::Truncated(i))? as usize;
                i += 1;
                n
            }
            0x4d => {
                let bytes = script.get(i..i + 2).ok_or(MultisigError::Truncated(i))?;
                i += 2;
                u16::from_le_bytes(bytes.try_into().unwrap()) as usize
            }
            // Any other opcode in a P2SH scriptSig is not something this
            // bridge produces; skipping it silently would hide a malformed
            // input, so treat the script as unparseable.
            _ => return Err(MultisigError::Truncated(i)),
        };
        let end = i.checked_add(n).ok_or(MultisigError::Truncated(i))?;
        if end > script.len() {
            return Err(MultisigError::Truncated(i));
        }
        items.push(script[i..end].to_vec());
        i = end;
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real regtest transaction: 1-input, 1-output, spending a 2-of-3 P2SH
    // vault. Captured from the goldcoind 0.17.0 session recorded in
    // docs/experiments/phase7e-04-signature-ordering.py.
    const UNSIGNED_HEX: &str = "0100000001691c05d30acf60621d64a568d36cf447b675cc56b4b48199df232f226371d40f0000000000ffffffff01c0878b3b000000001976a9148ad1cea515840af227960fe1e1f5400a9a00d55188ac00000000";

    fn tx() -> Transaction {
        Transaction::parse_hex(UNSIGNED_HEX).unwrap()
    }

    #[test]
    fn parses_and_reserializes_a_real_transaction_byte_for_byte() {
        // Round-tripping is the floor: if serialization drifts by one byte
        // the txid is wrong and every downstream guarantee collapses.
        let t = tx();
        assert_eq!(t.serialize_hex(), UNSIGNED_HEX);
        assert_eq!(t.inputs.len(), 1);
        assert_eq!(t.outputs.len(), 1);
        assert_eq!(t.version, 1);
        assert_eq!(t.lock_time, 0);
    }

    #[test]
    fn computes_the_txid_a_real_node_reported() {
        // The node reported this txid for the unsigned transaction above.
        assert_eq!(
            tx().txid_hex(),
            "450580f1ff0454934e803a3982ceb13f81790576fad1c99bc0835bcaccf48fd2"
        );
    }

    #[test]
    fn rejects_a_truncated_transaction() {
        let raw = crate::glc::hex::decode_vec(UNSIGNED_HEX).unwrap();
        for cut in [4, 10, 40, raw.len() - 1] {
            assert!(
                Transaction::parse(&raw[..cut]).is_err(),
                "must reject a transaction truncated at {cut}"
            );
        }
    }

    #[test]
    fn refuses_a_zero_input_transaction_rather_than_misparsing_segwit() {
        // A zero input count is the segwit marker. This bridge never builds
        // witness transactions, and silently mis-parsing one would be worse
        // than refusing.
        let mut raw = crate::glc::hex::decode_vec(UNSIGNED_HEX).unwrap();
        raw[4] = 0x00;
        assert_eq!(
            Transaction::parse(&raw).unwrap_err(),
            MultisigError::NoInputs
        );
    }

    #[test]
    fn varint_round_trips_across_every_encoding_boundary() {
        for n in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
        ] {
            let mut buf = Vec::new();
            put_varint(&mut buf, n);
            let mut c = Cursor { data: &buf, pos: 0 };
            assert_eq!(c.varint().unwrap(), n, "varint {n} must round-trip");
            assert_eq!(
                c.pos,
                buf.len(),
                "varint {n} must consume exactly its bytes"
            );
        }
    }

    #[test]
    fn push_data_uses_the_minimal_encoding() {
        // A non-minimal push changes the scriptSig bytes and therefore the
        // txid, so this has to match the reference implementation exactly.
        let mut out = Vec::new();
        push_data(&mut out, &[0xAA; 10]);
        assert_eq!(out[0], 10, "short pushes use a bare length byte");

        let mut out = Vec::new();
        push_data(&mut out, &[0xAA; 0x4c]);
        assert_eq!(&out[..2], &[0x4c, 0x4c], "0x4c..=0xff uses OP_PUSHDATA1");

        let mut out = Vec::new();
        push_data(&mut out, &[0xAA; 300]);
        assert_eq!(out[0], 0x4d, "over 0xff uses OP_PUSHDATA2");
        assert_eq!(&out[1..3], &300u16.to_le_bytes());
    }

    #[test]
    fn sighash_isolates_the_input_being_signed() {
        // Every other input's scriptSig must be emptied, and this input's
        // replaced by the redeem script. Getting this wrong produces
        // signatures that verify locally and fail at consensus.
        let mut t = tx();
        t.inputs.push(TxInput {
            prev_txid: [0x55; 32],
            prev_vout: 1,
            script_sig: vec![0xFF; 4],
            sequence: 0xffff_ffff,
        });
        let redeem = vec![0x52, 0x21, 0xAA];
        let a = t.sighash_all(0, &redeem);
        let b = t.sighash_all(1, &redeem);
        assert_ne!(a, b, "each input must have its own distinct sighash");
    }

    #[test]
    fn sighash_ignores_input_amounts_by_construction() {
        // ADR-0017 §2.5, asserted structurally: there is nowhere in this
        // computation for an amount to enter. If a future change added one,
        // this test would stop compiling or stop being true.
        let t = tx();
        let redeem = vec![0x52, 0x21, 0xAA];
        let before = t.sighash_all(0, &redeem);
        // Outputs are covered...
        let mut t2 = t.clone();
        t2.outputs[0].value += 1;
        assert_ne!(t2.sighash_all(0, &redeem), before, "outputs are committed");
        // ...but there is no input amount field at all to vary.
        assert_eq!(t.sighash_all(0, &redeem), before);
    }

    #[test]
    fn parse_script_pushes_handles_every_push_form() {
        let mut s = vec![OP_0];
        push_data(&mut s, &[1, 2, 3]);
        push_data(&mut s, &[9u8; 0x4c]);
        push_data(&mut s, &[7u8; 300]);
        let items = parse_script_pushes(&s).unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], Vec::<u8>::new());
        assert_eq!(items[1], vec![1, 2, 3]);
        assert_eq!(items[2].len(), 0x4c);
        assert_eq!(items[3].len(), 300);
    }

    #[test]
    fn parse_script_pushes_rejects_a_truncated_push() {
        assert!(parse_script_pushes(&[0x10, 0xAA]).is_err());
        assert!(parse_script_pushes(&[0x4c]).is_err());
        assert!(parse_script_pushes(&[0x4d, 0x01]).is_err());
    }
}
