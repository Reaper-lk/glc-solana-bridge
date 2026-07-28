# ADR-0002: Deposits are identified by (txid, vout)

- Status: Accepted
- Phase: 0 (implemented Phase 2)

## Context

The original blueprint identified inbound claims by "Goldcoin TX Hash +
Nonce". A single Goldcoin transaction can pay the vault in multiple outputs,
so txid alone under-identifies a deposit; a nonce is chosen off-chain, is not
derivable from the L1, and creates ambiguity/forgeability in what the
federation actually attests to.

## Decision

The canonical deposit identity is the pair `(txid: [u8; 32], vout: u32)` of
the confirmed UTXO paying the vault. It appears verbatim in `InboundClaim`,
in the signed claim bytes, and as the seed of the replay-guard PDA
(ADR-0003). txid byte-order convention is pinned in Phase 2
(`goldcoin-rpc-notes.md`).

## Consequences

- Multi-output vault payments yield multiple independent claims — correct by
  construction.
- No nonce management anywhere in the protocol.
- Everything the federation signs is recomputable by anyone from L1 data.
