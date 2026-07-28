# Goldcoin Core RPC notes

Verified facts about the Goldcoin node interface. **Phase 0: nothing is
verified — this file is the checklist.** Filled in during Phase 2 by running
against a real Goldcoin Core build; no fact below may be assumed from Bitcoin
documentation, because Goldcoin is a divergent fork (~Bitcoin 0.14 era).

## To verify (Phase 2)

- [ ] Exact Goldcoin Core version/lineage and upstream Bitcoin Core base
- [ ] Regtest mode: exists? activation flags? default RPC/P2P ports
      (the blueprint's 18332 is Bitcoin *testnet's* port — do not trust)
- [ ] Mainnet RPC/P2P default ports
- [ ] `getblock` verbosity levels (does verbosity 2 with full tx objects exist?)
- [ ] `getrawtransaction` availability without `-txindex`; `-txindex` support
- [ ] txid byte order in RPC output vs internal order (affects `DepositId.txid`)
- [ ] Address formats: base58 version bytes for P2PKH/P2SH; any bech32? →
      fixes the `glc_address` field encoding in `WithdrawalRequest`
- [ ] `OP_RETURN` standardness relay and size limit → deposit recipient binding
- [ ] P2SH multisig support end-to-end (`createmultisig`, spend path) → vault
- [ ] `sendrawtransaction` semantics/error shapes
- [ ] Native GLC decimals (assumed 8) and max money constant
- [ ] Confirmation/reorg behavior: headers-first sync? `getchaintips` available?
- [ ] Any Goldcoin-specific consensus features (e.g., its 51%-defense rules)
      that affect reorg handling or confirmation counting

## Verified facts

*(empty)*
