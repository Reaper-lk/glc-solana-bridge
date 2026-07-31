# ADR-0015: Goldcoin vault custody — P2SH M-of-N with a designated signing quorum

- Status: Accepted (owner decisions, 2026-07-31)
- Phase: 7b
- Refines: ADR-0014 §8. Supersedes ADR-0013's D2 (single-key regtest vault).
- Resolves: custody.md #2 (vault construction). Partially informs #3.

## Context

ADR-0013 shipped the withdrawal executor against a **single-key P2PKH vault
held in the Goldcoin node wallet** (owner decision D2), explicitly labelled
test-only. One key could drain it, and the node wallet would spend vault
outputs for unrelated transactions. ADR-0014 committed to replacing it with
P2SH M-of-N script multisig, gated on first verifying that Goldcoin's spend
path actually behaves as assumed (finding **F4**).

That verification is now done, against a real v0.15.0 regtest node with
three independently-held keys. It passed — and it changed the design.

## Decision

### 1. The vault is a P2SH M-of-N script multisig

`createmultisig M [pk1..pkN]` produces a `Q`-prefixed P2SH address and a
redeem script. Verified working end to end: partial signing yields
`complete: false`, the partial is rejected by the network
(`-26 mandatory-script-verify-flag-failed`), and a second independent
signature completes and confirms it. Any M of N in any order is accepted.

Threshold signing (TSS) remains rejected for the reasons in ADR-0014 §8.1:
script multisig is auditable, recoverable from seeds plus the redeem script,
and introduces no novel cryptography.

### 2. The signing quorum is designated explicitly in the payout intent

This is the decision that verification forced.

Measured on a real node: the same inputs and outputs signed by **different
quorums** produce **different txids**. Signing *order* is irrelevant
(deterministic ECDSA — the same quorum in either order gives an identical
txid), but signing *set* is not:

```
signers {1,2}: cc21b040eec6803c1a9ae71409a57e45e311e28e898e88f75c2db828f443ffd5
signers {1,3}: 13edc8c3b9b1a6b2d0844812446c965ea02fff6fc93fd13b08a8698248a50fe8
signers {2,3}: 7c76b400b178027b9fd3513efdbc7045da23c4315252b6d4e46ddce9af5d0ef7
```

ADR-0013 persists a payout's txid **before** broadcasting, and that durable
txid is the only mechanism for reconciling a lost broadcast response. Under
a free-for-all quorum that invariant breaks: the txid is unknown until M
signatures exist, and two overlapping quorums could each complete, producing
two valid transactions spending the same inputs.

**The payout intent therefore names exactly which M validators will sign.**
The txid is determined before any signature is collected, and the Phase 5/6
recovery model survives unchanged.

### 3. Reassignment is explicit, auditable, and never implicit

If a designated signer is unavailable, the executor does **not** fall back to
another quorum. A new intent is issued with an incremented `quorum_attempt`.
Because the attempt counter and the designated indices are inside the
committed bytes:

- the new intent has a different commitment, so signatures gathered for the
  superseded quorum cannot be replayed into it;
- the superseded attempt is recorded rather than overwritten, so every
  reassignment is visible after the fact;
- reassignment is a deliberate state transition, not a race outcome.

### 4. Canonical payout intent (v2)

```
"GLC_BRIDGE_PAYOUT"(17) ‖ protocol_version(1) ‖ withdrawal_index(8)
  ‖ vault_script_hash(20) ‖ dest_hash160(20)
  ‖ payout(8) ‖ fee(8) ‖ change(8) ‖ change_hash160(20)
  ‖ quorum_attempt(4 LE) ‖ quorum_count(1) ‖ quorum_indices(1 each)
  ‖ input_count(4 LE) ‖ [ txid(32) ‖ vout(4) ‖ amount(8) ]*
```

`vault_script_hash` binds the intent to one specific redeem script, which
pins the signer list and its order — so a one-byte `quorum_index` per
designated signer is unambiguous. An intent built for one vault can never be
signed against another.

This is a breaking change to the ADR-0013 intent format. Acceptable: nothing
is deployed to a persistent network, and the format is internal to the
relayer.

### 5. The relayer never holds a vault key

Signing goes through an **isolated signer** boundary. The relayer sends a
canonical intent; the signer independently re-derives the transaction,
verifies destination, amount, change and inputs against its own view, and
returns a partial signature. The Phase 6 path — calling `signrawtransaction`
on the node wallet — is deleted.

Phase 7b defines the boundary and ships a regtest implementation. Hardware
signers are 7b-follow-on work and must be **verified against Goldcoin**, not
assumed from Bitcoin support (ADR-0014 P7).

## Consequences

Three shipped Phase 6 behaviours were incompatible with a production vault
and are corrected here:

1. **`list_unspent` filtered on `spendable`.** Verified: after
   `importaddress`, a vault UTXO is `spendable: false` / `solvable: false`
   until the redeem script is imported, and `spendable` stays false whenever
   the local node cannot sign alone — the normal production case. The
   executor would have seen an empty vault and silently never paid out. The
   filter is now `solvable`.
2. **`signrawtransaction(hex)` was called bare.** Signing for a P2SH vault
   requires explicit `prevtxs` carrying the `redeemScript`.
3. **The vault was a single P2PKH address in config.** It is now a multisig
   descriptor: redeem script, M, N, and the ordered signer pubkeys, with the
   P2SH address re-derived from the script rather than trusted from config.

Further consequences:

- The vault must be registered with the node via `importaddress` (address
  and redeem script) before the executor can observe it. This is an
  operational precondition, and the executor should fail loudly rather than
  interpret an unimported vault as an empty one.
- Deterministic coin selection (ADR-0013) is unaffected: it operates on the
  UTXO set, not on signing.
- Quorum designation adds a liveness dependency — an unavailable designated
  signer stalls that payout until reassignment. This is deliberate: stalling
  is recoverable, double-paying is not.
- custody.md #3 (signing model) is now partially answered — script multisig,
  not TSS — but key-holding infrastructure (HSM vs air-gapped) remains open.
