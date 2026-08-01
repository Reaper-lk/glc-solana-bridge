# ADR-0017: Distributed payout signing (Phase 7e)

- Status: **Accepted** (owner approval, 2026-08-01). E1/E2/E3 resolved — see §7.
- Phase: 7e
- Scope: the **Goldcoin payout path only**. The deposit/mint path already
  works over the federation (ADR-0016) and is not touched.
- Builds on: ADR-0013 (withdrawal executor), ADR-0015 (vault custody and the
  designated quorum), ADR-0016 (federation signature exchange, mTLS
  transport).
- Empirical basis: `docs/goldcoin-rpc-notes.md` §"Distributed multisig
  signing (verified Phase 7e)", reproducible via `docs/experiments/
  phase7e-0{1,2,3,4}-*.py` against a real `goldcoind` 0.17.0 regtest node.

---

## 1. Context

Phase 7d retired the last of the unsafe key topologies on the **mint** side:
the relayer holds no validator key, signers run as separate processes behind
mTLS, and only signatures cross the network.

The **payout** side did not move. Today `WithdrawalExecutor::sign` calls
`signrawtransaction` on the operator's own Goldcoin node, which must
therefore hold enough vault keys to satisfy the M-of-N by itself. That is the
same "one process holds the quorum" shape Phase 7c removed from the mint
path, and it is the last place in the bridge where a single compromised host
can move funds.

Phase 7e closes it. This is a change to the *signing model*, which every
prior phase was deliberately scoped to avoid, and it is why the design was
written only after the underlying facts were verified experimentally.

---

## 2. Verified findings this design rests on

Every statement in this section was observed against a real Goldcoin 0.17.0
regtest node. Nothing here is inferred from Bitcoin Core behaviour.

### 2.1 Goldcoin 0.17 has NO PSBT and NO `combinerawtransaction`

Goldcoin 0.17 ships the **Bitcoin 0.16-era** raw-transaction API. Absent:
`combinerawtransaction`, `createpsbt`, `walletprocesspsbt`, `finalizepsbt`,
`converttopsbt`, `signrawtransactionwithkey`, `signrawtransactionwithwallet`,
`getaddressinfo`. Present: legacy `signrawtransaction`, whose argument order
is `(hexstring, prevtxs, privkeys, sighashtype)` — `prevtxs` **before**
`privkeys`.

There is therefore **no node-side mechanism** to combine independently
produced partial signatures. This is the finding that shapes the entire
design.

> `goldcoin-cli help <unknown-method>` exits **0**. Method existence must be
> probed by output text or JSON-RPC code `-32601`, never by exit status.

### 2.2 Signatures are RFC6979-deterministic, and txid determinism is preserved

Five signings of one unsigned transaction with one key produced byte-identical
output. A **second, independent** `goldcoind` — different datadir, empty
chain, never having seen the transaction — produced the identical partial
from the same `(unsigned tx, prevtxs, privkey)`.

**Consequence:** for a fixed designated quorum, the fully-signed transaction —
and therefore its txid — is a pure function of the unsigned transaction and
the participating keys. Re-collection after a crash reproduces the *same*
bytes and the *same* txid. ADR-0013's reconciliation model survives.

### 2.3 The relayer can assemble the scriptSig itself, in parallel

Extracting each signer's DER signature from its independent partial and
assembling `OP_0 <sig_a> <sig_b> <redeemScript>` reproduces the node's
sequential output **byte-for-byte**, verified on a 2-input transaction.

**Consequence:** signers are asked **in parallel**, and Phase 7d's
collect/timeout/failover machinery applies unchanged. No serial relay, and
no signer ever sees another signer's partial.

A signer asked to sign the unsigned transaction alone returns
`complete: false` with `Operation not valid with the current stack size`.
That error is the **normal, expected** result of a partial M-of-N signature,
not a failure, and the implementation must not treat it as one.

### 2.4 Signature ordering is consensus-critical

`OP_CHECKMULTISIG` requires signatures in the same relative order as the
pubkeys in the redeemScript. A reversed order is **rejected by consensus**
(`16: mandatory-script-verify-flag-failed`), verified against a separate
funded UTXO per ordering so no result could be masked.

This **refines** the Phase 7b note "signature order does not matter": that is
true of the order signers are *asked* in, but **not** of the order signatures
are *placed* in the scriptSig. The node was sorting them silently. Code that
assembles a scriptSig itself does not get that for free.

### 2.5 The legacy sighash does NOT commit to input amounts

Signing with deliberately falsified `amount` values in `prevtxs` produced a
transaction byte-identical to one signed with correct amounts, which the
network then accepted.

**Consequence — security-critical.** A signer **cannot** verify input amounts
from the signing request, because the amount is not part of what it signs.
Amounts must be validated against the signer's **own** UTXO view. A
requester-supplied amount is untrusted input.

### 2.6 A signer needs only its own key

Every signature above came from `signrawtransaction` with exactly **one** WIF
key plus public data (unsigned tx, redeemScript, scriptPubKeys). One key
signing twice cannot satisfy a 2-of-3 (`complete: false`; broadcast rejected).

---

## 3. Decisions

### D1. Parallel collection, relayer-side assembly

Each designated signer independently produces a partial signature over the
**same** unsigned transaction. The relayer collects them and assembles the
final scriptSig itself.

Rejected alternative — *sequential relay* (pass the partially-signed hex from
signer to signer): it works (§2.3) but serialises the round, so one slow
signer blocks every other, and it would discard the timeout/failover model
Phase 7d just built. It also leaks each signer's partial to the next.

### D2. Signature ordering is an explicit, tested invariant

The relayer orders signatures by **position of the signer's pubkey in the
redeemScript**, ascending — not by quorum index, not by collection order, not
by the order peers replied.

This is treated as a **consensus-critical invariant**, in the same class as
the canonical message layout: pinned by a golden vector against real node
output, mutation-tested, and asserted before broadcast.

### D3. Every signer independently rebuilds the transaction

A signer never signs bytes because it was asked to. It:

1. loads its **own** withdrawal record and its **own** vault UTXO set;
2. re-runs the deterministic coin selection (ADR-0013 D-decisions);
3. rebuilds the unsigned transaction and the canonical payout intent;
4. compares both, byte-for-byte, against the request;
5. signs **only** its own rebuilt transaction — never the requester's copy.

This is the payout analogue of the mint path's reload-and-recompute
safeguard, and it goes through the existing
`Db::verify_and_load_signable_payout`, so drift **halts** the withdrawal as
an integrity anomaly rather than merely declining.

### D4. Requester-supplied amounts are never trusted

Following directly from §2.5. The signer takes input amounts **only** from
its own `vault_utxos` table. The `amount` field in the request is used for
nothing but the RPC call it must make, and is overwritten with the locally
known value first. A mismatch between the requested and the locally observed
amount is a **refusal**, not a correction.

Stated plainly because the failure is silent otherwise: a signature over a
transaction whose inputs are worth more than the signer believes is a valid
signature. Only the local view stops it.

### D5. The designated quorum survives unchanged (ADR-0015)

Only the designated M signers are asked. A designated signer that is
unavailable produces a **shortfall requiring explicit, audited quorum
reassignment** (`Db::reassign_payout_quorum`), never an implicit substitution
— because different quorums over identical inputs and outputs produce
different txids (verified Phase 7b, re-confirmed §2.2).

`quorum_attempt` is part of the signing identity, so a signature for a
superseded designation neither satisfies nor conflicts with its replacement.

### D6. ADR-0013's txid-before-broadcast model is preserved

The order of operations is unchanged:

1. collect partials from the designated quorum;
2. assemble the scriptSig; compute the txid;
3. **persist the fully-signed transaction and its txid atomically**;
4. only then broadcast.

Determinism (§2.2) is what makes this safe under crash: re-collecting from
the same quorum after a restart reproduces the identical transaction and
txid, so a lost broadcast response is always reconcilable, and a retry can
never produce a second, different payout.

### D7. Vault signer identity must be bound to federation identity

To ask "the validator holding vault signer index 2", the relayer needs a
mapping from **federation ed25519 identity** to **vault secp256k1 pubkey /
redeemScript position**.

A returned partial is **self-authenticating**: its ECDSA signature verifies
against the expected vault pubkey over the sighash. That is a stronger check
than any attestation, and it is what the relayer will rely on. The mapping is
still needed to know *which* pubkey to expect from *which* peer, and to
detect a peer answering with a vault key it was not designated for.

**This requires an owner decision — see §7 E1.**

---

## 4. Protocol

### 4.1 A new RPC, not an overloaded one

`federation.proto` gains a **separate** `SignPayout` method. It is not folded
into `Sign`, because the two return different things: `Sign` returns one
ed25519 signature over a canonical message; `SignPayout` returns one **DER
ECDSA signature per transaction input** over Goldcoin sighashes. Overloading
one response shape to mean both would make the type system stop helping
exactly where the two must not be confused.

```
service FederationSigner {
  rpc Sign       (SignRequest)       returns (SignResponse);
  rpc SignPayout (PayoutSignRequest) returns (PayoutSignResponse);
  rpc Health     (HealthRequest)     returns (HealthResponse);
}

message PayoutSignRequest {
  bytes  request_id      = 1;
  uint64 epoch           = 2;
  uint64 withdrawal_index= 3;
  uint32 quorum_attempt  = 4;
  bytes  canonical_intent= 5;  // ADR-0015 intent; COMPARED, never adopted
  string unsigned_tx_hex = 6;  // COMPARED against the locally rebuilt tx
  int64  expiry_unix     = 7;
}

message PayoutSignResponse {
  bytes  request_id       = 1;
  bytes  validator_pubkey = 2;  // ed25519 federation identity
  bytes  vault_pubkey     = 3;  // compressed secp256k1, 33 bytes
  repeated bytes signatures = 4; // one DER sig per input, in INPUT order
}
```

`canonical_intent` and `unsigned_tx_hex` are both sent and both compared.
Sending only one would let the other drift unnoticed: the intent pins the
economic meaning (ADR-0015), the transaction pins the exact bytes that get
signed.

### 4.2 Flow

```
executor                          designated signer i
   |                                     |
   |-- build unsigned tx (own view) ---->|
   |   + canonical intent                |
   |                                     |-- rebuild from OWN db + OWN utxos
   |                                     |-- verify_and_load_signable_payout
   |                                     |-- compare intent   (byte-for-byte)
   |                                     |-- compare unsigned (byte-for-byte)
   |                                     |-- amounts from OWN utxo set (D4)
   |                                     |-- signrawtransaction, ONE key
   |<-- DER sig per input ---------------|
   |
   |-- verify each sig against expected vault pubkey + sighash
   |-- order by redeemScript pubkey position   (D2, consensus-critical)
   |-- assemble scriptSig; compute txid
   |-- PERSIST signed tx + txid atomically     (D6)
   |-- broadcast
```

### 4.3 New module boundaries

| module | responsibility |
|---|---|
| `withdrawal/multisig.rs` (new) | DER extraction, signature ordering, scriptSig assembly, txid computation. Pure, no I/O, no RPC — testable against golden vectors from real node output. |
| `p2p/payout_view.rs` (new) | the signer's independent rebuild-and-compare, over its own DB |
| `p2p/service.rs` | `SignPayout` handler; reuses expiry, epoch, seen-set, and rate-limit machinery unchanged |
| `p2p/collector.rs` | `collect_payout_partials` — reuses `Round`, `PER_PEER_TIMEOUT`, `ROUND_TIMEOUT` |
| `withdrawal/executor.rs` | `sign` switches from local `signrawtransaction` to collect-then-assemble |

---

## 5. Required tests

### 5.1 Mutation tests (guard must fail loudly when weakened)

Following the Phase 7d discipline: each mutant below must be **killed** by a
test. A survivor means the guard is untested and the work is not done.

| # | mutant | guard it proves |
|---|---|---|
| M1 | order signatures by collection order instead of redeemScript position | D2 ordering invariant |
| ~~M2~~ | ~~order by quorum index instead of pubkey position~~ | **Withdrawn during implementation as vacuous.** A quorum index *is* a position in the vault's ordered signer list, which *is* redeem-script order (ADR-0015 §4), so the two orderings are identical by construction and no vault can distinguish them. The meaningful mutant is M1. Recorded rather than silently dropped. |
| M3 | skip the `OP_0` CHECKMULTISIG dummy | scriptSig well-formedness |
| M4 | accept a partial without verifying its ECDSA signature | self-authentication of partials |
| M5 | accept a partial whose vault pubkey is not the designated one | D7 identity binding |
| M6 | accept fewer than M signatures | threshold |
| M7 | count one signer's signature twice toward threshold | duplicate-signature guard |
| M8 | take input amounts from the request instead of the local UTXO set | **D4 — the §2.5 finding** |
| M9 | skip the byte-for-byte unsigned-transaction comparison | D3 independent rebuild |
| M10 | skip the canonical-intent comparison | D3 / ADR-0015 |
| M11 | sign for a quorum_attempt other than the locally designated one | ADR-0015 |
| M12 | broadcast before persisting the txid | **D6 — ADR-0013 model** |
| M13 | substitute an available peer for an unavailable designated signer | D5 |
| M14 | proceed when the assembled txid differs from the recomputed one | D6 |

### 5.2 Failure cases (explicitly required)

| case | expected behaviour |
|---|---|
| **wrong signature ordering** | assembly rejects before broadcast; a deliberately mis-ordered scriptSig is proven to be rejected by a **real node** (`mandatory-script-verify-flag-failed`), so the guard is validated against consensus and not merely against our own assertion |
| **malformed scriptSig** | truncated DER, oversized push, missing redeemScript, wrong push opcodes — each rejected at assembly with a distinct error; never broadcast |
| **duplicate signatures** | one signer answering twice counts **once**; a scriptSig built from a duplicated partial is rejected, and proven non-spendable against a real node (§2.6) |
| **missing signatures** | below threshold is a normal shortfall — retried next tick, never an error that strands the withdrawal, and never a partial broadcast |
| **signer disagreement** | a signer whose rebuild differs refuses; the refusal is an **alarm**, is not retriable (ADR-0016 §9), and is surfaced with the differing field |
| **stale UTXO view** | a signer whose vault UTXO view is behind refuses rather than signing against inputs it cannot confirm; reuses `Refusal::StaleView` (ADR-0016 §10), extended to cover Goldcoin chain-tip lag as well as Solana epoch lag |
| **quorum timeout / failover** | bounded by `PER_PEER_TIMEOUT` / `ROUND_TIMEOUT`; an unavailable designated signer yields a shortfall requiring **explicit reassignment**, never substitution (D5) |

### 5.3 Real-node integration tests

Unit tests cannot establish that an assembled transaction is *valid*. These
run against a real `goldcoind`:

1. **Golden vector**: a 2-of-3 scriptSig assembled by our code is
   byte-identical to one produced by the node's own sequential signing.
2. **End-to-end**: three isolated signer processes, each holding exactly one
   vault key, produce a payout that a real node accepts and mines.
3. **Ordering fails against consensus**: a mis-ordered scriptSig is rejected
   by a real node — the invariant is verified against the chain, not our
   assumptions.
4. **Idempotent re-collection**: crash after collecting, restart, re-collect —
   identical txid, exactly one payout on chain (§2.2 + D6).
5. **Amount lie**: a requester claiming inflated input amounts is refused by
   the signer, closing §2.5 behaviourally.

### 5.4 Regression protection

Phase 6/7b/7d guards must not weaken. The existing withdrawal mutation tests
and the real-node e2e (deposit → mint → burn → payout) must continue to pass
unchanged.

---

## 6. Consequences

- **No single host can move vault funds.** The last remaining
  quorum-in-one-process is removed; each vault key lives in its own signer.
- **The operator's Goldcoin node no longer needs vault keys.** It builds,
  decodes, and broadcasts; it does not sign.
- **More code in our hands.** scriptSig assembly moves from the node into
  Rust. That is the direct cost of §2.1, and it is why D2's invariant is
  pinned by a golden vector against real node output rather than trusted.
- **A stale or disagreeing signer stalls payouts rather than rubber-stamping
  them.** Consistent with the mint path: refusing is always preferred to
  signing something unverified.
- **Recovery is unchanged for operators.** ADR-0013's reconciliation, ADR-0015's
  auditable reassignment, and Phase 6's never-double-pay layers all still hold.

---

## 7. Owner decisions — RESOLVED

### E1. Federation identity ↔ vault signer position: **configuration, validated at startup**

Resolved as recommended. The mapping is operator configuration, **not** an
on-chain account change; the account-layout migration is explicitly kept out
of Phase 7e.

Every configured signer is validated at startup against the configured
`redeemScript`: each designated signer index must resolve to exactly the
pubkey present at that position in the vault script. **Any mismatch fails
closed** — the process refuses to start rather than running with a mapping
that could route a signing request to the wrong key.

This is what removes the drift risk that made configuration the weaker option
in the abstract: a misconfigured operator cannot silently participate.

On-chain binding remains the right long-term answer and is recorded as future
work, not as a gap in 7e.

### E2. Each signer requires its own Goldcoin node: **required**

Resolved: a signer **must** operate against its own Goldcoin node. Sharing
the relayer's node is **not permitted**.

Independent UTXO validation is a **core security property, not an
optimisation** (owner decision). A signer sharing the relayer's node inherits
that node's view, which defeats D3 and D4 entirely: the whole point is that
the signer's answer comes from an observation the requester did not produce.
Higher deployment cost is accepted to preserve that independence.

The process cannot detect whether the endpoint it was handed is shared, so
this is enforced by documentation and deployment review rather than by code.
`docs/federation-deployment.md` states it as a hard requirement, and the
signer logs its Goldcoin endpoint at startup so a shared endpoint is visible
in review.

### E3. Scope boundary: **unchanged**

Phase 7e delivers only the distributed payout signing described here. The
deposit/mint path, the on-chain program, the canonical message formats, and
the withdrawal state machine are untouched.

## 8. Explicitly out of scope

- The deposit/mint path (ADR-0016) — unchanged.
- On-chain program changes — none, subject to E1 landing on (a).
- Threshold *cryptography* (FROST, MuSig, threshold ECDSA). This design
  distributes conventional M-of-N script multisig; it does not replace it
  with an aggregate-signature scheme. That would change the on-chain vault
  representation and is a separate, much larger decision.
- Vault key rotation and re-sharing.
- Segwit or PSBT adoption — impossible on Goldcoin 0.17 (§2.1).
