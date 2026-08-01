#!/usr/bin/env python3
"""Phase 7e round 2: parallel merge, multi-input, and sighash coverage.

Round 1 established that Goldcoin 0.17 has no combinerawtransaction and no
PSBT, that signing is RFC6979-deterministic, and that SEQUENTIAL signing
yields an order-independent, stable txid that matches on broadcast.

Round 2 asks the questions that decide the Phase 7e network shape:

  Q6. Can the relayer merge INDEPENDENT partials itself, in parallel,
      reproducing byte-for-byte what sequential signing produces? If yes,
      Phase 7d's collect-with-timeout/failover model applies unchanged. If
      no, payouts need a serial relay and one slow signer blocks the round.
  Q7. Does any of this hold for a MULTI-INPUT payout (the common case)?
  Q8. Does the legacy (non-segwit) sighash commit to the input AMOUNT?
      This decides what a signer can and cannot verify from the request.
"""
import base64
import json
import urllib.request

URL = "http://127.0.0.1:19881"
AUTH = base64.b64encode(b"u:p").decode()
_id = [0]


def rpc(method, *params, allow_error=False):
    _id[0] += 1
    body = json.dumps({"jsonrpc": "1.0", "id": _id[0], "method": method,
                       "params": list(params)}).encode()
    req = urllib.request.Request(URL, data=body, headers={
        "Authorization": "Basic " + AUTH, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)["result"]
    except urllib.error.HTTPError as e:
        detail = json.load(e).get("error", {})
        if allow_error:
            return {"__error__": detail.get("message", str(detail)),
                    "__code__": detail.get("code")}
        raise RuntimeError(f"{method} failed: {detail}") from None


def hr(t):
    print(f"\n{'=' * 70}\n{t}\n{'=' * 70}")


def txid_of(h):
    return rpc("decoderawtransaction", h)["txid"]


# --- minimal script push/parse helpers (no external deps) ------------------
def push(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return b"\x4c" + bytes([n]) + data
    return b"\x4d" + n.to_bytes(2, "little") + data


def parse_script(script: bytes):
    """Returns the list of pushed items in a scriptSig."""
    items, i = [], 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0:
            items.append(b"")
        elif op < 0x4c:
            items.append(script[i:i + op]); i += op
        elif op == 0x4c:
            n = script[i]; i += 1; items.append(script[i:i + n]); i += n
        elif op == 0x4d:
            n = int.from_bytes(script[i:i + 2], "little"); i += 2
            items.append(script[i:i + n]); i += n
        else:
            items.append(bytes([op]))
    return items


hr("Setup: fresh 2-of-3 vault with TWO funding UTXOs")
signers = []
for i in range(3):
    a = rpc("getnewaddress")
    signers.append({"addr": a, "priv": rpc("dumpprivkey", a),
                    "pub": rpc("validateaddress", a)["pubkey"]})
    print(f"signer {i}: pub={signers[i]['pub']}")

ms = rpc("createmultisig", 2, [s["pub"] for s in signers])
vault, redeem = ms["address"], ms["redeemScript"]
print(f"vault  = {vault}")

utxos = []
for amt in (4, 6):
    t = rpc("sendtoaddress", vault, amt)
    rpc("generate", 1)
    raw = rpc("getrawtransaction", t, 1)
    o = next(o for o in raw["vout"]
             if vault in o["scriptPubKey"].get("addresses", []))
    utxos.append({"txid": t, "vout": o["n"], "amount": o["value"],
                  "spk": o["scriptPubKey"]["hex"]})
    print(f"utxo: {t}:{o['n']} amount={o['value']}")

prevtxs = [{"txid": u["txid"], "vout": u["vout"], "scriptPubKey": u["spk"],
            "redeemScript": redeem, "amount": u["amount"]} for u in utxos]

dest = rpc("getnewaddress")
unsigned = rpc("createrawtransaction",
               [{"txid": u["txid"], "vout": u["vout"]} for u in utxos],
               {dest: 9.99})
print(f"unsigned tx has {len(rpc('decoderawtransaction', unsigned)['vin'])} inputs")


def sign(base, idx):
    return rpc("signrawtransaction", base, prevtxs, [signers[idx]["priv"]])


# ---------------------------------------------------------------------------
hr("Q7. Multi-input: does SEQUENTIAL signing complete and stay stable?")
seq = sign(sign(unsigned, 0)["hex"], 1)
print(f"complete = {seq['complete']}")
seq_hex = seq["hex"]
seq_txid = txid_of(seq_hex)
print(f"txid     = {seq_txid}")

rev = sign(sign(unsigned, 1)["hex"], 0)
print(f"reverse order txid = {txid_of(rev['hex'])}")
print(f"byte-identical     = {seq_hex == rev['hex']}")
print(f"RESULT: multi-input is "
      f"{'ORDER-INDEPENDENT' if seq_hex == rev['hex'] else 'ORDER-DEPENDENT'}")

# ---------------------------------------------------------------------------
hr("Q6. Can the RELAYER merge independent partials itself, in parallel?")
print("Each signer signs the SAME unsigned tx, in isolation, knowing nothing")
print("of the others. The relayer then assembles the scriptSigs.")
part = [sign(unsigned, i) for i in range(3)]
for i, r in enumerate(part):
    print(f"  signer {i}: complete={r['complete']}")

# Extract each signer's signature per input.
redeem_bytes = bytes.fromhex(redeem)
sigs_per_input = {}
for i, r in enumerate(part):
    d = rpc("decoderawtransaction", r["hex"])
    for vin_idx, vin in enumerate(d["vin"]):
        items = parse_script(bytes.fromhex(vin["scriptSig"]["hex"]))
        # items = [OP_0, <sig>, <redeemScript>]
        found = [it for it in items if it and it != redeem_bytes]
        sigs_per_input.setdefault(vin_idx, {})[i] = found[0] if found else None

for vin_idx, per_signer in sorted(sigs_per_input.items()):
    print(f"  input {vin_idx}: extracted "
          f"{sum(1 for v in per_signer.values() if v)} distinct signatures")

# The redeemScript lists pubkeys in a fixed order; CHECKMULTISIG requires
# signatures in that same relative order. Order by signer index, which here
# matches the order the pubkeys were passed to createmultisig.
merged = rpc("decoderawtransaction", unsigned)
tx_hex = unsigned
QUORUM = [0, 1]

manual = json.loads(json.dumps(merged))  # deep copy of the decoded shape
scriptsigs = []
for vin_idx in range(len(merged["vin"])):
    script = b"\x00"  # OP_0, the CHECKMULTISIG off-by-one dummy
    for s in QUORUM:
        script += push(sigs_per_input[vin_idx][s])
    script += push(redeem_bytes)
    scriptsigs.append(script.hex())
    print(f"  input {vin_idx}: manually built scriptSig len={len(script.hex())}")

# Splice the scriptSigs into the raw transaction by rebuilding it from the
# sequential result's structure — compare against what the node produced.
node_scriptsigs = [v["scriptSig"]["hex"]
                   for v in rpc("decoderawtransaction", seq_hex)["vin"]]
print()
for i, (mine, theirs) in enumerate(zip(scriptsigs, node_scriptsigs)):
    same = mine == theirs
    print(f"  input {i}: manual == node ? {same}")
    if not same:
        print(f"    manual: {mine[:120]}")
        print(f"    node  : {theirs[:120]}")

all_same = scriptsigs == node_scriptsigs
print(f"\nRESULT: parallel merge reproduces the node's bytes EXACTLY = {all_same}")
if all_same:
    print("=> Phase 7d's parallel collect/timeout/failover model applies unchanged.")
else:
    print("=> A serial relay would be required, or a different ordering rule.")

# ---------------------------------------------------------------------------
hr("Q8. Does the legacy sighash commit to the input AMOUNT?")
print("Non-segwit SIGHASH_ALL famously does NOT cover the input amount.")
print("Testing: sign with a DELIBERATELY WRONG amount in prevtxs.")
lying = [dict(p, amount=p["amount"] + 5) for p in prevtxs]
a = rpc("signrawtransaction", unsigned, lying, [signers[0]["priv"]])
b = rpc("signrawtransaction", a["hex"], lying, [signers[1]["priv"]])
print(f"signed with wrong amounts: complete={b['complete']}")
print(f"txid with lied amounts = {txid_of(b['hex'])}")
print(f"txid with true amounts = {seq_txid}")
print(f"identical = {b['hex'] == seq_hex}")
if b["hex"] == seq_hex:
    print("\nRESULT: the amount is NOT covered by the signature.")
    print("=> A signer CANNOT verify input amounts from the signing request.")
    print("=> It MUST verify them against its own UTXO view. Security-critical.")
else:
    print("\nRESULT: amount affects the signature")

# ---------------------------------------------------------------------------
hr("Q8b. Broadcast the amount-lied transaction: is it still valid on-chain?")
sent = rpc("sendrawtransaction", b["hex"], allow_error=True)
print(f"sendrawtransaction -> {sent}")
if sent == seq_txid:
    print("RESULT: accepted — confirming the amount is not part of the sighash")
rpc("generate", 1)

hr("Q5b. What does a signer need that is NOT its own key?")
print("- the unsigned transaction (public)")
print("- the redeemScript (public; contains every signer's PUBLIC key)")
print("- each input's scriptPubKey (public, on-chain)")
print("- each input's amount: accepted by the RPC but NOT signed over,")
print("  therefore NOT verifiable from the signature and NOT trustworthy")
print("  when supplied by a requester.")

hr("DONE")
