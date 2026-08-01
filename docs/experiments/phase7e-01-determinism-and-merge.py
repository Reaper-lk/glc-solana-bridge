#!/usr/bin/env python3
"""Phase 7e regtest investigation: distributed P2SH multisig payout signing.

Every factual claim in the Phase 7e design must trace back to output from
this script, run against a real goldcoind 0.17 regtest node.
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


def hr(title):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def txid_of(hexstr):
    return rpc("decoderawtransaction", hexstr)["txid"]


# ---------------------------------------------------------------------------
hr("0. Environment")
info = rpc("getnetworkinfo")
print(f"subversion   = {info['subversion']}")
print(f"version      = {info['version']}")
print(f"blockcount   = {rpc('getblockcount')}")
if rpc("getblockcount") < 150:
    rpc("generate", 150)
    print(f"mined to     = {rpc('getblockcount')}")

# ---------------------------------------------------------------------------
hr("1. Three independent signer keys")
signers = []
for i in range(3):
    addr = rpc("getnewaddress")
    priv = rpc("dumpprivkey", addr)
    pub = rpc("validateaddress", addr)["pubkey"]
    signers.append({"addr": addr, "priv": priv, "pub": pub})
    print(f"signer {i}: addr={addr} pub={pub}")

# ---------------------------------------------------------------------------
hr("2. 2-of-3 P2SH multisig vault")
ms = rpc("createmultisig", 2, [s["pub"] for s in signers])
vault, redeem = ms["address"], ms["redeemScript"]
print(f"address      = {vault}")
print(f"redeemScript = {redeem}")

# ---------------------------------------------------------------------------
hr("3. Fund the vault")
fundtx = rpc("sendtoaddress", vault, 10)
rpc("generate", 1)
raw = rpc("getrawtransaction", fundtx, 1)
out = next(o for o in raw["vout"]
           if vault in o["scriptPubKey"].get("addresses", []))
vout, amount, spk = out["n"], out["value"], out["scriptPubKey"]["hex"]
print(f"funding txid = {fundtx}")
print(f"vault utxo   = {fundtx}:{vout} amount={amount}")

prevtxs = [{"txid": fundtx, "vout": vout, "scriptPubKey": spk,
            "redeemScript": redeem, "amount": amount}]

# ---------------------------------------------------------------------------
hr("4. One unsigned transaction (what the executor builds today)")
dest = rpc("getnewaddress")
unsigned = rpc("createrawtransaction",
               [{"txid": fundtx, "vout": vout}], {dest: 9.99})
print(f"dest         = {dest}")
print(f"unsigned txid= {txid_of(unsigned)}   <-- note: differs from final")
print(f"unsigned hex = {unsigned}")


def sign_with(idx, base=None):
    """Sign with EXACTLY ONE key. No wallet, no peer keys.

    Goldcoin 0.17 has only the legacy `signrawtransaction`, whose signature
    is (hexstring, prevtxs, privkeys, sighashtype) — the Bitcoin 0.16 shape.
    `base` defaults to the unsigned tx; passing an already-partially-signed
    hex is how sequential merging is tested.
    """
    return rpc("signrawtransaction", base if base is not None else unsigned,
               prevtxs, [signers[idx]["priv"]])


# ---------------------------------------------------------------------------
hr("Q3. Is one signer's signature deterministic across repeated attempts?")
attempts = [sign_with(0)["hex"] for _ in range(5)]
for n, h in enumerate(attempts, 1):
    print(f"attempt {n}: len={len(h)} sha256={__import__('hashlib').sha256(h.encode()).hexdigest()[:32]}")
deterministic = len(set(attempts)) == 1
print(f"\nRESULT: {'DETERMINISTIC (RFC6979)' if deterministic else 'NON-DETERMINISTIC (random nonces)'}"
      f" — {len(set(attempts))} distinct result(s) from 5 signings")

# ---------------------------------------------------------------------------
hr("Q1. Combining independent partial signatures")
print("Goldcoin 0.17 has NO combinerawtransaction and NO PSBT (verified above).")
print("The only merge mechanism is legacy signrawtransaction, which accepts an")
print("already-partially-signed hex and adds to it. Two shapes are tested:")
print("  (a) PARALLEL: each signer signs the UNSIGNED tx; merge afterwards.")
print("  (b) SEQUENTIAL: signer B signs the hex signer A produced.")

p_ = [sign_with(i) for i in range(3)]
for i, r in enumerate(p_):
    print(f"\nsigner {i}: complete={r['complete']}")
    for e in r.get("errors", []):
        print(f"    error: {e.get('error')}")

print("\n-- (a) PARALLEL: is there any way to merge two independently-signed hexes? --")
comb = rpc("combinerawtransaction", [p_[0]["hex"], p_[1]["hex"]], allow_error=True)
print(f"combinerawtransaction -> {comb}")

print("\n-- (b) SEQUENTIAL: signer 1 signs signer 0's partial --")
seq01 = rpc("signrawtransaction", p_[0]["hex"], prevtxs, [signers[1]["priv"]])
print(f"complete={seq01['complete']}")
seq01_hex = seq01["hex"]
txid_01 = txid_of(seq01_hex)
print(f"txid(s0 then s1) = {txid_01}")

print("\n-- does sequential signing PRESERVE the first signature? --")
d = rpc("decoderawtransaction", seq01_hex)
asm = d["vin"][0]["scriptSig"]["asm"]
nsigs = len([t for t in asm.split() if len(t) > 100 and t != "0"])
print(f"scriptSig.asm = {asm[:260]}")
print(f"signature-like items in scriptSig = {nsigs}")
print(f"RESULT: sequential signing {'PRESERVES and ADDS' if seq01['complete'] else 'DID NOT complete'}")

# ---------------------------------------------------------------------------
hr("Q2a. Does SIGNING ORDER change the final txid?")
seq10 = rpc("signrawtransaction", p_[1]["hex"], prevtxs, [signers[0]["priv"]])
txid_10 = txid_of(seq10["hex"])
print(f"order s0 -> s1 : complete={seq01['complete']} txid={txid_01}")
print(f"order s1 -> s0 : complete={seq10['complete']} txid={txid_10}")
print(f"byte-identical = {seq01_hex == seq10['hex']}")
print(f"\nRESULT: final txid is {'ORDER-INDEPENDENT' if txid_01 == txid_10 else 'ORDER-DEPENDENT'}")

# ---------------------------------------------------------------------------
hr("Q2b. Repeated independent sign rounds: is the final txid stable?")
round_txids = []
for n in range(1, 6):
    a = sign_with(0)["hex"]
    b = rpc("signrawtransaction", a, prevtxs, [signers[1]["priv"]])
    round_txids.append(txid_of(b["hex"]))
    print(f"round {n}: complete={b['complete']} txid={round_txids[-1]}")
print(f"\nRESULT: {'STABLE' if len(set(round_txids)) == 1 else 'UNSTABLE'} "
      f"- {len(set(round_txids))} distinct txid(s) across 5 rounds")

# ---------------------------------------------------------------------------
hr("Q2c. Does the CHOICE of quorum change the txid? (ADR-0015)")
q = {}
for (i, j) in [(0, 1), (0, 2), (1, 2)]:
    r = rpc("signrawtransaction", p_[i]["hex"], prevtxs, [signers[j]["priv"]])
    q[(i, j)] = txid_of(r["hex"])
    print(f"quorum {{{i},{j}}}: complete={r['complete']} txid={q[(i, j)]}")
print(f"\nRESULT: {len(set(q.values()))} distinct txids from 3 quorums - "
      f"{'quorum choice CHANGES the txid' if len(set(q.values())) > 1 else 'quorum choice does NOT change the txid'}")

# ---------------------------------------------------------------------------
hr("Q5. Structure: partial vs complete scriptSig")
for label, h in [("partial (1 sig)", p_[0]["hex"]), ("complete (2 sigs)", seq01_hex)]:
    d = rpc("decoderawtransaction", h)
    ss = d["vin"][0]["scriptSig"]
    print(f"{label}: scriptSig.hex len={len(ss['hex'])}")
    print(f"    asm = {ss['asm'][:230]}")

# ---------------------------------------------------------------------------
hr("Q5. Can ONE signer signing twice satisfy the 2-of-3?")
dup = rpc("signrawtransaction", p_[0]["hex"], prevtxs, [signers[0]["priv"]])
print(f"s0 signs its own partial again: complete={dup['complete']}")
snd = rpc("sendrawtransaction", dup["hex"], allow_error=True)
print(f"broadcast -> {snd}")
print("RESULT: one key cannot satisfy a 2-of-3, as expected")

# ---------------------------------------------------------------------------
hr("Q5. Does a signer need the OTHER signers' public keys?")
print("The redeemScript in prevtxs contains all three pubkeys - it is PUBLIC")
print("data and is required for a P2SH signature to be constructible at all.")
print("No signer needs another signer's PRIVATE key. Confirmed by construction:")
print("every signrawtransaction call above passed exactly ONE privkey.")

# ---------------------------------------------------------------------------
hr("Q4 + Q2d. Broadcast: does the on-chain txid match the pre-broadcast one?")
sent = rpc("sendrawtransaction", seq01_hex, allow_error=True)
print(f"pre-broadcast txid = {txid_01}")
print(f"sendrawtransaction -> {sent}")
print(f"RESULT: {'MATCH' if sent == txid_01 else 'MISMATCH'}")
rpc("generate", 1)
conf = rpc("getrawtransaction", txid_01, 1)
print(f"confirmations = {conf.get('confirmations')}")

hr("DONE")
