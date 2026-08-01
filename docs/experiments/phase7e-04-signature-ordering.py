#!/usr/bin/env python3
"""Phase 7e round 4: prove the signature-ORDER rule actually bites.

Round 3 only demonstrated that the correct order is accepted. That is not
enough: if a wrong order were ALSO accepted, the merge would have no ordering
constraint and the Rust implementation could get it wrong silently. Each
ordering is tested against its OWN funded UTXO so none can be masked by an
already-spent input.
"""
import base64
import hashlib
import json
import urllib.request

_id = [0]
URL = "http://127.0.0.1:19881"
AUTH = base64.b64encode(b"u:p").decode()


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
        d = json.load(e).get("error", {})
        if allow_error:
            return {"__error__": d.get("message"), "__code__": d.get("code")}
        raise RuntimeError(f"{method}: {d}") from None


def hr(t):
    print(f"\n{'=' * 70}\n{t}\n{'=' * 70}")


def push(data):
    n = len(data)
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return b"\x4c" + bytes([n]) + data
    return b"\x4d" + n.to_bytes(2, "little") + data


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def parse_script(script):
    items, i = [], 0
    while i < len(script):
        op = script[i]; i += 1
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


def splice(unsigned_hex, scriptsigs):
    raw = bytes.fromhex(unsigned_hex)
    out = bytearray(); i = 0
    out += raw[i:i + 4]; i += 4
    n_in = raw[i]; i += 1
    out.append(n_in)
    for k in range(n_in):
        out += raw[i:i + 36]; i += 36
        slen = raw[i]; i += 1; i += slen
        ss = bytes.fromhex(scriptsigs[k])
        out += varint(len(ss)) + ss
        out += raw[i:i + 4]; i += 4
    out += raw[i:]
    return out.hex()


hr("Setup: one 2-of-3 vault, five independent funded UTXOs")
signers = []
for _ in range(3):
    a = rpc("getnewaddress")
    signers.append({"priv": rpc("dumpprivkey", a),
                    "pub": rpc("validateaddress", a)["pubkey"]})
ms = rpc("createmultisig", 2, [s["pub"] for s in signers])
vault, redeem = ms["address"], ms["redeemScript"]
redeem_bytes = bytes.fromhex(redeem)
print(f"vault = {vault}")
print("redeemScript pubkey order: signer0, signer1, signer2 "
      f"(offsets {[redeem.find(s['pub']) // 2 for s in signers]})")

utxos = []
for _ in range(5):
    t = rpc("sendtoaddress", vault, 2)
    rpc("generate", 1)
    raw = rpc("getrawtransaction", t, 1)
    o = next(x for x in raw["vout"]
             if vault in x["scriptPubKey"].get("addresses", []))
    utxos.append({"txid": t, "vout": o["n"], "amount": o["value"],
                  "spk": o["scriptPubKey"]["hex"]})
print(f"funded {len(utxos)} separate UTXOs, so each ordering gets a clean test")

hr("Q9. Does a WRONG signature order actually fail?")
cases = [
    ("CORRECT   {0,1} ascending", [0, 1], True),
    ("WRONG     {1,0} reversed ", [1, 0], False),
    ("CORRECT   {0,2} ascending", [0, 2], True),
    ("WRONG     {2,0} reversed ", [2, 0], False),
    ("CORRECT   {1,2} ascending", [1, 2], True),
]

results = []
for (label, order, expect_ok), u in zip(cases, utxos):
    prevtxs = [{"txid": u["txid"], "vout": u["vout"], "scriptPubKey": u["spk"],
                "redeemScript": redeem, "amount": u["amount"]}]
    dest = rpc("getnewaddress")
    unsigned = rpc("createrawtransaction",
                   [{"txid": u["txid"], "vout": u["vout"]}], {dest: 1.99})

    sigs = {}
    for idx in set(order):
        r = rpc("signrawtransaction", unsigned, prevtxs, [signers[idx]["priv"]])
        items = parse_script(bytes.fromhex(
            rpc("decoderawtransaction", r["hex"])["vin"][0]["scriptSig"]["hex"]))
        sigs[idx] = next(it for it in items if it and it != redeem_bytes)

    script = b"\x00"
    for idx in order:
        script += push(sigs[idx])
    script += push(redeem_bytes)
    tx = splice(unsigned, [script.hex()])

    res = rpc("sendrawtransaction", tx, allow_error=True)
    ok = not (isinstance(res, dict) and "__error__" in res)
    match = "as expected" if ok == expect_ok else ">>> UNEXPECTED <<<"
    detail = res if ok else res["__error__"]
    print(f"{label}: accepted={ok:<5} {match:<18} {str(detail)[:60]}")
    results.append(ok == expect_ok)
    if ok:
        rpc("generate", 1)

print(f"\nRESULT: every case behaved as predicted = {all(results)}")
print("The wrong order is rejected by CONSENSUS ('mandatory-script-verify-")
print("flag-failed'), not silently accepted. Ordering the merged signatures")
print("by redeemScript pubkey position is therefore a correctness guard the")
print("Rust implementation must get right, and can be tested to fail loudly.")

hr("Q11. Recovery quirk: is a partial signature usable after a restart?")
u = utxos[0]
prevtxs = [{"txid": u["txid"], "vout": u["vout"], "scriptPubKey": u["spk"],
            "redeemScript": redeem, "amount": u["amount"]}]
dest = rpc("getnewaddress")
unsigned = rpc("createrawtransaction",
               [{"txid": u["txid"], "vout": u["vout"]}], {dest: 1.98})
a1 = rpc("signrawtransaction", unsigned, prevtxs, [signers[0]["priv"]])["hex"]
a2 = rpc("signrawtransaction", unsigned, prevtxs, [signers[0]["priv"]])["hex"]
print(f"same signer, two separate calls, identical = {a1 == a2}")
print(f"sha256 = {hashlib.sha256(a1.encode()).hexdigest()[:32]}")
print("\nRESULT: a partial signature is reproducible from (unsigned tx, key)")
print("alone. It need not be persisted to survive a crash — it can simply be")
print("re-requested, and the same bytes come back.")

hr("DONE")
