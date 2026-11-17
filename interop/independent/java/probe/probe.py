#!/usr/bin/env python3
"""Ambiguity probes: sends hand-made inputs to the Java adapter and prints the answers."""
import json, subprocess, sys, copy
kit = sys.argv[1]
vec = json.load(open(kit + "/contracts/uai-vectors.json"))
req = vec["envelopes"][0]["wire"]
man = vec["envelopes"][2]["wire"]
p = subprocess.Popen(["java", "-cp", kit + "/java/out", "Adapter"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
def ask(o):
    p.stdin.write(json.dumps(o) + "\n"); p.stdin.flush(); return json.loads(p.stdout.readline())
def rx(text, now=1800000000000, trust=None, audience=None, kinds=None, ledger=False):
    ask({"op": "reset"}) if False else None
    return ask({"op": "receive", "wire_text": text, "now": now, "trust": trust, "audience": audience, "kinds": kinds, "ledger": ledger})
def j(o): return json.dumps(o)
def show(name, got): print(f"{name:55s} {got}")
ask({"op": "reset"})
show("baseline request-0", rx(j(req)))
e = copy.deepcopy(req); e["v"] = 1; show("v is number 1", rx(j(e)))
e = copy.deepcopy(req); e["v"] = "uai/2"; e["body"] = {"a": 1.5}; show("v=uai/2 and float in body", rx(j(e)))
e = copy.deepcopy(req); e["v"] = "uai/2"; e["body"] = {"a": 2**60}; show("v=uai/2 and big int in body", rx(j(e)))
t = j(req).replace('"issued_at": 1800000000000', '"issued_at": 1800000000000.5'); show("float issued_at", rx(t))
t = j(req).replace('"issued_at": 1800000000000', '"issued_at": 1.8e12'); show("exponent issued_at", rx(t))
t = j(req).replace('"issued_at": 1800000000000', '"issued_at": 9007199254740993'); show("issued_at > 2^53", rx(t))
t = j(req).replace('"issued_at": 1800000000000', '"issued_at": -0'); show("issued_at -0 (expires after)", rx(t))
e = copy.deepcopy(req); e["from"] = "uai:ed25519:" + "\ud800" + "0" * 63; show("lone surrogate in from", rx(j(e)))
e = copy.deepcopy(req); e["body"] = {"\ud800": 1}; show("lone surrogate as body key", rx(j(e)))
show("broadcast manifest, audience set", rx(j(man), audience="uai:ed25519:" + "1" * 64))
show("kinds=['gossip'] unknown kind text", rx(j(dict(req, kind="gossip")), kinds=["request"]))
show("unknown kind + wrong version", rx(j(dict(req, kind="gossip", v="uai/2"))))
show("expired + untrusted + wrong audience", rx(j(req), now=1800000060000, trust=[], audience="uai:ed25519:" + "1" * 64))
show("untrusted + wrong audience", rx(j(req), trust=[], audience="uai:ed25519:" + "1" * 64))
show("untrusted + replayed (ledger on, second time)", (ask({"op":"reset"}), rx(j(req), ledger=True), rx(j(req), trust=[], ledger=True))[2])
ask({"op": "reset"})
a = rx(j(req), trust=[], ledger=True); b = rx(j(req), ledger=True); c = rx(j(req), ledger=True)
show("untrusted then accepted then replayed", (a, b, c))
ask({"op": "reset"})
a = rx(j(req), now=1900000000000, ledger=True); b = rx(j(req), ledger=True)
show("expired does not spend the id", (a, b))
show("sig forged + expired", rx(j(dict(req, sig="0" * 128)), now=1900000000000))
show("bad sig + untrusted", rx(j(dict(req, sig="0" * 128)), trust=[]))
show("trust=[] (empty, not null)", rx(j(req), trust=[]))
show("kinds=[] (empty, not null)", rx(j(req), kinds=[]))
# session lifetime rules (no code in the spec)
for name, patch in [("request expires_at null", {"expires_at": None}), ("request lives 25h", {"expires_at": 1800000000000 + 25 * 3600 * 1000})]:
    show(name + " (unsigned edit)", rx(j(dict(req, **patch))))
# depth
def nest(n):
    s = "1"
    for _ in range(n - 1): s = '{"a":' + s + '}'
    return s
for n in (32, 33, 100, 700, 1000, 5000, 19990, 30000):
    t = j(req).replace('"body": {"capability": "income-screen", "version": 1}', '"body": ' + nest(n)); show(f"body nested {n} levels", rx(t))
show("whole document array nested 100000", rx("[" * 100000 + "]" * 100000))
show("object nested 100000 as extra field", rx(j(req)[:-1] + ',"x":' + "[" * 100000 + "]" * 100000 + "}"))
show("size exactly 1 MiB (padded spaces, bad sig)", rx(j(dict(req, sig="0"*128)) + " " * (1048576 - len(j(dict(req, sig="0"*128))))))
show("size 1 MiB + 1", rx(j(dict(req, sig="0"*128)) + " " * (1048577 - len(j(dict(req, sig="0"*128))))))
show("U+2028 in body string", rx(j(req).replace('income-screen', 'a b'), ))
show("raw tab char inside string", rx(j(req).replace('income-screen', 'a\tb')))
show("escaped solidus + uppercase \\u00E9 in body", rx(j(req).replace('income-screen', 'a\\/\\u00E9')))
show("NUL escaped in body (tampered)", rx(j(req).replace('income-screen', '\\u0000')))
show("JSON whitespace set incl form feed", rx("\f" + j(req)))
show("body is list", rx(j(dict(req, body=[]))))
show("empty body {}", rx(j(dict(req, body={}))))
show("to broadcast on request", rx(j(dict(req, to=""))))
p.stdin.close(); p.wait()
