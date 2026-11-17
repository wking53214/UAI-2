"""diff_fuzz.py: a differential fuzz of two UAI-1 implementations. Standard library only.

    python interop/diff_fuzz.py --seed 1 --per-case 100 --out report.json

It takes every message in the conformance suite, mutates its text (deleted, replaced and inserted characters, escapes, byte order marks,
lone surrogates, number forms, truncation, duplicated slices), sends the SAME text to the Python and the Node adapters, and compares.

* A disagreement about ACCEPT versus REFUSE is a finding: one implementation would act on bytes the other refuses. The exit status is 1.
* A disagreement only about the refusal CODE is listed in the report but is not a failure here. The specification fixes the code for one
  defect at a time; when a text has two defects (for example a duplicate key and an oversize integer) it does not say which code wins
  (see docs/AUDIT_2026-11-17.md).

This checks that two implementations written in this project agree. It is not evidence about a third implementation.
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
SUITE = json.loads((ROOT / "contracts" / "uai1" / "conformance-suite.json").read_text(encoding="utf-8"))["cases"]
INSERT = [" ", "\t", "\n", "\r", "﻿", " ", "\u0000", "\u007f", "é", " ", "\ud800", "\udc00", "\U0001F600", "\\u0041", "\\/",
          "\\ud83d", "\\ude00", ",", "{", "}", "[", "]", ":", '"', "\\", "1", "0", "-", ".", "e", "E", "+", "true", "null", "1.0", "1e2", "-0",
          "01", "9007199254740993", "NaN", "Infinity"]


class Adapter:
    def __init__(self, cmd: Sequence[str]) -> None:
        self.proc = subprocess.Popen(list(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
                                     errors="surrogatepass", cwd=ROOT)

    def ask(self, req: Dict[str, Any]) -> Dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        return json.loads(line) if line else {"crash": True}

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)


def mutate(rnd: random.Random, s: str) -> str:
    out = s
    for _ in range(rnd.choice([1, 1, 1, 2, 3])):
        if not out:
            break
        op, i = rnd.randrange(9), rnd.randrange(len(out))
        if op == 0:
            out = out[:i] + out[i + 1:]
        elif op == 1:
            out = out[:i] + rnd.choice(INSERT) + out[i + 1:]
        elif op == 2:
            out = out[:i] + rnd.choice(INSERT) + out[i:]
        elif op == 3:
            out = out[:i]
        elif op == 4:
            out = out + rnd.choice(INSERT + ["x", "\n\n", "{}"])
        elif op == 5:
            out = rnd.choice(INSERT + [" "]) + out
        elif op == 6:
            j = min(len(out), i + rnd.randrange(1, 40))
            out = out[:j] + out[i:j] + out[j:]
        elif op == 7:
            letters = [m for m, ch in enumerate(out) if ch.isalpha()]
            if letters:
                m = rnd.choice(letters)
                out = out[:m] + "\\u%04x" % ord(out[m]) + out[m + 1:]
        elif i + 1 < len(out):
            out = out[:i] + out[i + 1] + out[i] + out[i + 2:]
    return out


def run(seed: int = 1, per_case: int = 100, cmds: Optional[Sequence[Sequence[str]]] = None) -> Dict[str, Any]:
    cmds = cmds or ([sys.executable, str(ROOT / "interop/conformance/reference_adapter.py")],
                    ["node", str(ROOT / "interop/node/conformance_adapter.mjs")])
    a, b = Adapter(cmds[0]), Adapter(cmds[1])
    rnd = random.Random(seed)
    total = accepted = 0
    accept_gap: List[Dict[str, Any]] = []
    code_gap: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    try:
        for case in SUITE:
            recv = case["steps"][0]["receive"]
            for _ in range(per_case):
                text = mutate(rnd, recv["wire_text"])
                req = {"op": "receive", **recv, "wire_text": text}
                a.ask({"op": "reset"})
                b.ask({"op": "reset"})
                ra, rb = a.ask(req), b.ask(req)
                total += 1
                accepted += "accept" in ra
                if ra == rb:
                    continue
                row = {"case": case["name"], "text": text, "first": ra, "second": rb}
                if ("accept" in ra) != ("accept" in rb) or "crash" in ra or "crash" in rb:
                    accept_gap.append(row)
                else:
                    code_gap[f"{json.dumps(ra, sort_keys=True)} vs {json.dumps(rb, sort_keys=True)}"].append(row)
    finally:
        a.close()
        b.close()
    return {"seed": seed, "per_case": per_case, "comparisons": total, "first_accepts": accepted,
            "accept_vs_refuse_disagreements": accept_gap,
            "code_only_disagreements": {k: {"count": len(v), "example": v[0]} for k, v in sorted(code_gap.items())},
            "ok": not accept_gap}


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--per-case", type=int, default=100)
    ap.add_argument("--out", default="")
    opts = ap.parse_args(argv)
    rep = run(opts.seed, opts.per_case)
    if opts.out:
        Path(opts.out).write_text(json.dumps(rep, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"comparisons {rep['comparisons']}, accept-vs-refuse disagreements {len(rep['accept_vs_refuse_disagreements'])}, "
          f"code-only disagreement classes {len(rep['code_only_disagreements'])}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
