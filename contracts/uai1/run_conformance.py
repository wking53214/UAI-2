#!/usr/bin/env python3
"""run_conformance.py: check ANY implementation of UAI-1 against conformance-suite.json. Standard library only; it imports
nothing from CNS, so an independent implementation can be tested without the CNS source.

    python contracts/uai1/run_conformance.py --cmd "node path/to/your_adapter.js"

Your adapter is a program that reads one JSON request per line on stdin and writes one JSON answer per line on stdout
(protocol: README.md in this directory). The runner starts it once, sends `reset` before each case, then each step, and
compares the answer with the case's expectation. Exit status 0 only if every case passed. A case marked basis "reference"
is one the two shipped implementations agree on but the specification text does not fix; it is reported separately so a
disagreement there is read as a question, not necessarily a defect.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cmd", required=True, help="the adapter command (run through a shell-style split, not a shell)")
    ap.add_argument("--suite", default=str(Path(__file__).with_name("conformance-suite.json")))
    ap.add_argument("--json", action="store_true", help="print a machine-readable summary")
    args = ap.parse_args()
    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    proc = subprocess.Popen(shlex.split(args.cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(req: dict) -> dict:
        assert proc.stdin and proc.stdout
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise SystemExit("the adapter closed its output before answering")
        return json.loads(line)

    results = {"specification": [0, 0], "reference": [0, 0]}
    failures = []
    for case in suite["cases"]:
        ask({"op": "reset"})
        ok = True
        for step in case["steps"]:
            got = ask({"op": "receive", **step["receive"]})
            want = step["expect"]
            good = ("accept" in got) if want.get("accept") else (got.get("refuse") == want.get("refuse"))
            if not good:
                ok = False
                failures.append({"case": case["name"], "class": case["class"], "basis": case["basis"], "wanted": want, "got": got})
                break
        results[case["basis"]][0 if ok else 1] += 1
    proc.stdin.close() if proc.stdin else None
    proc.wait(timeout=10)
    summary = {"suite": suite["schema"], "cases": len(suite["cases"]), "passed": {k: v[0] for k, v in results.items()},
               "failed": {k: v[1] for k, v in results.items()}, "failures": failures}
    if args.json:
        print(json.dumps(summary, indent=1))
    else:
        for f in failures:
            print(f"FAIL [{f['basis']}] {f['case']} ({f['class']}): wanted {f['wanted']}, got {f['got']}")
        print(f"{summary['passed']} passed, {summary['failed']} failed of {summary['cases']} cases")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
