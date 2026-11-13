# A second implementation of the answer reader and policy chain (Go)

`main.go` implements `docs/interop/POLICY_CHAIN_SPEC.md` in Go with no JSON library for the answer (its own strict reader). It was
written by an agent that saw **only the spec, the UAI-1 text and the examples file**, not the Python. It is a test instrument,
not a product: it speaks the line protocol of the spec so it can be compared with the Python chain.

    cd interop/policy_go && go build -o policy_go .
    cd ../.. && python3 interop/policy_differential.py --impl interop/policy_go/policy_go --examples docs/interop/policy_examples.json
    python3 interop/policy_differential.py --impl interop/policy_go/policy_go --cases 200000 --seed 1

Not part of CI: the suite fails on a skip, and CI machines may lack Go. The Python side of the harness is tested in
`tests/test_policy_differential.py`.

## What happened (2026-11-13)

- First comparison: 80 of 80 examples agreed (75 before the boundary examples were added), and 200,000 random cases for each of
  seeds 1 to 5 agreed (1,000,000 cases, 0 disagreements). Roughly 72 percent of the random cases are refused by both, the rest
  judged identically.
- The random cases never reached the one disagreement that existed. Probing the nesting limit by hand found it: **Python and Node
  both accepted an empty object or list as the 33rd level**, while UAI-1 section 1 says 33 levels are refused and the Go reading
  (every object and list is a level, empty or not) refuses it. The conformance vectors never saw it because they end in a number.
  Fixed in Step 5 (Python and Node, one condition each), spec wording tightened, five boundary examples added, and the
  generator now spends 10 percent of cases within a few levels of the limit.
- After the fix: seeds 11 to 13 (600,000 more cases) and the 80 examples agree. With the fix removed, the boundary generator alone
  finds the problem (21 disagreements in 5,000 cases).

## What this does and does not show

It shows two readers written independently, one of them without sight of the other's code, agree on 1.6 million generated cases
and 80 hand-written ones, and that the search can find a real defect. It does not show the spec is complete: the Go author
listed nine places where it had to guess (counting of arrays, code points after unescaping, JSON whitespace, bad base64 in the
request, and others). Where the guess matched Python it proves less than it seems, because the generator and examples were
written by the same person who wrote the Python. An outside implementer is still the stronger test.
